use std::collections::HashMap;

use anyhow::{Result, anyhow};
use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use derive_more::From;
use int_enum::IntEnum;

use crate::{
    crypto::{HeaderSecret, StaticIv, StreamKey},
    wire::varint::Varint,
};

use super::stream_buffer::StreamBuffer;

const CHUNK_LEN: usize = 4096; // TODO: tuneable

bitflags! {
    pub struct TrafficFlags: u8 {
        const IS_HANDSHAKE = 0b00000001;
        const PHASE_BIT    = 0b00000010;
    }
}

pub struct TrafficFrame {
    pub packet_number: u64,
    pub flags: TrafficFlags,
    pub connection_id: Option<u64>,
}

#[repr(u8)]
#[derive(IntEnum, Copy, Clone)]
pub enum StreamFrameType {
    StreamData = 0x00,
    EndOfStream = 0x10,
    StreamMessage = 0x20,
}

bitflags! {
    pub struct StreamFlags: u8 {
        const IS_LAST_FRAME  = 0b00000001;
        const IS_MULTI_FRAME = 0b00000010;
    }
}

pub struct StreamFrameTypeFlags {
    pub frame_type: StreamFrameType,
    pub flags: StreamFlags,
}

impl StreamFrameTypeFlags {
    pub fn encode(&self, output: &mut BytesMut) {
        let hi = self.frame_type as u8;
        let lo = self.flags.bits() as u8;
        output.put_u8(hi | lo);
    }

    pub fn decode(input: &mut BytesMut) -> Result<Self> {
        let byte = input.get_u8();
        let frame_type = StreamFrameType::try_from(byte & 0b11110000)
            .map_err(|_| anyhow!("invalid stream frame type"))?;
        let flags = StreamFlags::from_bits_truncate(byte & 0b00001111);
        Ok(Self { frame_type, flags })
    }
}

#[derive(From)]
pub enum StreamFrame {
    StreamData(StreamDataFrame),
    EndOfStream(EndOfStreamFrame),
    StreamMessage(StreamMessageFrame),
}

pub struct StreamDataFrame {
    pub stream_id: Option<u64>,
    pub offset: usize,
    pub length: usize,
}

pub struct EndOfStreamFrame {
    pub stream_id: u64,
    pub offset: usize,
    pub length: usize,
}

pub struct StreamMessageFrame {
    pub stream_id: u64,
    pub message_id: u64,
    pub offset: usize,
    pub length: usize,
}

pub struct ConnectionDecoder {
    handshake_buffer: Option<StreamBuffer>,
    data_buffers: HashMap<u64, StreamBuffer>,
    message_buffers: HashMap<(u64, u64), StreamBuffer>,
}

impl ConnectionDecoder {
    pub fn new() -> Self {
        Self {
            handshake_buffer: None,
            data_buffers: HashMap::new(),
            message_buffers: HashMap::new(),
        }
    }

    pub fn traffic_frame(
        &mut self,
        input: &mut BytesMut,
        header_secret: Option<&mut HeaderSecret>,
    ) -> Result<(Bytes, TrafficFrame)> {
        const HEADER_LEN: usize = 8 + 1;

        let mut header = input.split_to(HEADER_LEN);

        if let Some(header_secret) = header_secret {
            let sample = &input[8..];
            header_secret.apply_header_mask::<HEADER_LEN>(&mut header, sample)?;
        }

        let packet_number = header.get_u64();
        let flags = TrafficFlags::from_bits_truncate(header.get_u8());

        let connection_id = if flags.contains(TrafficFlags::IS_HANDSHAKE) {
            None
        } else {
            Some(Varint::decode(input).into())
        };

        let header = header.freeze();

        let traffic_frame = TrafficFrame {
            packet_number,
            flags,
            connection_id,
        };

        Ok((header, traffic_frame))
    }

    pub fn decrypt(
        &mut self,
        input: &mut BytesMut,
        header: &Bytes,
        traffic_frame: TrafficFrame,
        static_iv: &mut StaticIv,
        stream_key: &mut StreamKey,
    ) -> Result<()> {
        let nonce = static_iv.derive_nonce(traffic_frame.packet_number);
        stream_key.decrypt(nonce, header, input)?;
        Ok(())
    }

    pub fn decode_stream_frame(
        &mut self,
        input: &mut BytesMut,
        output: &mut BytesMut,
        traffic_frame: TrafficFrame,
    ) -> Result<StreamFrame> {
        let StreamFrameTypeFlags { frame_type, flags } = StreamFrameTypeFlags::decode(input)?;

        let decoded = match frame_type {
            StreamFrameType::StreamData => self
                .decode_stream_data_frame(input, output, traffic_frame, flags)?
                .into(),

            StreamFrameType::EndOfStream => self
                .decode_end_of_stream_frame(input, output, traffic_frame, flags)?
                .into(),

            StreamFrameType::StreamMessage => self
                .decode_stream_message_frame(input, output, traffic_frame, flags)?
                .into(),
        };

        Ok(decoded)
    }

    fn decode_stream_data_frame(
        &mut self,
        input: &mut BytesMut,
        output: &mut BytesMut,
        traffic_frame: TrafficFrame,
        flags: StreamFlags,
    ) -> Result<StreamDataFrame> {
        let stream_id = if traffic_frame.flags.contains(TrafficFlags::IS_HANDSHAKE) {
            None
        } else {
            Some(Varint::decode(input))
        };

        let offset = Varint::decode(input).try_into()?;

        let length = if flags.contains(StreamFlags::IS_LAST_FRAME) {
            input.len()
        } else {
            Varint::decode(input).try_into()?
        };

        let data_buffer = match &stream_id {
            Some(stream_id) => self
                .data_buffers
                .entry(stream_id.into())
                // TODO XXX unwrap
                .or_insert_with(|| StreamBuffer::new(CHUNK_LEN, 0).unwrap()),
            None => {
                // TODO XXX unwrap
                self.handshake_buffer = Some(StreamBuffer::new(CHUNK_LEN, 0).unwrap());
                unsafe { self.handshake_buffer.as_mut().unwrap_unchecked() }
            }
        };

        data_buffer.write(offset, input)?;
        input.advance(length);

        data_buffer.consume(output);

        Ok(StreamDataFrame {
            stream_id: stream_id.map(|v| v.into()),
            offset,
            length,
        })
    }

    fn decode_end_of_stream_frame(
        &mut self,
        input: &mut BytesMut,
        output: &mut BytesMut,
        traffic_frame: TrafficFrame,
        flags: StreamFlags,
    ) -> Result<EndOfStreamFrame> {
        if traffic_frame.flags.contains(TrafficFlags::IS_HANDSHAKE) {
            return Err(anyhow!("unexpected END_OF_STREAM frame"));
        }

        let data_frame = self.decode_stream_data_frame(input, output, traffic_frame, flags)?;

        Ok(EndOfStreamFrame {
            // This is safe because we check if IS_CONNECTION is unset before
            // decoding the DATA_FRAME
            stream_id: unsafe { data_frame.stream_id.unwrap_unchecked() },
            offset: data_frame.offset,
            length: data_frame.length,
        })
    }

    fn decode_stream_message_frame(
        &mut self,
        input: &mut BytesMut,
        output: &mut BytesMut,
        traffic_frame: TrafficFrame,
        flags: StreamFlags,
    ) -> Result<StreamMessageFrame> {
        let stream_id = Varint::decode(input).into();

        let message_id = if flags.contains(StreamFlags::IS_MULTI_FRAME) {
            Varint::decode(input).into()
        } else {
            traffic_frame.packet_number
        };

        let offset = Varint::decode(input).try_into()?;

        let length = if flags.contains(StreamFlags::IS_LAST_FRAME) {
            input.len()
        } else {
            Varint::decode(input).try_into()?
        };

        // TODO: mechanism to cleanup these buffers
        let message_buffer = self
            .message_buffers
            .entry((stream_id, message_id))
            // TODO XXX unwrap
            .or_insert_with(|| StreamBuffer::new(CHUNK_LEN, 0).unwrap());

        message_buffer.write(offset, input)?;
        input.advance(length);

        message_buffer.consume(output);

        Ok(StreamMessageFrame {
            stream_id,
            message_id,
            offset,
            length,
        })
    }
}
