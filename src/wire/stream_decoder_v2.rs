use std::collections::HashMap;

use anyhow::{Result, anyhow};
use bitflags::bitflags;
use bytes::{Buf, BytesMut};
use derive_more::From;
use int_enum::IntEnum;

use crate::wire::varint::Varint;

use super::stream_buffer::StreamBuffer;

const CHUNK_LEN: usize = 4096; // TODO: tuneable

bitflags! {
    pub struct TrafficFlags: u8 {
        const IS_DATAGRAM   = 0b10000000;
        const IS_CONNECTION = 0b01000000;
        const PHASE_BIT     = 0b00100000;
    }
}

pub struct TrafficCtx {
    frame_len: usize,
    flags: TrafficFlags,
}

#[repr(u8)]
#[derive(IntEnum)]
pub enum StreamFrameType {
    Data = 0,
    EndOfStream = 1,
    LargeMessageFrame = 2,
    SmallMessageFrame = 3,
    DatagramFrame = 4,
}

#[derive(From)]
pub enum DecodedStreamFrame {
    Data(DecodedDataFrame),
    EndOfStream(DecodedEndOfStreamFrame),
    LargeMessage(DecodedLargeMessageFrame),
    SmallMessage(DecodedSmallMessageFrame),
}

pub struct DecodedDataFrame {
    pub stream_id: Option<u64>,
    pub offset: usize,
    pub length: usize,
}

pub struct DecodedEndOfStreamFrame {
    pub stream_id: u64,
    pub offset: usize,
    pub length: usize,
}

pub struct DecodedLargeMessageFrame {
    pub stream_id: Option<u64>,
    pub message_id: u64,
    pub offset: usize,
    pub length: usize,
}

pub struct DecodedSmallMessageFrame {
    pub is_datagram: bool,
    pub stream_id: Option<u64>,
    pub length: usize,
}

pub struct StreamDecoderV2 {
    data_buffer: StreamBuffer,
    message_buffers: HashMap<u64, StreamBuffer>,
}

impl StreamDecoderV2 {
    pub fn new() -> Self {
        Self {
            data_buffer: StreamBuffer::new(CHUNK_LEN, 0),
            message_buffers: HashMap::new(),
        }
    }

    pub fn decode_stream_frame(
        &mut self,
        input: &mut BytesMut,
        output: &mut BytesMut,
        traffic_cx: TrafficCtx,
    ) -> Result<DecodedStreamFrame> {
        let packet_type = StreamFrameType::try_from(input.get_u8())
            .map_err(|_| anyhow!("invalid stream frame type"))?;

        let decoded = match packet_type {
            StreamFrameType::Data => self.decode_data_frame(input, output, traffic_cx)?.into(),
            StreamFrameType::EndOfStream => self
                .decode_end_of_stream_frame(input, output, traffic_cx)?
                .into(),
            StreamFrameType::LargeMessageFrame => self
                .decode_large_message_frame(input, output, traffic_cx)?
                .into(),
            StreamFrameType::SmallMessageFrame => self
                .decode_small_message_frame(input, output, traffic_cx, false)?
                .into(),
            StreamFrameType::DatagramFrame => self
                .decode_small_message_frame(input, output, traffic_cx, true)?
                .into(),
        };

        Ok(decoded)
    }

    fn decode_data_frame(
        &mut self,
        input: &mut BytesMut,
        output: &mut BytesMut,
        traffic_cx: TrafficCtx,
    ) -> Result<DecodedDataFrame> {
        let stream_id = if traffic_cx.flags.contains(TrafficFlags::IS_CONNECTION) {
            Some(Varint::decode(input))
        } else {
            None
        };

        let offset = Varint::decode(input).try_into()?;

        let length = if traffic_cx.flags.contains(TrafficFlags::IS_DATAGRAM) {
            input.len()
        } else {
            Varint::decode(input).try_into()?
        };

        self.data_buffer.write(offset, input);
        input.advance(length);

        self.data_buffer.consume(output);

        Ok(DecodedDataFrame {
            stream_id: stream_id.map(|v| v.into()),
            offset,
            length,
        })
    }

    fn decode_end_of_stream_frame(
        &mut self,
        input: &mut BytesMut,
        output: &mut BytesMut,
        traffic_cx: TrafficCtx,
    ) -> Result<DecodedEndOfStreamFrame> {
        if !traffic_cx.flags.contains(TrafficFlags::IS_CONNECTION) {
            return Err(anyhow!("unexpected END_OF_STREAM frame"));
        }

        let data_frame = self.decode_data_frame(input, output, traffic_cx)?;

        Ok(DecodedEndOfStreamFrame {
            // This is safe because we check if IS_CONNECTION is unset before
            // decoding the DATA_FRAME
            stream_id: unsafe { data_frame.stream_id.unwrap_unchecked() },
            offset: data_frame.offset,
            length: data_frame.length,
        })
    }

    fn decode_large_message_frame(
        &mut self,
        input: &mut BytesMut,
        output: &mut BytesMut,
        traffic_cx: TrafficCtx,
    ) -> Result<DecodedLargeMessageFrame> {
        let stream_id = if traffic_cx.flags.contains(TrafficFlags::IS_CONNECTION) {
            Some(Varint::decode(input).into())
        } else {
            None
        };

        let message_id = Varint::decode(input).into();
        let offset = Varint::decode(input).try_into()?;

        let length = if traffic_cx.flags.contains(TrafficFlags::IS_DATAGRAM) {
            input.len()
        } else {
            Varint::decode(input).try_into()?
        };

        // TODO: mechanism to cleanup these buffers
        let message_buffer = self
            .message_buffers
            .entry(message_id)
            .or_insert_with(|| StreamBuffer::new(CHUNK_LEN, 0));

        message_buffer.write(offset, input);
        input.advance(length);

        message_buffer.consume(output);

        Ok(DecodedLargeMessageFrame {
            stream_id,
            message_id,
            offset,
            length,
        })
    }

    fn decode_small_message_frame(
        &mut self,
        input: &mut BytesMut,
        output: &mut BytesMut,
        traffic_cx: TrafficCtx,
        is_datagram: bool,
    ) -> Result<DecodedSmallMessageFrame> {
        let stream_id = if traffic_cx.flags.contains(TrafficFlags::IS_CONNECTION) {
            Some(Varint::decode(input).into())
        } else {
            None
        };

        let length = if traffic_cx.flags.contains(TrafficFlags::IS_DATAGRAM) {
            input.len()
        } else {
            Varint::decode(input).try_into()?
        };

        input.copy_to_slice(output);

        Ok(DecodedSmallMessageFrame {
            is_datagram,
            stream_id,
            length,
        })
    }
}
