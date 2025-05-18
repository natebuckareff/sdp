use anyhow::{Result, anyhow};
use bytes::{Buf, BytesMut};

use crate::{
    crypto::{HeaderSecret, StreamDecryptor},
    wire::stream_frame::{StreamFlags, StreamFramePacketType},
};

use super::{
    connection_frame::StreamHeader,
    stream_frame::{StreamFrame, StreamMessage, StreamStart, StreamTransmission},
};

pub enum StreamDecoderCrypto {
    Secured {
        header_secret: HeaderSecret,
        stream_decryptor: StreamDecryptor,
    },
    Unsecured {
        counter: u64,
    },
}

pub struct StreamFrameDecoder {
    crypto: StreamDecoderCrypto,
}

impl StreamFrameDecoder {
    pub fn new(crypto: StreamDecoderCrypto) -> Self {
        Self { crypto }
    }

    pub fn decode_stream_frame(
        &mut self,
        buf: &mut BytesMut,
        stream_header: &StreamHeader,
    ) -> Result<StreamFrame> {
        self.decrypt(buf, stream_header)?;

        let packet_type = StreamFramePacketType::try_from(buf.get_u8())?;

        match packet_type {
            StreamFramePacketType::Start => {
                let stream_start = self.decode_stream_start(buf)?;
                Ok(StreamFrame::Start(stream_start))
            }
            StreamFramePacketType::End => Ok(StreamFrame::End),
            _ => {
                let transmission = self.decode_transmission(buf)?;
                Ok(StreamFrame::Transmission(transmission))
            }
        }
    }

    fn decrypt(&mut self, buf: &mut BytesMut, stream_header: &StreamHeader) -> Result<()> {
        // Expected buf format: stream_id || packet_number || ciphertext

        if buf.len() < StreamHeader::encoded_masked_len() {
            return Err(anyhow!("unexpected end-of-frame"));
        }

        if buf.len() == StreamHeader::encoded_masked_len() {
            // TODO: Should empty ciphertext be allowed?
            return Err(anyhow!("unexpected empty ciphertext"));
        }

        match &mut self.crypto {
            StreamDecoderCrypto::Secured {
                stream_decryptor, ..
            } => {
                stream_decryptor.decrypt(buf, stream_header.packet_number)?;
            }
            StreamDecoderCrypto::Unsecured { counter, .. } => {
                *counter += 1;
            }
        }
        Ok(())
    }

    fn decode_stream_start(&mut self, buf: &mut BytesMut) -> Result<StreamStart> {
        let payload_len = StreamStart::encoded_len() - 1;

        if buf.len() < payload_len {
            return Err(anyhow!("unexpected end-of-frame"));
        }

        let stream_flags = StreamFlags::from(buf.get_u8());

        let transmission = if buf.len() > 0 {
            Some(self.decode_transmission(buf)?)
        } else {
            None
        };

        Ok(StreamStart {
            stream_flags,
            transmission,
        })
    }

    fn decode_transmission(&mut self, buf: &mut BytesMut) -> Result<StreamTransmission> {
        if buf.len() == 0 {
            return Err(anyhow!("unexpected empty frame"));
        }

        let packet_type = StreamFramePacketType::try_from(buf.get_u8())?;

        match packet_type {
            StreamFramePacketType::Start => Err(anyhow!("unexpected start stream packet type")),
            StreamFramePacketType::Data => Ok(StreamTransmission::Data),
            StreamFramePacketType::Datagram => Ok(StreamTransmission::Datagram),
            StreamFramePacketType::Message => {
                todo!()
            }
            StreamFramePacketType::FinalMessage => {
                todo!()
            }
            StreamFramePacketType::End => Err(anyhow!("unexpected end stream packet type")),
        }
    }

    fn decode_message(
        &mut self,
        buf: &mut BytesMut,
        stream_header: &StreamHeader,
    ) -> Result<StreamMessage> {
        todo!()
    }

    fn decode_final_message(
        &mut self,
        buf: &mut BytesMut,
        stream_header: &StreamHeader,
    ) -> Result<StreamMessage> {
        todo!()
    }
}
