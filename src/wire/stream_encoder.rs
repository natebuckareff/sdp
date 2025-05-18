use anyhow::Result;
use bytes::{BufMut, BytesMut};

use crate::{
    crypto::{HeaderSecret, StreamEncryptor},
    wire::{
        connection_frame::StreamHeader,
        stream_frame::{StreamFramePacketType, StreamStart},
    },
};

use super::stream_frame::{StartInput, StreamFrameInput, StreamMessage, TransmissionInput};

pub enum StreamEncoderCrypto {
    Secured {
        header_secret: HeaderSecret,
        stream_encryptor: StreamEncryptor,
    },
    Unsecured {
        counter: u64,
    },
}

pub struct StreamFrameEncoder {
    connection_id: u32,
    stream_id: u32,
    crypto: StreamEncoderCrypto,
}

impl StreamFrameEncoder {
    pub fn new(connection_id: u32, stream_id: u32, crypto: StreamEncoderCrypto) -> Self {
        Self {
            connection_id,
            stream_id,
            crypto,
        }
    }

    pub fn encode_stream_frame(
        &mut self,
        buf: &mut BytesMut,
        frame: StreamFrameInput,
    ) -> Result<()> {
        self.encode_header(buf)?;

        match frame {
            StreamFrameInput::Start(start_input) => {
                self.encode_start(buf, start_input)?;
            }
            StreamFrameInput::Transmission(transmission_input) => {
                self.encode_transmission(buf, transmission_input)?;
            }
            StreamFrameInput::End => {
                self.encode_end(buf);
            }
        };

        self.encrypt(buf)
    }

    fn encode_header(&self, buf: &mut BytesMut) -> Result<()> {
        buf.reserve(StreamHeader::encoded_len());
        buf.put_u8(StreamFramePacketType::Start as u8);
        buf.put_u32(self.connection_id);
        buf.put_u32(self.stream_id);

        match &self.crypto {
            StreamEncoderCrypto::Secured { .. } => {
                buf.put_u64(0);
            }
            StreamEncoderCrypto::Unsecured { counter } => {
                buf.put_u64(*counter);
            }
        }

        Ok(())
    }

    fn encode_start(&self, buf: &mut BytesMut, start_input: StartInput) -> Result<()> {
        buf.reserve(StreamStart::encoded_len());
        buf.put_u8(StreamFramePacketType::Start as u8);
        buf.put_u8(start_input.stream_flags as u8);
        Ok(())
    }

    fn encode_transmission(
        &self,
        buf: &mut BytesMut,
        transmission_input: TransmissionInput,
    ) -> Result<()> {
        match transmission_input {
            TransmissionInput::Data => self.encode_data(buf),
            TransmissionInput::Datagram => self.encode_datagram(buf),
            TransmissionInput::Message(message) => self.encode_message(buf, false, message),
            TransmissionInput::FinalMessage(message) => self.encode_message(buf, true, message),
        }
    }

    fn encode_data(&self, buf: &mut BytesMut) -> Result<()> {
        buf.reserve(1);
        buf.put_u8(StreamFramePacketType::Data as u8);
        Ok(())
    }

    fn encode_datagram(&self, buf: &mut BytesMut) -> Result<()> {
        buf.reserve(1);
        buf.put_u8(StreamFramePacketType::Datagram as u8);
        Ok(())
    }

    fn encode_message(
        &self,
        buf: &mut BytesMut,
        is_final: bool,
        message: StreamMessage,
    ) -> Result<()> {
        buf.reserve(StreamMessage::encoded_len());
        if is_final {
            buf.put_u8(StreamFramePacketType::FinalMessage as u8);
        } else {
            buf.put_u8(StreamFramePacketType::Message as u8);
        }
        buf.put_u64(message.id);
        buf.put_u64(message.offset);
        Ok(())
    }

    fn encode_end(&self, buf: &mut BytesMut) -> Result<()> {
        buf.reserve(1);
        buf.put_u8(StreamFramePacketType::End as u8);
        Ok(())
    }

    fn encrypt(&mut self, buf: &mut BytesMut) -> Result<()> {
        // Expected buf format: stream_id || packet_number || stream_frame

        match &mut self.crypto {
            StreamEncoderCrypto::Secured {
                stream_encryptor, ..
            } => {
                stream_encryptor.encrypt(buf)?;
            }
            StreamEncoderCrypto::Unsecured { counter, .. } => {
                *counter += 1;
            }
        }

        Ok(())
    }
}
