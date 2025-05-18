use std::io::Cursor;

use anyhow::{Context, Result, anyhow};
use bytes::{Buf, BytesMut};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, Signature, VerifyingKey};
use x25519_dalek::PublicKey;

use crate::crypto::ConnectionCrypto;

use super::connection_frame::{
    AcceptPacket, ConnectPacket, ConnectionFrame, ConnectionFrameCrypto, ConnectionPacketType,
    RejectPacket, RejectReason, StreamHeader,
};

pub struct ConnectionFrameDecoder {
    crypto: Option<ConnectionCrypto>,
}

impl ConnectionFrameDecoder {
    pub fn new(crypto: Option<ConnectionCrypto>) -> Self {
        Self { crypto }
    }

    pub fn decode_connection_frame(&mut self, buf: &mut BytesMut) -> Result<ConnectionFrame> {
        if buf.len() == 0 {
            return Err(anyhow!("unexpected empty frame"));
        }

        let packet_type = ConnectionPacketType::try_from(buf.get_u8())?;

        match packet_type {
            ConnectionPacketType::Connect => {
                let connect_packet = self.decode_connect_packet(buf)?;
                Ok(ConnectionFrame::Connect(connect_packet))
            }
            ConnectionPacketType::Accept => {
                let accept_packet = self.decode_accept_packet(buf)?;
                Ok(ConnectionFrame::Accept(accept_packet))
            }
            ConnectionPacketType::Reject => {
                let reject_packet = self.decode_reject_packet(buf)?;
                Ok(ConnectionFrame::Reject(reject_packet))
            }
            ConnectionPacketType::StreamHeader => {
                let stream_header = self.decode_stream_header(buf)?;
                Ok(ConnectionFrame::StreamHeader(stream_header))
            }
        }
    }

    fn decode_connect_packet(&self, buf: &mut BytesMut) -> Result<ConnectPacket> {
        let payload_len = ConnectPacket::encoded_len() - 1;

        if buf.len() < payload_len {
            return Err(anyhow!("unexpected end-of-frame"));
        }

        let mut cursor = Cursor::new(buf.as_ref());

        let protocol_version = cursor.get_u16();
        let src_connection_id = cursor.get_u32();

        let static_public_key = {
            let mut bytes = [0u8; PUBLIC_KEY_LENGTH];
            cursor.copy_to_slice(&mut bytes);
            VerifyingKey::from_bytes(&bytes)?
        };

        let ephemeral_public_key = if self.crypto.is_some() {
            let mut bytes = [0u8; PUBLIC_KEY_LENGTH];
            cursor.copy_to_slice(&mut bytes);
            Some(PublicKey::from(bytes))
        } else {
            None
        };

        let signature = {
            let mut bytes = [0u8; SIGNATURE_LENGTH];
            cursor.copy_to_slice(&mut bytes);
            Signature::from(bytes)
        };

        let message = &buf[..payload_len - SIGNATURE_LENGTH];

        static_public_key
            .verify_strict(message, &signature)
            .context("failed to verify signature")?;

        buf.advance(payload_len);

        Ok(ConnectPacket {
            protocol_version,
            src_connection_id,
            static_public_key,
            ephemeral_public_key,
            signature,
        })
    }

    fn decode_accept_packet(&self, buf: &mut BytesMut) -> Result<AcceptPacket> {
        let payload_len = AcceptPacket::encoded_len() - 1;

        if buf.len() < payload_len {
            return Err(anyhow!("unexpected end-of-frame"));
        }

        let mut cursor = Cursor::new(buf.as_ref());

        let protocol_version = cursor.get_u16();
        let src_connection_id = cursor.get_u32();
        let dst_connection_id = cursor.get_u32();

        let static_public_key = {
            let mut bytes = [0u8; PUBLIC_KEY_LENGTH];
            cursor.copy_to_slice(&mut bytes);
            VerifyingKey::from_bytes(&bytes)?
        };

        let ephemeral_public_key = if self.crypto.is_some() {
            let mut bytes = [0u8; PUBLIC_KEY_LENGTH];
            cursor.copy_to_slice(&mut bytes);
            Some(PublicKey::from(bytes))
        } else {
            None
        };

        let signature = {
            let mut bytes = [0u8; SIGNATURE_LENGTH];
            cursor.copy_to_slice(&mut bytes);
            Signature::from(bytes)
        };

        let message = &buf[..payload_len - SIGNATURE_LENGTH];

        static_public_key
            .verify_strict(message, &signature)
            .context("failed to verify signature")?;

        buf.advance(payload_len);

        Ok(AcceptPacket {
            protocol_version,
            src_connection_id,
            dst_connection_id,
            static_public_key,
            ephemeral_public_key,
            signature,
        })
    }

    fn decode_reject_packet(&self, buf: &mut BytesMut) -> Result<RejectPacket> {
        let payload_len = RejectPacket::encoded_len() - 1;

        if buf.len() < payload_len {
            return Err(anyhow!("unexpected end-of-frame"));
        }

        let mut cursor = Cursor::new(buf.as_ref());

        let dst_connection_id = cursor.get_u32();
        let reason_code = RejectReason::try_from(cursor.get_u8())?;

        let static_public_key = {
            let mut bytes = [0u8; PUBLIC_KEY_LENGTH];
            cursor.copy_to_slice(&mut bytes);
            VerifyingKey::from_bytes(&bytes)?
        };

        let signature = {
            let mut bytes = [0u8; SIGNATURE_LENGTH];
            cursor.copy_to_slice(&mut bytes);
            Signature::from(bytes)
        };

        let message = &buf[..payload_len - SIGNATURE_LENGTH];

        static_public_key
            .verify_strict(message, &signature)
            .context("failed to verify signature")?;

        buf.advance(payload_len);

        Ok(RejectPacket {
            dst_connection_id,
            reason_code,
            static_public_key,
            signature,
        })
    }

    fn decode_stream_header(&mut self, buf: &mut BytesMut) -> Result<StreamHeader> {
        let header_len = StreamHeader::encoded_len() - 1;

        if buf.len() < header_len {
            return Err(anyhow!("unexpected end-of-frame"));
        }

        let dst_connection_id = buf.get_u32();
        let mut masked = buf.split_off(0);

        if let Some(crypto) = &mut self.crypto {
            let ciphertext = &buf[header_len..];
            crypto.apply_header_mask(&mut masked, ciphertext)?;
        }

        let stream_id = masked.get_u32();
        let packet_number = masked.get_u64();

        // NOTE: buf still contains the now unmasked stream ID and packet number

        Ok(StreamHeader {
            dst_connection_id,
            stream_id,
            packet_number,
        })
    }
}
