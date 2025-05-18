use aead::OsRng;
use anyhow::Result;
use bytes::{Buf, BufMut, BytesMut};
use ed25519_dalek::{Signer, SigningKey};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{crypto::ConnectionCrypto, wire::connection_frame::ConnectionPacketType};

use super::connection_frame::{
    AcceptPacket, AcceptPacketInput, ConnectPacket, ConnectPacketInput, ConnectionFrameInput,
    RejectPacket, RejectPacketInput,
};

pub struct ConnectionFrameEncoder {
    protocol_version: u16,
    static_secret: SigningKey,
    crypto: Option<ConnectionCrypto>,
}

impl ConnectionFrameEncoder {
    pub fn new(
        protocol_version: u16,
        static_secret: SigningKey,
        crypto: Option<ConnectionCrypto>,
    ) -> Self {
        Self {
            protocol_version,
            static_secret,
            crypto,
        }
    }

    pub fn encode_connection_frame(
        &mut self,
        buf: &mut BytesMut,
        frame: ConnectionFrameInput,
    ) -> Result<()> {
        match frame {
            ConnectionFrameInput::Connect(connect_packet) => {
                self.encode_connect_packet(buf, connect_packet)?;
            }
            ConnectionFrameInput::Accept(accept_packet) => {
                self.encode_accept_packet(buf, accept_packet)?;
            }
            ConnectionFrameInput::Reject(reject_packet) => {
                self.encode_reject_packet(buf, reject_packet)?;
            }
        }
        Ok(())
    }

    fn encode_connect_packet(
        &mut self,
        buf: &mut BytesMut,
        connect_packet: ConnectPacketInput,
    ) -> Result<()> {
        buf.reserve(ConnectPacket::encoded_len());

        let mut packet = buf.split_off(buf.len());

        packet.put_u8(ConnectionPacketType::Connect as u8);
        packet.put_u16(self.protocol_version);
        packet.put_u32(connect_packet.src_connection_id);
        packet.put_slice(&connect_packet.static_public_key.to_bytes());

        if self.crypto.is_some() {
            let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
            let ephemeral_public_key = PublicKey::from(&ephemeral_secret);

            packet.put_slice(&ephemeral_public_key.to_bytes());
        }

        let signature = self.static_secret.sign(&packet);

        packet.put_slice(&signature.to_bytes());

        buf.advance(packet.len());

        Ok(())
    }

    fn encode_accept_packet(
        &mut self,
        buf: &mut BytesMut,
        accept_packet: AcceptPacketInput,
    ) -> Result<()> {
        buf.reserve(AcceptPacket::encoded_len());

        let mut packet = buf.split_off(buf.len());

        packet.put_u8(ConnectionPacketType::Accept as u8);
        packet.put_u16(self.protocol_version);
        packet.put_u32(accept_packet.dst_connection_id);
        packet.put_u32(accept_packet.src_connection_id);
        packet.put_slice(&accept_packet.static_public_key.to_bytes());

        if self.crypto.is_some() {
            let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
            let ephemeral_public_key = PublicKey::from(&ephemeral_secret);

            packet.put_slice(&ephemeral_public_key.to_bytes());
        }

        let signature = self.static_secret.sign(&packet);

        packet.put_slice(&signature.to_bytes());

        buf.advance(packet.len());

        Ok(())
    }

    fn encode_reject_packet(
        &mut self,
        buf: &mut BytesMut,
        reject_packet: RejectPacketInput,
    ) -> Result<()> {
        buf.reserve(RejectPacket::encoded_len());

        let mut packet = buf.split_off(buf.len());

        packet.put_u8(ConnectionPacketType::Reject as u8);
        packet.put_u32(reject_packet.dst_connection_id);
        packet.put_u8(reject_packet.reason_code as u8);
        packet.put_slice(&reject_packet.static_public_key.to_bytes());

        let signature = self.static_secret.sign(&packet);

        packet.put_slice(&signature.to_bytes());

        buf.advance(packet.len());

        Ok(())
    }
}
