use anyhow::Result;
use bytes::BytesMut;
use ed25519_dalek::{Signature, VerifyingKey};
use x25519_dalek::PublicKey;

pub struct ConnectPacket {
    pub protocol_version: u16,
    pub connection_id: u32,
    pub static_public_key: VerifyingKey,
    pub ephemeral_public_key: Option<PublicKey>, // Keep as Option for WebRTC case
    pub signature: Signature,
}

impl ConnectPacket {
    fn encode(
        buf: &mut BytesMut,
        connection_id: u32,
        static_public_key: VerifyingKey,
        ephemeral_public_key: Option<PublicKey>,
        signature: Signature,
    ) -> Result<()> {
        todo!()
    }

    fn decode(buf: &mut BytesMut) -> Result<ConnectPacket> {
        todo!()
    }
}
