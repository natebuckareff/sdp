use anyhow::Result;
use bytes::BytesMut;
use ed25519_dalek::{Signature, VerifyingKey};
use x25519_dalek::PublicKey;

pub struct AcceptPacket {
    pub protocol_version: u16,
    pub connection_id: u32, // Consistent with ConnectPacket
    pub static_public_key: VerifyingKey,
    pub ephemeral_public_key: Option<PublicKey>, // Consistent with ConnectPacket, for WebRTC
    pub signature: Signature,
}

impl AcceptPacket {
    fn encode(
        buf: &mut BytesMut,
        connection_id: u32,
        static_public_key: VerifyingKey,
        ephemeral_public_key: Option<PublicKey>,
        signature: Signature,
    ) -> Result<()> {
        // Wire format:
        // protocol_version (using crate::protocol::constants::PROTOCOL_VERSION)
        // connection_id
        // static_public_key
        // ephemeral_public_key (optional)
        // signature
        // Implementation should use crate::protocol::constants::PROTOCOL_VERSION for the protocol_version field.
        todo!()
    }

    fn decode(buf: &mut BytesMut) -> Result<AcceptPacket> {
        // Decode logic here, will decode u16 for protocol_version.
        todo!()
    }
}
