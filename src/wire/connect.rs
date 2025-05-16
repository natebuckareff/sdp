use anyhow::Result;
use bytes::BytesMut;
use ed25519_dalek::VerifyingKey;
use x25519_dalek::PublicKey;

pub struct ConnectPacket {
    pub connection_id: u32,
    pub static_public_key: VerifyingKey,
    pub ephemeral_public_key: Option<PublicKey>,
}

impl ConnectPacket {
    fn encode(
        buf: &mut BytesMut,
        connection_id: u32,
        static_public_key: VerifyingKey,
        ephemeral_public_key: Option<PublicKey>,
    ) -> Result<()> {
        todo!()
    }

    fn decode(buf: &mut BytesMut) -> Result<ConnectPacket> {
        todo!()
    }
}
