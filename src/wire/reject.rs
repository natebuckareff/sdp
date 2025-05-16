use anyhow::Result;
use bytes::BytesMut;

pub type ErrorCode = u16; // Placeholder for ErrorCode type

pub struct RejectPacket {
    pub connection_id: u32, // Consistent with ConnectPacket
    pub error_code: ErrorCode,
}

impl RejectPacket {
    fn encode(buf: &mut BytesMut, connection_id: u32, error_code: ErrorCode) -> Result<()> {
        // Wire format:
        // connection_id
        // error_code
        todo!()
    }

    fn decode(buf: &mut BytesMut) -> Result<RejectPacket> {
        // Decode logic here
        todo!()
    }
}
