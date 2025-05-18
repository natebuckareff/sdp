use anyhow::{Result, anyhow};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, Signature, VerifyingKey};
use x25519_dalek::PublicKey;

use crate::crypto::HeaderSecret;

pub struct ConnectionFrameCrypto {
    pub header_secret: HeaderSecret,
}

#[repr(u8)]
pub enum ConnectionPacketType {
    Connect = 0x00,
    Accept = 0x01,
    Reject = 0x02,
    StreamHeader = 0x03,
}

impl TryFrom<u8> for ConnectionPacketType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(ConnectionPacketType::Connect),
            0x01 => Ok(ConnectionPacketType::Accept),
            0x02 => Ok(ConnectionPacketType::Reject),
            0x03 => Ok(ConnectionPacketType::StreamHeader),
            _ => Err(anyhow!("invalid connection packet type")),
        }
    }
}

pub enum ConnectionFrameInput {
    Connect(ConnectPacketInput),
    Accept(AcceptPacketInput),
    Reject(RejectPacketInput),
}

pub struct ConnectPacketInput {
    pub src_connection_id: u32,
    pub static_public_key: VerifyingKey,
}

pub struct AcceptPacketInput {
    pub dst_connection_id: u32,
    pub src_connection_id: u32,
    pub static_public_key: VerifyingKey,
}

pub struct RejectPacketInput {
    pub dst_connection_id: u32,
    pub reason_code: RejectReason,
    pub static_public_key: VerifyingKey,
}

pub enum ConnectionFrame {
    Connect(ConnectPacket),
    Accept(AcceptPacket),
    Reject(RejectPacket),
    StreamHeader(StreamHeader),
}

pub struct ConnectPacket {
    pub protocol_version: u16,
    pub src_connection_id: u32,
    pub static_public_key: VerifyingKey,
    pub ephemeral_public_key: Option<PublicKey>,
    pub signature: Signature,
}

impl ConnectPacket {
    pub fn encoded_len() -> usize {
        std::mem::size_of::<u8>() // packet_type
        + std::mem::size_of::<u16>() // protocol_version
        + std::mem::size_of::<u32>() // dst_connection_id
        + std::mem::size_of::<u32>() // src_connection_id
        + PUBLIC_KEY_LENGTH // static_public_key
        + PUBLIC_KEY_LENGTH // ephemeral_public_key
        + SIGNATURE_LENGTH // signature
    }
}

pub struct AcceptPacket {
    pub protocol_version: u16,
    pub dst_connection_id: u32,
    pub src_connection_id: u32,
    pub static_public_key: VerifyingKey,
    pub ephemeral_public_key: Option<PublicKey>,
    pub signature: Signature,
}

impl AcceptPacket {
    pub fn encoded_len() -> usize {
        std::mem::size_of::<u8>() // packet_type
        + std::mem::size_of::<u16>() // protocol_version
        + std::mem::size_of::<u32>() // dst_connection_id
        + std::mem::size_of::<u32>() // src_connection_id
        + PUBLIC_KEY_LENGTH // static_public_key
        + PUBLIC_KEY_LENGTH // ephemeral_public_key
        + SIGNATURE_LENGTH // signature
    }
}

pub struct RejectPacket {
    pub dst_connection_id: u32,
    pub reason_code: RejectReason,
    pub static_public_key: VerifyingKey,
    pub signature: Signature,
}

impl RejectPacket {
    pub fn encoded_len() -> usize {
        std::mem::size_of::<u8>() // packet_type
        + std::mem::size_of::<u32>() // dst_connection_id
        + std::mem::size_of::<u8>() // reason_code
        + PUBLIC_KEY_LENGTH // static_public_key
        + SIGNATURE_LENGTH // signature
    }
}

#[repr(u8)]
pub enum RejectReason {
    Unspecified = 0x00,
    ProtocolVersionMismatch = 0x01,
    PublicKeyDenied = 0x02,
}

impl TryFrom<u8> for RejectReason {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(RejectReason::Unspecified),
            0x01 => Ok(RejectReason::ProtocolVersionMismatch),
            0x02 => Ok(RejectReason::PublicKeyDenied),
            _ => Err(anyhow!("invalid reject reason code")),
        }
    }
}

pub struct StreamHeader {
    pub dst_connection_id: u32,
    pub stream_id: u32,
    pub packet_number: u64,
}

impl StreamHeader {
    pub fn encoded_len() -> usize {
        std::mem::size_of::<u8>() // packet_type
        + std::mem::size_of::<u32>() // dst_connection_id
        + Self::encoded_masked_len()
    }

    pub fn encoded_masked_len() -> usize {
        std::mem::size_of::<u32>() // stream_id
        + std::mem::size_of::<u64>() // packet_number
    }
}
