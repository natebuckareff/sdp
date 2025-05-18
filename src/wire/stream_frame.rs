use anyhow::{Result, anyhow};

#[repr(u8)]
pub enum StreamFramePacketType {
    Start = 0x00,
    Data = 0x01,
    Datagram = 0x02,
    Message = 0x03,
    FinalMessage = 0x04,
    End = 0x05,
}

impl TryFrom<u8> for StreamFramePacketType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(StreamFramePacketType::Start),
            0x01 => Ok(StreamFramePacketType::Data),
            0x02 => Ok(StreamFramePacketType::Datagram),
            0x03 => Ok(StreamFramePacketType::Message),
            0x04 => Ok(StreamFramePacketType::FinalMessage),
            0x05 => Ok(StreamFramePacketType::End),
            _ => Err(anyhow!("invalid stream frame packet type")),
        }
    }
}

pub enum StreamFrameInput {
    Start(StartInput),
    Transmission(TransmissionInput),
    End,
}

pub struct StartInput {
    pub stream_flags: StreamFlags,
    pub transmission: Option<TransmissionInput>,
}

pub enum TransmissionInput {
    Data,
    Datagram,
    Message(StreamMessage),
    FinalMessage(StreamMessage),
}

pub enum StreamFrame {
    Start(StreamStart),
    Transmission(StreamTransmission),
    End,
}

pub struct StreamStart {
    pub stream_flags: StreamFlags,
    pub transmission: Option<StreamTransmission>,
}

impl StreamStart {
    pub fn encoded_len() -> usize {
        std::mem::size_of::<u8>() // packet_type
        + std::mem::size_of::<u8>() // stream_flags
    }
}

#[repr(u8)]
pub enum StreamFlags {
    Ordered = 0b01000000,
    DatagramReliable = 0b10000000,
    DatagramUnreliable = 0b10000001,
    Message = 0b11000000,
}

impl From<u8> for StreamFlags {
    fn from(value: u8) -> Self {
        todo!()
    }
}

pub enum StreamTransmission {
    Data,
    Datagram,
    Message(StreamMessage),
    FinalMessage(StreamMessage),
}

pub struct StreamMessage {
    pub id: u64,
    pub offset: u64,
}

impl StreamMessage {
    pub fn encoded_len() -> usize {
        std::mem::size_of::<u8>() // packet_type
        + std::mem::size_of::<u64>() // id
        + std::mem::size_of::<u64>() // offset
    }
}
