use std::fmt::{self, Display};

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Side {
    Send,
    Recv,
}

impl Display for Side {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Side::Send => write!(f, "send"),
            Side::Recv => write!(f, "recv"),
        }
    }
}

pub struct ConnectionBond {
    send: SendId,
    recv: RecvId,
}

impl ConnectionBond {
    pub fn new(send: SendId, recv: RecvId) -> Self {
        Self { send, recv }
    }

    pub fn get_connection_id(&self, side: Side) -> u32 {
        match side {
            Side::Send => self.send.0,
            Side::Recv => self.recv.0,
        }
    }

    pub fn send(&self) -> &SendId {
        &self.send
    }

    pub fn recv(&self) -> &RecvId {
        &self.recv
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SendId(u32);

impl SendId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }
}

impl Into<u32> for SendId {
    fn into(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecvId(u32);

impl RecvId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }
}

impl Into<u32> for RecvId {
    fn into(self) -> u32 {
        self.0
    }
}
