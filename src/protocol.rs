pub const PROTOCOL_VERSION: u16 = 1;

pub enum Side {
    Send,
    Recv,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecvId(u32);

impl RecvId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }
}
