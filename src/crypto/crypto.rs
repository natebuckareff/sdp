use x25519_dalek::EphemeralSecret;
use zeroize::Zeroizing;

pub const CONNECTION_SECRET_LEN: usize = 32;
pub const HEADER_SECRET_LEN: usize = 32;

pub struct ConnectionSecret {
    secret: Zeroizing<[u8; CONNECTION_SECRET_LEN]>,
}

impl ConnectionSecret {
    pub fn new() -> Self {
        todo!()
    }
}

pub struct ConnectionCrypto {
    shared_secret: EphemeralSecret,
    connection_secret: Zeroizing<[u8; CONNECTION_SECRET_LEN]>,
    header_secret: Zeroizing<[u8; CONNECTION_SECRET_LEN]>,
}

impl ConnectionCrypto {
    pub fn new() -> Self {
        todo!()
    }
}
