use anyhow::Result;
use bytes::BytesMut;

use crate::protocol::{ConnectionBond, Side};

use super::{
    ConnectionCrypto,
    secrets::{AeadKey, StaticIv, StreamSecret},
};

pub struct SessionCrypto {
    connection_crypto: ConnectionCrypto,
    stream_secret: StreamSecret,
    static_iv: StaticIv,
    aead_key: AeadKey,
    counter: u64,
}

impl SessionCrypto {
    pub fn new(side: Side, bond: ConnectionBond) -> Self {
        todo!()
    }

    pub fn rekey(&mut self) {
        self.stream_secret.rekey();
        self.static_iv = self.stream_secret.derive_stativ_iv();
        self.aead_key = self.stream_secret.derive_aead_key();
        self.counter = 0;
    }

    pub fn encrypt(&self, buf: &BytesMut) -> Result<()> {
        todo!()
    }

    pub fn decrypt(&self, buf: &BytesMut) -> Result<()> {
        todo!()
    }
}
