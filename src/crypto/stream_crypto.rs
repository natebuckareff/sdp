use anyhow::Result;
use bytes::BytesMut;

use crate::protocol::{ConnectionBond, Side};

use super::{
    ConnectionCrypto,
    secrets::{AeadKey, HeaderSecret, StaticIv, StreamSecret},
};

const PACKET_NUMBER_ROLLOVER: u64 = 1 << 62;

pub struct StreamCrypto {
    header_secret: HeaderSecret,
    stream_secret: StreamSecret,
    static_iv: StaticIv,
    aead_key: AeadKey,
    counter: u64,
}

impl StreamCrypto {
    pub fn new(side: Side, bond: ConnectionBond) -> Self {
        todo!()
    }

    pub fn packet_number(&self) -> u64 {
        self.counter
    }

    pub fn rekey(&mut self) {
        self.stream_secret.rekey();
        self.static_iv = self.stream_secret.derive_stativ_iv();
        self.aead_key = self.stream_secret.derive_aead_key();
        self.counter = 0;
    }

    pub fn encrypt(&mut self, buf: &mut BytesMut, partial_header_len: usize) -> Result<()> {
        // Rekey if the counter should rollover
        if self.counter >= PACKET_NUMBER_ROLLOVER {
            self.rekey();
        }

        // Copy the packet number after the header
        let counter_bytes = self.counter.to_be_bytes();
        buf[partial_header_len..partial_header_len + 8].copy_from_slice(&counter_bytes);

        // Derive the nonce
        let nonce = self.static_iv.derive_nonce(self.counter);

        // Encrypt the plaintext in-place
        let _ = self
            .aead_key
            .encrypt(nonce, &mut buf[partial_header_len + 8..])?;

        // Mask the header
        self.header_secret
            .mask_header(&mut buf[..], partial_header_len + 8)?;

        self.counter += 1;

        Ok(())
    }

    pub fn decrypt(&mut self, buf: &mut BytesMut, partial_header_len: usize) -> Result<()> {
        // Expects: `masked(partial_header || packet_number) || ciphertext`
        // - Checks if `self.counter + 1 >= PACKET_NUMBER_ROLLOVER`
        //   - Rekeys
        // - Unmasks header
        // - Decodes packet number
        // - Compares decoded packet number to current counter
        // - Decrypts ciphertext in-place
        todo!()
    }
}
