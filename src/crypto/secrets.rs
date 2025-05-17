use anyhow::Result;
use bytes::BytesMut;
use chacha20poly1305::Nonce;
use x25519_dalek::EphemeralSecret;
use zeroize::Zeroizing;

use crate::protocol::{ConnectionBond, Side};

const CONNECTION_SECRET_LEN: usize = 32;
const HEADER_SECRET_LEN: usize = 32;
const STREAM_SECRET_LEN: usize = 32;
const STATIC_IV_LEN: usize = 12;

pub struct ConnectionSecret {
    secret: Zeroizing<[u8; CONNECTION_SECRET_LEN]>,
}

impl ConnectionSecret {
    pub fn new(ephemeral_secret: &EphemeralSecret, side: Side, bond: &ConnectionBond) -> Self {
        todo!()
    }

    pub fn len(&self) -> usize {
        CONNECTION_SECRET_LEN
    }

    pub fn derive_header_secret(&self) -> HeaderSecret {
        todo!()
    }

    pub fn derive_stream_secret(&self, stream_id: u32) -> StreamSecret {
        todo!()
    }
}

pub struct HeaderSecret {
    side: Side,
    secret: Zeroizing<[u8; HEADER_SECRET_LEN]>,
}

impl HeaderSecret {
    pub fn mask_header(&self, buf: &mut [u8], header_len: usize) -> Result<()> {
        // Expects `header || ciphertext`
        // Will sample N bytes from ciphertext, encrypt, and mask with XOR
        todo!()
    }
}

pub struct StreamSecret {
    side: Side,
    stream_id: u32,
    secret: Zeroizing<[u8; STREAM_SECRET_LEN]>,
}

impl StreamSecret {
    pub fn rekey(&mut self) {
        todo!()
    }

    pub fn derive_stativ_iv(&self) -> StaticIv {
        todo!()
    }

    pub fn derive_aead_key(&self) -> AeadKey {
        todo!()
    }
}

pub struct StaticIv {
    secret: Zeroizing<[u8; STATIC_IV_LEN]>,
}

impl StaticIv {
    pub fn derive_nonce(&self, packet_number: u64) -> Nonce {
        let mut padded_packet_number = [0u8; STATIC_IV_LEN];
        let packet_number_bytes = packet_number.to_be_bytes();

        // Copy packet_number_bytes to the end of padded_packet_number
        // packet_number_bytes is 8 bytes, STATIC_IV_LEN is 12 bytes.
        // So, the first 4 bytes of padded_packet_number remain 0.
        padded_packet_number[STATIC_IV_LEN - packet_number_bytes.len()..]
            .copy_from_slice(&packet_number_bytes);

        // XOR in-place
        for i in 0..STATIC_IV_LEN {
            padded_packet_number[i] ^= self.secret[i];
        }

        Nonce::from(padded_packet_number)
    }
}

pub struct AeadKey {
    cipher: chacha20poly1305::ChaCha20Poly1305,
}

impl AeadKey {
    pub fn encrypt(&self, nonce: chacha20poly1305::Nonce, plaintext: &mut [u8]) -> Result<()> {
        // Encrypt in-place
        todo!()
    }

    pub fn decrypt(&self, nonce: chacha20poly1305::Nonce, ciphertext: &mut [u8]) -> Result<()> {
        todo!()
    }
}
