use anyhow::Result;
use bytes::BytesMut;
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
    pub fn mask_header(&self, header: &BytesMut, ciphertext: &[u8]) -> Result<()> {
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
    pub fn derive_nonce(&self, packet_number: u64) -> () {
        // TODO: return type
        todo!()
    }
}

pub struct AeadKey {
    cipher: chacha20poly1305::ChaCha20Poly1305,
}

impl AeadKey {
    pub fn encrypt(&self, nonce: chacha20poly1305::Nonce, plaintext: &BytesMut) -> Result<()> {
        todo!()
    }

    pub fn decrypt(&self, nonce: chacha20poly1305::Nonce, ciphertext: &BytesMut) -> Result<()> {
        todo!()
    }
}
