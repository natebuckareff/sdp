use anyhow::{Result, anyhow};
use bytes::BytesMut;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20poly1305::Nonce;
use chacha20poly1305::aead::AeadMutInPlace;
use x25519_dalek::EphemeralSecret;
use zeroize::Zeroizing;

use crate::protocol::{ConnectionBond, Side};

const CONNECTION_SECRET_LEN: usize = 32;
const HEADER_SECRET_LEN: usize = 32;
const STREAM_SECRET_LEN: usize = 32;
const STATIC_IV_LEN: usize = 12;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

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
    secret: Zeroizing<[u8; HEADER_SECRET_LEN]>, // remove?
    key: chacha20::Key,                         // XXX
    mask: Vec<u8>,
}

impl HeaderSecret {
    fn derive_mask(&mut self, header_len: usize, ciphertext: &[u8]) -> &[u8] {
        let nonce = Nonce::from_slice(&ciphertext[..NONCE_LEN]);
        let mut cipher = chacha20::ChaCha20::new(&self.key, nonce);

        self.mask.resize(header_len, 0);
        cipher.apply_keystream(&mut self.mask);

        &self.mask
    }

    pub fn apply_header_mask(&mut self, header_bytes: &mut [u8], ciphertext: &[u8]) -> Result<()> {
        if ciphertext.len() - TAG_LEN < NONCE_LEN {
            return Err(anyhow!(
                "ciphertext must at least as long as the nonce length"
            ));
        }

        let mask = self.derive_mask(header_bytes.len(), ciphertext);

        for (header_byte, mask_byte) in header_bytes.iter_mut().zip(mask.iter()) {
            *header_byte ^= *mask_byte;
        }

        Ok(())
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
    pub fn encrypt(
        &mut self,
        nonce: chacha20poly1305::Nonce,
        header: &[u8],
        plaintext: &mut BytesMut,
    ) -> Result<()> {
        plaintext.reserve(TAG_LEN);
        self.cipher.encrypt_in_place(&nonce, header, plaintext)?;
        Ok(())
    }

    pub fn decrypt(
        &mut self,
        nonce: chacha20poly1305::Nonce,
        header: &[u8],
        ciphertext: &mut BytesMut,
    ) -> Result<()> {
        // Expected ciphertext format: ciphertext || auth_tag
        // plaintext_len = ciphertext_len - TAG_LEN
        // ciphertext is truncated to plaintext_len
        self.cipher.decrypt_in_place(&nonce, header, ciphertext)?;
        Ok(())
    }
}
