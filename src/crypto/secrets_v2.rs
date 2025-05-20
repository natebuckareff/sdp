use anyhow::{Context, Result, anyhow};
use bytes::BytesMut;
use pqcrypto::kem::mlkem768;
use pqcrypto::traits::kem::SharedSecret as _;
use x25519_dalek;
use zeroize::Zeroizing;

use crate::protocol::Side;

use super::identity::Identity;

fn hkdf_expand<const N: usize>(ikm: &[u8], label: &str) -> Result<Zeroizing<[u8; N]>> {
    let mut okm = Zeroizing::new([0u8; N]);
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, ikm);
    hkdf.expand(label.as_bytes(), okm.as_mut_slice())
        .map_err(|_| anyhow!("failed to derive key"))?;
    Ok(okm)
}

pub struct ConnectionSecretBuilder {
    side: Option<Side>,
    c_sk: Option<x25519_dalek::EphemeralSecret>,
    c_pk: Option<x25519_dalek::PublicKey>,
    pq_sk: Option<mlkem768::SecretKey>,
    pq_ct: Option<mlkem768::Ciphertext>,
}

impl ConnectionSecretBuilder {
    fn new() -> Self {
        Self {
            side: None,
            c_sk: None,
            c_pk: None,
            pq_sk: None,
            pq_ct: None,
        }
    }

    pub fn set_side(mut self, side: Side) -> Self {
        self.side = Some(side);
        self
    }

    pub fn set_ephemeral_secret(mut self, ephemeral_secret: x25519_dalek::EphemeralSecret) -> Self {
        self.c_sk = Some(ephemeral_secret);
        self
    }

    pub fn set_ephemeral_public_key(mut self, public_key: x25519_dalek::PublicKey) -> Self {
        self.c_pk = Some(public_key);
        self
    }

    pub fn set_post_quantum_secret_key(mut self, secret_key: mlkem768::SecretKey) -> Self {
        self.pq_sk = Some(secret_key);
        self
    }

    pub fn set_post_quantum_ciphertext(mut self, ciphertext: mlkem768::Ciphertext) -> Self {
        self.pq_ct = Some(ciphertext);
        self
    }

    pub fn build(self) -> Result<ConnectionSecret> {
        let Some(side) = self.side else {
            return Err(anyhow!("side not set"));
        };

        let mut has_classical = false;
        let mut has_post_quantum = false;
        let mut shared_secret = Zeroizing::new([0u8; 64]);

        if let (Some(c_sk), Some(c_pk)) = (self.c_sk, self.c_pk) {
            let c_shared_secret = c_sk.diffie_hellman(&c_pk);
            shared_secret.copy_from_slice(c_shared_secret.as_bytes());
            has_classical = true;
        };

        if let (Some(pq_sk), Some(pq_ct)) = (self.pq_sk, self.pq_ct) {
            let pq_shared_secret = mlkem768::decapsulate(&pq_ct, &pq_sk);
            shared_secret[32..].copy_from_slice(pq_shared_secret.as_bytes());
            has_post_quantum = true;
        };

        let ss = match (has_classical, has_post_quantum) {
            (true, true) => shared_secret.as_ref(),
            (true, false) => &shared_secret[..32],
            (false, true) => &shared_secret[32..],
            (false, false) => {
                return Err(anyhow!("no classical or post-quantum secrets set"));
            }
        };

        ConnectionSecret::create(side, ss)
    }
}

#[derive(Clone)]
pub struct ConnectionSecret {
    side: Side,
    secret: Zeroizing<[u8; 32]>,
    phase: i32,
}

impl ConnectionSecret {
    pub fn new() -> ConnectionSecretBuilder {
        ConnectionSecretBuilder::new()
    }

    fn create(side: Side, ikm: &[u8]) -> Result<Self> {
        let label = format!("sdp connection 0 {}", side);
        let secret = hkdf_expand(ikm, &label)?;
        Ok(Self {
            side,
            secret,
            phase: 0,
        })
    }

    pub fn side(&self) -> Side {
        self.side
    }

    pub fn phase(&self) -> i32 {
        self.phase
    }

    pub fn increment_phase(&mut self) -> Result<()> {
        if self.phase >= 1 << 30 {
            return Err(anyhow!("phase overflow"));
        }
        self.phase += 1;
        let label = format!("sdp connection {} {}", self.phase, self.side);
        self.secret = hkdf_expand(self.secret.as_ref(), &label)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct HeaderSecret {
    side: Side,
    key: chacha20::Key,
}

impl HeaderSecret {
    fn new(side: Side, connection_secret: &ConnectionSecret) -> Result<Self> {
        let label = format!("sdp header {} {}", connection_secret.phase(), side);
        let secret = hkdf_expand::<32>(connection_secret.secret.as_ref(), &label)?;
        let key = chacha20::Key::from(*secret);
        Ok(Self { side, key })
    }

    pub fn side(&self) -> Side {
        self.side
    }

    pub fn apply_header_mask<const N: usize>(
        &self,
        header_bytes: &mut [u8; N],
        ciphertext: &[u8],
    ) -> Result<()> {
        use chacha20::cipher::KeyIvInit;
        use chacha20::cipher::StreamCipher;

        let mut header_mask = [0u8; N];
        let nonce: &[u8; 12] = &ciphertext[..12]
            .try_into()
            .context("invalid ciphertext sample length")?;

        let mut cipher = chacha20::ChaCha20::new(&self.key, nonce.into());
        cipher.apply_keystream(&mut header_mask);

        for (header_byte, mask_byte) in header_bytes.iter_mut().zip(header_mask.iter()) {
            *header_byte ^= mask_byte;
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct StaticIv {
    secret: Zeroizing<[u8; 12]>,
}

impl StaticIv {
    fn new(side: Side, connection_secret: &ConnectionSecret) -> Result<Self> {
        let label = format!("sdp iv {} {}", connection_secret.phase(), side);
        let secret = hkdf_expand::<12>(connection_secret.secret.as_ref(), &label)?;
        Ok(Self { secret })
    }

    pub fn derive_nonce(&self, packet_number: u64) -> chacha20::Nonce {
        let mut padded_packet_number = [0u8; 12];
        padded_packet_number[8..].copy_from_slice(&packet_number.to_be_bytes());

        for i in 0..12 {
            padded_packet_number[i] ^= self.secret[i];
        }

        chacha20::Nonce::from(padded_packet_number)
    }
}

#[derive(Clone)]
pub struct StreamKey {
    cipher: chacha20poly1305::ChaCha20Poly1305,
}

impl StreamKey {
    fn new(side: Side, connection_secret: &ConnectionSecret) -> Result<Self> {
        use aead::KeyInit;

        let label = format!("sdp stream {} {}", connection_secret.phase(), side);
        let secret = hkdf_expand::<32>(connection_secret.secret.as_ref(), &label)?;
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(&(*secret).into());
        Ok(Self { cipher })
    }

    pub fn encrypt(
        &mut self,
        nonce: chacha20poly1305::Nonce,
        header: &[u8],
        plaintext: &mut BytesMut,
    ) -> Result<()> {
        use aead::AeadInPlace;
        plaintext.reserve(16);
        self.cipher.encrypt_in_place(&nonce, header, plaintext)?;
        Ok(())
    }

    pub fn decrypt(
        &mut self,
        nonce: chacha20poly1305::Nonce,
        header: &[u8],
        ciphertext: &mut BytesMut,
    ) -> Result<()> {
        use aead::AeadInPlace;
        self.cipher.decrypt_in_place(&nonce, header, ciphertext)?;
        Ok(())
    }
}
