use anyhow::{Context, Result};
use bytes::BytesMut;

use crate::protocol::{ConnectionBond, Side};

use super::{
    ConnectionCrypto,
    secrets::{AeadKey, HeaderSecret, StaticIv, StreamSecret},
};

const PACKET_NUMBER_ROLLOVER: u64 = 1 << 62;

struct StreamCoreCrypto {
    header_secret: HeaderSecret,
    stream_secret: StreamSecret,
    static_iv: StaticIv,
    aead_key: AeadKey,
    counter: u64,
}

impl StreamCoreCrypto {
    pub fn new(side: Side, bond: ConnectionBond) -> Self {
        todo!()
    }

    fn packet_number(&self) -> u64 {
        self.counter
    }

    fn rekey(&mut self) {
        self.stream_secret.rekey();
        self.static_iv = self.stream_secret.derive_stativ_iv();
        self.aead_key = self.stream_secret.derive_aead_key();
        self.counter = 0;
    }

    fn encrypt(&mut self, buf: &mut BytesMut, partial_header_len: usize) -> Result<()> {
        // Expected buf format: partial_header || zeroed_packet_number || plaintext
        // plaintext_len = buf.len() - (partial_header_len + 8)

        // Rekey if the counter should rollover
        if self.counter >= PACKET_NUMBER_ROLLOVER {
            self.rekey();
        }

        let header_len = partial_header_len + 8;

        if buf.len() < header_len {
            return Err(anyhow::anyhow!("buffer length smaller than header length"));
        }

        // Copy the packet number after the header
        let counter_bytes = self.counter.to_be_bytes();
        buf[partial_header_len..header_len].copy_from_slice(&counter_bytes);

        let nonce = self.static_iv.derive_nonce(self.counter);
        let mut plaintext_buf = buf.split_off(header_len);
        let associated_data = &buf[..header_len];

        // Encrypt in-place and append auth tag
        self.aead_key
            .encrypt(nonce, associated_data, &mut plaintext_buf)
            .context("encryption failed")?;

        // Mask the header after using as associated data
        self.header_secret
            .apply_header_mask(&mut buf[..header_len], &plaintext_buf)
            .context("failed to mask header")?;

        self.counter += 1;

        Ok(())
    }

    fn decrypt(&mut self, buf: &mut BytesMut, partial_header_len: usize) -> Result<()> {
        // Expected buf format: masked(partial_header || packet_number) || ciphertext
        // ciphertext_len = buf.len() - (partial_header_len + 8)
        // plaintext_len = ciphertext_len - TAG_LEN
        // TAG_LEN bytes will be removed from buf by truncation

        // Rekey if the counter should rollover
        if self.counter >= PACKET_NUMBER_ROLLOVER {
            self.rekey();
        }

        let header_len = partial_header_len + 8;

        if buf.len() < header_len {
            return Err(anyhow::anyhow!("buffer length smaller than header length"));
        }

        let mut header_buf = buf.split_to(header_len);

        // Unmask the header
        self.header_secret
            .apply_header_mask(&mut header_buf, buf)
            .context("failed to unmask header")?;

        let packet_number = u64::from_be_bytes(header_buf[partial_header_len..].try_into()?);
        let nonce = self.static_iv.derive_nonce(packet_number);

        if packet_number != self.counter {
            return Err(anyhow::anyhow!("packet number mismatch"));
        }

        self.aead_key
            .decrypt(nonce, &header_buf, buf)
            .context("decryption failed")?;

        self.counter += 1;

        if self.counter >= PACKET_NUMBER_ROLLOVER {
            self.rekey();
        }

        Ok(())
    }
}

pub struct StreamEncryptor {
    core_crypto: StreamCoreCrypto,
}

impl StreamEncryptor {
    pub fn new(side: Side, bond: ConnectionBond) -> Self {
        Self {
            core_crypto: StreamCoreCrypto::new(side, bond),
        }
    }

    pub fn encrypt(&mut self, buf: &mut BytesMut, partial_header_len: usize) -> Result<()> {
        self.core_crypto.encrypt(buf, partial_header_len)
    }
}

pub struct StreamDecryptor {
    core_crypto: StreamCoreCrypto,
}

impl StreamDecryptor {
    pub fn new(side: Side, bond: ConnectionBond) -> Self {
        Self {
            core_crypto: StreamCoreCrypto::new(side, bond),
        }
    }

    pub fn decrypt(&mut self, buf: &mut BytesMut, partial_header_len: usize) -> Result<()> {
        self.core_crypto.decrypt(buf, partial_header_len)
    }
}
