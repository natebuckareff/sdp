use anyhow::{Context, Result};
use bytes::BytesMut;

use super::secrets::{AeadKey, HeaderSecret, StaticIv, StreamSecret};

const PACKET_NUMBER_ROLLOVER: u64 = 1 << 62;

#[derive(Clone)]
struct StreamCoreCrypto {
    stream_id: u32,
    header_secret: HeaderSecret,
    stream_secret: StreamSecret,
    static_iv: StaticIv,
    aead_key: AeadKey,
    counter: u64,
}

impl StreamCoreCrypto {
    pub fn new(
        stream_id: u32,
        header_secret: HeaderSecret,
        stream_secret: StreamSecret,
    ) -> Result<(StreamEncryptor, StreamDecryptor)> {
        assert!(stream_id == stream_secret.stream_id());
        let static_iv = stream_secret.derive_static_iv()?;
        let aead_key = stream_secret.derive_aead_key()?;
        let core_crypto = Self {
            stream_id,
            header_secret,
            stream_secret,
            static_iv,
            aead_key,
            counter: 0,
        };
        let encryptor = StreamEncryptor {
            core_crypto: core_crypto.clone(),
        };
        let decryptor = StreamDecryptor { core_crypto };
        Ok((encryptor, decryptor))
    }

    fn packet_number(&self) -> u64 {
        self.counter
    }

    fn rekey(&mut self) -> Result<()> {
        self.stream_secret.rekey()?;
        self.static_iv = self.stream_secret.derive_static_iv()?;
        self.aead_key = self.stream_secret.derive_aead_key()?;
        self.counter = 0;
        Ok(())
    }

    fn encrypt(&mut self, buf: &mut BytesMut, partial_header_len: usize) -> Result<()> {
        // Expected buf format: partial_header || zeroed_packet_number || plaintext
        // plaintext_len = buf.len() - (partial_header_len + 8)

        // Rekey if the counter should rollover
        if self.counter >= PACKET_NUMBER_ROLLOVER {
            self.rekey().context("failed to rekey")?;
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

        // Append the encrypted payload (ciphertext + tag) back to the main buffer
        buf.unsplit(plaintext_buf);

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
            self.rekey().context("failed to rekey")?;
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
            self.rekey().context("failed to rekey")?;
        }

        Ok(())
    }
}

pub struct StreamEncryptor {
    core_crypto: StreamCoreCrypto,
}

impl StreamEncryptor {
    pub fn encrypt(&mut self, buf: &mut BytesMut, partial_header_len: usize) -> Result<()> {
        self.core_crypto.encrypt(buf, partial_header_len)
    }
}

pub struct StreamDecryptor {
    core_crypto: StreamCoreCrypto,
}

impl StreamDecryptor {
    pub fn decrypt(&mut self, buf: &mut BytesMut, partial_header_len: usize) -> Result<()> {
        self.core_crypto.decrypt(buf, partial_header_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Side;
    use anyhow::Result;
    use bytes::BytesMut;
    use chacha20::Key as ChaChaKey;
    use zeroize::Zeroizing;
    // Import necessary items from the secrets module
    use crate::crypto::secrets::{
        HEADER_SECRET_LEN, HeaderSecret, STREAM_SECRET_LEN, StreamSecret, TAG_LEN,
    };

    fn setup_crypto_direct(stream_id: u32) -> Result<(StreamEncryptor, StreamDecryptor)> {
        let side = Side::Send;

        let dummy_key_bytes = [0u8; HEADER_SECRET_LEN];
        let header_key = ChaChaKey::from_slice(&dummy_key_bytes);
        let header_secret = HeaderSecret::new(side, *header_key);

        let dummy_secret_bytes = Zeroizing::new([1u8; STREAM_SECRET_LEN]);
        // Assuming StreamSecret::new_for_test is available and pub(crate) in secrets.rs
        let stream_secret = StreamSecret::new_for_test(side, stream_id, dummy_secret_bytes);

        StreamCoreCrypto::new(stream_id, header_secret, stream_secret)
    }

    #[test]
    fn test_stream_encryptor_encrypts_successfully() -> Result<()> {
        let stream_id = 1;
        let (mut encryptor, _decryptor) = setup_crypto_direct(stream_id)?;

        const PARTIAL_HEADER_LEN: usize = 4;
        let mut buffer = BytesMut::new();
        buffer.extend_from_slice(&[0u8; PARTIAL_HEADER_LEN]);
        buffer.extend_from_slice(&[0u8; 8]); // Space for packet number
        let original_plaintext = b"hello world!!";
        buffer.extend_from_slice(original_plaintext);

        let header_and_pn_len = PARTIAL_HEADER_LEN + 8;
        let expected_ciphertext_len = header_and_pn_len + original_plaintext.len() + TAG_LEN;

        encryptor.encrypt(&mut buffer, PARTIAL_HEADER_LEN)?;

        assert_eq!(buffer.len(), expected_ciphertext_len);
        Ok(())
    }

    #[test]
    fn test_stream_decryptor_decrypts_successfully() -> Result<()> {
        let stream_id = 1;
        let (mut encryptor, mut decryptor) = setup_crypto_direct(stream_id)?;

        let partial_header_len = 4;
        let mut buffer = BytesMut::new();
        let partial_header_content = &[1, 2, 3, 4];
        buffer.extend_from_slice(partial_header_content);
        buffer.extend_from_slice(&[0u8; 8]); // Space for packet number

        let original_plaintext = b"secret message";
        buffer.extend_from_slice(original_plaintext);

        let mut encrypt_buffer = buffer.clone();

        encryptor.encrypt(&mut encrypt_buffer, partial_header_len)?;
        assert_ne!(encrypt_buffer.as_ref(), buffer.as_ref());

        let mut decrypt_buffer = encrypt_buffer.clone();
        decryptor.decrypt(&mut decrypt_buffer, partial_header_len)?;

        assert_eq!(decrypt_buffer.as_ref(), original_plaintext.as_ref());

        Ok(())
    }
}
