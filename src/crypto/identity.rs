use anyhow::Result;
use bytes::BytesMut;
use pqcrypto::sign::mldsa65;

pub struct Identity {
    classical: Option<ed25519_dalek::SigningKey>,
    post_quantum: Option<(mldsa65::PublicKey, mldsa65::SecretKey)>,
}

impl Identity {
    pub fn new(
        classical: Option<ed25519_dalek::SigningKey>,
        post_quantum: Option<(mldsa65::PublicKey, mldsa65::SecretKey)>,
    ) -> Self {
        Self {
            classical,
            post_quantum,
        }
    }

    pub fn classical_secret_key(&self) -> Option<&ed25519_dalek::SigningKey> {
        self.classical.as_ref()
    }

    pub fn post_quantum_key_pair(&self) -> Option<(&mldsa65::PublicKey, &mldsa65::SecretKey)> {
        self.post_quantum.as_ref().map(|(pk, sk)| (pk, sk))
    }

    pub fn sign(&self, message: &[u8], signature: &mut BytesMut) -> Result<()> {
        todo!()
    }
}

pub struct PublicIdentity {
    classical: Option<ed25519_dalek::VerifyingKey>,
    post_quantum: Option<mldsa65::PublicKey>,
}

impl From<Identity> for PublicIdentity {
    fn from(identity: Identity) -> Self {
        Self {
            classical: identity.classical.map(|sk| sk.verifying_key()),
            post_quantum: identity.post_quantum.map(|(pk, _)| pk),
        }
    }
}

impl From<(ed25519_dalek::VerifyingKey, mldsa65::PublicKey)> for PublicIdentity {
    fn from((classical, post_quantum): (ed25519_dalek::VerifyingKey, mldsa65::PublicKey)) -> Self {
        Self {
            classical: Some(classical),
            post_quantum: Some(post_quantum),
        }
    }
}

impl PublicIdentity {
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        todo!()
    }
}
