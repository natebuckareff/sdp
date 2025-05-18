use anyhow::Result;

use crate::protocol::{ConnectionBond, Side};

use super::secrets::{ConnectionSecret, HeaderSecret};

pub struct ConnectionCrypto {
    side: Side,
    connection_bond: ConnectionBond,
    connection_secret: ConnectionSecret,
    header_secret: HeaderSecret,
}

impl ConnectionCrypto {
    pub fn new(side: Side, bond: ConnectionBond) -> Self {
        todo!()
    }

    pub fn get_header_secret(&self) -> &HeaderSecret {
        &self.header_secret
    }

    pub fn apply_header_mask(&mut self, header_bytes: &mut [u8], ciphertext: &[u8]) -> Result<()> {
        self.header_secret
            .apply_header_mask(header_bytes, ciphertext)
    }
}
