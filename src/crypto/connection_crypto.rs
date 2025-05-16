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
}
