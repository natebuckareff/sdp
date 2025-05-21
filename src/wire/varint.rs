use std::io::Cursor;

use anyhow::{Result, anyhow};
use bytes::{Buf, BufMut, BytesMut};

const MASK_6: u64 = 0xffffffffffffffc0;
const MASK_14: u64 = 0xffffffffffffc000;
const MASK_30: u64 = 0xffffffffc0000000;
const MASK_62: u64 = 0xc000000000000000;

pub struct Varint(u64);

impl TryInto<usize> for Varint {
    type Error = std::num::TryFromIntError;

    fn try_into(self) -> std::result::Result<usize, Self::Error> {
        self.0.try_into()
    }
}

impl Into<u64> for Varint {
    fn into(self) -> u64 {
        self.0
    }
}

impl Into<u64> for &Varint {
    fn into(self) -> u64 {
        self.0
    }
}

impl From<u64> for Varint {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl Varint {
    pub fn encode(&self, output: &mut BytesMut) -> Result<()> {
        if (self.0 & MASK_6) == 0 {
            output.put_u8((self.0 as u8) | 0b00 << (8 - 2));
        } else if (self.0 & MASK_14) == 0 {
            output.put_u16((self.0 as u16) | 0b01 << (8 * 2 - 2));
        } else if (self.0 & MASK_30) == 0 {
            output.put_u32((self.0 as u32) | 0b10 << (8 * 4 - 2));
        } else if (self.0 & MASK_62) == 0 {
            output.put_u64((self.0 as u64) | 0b11 << (8 * 8 - 2));
        } else {
            return Err(anyhow!("value too large for varint"));
        }
        Ok(())
    }

    pub fn decode(input: &mut BytesMut) -> Self {
        let most_significant_byte = {
            let mut cursor = Cursor::new(&input);
            cursor.get_u8()
        };
        let mode = (most_significant_byte & 0b11000000) >> 6;
        match mode {
            0b00 => Varint((input.get_u8() & 0x3f) as u64),
            0b01 => Varint((input.get_u16() & 0x3fff) as u64),
            0b10 => Varint((input.get_u32() & 0x3fffffff) as u64),
            0b11 => Varint((input.get_u64() & 0x3fffffffffffffff) as u64),
            _ => unreachable!(),
        }
    }
}
