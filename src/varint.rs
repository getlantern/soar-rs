//! QUIC variable-length integers (RFC 9000 §16): 1, 2, 4 or 8 bytes, length in the top two bits.

use crate::Error;

pub fn len(v: u64) -> usize {
    match v {
        0..0x40 => 1,
        0x40..0x4000 => 2,
        0x4000..0x4000_0000 => 4,
        _ => 8,
    }
}

pub fn put(b: &mut Vec<u8>, v: u64) {
    match len(v) {
        1 => b.push(v as u8),
        2 => b.extend_from_slice(&(v as u16 | 0x4000).to_be_bytes()),
        4 => b.extend_from_slice(&(v as u32 | 0x8000_0000).to_be_bytes()),
        _ => b.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes()),
    }
}

/// Reader consumes a byte slice.
pub struct Reader<'a> {
    pub b: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Reader { b }
    }

    pub fn varint(&mut self) -> Result<u64, Error> {
        let first = *self.b.first().ok_or(Error::Short)?;
        let n = 1 << (first >> 6);
        let bytes = self.bytes(n)?;
        Ok(bytes[1..]
            .iter()
            .fold(u64::from(first & 0x3F), |v, &c| v << 8 | u64::from(c)))
    }

    pub fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.bytes(1)?[0])
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.b.len() < n {
            return Err(Error::Short);
        }
        let (head, rest) = self.b.split_at(n);
        self.b = rest;
        Ok(head)
    }
}
