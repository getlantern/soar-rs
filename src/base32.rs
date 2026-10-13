//! Unpadded lower-case base32 (RFC 4648 alphabet), as carried in query names (SPEC §3.1).

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

const REV: [u8; 256] = {
    let mut t = [0xFF; 256];
    let mut i = 0;
    while i < 32 {
        let c = ALPHABET[i];
        t[c as usize] = i as u8;
        if c.is_ascii_lowercase() {
            t[c.to_ascii_uppercase() as usize] = i as u8;
        }
        i += 1;
    }
    t
};

pub fn encoded_len(n: usize) -> usize {
    (n * 8).div_ceil(5)
}

pub fn encode(dst: &mut Vec<u8>, src: &[u8]) {
    let (mut acc, mut bits) = (0u64, 0u32);
    for &c in src {
        acc = acc << 8 | u64::from(c);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            dst.push(ALPHABET[(acc >> bits) as usize & 0x1F]);
        }
    }
    if bits > 0 {
        dst.push(ALPHABET[(acc << (5 - bits)) as usize & 0x1F]);
    }
}

/// Decodes either letter case (resolvers may randomize it), dropping leftover bits. None if a
/// character is outside the alphabet.
pub fn decode(src: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(src.len() * 5 / 8);
    let (mut acc, mut bits) = (0u64, 0u32);
    for &c in src {
        let v = REV[c as usize];
        if v == 0xFF {
            return None;
        }
        acc = acc << 5 | u64::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}
