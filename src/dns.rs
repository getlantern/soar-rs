//! The DNS carrier (SPEC §3): payloads in query names, and in TXT or numbered AAAA answers.

use crate::Error;
use crate::base32;

pub const TYPE_SOA: u16 = 6;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
const TYPE_OPT: u16 = 41;
const CLASS_IN: u16 = 1;
pub const HDR_LEN: usize = 12;
const MAX_LABEL: usize = 63;
/// The longest presentation-format name (RFC 1035: 255 wire bytes).
pub const MAX_NAME: usize = 253;

/// An AAAA record carries an index byte and 15 payload bytes: resolvers may shuffle an RRset and
/// drop duplicate records, so each is numbered (and so unique).
const AAAA_CHUNK: usize = 15;
const AAAA_RR_LEN: usize = 2 + 10 + 16;
const AAAA_MAX_RECS: usize = 255;

/// The UDP payload size advertised in every OPT record we send.
pub const EDNS_SIZE: u16 = 1232;

pub const RCODE_OK: u8 = 0;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_REFUSED: u8 = 5;

/// A tunnel domain, lower-cased, without the root label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    /// Length-prefixed labels, without the terminating root label.
    pub wire: Vec<u8>,
    pub text: String,
    labels: usize,
}

impl Zone {
    pub fn parse(s: &str) -> Result<Zone, Error> {
        let s = s.trim();
        let s = s.strip_suffix('.').unwrap_or(s).to_ascii_lowercase();
        if s.is_empty() {
            return Err(Error::Zone("empty zone"));
        }
        if !s.is_ascii() {
            return Err(Error::Zone("zone must be ASCII"));
        }
        let mut wire = Vec::with_capacity(s.len() + 1);
        let mut labels = 0;
        for l in s.split('.') {
            if l.is_empty() || l.len() > MAX_LABEL {
                return Err(Error::Zone("bad zone"));
            }
            wire.push(l.len() as u8);
            wire.extend_from_slice(l.as_bytes());
            labels += 1;
        }
        let z = Zone {
            wire,
            text: s,
            labels,
        };
        if z.max_payload(MAX_NAME) < 2 + 32 {
            return Err(Error::Zone("zone too long to carry a handshake"));
        }
        Ok(z)
    }

    /// How many bytes fit base32-encoded under the zone in a name of at most name_len
    /// presentation characters.
    pub fn max_payload(&self, name_len: usize) -> usize {
        // The dot before the zone.
        let Some(avail) = name_len.min(MAX_NAME).checked_sub(self.text.len() + 1) else {
            return 0;
        };
        // c chars need ceil(c/63)-1 separating dots.
        let mut c = avail;
        while c > 0 && c + (c - 1) / MAX_LABEL > avail {
            c -= 1;
        }
        c * 5 / 8
    }
}

/// Appends a query of qtype (TXT or AAAA) carrying payload under z.
pub fn put_query(b: &mut Vec<u8>, txn: u16, payload: &[u8], z: &Zone, qtype: u16, edns_size: u16) {
    b.extend_from_slice(&txn.to_be_bytes());
    b.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]); // RD; QD=1, AR=1
    let mut enc = Vec::with_capacity(base32::encoded_len(payload.len()));
    base32::encode(&mut enc, payload);
    for label in enc.chunks(MAX_LABEL) {
        b.push(label.len() as u8);
        b.extend_from_slice(label);
    }
    b.extend_from_slice(&z.wire);
    b.push(0);
    b.extend_from_slice(&qtype.to_be_bytes());
    b.extend_from_slice(&CLASS_IN.to_be_bytes());
    put_opt(b, edns_size);
}

fn put_opt(b: &mut Vec<u8>, size: u16) {
    b.push(0);
    b.extend_from_slice(&TYPE_OPT.to_be_bytes());
    b.extend_from_slice(&size.to_be_bytes());
    b.extend_from_slice(&[0; 6]);
}

/// A parsed incoming query.
#[derive(Debug, Clone)]
pub struct Query {
    pub txn: u16,
    pub rd: bool,
    /// QNAME through QCLASS, as received.
    pub question: Vec<u8>,
    pub qtype: u16,
    /// The decoded tunnel payload, or None if the name carries none.
    pub payload: Option<Vec<u8>>,
    /// The sender's UDP payload size; 512 without OPT.
    pub edns: usize,
    pub has_opt: bool,
    /// Bytes in the query message, for amplification accounting.
    pub size: usize,
    /// The name is the zone or under it.
    pub in_zone: bool,
    /// The name is the zone itself.
    pub apex: bool,
}

fn u16_at(msg: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([msg[i], msg[i + 1]])
}

/// Parses a query and decodes the tunnel payload under z (SPEC §3.3).
pub fn parse_query(msg: &[u8], z: &Zone) -> Result<Query, Error> {
    if msg.len() < HDR_LEN || msg[2] & 0x80 != 0 || u16_at(msg, 4) != 1 {
        return Err(Error::Dns);
    }
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut i = HDR_LEN;
    loop {
        let n = *msg.get(i).ok_or(Error::Dns)? as usize;
        if n == 0 {
            i += 1;
            break;
        }
        if n > MAX_LABEL || i + 1 + n > msg.len() {
            return Err(Error::Dns);
        }
        labels.push(&msg[i + 1..i + 1 + n]);
        i += 1 + n;
    }
    if i + 4 > msg.len() {
        return Err(Error::Dns);
    }
    let mut q = Query {
        txn: u16_at(msg, 0),
        rd: msg[2] & 0x01 != 0,
        question: msg[HDR_LEN..i + 4].to_vec(),
        qtype: u16_at(msg, i),
        payload: None,
        edns: 512,
        has_opt: false,
        size: msg.len(),
        in_zone: false,
        apex: false,
    };
    i += 4;
    if u16_at(msg, 10) > 0 && i + 11 <= msg.len() && msg[i] == 0 && u16_at(msg, i + 1) == TYPE_OPT {
        q.has_opt = true;
        q.edns = usize::from(u16_at(msg, i + 3)).max(512);
    }
    if labels.len() < z.labels {
        return Ok(q);
    }
    let (sub, tail) = labels.split_at(labels.len() - z.labels);
    let mut w = &z.wire[..];
    for l in tail {
        let n = w[0] as usize;
        if n != l.len() || !w[1..1 + n].eq_ignore_ascii_case(l) {
            return Ok(q);
        }
        w = &w[1 + n..];
    }
    q.in_zone = true;
    q.apex = sub.is_empty();
    if !q.apex {
        q.payload = base32::decode(&sub.concat());
    }
    Ok(q)
}

/// The size of a TXT answer to q, excluding the RDATA.
fn answer_overhead(q: &Query) -> usize {
    HDR_LEN + q.question.len() + 2 + 2 + 2 + 4 + 2 + if q.has_opt { 11 } else { 0 }
}

/// How many payload bytes fit in an answer of at most limit bytes to q (SPEC §3.5).
pub fn capacity(q: &Query, limit: usize) -> usize {
    let room = limit as isize - answer_overhead(q) as isize;
    if q.qtype == TYPE_AAAA {
        let recs = ((room + 12) / AAAA_RR_LEN as isize).min(AAAA_MAX_RECS as isize);
        return (recs * AAAA_CHUNK as isize - 2).max(0) as usize;
    }
    if room <= 1 {
        return 0;
    }
    // Each 255-byte character-string costs one length byte.
    (room - (room + 255) / 256) as usize
}

fn put_header(b: &mut Vec<u8>, q: &Query, rcode: u8, an: u16, ns: u16) {
    b.extend_from_slice(&q.txn.to_be_bytes());
    b.push(0x84 | u8::from(q.rd)); // QR, AA
    b.push(rcode);
    b.extend_from_slice(&[0, 1]);
    b.extend_from_slice(&an.to_be_bytes());
    b.extend_from_slice(&ns.to_be_bytes());
    b.extend_from_slice(&u16::from(q.has_opt).to_be_bytes());
    b.extend_from_slice(&q.question);
}

/// Appends a response to q carrying payload in records of the query's type, or no records if
/// payload is None (SPEC §3.4).
pub fn put_answer(b: &mut Vec<u8>, q: &Query, rcode: u8, payload: Option<&[u8]>) {
    match payload {
        None => put_header(b, q, rcode, 0, 0),
        Some(p) if q.qtype == TYPE_AAAA => {
            let mut data = Vec::with_capacity(2 + p.len());
            data.extend_from_slice(&(p.len() as u16).to_be_bytes());
            data.extend_from_slice(p);
            let recs = data.len().div_ceil(AAAA_CHUNK);
            put_header(b, q, rcode, recs as u16, 0);
            for (i, chunk) in data.chunks(AAAA_CHUNK).enumerate() {
                b.extend_from_slice(&[0xC0, HDR_LEN as u8]);
                b.extend_from_slice(&TYPE_AAAA.to_be_bytes());
                b.extend_from_slice(&CLASS_IN.to_be_bytes());
                b.extend_from_slice(&[0, 0, 0, 0, 0, 16, i as u8]);
                b.extend_from_slice(chunk);
                b.resize(b.len() + AAAA_CHUNK - chunk.len(), 0);
            }
        }
        Some(p) => {
            put_header(b, q, rcode, 1, 0);
            b.extend_from_slice(&[0xC0, HDR_LEN as u8]);
            b.extend_from_slice(&TYPE_TXT.to_be_bytes());
            b.extend_from_slice(&CLASS_IN.to_be_bytes());
            b.extend_from_slice(&[0, 0, 0, 0]); // TTL 0: never cache
            let rdlen = if p.is_empty() {
                1
            } else {
                p.len() + p.len().div_ceil(255)
            };
            b.extend_from_slice(&(rdlen as u16).to_be_bytes());
            if p.is_empty() {
                b.push(0);
            }
            for s in p.chunks(255) {
                b.push(s.len() as u8);
                b.extend_from_slice(s);
            }
        }
    }
    if q.has_opt {
        put_opt(b, EDNS_SIZE);
    }
}

/// Answers an in-zone query that isn't tunnel traffic: NOERROR with no records and the zone's SOA
/// in the authority section, or the SOA itself for an SOA query at the apex (SPEC §3.6).
pub fn put_no_data(b: &mut Vec<u8>, q: &Query, z: &Zone) {
    let soa = q.apex && q.qtype == TYPE_SOA;
    put_header(b, q, RCODE_OK, u16::from(soa), u16::from(!soa));
    b.extend_from_slice(&z.wire);
    b.push(0);
    b.extend_from_slice(&TYPE_SOA.to_be_bytes());
    b.extend_from_slice(&CLASS_IN.to_be_bytes());
    b.extend_from_slice(&60u32.to_be_bytes()); // TTL
    let mut rd = Vec::with_capacity(2 * z.wire.len() + 22);
    for _ in 0..2 {
        rd.extend_from_slice(&z.wire);
        rd.push(0);
    }
    // Serial, refresh, retry, expire, negative TTL.
    for v in [1u32, 3600, 600, 86400, 60] {
        rd.extend_from_slice(&v.to_be_bytes());
    }
    b.extend_from_slice(&(rd.len() as u16).to_be_bytes());
    b.extend_from_slice(&rd);
    if q.has_opt {
        put_opt(b, EDNS_SIZE);
    }
}

/// A parsed response.
#[derive(Debug, Clone)]
pub struct Answer {
    pub txn: u16,
    pub tc: bool,
    pub rcode: u8,
    pub question: Vec<u8>,
    /// The carried payload (TXT strings, or reassembled AAAA chunks).
    pub payload: Vec<u8>,
    /// A carrier record was present.
    pub carried: bool,
}

pub fn parse_answer(msg: &[u8]) -> Result<Answer, Error> {
    if msg.len() < HDR_LEN || msg[2] & 0x80 == 0 || u16_at(msg, 4) != 1 {
        return Err(Error::Dns);
    }
    let an = u16_at(msg, 6);
    let mut i = skip_name(msg, HDR_LEN)?;
    if i + 4 > msg.len() {
        return Err(Error::Dns);
    }
    let mut a = Answer {
        txn: u16_at(msg, 0),
        tc: msg[2] & 0x02 != 0,
        rcode: msg[3] & 0x0F,
        question: msg[HDR_LEN..i + 4].to_vec(),
        payload: Vec::new(),
        carried: false,
    };
    i += 4;
    let mut aaaa: Vec<&[u8]> = Vec::new();
    for _ in 0..an {
        i = skip_name(msg, i)?;
        if i + 10 > msg.len() {
            return Err(Error::Dns);
        }
        let typ = u16_at(msg, i);
        let rdlen = usize::from(u16_at(msg, i + 8));
        i += 10;
        let rd = msg.get(i..i + rdlen).ok_or(Error::Dns)?;
        if typ == TYPE_AAAA && rdlen == 16 {
            aaaa.push(rd);
        }
        if typ == TYPE_TXT {
            a.carried = true;
            let mut s = rd;
            while let Some((&n, rest)) = s.split_first() {
                let n = n as usize;
                if n > rest.len() {
                    return Err(Error::Dns);
                }
                a.payload.extend_from_slice(&rest[..n]);
                s = &rest[n..];
            }
        }
        i += rdlen;
    }
    if !aaaa.is_empty() && !a.carried {
        let mut data = vec![0u8; aaaa.len() * AAAA_CHUNK];
        let mut seen = vec![false; aaaa.len()];
        for rr in &aaaa {
            let k = rr[0] as usize;
            if k >= aaaa.len() || seen[k] {
                return Err(Error::Dns);
            }
            seen[k] = true;
            data[k * AAAA_CHUNK..(k + 1) * AAAA_CHUNK].copy_from_slice(&rr[1..]);
        }
        let n = usize::from(u16_at(&data, 0));
        if 2 + n > data.len() {
            return Err(Error::Dns);
        }
        a.payload = data[2..2 + n].to_vec();
        a.carried = true;
    }
    Ok(a)
}

/// Returns the offset just past the name at i.
pub fn skip_name(msg: &[u8], mut i: usize) -> Result<usize, Error> {
    loop {
        let n = *msg.get(i).ok_or(Error::Dns)? as usize;
        match n {
            0 => return Ok(i + 1),
            _ if n & 0xC0 == 0xC0 => return Ok(i + 2),
            _ if n > MAX_LABEL => return Err(Error::Dns),
            _ => i += 1 + n,
        }
    }
}
