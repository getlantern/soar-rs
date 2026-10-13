//! Frames (SPEC §6).

use crate::Error;
use crate::ranges::{RangeSet, Span};
use crate::varint::{self, Reader};

pub const PADDING: u8 = 0x00;
pub const PING: u8 = 0x01;
pub const ACK: u8 = 0x02;
pub const RESET_STREAM: u8 = 0x03;
pub const MAX_STREAM_DATA: u8 = 0x04;
pub const CLOSE: u8 = 0x05;
pub const LOST: u8 = 0x06;
pub const OPENED: u8 = 0x07;
pub const STREAM: u8 = 0x08;

const STREAM_FIN: u8 = 0x01;
const STREAM_LEN: u8 = 0x02;
const STREAM_OFF: u8 = 0x04;

/// The most ack ranges an encoder sends; decoders accept up to four times as many.
pub const MAX_ACK_RANGES: usize = 16;
/// The most lost packet numbers an encoder sends; decoders accept up to four times as many.
pub const MAX_LOST_PER_PKT: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame<'a> {
    Ping,
    /// Ranges of received packet numbers, ascending.
    Ack(RangeSet),
    ResetStream {
        id: u64,
        code: u64,
    },
    MaxStreamData {
        id: u64,
        max: u64,
    },
    Close {
        code: u64,
    },
    /// Upstream packet numbers that got no usable answer, descending.
    Lost(Vec<u64>),
    Opened {
        id: u64,
    },
    Stream {
        id: u64,
        offset: u64,
        data: &'a [u8],
        fin: bool,
        explicit_len: bool,
    },
}

/// Parses the frames in a packet's plaintext. Stream data borrows from b.
pub fn parse(b: &[u8]) -> Result<Vec<Frame<'_>>, Error> {
    let mut r = Reader::new(b);
    let mut out = Vec::new();
    while !r.b.is_empty() {
        let typ = r.byte()?;
        let f = match typ {
            // Padding runs to the end of the packet.
            PADDING => break,
            PING => Frame::Ping,
            ACK => Frame::Ack(parse_ack(&mut r)?),
            RESET_STREAM => Frame::ResetStream {
                id: r.varint()?,
                code: r.varint()?,
            },
            MAX_STREAM_DATA => Frame::MaxStreamData {
                id: r.varint()?,
                max: r.varint()?,
            },
            CLOSE => Frame::Close { code: r.varint()? },
            LOST => Frame::Lost(parse_lost(&mut r)?),
            OPENED => {
                let id = r.varint()?;
                r.varint()?; // reserved
                Frame::Opened { id }
            }
            t if t & 0xF8 == STREAM => {
                let id = r.varint()?;
                let offset = if t & STREAM_OFF != 0 { r.varint()? } else { 0 };
                let n = if t & STREAM_LEN != 0 {
                    r.varint()?
                } else {
                    r.b.len() as u64
                };
                let data = r.bytes(usize::try_from(n).map_err(|_| Error::Short)?)?;
                Frame::Stream {
                    id,
                    offset,
                    data,
                    fin: t & STREAM_FIN != 0,
                    explicit_len: t & STREAM_LEN != 0,
                }
            }
            _ => return Err(Error::Frame),
        };
        out.push(f);
    }
    Ok(out)
}

fn parse_ack(r: &mut Reader<'_>) -> Result<RangeSet, Error> {
    let n = r.varint()?;
    if n == 0 || n > (MAX_ACK_RANGES * 4) as u64 {
        return Err(Error::Frame);
    }
    let mut spans = Vec::with_capacity(n as usize);
    let mut lo = 0u64;
    for i in 0..n {
        let hi = if i == 0 {
            r.varint()? + 1
        } else {
            let gap = r.varint()?;
            if gap + 1 >= lo {
                return Err(Error::Frame);
            }
            lo - gap - 1
        };
        let len = r.varint()? + 1;
        if len > hi {
            return Err(Error::Frame);
        }
        lo = hi - len;
        spans.push(Span { lo, hi });
    }
    spans.reverse();
    Ok(RangeSet(spans))
}

fn parse_lost(r: &mut Reader<'_>) -> Result<Vec<u64>, Error> {
    let n = r.varint()?;
    if n > (MAX_LOST_PER_PKT * 4) as u64 {
        return Err(Error::Frame);
    }
    let mut pns: Vec<u64> = Vec::with_capacity(n as usize);
    for i in 0..n {
        let mut v = r.varint()?;
        if i > 0 {
            let prev = pns[pns.len() - 1];
            if v + 1 > prev {
                return Err(Error::Frame);
            }
            v = prev - v - 1;
        }
        pns.push(v);
    }
    Ok(pns)
}

/// Encodes up to MAX_ACK_RANGES of the highest spans in rs.
pub fn put_ack(b: &mut Vec<u8>, rs: &RangeSet) {
    let n = rs.len().min(MAX_ACK_RANGES);
    b.push(ACK);
    varint::put(b, n as u64);
    let mut prev_lo = 0;
    for (i, s) in rs.0.iter().rev().take(n).enumerate() {
        varint::put(b, if i == 0 { s.hi - 1 } else { prev_lo - s.hi - 1 });
        varint::put(b, s.hi - s.lo - 1);
        prev_lo = s.lo;
    }
}

pub fn ack_len(rs: &RangeSet) -> usize {
    let mut b = Vec::with_capacity(64);
    put_ack(&mut b, rs);
    b.len()
}

/// Encodes pns, which must be distinct and descending.
pub fn put_lost(b: &mut Vec<u8>, pns: &[u64]) {
    b.push(LOST);
    varint::put(b, pns.len() as u64);
    for (i, &pn) in pns.iter().enumerate() {
        varint::put(b, if i == 0 { pn } else { pns[i - 1] - pn - 1 });
    }
}

pub fn put_reset(b: &mut Vec<u8>, id: u64, code: u64) {
    b.push(RESET_STREAM);
    varint::put(b, id);
    varint::put(b, code);
}

pub fn put_max_stream_data(b: &mut Vec<u8>, id: u64, max: u64) {
    b.push(MAX_STREAM_DATA);
    varint::put(b, id);
    varint::put(b, max);
}

pub fn put_close(b: &mut Vec<u8>, code: u64) {
    b.push(CLOSE);
    varint::put(b, code);
}

pub fn put_opened(b: &mut Vec<u8>, id: u64) {
    b.push(OPENED);
    varint::put(b, id);
    varint::put(b, 0);
}

/// The size of a STREAM frame header that carries an explicit length.
pub fn stream_header_len(id: u64, offset: u64, n: usize) -> usize {
    let off = if offset > 0 { varint::len(offset) } else { 0 };
    1 + varint::len(id) + varint::len(n as u64) + off
}

/// Encodes a STREAM frame; `explicit_len` false lets its data run to the end of the packet.
pub fn put_stream(
    b: &mut Vec<u8>,
    id: u64,
    offset: u64,
    data: &[u8],
    fin: bool,
    explicit_len: bool,
) {
    let mut t = STREAM;
    if offset > 0 {
        t |= STREAM_OFF;
    }
    if explicit_len {
        t |= STREAM_LEN;
    }
    if fin {
        t |= STREAM_FIN;
    }
    b.push(t);
    varint::put(b, id);
    if offset > 0 {
        varint::put(b, offset);
    }
    if explicit_len {
        varint::put(b, data.len() as u64);
    }
    b.extend_from_slice(data);
}

impl Frame<'_> {
    pub fn put(&self, b: &mut Vec<u8>) {
        match self {
            Frame::Ping => b.push(PING),
            Frame::Ack(rs) => put_ack(b, rs),
            Frame::ResetStream { id, code } => put_reset(b, *id, *code),
            Frame::MaxStreamData { id, max } => put_max_stream_data(b, *id, *max),
            Frame::Close { code } => put_close(b, *code),
            Frame::Lost(pns) => put_lost(b, pns),
            Frame::Opened { id } => put_opened(b, *id),
            Frame::Stream {
                id,
                offset,
                data,
                fin,
                explicit_len,
            } => put_stream(b, *id, *offset, data, *fin, *explicit_len),
        }
    }

    /// Whether the frame asks for an acknowledgement.
    pub fn ack_eliciting(&self) -> bool {
        !matches!(self, Frame::Ack(_) | Frame::Lost(_))
    }
}
