//! One tunneled connection's state. The session owns streams and drives them.

use std::collections::{BTreeMap, VecDeque};

use crate::ranges::RangeSet;

/// Every stream's flow-control limit until the receiver advertises its own (SPEC §8.3).
pub const INITIAL_WINDOW: u64 = 32 << 10;

/// Bounds on reassembly bookkeeping: payload is bounded by the window, these bound how finely a
/// peer can slice it. Real reordering leaves at most one gap and a few pieces per packet in flight.
const MAX_GAPS: usize = 1024;
const MAX_PIECES: usize = 4096;

/// Why a stream ended abnormally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    /// The peer reset the stream.
    Reset,
    /// The stream was closed locally.
    Closed,
    /// The session ended.
    SessionClosed,
    /// The destination couldn't be reached.
    Unreachable,
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            StreamError::Reset => "soar: stream reset by peer",
            StreamError::Closed => "soar: stream closed",
            StreamError::SessionClosed => "soar: session closed",
            StreamError::Unreachable => "soar: destination unreachable",
        })
    }
}

impl std::error::Error for StreamError {}

#[derive(Debug)]
pub(crate) struct Stream {
    // Send side. sbuf holds bytes [sbase, sbase+len); everything below sbase is acked.
    pub sbuf: VecDeque<u8>,
    pub sbase: u64,
    /// Ranges to send or retransmit.
    pub spending: RangeSet,
    /// Acked ranges above sbase.
    pub sacked: RangeSet,
    /// The peer's flow-control limit.
    pub smax: u64,
    /// The app closed its write side.
    pub sfin: bool,
    /// A FIN is in flight (pending acks or loss).
    pub sfin_sent: bool,
    pub sfin_acked: bool,
    /// The peer reset our sending; acks and losses for old ranges are moot.
    pub saborted: bool,
    /// Bytes the app may buffer.
    pub scap: usize,

    // Receive side. rbuf holds contiguous bytes from rread; rooo out-of-order pieces by offset.
    pub rbuf: VecDeque<u8>,
    pub rread: u64,
    pub rooo: BTreeMap<u64, Vec<u8>>,
    /// The ranges rooo holds.
    pub rgot: RangeSet,
    pub rfin: bool,
    pub rfin_off: u64,
    /// Highest offset received.
    pub rhigh: u64,
    /// Window size.
    pub rwin: u64,
    /// The limit last advertised.
    pub rmax: u64,
    /// The app closed its read side; arriving data is discarded.
    pub rclosed: bool,

    /// Aborted by either side.
    pub reset: bool,
    pub reset_err: Option<StreamError>,
    /// Closed locally or aborted: blocked reads and writes give up.
    pub dead: bool,
    /// Client: the server reported its dial succeeded.
    pub opened: bool,
    /// Its driver (a relay, a connection handle) still uses it: it stays in the session, and
    /// counted, until released, so reads keep reporting EOF or the error after it's finished.
    pub held: bool,
}

impl Stream {
    pub fn new(stream_window: u64, send_buffer: usize) -> Stream {
        Stream {
            sbuf: VecDeque::new(),
            sbase: 0,
            spending: RangeSet::default(),
            sacked: RangeSet::default(),
            smax: INITIAL_WINDOW,
            sfin: false,
            sfin_sent: false,
            sfin_acked: false,
            saborted: false,
            scap: send_buffer,
            rbuf: VecDeque::new(),
            rread: 0,
            rooo: BTreeMap::new(),
            rgot: RangeSet::default(),
            rfin: false,
            rfin_off: 0,
            rhigh: 0,
            rwin: stream_window,
            rmax: INITIAL_WINDOW,
            rclosed: false,
            reset: false,
            reset_err: None,
            dead: false,
            opened: false,
            held: true,
        }
    }

    pub fn rcontig(&self) -> u64 {
        self.rread + self.rbuf.len() as u64
    }

    /// One past the last byte written.
    pub fn send_end(&self) -> u64 {
        self.sbase + self.sbuf.len() as u64
    }

    /// Handles a STREAM frame. Returns whether anything became readable.
    pub fn on_data(&mut self, off: u64, data: &[u8], fin: bool) -> Result<bool, &'static str> {
        let end = off + data.len() as u64;
        if end > self.rmax {
            return Err("soar: peer exceeded stream flow control");
        }
        // A FIN fixes the final size: nothing may arrive beyond it, and it can't fall below data
        // already received (either way a read would never reach EOF).
        if self.rfin && end > self.rfin_off {
            return Err("soar: stream data beyond its final size");
        }
        if fin {
            if self.rfin && self.rfin_off != end || end < self.rhigh {
                return Err("soar: inconsistent stream FIN");
            }
            self.rfin = true;
            self.rfin_off = end;
        }
        self.rhigh = self.rhigh.max(end);
        if self.rclosed || self.reset {
            return Ok(true);
        }
        let mut c = self.rcontig();
        if end <= c {
            return Ok(fin);
        }
        if off > c {
            // Keep only what's new, so storage never exceeds the window however it's sliced.
            let mut novel = RangeSet::default();
            novel.add(off, end);
            for g in &self.rgot.0 {
                novel.remove(g.lo, g.hi);
            }
            for n in novel.0 {
                self.rooo.insert(
                    n.lo,
                    data[(n.lo - off) as usize..(n.hi - off) as usize].to_vec(),
                );
                self.rgot.add(n.lo, n.hi);
            }
            if self.rgot.len() > MAX_GAPS || self.rooo.len() > MAX_PIECES {
                return Err("soar: stream reassembly too fragmented");
            }
            return Ok(false);
        }
        self.rbuf.extend(&data[(c - off) as usize..]);
        // Pull in out-of-order pieces now contiguous.
        while let Some(g) = self.rgot.0.first().copied() {
            if g.lo > self.rcontig() {
                break;
            }
            c = self.rcontig();
            let mut o = g.lo;
            while o < g.hi {
                let Some(d) = self.rooo.remove(&o) else {
                    break; // pieces tile rgot; never spin if that breaks
                };
                let e = o + d.len() as u64;
                if e > c {
                    self.rbuf.extend(&d[(c.max(o) - o) as usize..]);
                    c = e;
                }
                o = e;
            }
            self.rgot.0.remove(0);
        }
        if !self.rgot.is_empty() {
            let c = self.rcontig();
            self.rgot.trim_below(c);
        }
        Ok(true)
    }

    /// Records that the peer received [lo, hi) and maybe the FIN. Returns whether send-buffer
    /// room opened up.
    pub fn on_acked(&mut self, lo: u64, hi: u64, fin: bool) -> bool {
        if self.reset || self.saborted {
            return false;
        }
        self.sacked.add(lo, hi);
        self.spending.remove(lo, hi);
        let mut freed = false;
        let base = self.sacked.covered_from(self.sbase);
        if base > self.sbase {
            self.sbuf.drain(..(base - self.sbase) as usize);
            self.sbase = base;
            self.sacked.trim_below(base);
            freed = true;
        }
        if fin {
            self.sfin_acked = true;
        }
        freed
    }

    /// Requeues [lo, hi) minus whatever has been acked since.
    pub fn on_lost(&mut self, lo: u64, hi: u64, fin: bool) {
        if self.reset || self.saborted {
            return;
        }
        let lo = lo.max(self.sbase);
        if lo < hi {
            self.spending.add(lo, hi);
            for a in &self.sacked.0 {
                self.spending.remove(a.lo, a.hi);
            }
        }
        if fin && !self.sfin_acked {
            self.sfin_sent = false;
        }
    }

    /// Whether the stream has something sendable now.
    pub fn wants_send(&self) -> bool {
        if self.reset || self.saborted {
            return false;
        }
        if self.spending.0.first().is_some_and(|r| r.lo < self.smax) {
            return true;
        }
        self.sfin && !self.sfin_sent && !self.sfin_acked && self.spending.is_empty()
    }

    /// Every byte and the FIN are acked (a FIN can be acked before earlier lost data), or sending
    /// was aborted.
    pub fn done_sending(&self) -> bool {
        self.reset
            || self.saborted
            || (self.sfin && self.sfin_acked && self.sbuf.is_empty() && self.spending.is_empty())
    }

    pub fn done_receiving(&self) -> bool {
        self.reset || self.rclosed || (self.rfin && self.rread == self.rfin_off)
    }

    pub fn abort(&mut self, err: StreamError) {
        self.reset = true;
        self.reset_err = Some(err);
        self.sbuf.clear();
        self.spending = RangeSet::default();
        self.sacked = RangeSet::default();
        self.rooo.clear();
        self.rgot = RangeSet::default();
        self.dead = true;
    }
}
