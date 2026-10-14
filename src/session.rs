//! The transport-independent half of a tunnel endpoint: streams, packet numbers, acknowledgement
//! and retransmission (SPEC §7, §8). It does no I/O and reads no clock: callers pass the time in,
//! and drain [`Event`]s to learn what changed.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::crypto::{MIN_PLAIN, PacketCipher};
use crate::frames::{self, Frame, MAX_ACK_RANGES, MAX_LOST_PER_PKT};
use crate::ranges::RangeSet;
use crate::stream::{Stream, StreamError};

/// Bounds per-stream memory.
#[derive(Debug, Clone, Copy)]
pub struct StreamConfig {
    /// Receive window per stream.
    pub stream_window: u64,
    /// Bytes the app may buffer per stream.
    pub send_buffer: usize,
    pub max_streams: usize,
}

/// A peer can't make us queue control frames without bound: past this many queued, the session
/// ends (see queue_ctrl), since dropping one could stall a stream for good.
const MAX_CTRL_QUEUE: usize = 1024;
/// How far below the largest received packet number duplicates are still recognized.
const REPLAY_WINDOW: u64 = 1 << 14;

/// A retransmittable control frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ctrl {
    pub typ: u8,
    pub id: u64,
    pub val: u64,
}

impl Ctrl {
    fn put(&self, b: &mut Vec<u8>) {
        match self.typ {
            frames::CLOSE => frames::put_close(b, self.val),
            frames::OPENED => frames::put_opened(b, self.id),
            frames::RESET_STREAM => frames::put_reset(b, self.id, self.val),
            _ => frames::put_max_stream_data(b, self.id, self.val),
        }
    }

    fn encoded_len(&self) -> usize {
        let mut b = Vec::with_capacity(20);
        self.put(&mut b);
        b.len()
    }
}

#[derive(Debug, Clone, Copy)]
struct SentRange {
    id: u64,
    lo: u64,
    hi: u64,
    fin: bool,
}

#[derive(Debug)]
struct SentPkt {
    at: Instant,
    streams: Vec<SentRange>,
    ctrls: Vec<Ctrl>,
    /// Ack ranges this packet conveyed.
    ack: RangeSet,
    /// Lost packet numbers this packet reported.
    lost: Vec<u64>,
    /// Server: the upstream packet number this packet answered.
    reply_to: u64,
}

/// What changed in a session, for whoever drives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Server: the peer opened a stream.
    Accepted(u64),
    /// A stream has data, EOF or an error to read.
    Readable(u64),
    /// A stream has send-buffer room again.
    Writable(u64),
    /// Client: the server reached the stream's destination.
    Opened(u64),
    /// A stream ended abnormally.
    Aborted(u64),
    /// The session ended.
    Closed,
}

/// The result of a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Read {
    Data(usize),
    Eof,
    WouldBlock,
    Err(StreamError),
}

/// A shared cap on streams across sessions.
#[derive(Debug, Default)]
pub struct StreamSlots {
    used: AtomicUsize,
    max: usize,
}

impl StreamSlots {
    pub fn new(max: usize) -> Arc<StreamSlots> {
        Arc::new(StreamSlots {
            used: AtomicUsize::new(0),
            max,
        })
    }

    fn take(&self) -> bool {
        let mut n = self.used.load(Ordering::Acquire);
        while n < self.max {
            match self
                .used
                .compare_exchange_weak(n, n + 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(now) => n = now,
            }
        }
        false
    }

    /// Gives a slot back. Saturates at zero: an accounting slip must never wrap the count,
    /// which would refuse every stream in every session from then on.
    fn release(&self) {
        let mut n = self.used.load(Ordering::Acquire);
        while n > 0 {
            match self
                .used
                .compare_exchange_weak(n, n - 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return,
                Err(now) => n = now,
            }
        }
    }

    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub struct Session {
    cfg: StreamConfig,
    client: bool,
    pub(crate) seal: PacketCipher,
    pub(crate) open: PacketCipher,

    pub(crate) next_pn: u64,
    sent: HashMap<u64, SentPkt>,
    /// Server: smoothed time from sending a packet to its ack.
    ack_rtt: Option<Duration>,

    /// Peer packet numbers received, for dedup (trimmed below a window).
    recvd: RangeSet,
    pub(crate) largest_recv: u64,
    pub(crate) have_recv: bool,
    /// Client: downstream packet numbers the server hasn't been told about.
    pub(crate) to_ack: RangeSet,
    /// Client: upstream packet numbers to report lost.
    pub(crate) lost_q: Vec<u64>,
    /// Server: upstream packet number → the downstream packet that answered it.
    reply_of: HashMap<u64, u64>,
    /// The last received packet carried stream or control frames.
    pub(crate) rx_data: bool,

    streams: HashMap<u64, Stream>,
    /// Server: one past the highest stream id the client has used.
    peer_next: u64,
    /// Server: ids below peer_next not yet opened (reordered opens).
    peer_gaps: RangeSet,
    next_stream_id: u64,
    /// Stream ids in round-robin order.
    rr: VecDeque<u64>,
    ctrl_q: VecDeque<Ctrl>,

    closed: bool,
    events: VecDeque<Event>,
    slots: Option<Arc<StreamSlots>>,
    /// Server: upstream packet numbers the client reported lost that had no recorded reply.
    pub(crate) lost_unknown: Vec<u64>,
}

impl Session {
    pub fn new(client: bool, cfg: StreamConfig, seal: PacketCipher, open: PacketCipher) -> Session {
        Session {
            cfg,
            client,
            seal,
            open,
            next_pn: 0,
            sent: HashMap::new(),
            ack_rtt: None,
            recvd: RangeSet::default(),
            largest_recv: 0,
            have_recv: false,
            to_ack: RangeSet::default(),
            lost_q: Vec::new(),
            reply_of: HashMap::new(),
            rx_data: false,
            streams: HashMap::new(),
            peer_next: 0,
            peer_gaps: RangeSet::default(),
            next_stream_id: 0,
            rr: VecDeque::new(),
            ctrl_q: VecDeque::new(),
            closed: false,
            events: VecDeque::new(),
            slots: None,
            lost_unknown: Vec::new(),
        }
    }

    /// Counts the peer's streams against a cap shared with other sessions.
    pub fn set_slots(&mut self, slots: Arc<StreamSlots>) {
        self.slots = Some(slots);
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    pub(crate) fn queue_ctrl(&mut self, c: Ctrl) {
        if c.typ == frames::MAX_STREAM_DATA
            && let Some(q) = self
                .ctrl_q
                .iter_mut()
                .find(|q| q.typ == frames::MAX_STREAM_DATA && q.id == c.id)
        {
            q.val = q.val.max(c.val);
            return;
        }
        // The same frame already waiting (a second RESET or OPENED for a stream) adds nothing.
        if self.ctrl_q.contains(&c) {
            return;
        }
        // Callers update their state as if the frame will go out (a read raises rmax before
        // its MAX_STREAM_DATA), so dropping one would stall a stream for good. Legitimate
        // traffic stays far below the cap: grants coalesce per stream, and each stream has
        // one OPENED and one RESET at most. Only a misbehaving peer fills it (say, opening
        // stream after stream past the limit, each refused with a RESET), so end the session.
        if self.ctrl_q.len() >= MAX_CTRL_QUEUE {
            self.close("soar: control frame queue overflow");
            return;
        }
        self.ctrl_q.push_back(c);
    }

    /// Sends the receive window if it's larger than the initial one.
    fn advertise(&mut self, id: u64) {
        let st = self.streams.get_mut(&id).expect("advertise a live stream");
        if st.rwin > st.rmax {
            st.rmax = st.rwin;
            let c = Ctrl {
                typ: frames::MAX_STREAM_DATA,
                id,
                val: st.rmax,
            };
            self.queue_ctrl(c);
        }
    }

    /// Client: opens a stream whose first bytes name its destination (SPEC §8.2).
    pub fn open_stream(&mut self, addr: &str) -> Result<u64, StreamError> {
        if self.closed {
            return Err(StreamError::SessionClosed);
        }
        if addr.is_empty() || addr.len() > 255 || self.streams.len() >= self.cfg.max_streams {
            return Err(StreamError::Closed);
        }
        let id = self.next_stream_id;
        self.next_stream_id += 1;
        let mut st = Stream::new(self.cfg.stream_window, self.cfg.send_buffer);
        st.sbuf.push_back(addr.len() as u8);
        st.sbuf.extend(addr.as_bytes());
        st.spending.add(0, st.sbuf.len() as u64);
        self.streams.insert(id, st);
        self.advertise(id);
        // Advertising can overflow the control queue and end the session.
        if self.closed {
            return Err(StreamError::SessionClosed);
        }
        self.rr.push_back(id);
        Ok(id)
    }

    /// Forgets a stream once both directions are finished.
    fn maybe_remove(&mut self, id: u64) {
        let Some(st) = self.streams.get(&id) else {
            return;
        };
        if st.held || !st.done_sending() || !st.done_receiving() {
            return;
        }
        if st.rclosed && !st.rfin && !st.reset {
            // We stopped reading before the peer finished: tell it to stop sending.
            self.queue_ctrl(Ctrl {
                typ: frames::RESET_STREAM,
                id,
                val: 0,
            });
        }
        // The RESET above can overflow the control queue and end the session, which already
        // released every stream's slot: release this one only if it's still here to remove.
        if self.streams.remove(&id).is_some()
            && !self.client
            && let Some(s) = &self.slots
        {
            s.release();
        }
        self.rr.retain(|&x| x != id);
    }

    /// Ends the session, aborting its streams. The reason documents the call site.
    pub fn close(&mut self, _reason: &str) {
        if self.closed {
            return;
        }
        self.closed = true;
        for (id, mut st) in self.streams.drain() {
            st.abort(StreamError::SessionClosed);
            if !self.client
                && let Some(s) = &self.slots
            {
                s.release();
            }
            self.events.push_back(Event::Aborted(id));
        }
        self.rr.clear();
        self.events.push_back(Event::Closed);
    }

    fn abort_stream(&mut self, id: u64, err: StreamError) {
        if let Some(st) = self.streams.get_mut(&id) {
            st.abort(err);
            self.events.push_back(Event::Aborted(id));
        }
    }

    /// Processes an authenticated packet's frames. Returns whether the packet was new.
    pub fn receive(&mut self, pn: u64, payload: &[u8], now: Instant) -> bool {
        // recvd only remembers the last REPLAY_WINDOW pns, so anything older is refused outright.
        if self.recvd.contains(pn) || (self.have_recv && pn + REPLAY_WINDOW < self.largest_recv) {
            // A duplicate (a resolver's retry) isn't reapplied, but its frames still say whether
            // it carried data, which decides whether the server may hold it (SPEC §7.2).
            if let Ok(fs) = frames::parse(payload)
                && fs
                    .iter()
                    .any(|f| !matches!(f, Frame::Ack(_) | Frame::Lost(_) | Frame::Ping))
            {
                self.rx_data = true;
            }
            return false;
        }
        self.recvd.add(pn, pn + 1);
        if !self.have_recv || pn > self.largest_recv {
            self.largest_recv = pn;
            self.have_recv = true;
        }
        if self.largest_recv > REPLAY_WINDOW {
            self.recvd.trim_below(self.largest_recv - REPLAY_WINDOW);
        }
        let mut eliciting = false;
        let result = frames::parse(payload)
            .map_err(|e| e.to_string())
            .and_then(|fs| {
                for f in &fs {
                    if f.ack_eliciting() {
                        eliciting = true;
                    }
                    if !matches!(f, Frame::Ack(_) | Frame::Lost(_) | Frame::Ping) {
                        self.rx_data = true;
                    }
                    self.on_frame(f, now)?;
                }
                Ok(())
            });
        // Ack only packets that carry something (SPEC §7.3): acking an empty answer to an idle
        // poll would need a query, whose empty answer would need an ack, and so on forever.
        if self.client && eliciting {
            self.to_ack.add(pn, pn + 1);
            let n = self.to_ack.len();
            if n > MAX_ACK_RANGES {
                self.to_ack.0.drain(..n - MAX_ACK_RANGES);
            }
        }
        if let Err(e) = result {
            self.close(&e);
        }
        true
    }

    fn on_frame(&mut self, f: &Frame<'_>, now: Instant) -> Result<(), String> {
        match f {
            Frame::Ping => {}
            Frame::Ack(rs) => self.on_ack(rs, now),
            Frame::Lost(pns) => {
                for &up in pns {
                    if let Some(down) = self.reply_of.remove(&up) {
                        self.declare_lost(down);
                    } else if !self.client {
                        self.lost_unknown.push(up);
                    }
                }
            }
            &Frame::ResetStream { id, .. } => {
                if let Some(st) = self.streams.get_mut(&id) {
                    // The peer stopped: abort our sending; keep data it already delivered.
                    if st.rfin && st.rcontig() == st.rfin_off {
                        st.sbuf.clear();
                        st.spending = RangeSet::default();
                        st.sacked = RangeSet::default();
                        st.sfin = true;
                        st.saborted = true;
                        st.dead = true;
                        self.events.push_back(Event::Readable(id));
                        self.events.push_back(Event::Writable(id));
                    } else {
                        self.abort_stream(id, StreamError::Reset);
                    }
                    self.maybe_remove(id);
                }
            }
            &Frame::MaxStreamData { id, max } => {
                if let Some(st) = self.peer_stream(id)
                    && max > st.smax
                {
                    st.smax = max;
                }
            }
            &Frame::Opened { id } => {
                if self.client
                    && let Some(st) = self.streams.get_mut(&id)
                    && !st.opened
                {
                    st.opened = true;
                    self.events.push_back(Event::Opened(id));
                }
            }
            &Frame::Close { code } => {
                self.close(&format!("soar: session closed by peer (code {code})"))
            }
            &Frame::Stream {
                id,
                offset,
                data,
                fin,
                ..
            } => {
                let Some(st) = self.peer_stream(id) else {
                    return Ok(());
                };
                if st.on_data(offset, data, fin)? {
                    self.events.push_back(Event::Readable(id));
                }
                self.maybe_remove(id);
            }
        }
        Ok(())
    }

    /// Returns stream id, accepting it if the peer is opening it.
    fn peer_stream(&mut self, id: u64) -> Option<&mut Stream> {
        if self.streams.contains_key(&id) {
            return self.streams.get_mut(&id);
        }
        // A closed session already released its streams; accepting more would leak them.
        if self.closed || self.client {
            return None;
        }
        // Clients open ids in order, so a window around the highest seen bounds what we track: an id
        // below it opens only if it was skipped (its first packet arrived late), else it's closed.
        let max = self.cfg.max_streams as u64;
        if id >= self.peer_next + max {
            return None;
        }
        if id < self.peer_next {
            if !self.peer_gaps.contains(id) {
                return None;
            }
            self.peer_gaps.remove(id, id + 1);
        } else {
            self.peer_gaps.add(self.peer_next, id);
            self.peer_next = id + 1;
            let floor = self.peer_next - self.peer_next.min(2 * max);
            if floor > 0 {
                self.peer_gaps.trim_below(floor);
            }
        }
        let refuse = self.streams.len() >= self.cfg.max_streams
            || self.slots.as_ref().is_some_and(|s| !s.take());
        if refuse {
            self.queue_ctrl(Ctrl {
                typ: frames::RESET_STREAM,
                id,
                val: 0,
            });
            return None;
        }
        self.streams.insert(
            id,
            Stream::new(self.cfg.stream_window, self.cfg.send_buffer),
        );
        self.advertise(id);
        // Advertising can overflow the control queue and end the session, taking this stream
        // with it: there's nothing to accept.
        if self.closed {
            return None;
        }
        self.rr.push_back(id);
        self.events.push_back(Event::Accepted(id));
        self.streams.get_mut(&id)
    }

    /// Handles the client's acknowledgement of downstream packets, then declares lost any packet a
    /// later-sent acked one overtook by more than 9/8 of the ack RTT (RFC 9002 §6.1).
    fn on_ack(&mut self, rs: &RangeSet, now: Instant) {
        let acked: Vec<u64> = self
            .sent
            .keys()
            .copied()
            .filter(|&pn| rs.contains(pn))
            .collect();
        let Some(&largest) = acked.iter().max() else {
            return;
        };
        for pn in acked {
            let p = self.sent.remove(&pn).expect("listed");
            let sample = now.saturating_duration_since(p.at);
            self.ack_rtt = Some(match self.ack_rtt {
                None => sample,
                Some(r) => (7 * r + sample) / 8,
            });
            self.apply_acked(pn, p);
        }
        // RFC 9002's time threshold. Its packet threshold is left out on purpose: answers arrive
        // over several resolvers, where three later acks is ordinary reordering, not loss.
        let rtt = self.ack_rtt.unwrap_or_default();
        let lost: Vec<u64> = self
            .sent
            .iter()
            .filter(|&(&pn, p)| pn < largest && now.saturating_duration_since(p.at) > rtt * 9 / 8)
            .map(|(&pn, _)| pn)
            .collect();
        for pn in lost {
            self.declare_lost(pn);
        }
    }

    /// Client: the upstream packet pn was delivered (its query was answered).
    pub(crate) fn acked(&mut self, pn: u64) {
        if let Some(p) = self.sent.remove(&pn) {
            self.apply_acked(pn, p);
        }
    }

    fn apply_acked(&mut self, pn: u64, p: SentPkt) {
        if self.reply_of.get(&p.reply_to) == Some(&pn) {
            self.reply_of.remove(&p.reply_to);
        }
        for r in &p.streams {
            if let Some(st) = self.streams.get_mut(&r.id) {
                if st.on_acked(r.lo, r.hi, r.fin) {
                    self.events.push_back(Event::Writable(r.id));
                }
                self.maybe_remove(r.id);
            }
        }
        for a in &p.ack.0 {
            self.to_ack.remove(a.lo, a.hi);
        }
    }

    /// Whether a sent packet still carries stream or control frames. Ack- and lost-only packets
    /// are tracked for re-conveying but don't justify a query on their own.
    pub(crate) fn data_in_flight(&self) -> bool {
        self.sent
            .values()
            .any(|p| !p.streams.is_empty() || !p.ctrls.is_empty())
    }

    /// Requeues a lost packet's contents.
    pub(crate) fn declare_lost(&mut self, pn: u64) {
        let Some(p) = self.sent.remove(&pn) else {
            return;
        };
        if self.reply_of.get(&p.reply_to) == Some(&pn) {
            self.reply_of.remove(&p.reply_to);
        }
        for r in &p.streams {
            if let Some(st) = self.streams.get_mut(&r.id) {
                st.on_lost(r.lo, r.hi, r.fin);
            }
        }
        for c in p.ctrls {
            if c.typ == frames::MAX_STREAM_DATA
                && self.streams.get(&c.id).is_none_or(|st| st.rmax != c.val)
            {
                continue; // superseded
            }
            self.queue_ctrl(c);
        }
        // Ack ranges this packet carried still need conveying, if they're recent.
        for a in &p.ack.0 {
            if self.recvd.contains(a.lo) {
                self.to_ack.add(a.lo, a.hi);
            }
        }
        self.lost_q.extend(p.lost);
    }

    /// Declares lost every packet sent before cutoff.
    pub(crate) fn expire_sent(&mut self, cutoff: Instant) {
        let old: Vec<u64> = self
            .sent
            .iter()
            .filter(|(_, p)| p.at < cutoff)
            .map(|(&pn, _)| pn)
            .collect();
        for pn in old {
            self.declare_lost(pn);
        }
    }

    /// Makes a just-built packet's stream data pending again so the next packet carries a copy:
    /// the tail of a transfer is duplicated rather than waiting out a loss.
    pub(crate) fn requeue(&mut self, pn: u64) -> bool {
        let Some(p) = self.sent.get(&pn) else {
            return false;
        };
        let mut any = false;
        for r in &p.streams {
            let Some(st) = self.streams.get_mut(&r.id) else {
                continue;
            };
            if st.reset {
                continue;
            }
            if r.lo < r.hi {
                st.spending.add(r.lo.max(st.sbase), r.hi);
                any = true;
            }
            if r.fin && !st.sfin_acked {
                st.sfin_sent = false;
                any = true;
            }
        }
        any
    }

    /// Whether a packet carries stream data, by number.
    pub(crate) fn carries_streams(&self, pn: u64) -> bool {
        self.sent.get(&pn).is_some_and(|p| !p.streams.is_empty())
    }

    /// Whether control frames are waiting to be sent.
    pub(crate) fn ctrl_pending(&self) -> bool {
        !self.ctrl_q.is_empty()
    }

    /// Whether anything other than acks is waiting to be sent.
    pub fn has_data(&self) -> bool {
        !self.ctrl_q.is_empty()
            || !self.lost_q.is_empty()
            || self
                .rr
                .iter()
                .any(|id| self.streams.get(id).is_some_and(Stream::wants_send))
    }

    /// An estimate of the stream bytes waiting to be sent.
    pub(crate) fn pending_bytes(&self) -> usize {
        self.streams
            .values()
            .flat_map(|st| {
                st.spending
                    .0
                    .iter()
                    .filter(|r| r.lo < st.smax)
                    .map(|r| (r.hi.min(st.smax) - r.lo) as usize)
            })
            .sum()
    }

    /// Appends a packet's frames to b, up to budget bytes, and records it as sent. It always
    /// produces at least MIN_PLAIN bytes. Returns the packet number, whether it carries stream or
    /// control frames, and whether it was recorded (it carries anything worth tracking).
    pub(crate) fn build(
        &mut self,
        b: &mut Vec<u8>,
        budget: usize,
        now: Instant,
        reply_to: u64,
    ) -> (u64, bool, bool) {
        let start = b.len();
        let room = |b: &Vec<u8>| budget.saturating_sub(b.len() - start);
        let pn = self.next_pn;
        self.next_pn += 1;
        let mut p = SentPkt {
            at: now,
            streams: Vec::new(),
            ctrls: Vec::new(),
            ack: RangeSet::default(),
            lost: Vec::new(),
            reply_to,
        };
        let mut data = false;

        // Control frames first: they unblock the peer.
        while let Some(&c) = self.ctrl_q.front() {
            if c.encoded_len() > room(b) {
                break;
            }
            c.put(b);
            p.ctrls.push(c);
            self.ctrl_q.pop_front();
            data = true;
        }
        if !self.lost_q.is_empty() && room(b) > 4 {
            self.lost_q.sort_unstable_by(|a, b| b.cmp(a));
            self.lost_q.dedup();
            let mut n = self.lost_q.len().min(MAX_LOST_PER_PKT);
            while n > 0 && {
                let mut t = Vec::new();
                frames::put_lost(&mut t, &self.lost_q[..n]);
                t.len() > room(b)
            } {
                n -= 1;
            }
            if n > 0 {
                frames::put_lost(b, &self.lost_q[..n]);
                p.lost = self.lost_q.drain(..n).collect();
            }
        }
        if self.client && !self.to_ack.is_empty() {
            let mut rs = self.to_ack.clone();
            while !rs.is_empty() && frames::ack_len(&rs) > room(b) {
                rs.0.remove(0);
            }
            if !rs.is_empty() {
                frames::put_ack(b, &rs);
                p.ack = rs;
            }
        }
        // Stream data, round-robin across streams so one bulk transfer can't starve the rest.
        let mut i = 0;
        while i < self.rr.len() && room(b) > 3 {
            i += 1;
            let id = self.rr.pop_front().expect("nonempty");
            self.rr.push_back(id);
            let Some(st) = self.streams.get_mut(&id) else {
                continue;
            };
            while st.wants_send() && room(b) > 3 {
                let Some(r) = st.spending.0.first().copied() else {
                    // A bare FIN.
                    let off = st.send_end();
                    if frames::stream_header_len(id, off, 0) > room(b) {
                        break;
                    }
                    frames::put_stream(b, id, off, &[], true, true);
                    st.sfin_sent = true;
                    p.streams.push(SentRange {
                        id,
                        lo: off,
                        hi: off,
                        fin: true,
                    });
                    data = true;
                    break;
                };
                let mut hi = r.hi.min(st.smax);
                let hdr = frames::stream_header_len(id, r.lo, (hi - r.lo) as usize);
                if hdr >= room(b) {
                    break;
                }
                hi = hi.min(r.lo + (room(b) - hdr) as u64);
                let fin = st.sfin && !st.sfin_acked && hi == st.send_end();
                let (from, to) = ((r.lo - st.sbase) as usize, (hi - st.sbase) as usize);
                let chunk: Vec<u8> = st.sbuf.range(from..to).copied().collect();
                frames::put_stream(b, id, r.lo, &chunk, fin, true);
                st.spending.remove(r.lo, hi);
                if fin {
                    st.sfin_sent = true;
                }
                p.streams.push(SentRange {
                    id,
                    lo: r.lo,
                    hi,
                    fin,
                });
                data = true;
            }
        }
        while b.len() - start < MIN_PLAIN {
            b.push(frames::PADDING);
        }
        let tracked = data || !p.ack.is_empty() || !p.lost.is_empty();
        if tracked {
            if !self.client {
                self.reply_of.insert(reply_to, pn);
            }
            self.sent.insert(pn, p);
        }
        (pn, data, tracked)
    }

    // The stream API, for whoever relays a stream's bytes.

    /// Reads from stream id into buf.
    pub fn read(&mut self, id: u64, buf: &mut [u8]) -> Read {
        let Some(st) = self.streams.get_mut(&id) else {
            return Read::Err(if self.closed {
                StreamError::SessionClosed
            } else {
                StreamError::Closed
            });
        };
        if !st.rbuf.is_empty() {
            let n = buf.len().min(st.rbuf.len());
            for (d, s) in buf.iter_mut().zip(st.rbuf.drain(..n)) {
                *d = s;
            }
            st.rread += n as u64;
            // Re-advertise once half the window has been consumed. Limits only ever grow: the
            // peer keeps whatever it was granted before.
            let limit = st.rread + st.rwin;
            if limit > st.rmax && limit - st.rmax >= st.rwin / 2 && !st.rfin {
                st.rmax = limit;
                self.queue_ctrl(Ctrl {
                    typ: frames::MAX_STREAM_DATA,
                    id,
                    val: limit,
                });
            }
            self.maybe_remove(id);
            return Read::Data(n);
        }
        if st.rfin && st.rread == st.rfin_off {
            self.maybe_remove(id);
            return Read::Eof;
        }
        if st.reset {
            return Read::Err(st.reset_err.unwrap_or(StreamError::Reset));
        }
        if st.rclosed || st.dead {
            return Read::Err(StreamError::Closed);
        }
        Read::WouldBlock
    }

    /// Buffers as much of data as there's room for. Ok(0) means the buffer is full.
    pub fn write(&mut self, id: u64, data: &[u8]) -> Result<usize, StreamError> {
        let Some(st) = self.streams.get_mut(&id) else {
            return Err(if self.closed {
                StreamError::SessionClosed
            } else {
                StreamError::Closed
            });
        };
        if st.reset {
            return Err(st.reset_err.unwrap_or(StreamError::Reset));
        }
        if st.sfin || st.dead {
            return Err(StreamError::Closed);
        }
        let n = st.scap.saturating_sub(st.sbuf.len()).min(data.len());
        let start = st.send_end();
        st.sbuf.extend(&data[..n]);
        st.spending.add(start, start + n as u64);
        Ok(n)
    }

    /// Sends a FIN: the peer reads EOF after the data written so far.
    pub fn finish(&mut self, id: u64) {
        if let Some(st) = self.streams.get_mut(&id) {
            st.sfin = true;
        }
    }

    /// Closes both directions. Data already written is still delivered.
    pub fn close_stream(&mut self, id: u64) {
        let Some(st) = self.streams.get_mut(&id) else {
            return;
        };
        st.sfin = true;
        let mut reset = false;
        if !st.done_receiving() {
            st.rclosed = true;
            st.rbuf.clear();
            st.rooo.clear();
            st.rgot = RangeSet::default();
            // Ask the peer to stop sending, but only once our FIN is acknowledged: a RESET
            // before the peer has the FIN aborts the stream, and data already written would be
            // lost. Until then the FIN goes out, and maybe_remove sends the RESET when the
            // stream is done.
            reset = st.done_sending();
        }
        st.dead = true;
        if reset {
            self.queue_ctrl(Ctrl {
                typ: frames::RESET_STREAM,
                id,
                val: 0,
            });
            self.abort_stream(id, StreamError::Closed);
        }
        self.maybe_remove(id);
    }

    /// Server: the stream's destination couldn't be reached. Resets it with code 1 (SPEC §6).
    pub fn refuse_stream(&mut self, id: u64) {
        if self.streams.contains_key(&id) {
            self.queue_ctrl(Ctrl {
                typ: frames::RESET_STREAM,
                id,
                val: 1,
            });
            self.abort_stream(id, StreamError::Unreachable);
            self.maybe_remove(id);
        }
    }

    /// Server: the stream's destination dial succeeded.
    pub fn stream_opened(&mut self, id: u64) {
        if self.streams.contains_key(&id) {
            self.queue_ctrl(Ctrl {
                typ: frames::OPENED,
                id,
                val: 0,
            });
        }
    }

    /// The driver is done with the stream; it leaves the session once both directions finish.
    pub fn release_stream(&mut self, id: u64) {
        if let Some(st) = self.streams.get_mut(&id) {
            st.held = false;
            self.maybe_remove(id);
        }
    }

    /// Whether the stream was reset or the session ended, as opposed to closed cleanly.
    pub fn stream_aborted(&self, id: u64) -> bool {
        self.streams.get(&id).is_none_or(|st| st.reset)
    }

    /// Whether the client has stopped reading the stream (it reset or closed it).
    pub fn stream_gone(&self, id: u64) -> bool {
        self.streams
            .get(&id)
            .is_none_or(|st| st.reset || st.rclosed || st.dead)
    }

    /// Client: whether the server reported the stream's destination reachable.
    pub fn stream_is_opened(&self, id: u64) -> bool {
        self.streams.get(&id).is_some_and(|st| st.opened)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher() -> PacketCipher {
        PacketCipher {
            key: [1; 32],
            iv: [2; 12],
            hp: [3; 32],
        }
    }

    fn pair() -> (Session, Session) {
        let cfg = StreamConfig {
            stream_window: 1 << 16,
            send_buffer: 1 << 16,
            max_streams: 4,
        };
        (
            Session::new(true, cfg, cipher(), cipher()),
            Session::new(false, cfg, cipher(), cipher()),
        )
    }

    /// Moves one packet from a to b; returns its number.
    fn deliver(a: &mut Session, b: &mut Session, now: Instant) -> u64 {
        let mut p = Vec::new();
        let (pn, _, _) = a.build(&mut p, 1000, now, 0);
        b.receive(pn, &p, now);
        pn
    }

    #[test]
    fn stream_round_trip() {
        let now = Instant::now();
        let (mut c, mut s) = pair();
        let id = c.open_stream("example.com:443").unwrap();
        assert_eq!(c.write(id, b"hello").unwrap(), 5);
        c.finish(id);
        let up = deliver(&mut c, &mut s, now);
        c.acked(up);
        assert_eq!(s.poll_event(), Some(Event::Accepted(0)));
        let mut buf = [0u8; 64];
        let Read::Data(n) = s.read(0, &mut buf) else {
            panic!()
        };
        assert_eq!(&buf[..n], b"\x0fexample.com:443hello");
        assert_eq!(s.read(0, &mut buf), Read::Eof);

        s.stream_opened(0);
        s.write(0, b"world").unwrap();
        s.finish(0);
        deliver(&mut s, &mut c, now);
        assert!(c.stream_is_opened(id));
        let Read::Data(n) = c.read(id, &mut buf) else {
            panic!()
        };
        assert_eq!(&buf[..n], b"world");
        assert_eq!(c.read(id, &mut buf), Read::Eof);
        // The client acks what it received; once acked and released, both forget it.
        deliver(&mut c, &mut s, now);
        s.release_stream(0);
        c.release_stream(id);
        assert_eq!((s.stream_count(), c.stream_count()), (0, 0));
    }

    #[test]
    fn loss_requeues() {
        let now = Instant::now();
        let (mut c, mut s) = pair();
        let id = c.open_stream("a:1").unwrap();
        c.write(id, b"data").unwrap();
        let mut p = Vec::new();
        let (pn, data, _) = c.build(&mut p, 1000, now, 0);
        assert!(data && !c.has_data());
        c.declare_lost(pn);
        assert!(c.has_data());
        deliver(&mut c, &mut s, now);
        let mut buf = [0u8; 64];
        let Read::Data(n) = s.read(0, &mut buf) else {
            panic!()
        };
        assert_eq!(&buf[..n], b"\x03a:1data");
    }

    #[test]
    fn flow_control_violation_closes() {
        let now = Instant::now();
        let (mut c, mut s) = pair();
        let mut p = Vec::new();
        // The server grants its 64 KiB window on accept; one byte past it is a violation.
        frames::put_stream(&mut p, 0, 1 << 16, b"x", false, true);
        s.receive(0, &p, now);
        assert!(s.is_closed());
        let _ = c.open_stream("a:1");
    }

    #[test]
    fn close_after_data_acked_still_delivers_the_fin() {
        let now = Instant::now();
        let (mut c, mut s) = pair();
        let id = c.open_stream("a:1").unwrap();
        c.write(id, b"request").unwrap();
        let up = deliver(&mut c, &mut s, now);
        c.acked(up); // the data is acknowledged: the send buffer is empty, the FIN unsent
        c.close_stream(id);
        c.release_stream(id);
        deliver(&mut c, &mut s, now);
        let mut buf = [0u8; 64];
        assert_eq!(s.read(0, &mut buf), Read::Data(11));
        assert_eq!(
            s.read(0, &mut buf),
            Read::Eof,
            "the FIN arrives, not a RESET"
        );
        assert!(!s.stream_aborted(0));
    }

    #[test]
    fn control_queue_overflow_ends_the_session_instead_of_dropping_frames() {
        let now = Instant::now();
        let (_, mut s) = pair();
        // The server is at its stream limit (4); the peer keeps opening streams anyway, and
        // each refusal queues a RESET.
        for id in 0..2000u64 {
            let mut p = Vec::new();
            frames::put_stream(&mut p, id, 0, b"x", false, true);
            s.receive(id, &p, now);
            if s.is_closed() {
                break;
            }
        }
        assert!(s.is_closed(), "the queue silently dropped frames instead");
    }

    /// A RESET that overflows the control queue ends the session, which releases every stream's
    /// slot in the cross-session cap. The stream being removed must not be released again.
    #[test]
    fn overflow_while_removing_a_stream_releases_its_slot_once() {
        let now = Instant::now();
        let (_, mut s) = pair();
        let slots = StreamSlots::new(10);
        assert!(slots.take()); // another session's stream holds a slot throughout
        s.set_slots(slots.clone());
        let mut p = Vec::new();
        frames::put_stream(&mut p, 0, 0, b"\x03a:1", false, true);
        s.receive(0, &p, now);
        assert_eq!(slots.used(), 2);
        // The control queue is full, and the stream is about to be removed with a RESET (we
        // stopped reading before the peer finished, and our sending was aborted).
        while s.ctrl_q.len() < MAX_CTRL_QUEUE {
            let id = s.ctrl_q.len() as u64 + 100;
            s.ctrl_q.push_back(Ctrl {
                typ: frames::OPENED,
                id,
                val: 0,
            });
        }
        let st = s.streams.get_mut(&0).unwrap();
        (st.rclosed, st.saborted) = (true, true);
        s.release_stream(0);
        assert!(s.is_closed(), "the RESET overflowed the queue");
        assert_eq!(slots.used(), 1, "the stream's slot was released twice");
    }

    #[test]
    fn duplicates_are_not_reprocessed() {
        let now = Instant::now();
        let (_, mut s) = pair();
        let mut p = Vec::new();
        frames::put_stream(&mut p, 0, 0, b"\x03a:1", false, true);
        assert!(s.receive(5, &p, now));
        assert!(!s.receive(5, &p, now));
        let mut buf = [0u8; 8];
        assert_eq!(s.read(0, &mut buf), Read::Data(4));
        assert_eq!(s.read(0, &mut buf), Read::WouldBlock);
    }
}
