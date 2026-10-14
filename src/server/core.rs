//! The server as a state machine: DNS messages in, DNS messages out, stream events for whoever
//! relays streams to their destinations. No I/O and no clock; see [`super`] for the runtime.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};

use crate::crypto::{self, PUB_LEN, TAG_LEN};
use crate::dns::{self, Query, Zone};
use crate::ranges::RangeSet;
use crate::session::{Event, Read, Session, StreamConfig, StreamSlots};
use crate::stream::StreamError;

/// Configures a tunnel server: the authoritative name server for `zone`.
#[derive(Clone)]
pub struct ServerConfig {
    pub zone: String,
    pub key: SigningKey,
    /// Caps how long an idle poll is held waiting for data.
    pub max_hold: Duration,
    /// Declares a downstream packet lost if neither acked nor reported.
    pub loss_timeout: Duration,
    /// Ends sessions that send nothing.
    pub idle_timeout: Duration,
    pub max_sessions: usize,
    /// Caps open streams across all sessions.
    pub max_total_streams: usize,
    /// Caps answer bytes per second sent to one source /24 (IPv4) or /48 (IPv6), bounding how much
    /// a spoofed-source flood can reflect at a victim.
    pub max_bytes_per_prefix: usize,
    /// Handshakes per second; past it new hellos are refused (clients retry).
    pub max_hellos_per_sec: f64,
    pub stream_window: u64,
    pub send_buffer: usize,
    pub max_streams: usize,
}

impl ServerConfig {
    pub fn new(zone: &str, key: SigningKey) -> ServerConfig {
        ServerConfig {
            zone: zone.to_owned(),
            key,
            max_hold: Duration::from_millis(1500),
            loss_timeout: Duration::from_secs(3),
            idle_timeout: Duration::from_secs(120),
            max_sessions: 8192,
            max_total_streams: 16384,
            max_bytes_per_prefix: 8 << 20,
            max_hellos_per_sec: 2000.0,
            // Uploads are small; a modest receive window bounds what one session can make us buffer.
            stream_window: 64 << 10,
            send_buffer: 256 << 10,
            max_streams: 128,
        }
    }
}

/// A DNS message to send.
#[derive(Debug)]
pub struct Transmit {
    pub to: SocketAddr,
    pub msg: Vec<u8>,
}

/// Names a stream across the server's lifetime: sids are reused, session serials aren't.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub session: u64,
    pub id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerEvent {
    /// A client opened a stream: read its destination, dial it, relay.
    Accepted(StreamKey),
    Readable(StreamKey),
    Writable(StreamKey),
    Aborted(StreamKey),
    /// A session ended; all its streams are gone.
    SessionClosed(u64),
}

struct HelloEntry {
    reply: Vec<u8>,
    at: Instant,
    sid: u16,
}

struct HeldQuery {
    /// Names it in the deadline index.
    id: u64,
    q: Query,
    addr: SocketAddr,
    up_pn: u64,
    limit: usize,
    at: Instant,
    deadline: Instant,
}

struct SrvSession {
    s: Session,
    serial: u64,
    created: Instant,
    /// A valid data packet arrived: the hello wasn't just noise.
    used: bool,
    held: VecDeque<HeldQuery>,
    last_seen: Instant,
    /// Upstream packet numbers the client gave up on.
    abandoned: RangeSet,
}

/// A rate limiter: rate per second, burst of `burst`.
struct Bucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn new(rate: f64, burst: f64, now: Instant) -> Bucket {
        Bucket {
            rate,
            burst,
            tokens: burst,
            last: now,
        }
    }

    fn take(&mut self, now: Instant, n: f64) -> bool {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = self.burst.min(self.tokens + dt * self.rate);
        self.last = now;
        if self.tokens < n {
            return false;
        }
        self.tokens -= n;
        true
    }
}

/// Bounds the per-prefix table; prefixes beyond it share one overflow budget, so a flood of
/// spoofed sources can neither grow memory nor escape the limit.
const MAX_RRL_PREFIXES: usize = 1 << 16;
/// Held queries per session; past it the oldest is answered.
const MAX_HELD: usize = 128;
const SWEEP_EVERY: Duration = Duration::from_millis(250);

pub struct ServerCore {
    cfg: ServerConfig,
    zone: Zone,
    sessions: HashMap<u16, SrvSession>,
    serials: HashMap<u64, u16>,
    next_serial: u64,
    hellos: HashMap<[u8; PUB_LEN], HelloEntry>,
    slots: Arc<StreamSlots>,
    sign_tokens: Bucket,
    hello_tokens: Bucket,
    rrl: HashMap<(bool, u128), Bucket>,
    rrl_overflow: Option<Bucket>,
    next_sweep: Instant,
    /// Held polls' deadlines, earliest first, so timers cost O(log n) rather than a scan of
    /// every held poll on every wakeup. Entries for polls answered early go stale; they're
    /// skipped when they come due.
    held_deadlines: BinaryHeap<Reverse<(Instant, u64, u64)>>,
    next_held_id: u64,
    out: Vec<Transmit>,
    events: VecDeque<ServerEvent>,
}

impl ServerCore {
    pub fn new(cfg: ServerConfig, now: Instant) -> Result<ServerCore, crate::Error> {
        let zone = Zone::parse(&cfg.zone)?;
        Ok(ServerCore {
            slots: StreamSlots::new(cfg.max_total_streams),
            sign_tokens: Bucket::new(200.0, 200.0, now),
            hello_tokens: Bucket::new(cfg.max_hellos_per_sec, cfg.max_hellos_per_sec, now),
            cfg,
            zone,
            sessions: HashMap::new(),
            serials: HashMap::new(),
            next_serial: 1,
            hellos: HashMap::new(),
            rrl: HashMap::new(),
            rrl_overflow: None,
            next_sweep: now + SWEEP_EVERY,
            held_deadlines: BinaryHeap::new(),
            next_held_id: 0,
            out: Vec::new(),
            events: VecDeque::new(),
        })
    }

    /// Messages to send, accumulated since the last call.
    pub fn take_transmits(&mut self) -> Vec<Transmit> {
        std::mem::take(&mut self.out)
    }

    pub fn poll_event(&mut self) -> Option<ServerEvent> {
        self.events.pop_front()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Streams open across all sessions.
    pub fn stream_count(&self) -> usize {
        self.slots.used()
    }

    /// When handle_timeout next needs to run.
    pub fn poll_timeout(&self) -> Instant {
        self.held_deadlines
            .peek()
            .map_or(self.next_sweep, |Reverse((d, ..))| {
                (*d).min(self.next_sweep)
            })
    }

    /// Handles a DNS message from addr.
    pub fn handle(&mut self, msg: &[u8], addr: SocketAddr, now: Instant) {
        let Ok(q) = dns::parse_query(msg, &self.zone) else {
            return;
        };
        if !q.in_zone {
            return self.reply(&q, addr, dns::RCODE_REFUSED, None, now);
        }
        let payload = match &q.payload {
            Some(p) if p.len() >= 2 && (q.qtype == dns::TYPE_TXT || q.qtype == dns::TYPE_AAAA) => {
                p.clone()
            }
            _ => return self.no_data(&q, addr, now),
        };
        let sid = u16::from_be_bytes([payload[0], payload[1]]);
        if sid == 0 {
            return self.hello(&q, addr, &payload[2..], now);
        }
        if !self.sessions.contains_key(&sid) {
            return self.reply_unknown(&q, addr, now);
        }
        if payload.len() < 4 + crypto::MIN_PLAIN + TAG_LEN {
            return self.no_data(&q, addr, now);
        }
        self.on_query(sid, q, addr, &payload, now);
    }

    fn send(&mut self, msg: Vec<u8>, to: SocketAddr, query_size: usize, now: Instant) {
        // Only the amplified bytes count: error replies and small answers cost nothing, so
        // spoofing a busy resolver's prefix with cheap queries can't drain its users' budget.
        let amp = msg.len().saturating_sub(query_size);
        if amp > 0 && !self.allow_amplification(to.ip(), amp, now) {
            return;
        }
        self.out.push(Transmit { to, msg });
    }

    fn allow_amplification(&mut self, ip: IpAddr, n: usize, now: Instant) -> bool {
        let key = match ip.to_canonical() {
            IpAddr::V4(v4) => (false, u128::from(u32::from(v4) & 0xFFFF_FF00)),
            IpAddr::V6(v6) => (true, u128::from(v6) & !((1u128 << 80) - 1)),
        };
        let rate = self.cfg.max_bytes_per_prefix as f64;
        let n = n as f64;
        if let Some(b) = self.rrl.get_mut(&key) {
            return b.take(now, n);
        }
        if self.rrl.len() >= MAX_RRL_PREFIXES {
            return self
                .rrl_overflow
                .get_or_insert_with(|| Bucket::new(rate, rate / 4.0, now))
                .take(now, n);
        }
        self.rrl
            .entry(key)
            .or_insert_with(|| Bucket::new(rate, rate / 4.0, now))
            .take(now, n)
    }

    fn reply(
        &mut self,
        q: &Query,
        addr: SocketAddr,
        rcode: u8,
        payload: Option<&[u8]>,
        now: Instant,
    ) {
        let mut b = Vec::with_capacity(512);
        dns::put_answer(&mut b, q, rcode, payload);
        self.send(b, addr, q.size, now);
    }

    fn no_data(&mut self, q: &Query, addr: SocketAddr, now: Instant) {
        let mut b = Vec::with_capacity(256);
        dns::put_no_data(&mut b, q, &self.zone);
        self.send(b, addr, q.size, now);
    }

    /// Tells the client its session is gone, signed so an injector can't forge it. Signing is
    /// rate-limited; past the limit the answer is no-data, as an unsigned one would be ignored.
    fn reply_unknown(&mut self, q: &Query, addr: SocketAddr, now: Instant) {
        if !self.sign_tokens.take(now, 1.0) {
            return self.no_data(q, addr, now);
        }
        let sig = crypto::sign_unknown_session(&self.cfg.key, &q.question);
        self.reply(q, addr, dns::RCODE_NXDOMAIN, Some(&sig), now);
    }

    /// Answers a hello, from the cache for a copy of one already answered.
    fn hello(&mut self, q: &Query, addr: SocketAddr, eph: &[u8], now: Instant) {
        let Some(key) = eph.get(..PUB_LEN) else {
            return self.no_data(q, addr, now);
        };
        let key: [u8; PUB_LEN] = key.try_into().expect("sliced");
        // Resolvers retry and clients send the hello down several paths: answer each copy alike.
        if let Some(h) = self.hellos.get(&key) {
            let reply = h.reply.clone();
            return self.reply(q, addr, dns::RCODE_OK, Some(&reply), now);
        }
        if !self.hello_tokens.take(now, 1.0) {
            return self.reply(q, addr, dns::RCODE_REFUSED, None, now);
        }
        if self.sessions.len() >= self.cfg.max_sessions && !self.evict_unused() {
            return self.reply(q, addr, dns::RCODE_REFUSED, None, now);
        }
        // The transcript covers the sid, so pick a free one first.
        let mut sid = 0u16;
        for _ in 0..16 {
            let candidate = (OsRng.next_u32() & 0xFFFF) as u16;
            if candidate != 0 && !self.sessions.contains_key(&candidate) {
                sid = candidate;
                break;
            }
        }
        if sid == 0 {
            return self.reply(q, addr, dns::RCODE_REFUSED, None, now);
        }
        let Ok((reply, hs)) = crypto::server_hello(&self.cfg.key, &key, sid) else {
            return self.no_data(q, addr, now);
        };
        let cfg = StreamConfig {
            stream_window: self.cfg.stream_window,
            send_buffer: self.cfg.send_buffer,
            max_streams: self.cfg.max_streams,
        };
        let mut s = Session::new(false, cfg, hs.down, hs.up);
        s.set_slots(self.slots.clone());
        let serial = self.next_serial;
        self.next_serial += 1;
        self.sessions.insert(
            sid,
            SrvSession {
                s,
                serial,
                created: now,
                used: false,
                held: VecDeque::new(),
                last_seen: now,
                abandoned: RangeSet::default(),
            },
        );
        self.serials.insert(serial, sid);
        self.hellos.insert(
            key,
            HelloEntry {
                reply: reply.clone(),
                at: now,
                sid,
            },
        );
        self.reply(q, addr, dns::RCODE_OK, Some(&reply), now);
    }

    /// Drops the oldest session that never sent a valid data packet, so a flood of hellos can't
    /// lock real clients out.
    fn evict_unused(&mut self) -> bool {
        let victim = self
            .sessions
            .iter()
            .filter(|(_, ss)| !ss.used)
            .min_by_key(|(_, ss)| ss.created)
            .map(|(&sid, _)| sid);
        match victim {
            Some(sid) => {
                self.remove_session(sid);
                true
            }
            None => false,
        }
    }

    /// Ends every session, aborting their streams.
    pub fn close_all(&mut self) {
        let sids: Vec<u16> = self.sessions.keys().copied().collect();
        for sid in sids {
            self.remove_session(sid);
        }
    }

    fn remove_session(&mut self, sid: u16) {
        if let Some(mut ss) = self.sessions.remove(&sid) {
            ss.s.close("soar: closed");
            self.serials.remove(&ss.serial);
            self.hellos.retain(|_, h| h.sid != sid);
            self.pump(&mut ss);
        }
    }

    /// Moves a session's events to the server's queue.
    fn pump(&mut self, ss: &mut SrvSession) {
        while let Some(e) = ss.s.poll_event() {
            let k = |id| StreamKey {
                session: ss.serial,
                id,
            };
            self.events.push_back(match e {
                Event::Accepted(id) => ServerEvent::Accepted(k(id)),
                Event::Readable(id) => ServerEvent::Readable(k(id)),
                Event::Writable(id) => ServerEvent::Writable(k(id)),
                Event::Aborted(id) => ServerEvent::Aborted(k(id)),
                Event::Opened(_) => continue,
                Event::Closed => ServerEvent::SessionClosed(ss.serial),
            });
        }
    }

    /// Runs f on a session, taken out of the map so the core's other fields stay usable.
    fn with_session<R>(
        &mut self,
        sid: u16,
        f: impl FnOnce(&mut Self, &mut SrvSession) -> R,
    ) -> Option<R> {
        let mut ss = self.sessions.remove(&sid)?;
        let r = f(self, &mut ss);
        self.pump(&mut ss);
        self.sessions.insert(sid, ss);
        Some(r)
    }

    /// Rebuilds the deadline index from the polls still held once stale entries (polls answered
    /// early) could outnumber them, so its size is bounded by the held polls, not by query rate.
    fn compact_deadlines(&mut self) {
        let bound = 2 * MAX_HELD * self.sessions.len() + 1024;
        if self.held_deadlines.len() <= bound {
            return;
        }
        self.held_deadlines = self
            .sessions
            .values()
            .flat_map(|ss| {
                ss.held
                    .iter()
                    .map(|h| Reverse((h.deadline, ss.serial, h.id)))
            })
            .collect();
    }

    /// Handles a data query: applies the client's packet, then answers now or holds the query.
    fn on_query(&mut self, sid: u16, q: Query, addr: SocketAddr, p: &[u8], now: Instant) {
        self.on_session_query(sid, q, addr, p, now);
        self.compact_deadlines();
    }

    fn on_session_query(&mut self, sid: u16, q: Query, addr: SocketAddr, p: &[u8], now: Instant) {
        self.with_session(sid, |core, ss| {
            let (largest, have) = (ss.s.largest_recv, ss.s.have_recv);
            let Ok((pn, plain)) =
                ss.s.open
                    .open_up(p, |t| crypto::decode_pn(largest, have, t))
            else {
                return core.no_data(&q, addr, now);
            };
            let Some(&hdr) = plain.first() else {
                return core.no_data(&q, addr, now);
            };
            let (size_class, hold_class) = (usize::from(hdr & 0x0F), u32::from(hdr >> 4));
            ss.s.rx_data = false;
            // Only a new packet is activity: a replay mustn't keep the session alive or mark a
            // hello-only session used. Duplicates (resolver retries) are still answered.
            if ss.s.receive(pn, &plain[1..], now) {
                ss.last_seen = now;
                ss.used = true;
            }
            // The client gave up on queries we haven't answered: don't spend data on them, since
            // an answer lost now would never be reported.
            for up in std::mem::take(&mut ss.s.lost_unknown) {
                ss.held.retain(|h| h.up_pn != up);
                ss.abandoned.add(up, up + 1);
                let n = ss.abandoned.len();
                if n > 256 {
                    ss.abandoned.0.drain(..n - 256);
                }
            }
            let hold = (Duration::from_millis(100) * hold_class).min(core.cfg.max_hold);
            core.next_held_id += 1;
            let hq = HeldQuery {
                id: core.next_held_id,
                limit: (512 + 48 * size_class).min(q.edns),
                q,
                addr,
                up_pn: pn,
                at: now,
                deadline: now + hold,
            };
            if ss.abandoned.contains(pn) {
                core.empty_answer(ss, hq, now);
            } else if ss.s.is_closed() || hold.is_zero() || ss.s.rx_data {
                core.answer(ss, hq, now);
            } else {
                // A poll joins the queue even when there's data to send: the drain below answers
                // the queue oldest first, at once. Releasing polls in arrival order is what lets
                // the client tell a lost poll from a held one; answering this one first would
                // leave older polls looking lost.
                core.held_deadlines
                    .push(Reverse((hq.deadline, ss.serial, hq.id)));
                ss.held.push_back(hq);
                while ss.held.len() > MAX_HELD {
                    let oldest = ss.held.pop_front().expect("nonempty");
                    core.answer(ss, oldest, now);
                }
            }
            core.drain(ss, now);
        });
    }

    /// Answers hq with the next packet. Returns its number if it was recorded with stream data.
    fn answer(&mut self, ss: &mut SrvSession, hq: HeldQuery, now: Instant) -> Option<u64> {
        let budget = dns::capacity(&hq.q, hq.limit).saturating_sub(2 + TAG_LEN);
        let held = (now.saturating_duration_since(hq.at).as_millis() / 10).min(255) as u8;
        let mut plain = vec![held, 0];
        let (pn, _, tracked) =
            ss.s.build(&mut plain, budget.saturating_sub(2), now, hq.up_pn);
        if let Some(backlog) = ss.s.pending_bytes().checked_div(budget) {
            plain[1] = backlog.min(255) as u8;
        }
        let payload = ss.s.seal.seal_down(pn, hq.up_pn, &plain);
        let mut msg = Vec::with_capacity(hq.limit);
        dns::put_answer(&mut msg, &hq.q, dns::RCODE_OK, Some(&payload));
        self.send(msg, hq.addr, hq.q.size, now);
        (tracked && ss.s.carries_streams(pn)).then_some(pn)
    }

    /// Answers hq with a packet carrying no frames.
    fn empty_answer(&mut self, ss: &mut SrvSession, hq: HeldQuery, now: Instant) {
        let pn = ss.s.next_pn;
        ss.s.next_pn += 1;
        let payload =
            ss.s.seal
                .seal_down(pn, hq.up_pn, &[0; 2 + crypto::MIN_PLAIN]);
        let mut msg = Vec::with_capacity(128);
        dns::put_answer(&mut msg, &hq.q, dns::RCODE_OK, Some(&payload));
        self.send(msg, hq.addr, hq.q.size, now);
    }

    /// Answers held queries, oldest first, while there's data.
    fn drain(&mut self, ss: &mut SrvSession, now: Instant) {
        while ss.s.has_data() {
            let Some(hq) = ss.held.pop_front() else { break };
            let sent = self.answer(ss, hq, now);
            // The queue just drained: send the tail again in another held poll.
            if let Some(pn) = sent
                && !ss.s.has_data()
                && !ss.held.is_empty()
                && ss.s.requeue(pn)
            {
                let hq = ss.held.pop_front().expect("nonempty");
                self.answer(ss, hq, now);
            }
        }
    }

    /// Answers expired held polls, and every 250ms declares stale downstream packets lost and
    /// ends idle sessions.
    pub fn handle_timeout(&mut self, now: Instant) {
        while let Some(&Reverse((deadline, serial, id))) = self.held_deadlines.peek() {
            if deadline > now {
                break;
            }
            self.held_deadlines.pop();
            let Some(&sid) = self.serials.get(&serial) else {
                continue;
            };
            self.with_session(sid, |core, ss| {
                if let Some(i) = ss.held.iter().position(|h| h.id == id) {
                    let hq = ss.held.remove(i).expect("found");
                    core.answer(ss, hq, now);
                }
            });
        }
        if now < self.next_sweep {
            return;
        }
        let sids: Vec<u16> = self.sessions.keys().copied().collect();
        self.next_sweep = now + SWEEP_EVERY;
        let hello_ttl = Duration::from_secs(60);
        let sessions = &self.sessions;
        self.hellos.retain(|_, h| {
            now.saturating_duration_since(h.at) <= hello_ttl && sessions.contains_key(&h.sid)
        });
        self.rrl
            .retain(|_, b| now.saturating_duration_since(b.last) <= Duration::from_secs(30));
        let (loss, idle_after) = (self.cfg.loss_timeout, self.cfg.idle_timeout);
        for sid in sids {
            let idle = self.with_session(sid, |core, ss| {
                if let Some(cutoff) = now.checked_sub(loss) {
                    ss.s.expire_sent(cutoff);
                }
                let idle = now.saturating_duration_since(ss.last_seen) > idle_after
                    || ss.s.is_closed()
                    || (!ss.used
                        && now.saturating_duration_since(ss.created) > Duration::from_secs(15));
                core.drain(ss, now);
                idle
            });
            if idle == Some(true) {
                self.remove_session(sid);
            }
        }
    }

    // The stream API, for the relay of a stream accepted with ServerEvent::Accepted. After any of
    // these, send take_transmits(): new data may let held polls be answered.

    fn stream_op<R>(
        &mut self,
        k: StreamKey,
        now: Instant,
        f: impl FnOnce(&mut Session) -> R,
    ) -> Option<R> {
        let sid = *self.serials.get(&k.session)?;
        self.with_session(sid, |core, ss| {
            let r = f(&mut ss.s);
            core.drain(ss, now);
            r
        })
    }

    pub fn read(&mut self, k: StreamKey, buf: &mut [u8], now: Instant) -> Read {
        self.stream_op(k, now, |s| s.read(k.id, buf))
            .unwrap_or(Read::Err(StreamError::SessionClosed))
    }

    pub fn write(&mut self, k: StreamKey, data: &[u8], now: Instant) -> Result<usize, StreamError> {
        self.stream_op(k, now, |s| s.write(k.id, data))
            .unwrap_or(Err(StreamError::SessionClosed))
    }

    pub fn finish(&mut self, k: StreamKey, now: Instant) {
        self.stream_op(k, now, |s| s.finish(k.id));
    }

    pub fn close_stream(&mut self, k: StreamKey, now: Instant) {
        self.stream_op(k, now, |s| s.close_stream(k.id));
    }

    /// The stream's destination dial succeeded.
    pub fn opened(&mut self, k: StreamKey, now: Instant) {
        self.stream_op(k, now, |s| s.stream_opened(k.id));
    }

    /// The stream's destination couldn't be reached.
    pub fn refuse(&mut self, k: StreamKey, now: Instant) {
        self.stream_op(k, now, |s| s.refuse_stream(k.id));
    }

    /// The relay is done with the stream.
    pub fn release(&mut self, k: StreamKey, now: Instant) {
        self.stream_op(k, now, |s| s.release_stream(k.id));
    }

    /// Whether the client reset or closed the stream (or its session ended).
    pub fn gone(&self, k: StreamKey) -> bool {
        self.serials
            .get(&k.session)
            .and_then(|sid| self.sessions.get(sid))
            .is_none_or(|ss| ss.s.stream_gone(k.id))
    }

    /// Whether the stream was aborted, as opposed to finished cleanly.
    pub fn aborted(&self, k: StreamKey) -> bool {
        self.serials
            .get(&k.session)
            .and_then(|sid| self.sessions.get(sid))
            .is_none_or(|ss| ss.s.stream_aborted(k.id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frames;
    use x25519_dalek::{PublicKey, StaticSecret};

    const ZONE: &str = "t.example.com";

    fn client_addr() -> SocketAddr {
        "192.0.2.1:5300".parse().unwrap()
    }

    fn query(z: &Zone, txn: u16, payload: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        dns::put_query(&mut b, txn, payload, z, dns::TYPE_TXT, dns::EDNS_SIZE);
        b
    }

    /// Sends msg and returns the answers produced at once.
    fn exchange(core: &mut ServerCore, msg: &[u8], now: Instant) -> Vec<dns::Answer> {
        core.handle(msg, client_addr(), now);
        core.take_transmits()
            .iter()
            .map(|t| dns::parse_answer(&t.msg).unwrap())
            .collect()
    }

    /// A server and an established client session with it.
    fn setup(now: Instant) -> (ServerCore, Zone, crypto::Session) {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut core = ServerCore::new(ServerConfig::new(ZONE, key.clone()), now).unwrap();
        let z = Zone::parse(ZONE).unwrap();
        let eph = StaticSecret::from([9; 32]);
        let mut hello = vec![0, 0];
        hello.extend_from_slice(PublicKey::from(&eph).as_bytes());
        let a = exchange(&mut core, &query(&z, 1, &hello), now);
        // A resolver's retry gets the same reply, without a second session.
        let again = exchange(&mut core, &query(&z, 2, &hello), now);
        assert_eq!(a[0].payload, again[0].payload);
        assert_eq!(core.session_count(), 1);
        let s = crypto::client_finish(&key.verifying_key(), &eph, &a[0].payload).unwrap();
        (core, z, s)
    }

    fn open(s: &crypto::Session, a: &dns::Answer, up_pn: u64) -> Vec<u8> {
        s.down.open_down(&a.payload, up_pn, u64::from).unwrap().1
    }

    #[test]
    fn idle_poll_is_held_until_its_hold_expires() {
        let t0 = Instant::now();
        let (mut core, z, s) = setup(t0);
        // Hold class 5 (500 ms), size class 0, a PING: nothing for the server to send.
        let poll = s.up.seal_up(s.sid, 0, &[0x50, frames::PING, 0, 0, 0]);
        assert!(
            exchange(&mut core, &query(&z, 3, &poll), t0).is_empty(),
            "answered at once"
        );
        // The 250 ms sweep comes first and leaves the poll alone; then the hold's deadline.
        assert_eq!(core.poll_timeout(), t0 + SWEEP_EVERY);
        core.handle_timeout(t0 + SWEEP_EVERY);
        assert!(core.take_transmits().is_empty());
        assert_eq!(core.poll_timeout(), t0 + Duration::from_millis(500));
        core.handle_timeout(t0 + Duration::from_millis(499));
        assert!(core.take_transmits().is_empty());
        core.handle_timeout(t0 + Duration::from_millis(500));
        let out = core.take_transmits();
        assert_eq!(out.len(), 1);
        let plain = open(&s, &dns::parse_answer(&out[0].msg).unwrap(), 0);
        assert_eq!(plain[0], 50, "held 500 ms, in 10 ms units");
    }

    #[test]
    fn poll_answered_early_is_not_answered_again_at_its_deadline() {
        let t0 = Instant::now();
        let (mut core, z, s) = setup(t0);
        // Open a stream; its answer carries the window grant, so nothing is left to send.
        let mut plain = vec![0x50];
        frames::put_stream(&mut plain, 0, 0, b"\x03a:1", false, true);
        assert_eq!(
            exchange(
                &mut core,
                &query(&z, 3, &s.up.seal_up(s.sid, 0, &plain)),
                t0
            )
            .len(),
            1
        );
        let k = StreamKey { session: 1, id: 0 };
        // A poll is held: there's nothing to send.
        let poll = s.up.seal_up(s.sid, 1, &[0x50, frames::PING, 0, 0, 0]);
        assert!(exchange(&mut core, &query(&z, 4, &poll), t0).is_empty());
        // The relay writes data: it goes out at once, in the held poll.
        let later = t0 + Duration::from_millis(10);
        assert_eq!(core.write(k, b"response", later), Ok(8));
        assert_eq!(
            core.take_transmits().len(),
            1,
            "the held poll carries the data at once"
        );
        // Its index entry is now stale: the deadline passes without a second answer.
        core.handle_timeout(t0 + Duration::from_millis(600));
        assert!(
            core.take_transmits().is_empty(),
            "a held poll was answered twice"
        );
    }

    /// Held polls are released in arrival order, which the client relies on to tell a lost poll
    /// from a held one. A later poll whose LOST frame makes data pending must not jump the queue.
    #[test]
    fn held_polls_are_released_oldest_first_even_when_a_poll_brings_data() {
        let t0 = Instant::now();
        let (mut core, z, s) = setup(t0);
        let mut plain = vec![0x50];
        frames::put_stream(&mut plain, 0, 0, b"\x03a:1", false, true);
        exchange(
            &mut core,
            &query(&z, 1, &s.up.seal_up(s.sid, 0, &plain)),
            t0,
        );
        let k = StreamKey { session: 1, id: 0 };
        let poll = |pn: u64, extra: &[u8]| {
            let mut p = vec![0x50];
            p.extend_from_slice(extra);
            p.resize(p.len().max(5), frames::PADDING);
            s.up.seal_up(s.sid, pn, &p)
        };
        // Poll 1 is held, then carries the relay's data out.
        assert!(exchange(&mut core, &query(&z, 2, &poll(1, &[frames::PING])), t0).is_empty());
        core.write(k, b"response", t0).unwrap();
        assert_eq!(core.take_transmits().len(), 1);
        // Poll 2 is held: nothing left to send.
        assert!(exchange(&mut core, &query(&z, 3, &poll(2, &[frames::PING])), t0).is_empty());
        // Poll 3 reports poll 1's answer lost, so its data is pending again.
        let mut lost = Vec::new();
        frames::put_lost(&mut lost, &[1]);
        let out = exchange(&mut core, &query(&z, 4, &poll(3, &lost)), t0);
        assert!(!out.is_empty());
        assert_eq!(
            out[0].txn, 3,
            "poll 2, held first, must be answered before poll 3"
        );
    }

    /// A resolver's retry of a data-bearing query is answered at once like the original, not held.
    #[test]
    fn duplicate_data_query_is_answered_at_once() {
        let t0 = Instant::now();
        let (mut core, z, s) = setup(t0);
        let mut plain = vec![0x50];
        frames::put_stream(&mut plain, 0, 0, b"\x03a:1", false, true);
        let packet = s.up.seal_up(s.sid, 0, &plain);
        assert_eq!(exchange(&mut core, &query(&z, 1, &packet), t0).len(), 1);
        assert_eq!(
            exchange(&mut core, &query(&z, 2, &packet), t0).len(),
            1,
            "the retry was held"
        );
    }

    /// Polls answered early leave stale deadline entries; the index stays bounded anyway.
    #[test]
    fn deadline_index_stays_bounded_by_held_polls() {
        let t0 = Instant::now();
        let (mut core, z, s) = setup(t0);
        let mut plain = vec![0x50];
        frames::put_stream(&mut plain, 0, 0, b"\x03a:1", false, true);
        exchange(
            &mut core,
            &query(&z, 1, &s.up.seal_up(s.sid, 0, &plain)),
            t0,
        );
        let k = StreamKey { session: 1, id: 0 };
        for pn in 1..3000u64 {
            let poll = s.up.seal_up(s.sid, pn, &[0x50, frames::PING, 0, 0, 0]);
            exchange(&mut core, &query(&z, pn as u16, &poll), t0);
            core.write(k, b"x", t0).unwrap(); // answers the poll at once
            core.take_transmits();
        }
        let bound = 2 * MAX_HELD * core.session_count() + 1024;
        assert!(
            core.held_deadlines.len() <= bound,
            "{} entries",
            core.held_deadlines.len()
        );
    }

    #[test]
    fn data_query_is_answered_at_once_and_opens_a_stream() {
        let t0 = Instant::now();
        let (mut core, z, s) = setup(t0);
        let mut plain = vec![0x50];
        frames::put_stream(&mut plain, 0, 0, b"\x0fexample.com:443", false, true);
        let a = exchange(
            &mut core,
            &query(&z, 4, &s.up.seal_up(s.sid, 0, &plain)),
            t0,
        );
        assert_eq!(a.len(), 1);
        let k = StreamKey { session: 1, id: 0 };
        assert_eq!(core.poll_event(), Some(ServerEvent::Accepted(k)));
        // The answer carries the server's window grant for the new stream.
        let down = open(&s, &a[0], 0);
        assert!(matches!(
            frames::parse(&down[2..]).unwrap()[0],
            frames::Frame::MaxStreamData { id: 0, .. }
        ));
        let mut buf = [0u8; 32];
        assert_eq!(core.read(k, &mut buf, t0), Read::Data(16));
        assert_eq!(&buf[1..16], b"example.com:443");
    }

    #[test]
    fn unknown_session_is_signed() {
        let t0 = Instant::now();
        let (mut core, z, s) = setup(t0);
        let poll = s.up.seal_up(s.sid ^ 1, 0, &[0x50, frames::PING, 0, 0, 0]);
        let a = exchange(&mut core, &query(&z, 5, &poll), t0);
        assert_eq!(a[0].rcode, dns::RCODE_NXDOMAIN);
        let key = SigningKey::from_bytes(&[7; 32]).verifying_key();
        assert!(crypto::verify_unknown_session(
            &key,
            &a[0].question,
            &a[0].payload
        ));
    }
}
