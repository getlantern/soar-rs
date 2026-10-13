//! The client as a state machine: resolver paths, query scheduling, loss and size control,
//! discovery. No I/O and no clock: [`ClientCore::tick`] after every input, send what
//! [`ClientCore::take_transmits`] returns, and act on [`ClientEvent`]s. See [`super`] for the
//! runtime.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

use super::discovery::{Discovery, parse_resolver};
use crate::crypto::{self, MIN_PLAIN, PUB_LEN, SIG_LEN, TAG_LEN};
use crate::dns::{self, Zone};
use crate::frames;
use crate::session::{Event, Read, Session, StreamConfig};
use crate::stream::StreamError;

/// When to use TCP/53 paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpMode {
    /// Add one for a resolver whose UDP path never answers.
    Auto,
    /// Add one for every resolver up front.
    On,
    /// Use TCP alone.
    Only,
    /// Never (except for resolvers `stream_only` reports).
    Off,
}

/// Reports whether a resolver speaks only a stream transport.
pub type StreamOnly = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Configures a tunnel client.
#[derive(Clone)]
pub struct ClientConfig {
    pub zone: String,
    pub server_key: VerifyingKey,
    /// Recursive resolvers (ip:port, or ip for port 53) to tunnel through, all at once. May be
    /// empty when discovery is enabled.
    pub resolvers: Vec<String>,
    pub discovery: Discovery,
    /// The name length every path starts at; some networks drop longer names (Iran ~101).
    pub safe_qname: usize,
    /// The name length paths probe up to.
    pub max_qname: usize,
    /// How long the server may hold an idle poll.
    pub hold: Duration,
    /// Queries outstanding across all paths.
    pub max_inflight: usize,
    /// Queries outstanding on one path.
    pub max_path_window: usize,
    /// The DNS answer size (bytes) paths may probe up to. Every path starts at 512, which every
    /// network delivers, and grows only while larger answers keep arriving.
    pub max_answer: usize,
    pub stream_window: u64,
    pub send_buffer: usize,
    pub max_streams: usize,
    pub tcp: TcpMode,
    /// Reports resolvers that only speak a stream transport: they get a TCP path from the start
    /// and never a UDP one, whatever `tcp` says.
    pub stream_only: Option<StreamOnly>,
}

impl ClientConfig {
    pub fn new(zone: &str, server_key: VerifyingKey, resolvers: &[&str]) -> ClientConfig {
        ClientConfig {
            zone: zone.to_owned(),
            server_key,
            resolvers: resolvers.iter().map(|s| s.to_string()).collect(),
            discovery: Discovery::default(),
            safe_qname: 101,
            max_qname: dns::MAX_NAME,
            hold: Duration::from_millis(500),
            max_inflight: 128,
            max_path_window: 32,
            max_answer: 1232,
            stream_window: 256 << 10,
            send_buffer: 64 << 10,
            max_streams: 64,
            tcp: TcpMode::Auto,
            stream_only: None,
        }
    }

    /// The answer-size class for max_answer (512 + 48*class bytes).
    fn max_limit_class(&self) -> usize {
        (self.max_answer.saturating_sub(512) / 48).min(LIMIT_CLASSES - 1)
    }
}

/// Answer limit = 512 + 48*class.
const LIMIT_CLASSES: usize = 16;
const OUTCOME_WINDOW: usize = 20;
const LATE_GRACE: Duration = Duration::from_secs(3);
const HELLO_RETRY: Duration = Duration::from_secs(1);
const MAX_HELLO_PATHS: usize = 16;
/// A session that gets no authenticated answer for this long while queries are outstanding is
/// presumed lost. The server's signed unknown-session answer is the fast path; this is the
/// backstop, since its signing is rate-limited.
const DEAD_SESSION_AFTER: Duration = Duration::from_secs(15);
/// Outcomes per side before an answer-size trial can pass.
const TRIAL_SAMPLES: usize = 16;
/// Successes at the proven size before a trial.
const EARN_TRIAL: usize = 8;

/// A DNS message to send to a resolver, over UDP or its TCP link.
#[derive(Debug)]
pub struct Transmit {
    pub to: SocketAddr,
    pub tcp: bool,
    pub msg: Vec<u8>,
}

/// Names a stream across sessions: a new session starts a new generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamRef {
    pub session: u64,
    pub id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEvent {
    /// A session is up: streams can open.
    Established(u64),
    /// A session ended; its streams are gone.
    SessionClosed(u64),
    Readable(StreamRef),
    Writable(StreamRef),
    /// The server reached the stream's destination.
    Opened(StreamRef),
    Aborted(StreamRef),
    /// Open a TCP/53 link to this resolver (and report it with `tcp_link`).
    TcpStart(SocketAddr),
    TcpStop(SocketAddr),
    /// The verified resolvers changed: store them in the cache.
    CacheStore(Vec<String>),
}

/// A small sliding window of query fates.
#[derive(Debug, Clone, Copy, Default)]
struct Outcomes {
    lost: [bool; 32],
    i: usize,
    n: usize,
}

impl Outcomes {
    fn lost_count(&self) -> usize {
        self.lost[..self.n].iter().filter(|&&l| l).count()
    }

    fn record(&mut self, lost: bool) {
        self.lost[self.i] = lost;
        self.i = (self.i + 1) % self.lost.len();
        self.n = (self.n + 1).min(self.lost.len());
    }
}

/// Whether a loses significantly more than b: by over a quarter of queries and by more than 3
/// standard errors of the difference, so loss that hits both alike never counts.
fn worse(a: &Outcomes, b: &Outcomes) -> bool {
    let (ka, kb) = (a.lost_count() as f64, b.lost_count() as f64);
    let (na, nb) = (a.n as f64, b.n as f64);
    let gap = ka / na - kb / nb;
    let pool = (ka + kb) / (na + nb);
    let se = (pool * (1.0 - pool) * (1.0 / na + 1.0 / nb)).sqrt();
    gap > 0.25f64.max(3.0 * se)
}

/// Heavy size-specific loss, caught early at fixed checkpoints so chance gets few tries.
fn blatant(a: &Outcomes, b: &Outcomes) -> bool {
    matches!(a.n, 8 | 16 | 24) && b.n >= 4 && a.lost_count() * 8 >= a.n * 7 && b.lost_count() == 0
}

fn after(t: Option<Instant>, now: Instant) -> bool {
    t.is_some_and(|t| t > now)
}

/// How long since t, treating "never" as forever ago.
fn since(now: Instant, t: Option<Instant>) -> Duration {
    t.map_or(Duration::MAX, |t| now.saturating_duration_since(t))
}

#[derive(Debug)]
struct Path {
    id: u64,
    addr: SocketAddr,
    tcp: bool,
    tcp_up: bool,
    /// A TCP path was added for this UDP path.
    sibling: bool,
    /// Added by discovery; pruned if it never answers.
    candidate: bool,
    created: Instant,
    /// The record type carrying answers: TXT, or AAAA where TXT is refused.
    qtype: u16,
    srtt: Duration,
    rttvar: Duration,
    has_rtt: bool,
    cwnd: f64,
    ssthresh: f64,
    inflight: usize,
    outcomes: [bool; OUTCOME_WINDOW],
    out_idx: usize,
    out_n: usize,
    last_cut: Option<Instant>,
    consec: u32,
    suspended: Option<Instant>,
    dead: bool,

    name_len: usize,
    probe_fails: u32,
    probing: bool,
    successes: u64,

    // Answer size, by class. size_ok is the largest class shown to arrive and size_ceil the
    // smallest shown not to (or one past max_class). While a trial runs, queries alternate
    // between `test` and size_ok so the two are judged side by side.
    size_ok: usize,
    size_ceil: usize,
    max_class: usize,
    test: usize,
    size_blocked: Option<Instant>,
    size_since: usize,
    size_fails: u32,
    test_win: Outcomes,
    base_win: Outcomes,
    alt: u64,
    last_hello: Option<Instant>,

    /// Has answered at least once.
    verified: bool,
    last_success: Option<Instant>,
    next_seq: u64,
    /// Highest per-path sequence number answered, plus one.
    max_answered: u64,
    /// Highest sequence number of a poll answered, plus one. The server releases held polls in
    /// the order they arrived, so a poll overtaken by later polls is lost, while one overtaken by
    /// data queries, which the server answers at once, may just be held.
    max_poll_answered: u64,
}

impl Path {
    fn usable(&self, now: Instant) -> bool {
        !self.dead && !after(self.suspended, now) && (!self.tcp || self.tcp_up)
    }

    /// How long a query may take before it's presumed lost, excluding any hold.
    fn rto(&self) -> Duration {
        if !self.has_rtt {
            return Duration::from_secs(1);
        }
        (self.srtt + (4 * self.rttvar).max(Duration::from_millis(50)))
            .clamp(Duration::from_millis(200), Duration::from_secs(3))
    }

    fn loss_rate(&self) -> f64 {
        if self.out_n == 0 {
            return 0.0;
        }
        self.outcomes[..self.out_n].iter().filter(|&&l| l).count() as f64 / self.out_n as f64
    }

    fn record(&mut self, lost: bool) {
        self.outcomes[self.out_idx] = lost;
        self.out_idx = (self.out_idx + 1) % OUTCOME_WINDOW;
        self.out_n = (self.out_n + 1).min(OUTCOME_WINDOW);
    }

    fn on_success(&mut self, now: Instant, rtt: Duration, max_win: usize) {
        self.record(false);
        self.consec = 0;
        self.verified = true;
        self.last_success = Some(now);
        self.successes += 1;
        if !rtt.is_zero() {
            if !self.has_rtt {
                (self.srtt, self.rttvar, self.has_rtt) = (rtt, rtt / 2, true);
            } else {
                let d = self.srtt.abs_diff(rtt);
                self.rttvar = (3 * self.rttvar + d) / 4;
                self.srtt = (7 * self.srtt + rtt) / 8;
            }
        }
        if self.cwnd < self.ssthresh {
            self.cwnd += 1.0;
        } else {
            self.cwnd += 1.0 / self.cwnd;
        }
        self.cwnd = self.cwnd.min(max_win as f64);
    }

    /// Backs off on runs of losses. Random loss is scattered among successes; a resolver's rate
    /// limit drops every query past its budget, so overload shows up as consecutive losses.
    fn on_loss(&mut self, now: Instant) {
        self.record(true);
        self.consec += 1;
        if self.consec >= 3 && since(now, self.last_cut) > self.rto() {
            self.cwnd = (self.cwnd * 0.7).max(1.0);
            self.ssthresh = self.cwnd.max(2.0);
            self.last_cut = Some(now);
        }
        if self.consec >= 5 && since(now, self.last_success) > Duration::from_secs(2) {
            let backoff =
                Duration::from_secs(1 << (self.consec - 5).min(4)).min(Duration::from_secs(15));
            self.suspended = Some(now + backoff);
            self.cwnd = 1.0;
        }
    }

    // Answer-size control works like path-MTU discovery, but every verdict is a side-by-side
    // comparison, because the losses that matter are size-specific: some networks silently drop
    // large DNS answers. Rate limits, random loss and outages hit small and large alike and must
    // not move the size.

    fn next_class(&mut self) -> usize {
        self.alt += 1;
        if self.test > 0 {
            return if self.alt.is_multiple_of(2) {
                self.test
            } else {
                self.size_ok
            };
        }
        if self.size_ok > 0 && self.alt.is_multiple_of(4) {
            return 0; // a 512-byte canary guarding the proven size
        }
        self.size_ok
    }

    fn size_outcome(&mut self, class: usize, lost: bool, now: Instant) {
        if self.test > 0 {
            if class == self.test {
                self.test_win.record(lost);
            } else if class == self.size_ok {
                self.base_win.record(lost);
            } else {
                return;
            }
            let full = self.test_win.n >= 2 * TRIAL_SAMPLES && self.base_win.n >= 2 * TRIAL_SAMPLES;
            if blatant(&self.test_win, &self.base_win)
                || full && worse(&self.test_win, &self.base_win)
            {
                self.size_failed(self.test, self.size_ok, now);
            } else if full {
                // Not measurably worse: keep the larger size.
                (self.size_ok, self.test, self.size_since, self.size_fails) = (self.test, 0, 0, 0);
                (self.test_win, self.base_win) = (Outcomes::default(), Outcomes::default());
            }
            return;
        }
        if self.size_ok > 0 && (class == self.size_ok || class == 0) {
            if class == 0 {
                self.base_win.record(lost);
            } else {
                self.test_win.record(lost);
            }
            let full = self.test_win.n >= self.test_win.lost.len() && self.base_win.n >= 8;
            if blatant(&self.test_win, &self.base_win)
                || full && worse(&self.test_win, &self.base_win)
            {
                self.size_failed(self.size_ok, 0, now);
                return;
            }
            if full {
                (self.test_win, self.base_win) = (Outcomes::default(), Outcomes::default());
            }
        }
        if class == self.size_ok && !lost {
            self.size_since += 1;
        }
        if self.test == 0
            && self.size_since >= EARN_TRIAL
            && !after(self.size_blocked, now)
            && self.size_ok + 1 < self.size_ceil
        {
            // Nothing has failed yet: try the largest; else binary search below the failure.
            self.test = if self.size_ceil > self.max_class {
                self.max_class
            } else {
                (self.size_ok + self.size_ceil) / 2
            };
            if self.test <= self.size_ok {
                self.test = 0;
                return;
            }
            (self.test_win, self.base_win) = (Outcomes::default(), Outcomes::default());
        }
    }

    /// Answers of class don't arrive: it becomes the ceiling and the path falls back to `back`.
    /// Trials back off exponentially, since whatever polices large answers may penalise repeat
    /// offenders.
    fn size_failed(&mut self, class: usize, back: usize, now: Instant) {
        self.size_ceil = self.size_ceil.min(class.max(1));
        self.size_ok = back.min(self.size_ceil - 1);
        (self.test, self.size_since) = (0, 0);
        (self.test_win, self.base_win) = (Outcomes::default(), Outcomes::default());
        let backoff = (Duration::from_secs(10) * (1 << (2 * self.size_fails.min(4))))
            .min(Duration::from_secs(1800));
        self.size_blocked = Some(now + backoff);
        self.size_fails += 1;
    }

    /// An answer of this class came back truncated: it's too big here.
    fn size_truncated(&mut self, class: usize, now: Instant) {
        if class > 0 {
            self.size_failed(class, self.size_ok.min(class - 1), now);
        }
    }
}

#[derive(Debug)]
struct PendingQuery {
    path: u64,
    /// The session generation it belongs to (0: none).
    session: u64,
    question: Vec<u8>,
    sent: Instant,
    deadline: Instant,
    pn: u64,
    hello: bool,
    probe: bool,
    expired: bool,
    /// Per-path send order.
    seq: u64,
    /// Carries no data: a hello or a probe of an unverified path.
    scout: bool,
    /// Carries no stream or control frames, so the server may hold it (SPEC §7.2): later queries
    /// being answered first says nothing about whether it was lost.
    poll: bool,
    /// An error answer arrived; it may be forged, so we keep waiting for the real one.
    err_rcode: Option<u8>,
    err_tc: bool,
    /// The answer-size class it asked for.
    class: usize,
}

struct ClientSession {
    generation: u64,
    eph: StaticSecret,
    s: Option<Session>,
    sid: u16,
    backlog: usize,
    last_auth: Option<Instant>,
    /// When the first query since the last authenticated answer went out.
    unanswered: Option<Instant>,
}

impl ClientSession {
    fn live(&self) -> Option<&Session> {
        self.s.as_ref().filter(|s| !s.is_closed())
    }
}

/// A snapshot of one resolver path, for diagnostics.
#[derive(Debug, Clone)]
pub struct PathStat {
    pub resolver: SocketAddr,
    pub tcp: bool,
    pub verified: bool,
    pub suspended: bool,
    pub candidate: bool,
    pub rtt: Duration,
    pub loss: f64,
    pub inflight: usize,
    pub window: f64,
    pub name_len: usize,
    /// The answer size accepted for this path; 0 until verified.
    pub answer_limit: usize,
    pub record_type: &'static str,
    pub successes: u64,
}

pub struct ClientCore {
    cfg: ClientConfig,
    zone: Zone,
    paths: Vec<Path>,
    next_path_id: u64,
    pending: HashMap<u16, PendingQuery>,
    sess: Option<ClientSession>,
    next_generation: u64,
    cands: Vec<String>,
    cand_idx: usize,
    last_cand: Option<Instant>,
    cached_verified: usize,
    out: Vec<Transmit>,
    events: VecDeque<ClientEvent>,
}

impl ClientCore {
    pub fn new(cfg: ClientConfig, now: Instant) -> Result<ClientCore, String> {
        let zone = Zone::parse(&cfg.zone).map_err(|e| e.to_string())?;
        let mut cfg = cfg;
        cfg.max_qname = cfg.max_qname.min(dns::MAX_NAME);
        cfg.safe_qname = cfg.safe_qname.min(cfg.max_qname);
        if zone.max_payload(cfg.safe_qname) < 2 + PUB_LEN {
            return Err("soar: safe_qname too short to carry a handshake under this zone".into());
        }
        if cfg.resolvers.is_empty() && !cfg.discovery.enabled {
            return Err("soar: no resolvers and discovery is off".into());
        }
        let mut c = ClientCore {
            zone,
            paths: Vec::new(),
            next_path_id: 1,
            pending: HashMap::new(),
            sess: None,
            next_generation: 1,
            cands: Vec::new(),
            cand_idx: 0,
            last_cand: None,
            cached_verified: 0,
            out: Vec::new(),
            events: VecDeque::new(),
            cfg,
        };
        for r in c.cfg.resolvers.clone() {
            let _ = c.add_path(&r, now);
        }
        if c.paths.is_empty() && !c.cfg.discovery.enabled {
            return Err("soar: no usable resolvers".into());
        }
        if c.cfg.discovery.enabled {
            c.cands = c.cfg.discovery.candidates();
        }
        Ok(c)
    }

    pub fn take_transmits(&mut self) -> Vec<Transmit> {
        std::mem::take(&mut self.out)
    }

    pub fn poll_event(&mut self) -> Option<ClientEvent> {
        self.events.pop_front()
    }

    fn add_path(&mut self, spec: &str, now: Instant) -> Result<(), String> {
        let addr = parse_resolver(spec).ok_or_else(|| format!("soar: bad resolver {spec:?}"))?;
        if self.paths.iter().any(|p| p.addr == addr) {
            return Ok(());
        }
        let stream_only = self.cfg.stream_only.as_ref().is_some_and(|f| f(spec));
        if self.cfg.tcp == TcpMode::Only || stream_only {
            self.new_path(addr, true, now);
            return Ok(());
        }
        self.new_path(addr, false, now);
        if self.cfg.tcp == TcpMode::On {
            self.paths.last_mut().expect("just added").sibling = true;
            self.new_path(addr, true, now);
        }
        Ok(())
    }

    fn new_path(&mut self, addr: SocketAddr, tcp: bool, now: Instant) -> &mut Path {
        let max_class = self.cfg.max_limit_class();
        let id = self.next_path_id;
        self.next_path_id += 1;
        if tcp {
            self.events.push_back(ClientEvent::TcpStart(addr));
        }
        self.paths.push(Path {
            id,
            addr,
            tcp,
            tcp_up: false,
            sibling: false,
            candidate: false,
            created: now,
            qtype: dns::TYPE_TXT,
            srtt: Duration::ZERO,
            rttvar: Duration::ZERO,
            has_rtt: false,
            cwnd: 4.0,
            ssthresh: self.cfg.max_path_window as f64,
            inflight: 0,
            outcomes: [false; OUTCOME_WINDOW],
            out_idx: 0,
            out_n: 0,
            last_cut: None,
            consec: 0,
            suspended: None,
            dead: false,
            name_len: self.cfg.safe_qname,
            probe_fails: 0,
            probing: false,
            successes: 0,
            size_ok: 0,
            size_ceil: max_class + 1,
            max_class,
            test: 0,
            size_blocked: None,
            size_since: 0,
            size_fails: 0,
            test_win: Outcomes::default(),
            base_win: Outcomes::default(),
            alt: 0,
            last_hello: None,
            verified: false,
            last_success: None,
            next_seq: 0,
            max_answered: 0,
            max_poll_answered: 0,
        });
        self.paths.last_mut().expect("just added")
    }

    fn path_mut(&mut self, id: u64) -> Option<&mut Path> {
        self.paths.iter_mut().find(|p| p.id == id)
    }

    /// A TCP/53 link to addr came up or went down. When it goes down, the answers to anything in
    /// flight on it are gone: those queries fail now, so their data goes out on other paths.
    pub fn tcp_link(&mut self, addr: SocketAddr, up: bool, now: Instant) {
        let ids: Vec<u64> = self
            .paths
            .iter()
            .filter(|p| p.tcp && p.addr == addr)
            .map(|p| p.id)
            .collect();
        for p in self.paths.iter_mut().filter(|p| ids.contains(&p.id)) {
            p.tcp_up = up;
        }
        if !up {
            for q in self.pending.values_mut() {
                if ids.contains(&q.path) && !q.expired && q.deadline > now {
                    q.deadline = now;
                }
            }
        }
    }

    /// Starts a handshake if there's no live session. Established arrives as an event.
    pub fn connect(&mut self) {
        let live = self
            .sess
            .as_ref()
            .is_some_and(|cs| cs.s.as_ref().is_none_or(|s| !s.is_closed()));
        if live {
            return;
        }
        let generation = self.next_generation;
        self.next_generation += 1;
        self.sess = Some(ClientSession {
            generation,
            eph: StaticSecret::random_from_rng(OsRng),
            s: None,
            sid: 0,
            backlog: 0,
            last_auth: None,
            unanswered: None,
        });
        for p in &mut self.paths {
            p.last_hello = None;
        }
    }

    /// The live session's generation, if one is established.
    pub fn established(&self) -> Option<u64> {
        self.sess
            .as_ref()
            .filter(|cs| cs.live().is_some())
            .map(|cs| cs.generation)
    }

    /// Closes the session, aborting its streams.
    pub fn close(&mut self) {
        if let Some(cs) = &mut self.sess
            && let Some(s) = &mut cs.s
        {
            s.close("soar: closed");
        }
        self.pump();
    }

    /// Moves the session's events to the client's queue.
    fn pump(&mut self) {
        let Some(cs) = &mut self.sess else { return };
        let Some(s) = &mut cs.s else { return };
        let generation = cs.generation;
        while let Some(e) = s.poll_event() {
            let r = |id| StreamRef {
                session: generation,
                id,
            };
            self.events.push_back(match e {
                Event::Readable(id) => ClientEvent::Readable(r(id)),
                Event::Writable(id) => ClientEvent::Writable(r(id)),
                Event::Opened(id) => ClientEvent::Opened(r(id)),
                Event::Aborted(id) => ClientEvent::Aborted(r(id)),
                Event::Closed => ClientEvent::SessionClosed(generation),
                Event::Accepted(_) => continue,
            });
        }
    }

    /// When tick next needs to run.
    pub fn poll_timeout(&self, now: Instant) -> Instant {
        let mut next = now + Duration::from_secs(1);
        for q in self.pending.values() {
            next = next.min(if q.expired {
                q.deadline + LATE_GRACE
            } else {
                q.deadline
            });
        }
        for p in &self.paths {
            if let Some(s) = p.suspended
                && s > now
            {
                next = next.min(s);
            }
        }
        next.max(now + Duration::from_millis(1))
    }

    /// Runs everything time- or state-driven: expiring queries, liveness, discovery, and filling
    /// paths with queries.
    pub fn tick(&mut self, now: Instant) {
        self.expire(now);
        self.check_liveness(now);
        self.discover(now);
        self.add_tcp_siblings(now);
        self.fill(now);
        self.pump();
    }

    fn expire(&mut self, now: Instant) {
        let txns: Vec<u16> = self.pending.keys().copied().collect();
        for txn in txns {
            let q = &self.pending[&txn];
            if q.expired {
                if now > q.deadline + LATE_GRACE {
                    self.pending.remove(&txn);
                }
                continue;
            }
            // Packet threshold: three later queries on this path were answered. A poll counts only
            // later polls: the server holds polls while it answers data queries at once, so being
            // overtaken by those is no sign of loss.
            let early = self.paths.iter().find(|p| p.id == q.path).is_some_and(|p| {
                let answered = if q.poll {
                    p.max_poll_answered
                } else {
                    p.max_answered
                };
                p.has_rtt
                    && answered >= q.seq + 4
                    && now.saturating_duration_since(q.sent) > p.srtt + 2 * p.rttvar
            });
            if now < q.deadline && !early {
                continue;
            }
            let q = self.pending.get_mut(&txn).expect("listed");
            q.expired = true;
            // A held error answer may be forged, so it only counts once no real answer came in the
            // whole deadline; expired early, the real one may yet arrive.
            let trusted = now >= q.deadline;
            let (path, class, err_tc, refused) = (
                q.path,
                q.class,
                q.err_tc,
                q.err_rcode == Some(dns::RCODE_REFUSED) && trusted,
            );
            if err_tc
                && trusted
                && let Some(p) = self.path_mut(path)
            {
                p.size_truncated(class, now); // answers this size get truncated here
            }
            self.fail(txn, now, refused);
        }
    }

    fn check_liveness(&mut self, now: Instant) {
        let Some(cs) = &mut self.sess else { return };
        let (Some(s), Some(t)) = (&mut cs.s, cs.unanswered) else {
            return;
        };
        if !s.is_closed() && now.saturating_duration_since(t) >= DEAD_SESSION_AFTER {
            s.close("soar: no authenticated answers; session presumed lost");
        }
    }

    fn any_usable(&self, now: Instant) -> bool {
        self.paths.iter().any(|p| p.verified && p.usable(now))
    }

    /// A query got no usable answer.
    fn fail(&mut self, txn: u16, now: Instant, refused: bool) {
        let q = &self.pending[&txn];
        let (path, probe, class, hello, generation, pn) =
            (q.path, q.probe, q.class, q.hello, q.session, q.pn);
        let safe = self.cfg.safe_qname;
        if let Some(p) = self.path_mut(path) {
            p.inflight = p.inflight.saturating_sub(1);
            if probe {
                p.probing = false;
                p.probe_fails += 1;
            }
            // A promoted name length that then fails repeatedly goes back to safe for good.
            if p.name_len > safe && p.consec >= 2 {
                (p.name_len, p.probe_fails) = (safe, 2);
            }
            if refused && p.qtype == dns::TYPE_TXT {
                // Some resolvers refuse TXT (seen in Iran): carry answers in AAAA instead.
                p.qtype = dns::TYPE_AAAA;
                (p.out_n, p.consec, p.suspended) = (0, 0, None);
            } else {
                if refused {
                    p.consec += 2;
                }
                p.on_loss(now);
                p.size_outcome(class, true, now);
            }
        }
        // Never suspend every path: with nothing in flight nothing can recover, and the session
        // would be presumed lost. The last usable one keeps probing at a window of 1.
        if self
            .paths
            .iter()
            .any(|p| p.id == path && after(p.suspended, now))
            && !self.any_usable(now)
        {
            self.path_mut(path).expect("found").suspended = None;
        }
        if hello {
            return;
        }
        if let Some(cs) = &mut self.sess
            && cs.generation == generation
            && let Some(s) = &mut cs.s
        {
            s.declare_lost(pn);
            s.lost_q.push(pn);
        }
    }

    /// How many queries the session wants outstanding with nothing else to send.
    fn want_queries(s: &Session, backlog: usize) -> usize {
        if s.stream_count() == 0 {
            return usize::from(!s.to_ack.is_empty() || s.data_in_flight());
        }
        2 + backlog
    }

    fn live_queries(&self) -> usize {
        self.pending.values().filter(|q| !q.expired).count()
    }

    fn fill(&mut self, now: Instant) {
        let Some(cs) = &self.sess else { return };
        let Some(s) = &cs.s else {
            return self.send_hellos(now);
        };
        if s.is_closed() {
            return;
        }
        // Keep one probe on each unverified path, so new and recovering resolvers get vetted,
        // but only while there's real traffic: else an idle session would never go quiet.
        let busy = s.stream_count() > 0 || s.ctrl_pending() || s.data_in_flight();
        if busy {
            let ids: Vec<u64> = self.paths.iter().map(|p| p.id).collect();
            for id in ids {
                if self.live_queries() >= self.cfg.max_inflight {
                    break;
                }
                let p = self.paths.iter().find(|p| p.id == id).expect("listed");
                if !p.verified && p.inflight == 0 && p.usable(now) {
                    self.send_data(id, now, false);
                }
            }
        }
        loop {
            let (mut inflight, mut polls) = (0, 0);
            for q in self.pending.values().filter(|q| !q.expired) {
                inflight += 1;
                polls += usize::from(!q.scout);
            }
            if inflight >= self.cfg.max_inflight {
                return;
            }
            let cs = self.sess.as_ref().expect("checked");
            let s = cs.s.as_ref().expect("checked");
            if !s.has_data() && polls >= Self::want_queries(s, cs.backlog) {
                return;
            }
            let Some(id) = self.pick_path(now, None) else {
                return;
            };
            self.send_data(id, now, true);
        }
    }

    /// The path with a free slot and the earliest expected answer.
    fn pick_path(&self, now: Instant, exclude: Option<u64>) -> Option<u64> {
        let mut best: Option<(f64, u64)> = None;
        for p in &self.paths {
            if Some(p.id) == exclude
                || !p.usable(now)
                || p.inflight as f64 >= p.cwnd
                || (!p.verified && p.inflight > 0)
            {
                continue;
            }
            let rtt = if p.has_rtt { p.srtt } else { p.rto() };
            let score = rtt.as_secs_f64() * (1.0 + p.inflight as f64 / p.cwnd)
                / (1.0 - p.loss_rate().min(0.9));
            if best.is_none_or(|(b, _)| score < b) {
                best = Some((score, p.id));
            }
        }
        best.map(|(_, id)| id)
    }

    fn send_hellos(&mut self, now: Instant) {
        let cs = self.sess.as_ref().expect("checked");
        let mut payload = vec![0, 0];
        payload.extend_from_slice(PublicKey::from(&cs.eph).as_bytes());
        let generation = cs.generation;
        let mut sent = 0;
        let ids: Vec<u64> = self.paths.iter().map(|p| p.id).collect();
        for id in ids {
            if sent >= MAX_HELLO_PATHS || self.live_queries() >= self.cfg.max_inflight {
                break;
            }
            let p = self.path_mut(id).expect("listed");
            if !p.usable(now) || p.inflight > 0 || since(now, p.last_hello) < HELLO_RETRY {
                continue;
            }
            p.last_hello = Some(now);
            let q = self.query(id, generation, now);
            self.send(
                id,
                PendingQuery {
                    hello: true,
                    scout: true,
                    ..q
                },
                &payload,
                now,
                HELLO_RETRY,
            );
            sent += 1;
        }
    }

    fn query(&self, path: u64, session: u64, now: Instant) -> PendingQuery {
        PendingQuery {
            path,
            session,
            question: Vec::new(),
            sent: now,
            deadline: now,
            pn: 0,
            hello: false,
            probe: false,
            expired: false,
            seq: 0,
            scout: false,
            poll: false,
            err_rcode: None,
            err_tc: false,
            class: 0,
        }
    }

    fn send_data(&mut self, id: u64, now: Instant, allow_dup: bool) {
        let (max_qname, hold) = (self.cfg.max_qname, self.cfg.hold);
        let p = self.paths.iter_mut().find(|p| p.id == id).expect("listed");
        let mut name_len = p.name_len;
        let mut probe = false;
        if !p.probing && p.successes >= 3 && p.name_len < max_qname && p.probe_fails < 2 {
            (name_len, probe, p.probing) = (max_qname, true, true);
        }
        let verified = p.verified;
        let class = p.next_class();
        let timeout_base = p.rto();
        let mut budget = self
            .zone
            .max_payload(name_len)
            .saturating_sub(4 + TAG_LEN + 1);
        if !verified {
            budget = MIN_PLAIN; // a probe: don't strand data on a path that may be dead
        }
        let hold_class = (hold.as_millis() / 100).min(15) as u8;
        let hdr = hold_class << 4 | class as u8;

        let cs = self.sess.as_mut().expect("established");
        let s = cs.s.as_mut().expect("established");
        let mut plain = vec![hdr];
        let (pn, data, tracked) = s.build(&mut plain, budget, now, 0);
        if probe {
            // Pad to the length under test (inside the seal), or a short probe would "prove" it.
            plain.resize(1 + budget, frames::PADDING);
        }
        let dup = allow_dup && tracked && s.carries_streams(pn) && verified && !s.has_data();
        let payload = s.seal.seal_up(cs.sid, pn, &plain);
        let mut timeout = timeout_base;
        if !data {
            timeout += hold;
        }
        cs.unanswered.get_or_insert(now);
        let generation = cs.generation;
        let q = self.query(id, generation, now);
        self.send(
            id,
            PendingQuery {
                pn,
                probe,
                scout: !verified,
                poll: !data,
                class,
                ..q
            },
            &payload,
            now,
            timeout,
        );
        // The tail of an upload (often a whole request) goes out twice, on another path if there
        // is one, so the copies don't share a failure.
        if dup {
            let p2 = self
                .pick_path(now, Some(id))
                .filter(|&p2| self.paths.iter().any(|p| p.id == p2 && p.verified))
                .or_else(|| self.pick_path(now, None));
            if let Some(p2) = p2
                && self.paths.iter().any(|p| p.id == p2 && p.verified)
            {
                let s = self
                    .sess
                    .as_mut()
                    .and_then(|cs| cs.s.as_mut())
                    .expect("established");
                if s.requeue(pn) {
                    self.send_data(p2, now, false);
                }
            }
        }
    }

    fn send(
        &mut self,
        id: u64,
        mut q: PendingQuery,
        payload: &[u8],
        now: Instant,
        timeout: Duration,
    ) {
        let mut txn = (OsRng.next_u32() & 0xFFFF) as u16;
        while self.pending.contains_key(&txn) {
            txn = (OsRng.next_u32() & 0xFFFF) as u16;
        }
        let Some(p) = self.paths.iter_mut().find(|p| p.id == id) else {
            return;
        };
        let mut msg = Vec::with_capacity(300);
        dns::put_query(&mut msg, txn, payload, &self.zone, p.qtype, dns::EDNS_SIZE);
        let Ok(end) = dns::skip_name(&msg, dns::HDR_LEN) else {
            return;
        };
        q.question = msg[dns::HDR_LEN..end + 4].to_vec();
        q.sent = now;
        q.deadline = now + timeout;
        q.seq = p.next_seq;
        p.next_seq += 1;
        p.inflight += 1;
        self.out.push(Transmit {
            to: p.addr,
            tcp: p.tcp,
            msg,
        });
        self.pending.insert(txn, q);
    }

    /// Handles a DNS answer from a resolver, over UDP or TCP.
    pub fn handle_answer(&mut self, msg: &[u8], now: Instant) {
        self.on_answer(msg, now);
        self.pump();
    }

    fn on_answer(&mut self, msg: &[u8], now: Instant) {
        let Ok(a) = dns::parse_answer(msg) else {
            return;
        };
        // Off-path injectors can't match the question; on-path ones fail authentication below.
        let Some(q) = self.pending.get(&a.txn) else {
            return;
        };
        if !a.question.eq_ignore_ascii_case(&q.question) {
            return;
        }
        let (late, generation, hello, up_pn, path, seq, sent, probe, class, poll) = (
            q.expired, q.session, q.hello, q.pn, q.path, q.seq, q.sent, q.probe, q.class, q.poll,
        );
        if a.tc || a.rcode != dns::RCODE_OK || !a.carried {
            if a.rcode == dns::RCODE_NXDOMAIN {
                // Only an answer the server signed over this question ends the session; an
                // unsigned NXDOMAIN may be injected, so it's ignored like a forged NOERROR.
                let signed = a.payload.len() == SIG_LEN
                    && crypto::verify_unknown_session(
                        &self.cfg.server_key,
                        &q.question,
                        &a.payload,
                    );
                let mut ended = false;
                if let Some(cs) = &mut self.sess
                    && signed
                    && !hello
                    && cs.generation == generation
                    && let Some(s) = &mut cs.s
                {
                    s.close("soar: server lost the session");
                    ended = true;
                }
                if ended && !late {
                    self.fail(a.txn, now, false);
                    self.pending.remove(&a.txn);
                }
                return;
            }
            let q = self.pending.get_mut(&a.txn).expect("found");
            if late || q.err_rcode.is_some() {
                return;
            }
            // An unauthenticated answer may be injected (China's GFW forges them on UDP/53), so it
            // never cuts the wait for the real one short. It's only recorded: if no authenticated
            // answer comes by the deadline, it says why the query failed.
            q.err_rcode = Some(if a.tc { dns::RCODE_SERVFAIL } else { a.rcode });
            q.err_tc = a.tc;
            return;
        }
        if hello {
            return self.on_hello(a.txn, &a.payload, now);
        }
        let Some(cs) = &mut self.sess else { return };
        let Some(s) = &mut cs.s else { return };
        if cs.generation != generation {
            return;
        }
        let (largest, have) = (s.largest_recv, s.have_recv);
        let Ok((pn, plain)) = s
            .open
            .open_down(&a.payload, up_pn, |t| crypto::decode_pn(largest, have, t))
        else {
            return; // forged or corrupt: keep waiting for the real answer
        };
        if plain.len() < 2 {
            return;
        }
        self.pending.remove(&a.txn);
        cs.last_auth = Some(now);
        cs.unanswered = None;
        let held = Duration::from_millis(10 * u64::from(plain[0]));
        cs.backlog = usize::from(plain[1]);
        s.receive(pn, &plain[2..], now);
        s.acked(up_pn);
        let (max_qname, max_win) = (self.cfg.max_qname, self.cfg.max_path_window);
        let Some(p) = self.path_mut(path) else { return };
        p.max_answered = p.max_answered.max(seq + 1);
        if poll {
            p.max_poll_answered = p.max_poll_answered.max(seq + 1);
        }
        if late {
            return;
        }
        p.inflight = p.inflight.saturating_sub(1);
        if probe {
            p.probing = false;
            p.name_len = max_qname;
        }
        p.on_success(
            now,
            now.saturating_duration_since(sent).saturating_sub(held),
            max_win,
        );
        p.size_outcome(class, false, now);
    }

    fn on_hello(&mut self, txn: u16, reply: &[u8], now: Instant) {
        let q = &self.pending[&txn];
        let (path, generation, expired, sent) = (q.path, q.session, q.expired, q.sent);
        let Some(cs) = &self.sess else { return };
        if cs.generation != generation {
            return;
        }
        let Ok(hs) = crypto::client_finish(&self.cfg.server_key, &cs.eph, reply) else {
            return; // forged
        };
        self.pending.remove(&txn);
        let max_win = self.cfg.max_path_window;
        if !expired && let Some(p) = self.path_mut(path) {
            p.inflight = p.inflight.saturating_sub(1);
            p.on_success(now, now.saturating_duration_since(sent), max_win);
        }
        let cfg = StreamConfig {
            stream_window: self.cfg.stream_window,
            send_buffer: self.cfg.send_buffer,
            max_streams: self.cfg.max_streams,
        };
        let cs = self.sess.as_mut().expect("checked");
        if cs.s.is_some() {
            return;
        }
        cs.s = Some(Session::new(true, cfg, hs.up, hs.down));
        cs.sid = hs.sid;
        cs.last_auth = Some(now);
        self.events.push_back(ClientEvent::Established(generation));
    }

    /// Gives a TCP path to each resolver whose UDP path has failed repeatedly without ever
    /// answering.
    fn add_tcp_siblings(&mut self, now: Instant) {
        if self.cfg.tcp != TcpMode::Auto {
            return;
        }
        let want: Vec<(SocketAddr, bool)> = self
            .paths
            .iter_mut()
            .filter(|p| !p.tcp && !p.sibling && !p.verified && p.out_n >= 2)
            .map(|p| {
                p.sibling = true;
                (p.addr, p.candidate)
            })
            .collect();
        for (addr, candidate) in want {
            self.new_path(addr, true, now).candidate = candidate;
        }
    }

    /// Adds candidate paths at the configured pace while too few paths are verified, and prunes
    /// candidates that failed without ever answering.
    fn discover(&mut self, now: Instant) {
        if !self.cfg.discovery.enabled {
            return;
        }
        let (mut verified, mut probing) = (0, 0);
        let mut stopped = Vec::new();
        self.paths.retain(|p| {
            if p.verified {
                verified += 1;
                return true;
            }
            if p.candidate
                && (p.out_n >= 3 && p.inflight == 0
                    || p.tcp && now.saturating_duration_since(p.created) > Duration::from_secs(10))
            {
                if p.tcp {
                    stopped.push(p.addr);
                }
                return false; // never answered: drop it
            }
            if p.candidate {
                probing += 1;
            }
            true
        });
        self.events
            .extend(stopped.into_iter().map(ClientEvent::TcpStop));
        if verified != self.cached_verified && self.cfg.discovery.cache.is_some() {
            self.cached_verified = verified;
            // Cache every verified resolver, whatever transport verified it: a TCP-only resolver
            // is the usual case where UDP/53 is intercepted, and it gets its TCP path again on load.
            let mut good: Vec<String> = Vec::new();
            for p in self.paths.iter().filter(|p| p.verified) {
                let a = p.addr.to_string();
                if !good.contains(&a) {
                    good.push(a);
                }
            }
            self.events.push_back(ClientEvent::CacheStore(good));
        }
        let d = &self.cfg.discovery;
        if verified >= d.want || probing >= d.concurrency || since(now, self.last_cand) < d.pace {
            return;
        }
        while self.cand_idx < self.cands.len() {
            let r = self.cands[self.cand_idx].clone();
            self.cand_idx += 1;
            let before = self.paths.len();
            if self.add_path(&r, now).is_ok() && self.paths.len() > before {
                for p in &mut self.paths[before..] {
                    p.candidate = true;
                }
                self.last_cand = Some(now);
                return;
            }
        }
    }

    pub fn path_stats(&self, now: Instant) -> Vec<PathStat> {
        self.paths
            .iter()
            .map(|p| PathStat {
                resolver: p.addr,
                tcp: p.tcp,
                verified: p.verified,
                suspended: after(p.suspended, now),
                candidate: p.candidate,
                rtt: if p.has_rtt { p.srtt } else { Duration::ZERO },
                loss: p.loss_rate(),
                inflight: p.inflight,
                window: p.cwnd,
                name_len: p.name_len,
                answer_limit: if p.verified { 512 + 48 * p.size_ok } else { 0 },
                record_type: if p.qtype == dns::TYPE_AAAA {
                    "AAAA"
                } else {
                    "TXT"
                },
                successes: p.successes,
            })
            .collect()
    }

    // The stream API. Streams belong to a session generation; one from an earlier session is gone.

    fn session_for(&mut self, r: StreamRef) -> Option<&mut Session> {
        self.sess
            .as_mut()
            .filter(|cs| cs.generation == r.session)
            .and_then(|cs| cs.s.as_mut())
    }

    /// Opens a stream to addr (host:port) on the established session.
    pub fn open_stream(&mut self, addr: &str) -> Result<StreamRef, StreamError> {
        let cs = self.sess.as_mut().ok_or(StreamError::SessionClosed)?;
        let s = cs.s.as_mut().ok_or(StreamError::SessionClosed)?;
        let id = s.open_stream(addr)?;
        Ok(StreamRef {
            session: cs.generation,
            id,
        })
    }

    pub fn read(&mut self, r: StreamRef, buf: &mut [u8]) -> Read {
        let res = self
            .session_for(r)
            .map_or(Read::Err(StreamError::SessionClosed), |s| s.read(r.id, buf));
        self.pump();
        res
    }

    pub fn write(&mut self, r: StreamRef, data: &[u8]) -> Result<usize, StreamError> {
        let res = self
            .session_for(r)
            .map_or(Err(StreamError::SessionClosed), |s| s.write(r.id, data));
        self.pump();
        res
    }

    pub fn finish(&mut self, r: StreamRef) {
        if let Some(s) = self.session_for(r) {
            s.finish(r.id);
        }
        self.pump();
    }

    /// Closes both directions and releases the stream.
    pub fn close_stream(&mut self, r: StreamRef) {
        if let Some(s) = self.session_for(r) {
            s.close_stream(r.id);
            s.release_stream(r.id);
        }
        self.pump();
    }

    pub fn stream_opened(&mut self, r: StreamRef) -> bool {
        self.session_for(r)
            .is_some_and(|s| s.stream_is_opened(r.id))
    }

    pub fn stream_aborted(&mut self, r: StreamRef) -> bool {
        self.session_for(r).is_none_or(|s| s.stream_aborted(r.id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn even_loss_never_moves_answer_size() {
        let now = Instant::now();
        let key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key();
        let mut c = ClientCore::new(
            ClientConfig::new("t.example.com", key, &["192.0.2.1:53"]),
            now,
        )
        .unwrap();
        let p = &mut c.paths[0];
        for i in 0..2000u64 {
            let class = p.next_class();
            p.size_outcome(class, i % 5 == 0, now);
        }
        assert!(
            p.size_ok > 0,
            "loss that hits every size alike must not block growth"
        );
        assert_eq!(p.size_ceil, p.max_class + 1, "and must not set a ceiling");
    }

    #[test]
    fn size_specific_loss_is_found() {
        let now = Instant::now();
        let key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key();
        let mut c = ClientCore::new(
            ClientConfig::new("t.example.com", key, &["192.0.2.1:53"]),
            now,
        )
        .unwrap();
        let p = &mut c.paths[0];
        // Answers above class 6 never arrive.
        for _ in 0..4000 {
            let class = p.next_class();
            p.size_outcome(class, class > 6, now + Duration::from_secs(3600));
            p.size_blocked = None;
        }
        assert!(p.size_ok <= 6 && p.size_ok >= 5, "settled at {}", p.size_ok);
    }
}
