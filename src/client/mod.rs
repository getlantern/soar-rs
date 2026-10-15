//! The tunnel client: carries TCP streams through recursive resolvers to a Soar server.
//! [`ClientCore`] is the protocol; [`Client`] runs it on Tokio, with each stream a [`Conn`] that
//! implements `AsyncRead` and `AsyncWrite`.

mod core;
mod discovery;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Notify, mpsc, watch};
use tokio::task::JoinHandle;

pub use self::core::{
    ClientConfig, ClientCore, ClientEvent, PathStat, StreamRef, TcpMode, Transmit,
};
pub use self::discovery::{Discovery, ResolverCache};
use crate::session::Read;
use crate::stream::StreamError;

#[derive(Default)]
struct Wakers {
    read: Option<Waker>,
    write: Option<Waker>,
    /// Wakes every opened() waiting. Notify's waiters unregister themselves when a future is
    /// dropped, so cancelled waits leave nothing behind.
    opened: Arc<Notify>,
}

impl Wakers {
    fn wake_all(&mut self) {
        self.opened.notify_waiters();
        for w in [self.read.take(), self.write.take()].into_iter().flatten() {
            w.wake();
        }
    }
}

struct Link {
    tx: mpsc::Sender<Vec<u8>>,
    task: JoinHandle<()>,
}

/// The TCP links, and whether the client is shutting down: once it is, no link may start.
#[derive(Default)]
struct Links {
    by_addr: HashMap<SocketAddr, Link>,
    closed: bool,
}

struct Shared {
    core: Mutex<ClientCore>,
    udp4: UdpSocket,
    udp6: Option<UdpSocket>,
    links: Mutex<Links>,
    wakers: Mutex<HashMap<StreamRef, Wakers>>,
    /// Wakes the driver: something changed that may need sending.
    kick: Notify,
    /// The newest established session's generation.
    established: watch::Sender<u64>,
    /// Feeds the cache writer. Taken on Drop, which closes the channel: the writer stores what's
    /// queued, then exits.
    cache: Mutex<Option<mpsc::UnboundedSender<Vec<String>>>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Shared {
    fn core(&self) -> MutexGuard<'_, ClientCore> {
        lock(&self.core)
    }

    async fn transmit(self: &Arc<Self>, t: Transmit) {
        if t.tcp {
            // A full queue drops the message, which the query's deadline treats as loss.
            if let Some(l) = lock(&self.links).by_addr.get(&t.to) {
                let _ = l.tx.try_send(t.msg);
            }
            return;
        }
        let sock = match (t.to, &self.udp6) {
            (SocketAddr::V6(_), Some(s)) => s,
            _ => &self.udp4,
        };
        let _ = sock.send_to(&t.msg, t.to).await;
    }

    fn dispatch(self: &Arc<Self>, e: ClientEvent) {
        let wake = |r: StreamRef, f: fn(&mut Wakers) -> Option<Waker>| {
            if let Some(w) = lock(&self.wakers).get_mut(&r).and_then(f) {
                w.wake();
            }
        };
        match e {
            ClientEvent::Established(generation) => {
                self.established.send_replace(generation);
            }
            ClientEvent::SessionClosed(generation) => {
                lock(&self.wakers)
                    .iter_mut()
                    .filter(|(r, _)| r.session == generation)
                    .for_each(|(_, w)| w.wake_all());
            }
            ClientEvent::Readable(r) => wake(r, |w| w.read.take()),
            ClientEvent::Writable(r) => wake(r, |w| w.write.take()),
            ClientEvent::Opened(r) => {
                if let Some(w) = lock(&self.wakers).get(&r) {
                    w.opened.notify_waiters();
                }
            }
            ClientEvent::Aborted(r) => {
                if let Some(w) = lock(&self.wakers).get_mut(&r) {
                    w.wake_all();
                }
            }
            ClientEvent::TcpStart(addr) => {
                // Checked and inserted under one lock with Drop's shutdown, so a driver that
                // was mid-dispatch when the client dropped can't start a link that outlives it.
                let mut links = lock(&self.links);
                if links.closed {
                    return;
                }
                let (tx, rx) = mpsc::channel(256);
                let task = tokio::spawn(tcp_link(self.clone(), addr, rx));
                if let Some(old) = links.by_addr.insert(addr, Link { tx, task }) {
                    old.task.abort();
                }
            }
            ClientEvent::TcpStop(addr) => {
                if let Some(l) = lock(&self.links).by_addr.remove(&addr) {
                    l.task.abort();
                }
            }
            ClientEvent::CacheStore(good) => {
                if let Some(tx) = lock(&self.cache).as_ref() {
                    let _ = tx.send(good);
                }
            }
        }
    }

    /// Registers a waker for a stream, under the core lock so no event can slip between the
    /// check that found nothing and the registration.
    fn register(&self, r: StreamRef, cx: &Context<'_>, f: fn(&mut Wakers) -> &mut Option<Waker>) {
        *f(lock(&self.wakers).entry(r).or_default()) = Some(cx.waker().clone());
    }
}

/// Sends what the core produces and acts on its events, ticking it when its timers come due or
/// something kicks it.
async fn driver(sh: Arc<Shared>) {
    loop {
        let now = Instant::now();
        let (out, events, deadline) = {
            let mut c = sh.core();
            c.tick(now);
            let events: Vec<ClientEvent> = std::iter::from_fn(|| c.poll_event()).collect();
            (c.take_transmits(), events, c.poll_timeout(now))
        };
        for t in out {
            sh.transmit(t).await;
        }
        for e in events {
            sh.dispatch(e);
        }
        tokio::select! {
            _ = tokio::time::sleep_until(deadline.into()) => {}
            _ = sh.kick.notified() => {}
        }
    }
}

async fn recv(sh: Arc<Shared>, v6: bool) {
    let mut buf = vec![0u8; 4096];
    loop {
        let sock = if v6 {
            sh.udp6.as_ref().expect("bound")
        } else {
            &sh.udp4
        };
        match sock.recv_from(&mut buf).await {
            Ok((n, _)) => {
                sh.core().handle_answer(&buf[..n], Instant::now());
                sh.kick.notify_one();
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused
                ) => {}
            Err(_) => return,
        }
    }
}

/// Carries one resolver's queries over TCP, pipelined on one connection (RFC 7766). Some
/// networks intercept or block UDP/53 but leave TCP/53 alone. It redials with backoff for as long
/// as the client runs.
async fn tcp_link(sh: Arc<Shared>, addr: SocketAddr, mut rx: mpsc::Receiver<Vec<u8>>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let conn = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await;
        let Ok(Ok(conn)) = conn else {
            tokio::time::sleep(backoff).await;
            backoff = (2 * backoff).min(Duration::from_secs(30));
            continue;
        };
        backoff = Duration::from_secs(1);
        sh.core().tcp_link(addr, true, Instant::now());
        sh.kick.notify_one();
        serve_link(&sh, conn, &mut rx).await;
        // Answers to anything in flight on that connection are gone: fail those queries now so
        // their data goes out on other paths, rather than waiting out their deadlines.
        sh.core().tcp_link(addr, false, Instant::now());
        sh.kick.notify_one();
    }
}

async fn serve_link(sh: &Arc<Shared>, conn: TcpStream, rx: &mut mpsc::Receiver<Vec<u8>>) {
    let (mut rd, mut wr) = conn.into_split();
    let reader = async {
        let mut buf = vec![0u8; 65535];
        loop {
            // A black-holed connection accepts writes for a long time; a read deadline over
            // each whole message closes it so the link redials (resolvers drop idle TCP/53
            // anyway), including one that stalls partway through a message.
            let msg = async {
                let mut hdr = [0u8; 2];
                rd.read_exact(&mut hdr).await?;
                let n = usize::from(u16::from_be_bytes(hdr));
                rd.read_exact(&mut buf[..n]).await?;
                Ok::<_, io::Error>(n)
            };
            let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(30), msg).await else {
                return;
            };
            sh.core().handle_answer(&buf[..n], Instant::now());
            sh.kick.notify_one();
        }
    };
    let writer = async {
        while let Some(msg) = rx.recv().await {
            let mut framed = (msg.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&msg);
            if !matches!(
                tokio::time::timeout(Duration::from_secs(5), wr.write_all(&framed)).await,
                Ok(Ok(()))
            ) {
                return;
            }
        }
    };
    tokio::select! {
        _ = reader => {}
        _ = writer => {}
    }
}

/// A tunnel client. Dropping it ends the session at once and stops its tasks: data written to a
/// [`Conn`] but not yet delivered is discarded, even if the Conn was flushed or shut down, since
/// flushing hands bytes to the session, not to the server. Keep the Client until the streams
/// that matter have finished, as you'd wait for an EOF before tearing down any connection.
pub struct Client {
    sh: Arc<Shared>,
    tasks: Vec<JoinHandle<()>>,
    /// The resolver-cache writer: Drop leaves it to drain on its own; close() waits for it.
    cache_task: Option<JoinHandle<()>>,
}

impl Client {
    pub async fn new(cfg: ClientConfig) -> io::Result<Client> {
        let cache = cfg.discovery.cache.clone();
        let discovery = cfg.discovery.clone();
        let discovery_enabled = discovery.enabled;
        let mut core = ClientCore::new(cfg, Instant::now()).map_err(io::Error::other)?;
        if discovery.enabled {
            // Reads the cache and /etc/resolv.conf: off the async workers, and out of the core.
            let cands = tokio::task::spawn_blocking(move || discovery.candidates())
                .await
                .map_err(io::Error::other)?;
            core.add_candidates(cands);
        }
        let udp4 = UdpSocket::bind("0.0.0.0:0").await?;
        let udp6 = UdpSocket::bind("[::]:0").await.ok();
        if udp6.is_none() {
            core.disable_udp6(Instant::now());
        }
        // With no path and nothing for discovery to try, the client could never connect.
        if core.path_count() == 0 && !core.has_candidates() {
            return Err(io::Error::other(if discovery_enabled {
                "soar: no usable resolvers, and discovery found no candidates"
            } else {
                "soar: no usable resolvers (IPv6 resolvers, no IPv6 socket, TCP off)"
            }));
        }
        let mut tasks = Vec::new();
        let mut cache_task = None;
        let cache_tx = cache.map(|cache| {
            // One task stores snapshots in order, so a cache needn't be safe for concurrent use
            // and an older snapshot never lands last.
            // It isn't aborted on Drop, so a snapshot queued just before shutdown is still stored:
            // Drop closes the channel instead, and the writer exits once it has drained it.
            let (tx, mut rx) = mpsc::unbounded_channel::<Vec<String>>();
            cache_task = Some(tokio::spawn(async move {
                while let Some(good) = rx.recv().await {
                    let cache = cache.clone();
                    let _ = tokio::task::spawn_blocking(move || cache.store(&good)).await;
                }
            }));
            tx
        });
        let has6 = udp6.is_some();
        let sh = Arc::new(Shared {
            core: Mutex::new(core),
            udp4,
            udp6,
            links: Mutex::new(Links::default()),
            wakers: Mutex::new(HashMap::new()),
            kick: Notify::new(),
            established: watch::Sender::new(0),
            cache: Mutex::new(cache_tx),
        });
        tasks.push(tokio::spawn(driver(sh.clone())));
        tasks.push(tokio::spawn(recv(sh.clone(), false)));
        if has6 {
            tasks.push(tokio::spawn(recv(sh.clone(), true)));
        }
        Ok(Client {
            sh,
            tasks,
            cache_task,
        })
    }

    /// Opens a stream to addr (host:port) through the tunnel, handshaking first if needed. Bytes
    /// may be written at once; [`Conn::opened`] waits for the server to reach addr.
    pub async fn connect(&self, addr: &str) -> io::Result<Conn> {
        let mut est = self.sh.established.subscribe();
        loop {
            {
                let mut c = self.sh.core();
                c.connect(Instant::now());
                if c.established().is_some() {
                    let r = c.open_stream(addr).map_err(io::Error::other)?;
                    drop(c);
                    self.sh.kick.notify_one();
                    return Ok(Conn {
                        sh: self.sh.clone(),
                        r,
                    });
                }
            }
            self.sh.kick.notify_one();
            est.changed()
                .await
                .map_err(|_| io::Error::other(StreamError::SessionClosed))?;
        }
    }

    /// connect, then wait for the server to report the destination reachable.
    pub async fn connect_opened(&self, addr: &str) -> io::Result<Conn> {
        let conn = self.connect(addr).await?;
        conn.opened().await?;
        Ok(conn)
    }

    /// Whether a session with the server is up.
    pub fn established(&self) -> bool {
        self.sh.core().established().is_some()
    }

    pub fn path_stats(&self) -> Vec<PathStat> {
        self.sh.core().path_stats(Instant::now())
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl Client {
    /// Closes the client: ends the session and stops its tasks, then waits until any resolvers
    /// queued for the cache are stored. Dropping the Client does the same without waiting, so
    /// a snapshot queued just before the runtime shuts down could still be lost; call this when
    /// the cache matters.
    pub async fn close(mut self) {
        self.shutdown();
        if let Some(t) = self.cache_task.take() {
            let _ = t.await;
        }
    }

    /// Ends the session and stops the client's tasks. Idempotent.
    fn shutdown(&mut self) {
        self.sh.core().close();
        lock(&self.sh.cache).take();
        // The driver won't dispatch the close any more: wake every stream's waiters now, so
        // Conns that outlive the Client see it closed rather than hanging.
        for w in lock(&self.sh.wakers).values_mut() {
            w.wake_all();
        }
        for t in &self.tasks {
            t.abort();
        }
        let mut links = lock(&self.sh.links);
        links.closed = true;
        for (_, l) in links.by_addr.drain() {
            l.task.abort();
        }
    }
}

/// One tunneled stream. Dropping it closes it; written data is still delivered.
pub struct Conn {
    sh: Arc<Shared>,
    r: StreamRef,
}

fn stream_err(e: StreamError) -> io::Error {
    let kind = match e {
        StreamError::Reset | StreamError::Unreachable => io::ErrorKind::ConnectionReset,
        StreamError::Closed | StreamError::SessionClosed => io::ErrorKind::NotConnected,
    };
    io::Error::new(kind, e)
}

impl Conn {
    /// Waits for the server to report the stream's destination reachable.
    pub async fn opened(&self) -> io::Result<()> {
        let notify = lock(&self.sh.wakers)
            .entry(self.r)
            .or_default()
            .opened
            .clone();
        loop {
            // Register before checking, so an Opened dispatched in between still wakes us.
            let wait = notify.notified();
            tokio::pin!(wait);
            wait.as_mut().enable();
            {
                let mut c = self.sh.core();
                let opened = c.stream_opened(self.r);
                let aborted = c.stream_aborted(self.r);
                if let Some(r) = opened_result(opened, aborted, c.established(), self.r.session) {
                    return r.map_err(stream_err);
                }
            }
            wait.await;
        }
    }
}

/// What a waiting opened() reports, if anything yet. The session is checked before the stream:
/// when a session ends its streams are gone too, and that's SessionClosed, not a destination
/// that refused. Unreachable is a stream reset while its session is still up.
fn opened_result(
    opened: bool,
    aborted: bool,
    live_session: Option<u64>,
    session: u64,
) -> Option<Result<(), StreamError>> {
    if opened {
        return Some(Ok(()));
    }
    if live_session != Some(session) {
        return Some(Err(StreamError::SessionClosed));
    }
    aborted.then_some(Err(StreamError::Unreachable))
}

impl AsyncRead for Conn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(())); // nothing to read into: done, without waiting for data
        }
        let mut c = self.sh.core();
        match c.read(self.r, buf.initialize_unfilled()) {
            Read::Data(n) => {
                drop(c);
                buf.advance(n);
                self.sh.kick.notify_one(); // a window grant may be due
                Poll::Ready(Ok(()))
            }
            Read::Eof => Poll::Ready(Ok(())),
            Read::Err(e) => Poll::Ready(Err(stream_err(e))),
            Read::WouldBlock => {
                self.sh.register(self.r, cx, |w| &mut w.read);
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut c = self.sh.core();
        match c.write(self.r, data) {
            Ok(0) if !data.is_empty() => {
                self.sh.register(self.r, cx, |w| &mut w.write);
                Poll::Pending
            }
            Ok(n) => {
                drop(c);
                self.sh.kick.notify_one();
                Poll::Ready(Ok(n))
            }
            Err(e) => Poll::Ready(Err(stream_err(e))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// Sends a FIN: the peer reads EOF after the data written so far.
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.sh.core().finish(self.r);
        self.sh.kick.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.sh.core().close_stream(self.r);
        lock(&self.sh.wakers).remove(&self.r);
        self.sh.kick.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opened_reports_a_closed_session_as_such() {
        assert_eq!(opened_result(true, false, Some(1), 1), Some(Ok(())));
        assert_eq!(
            opened_result(false, false, Some(1), 1),
            None,
            "still waiting"
        );
        assert_eq!(
            opened_result(false, true, Some(1), 1),
            Some(Err(StreamError::Unreachable))
        );
        // The session ended (its streams with it): not a refusal by the destination.
        assert_eq!(
            opened_result(false, true, None, 1),
            Some(Err(StreamError::SessionClosed))
        );
        assert_eq!(
            opened_result(false, true, Some(2), 1),
            Some(Err(StreamError::SessionClosed))
        );
    }
}
