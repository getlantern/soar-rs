//! The tunnel client: carries TCP streams through recursive resolvers to a Soar server.
//! [`ClientCore`] is the protocol; [`Client`] runs it on Tokio, with each stream a [`Conn`] that
//! implements `AsyncRead` and `AsyncWrite`.

mod core;
mod discovery;

use std::collections::HashMap;
use std::future::poll_fn;
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
    opened: Option<Waker>,
}

impl Wakers {
    fn wake_all(&mut self) {
        for w in [self.read.take(), self.write.take(), self.opened.take()]
            .into_iter()
            .flatten()
        {
            w.wake();
        }
    }
}

struct Link {
    tx: mpsc::Sender<Vec<u8>>,
    task: JoinHandle<()>,
}

struct Shared {
    core: Mutex<ClientCore>,
    udp4: UdpSocket,
    udp6: Option<UdpSocket>,
    links: Mutex<HashMap<SocketAddr, Link>>,
    wakers: Mutex<HashMap<StreamRef, Wakers>>,
    /// Wakes the driver: something changed that may need sending.
    kick: Notify,
    /// The newest established session's generation.
    established: watch::Sender<u64>,
    cache: Option<mpsc::UnboundedSender<Vec<String>>>,
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
            if let Some(l) = lock(&self.links).get(&t.to) {
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
            ClientEvent::Opened(r) => wake(r, |w| w.opened.take()),
            ClientEvent::Aborted(r) => {
                if let Some(w) = lock(&self.wakers).get_mut(&r) {
                    w.wake_all();
                }
            }
            ClientEvent::TcpStart(addr) => {
                let (tx, rx) = mpsc::channel(256);
                let task = tokio::spawn(tcp_link(self.clone(), addr, rx));
                if let Some(old) = lock(&self.links).insert(addr, Link { tx, task }) {
                    old.task.abort();
                }
            }
            ClientEvent::TcpStop(addr) => {
                if let Some(l) = lock(&self.links).remove(&addr) {
                    l.task.abort();
                }
            }
            ClientEvent::CacheStore(good) => {
                if let Some(tx) = &self.cache {
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
            // A black-holed connection accepts writes for a long time; an idle read deadline
            // closes it so the link redials (resolvers drop idle TCP/53 anyway).
            let mut hdr = [0u8; 2];
            let idle = Duration::from_secs(30);
            if !matches!(
                tokio::time::timeout(idle, rd.read_exact(&mut hdr)).await,
                Ok(Ok(_))
            ) {
                return;
            }
            let n = usize::from(u16::from_be_bytes(hdr));
            if rd.read_exact(&mut buf[..n]).await.is_err() {
                return;
            }
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

/// A tunnel client. Dropping it stops its tasks.
pub struct Client {
    sh: Arc<Shared>,
    tasks: Vec<JoinHandle<()>>,
}

impl Client {
    pub async fn new(cfg: ClientConfig) -> io::Result<Client> {
        let cache = cfg.discovery.cache.clone();
        let core = ClientCore::new(cfg, Instant::now()).map_err(io::Error::other)?;
        let udp4 = UdpSocket::bind("0.0.0.0:0").await?;
        let udp6 = UdpSocket::bind("[::]:0").await.ok();
        let mut tasks = Vec::new();
        let cache_tx = cache.map(|cache| {
            // One task stores snapshots in order, so a cache needn't be safe for concurrent use
            // and an older snapshot never lands last.
            let (tx, mut rx) = mpsc::unbounded_channel::<Vec<String>>();
            tasks.push(tokio::spawn(async move {
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
            links: Mutex::new(HashMap::new()),
            wakers: Mutex::new(HashMap::new()),
            kick: Notify::new(),
            established: watch::Sender::new(0),
            cache: cache_tx,
        });
        tasks.push(tokio::spawn(driver(sh.clone())));
        tasks.push(tokio::spawn(recv(sh.clone(), false)));
        if has6 {
            tasks.push(tokio::spawn(recv(sh.clone(), true)));
        }
        Ok(Client { sh, tasks })
    }

    /// Opens a stream to addr (host:port) through the tunnel, handshaking first if needed. Bytes
    /// may be written at once; [`Conn::opened`] waits for the server to reach addr.
    pub async fn connect(&self, addr: &str) -> io::Result<Conn> {
        let mut est = self.sh.established.subscribe();
        loop {
            {
                let mut c = self.sh.core();
                c.connect();
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
        self.sh.core().close();
        for t in &self.tasks {
            t.abort();
        }
        for (_, l) in lock(&self.sh.links).drain() {
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
        poll_fn(|cx| {
            let mut c = self.sh.core();
            if c.stream_opened(self.r) {
                return Poll::Ready(Ok(()));
            }
            if c.stream_aborted(self.r) || c.established() != Some(self.r.session) {
                return Poll::Ready(Err(stream_err(StreamError::Unreachable)));
            }
            self.sh.register(self.r, cx, |w| &mut w.opened);
            Poll::Pending
        })
        .await
    }
}

impl AsyncRead for Conn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
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
