//! The Tokio runtimes end to end on loopback: shutdown and abort paths.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use soar::client::{Client, ClientConfig, TcpMode};
use soar::server::{DialPolicy, ServerConfig, serve};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, UdpSocket};

const ZONE: &str = "t.example.com";

fn key() -> SigningKey {
    SigningKey::from_bytes(&[3; 32])
}

/// Starts a server on loopback that may dial loopback destinations.
async fn start_server() -> (String, tokio::task::JoinHandle<std::io::Result<()>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap().to_string();
    let dial = DialPolicy {
        allow_ports: None,
        allow_private: true,
        ..DialPolicy::default()
    };
    (
        addr,
        tokio::spawn(serve(sock, ServerConfig::new(ZONE, key()), dial)),
    )
}

/// A destination that answers each connection's "ping" with "pong".
async fn start_ponger() -> String {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = ln.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 4];
                if s.read_exact(&mut b).await.is_ok() && &b == b"ping" {
                    let _ = s.write_all(b"pong").await;
                }
            });
        }
    });
    addr
}

async fn ping(c: &Client, dest: &str) -> std::io::Result<()> {
    let mut conn = c.connect(dest).await?;
    conn.write_all(b"ping").await?;
    let mut b = [0u8; 4];
    conn.read_exact(&mut b).await?;
    assert_eq!(&b, b"pong");
    Ok(())
}

/// A client idle past the server's idle timeout must not dial on the session the server ended:
/// the first connect after the pause has to work, not fail with "server lost the session".
#[tokio::test(flavor = "multi_thread")]
async fn idle_session_is_retired_before_the_server_forgets_it() {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = sock.local_addr().unwrap().to_string();
    let dial = DialPolicy {
        allow_ports: None,
        allow_private: true,
        ..DialPolicy::default()
    };
    let mut scfg = ServerConfig::new(ZONE, key());
    scfg.idle_timeout = Duration::from_secs(1);
    tokio::spawn(serve(sock, scfg, dial));
    let dest = start_ponger().await;
    let mut cfg = ClientConfig::new(ZONE, key().verifying_key(), &[&server]);
    cfg.tcp = TcpMode::Off;
    cfg.session_idle = Duration::from_millis(500);
    let c = Client::new(cfg).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), ping(&c, &dest))
        .await
        .expect("first ping timed out")
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await; // the server has ended the session by now
    tokio::time::timeout(Duration::from_secs(10), ping(&c, &dest))
        .await
        .expect("ping after idling timed out")
        .expect("first connect after idling failed");
}

/// Even a session_idle so short that every session is idle by the time it's used must not stop
/// connect from opening a stream on the session it just waited for.
#[tokio::test(flavor = "multi_thread")]
async fn tiny_session_idle_still_connects() {
    let (server, _srv) = start_server().await;
    let dest = start_ponger().await;
    let mut cfg = ClientConfig::new(ZONE, key().verifying_key(), &[&server]);
    cfg.tcp = TcpMode::Off;
    cfg.session_idle = Duration::from_nanos(1);
    let c = Client::new(cfg).await.unwrap();
    for _ in 0..2 {
        tokio::time::timeout(Duration::from_secs(10), ping(&c, &dest))
            .await
            .expect("connect kept handshaking")
            .unwrap();
    }
}

/// Relays queries to `server` but holds the answers until `release`, so a test can drop a connect
/// while its hello is answered but not yet delivered.
struct GatedResolver {
    addr: String,
    front: std::sync::Arc<UdpSocket>,
    held: HeldAnswers,
}

/// Answers waiting for release, or None once released.
type HeldAnswers = std::sync::Arc<std::sync::Mutex<Option<Vec<(Vec<u8>, std::net::SocketAddr)>>>>;

impl GatedResolver {
    async fn start(server: &str) -> GatedResolver {
        let front = std::sync::Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = front.local_addr().unwrap().to_string();
        let held = std::sync::Arc::new(std::sync::Mutex::new(Some(Vec::new())));
        let (f, h, server) = (front.clone(), held.clone(), server.to_owned());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, from)) = f.recv_from(&mut buf).await {
                let (msg, f, h, server) = (buf[..n].to_vec(), f.clone(), h.clone(), server.clone());
                tokio::spawn(async move {
                    let back = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    back.send_to(&msg, &server).await.unwrap();
                    let mut rb = vec![0u8; 4096];
                    let Ok(Ok((m, _))) =
                        tokio::time::timeout(Duration::from_secs(3), back.recv_from(&mut rb)).await
                    else {
                        return;
                    };
                    let answer = rb[..m].to_vec();
                    if let Some(q) = h.lock().unwrap().as_mut() {
                        return q.push((answer, from));
                    }
                    let _ = f.send_to(&answer, from).await;
                });
            }
        });
        GatedResolver { addr, front, held }
    }

    fn held(&self) -> usize {
        self.held.lock().unwrap().as_ref().map_or(0, Vec::len)
    }

    async fn release(&self) {
        let q = self.held.lock().unwrap().take().unwrap_or_default();
        for (answer, to) in q {
            let _ = self.front.send_to(&answer, to).await;
        }
    }
}

/// A connect abandoned mid-handshake, as when another transport wins a race, leaves a session
/// that never carries a stream once the hello's answer arrives. The server ends it 15 s after the
/// hello, so a later connect must handshake afresh rather than fail with SessionClosed.
#[tokio::test(flavor = "multi_thread")]
async fn abandoned_connect_does_not_strand_a_session() {
    let (server, _srv) = start_server().await;
    let dest = start_ponger().await;
    let resolver = GatedResolver::start(&server).await;
    let mut cfg = ClientConfig::new(ZONE, key().verifying_key(), &[&resolver.addr]);
    cfg.tcp = TcpMode::Off;
    let c = Client::new(cfg).await.unwrap();

    let mut connect = Box::pin(c.connect(&dest));
    let answered = async {
        while resolver.held() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::select! {
        r = connect.as_mut() => panic!("connect finished with its hello answer held back: {:?}", r.err()),
        _ = tokio::time::timeout(Duration::from_secs(5), answered) => {}
    }
    assert!(resolver.held() > 0, "the server never answered the hello");
    drop(connect);
    resolver.release().await;
    let up = tokio::time::timeout(Duration::from_secs(5), async {
        while !c.established() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        up.is_ok(),
        "the abandoned handshake never left an established session"
    );

    tokio::time::sleep(Duration::from_secs(16)).await; // past the server's 15 s unused limit
    tokio::time::timeout(Duration::from_secs(10), ping(&c, &dest))
        .await
        .expect("ping timed out")
        .expect("connect after an abandoned handshake failed");
}

async fn client(server: &str) -> Client {
    let mut cfg = ClientConfig::new(ZONE, key().verifying_key(), &[server]);
    cfg.tcp = TcpMode::Off;
    Client::new(cfg).await.unwrap()
}

/// A destination that stops reading must not strand its relay: when the stream's session ends, the
/// server closes the destination even though its write to it is blocked.
#[tokio::test(flavor = "multi_thread")]
async fn ended_session_closes_a_destination_that_stopped_reading() {
    let (server, srv) = start_server().await;
    // A small receive buffer, so the upload fills it (and the relay's send buffer) quickly.
    let sock = TcpSocket::new_v4().unwrap();
    sock.set_recv_buffer_size(4096).unwrap();
    sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let dest = sock.listen(1).unwrap();
    let dest_addr = dest.local_addr().unwrap().to_string();
    let c = client(&server).await;
    let mut conn = c.connect_opened(&dest_addr).await.unwrap();
    let (mut accepted, _) = dest.accept().await.unwrap();
    // Upload for a while: more than the destination's and the relay's buffers hold, so the
    // relay's write to the destination blocks.
    let junk = vec![7u8; 16 << 10];
    let _ = tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            conn.write_all(&junk).await.unwrap();
        }
    })
    .await;
    srv.abort(); // the server shuts down, ending the session
    let _ = srv.await;
    // The destination never reads, so it can't wait for EOF (reading would unblock the relay).
    // It writes instead: once the relay drops the connection, the kernel answers with a reset and
    // a write fails; while the relay is stuck, writes keep landing in its receive buffer.
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if accepted.write_all(b"x").await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(closed.is_ok(), "the destination was never closed");
}

/// Conns can outlive their Client: a read pending when the Client drops fails rather than hangs.
#[tokio::test(flavor = "multi_thread")]
async fn dropping_the_client_wakes_pending_reads() {
    let (server, _srv) = start_server().await;
    let quiet = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let quiet_addr = quiet.local_addr().unwrap().to_string();
    let c = client(&server).await;
    let mut conn = c.connect_opened(&quiet_addr).await.unwrap();
    let _held = quiet.accept().await.unwrap(); // accepts, never sends
    let read = tokio::spawn(async move {
        let mut buf = [0u8; 16];
        conn.read(&mut buf).await
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(c);
    let res = tokio::time::timeout(Duration::from_secs(5), read).await;
    assert!(res.is_ok(), "the read hung after the client was dropped");
    assert!(res.unwrap().unwrap().is_err(), "the read should fail");
}

/// Dropping serve releases its socket: the address can be bound again.
#[tokio::test(flavor = "multi_thread")]
async fn dropping_serve_releases_the_socket() {
    let (addr, srv) = start_server().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    srv.abort();
    let _ = srv.await;
    let mut rebound = false;
    for _ in 0..50 {
        if UdpSocket::bind(&addr).await.is_ok() {
            rebound = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(rebound, "the server's socket outlived serve");
}

/// A zero-length read completes at once, with nothing read, rather than waiting for data.
#[tokio::test(flavor = "multi_thread")]
async fn zero_length_read_completes_at_once() {
    let (server, _srv) = start_server().await;
    let quiet = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let quiet_addr = quiet.local_addr().unwrap().to_string();
    let c = client(&server).await;
    let mut conn = c.connect_opened(&quiet_addr).await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(1), conn.read(&mut []))
        .await
        .expect("a zero-length read waited for data");
    assert_eq!(n.unwrap(), 0);
}

/// A client with no resolver and nothing for discovery to try could never connect: refuse it.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_with_no_way_to_reach_a_resolver_is_refused() {
    let mut cfg = ClientConfig::new(ZONE, key().verifying_key(), &[]);
    cfg.discovery.enabled = true;
    cfg.discovery.no_bundled = true; // and no candidates or cache
    assert!(Client::new(cfg).await.is_err());
}

/// A cache that records what it stores, slowly, so a shutdown that doesn't wait loses the race.
struct SlowCache(std::sync::Mutex<Vec<Vec<String>>>);

impl soar::client::ResolverCache for SlowCache {
    fn load(&self) -> Vec<String> {
        Vec::new()
    }
    fn store(&self, resolvers: &[String]) {
        std::thread::sleep(Duration::from_millis(300));
        self.0.lock().unwrap().push(resolvers.to_vec());
    }
}

/// close() returns only once the resolvers queued for the cache are stored.
#[tokio::test(flavor = "multi_thread")]
async fn close_waits_for_the_cache() {
    let (server, _srv) = start_server().await;
    let quiet = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let quiet_addr = quiet.local_addr().unwrap().to_string();
    let cache = std::sync::Arc::new(SlowCache(std::sync::Mutex::new(Vec::new())));
    let mut cfg = ClientConfig::new(ZONE, key().verifying_key(), &[]);
    cfg.tcp = TcpMode::Off;
    cfg.discovery.enabled = true;
    cfg.discovery.no_bundled = true;
    cfg.discovery.candidates = vec![server.clone()];
    cfg.discovery.cache = Some(cache.clone());
    let c = Client::new(cfg).await.unwrap();
    // Verifying the server's path queues it for the cache.
    let conn = c.connect_opened(&quiet_addr).await.unwrap();
    drop(conn);
    tokio::time::sleep(Duration::from_millis(50)).await;
    c.close().await;
    let stored = cache.0.lock().unwrap().clone();
    assert!(
        stored.iter().any(|s| s.contains(&server)),
        "the verified resolver wasn't stored: {stored:?}"
    );
}
