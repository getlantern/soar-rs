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
