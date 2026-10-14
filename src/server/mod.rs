//! The tunnel server: the authoritative name server for a zone, relaying streams to their
//! destinations. [`ServerCore`] is the protocol; [`serve`] runs it on Tokio.

mod core;
mod dial;

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Notify;

pub use self::core::{ServerConfig, ServerCore, ServerEvent, StreamKey, Transmit};
pub use self::dial::{DialPolicy, is_public};
use crate::session::Read;

/// Wakes a stream's relay: `read` when there's something to read, `write` when there's room.
#[derive(Default)]
struct Wake {
    read: Notify,
    write: Notify,
}

impl Wake {
    fn both(&self) {
        self.read.notify_one();
        self.write.notify_one();
    }
}

struct Shared {
    core: Mutex<ServerCore>,
    socket: UdpSocket,
    wakes: Mutex<HashMap<StreamKey, Arc<Wake>>>,
    timer: Notify,
    dial: DialPolicy,
}

/// Serves the tunnel on socket until it fails.
pub async fn serve(socket: UdpSocket, cfg: ServerConfig, dial: DialPolicy) -> io::Result<()> {
    let core = ServerCore::new(cfg, Instant::now()).map_err(io::Error::other)?;
    let sh = Arc::new(Shared {
        core: Mutex::new(core),
        socket,
        wakes: Mutex::new(HashMap::new()),
        timer: Notify::new(),
        dial,
    });
    // However serve ends, including by being dropped, stop the timer and end every session, so
    // relays let go of their destinations and nothing keeps the socket.
    let _stop = Stop(sh.clone(), tokio::spawn(run_timer(sh.clone())));
    let mut buf = vec![0u8; 4096];
    loop {
        match sh.socket.recv_from(&mut buf).await {
            Ok((n, from)) => sh.run(|c, now| c.handle(&buf[..n], from, now)).await,
            // ICMP errors from earlier sends surface here on some platforms.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused
                ) => {}
            Err(e) => return Err(e),
        }
    }
}

/// Ends a server when dropped.
struct Stop(Arc<Shared>, tokio::task::JoinHandle<()>);

impl Drop for Stop {
    fn drop(&mut self) {
        self.1.abort();
        let events: Vec<ServerEvent> = {
            let mut c = self.0.lock();
            c.close_all();
            std::iter::from_fn(|| c.poll_event()).collect()
        };
        // Aborted streams wake their relays, which then close their destinations.
        for e in events {
            self.0.dispatch(e);
        }
    }
}

async fn run_timer(sh: Arc<Shared>) {
    loop {
        let deadline = sh.lock().poll_timeout();
        tokio::select! {
            _ = tokio::time::sleep_until(deadline.into()) => sh.run(|c, now| c.handle_timeout(now)).await,
            _ = sh.timer.notified() => {}
        }
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, ServerCore> {
        self.core.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Runs f on the core, then sends what it produced and passes on its events.
    async fn run<R>(self: &Arc<Self>, f: impl FnOnce(&mut ServerCore, Instant) -> R) -> R {
        let (r, out, events) = {
            let mut c = self.lock();
            let r = f(&mut c, Instant::now());
            let events: Vec<ServerEvent> = std::iter::from_fn(|| c.poll_event()).collect();
            (r, c.take_transmits(), events)
        };
        for t in out {
            let _ = self.socket.send_to(&t.msg, t.to).await;
        }
        for e in events {
            self.dispatch(e);
        }
        // Held polls may have new deadlines.
        self.timer.notify_one();
        r
    }

    fn dispatch(self: &Arc<Self>, e: ServerEvent) {
        let mut wakes = self.wakes.lock().unwrap_or_else(|e| e.into_inner());
        match e {
            ServerEvent::Accepted(k) => {
                let w = Arc::new(Wake::default());
                wakes.insert(k, w.clone());
                tokio::spawn(relay(self.clone(), k, w));
            }
            ServerEvent::Readable(k) => wakes.get(&k).into_iter().for_each(|w| w.read.notify_one()),
            ServerEvent::Writable(k) => {
                wakes.get(&k).into_iter().for_each(|w| w.write.notify_one())
            }
            ServerEvent::Aborted(k) => wakes.get(&k).into_iter().for_each(|w| w.both()),
            ServerEvent::SessionClosed(serial) => wakes
                .iter()
                .filter(|(k, _)| k.session == serial)
                .for_each(|(_, w)| w.both()),
        }
    }

    /// Reads from the stream, waiting while there's nothing to read.
    async fn read(self: &Arc<Self>, k: StreamKey, w: &Wake, buf: &mut [u8]) -> Read {
        loop {
            match self.run(|c, now| c.read(k, buf, now)).await {
                Read::WouldBlock => w.read.notified().await,
                r => return r,
            }
        }
    }

    async fn read_exact(
        self: &Arc<Self>,
        k: StreamKey,
        w: &Wake,
        mut buf: &mut [u8],
    ) -> io::Result<()> {
        while !buf.is_empty() {
            match self.read(k, w, buf).await {
                Read::Data(n) => buf = &mut buf[n..],
                _ => return Err(io::ErrorKind::UnexpectedEof.into()),
            }
        }
        Ok(())
    }
}

/// How one direction of a relay ended badly.
enum End {
    /// The client stopped reading the stream.
    Gone,
    Failed,
}

/// Reads the stream's destination from its first bytes, dials it, and relays both ways.
async fn relay(sh: Arc<Shared>, k: StreamKey, w: Arc<Wake>) {
    serve_stream(&sh, k, &w).await;
    sh.run(|c, now| {
        c.close_stream(k, now);
        c.release(k, now);
    })
    .await;
    sh.wakes
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&k);
}

async fn serve_stream(sh: &Arc<Shared>, k: StreamKey, w: &Wake) {
    let addr = tokio::time::timeout(Duration::from_secs(30), async {
        let mut n = [0u8; 1];
        sh.read_exact(k, w, &mut n).await?;
        let mut addr = vec![0u8; usize::from(n[0])];
        if addr.is_empty() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        sh.read_exact(k, w, &mut addr).await?;
        String::from_utf8(addr).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
    })
    .await;
    let Ok(Ok(addr)) = addr else {
        // No usable destination (malformed, or none within 30 s): refuse the stream as
        // unreachable. A graceful close would end in a FIN and then a "stop sending" RESET,
        // which tells a client waiting for OPENED nothing, so it would wait forever.
        sh.run(|c, now| c.refuse(k, now)).await;
        return;
    };

    // A stream the client aborted is never dialed, and an abort cancels a pending dial. A RESET
    // after the client's FIN isn't an abort: it means "I won't read the reply", so the upload is
    // still delivered.
    let aborted = || sh.lock().aborted(k);
    if aborted() {
        return;
    }
    let dialed = tokio::select! {
        r = sh.dial.dial(&addr) => r,
        _ = async { loop { w.read.notified().await; if aborted() { break } } } => return,
    };
    let Ok(tcp) = dialed else {
        sh.run(|c, now| c.refuse(k, now)).await;
        return;
    };
    // Tell the client the destination is reachable: a caller that must know a connection is up
    // before sending waits for this.
    sh.run(|c, now| c.opened(k, now)).await;

    let (mut rd, mut wr) = tcp.into_split();
    let up = async {
        let mut buf = vec![0u8; 16 << 10];
        loop {
            match sh.read(k, w, &mut buf).await {
                Read::Data(n) => {
                    // A destination that stops reading would block this forever: give up when
                    // the stream is aborted or its session ends, as the downstream side does.
                    let write = wr.write_all(&buf[..n]);
                    tokio::pin!(write);
                    loop {
                        tokio::select! {
                            r = &mut write => break r.map_err(|_| End::Failed)?,
                            _ = w.read.notified() => if sh.lock().aborted(k) { return Err(End::Failed) },
                        }
                    }
                }
                Read::Eof => {
                    let _ = wr.shutdown().await;
                    return Ok(());
                }
                _ => return Err(End::Failed),
            }
        }
    };
    let down = async {
        let mut buf = vec![0u8; 16 << 10];
        loop {
            let n = loop {
                tokio::select! {
                    r = rd.read(&mut buf) => break r.map_err(|_| End::Failed)?,
                    _ = w.write.notified() => if sh.lock().gone(k) { return Err(End::Gone) },
                }
            };
            if n == 0 {
                sh.run(|c, now| c.finish(k, now)).await;
                return Ok(());
            }
            let mut off = 0;
            while off < n {
                match sh.run(|c, now| c.write(k, &buf[off..n], now)).await {
                    Ok(0) => w.write.notified().await,
                    Ok(m) => off += m,
                    Err(_) => return Err(End::Gone),
                }
            }
        }
    };
    tokio::pin!(up, down);
    let (mut up_done, mut down_done) = (false, false);
    while !(up_done && down_done) {
        tokio::select! {
            r = &mut up, if !up_done => {
                up_done = true;
                if r.is_err() { return }
            }
            r = &mut down, if !down_done => {
                down_done = true;
                // Once the client stops reading, the destination closes as soon as the upload
                // has been delivered; any other failure closes it at once.
                if let Err(End::Failed) = r { return }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use crate::dns::{self, Zone};
    use crate::frames::{self, Frame};
    use ed25519_dalek::SigningKey;
    use x25519_dalek::{PublicKey, StaticSecret};

    /// A stream whose destination prefix is malformed is refused with RESET_STREAM code 1, so a
    /// client waiting for OPENED gets an answer instead of waiting forever.
    #[tokio::test]
    async fn malformed_destination_is_refused() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let dial = DialPolicy {
            allow_ports: None,
            allow_private: true,
            ..DialPolicy::default()
        };
        tokio::spawn(serve(
            sock,
            ServerConfig::new("t.example.com", key.clone()),
            dial,
        ));
        let z = Zone::parse("t.example.com").unwrap();
        let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut txn = 0u16;
        let mut ask = async |payload: &[u8]| -> Option<dns::Answer> {
            txn += 1;
            let mut q = Vec::new();
            dns::put_query(&mut q, txn, payload, &z, dns::TYPE_TXT, dns::EDNS_SIZE);
            c.send_to(&q, addr).await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(2), c.recv(&mut buf))
                .await
                .ok()?
                .ok()?;
            dns::parse_answer(&buf[..n]).ok()
        };
        // Handshake by hand.
        let eph = StaticSecret::from([6; 32]);
        let mut hello = vec![0, 0];
        hello.extend_from_slice(PublicKey::from(&eph).as_bytes());
        let reply = ask(&hello).await.expect("hello reply");
        let s = crypto::client_finish(&key.verifying_key(), &eph, &reply.payload).unwrap();
        // Open stream 0 with a zero-length destination, then poll until the server reacts.
        let mut first = vec![0x50];
        frames::put_stream(&mut first, 0, 0, &[0], false, true);
        let (mut up_pn, mut largest) = (0u64, None::<u64>);
        let mut next = Some(first);
        for _ in 0..8 {
            let plain = next
                .take()
                .unwrap_or_else(|| vec![0x50, frames::PING, 0, 0, 0]);
            let Some(a) = ask(&s.up.seal_up(s.sid, up_pn, &plain)).await else {
                continue;
            };
            let dec = |t| crypto::decode_pn(largest.unwrap_or(0), largest.is_some(), t);
            if let Ok((pn, down)) = s.down.open_down(&a.payload, up_pn, dec) {
                largest = Some(largest.map_or(pn, |l: u64| l.max(pn)));
                for f in frames::parse(&down[2..]).unwrap() {
                    if let Frame::ResetStream { id: 0, code } = f {
                        assert_eq!(code, 1, "refused as unreachable, not closed gracefully");
                        return;
                    }
                }
            }
            up_pn += 1;
        }
        panic!("the server never refused the malformed stream");
    }
}
