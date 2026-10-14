//! Drives the Rust client against a running Soar server (the Go one, in CI) and checks what comes
//! back, mirroring interop/main.go. It serves its own origin on loopback, so the server must allow
//! private destinations on any port.
//!
//!     cargo run --example interop_client -- -server 127.0.0.1:5353 -pubkey BASE64

use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::VerifyingKey;
use soar::client::{Client, ClientConfig, TcpMode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn pattern(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| (i.wrapping_mul(7) + (i >> 8)) as u8)
        .collect()
}

/// Serves "N\n" → N pattern bytes, echoes for "echo\n", and for "sink\n" reads to EOF and replies
/// with the byte count.
async fn start_origin() -> String {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let Ok((mut c, _)) = ln.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut line = Vec::new();
                let mut b = [0u8; 1];
                loop {
                    if c.read_exact(&mut b).await.is_err() {
                        return;
                    }
                    if b[0] == b'\n' {
                        break;
                    }
                    line.push(b[0]);
                }
                match &line[..] {
                    b"echo" => {
                        let (mut r, mut w) = c.split();
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                    }
                    b"sink" => {
                        let mut n = 0u64;
                        let mut buf = vec![0u8; 16 << 10];
                        while let Ok(k) = c.read(&mut buf).await {
                            if k == 0 {
                                break;
                            }
                            n += k as u64;
                        }
                        let _ = c.write_all(n.to_string().as_bytes()).await;
                    }
                    _ => {
                        let n: usize = String::from_utf8_lossy(&line).trim().parse().unwrap_or(0);
                        let _ = c.write_all(&pattern(n)).await;
                    }
                }
            });
        }
    });
    addr
}

type Check = Result<(), String>;

async fn fetch(c: &Client, origin: &str, n: usize) -> Check {
    let mut conn = c.connect(origin).await.map_err(|e| e.to_string())?;
    conn.write_all(format!("{n}\n").as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut got = Vec::new();
    conn.read_to_end(&mut got)
        .await
        .map_err(|e| format!("after {} bytes: {e}", got.len()))?;
    if got != pattern(n) {
        return Err(format!("got {} bytes, want {n} (or corrupted)", got.len()));
    }
    Ok(())
}

async fn upload(c: &Client, origin: &str) -> Check {
    let n = 200 << 10;
    let mut conn = c.connect(origin).await.map_err(|e| e.to_string())?;
    let mut req = b"sink\n".to_vec();
    req.extend(pattern(n));
    conn.write_all(&req).await.map_err(|e| e.to_string())?;
    conn.shutdown().await.map_err(|e| e.to_string())?;
    let mut got = String::new();
    conn.read_to_string(&mut got)
        .await
        .map_err(|e| e.to_string())?;
    if got != n.to_string() {
        return Err(format!("origin got {got:?} bytes, want {n}"));
    }
    Ok(())
}

async fn echo(c: &Client, origin: &str) -> Check {
    let want = pattern(200 << 10);
    let conn = c.connect(origin).await.map_err(|e| e.to_string())?;
    let (mut r, mut w) = tokio::io::split(conn);
    let up = want.clone();
    let writer = tokio::spawn(async move {
        w.write_all(b"echo\n").await?;
        w.write_all(&up).await?;
        w.shutdown().await
    });
    let mut got = Vec::new();
    r.read_to_end(&mut got)
        .await
        .map_err(|e| format!("after {} bytes: {e}", got.len()))?;
    writer
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    if got != want {
        return Err(format!(
            "echoed {} bytes, want {} (or corrupted)",
            got.len(),
            want.len()
        ));
    }
    Ok(())
}

async fn concurrent(c: &Client, origin: &str) -> Check {
    let fetches = (0..8).map(|i| fetch(c, origin, (20 << 10) + i));
    let errs: Vec<String> = futures::future::join_all(fetches)
        .await
        .into_iter()
        .filter_map(Result::err)
        .collect();
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("; "))
    }
}

/// A refused destination comes back as a reset stream, not a hang.
async fn unreachable(c: &Client) -> Check {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap().to_string();
    drop(ln); // nothing listens here now
    match c.connect_opened(&addr).await {
        Ok(_) => Err("connected to a closed port".into()),
        Err(_) => Ok(()),
    }
}

async fn opened(c: &Client, origin: &str) -> Check {
    c.connect_opened(origin)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() {
    let mut server = "127.0.0.1:5353".to_string();
    let mut pubkey = String::new();
    let mut zone = "t.example.com".to_string();
    let mut verbose = false;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.trim_start_matches('-') {
            "server" => server = it.next().cloned().unwrap_or_default(),
            "pubkey" => pubkey = it.next().cloned().unwrap_or_default(),
            "zone" => zone = it.next().cloned().unwrap_or_default(),
            "v" => verbose = true,
            other => panic!("unknown flag {other}"),
        }
    }
    let key: [u8; 32] = B64
        .decode(pubkey.trim())
        .ok()
        .and_then(|k| k.try_into().ok())
        .expect("bad -pubkey");
    let key = VerifyingKey::from_bytes(&key).expect("bad -pubkey");
    let origin = start_origin().await;
    let mut cfg = ClientConfig::new(&zone, key, &[&server]);
    cfg.tcp = TcpMode::Off;
    let c = Client::new(cfg).await.expect("client");

    let mut failed = 0;
    let mut report = |name: &str,
                      start: Instant,
                      res: Result<Check, tokio::time::error::Elapsed>| {
        let res = res.unwrap_or_else(|_| Err("timed out".into()));
        let status = if res.is_ok() { "ok  " } else { "FAIL" };
        print!("{status} {name:<26} {:6.2}s", start.elapsed().as_secs_f64());
        if let Err(e) = &res {
            failed += 1;
            print!("  {e}");
        }
        println!();
        if verbose {
            for p in c.path_stats() {
                println!(
                    "     path {} rtt={:?} loss={:.2} window={:.1} answer_limit={} name_len={} successes={}",
                    p.resolver, p.rtt, p.loss, p.window, p.answer_limit, p.name_len, p.successes
                );
            }
        }
    };
    let limit = Duration::from_secs(60);
    macro_rules! check {
        ($name:expr, $fut:expr) => {{
            let start = Instant::now();
            report($name, start, tokio::time::timeout(limit, $fut).await);
        }};
    }
    check!("fetch 1 byte", fetch(&c, &origin, 1));
    check!("fetch 100 KB", fetch(&c, &origin, 100 << 10));
    check!("fetch 1 MB", fetch(&c, &origin, 1 << 20));
    check!("upload 200 KB", upload(&c, &origin));
    check!("echo 200 KB", echo(&c, &origin));
    check!("8 concurrent fetches", concurrent(&c, &origin));
    check!("unreachable destination", unreachable(&c));
    check!("OPENED before data", opened(&c, &origin));
    if failed > 0 {
        eprintln!("interop: {failed} checks failed");
        std::process::exit(1);
    }
}
