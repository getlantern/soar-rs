//! soar-client: forwards local TCP connections through a Soar tunnel to one destination, like
//! dnstt-client.
//!
//!     soar-client -zone t.example.com -pubkey BASE64 -resolver 8.8.8.8 -resolver 1.1.1.1 \
//!         -listen 127.0.0.1:7000 -forward example.com:443

use std::process::exit;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::VerifyingKey;
use soar::client::{Client, ClientConfig, TcpMode};
use tokio::net::TcpListener;

const USAGE: &str = "usage: soar-client -zone ZONE -pubkey BASE64 -resolver ADDR [-resolver ADDR ...] \
-listen ADDR -forward HOST:PORT [-discover] [-country CC] [-tcp auto|on|only|off]";

fn fatal(msg: impl std::fmt::Display) -> ! {
    eprintln!("soar-client: {msg}");
    exit(1)
}

#[tokio::main]
async fn main() {
    let (mut zone, mut pubkey, mut listen, mut forward) =
        (String::new(), String::new(), String::new(), String::new());
    let (mut resolvers, mut discover, mut country, mut tcp) =
        (Vec::new(), false, String::new(), TcpMode::Auto);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let flag = arg.trim_start_matches('-');
        if flag.len() == arg.len() {
            fatal(format!("unexpected argument {arg:?}\n{USAGE}"));
        }
        let (name, inline) = match flag.split_once('=') {
            Some((n, v)) => (n, Some(v.to_owned())),
            None => (flag, None),
        };
        let mut value = || {
            inline
                .clone()
                .or_else(|| it.next().cloned())
                .unwrap_or_else(|| fatal(format!("-{name} needs a value")))
        };
        match name {
            "zone" => zone = value(),
            "pubkey" => pubkey = value(),
            "listen" => listen = value(),
            "forward" => forward = value(),
            // Repeatable, and each may be a comma-separated list.
            "resolver" | "resolvers" => {
                resolvers.extend(value().split(',').map(|s| s.trim().to_owned()))
            }
            "discover" => discover = true,
            "country" => country = value(),
            "tcp" => {
                tcp = match value().as_str() {
                    "auto" => TcpMode::Auto,
                    "on" => TcpMode::On,
                    "only" => TcpMode::Only,
                    "off" => TcpMode::Off,
                    v => fatal(format!("bad -tcp {v:?}")),
                }
            }
            "h" | "help" => {
                println!("{USAGE}");
                exit(0)
            }
            _ => fatal(format!("unknown flag -{name}\n{USAGE}")),
        }
    }
    if zone.is_empty() || pubkey.is_empty() || listen.is_empty() || forward.is_empty() {
        eprintln!("{USAGE}");
        exit(2);
    }
    let key = B64
        .decode(pubkey.trim())
        .ok()
        .and_then(|k| <[u8; 32]>::try_from(k).ok());
    let key = key
        .and_then(|k| VerifyingKey::from_bytes(&k).ok())
        .unwrap_or_else(|| fatal("bad -pubkey"));
    let refs: Vec<&str> = resolvers.iter().map(String::as_str).collect();
    let mut cfg = ClientConfig::new(&zone, key, &refs);
    cfg.tcp = tcp;
    cfg.discovery.enabled = discover;
    cfg.discovery.country = country;
    let client = Arc::new(Client::new(cfg).await.unwrap_or_else(|e| fatal(e)));
    let ln = TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|e| fatal(e));
    eprintln!(
        "soar-client: listening on {}",
        ln.local_addr().map(|a| a.to_string()).unwrap_or_default()
    );
    loop {
        let (mut local, _) = match ln.accept().await {
            Ok(c) => c,
            Err(e) => fatal(e),
        };
        let (client, forward) = (client.clone(), forward.clone());
        tokio::spawn(async move {
            let mut tunnel = match client.connect(&forward).await {
                Ok(c) => c,
                Err(e) => return eprintln!("soar-client: {e}"),
            };
            // EOF on either side half-closes the other: a FIN through the tunnel, or a TCP FIN.
            let _ = tokio::io::copy_bidirectional(&mut local, &mut tunnel).await;
        });
    }
}
