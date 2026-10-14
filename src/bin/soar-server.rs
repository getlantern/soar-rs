//! soar-server: the authoritative name server for a Soar tunnel zone. Its command line and key
//! files match the Go soar-server's, so either can replace the other.
//!
//!     soar-server keygen                      # prints a private and public key
//!     soar-server pubkey key                  # prints the public key for a private key file
//!     soar-server -zone t.example.com -key-file key -listen :53

use std::process::exit;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use soar::server::{DialPolicy, ServerConfig, serve};
use tokio::net::UdpSocket;

const USAGE: &str = "usage:
  soar-server keygen
  soar-server pubkey KEY_FILE
  soar-server -zone ZONE -key-file KEY_FILE [-listen :53] [-allow-ports 80,443|any] [-allow-private] [-v]";

fn fatal(msg: impl std::fmt::Display) -> ! {
    eprintln!("soar-server: {msg}");
    exit(1)
}

fn read_key(path: &str) -> SigningKey {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| fatal(e));
    let seed = B64
        .decode(raw.trim())
        .ok()
        .and_then(|s| <[u8; 32]>::try_from(s).ok());
    let seed = seed.unwrap_or_else(|| fatal("key file must hold a base64 32-byte seed"));
    SigningKey::from_bytes(&seed)
}

struct Args {
    zone: String,
    key_file: String,
    listen: String,
    allow_ports: String,
    allow_private: bool,
    verbose: bool,
}

/// Parses Go-style flags: -name value, -name=value, or --name; booleans take no value.
fn parse_args(args: &[String]) -> Args {
    let mut a = Args {
        zone: String::new(),
        key_file: String::new(),
        listen: ":53".into(),
        allow_ports: "80,443".into(),
        allow_private: false,
        verbose: false,
    };
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
            "zone" => a.zone = value(),
            "key-file" => a.key_file = value(),
            "listen" => a.listen = value(),
            "allow-ports" => a.allow_ports = value(),
            "allow-private" => a.allow_private = inline.as_deref().is_none_or(|v| v == "true"),
            "v" => a.verbose = inline.as_deref().is_none_or(|v| v == "true"),
            "h" | "help" => {
                println!("{USAGE}");
                exit(0)
            }
            _ => fatal(format!("unknown flag -{name}\n{USAGE}")),
        }
    }
    if a.zone.is_empty() || a.key_file.is_empty() {
        eprintln!("{USAGE}");
        exit(2);
    }
    a
}

/// Binds every interface on port: a dual-stack socket, with IPV6_V6ONLY cleared explicitly rather
/// than left to the platform default (IPv6-only on Windows, OpenBSD, and Linux with bindv6only),
/// or IPv4 alone where the host has no IPv6.
fn bind_any(port: u16) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    let dual = || -> std::io::Result<Socket> {
        let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        s.set_only_v6(false)?;
        s.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
        Ok(s)
    };
    let socket = dual().or_else(|_| {
        let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
        Ok::<_, std::io::Error>(s)
    })?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("keygen") => {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            let key = SigningKey::from_bytes(&seed);
            println!("private {}", B64.encode(key.to_bytes()));
            println!("public  {}", B64.encode(key.verifying_key().to_bytes()));
            return;
        }
        Some("pubkey") if args.len() > 1 => {
            println!(
                "{}",
                B64.encode(read_key(&args[1]).verifying_key().to_bytes())
            );
            return;
        }
        _ => {}
    }
    let a = parse_args(&args);
    let key = read_key(&a.key_file);
    let allow_ports = if a.allow_ports == "any" {
        None
    } else {
        let ports = a.allow_ports.split(',').map(|p| p.trim().parse::<u16>());
        Some(
            ports
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_else(|_| fatal("bad -allow-ports")),
        )
    };
    let dial = DialPolicy {
        allow_ports,
        allow_private: a.allow_private,
        ..DialPolicy::default()
    };
    // Go-style ":53" means every interface, over IPv4 and IPv6 alike, as in the Go server.
    let socket = match a.listen.strip_prefix(':') {
        Some(port) => {
            let port: u16 = port.parse().unwrap_or_else(|_| fatal("bad -listen port"));
            bind_any(port).unwrap_or_else(|e| fatal(e))
        }
        None => UdpSocket::bind(&a.listen)
            .await
            .unwrap_or_else(|e| fatal(e)),
    };
    // Log hygiene: never the zone or the key. Either one in a leaked log hands a censor the
    // string it needs to block this server; `soar-server pubkey` prints the key on demand.
    eprintln!(
        "soar-server: serving on {}",
        socket
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default()
    );
    let _ = a.verbose; // accepted for compatibility with the Go server; there's no debug log yet
    let cfg = ServerConfig::new(&a.zone, key);
    tokio::select! {
        r = serve(socket, cfg, dial) => if let Err(e) = r { fatal(e) },
        _ = tokio::signal::ctrl_c() => {}
    }
}
