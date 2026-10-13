//! Which destinations streams may reach. Anyone holding the server's (public) key can open
//! streams, so by default the server dials only public addresses on ports 80 and 443: it must not
//! become a way into its own network.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct DialPolicy {
    /// Destination ports streams may reach; None allows any.
    pub allow_ports: Option<Vec<u16>>,
    /// Allow non-public destinations (lab use only).
    pub allow_private: bool,
    pub timeout: Duration,
}

impl Default for DialPolicy {
    fn default() -> Self {
        DialPolicy {
            allow_ports: Some(vec![80, 443]),
            allow_private: false,
            timeout: Duration::from_secs(15),
        }
    }
}

impl DialPolicy {
    /// Resolves addr (host:port) and connects to the first allowed address. The check runs on the
    /// addresses actually dialed, after resolution, so DNS rebinding can't get around it.
    pub async fn dial(&self, addr: &str) -> io::Result<TcpStream> {
        let denied = |why: String| io::Error::new(io::ErrorKind::PermissionDenied, why);
        let port = addr
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok());
        let Some(port) = port else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "soar: bad destination",
            ));
        };
        if self
            .allow_ports
            .as_ref()
            .is_some_and(|ps| !ps.contains(&port))
        {
            return Err(denied(format!(
                "soar: destination port not allowed: {addr}"
            )));
        }
        let connect = async {
            let mut last = None;
            for sa in tokio::net::lookup_host(addr).await? {
                if !self.allow_private && !is_public(sa.ip()) {
                    last = Some(denied(format!(
                        "soar: destination {} is not public",
                        sa.ip()
                    )));
                    continue;
                }
                match TcpStream::connect(sa).await {
                    Ok(c) => return Ok(c),
                    Err(e) => last = Some(e),
                }
            }
            Err(last
                .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "soar: no addresses")))
        };
        tokio::time::timeout(self.timeout, connect)
            .await
            .unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "soar: dial timed out",
                ))
            })
    }
}

const NON_PUBLIC_V4: [(u32, u32); 13] = [
    (0x0000_0000, 8),  // "this network"
    (0x0A00_0000, 8),  // private
    (0x6440_0000, 10), // CGNAT
    (0x7F00_0000, 8),  // loopback
    (0xA9FE_0000, 16), // link-local
    (0xAC10_0000, 12), // private
    (0xC000_0000, 24), // IETF protocol assignments
    (0xC000_0200, 24), // TEST-NET-1
    (0xC0A8_0000, 16), // private
    (0xC612_0000, 15), // benchmarking
    (0xC633_6400, 24), // TEST-NET-2
    (0xCB00_7100, 24), // TEST-NET-3
    (0xE000_0000, 3),  // multicast, reserved, broadcast
];

fn in_v4(a: Ipv4Addr, (net, bits): (u32, u32)) -> bool {
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    u32::from(a) & mask == net
}

fn in_v6(a: Ipv6Addr, net: u128, bits: u32) -> bool {
    let mask = if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits)
    };
    u128::from(a) & mask == net
}

/// The IPv4 destination a NAT64 (64:ff9b::/96) or 6to4 (2002::/16) address translates to.
fn embedded_v4(a: Ipv6Addr) -> Option<Ipv4Addr> {
    let b = a.octets();
    if in_v6(a, 0x0064_ff9b << 96, 96) {
        return Some(Ipv4Addr::new(b[12], b[13], b[14], b[15]));
    }
    if in_v6(a, 0x2002 << 112, 16) {
        return Some(Ipv4Addr::new(b[2], b[3], b[4], b[5]));
    }
    None
}

/// Whether a is a public unicast address, judging IPv6 forms that embed IPv4 by what they embed.
/// Like Go's soar.PublicOnly, it knows the well-known NAT64 prefix but not a network-specific one.
pub fn is_public(a: IpAddr) -> bool {
    if is_local(a) {
        return false;
    }
    match a.to_canonical() {
        IpAddr::V4(v) => !NON_PUBLIC_V4.iter().any(|&n| in_v4(v, n)),
        IpAddr::V6(v) => {
            // Stricter than Go's IsGlobalUnicast: only 2000::/3 (and NAT64), less special ranges.
            if !in_v6(v, 0x2000 << 112, 3) && !in_v6(v, 0x0064_ff9b << 96, 96) {
                return false;
            }
            const NON_PUBLIC_V6: [(u128, u32); 6] = [
                (0x0064_ff9b_0001 << 80, 48), // local-use NAT64
                (0x2001_0000 << 96, 32),      // Teredo: tunnels to arbitrary IPv4
                (0x2001_0db8 << 96, 32),      // documentation
                (0x2001_0002 << 96, 48),      // benchmarking
                (0x2001_0010 << 96, 28),      // ORCHID
                (0xfc00 << 112, 7),           // unique local
            ];
            if NON_PUBLIC_V6.iter().any(|&(n, b)| in_v6(v, n, b)) {
                return false;
            }
            embedded_v4(v).is_none_or(|e| is_public(IpAddr::V4(e)))
        }
    }
}

/// Whether a is one of this host's interface addresses: dialing our own public IP would reach
/// services bound to all interfaces from inside, past firewalls that only filter outside traffic.
fn is_local(a: IpAddr) -> bool {
    static CACHE: Mutex<Option<(Instant, Vec<IpAddr>)>> = Mutex::new(None);
    let a = a.to_canonical();
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let stale = cache
        .as_ref()
        .is_none_or(|(at, _)| at.elapsed() > Duration::from_secs(60));
    if stale {
        match if_addrs::get_if_addrs() {
            Ok(ifs) => {
                *cache = Some((
                    Instant::now(),
                    ifs.into_iter().map(|i| i.ip().to_canonical()).collect(),
                ))
            }
            // With no list at all, fail closed; otherwise keep the last good one.
            Err(_) if cache.is_none() => return true,
            Err(_) => {}
        }
    }
    let local = cache.as_ref().is_some_and(|(_, addrs)| addrs.contains(&a));
    local || embedded_local(a, cache.as_ref().map(|(_, a)| &a[..]).unwrap_or(&[]))
}

fn embedded_local(a: IpAddr, addrs: &[IpAddr]) -> bool {
    match a {
        IpAddr::V6(v) => embedded_v4(v).is_some_and(|e| addrs.contains(&IpAddr::V4(e))),
        IpAddr::V4(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_addresses() {
        for a in [
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "64:ff9b::808:808",
            "2002:808:808::1",
        ] {
            assert!(is_public(a.parse().unwrap()), "{a}");
        }
        for a in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
            "2002:7f00:1::1",
            "2001::1",
        ] {
            assert!(!is_public(a.parse().unwrap()), "{a}");
        }
    }
}
