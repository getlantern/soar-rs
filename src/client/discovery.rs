//! Finding resolvers that carry the tunnel when the configured ones don't, or none are configured.
//! Candidates join as unverified paths; only an answer authenticated by the server verifies one, so
//! hijacking resolvers and DPI that drops tunnel-shaped queries are filtered out by the same test
//! that proves the path works.

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rand_core::{OsRng, RngCore};

/// Bundled per-country candidates: resolvers known to forward in that country, and its address
/// ranges for optional sampling. The same lists as the Go client's (see data/THIRD_PARTY.md).
fn bundled_resolvers(country: &str) -> &'static str {
    match country {
        "cn" => include_str!("../../data/resolvers/cn.txt"),
        "ir" => include_str!("../../data/resolvers/ir.txt"),
        "ru" => include_str!("../../data/resolvers/ru.txt"),
        "global" => include_str!("../../data/resolvers/global.txt"),
        _ => "",
    }
}

fn bundled_ranges(country: &str) -> &'static str {
    match country {
        "cn" => include_str!("../../data/ranges/cn.txt"),
        "ir" => include_str!("../../data/ranges/ir.txt"),
        "ru" => include_str!("../../data/ranges/ru.txt"),
        _ => "",
    }
}

/// Stores resolvers that carried the tunnel on the current network. The caller keys it by
/// network, since what works is network-specific.
pub trait ResolverCache: Send + Sync {
    fn load(&self) -> Vec<String>;
    fn store(&self, resolvers: &[String]);
}

#[derive(Clone)]
pub struct Discovery {
    pub enabled: bool,
    /// The ISO 3166-1 alpha-2 code of the network the device is on (e.g. "IR"), if known.
    pub country: String,
    /// Extra resolvers to vet, tried before the bundled lists.
    pub candidates: Vec<String>,
    /// How many addresses to sample from the country's bundled ranges once the lists run out. Off
    /// by default: probing many in-country addresses is a visible pattern.
    pub sample_ranges: usize,
    /// Stop adding candidates once this many paths are verified.
    pub want: usize,
    /// Unverified candidates probed at once.
    pub concurrency: usize,
    /// The minimum gap between adding candidates.
    pub pace: Duration,
    /// Persists verified resolvers across runs; they're tried first.
    pub cache: Option<Arc<dyn ResolverCache>>,
    /// Skip the device's and the bundled lists (tests).
    pub no_bundled: bool,
}

impl Default for Discovery {
    fn default() -> Self {
        Discovery {
            enabled: false,
            country: String::new(),
            candidates: Vec::new(),
            sample_ranges: 0,
            want: 16,
            concurrency: 16,
            pace: Duration::from_millis(20),
            cache: None,
            no_bundled: false,
        }
    }
}

impl fmt::Debug for Discovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Discovery")
            .field("enabled", &self.enabled)
            .field("country", &self.country)
            .finish()
    }
}

/// Accepts "ip" or "ip:port" (port 53 by default).
pub fn parse_resolver(s: &str) -> Option<SocketAddr> {
    let s = s.trim();
    s.parse::<SocketAddr>()
        .ok()
        .or_else(|| s.parse::<IpAddr>().ok().map(|a| SocketAddr::new(a, 53)))
}

/// Non-comment, non-blank lines.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// The device's own resolvers.
fn system_resolvers() -> Vec<String> {
    let Ok(conf) = std::fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    conf.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            (f.next() == Some("nameserver")).then(|| f.next()).flatten()
        })
        .filter_map(|a| a.parse::<IpAddr>().ok())
        .map(|a| SocketAddr::new(a, 53).to_string())
        .collect()
}

impl Discovery {
    /// Resolvers to vet, in order: cached, extra, the device's own, the country's bundled list,
    /// global public resolvers, then sampled in-country addresses.
    pub fn candidates(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        let mut add = |specs: &mut dyn Iterator<Item = String>| {
            for s in specs {
                if let Some(a) = parse_resolver(&s)
                    && seen.insert(a)
                {
                    out.push(a.to_string());
                }
            }
        };
        if let Some(c) = &self.cache {
            add(&mut c.load().into_iter());
        }
        add(&mut self.candidates.iter().cloned());
        if self.no_bundled {
            return out;
        }
        let country = self.country.trim().to_ascii_lowercase();
        add(&mut system_resolvers().into_iter());
        if !country.is_empty() {
            add(&mut lines(bundled_resolvers(&country)).map(String::from));
        }
        add(&mut lines(bundled_resolvers("global")).map(String::from));
        if !country.is_empty() && self.sample_ranges > 0 {
            let ranges: Vec<&str> = lines(bundled_ranges(&country)).collect();
            add(&mut sample_ranges(&ranges, self.sample_ranges).into_iter());
        }
        out
    }
}

/// Draws n addresses from IPv4 prefixes as short contiguous runs at random offsets, in an order
/// unique to this client so devices don't all probe the same hosts.
fn sample_ranges(specs: &[&str], n: usize) -> Vec<String> {
    let prefixes: Vec<(u32, u32)> = specs
        .iter()
        .filter_map(|s| {
            let (a, bits) = s.split_once('/')?;
            let (a, bits) = (a.parse::<Ipv4Addr>().ok()?, bits.parse::<u32>().ok()?);
            (bits <= 32).then(|| {
                (
                    u32::from(a) & u32::MAX.checked_shl(32 - bits).unwrap_or(0),
                    bits,
                )
            })
        })
        .collect();
    if prefixes.is_empty() {
        return Vec::new();
    }
    const RUN: u64 = 4;
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for _ in 0..n * 4 {
        if out.len() >= n {
            break;
        }
        let (base, bits) = prefixes[OsRng.next_u32() as usize % prefixes.len()];
        let size = 1u64 << (32 - bits);
        if size < RUN + 2 {
            continue;
        }
        let off = 1 + u64::from(OsRng.next_u32()) % (size - RUN - 1); // skip the network address
        for k in 0..RUN {
            if out.len() >= n {
                break;
            }
            let a = Ipv4Addr::from(base.wrapping_add((off + k) as u32));
            if seen.insert(a) {
                out.push(SocketAddr::new(a.into(), 53).to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_in_order_without_duplicates() {
        let d = Discovery {
            candidates: vec![
                "192.0.2.1".into(),
                "192.0.2.1:53".into(),
                "192.0.2.2:5353".into(),
                "bogus".into(),
            ],
            no_bundled: true,
            ..Discovery::default()
        };
        assert_eq!(d.candidates(), ["192.0.2.1:53", "192.0.2.2:5353"]);
    }

    #[test]
    fn bundled_lists_load() {
        assert!(lines(bundled_resolvers("ir")).count() > 10);
        assert!(lines(bundled_resolvers("global")).count() > 3);
        let ranges: Vec<&str> = lines(bundled_ranges("ir")).collect();
        let sample = sample_ranges(&ranges, 20);
        assert_eq!(sample.len(), 20);
        assert!(sample.iter().all(|s| parse_resolver(s).is_some()));
    }
}
