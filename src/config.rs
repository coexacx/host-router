use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

pub const MAX_CONFIG: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub default_port: String,
    pub access_log: bool,
    pub dial_timeout_ms: u64,
    pub sniff_timeout_ms: u64,
    pub dns_refresh_seconds: u64,
    pub udp_idle_seconds: u64,
    pub max_tcp_connections: usize,
    pub max_udp_sessions: usize,
    pub max_connections_per_ip: usize,
    pub max_pending_handshakes: usize,
    pub udp_queue_bytes: usize,
    pub rules: Vec<Rule>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            default_port: "443".into(),
            access_log: false,
            dial_timeout_ms: 5000,
            sniff_timeout_ms: 5000,
            dns_refresh_seconds: 30,
            udp_idle_seconds: 60,
            max_tcp_connections: 1024,
            max_udp_sessions: 512,
            max_connections_per_ip: 64,
            max_pending_handshakes: 64,
            udp_queue_bytes: 16 * 1024 * 1024,
            rules: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub listen: String,
    pub domain: String,
    pub target: String,
    #[serde(default)]
    pub protocol: Protocol,
    #[serde(default)]
    pub note: String,
}
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    #[default]
    Both,
}
impl Protocol {
    pub fn tcp(self) -> bool {
        self != Self::Udp
    }
    pub fn udp(self) -> bool {
        self != Self::Tcp
    }
}

#[derive(Debug)]
pub struct Route {
    pub domain: String,
    pub host: String,
    pub port: u16,
}
#[derive(Default, Debug)]
pub struct Routes {
    exact: BTreeMap<String, Arc<Route>>,
    wild: Vec<(String, Arc<Route>)>,
    fallback: Option<Arc<Route>>,
}
impl Routes {
    fn insert(&mut self, route: Arc<Route>) {
        let d = &route.domain;
        if d == "*" {
            self.fallback = Some(route);
        } else if let Some(s) = d.strip_prefix('*') {
            self.wild.push((s.to_owned(), route));
            self.wild.sort_by_key(|(s, _)| std::cmp::Reverse(s.len()));
        } else {
            self.exact.insert(d.clone(), route);
        }
    }
    pub fn lookup(&self, host: Option<&str>) -> Option<Arc<Route>> {
        if let Some(host) = host {
            let host = host.trim_end_matches('.').to_ascii_lowercase();
            if let Some(r) = self.exact.get(&host) {
                return Some(r.clone());
            }
            for (suffix, r) in &self.wild {
                if host.len() > suffix.len() && host.ends_with(suffix) {
                    return Some(r.clone());
                }
            }
        }
        self.fallback.clone()
    }
    pub fn has_names(&self) -> bool {
        !self.exact.is_empty() || !self.wild.is_empty()
    }
}
#[derive(Default, Debug)]
pub struct ListenerRoutes {
    pub tcp: Routes,
    pub udp: Routes,
    pub tcp_enabled: bool,
    pub udp_enabled: bool,
}
pub type Tables = BTreeMap<SocketAddr, Arc<ListenerRoutes>>;

pub fn domain(input: &str, wildcard: bool) -> Result<String> {
    let d = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if wildcard && d == "*" {
        return Ok(d);
    }
    let name = if wildcard {
        d.strip_prefix("*.").unwrap_or(&d)
    } else {
        &d
    };
    ensure!(
        !name.is_empty() && name.len() <= 253,
        "invalid domain length"
    );
    ensure!(name.is_ascii(), "use ASCII/Punycode domain names");
    for label in name.split('.') {
        ensure!(
            !label.is_empty() && label.len() <= 63,
            "invalid domain label"
        );
        ensure!(
            !label.starts_with('-') && !label.ends_with('-'),
            "invalid domain hyphen"
        );
        ensure!(
            label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-'),
            "invalid domain characters"
        );
    }
    Ok(d)
}
pub fn port(s: &str) -> Result<u16> {
    let p: u16 = s.parse().context("port must be 1..65535")?;
    ensure!(p != 0, "port must be 1..65535");
    Ok(p)
}
pub fn target(s: &str, default: u16) -> Result<(String, u16)> {
    let s = s.trim();
    if let Ok(a) = s.parse::<SocketAddr>() {
        let a = crate::net::normalize(a);
        ensure!(a.port() != 0, "zero target port");
        return Ok((a.ip().to_string(), a.port()));
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok((
            crate::net::normalize(SocketAddr::new(ip, default))
                .ip()
                .to_string(),
            default,
        ));
    }
    if s.starts_with('[') && s.ends_with(']') {
        return Ok((
            crate::net::normalize(SocketAddr::new(
                s[1..s.len() - 1].parse::<Ipv6Addr>()?.into(),
                default,
            ))
            .ip()
            .to_string(),
            default,
        ));
    }
    let (h, p) = match s.rsplit_once(':') {
        Some((h, p)) => (h, port(p)?),
        None => (s, default),
    };
    Ok((domain(h, false)?, p))
}
pub fn listens(s: &str) -> Result<Vec<SocketAddr>> {
    let s = s.trim();
    if let Ok(a) = s.parse::<SocketAddr>() {
        let a = crate::net::normalize(a);
        ensure!(a.port() != 0, "zero listen port");
        ensure!(!a.ip().is_multicast(), "multicast listener is unsupported");
        return Ok(vec![a]);
    }
    let p = port(s.strip_prefix(':').unwrap_or(s))?;
    Ok(vec![
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), p),
        SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), p),
    ])
}
impl Config {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_CONFIG, "configuration exceeds 1 MiB");
        let cfg: Self = serde_json::from_slice(bytes)?;
        cfg.tables()?;
        Ok(cfg)
    }
    pub fn tables(&self) -> Result<Tables> {
        ensure!(self.rules.len() <= 4096, "at most 4096 rules");
        let default = port(&self.default_port)?;
        ensure!(
            (100..=120000).contains(&self.dial_timeout_ms),
            "dial_timeout_ms outside 100..120000"
        );
        ensure!(
            (100..=30000).contains(&self.sniff_timeout_ms),
            "sniff_timeout_ms outside 100..30000"
        );
        ensure!(
            (1..=3600).contains(&self.dns_refresh_seconds),
            "dns_refresh_seconds outside 1..3600"
        );
        ensure!(
            (1..=3600).contains(&self.udp_idle_seconds),
            "udp_idle_seconds outside 1..3600"
        );
        for (n, v, max) in [
            ("max_tcp_connections", self.max_tcp_connections, 65536),
            ("max_udp_sessions", self.max_udp_sessions, 16384),
            ("max_connections_per_ip", self.max_connections_per_ip, 4096),
            ("max_pending_handshakes", self.max_pending_handshakes, 1024),
        ] {
            ensure!((1..=max).contains(&v), "{n} outside 1..{max}");
        }
        ensure!(
            (65536..=256 * 1024 * 1024).contains(&self.udp_queue_bytes),
            "udp_queue_bytes outside 64 KiB..256 MiB"
        );
        let mut out: BTreeMap<SocketAddr, ListenerRoutes> = BTreeMap::new();
        let mut seen = HashSet::new();
        for (idx, r) in self.rules.iter().enumerate() {
            ensure!(
                r.note.len() <= 512 && !r.note.chars().any(|c| c.is_control()),
                "rule {}: invalid note",
                idx + 1
            );
            let d = domain(&r.domain, true).with_context(|| format!("rule {} domain", idx + 1))?;
            let (h, p) =
                target(&r.target, default).with_context(|| format!("rule {} target", idx + 1))?;
            if let Ok(ip) = h.parse::<IpAddr>() {
                ensure!(
                    !ip.is_multicast() && !ip.is_unspecified(),
                    "invalid target IP"
                );
            }
            let route = Arc::new(Route {
                domain: d.clone(),
                host: h,
                port: p,
            });
            for a in listens(&r.listen).with_context(|| format!("rule {} listen", idx + 1))? {
                let t = out.entry(a).or_default();
                if r.protocol.tcp() {
                    ensure!(
                        seen.insert((a, d.clone(), 0)),
                        "duplicate TCP rule on {a}: {d}"
                    );
                    t.tcp_enabled = true;
                    t.tcp.insert(route.clone());
                }
                if r.protocol.udp() {
                    ensure!(
                        seen.insert((a, d.clone(), 1)),
                        "duplicate UDP rule on {a}: {d}"
                    );
                    t.udp_enabled = true;
                    t.udp.insert(route.clone());
                }
            }
        }
        ensure!(out.len() <= 256, "at most 256 listening addresses");
        // Reject wildcard/specific address overlap before attempting any binds.
        for (a, t) in &out {
            for (b, u) in &out {
                if a != b
                    && a.port() == b.port()
                    && a.is_ipv4() == b.is_ipv4()
                    && (a.ip().is_unspecified() || b.ip().is_unspecified())
                    && ((t.tcp_enabled && u.tcp_enabled) || (t.udp_enabled && u.udp_enabled))
                {
                    bail!("overlapping listeners {a} and {b}");
                }
            }
        }
        Ok(out.into_iter().map(|(a, r)| (a, Arc::new(r))).collect())
    }
    pub fn compatible_limits(&self, other: &Self) -> bool {
        self.max_tcp_connections == other.max_tcp_connections
            && self.max_udp_sessions == other.max_udp_sessions
            && self.max_connections_per_ip == other.max_connections_per_ip
            && self.max_pending_handshakes == other.max_pending_handshakes
            && self.udp_queue_bytes == other.udp_queue_bytes
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mapped_addresses_cannot_bypass_target_checks() {
        assert_eq!(
            target("[::ffff:127.0.0.1]:443", 443).unwrap(),
            ("127.0.0.1".into(), 443)
        );
        assert_eq!(
            listens("[::ffff:127.0.0.1]:443").unwrap(),
            vec!["127.0.0.1:443".parse().unwrap()]
        );
        for ip in ["::ffff:0.0.0.0", "::ffff:224.0.0.1"] {
            let data = serde_json::json!({"rules":[{"listen":"443","domain":"*","target":format!("[{ip}]:443")}]});
            assert!(Config::parse(&serde_json::to_vec(&data).unwrap()).is_err());
        }
    }
    #[test]
    fn normalization() {
        assert_eq!(
            target("EXAMPLE.COM:8443", 443).unwrap(),
            ("example.com".into(), 8443)
        );
        assert_eq!(target("[::1]:443", 1).unwrap(), ("::1".into(), 443));
        assert_eq!(listens("443").unwrap().len(), 2);
        assert!(domain("a;echo", true).is_err());
        assert!(port("0").is_err());
    }
    #[test]
    fn precedence_and_duplicates() {
        let cfg = Config::parse(
            br#"{"rules":[
         {"listen":"127.0.0.1:4443","domain":"*","target":"127.0.0.1:1"},
         {"listen":"127.0.0.1:4443","domain":"*.example.com","target":"127.0.0.1:2"},
         {"listen":"127.0.0.1:4443","domain":"x.example.com","target":"127.0.0.1:3"}]}"#,
        )
        .unwrap();
        let t = cfg.tables().unwrap();
        let r = &t.values().next().unwrap().tcp;
        assert_eq!(r.lookup(Some("X.EXAMPLE.COM.")).unwrap().port, 3);
        assert_eq!(r.lookup(Some("a.b.example.com")).unwrap().port, 2);
        assert_eq!(r.lookup(Some("example.com")).unwrap().port, 1);
        let mut bad = cfg.clone();
        bad.rules.push(bad.rules[0].clone());
        assert!(bad.tables().is_err());
    }
}
