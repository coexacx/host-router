use anyhow::{Result, anyhow, ensure};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
struct Cached {
    until: Instant,
    result: std::result::Result<Vec<IpAddr>, String>,
}
struct Entry {
    cached: Mutex<Option<Cached>>,
}
pub struct Dns {
    entries: HashMap<String, Arc<Entry>>,
    refresh: Duration,
}
impl Dns {
    pub fn new(cfg: &crate::config::Config) -> Result<Self> {
        let mut entries = HashMap::new();
        let default = crate::config::port(&cfg.default_port)?;
        for r in &cfg.rules {
            let (h, _) = crate::config::target(&r.target, default)?;
            if h.parse::<IpAddr>().is_err() {
                entries.entry(h).or_insert_with(|| {
                    Arc::new(Entry {
                        cached: Mutex::new(None),
                    })
                });
            }
        }
        Ok(Self {
            entries,
            refresh: Duration::from_secs(cfg.dns_refresh_seconds),
        })
    }
    pub async fn lookup(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![crate::net::normalize(SocketAddr::new(ip, port))]);
        }
        let entry = self
            .entries
            .get(host)
            .ok_or_else(|| anyhow!("target absent from DNS table"))?;
        // One in-flight query per configured host; cache size is bounded by configuration.
        let mut state = entry.cached.lock().await;
        if state.as_ref().is_none_or(|e| e.until <= Instant::now()) {
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                tokio::net::lookup_host((host, port)),
            )
            .await;
            let ips = match result {
                Ok(Ok(it)) => {
                    let mut seen = HashSet::new();
                    let ips: Vec<_> = it
                        .map(|a| crate::net::normalize(a).ip())
                        .filter(|ip| !ip.is_multicast() && !ip.is_unspecified() && seen.insert(*ip))
                        .take(16)
                        .collect();
                    if ips.is_empty() {
                        Err("DNS returned no usable addresses".into())
                    } else {
                        Ok(ips)
                    }
                }
                Ok(Err(e)) => Err(e.to_string()),
                Err(_) => Err("DNS query timed out".into()),
            };
            let ttl = if ips.is_ok() {
                self.refresh
            } else {
                Duration::from_secs(2)
            };
            *state = Some(Cached {
                until: Instant::now() + ttl,
                result: ips,
            });
        }
        let ips = state
            .as_ref()
            .unwrap()
            .result
            .as_ref()
            .map_err(|e| anyhow!("{e}"))?;
        ensure!(!ips.is_empty(), "empty DNS result");
        Ok(ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect())
    }
}
