//! Cached resource sampling and admission control. No procfs reads in the forwarding path.
use crate::config::Config;
use serde::Serialize;
use std::{
    fs,
    io::{BufRead, BufReader},
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
const MIB: u64 = 1024 * 1024;
const UNIT: u64 = 128 * 1024;
const TCP_UNITS: usize = 2;
const UDP_UNITS: usize = 3;

#[derive(Clone, Debug, Serialize)]
pub struct Resources {
    pub memory_total_bytes: u64,
    pub memory_available_bytes: u64,
    pub cpu_cores: f64,
    pub fd_soft_limit: usize,
    pub system_cpu_percent: f64,
    pub process_cpu_percent: f64,
    pub cgroup_cpu_percent: f64,
    pub valid: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Limits {
    pub tcp: usize,
    pub udp: usize,
    pub pending: usize,
    pub queue_bytes: usize,
    pub memory_units: usize,
    pub fd_budget: usize,
    pub new_tcp_per_second: usize,
    pub new_udp_per_second: usize,
}
impl Limits {
    fn calculate(
        c: &Config,
        r: &Resources,
        factor: usize,
        listener_fds: usize,
        active_units: usize,
    ) -> Self {
        if !c.auto_capacity {
            return Self {
                tcp: c.max_tcp_connections,
                udp: c.max_udp_sessions,
                pending: c.max_pending_handshakes,
                queue_bytes: c.udp_queue_bytes,
                memory_units: usize::MAX,
                fd_budget: usize::MAX,
                new_tcp_per_second: usize::MAX,
                new_udp_per_second: 200,
            };
        }
        // Keep 40% of effective RAM outside the estimated connection budget.
        // This is an admission estimate, not a worst-case socket memory guarantee.
        let budget = r.memory_total_bytes.saturating_mul(60) / 100;
        let queue = (budget / 16)
            .clamp(64 * 1024, 64 * MIB)
            .min(c.udp_queue_bytes as u64);
        let units = (budget.saturating_sub(32 * MIB + queue) / UNIT) as usize;
        let reserve = (r.memory_total_bytes / 10).clamp(32 * MIB, 1024 * MIB);
        let growth = (r
            .memory_available_bytes
            .saturating_sub(reserve + 32 * MIB + queue)
            / UNIT) as usize;
        let units = units
            .min(growth.saturating_add(active_units))
            .saturating_mul(factor)
            / 100;
        // Reserve descriptors for listeners (up to 512), resolver and control socket.
        let fds = r
            .fd_soft_limit
            .saturating_sub((r.fd_soft_limit / 4).min(1024).max(listener_fds + 64));
        let tcp = c.max_tcp_connections.min(units / TCP_UNITS).min(fds / 6);
        let udp = c.max_udp_sessions.min(units / UDP_UNITS).min(fds);
        let cpu_pending = (r.cpu_cores * 128.0).ceil() as usize;
        Self {
            tcp,
            udp,
            pending: c
                .max_pending_handshakes
                .min(cpu_pending.max(16))
                .min(tcp + udp)
                .saturating_mul(factor)
                / 100,
            queue_bytes: (queue as usize).max(64 * 1024),
            memory_units: units,
            fd_budget: fds,
            new_tcp_per_second: ((r.cpu_cores * 4096.0) as usize).clamp(128, 65536) * factor / 100,
            new_udp_per_second: ((r.cpu_cores * 200.0) as usize).clamp(32, 2048) * factor / 100,
        }
    }
}
#[derive(Clone, Copy)]
pub enum Kind {
    Tcp,
    Udp,
}
struct State {
    cfg: Config,
    resources: Resources,
    limits: Limits,
    factor: usize,
    listener_fds: usize,
    high: u8,
    healthy: u8,
    pressure: &'static str,
    active_tcp: usize,
    active_udp: usize,
    tcp_tokens: f64,
    udp_tokens: f64,
    refill: Instant,
    rejected: u64,
    samples: u64,
}
pub struct Capacity {
    state: Mutex<State>,
    pub pending: AtomicUsize,
    pub queue: AtomicUsize,
}
pub struct Lease {
    capacity: Arc<Capacity>,
    kind: Kind,
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut s = self.capacity.state.lock().unwrap();
        match self.kind {
            Kind::Tcp => s.active_tcp -= 1,
            Kind::Udp => s.active_udp -= 1,
        }
    }
}
impl Capacity {
    pub fn new(cfg: &Config, r: Resources) -> Arc<Self> {
        let reserve = (r.memory_total_bytes / 10).clamp(32 * MIB, 1024 * MIB);
        let (factor, pressure) = if !cfg.auto_capacity {
            (100, "manual")
        } else if !r.valid {
            (0, "sensor_unavailable")
        } else if r.memory_available_bytes < reserve / 2 {
            (0, "memory_critical")
        } else if r.memory_available_bytes < reserve {
            (10, "memory")
        } else {
            (100, "normal")
        };
        let listener_fds = cfg
            .tables()
            .map(|t| {
                t.values()
                    .map(|v| usize::from(v.tcp_enabled) + usize::from(v.udp_enabled))
                    .sum()
            })
            .unwrap_or(512);
        let limits = Limits::calculate(cfg, &r, factor, listener_fds, 0);
        let mut settings = cfg.clone();
        settings.rules.clear();
        Arc::new(Self {
            pending: AtomicUsize::new(limits.pending),
            queue: AtomicUsize::new(limits.queue_bytes),
            state: Mutex::new(State {
                cfg: settings,
                resources: r,
                limits: limits.clone(),
                factor,
                listener_fds,
                high: 0,
                healthy: 0,
                pressure,
                active_tcp: 0,
                active_udp: 0,
                tcp_tokens: limits.new_tcp_per_second as f64,
                udp_tokens: limits.new_udp_per_second as f64,
                refill: Instant::now(),
                rejected: 0,
                samples: 0,
            }),
        })
    }
    pub fn enter(self: &Arc<Self>, kind: Kind) -> Option<Lease> {
        let mut s = self.state.lock().unwrap();
        let dt = s.refill.elapsed().as_secs_f64();
        s.refill = Instant::now();
        s.tcp_tokens = (s.tcp_tokens + dt * s.limits.new_tcp_per_second as f64)
            .min(s.limits.new_tcp_per_second as f64);
        s.udp_tokens = (s.udp_tokens + dt * s.limits.new_udp_per_second as f64)
            .min(s.limits.new_udp_per_second as f64);
        let (tcp, udp, tokens) = match kind {
            Kind::Tcp => (s.active_tcp + 1, s.active_udp, s.tcp_tokens),
            Kind::Udp => (s.active_tcp, s.active_udp + 1, s.udp_tokens),
        };
        if tcp > s.limits.tcp
            || udp > s.limits.udp
            || tcp * TCP_UNITS + udp * UDP_UNITS > s.limits.memory_units
            || tcp * 6 + udp > s.limits.fd_budget
            || tokens < 1.0
        {
            s.rejected = s.rejected.saturating_add(1);
            return None;
        }
        s.active_tcp = tcp;
        s.active_udp = udp;
        match kind {
            Kind::Tcp => s.tcp_tokens -= 1.0,
            Kind::Udp => s.udp_tokens -= 1.0,
        }
        Some(Lease {
            capacity: self.clone(),
            kind,
        })
    }
    pub fn sample(&self, r: Resources) {
        let mut s = self.state.lock().unwrap();
        s.samples += 1;
        if s.cfg.auto_capacity {
            let reserve = (r.memory_total_bytes / 10).clamp(32 * MIB, 1024 * MIB);
            let critical = r.memory_available_bytes < reserve / 2;
            let memory_high = r.memory_available_bytes < reserve;
            let cpu_high = r.system_cpu_percent >= 95.0
                || r.process_cpu_percent >= 90.0
                || r.cgroup_cpu_percent >= 90.0;
            if !r.valid || critical {
                s.factor = 0;
                s.high = 0;
                s.healthy = 0;
                s.pressure = if critical {
                    "memory_critical"
                } else {
                    "sensor_unavailable"
                };
            } else if memory_high || cpu_high {
                s.high = s.high.saturating_add(1);
                s.healthy = 0;
                // CPU must remain high for 3 samples (6s); memory acts immediately.
                if memory_high || s.high >= 3 {
                    s.factor = if s.factor == 0 {
                        0
                    } else {
                        (s.factor * 3 / 4).max(10)
                    };
                    s.pressure = if memory_high { "memory" } else { "cpu" };
                    s.high = 0;
                }
            } else if r.memory_available_bytes >= reserve * 3 / 2
                && r.system_cpu_percent < 85.0
                && r.process_cpu_percent < 80.0
                && r.cgroup_cpu_percent < 80.0
            {
                s.high = 0;
                s.healthy = s.healthy.saturating_add(1);
                if s.healthy >= 5 {
                    s.factor = (s.factor + 10).min(100);
                    s.healthy = 0;
                    s.pressure = if s.factor == 100 {
                        "normal"
                    } else {
                        "recovering"
                    };
                }
            } else {
                s.high = 0;
                s.healthy = 0;
            }
        } else {
            s.pressure = "manual";
        }
        let old = (s.limits.tcp, s.limits.udp);
        s.limits = Limits::calculate(
            &s.cfg,
            &r,
            s.factor,
            s.listener_fds,
            s.active_tcp * TCP_UNITS + s.active_udp * UDP_UNITS,
        );
        s.resources = r;
        self.pending.store(s.limits.pending, Ordering::Relaxed);
        self.queue.store(s.limits.queue_bytes, Ordering::Relaxed);
        if old.0 != s.limits.tcp || old.1 != s.limits.udp {
            tracing::info!(
                tcp = s.limits.tcp,
                udp = s.limits.udp,
                pressure = s.pressure,
                "admission capacity adjusted"
            );
        }
    }
    pub fn listeners(&self, n: usize) {
        let mut s = self.state.lock().unwrap();
        s.listener_fds = n;
        s.limits = Limits::calculate(
            &s.cfg,
            &s.resources,
            s.factor,
            n,
            s.active_tcp * TCP_UNITS + s.active_udp * UDP_UNITS,
        );
    }
    pub fn status(&self) -> serde_json::Value {
        let s = self.state.lock().unwrap();
        serde_json::json!({"mode":if s.cfg.auto_capacity{"auto"}else{"manual"},
            "pressure":s.pressure,"capacity_percent":s.factor,
            "resources":s.resources,"effective":s.limits,
            "ceilings":{"tcp":s.cfg.max_tcp_connections,"udp":s.cfg.max_udp_sessions,
                "per_ip":s.cfg.max_connections_per_ip,"pending":s.cfg.max_pending_handshakes},
            "admission_rejected":s.rejected,"samples":s.samples})
    }
    pub async fn monitor(self: Arc<Self>, stop: tokio_util::sync::CancellationToken) {
        // Blocking procfs/cgroup reads use one dedicated sleeping thread, never packet tasks.
        let mut sampler = Sampler::new();
        let _ = sampler.sample();
        loop {
            tokio::select! {_=stop.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(2))=>{}}
            let result = tokio::task::spawn_blocking(move || {
                let r = sampler.sample();
                (sampler, r)
            })
            .await;
            let Ok((next, r)) = result else { break };
            sampler = next;
            self.sample(r);
        }
    }
}

fn read(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path).unwrap_or_default()
}
fn number(path: impl AsRef<Path>) -> Option<u64> {
    read(path).trim().parse().ok()
}
fn field(text: &str, key: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.strip_prefix(key)?.split_whitespace().next()?.parse().ok())
}
fn safe_path(root: &Path, relative: &str) -> Option<PathBuf> {
    let p = Path::new(relative);
    if p.components()
        .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return None;
    }
    Some(root.join(relative.trim_start_matches('/')))
}
fn ancestry(root: &Path, leaf: PathBuf) -> Vec<PathBuf> {
    let mut out = vec![];
    let mut p = Some(leaf.as_path());
    while let Some(path) = p {
        if !path.starts_with(root) || out.len() >= 64 {
            break;
        }
        out.push(path.to_path_buf());
        if path == root {
            break;
        }
        p = path.parent();
    }
    out
}
fn cpu_list(s: &str) -> Option<usize> {
    let mut count = 0usize;
    for part in s.trim().split(',') {
        let (a, b) = part.split_once('-').unwrap_or((part, part));
        let a: usize = a.parse().ok()?;
        let b: usize = b.parse().ok()?;
        if b < a || b > 1048576 {
            return None;
        }
        count = count.checked_add(b - a + 1)?;
    }
    (count > 0).then_some(count)
}
fn cpu_ticks() -> Option<(u64, u64)> {
    let mut line = String::new();
    BufReader::new(fs::File::open("/proc/stat").ok()?)
        .read_line(&mut line)
        .ok()?;
    let n: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .take(8)
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    if n.len() < 8 {
        return None;
    }
    Some((n.iter().sum(), n[3] + n[4]))
}
fn process_ticks() -> Option<u64> {
    let raw = read("/proc/self/stat");
    let words: Vec<_> = raw.rsplit_once(')')?.1.split_whitespace().collect();
    Some(words.get(11)?.parse::<u64>().ok()? + words.get(12)?.parse::<u64>().ok()?)
}
fn fd_limit() -> Option<usize> {
    let raw = read("/proc/self/limits");
    raw.lines().find_map(|line| {
        line.strip_prefix("Max open files")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}
struct Group {
    path: PathBuf,
    v2: bool,
    memory: bool,
    cpu: bool,
}
// Resolve mount roots as well as mountpoints: containers may expose a subtree at /.
fn unescape_mount(s: &str) -> String {
    s.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}
fn discover_groups(membership: &str, mountinfo: &str) -> Vec<Group> {
    let mut groups = vec![];
    for entry in membership.lines() {
        let parts: Vec<_> = entry.splitn(3, ':').collect();
        if parts.len() != 3 {
            continue;
        }
        for line in mountinfo.lines() {
            let Some((left, right)) = line.split_once(" - ") else {
                continue;
            };
            let l: Vec<_> = left.split_whitespace().collect();
            let r: Vec<_> = right.split_whitespace().collect();
            if l.len() < 5 || r.len() < 3 {
                continue;
            }
            let v2 = r[0] == "cgroup2" && parts[0] == "0" && parts[1].is_empty();
            let has = |name: &str| {
                parts[1].split(',').any(|v| v == name) && r[2].split(',').any(|v| v == name)
            };
            let memory = v2 || (r[0] == "cgroup" && has("memory"));
            let cpu = v2 || (r[0] == "cgroup" && has("cpu"));
            if !memory && !cpu {
                continue;
            }
            let root = PathBuf::from(unescape_mount(l[4]));
            let mount_root = PathBuf::from(unescape_mount(l[3]));
            let member = Path::new(parts[2]);
            let relative = member.strip_prefix(&mount_root).unwrap_or(member);
            if let Some(leaf) = safe_path(&root, &relative.to_string_lossy()) {
                for path in ancestry(&root, leaf) {
                    if !groups
                        .iter()
                        .any(|g: &Group| g.path == path && g.memory == memory && g.cpu == cpu)
                    {
                        groups.push(Group {
                            path,
                            v2,
                            memory,
                            cpu,
                        });
                    }
                }
            }
        }
    }
    groups
}
pub struct Sampler {
    groups: Vec<Group>,
    last: Option<(Instant, u64, u64, u64)>,
    cpu_last: Vec<Option<u64>>,
    ticks: f64,
}
impl Default for Sampler {
    fn default() -> Self {
        Self::new()
    }
}
impl Sampler {
    pub fn new() -> Self {
        let groups = discover_groups(&read("/proc/self/cgroup"), &read("/proc/self/mountinfo"));
        let cpu_last = vec![None; groups.len()];
        let ticks = nix::unistd::sysconf(nix::unistd::SysconfVar::CLK_TCK)
            .ok()
            .flatten()
            .unwrap_or(100) as f64;
        Self {
            groups,
            last: None,
            cpu_last,
            ticks,
        }
    }
    pub fn sample(&mut self) -> Resources {
        let mem = read("/proc/meminfo");
        let total = field(&mem, "MemTotal:").map(|v| v * 1024);
        let available = field(&mem, "MemAvailable:").map(|v| v * 1024);
        let mut r = Resources {
            memory_total_bytes: total.unwrap_or(256 * MIB),
            memory_available_bytes: available.unwrap_or(0),
            cpu_cores: std::thread::available_parallelism()
                .map(|v| v.get() as f64)
                .unwrap_or(1.0),
            fd_soft_limit: fd_limit().unwrap_or(1024),
            system_cpu_percent: 0.0,
            process_cpu_percent: 0.0,
            cgroup_cpu_percent: 0.0,
            valid: total.is_some() && available.is_some() && !self.groups.is_empty(),
        };
        if let Some(n) = read("/proc/self/status")
            .lines()
            .find_map(|l| cpu_list(l.strip_prefix("Cpus_allowed_list:")?))
        {
            r.cpu_cores = r.cpu_cores.min(n as f64);
        }
        let now = Instant::now();
        let elapsed = self
            .last
            .map(|(t, _, _, _)| now.duration_since(t).as_secs_f64())
            .unwrap_or(0.0);
        for (i, g) in self.groups.iter().enumerate() {
            if g.memory {
                let (limit, usage) = if g.v2 {
                    let limit = [
                        number(g.path.join("memory.max")),
                        number(g.path.join("memory.high")),
                    ]
                    .into_iter()
                    .flatten()
                    .min();
                    (limit, number(g.path.join("memory.current")))
                } else {
                    (
                        number(g.path.join("memory.limit_in_bytes")),
                        number(g.path.join("memory.usage_in_bytes")),
                    )
                };
                if let Some(limit) = limit.filter(|n| *n < 1u64 << 60) {
                    r.memory_total_bytes = r.memory_total_bytes.min(limit);
                    if let Some(used) = usage {
                        r.memory_available_bytes =
                            r.memory_available_bytes.min(limit.saturating_sub(used))
                    } else {
                        r.valid = false
                    }
                }
            }
            if g.cpu {
                let quota = if g.v2 {
                    let text = read(g.path.join("cpu.max"));
                    let w: Vec<_> = text.split_whitespace().collect();
                    w.first()
                        .and_then(|v| v.parse::<f64>().ok())
                        .zip(w.get(1).and_then(|v| v.parse::<f64>().ok()))
                } else {
                    number(g.path.join("cpu.cfs_quota_us"))
                        .map(|v| v as f64)
                        .zip(number(g.path.join("cpu.cfs_period_us")).map(|v| v as f64))
                };
                let cores = quota
                    .filter(|(q, p)| *q > 0.0 && *p > 0.0)
                    .map(|(q, p)| q / p);
                if let Some(n) = cores {
                    r.cpu_cores = r.cpu_cores.min(n)
                }
                let used = if g.v2 {
                    field(&read(g.path.join("cpu.stat")), "usage_usec")
                } else {
                    number(g.path.join("cpuacct.usage")).map(|v| v / 1000)
                };
                if let (Some(used), Some(previous), Some(cores)) = (used, self.cpu_last[i], cores)
                    && elapsed > 0.0
                {
                    r.cgroup_cpu_percent = r
                        .cgroup_cpu_percent
                        .max(used.saturating_sub(previous) as f64 / 1e6 / elapsed / cores * 100.0);
                }
                self.cpu_last[i] = used;
            }
        }
        r.cpu_cores = r.cpu_cores.clamp(0.01, 65536.0);
        if let (Some((all, idle)), Some(process)) = (cpu_ticks(), process_ticks()) {
            if let Some((_, old_all, old_idle, old_process)) = self.last {
                let dt = all.saturating_sub(old_all);
                if dt > 0 {
                    r.system_cpu_percent = 100.0
                        * (dt.saturating_sub(idle.saturating_sub(old_idle))) as f64
                        / dt as f64
                }
                if elapsed > 0.0 {
                    r.process_cpu_percent = process.saturating_sub(old_process) as f64
                        / self.ticks
                        / elapsed
                        / r.cpu_cores.min(2.0)
                        * 100.0
                }
            }
            self.last = Some((now, all, idle, process));
        } else {
            r.valid = false
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn resources() -> Resources {
        Resources {
            memory_total_bytes: 8 * 1024 * MIB,
            memory_available_bytes: 7 * 1024 * MIB,
            cpu_cores: 1.0,
            fd_soft_limit: 1048576,
            system_cpu_percent: 0.0,
            process_cpu_percent: 0.0,
            cgroup_cpu_percent: 0.0,
            valid: true,
        }
    }
    #[test]
    fn shared_budget_and_fd_caps() {
        let mut r = resources();
        r.fd_soft_limit = 256;
        let cap = Capacity::new(&Config::default(), r);
        let mut leases = vec![];
        while let Some(l) = cap.enter(Kind::Tcp) {
            leases.push(l)
        }
        assert_eq!(leases.len(), 32);
        assert!(cap.enter(Kind::Udp).is_none());
        drop(leases);
        assert!(cap.enter(Kind::Udp).is_some());
        let mut r = resources();
        r.memory_total_bytes = 256 * MIB;
        let cap = Capacity::new(&Config::default(), r);
        let mut leases = vec![];
        while let Some(l) = cap.enter(Kind::Tcp) {
            leases.push(l)
        }
        // TCP exhausts the shared RAM budget even though UDP's separate ceiling is not reached.
        assert!(cap.enter(Kind::Udp).is_none());
        drop(leases);
    }
    #[test]
    fn critical_pressure_preserves_sessions_and_recovers_gradually() {
        let cap = Capacity::new(&Config::default(), resources());
        let lease = cap.enter(Kind::Tcp).unwrap();
        let mut low = resources();
        low.memory_available_bytes = 1;
        cap.sample(low);
        assert!(cap.enter(Kind::Tcp).is_none());
        assert_eq!(cap.state.lock().unwrap().active_tcp, 1);
        for _ in 0..4 {
            cap.sample(resources())
        }
        assert!(cap.enter(Kind::Tcp).is_none());
        cap.sample(resources());
        assert_eq!(cap.state.lock().unwrap().factor, 10);
        // Tokens replenish in real time rather than getting an unbounded post-recovery burst.
        drop(lease);
        assert_eq!(cap.state.lock().unwrap().active_tcp, 0);
    }
    #[test]
    fn cpu_spikes_do_not_cause_flapping() {
        let cap = Capacity::new(&Config::default(), resources());
        let mut busy = resources();
        busy.process_cpu_percent = 99.0;
        cap.sample(busy.clone());
        cap.sample(busy.clone());
        assert_eq!(cap.state.lock().unwrap().factor, 100);
        cap.sample(busy);
        assert_eq!(cap.state.lock().unwrap().factor, 75);
        for _ in 0..5 {
            cap.sample(resources())
        }
        assert_eq!(cap.state.lock().unwrap().factor, 85);
    }
    #[test]
    fn startup_respects_other_process_memory_usage() {
        let mut r = resources();
        r.memory_available_bytes = 950 * MIB;
        let cap = Capacity::new(&Config::default(), r);
        assert!(cap.state.lock().unwrap().limits.tcp < 500);
        let mut r = resources();
        r.memory_available_bytes = 1;
        let cap = Capacity::new(&Config::default(), r);
        assert!(cap.enter(Kind::Tcp).is_none());
        assert_eq!(cap.state.lock().unwrap().pressure, "memory_critical");
    }
    #[test]
    fn manual_limits_and_sensor_failure() {
        let c = Config {
            auto_capacity: false,
            max_tcp_connections: 3,
            ..Config::default()
        };
        let cap = Capacity::new(&c, resources());
        let mut invalid = resources();
        invalid.valid = false;
        cap.sample(invalid.clone());
        assert_eq!(cap.state.lock().unwrap().limits.tcp, 3);
        let cap = Capacity::new(&Config::default(), resources());
        cap.sample(invalid);
        assert!(cap.enter(Kind::Tcp).is_none());
    }
    #[test]
    fn cgroup_mount_roots_and_ancestors() {
        let g = discover_groups(
            "0::/docker/a/service\n",
            "27 21 0:24 /docker/a /custom/cg rw - cgroup2 cgroup rw\n",
        );
        assert_eq!(
            g.iter().map(|g| g.path.as_path()).collect::<Vec<_>>(),
            vec![Path::new("/custom/cg/service"), Path::new("/custom/cg")]
        );
        let g = discover_groups(
            "5:memory:/user/app\n6:cpu,cpuacct:/user/app\n",
            "21 20 0:1 / /cg/mem rw - cgroup cgroup rw,memory\n22 20 0:2 / /cg/cpu rw - cgroup cgroup rw,cpu,cpuacct\n",
        );
        assert_eq!(g.len(), 6);
        assert!(g[0].memory);
        assert!(g[3].cpu);
        assert!(!g[3].v2);
    }
    #[test]
    fn safe_cgroup_paths_and_cpu_lists() {
        assert!(safe_path(Path::new("/sys/fs/cgroup"), "/../../bad").is_none());
        assert_eq!(cpu_list("0-3,6,8-9"), Some(7));
        assert_eq!(cpu_list("5-1"), None);
        let r = Sampler::new().sample();
        assert!(r.valid);
        assert!(r.cpu_cores > 0.0);
    }
}
