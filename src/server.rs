use crate::{
    capacity::{Capacity, Kind, Sampler},
    config::{Config, Route, Tables},
    dns::Dns,
    net::{self, FrontUdp},
    quic,
    sniff::{self, Probe},
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
};
use tokio_util::sync::CancellationToken;

pub struct Runtime {
    pub cfg: Config,
    pub tables: Tables,
    pub dns: Dns,
}
impl Runtime {
    pub fn new(cfg: Config) -> Result<Self> {
        Ok(Self {
            tables: cfg.tables()?,
            dns: Dns::new(&cfg)?,
            cfg,
        })
    }
}
#[derive(Default)]
pub struct Stats {
    tcp_accepted: AtomicU64,
    tcp_failed: AtomicU64,
    tcp_bytes: AtomicU64,
    udp_created: AtomicU64,
    udp_rejected: AtomicU64,
    udp_packets: AtomicU64,
    udp_bytes: AtomicU64,
}
pub struct Shared {
    pub runtime: RwLock<Arc<Runtime>>,
    pub shutdown: CancellationToken,
    pub stats: Stats,
    pub capacity: Arc<Capacity>,
    tcp: Arc<Semaphore>,
    udp: Arc<Semaphore>,
    pending: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
    bytes_cap: usize,
    pending_cap: usize,
    ips: Arc<Mutex<HashMap<IpAddr, usize>>>,
}
impl Shared {
    pub fn new(runtime: Runtime) -> Arc<Self> {
        let c = &runtime.cfg;
        let capacity = Capacity::new(c, Sampler::new().sample());
        Arc::new(Self {
            capacity,
            bytes_cap: c.udp_queue_bytes,
            pending_cap: c.max_pending_handshakes,
            tcp: Arc::new(Semaphore::new(c.max_tcp_connections)),
            udp: Arc::new(Semaphore::new(c.max_udp_sessions)),
            pending: Arc::new(Semaphore::new(c.max_pending_handshakes)),
            bytes: Arc::new(Semaphore::new(c.udp_queue_bytes)),
            ips: Arc::new(Mutex::new(HashMap::new())),
            runtime: RwLock::new(Arc::new(runtime)),
            shutdown: CancellationToken::new(),
            stats: Stats::default(),
        })
    }
    pub fn snapshot(&self) -> Arc<Runtime> {
        self.runtime.read().unwrap().clone()
    }
    pub fn status(&self) -> serde_json::Value {
        let c = &self.snapshot().cfg;
        let s = &self.stats;
        serde_json::json!({"version":env!("CARGO_PKG_VERSION"),"rules":c.rules.len(),
            "tcp_active":c.max_tcp_connections-self.tcp.available_permits(),
            "udp_active":c.max_udp_sessions-self.udp.available_permits(),
            "pending_handshakes":c.max_pending_handshakes-self.pending.available_permits(),
            "queued_udp_bytes":c.udp_queue_bytes-self.bytes.available_permits(),
            "tracked_ips":self.ips.lock().unwrap().len(),
            "tcp_accepted":s.tcp_accepted.load(Ordering::Relaxed),"tcp_failed":s.tcp_failed.load(Ordering::Relaxed),
            "tcp_bytes":s.tcp_bytes.load(Ordering::Relaxed),"udp_created":s.udp_created.load(Ordering::Relaxed),
            "udp_packets":s.udp_packets.load(Ordering::Relaxed),"udp_bytes":s.udp_bytes.load(Ordering::Relaxed),
            "udp_rejected":s.udp_rejected.load(Ordering::Relaxed),
            "capacity": self.capacity.status()})
    }
    fn pending_guard(&self) -> Option<OwnedSemaphorePermit> {
        let permit = self.pending.clone().try_acquire_owned().ok()?;
        if self.pending_cap - self.pending.available_permits()
            > self.capacity.pending.load(Ordering::Relaxed)
        {
            return None;
        }
        Some(permit)
    }
    fn ip_guard(&self, ip: IpAddr) -> Option<IpGuard> {
        let limit = self.snapshot().cfg.max_connections_per_ip;
        let mut ips = self.ips.lock().unwrap();
        let n = ips.entry(ip).or_default();
        if *n >= limit {
            return None;
        }
        *n += 1;
        Some(IpGuard {
            ip,
            ips: self.ips.clone(),
        })
    }
    fn packet(&self, b: &[u8], stride: usize) -> Option<Packet> {
        let permit = self
            .bytes
            .clone()
            .try_acquire_many_owned(b.len().max(1) as u32)
            .ok()?;
        if self.bytes_cap - self.bytes.available_permits()
            > self.capacity.queue.load(Ordering::Relaxed)
        {
            return None;
        }
        Some(Packet {
            bytes: b.to_vec(),
            stride: stride.max(1),
            _permit: permit,
        })
    }
}
struct IpGuard {
    ip: IpAddr,
    ips: Arc<Mutex<HashMap<IpAddr, usize>>>,
}
impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut m = self.ips.lock().unwrap();
        if let Some(v) = m.get_mut(&self.ip) {
            *v -= 1;
            if *v == 0 {
                m.remove(&self.ip);
            }
        }
    }
}
struct Packet {
    bytes: Vec<u8>,
    stride: usize,
    _permit: OwnedSemaphorePermit,
}

impl Packet {
    fn count(&self) -> u64 {
        self.bytes.len().div_ceil(self.stride) as u64
    }
}

pub struct Manager {
    pub shared: Arc<Shared>,
    active: BTreeMap<(SocketAddr, bool), CancellationToken>,
}
enum Bound {
    Tcp(SocketAddr, tokio::net::TcpListener),
    Udp(SocketAddr, Arc<FrontUdp>),
}
impl Manager {
    pub fn new(cfg: Config) -> Result<Self> {
        Ok(Self {
            shared: Shared::new(Runtime::new(cfg)?),
            active: BTreeMap::new(),
        })
    }
    pub fn apply(&mut self, cfg: Config, persist: Option<&std::path::Path>) -> Result<()> {
        ensure!(
            self.shared.snapshot().cfg.compatible_limits(&cfg),
            "resource limit changes require a restart"
        );
        let rt = Runtime::new(cfg)?;
        let mut desired = BTreeMap::new();
        let mut bound = vec![];
        for (addr, routes) in &rt.tables {
            for udp in [false, true] {
                if if udp {
                    !routes.udp_enabled
                } else {
                    !routes.tcp_enabled
                } {
                    continue;
                }
                let key = (*addr, udp);
                desired.insert(key, ());
                if self.active.contains_key(&key) {
                    continue;
                }
                if udp {
                    bound.push(Bound::Udp(
                        *addr,
                        FrontUdp::bind(*addr).with_context(|| format!("bind UDP {addr}"))?,
                    ))
                } else {
                    bound.push(Bound::Tcp(
                        *addr,
                        net::tcp_listener(*addr).with_context(|| format!("bind TCP {addr}"))?,
                    ))
                }
            }
        }
        // All configuration validation and socket acquisition finish before writing/publishing.
        if let Some(path) = persist {
            crate::control::atomic_config(path, &rt.cfg)?
        }
        self.shared.capacity.listeners(desired.len());
        *self.shared.runtime.write().unwrap() = Arc::new(rt);
        self.active.retain(|key, token| {
            if desired.contains_key(key) {
                true
            } else {
                token.cancel();
                false
            }
        });
        for b in bound {
            let stop = self.shared.shutdown.child_token();
            let shared = self.shared.clone();
            match b {
                Bound::Tcp(a, l) => {
                    self.active.insert((a, false), stop.clone());
                    tokio::spawn(tcp_accept(l, a, shared, stop));
                }
                Bound::Udp(a, l) => {
                    self.active.insert((a, true), stop.clone());
                    tokio::spawn(udp_hub(l, shared, stop));
                }
            }
        }
        Ok(())
    }
}
async fn tcp_accept(
    listener: tokio::net::TcpListener,
    addr: SocketAddr,
    s: Arc<Shared>,
    stop: CancellationToken,
) {
    loop {
        let accepted = tokio::select! {_ =stop.cancelled()=>break,r=listener.accept()=>r};
        let Ok((stream, peer)) = accepted else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Some(admission) = s.capacity.enter(Kind::Tcp) else {
            s.stats.tcp_failed.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(2)).await;
            continue;
        };
        let Some(pending) = s.pending_guard() else {
            s.stats.tcp_failed.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(2)).await;
            continue;
        };
        let Ok(limit) = s.tcp.clone().try_acquire_owned() else {
            s.stats.tcp_failed.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let peer = net::normalize(peer);
        let Some(ip_guard) = s.ip_guard(peer.ip()) else {
            s.stats.tcp_failed.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let rt = s.snapshot();
        let Some(routes) = rt.tables.get(&addr).cloned() else {
            continue;
        };
        let s = s.clone();
        s.stats.tcp_accepted.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            let _limit = limit;
            let _admission = admission;
            let _ip = ip_guard;
            let result = tokio::select! {_=s.shutdown.cancelled()=>return,
            r=tcp_flow(stream,peer,routes,rt,pending,&s)=>r};
            if result.is_err() {
                s.stats.tcp_failed.fetch_add(1, Ordering::Relaxed);
            }
        });
    }
}
async fn tcp_flow(
    mut stream: TcpStream,
    peer: SocketAddr,
    routes: Arc<crate::config::ListenerRoutes>,
    rt: Arc<Runtime>,
    pending: OwnedSemaphorePermit,
    s: &Arc<Shared>,
) -> Result<()> {
    net::tune_tcp(&stream)?;
    let (host, prefix) = tokio::time::timeout(
        Duration::from_millis(rt.cfg.sniff_timeout_ms),
        sniff::tcp(&mut stream, routes.tcp.has_names()),
    )
    .await??;
    let route = routes.tcp.lookup(host.as_deref()).context("no TCP route")?;
    let mut upstream = tokio::time::timeout(
        Duration::from_millis(rt.cfg.dial_timeout_ms),
        tcp_dial(&rt, &route),
    )
    .await??;
    drop(pending);
    net::tune_tcp(&upstream)?;
    if rt.cfg.access_log {
        tracing::info!(protocol="tcp",client=%peer,domain=?host,target=%route.host,port=route.port,"forward");
    }
    upstream.write_all(&prefix).await?;
    let prefix_bytes = prefix.len() as u64;
    // Long-lived streams must not retain an obsolete routing table/DNS cache after reload.
    drop(prefix);
    drop(route);
    drop(routes);
    drop(rt);
    let (a, b) = crate::relay::copy(&stream, &upstream).await?;
    s.stats
        .tcp_bytes
        .fetch_add(a + b + prefix_bytes, Ordering::Relaxed);
    Ok(())
}
async fn tcp_dial(rt: &Runtime, r: &Route) -> Result<TcpStream> {
    let addresses = rt.dns.lookup(&r.host, r.port).await?;
    let each = Duration::from_millis((rt.cfg.dial_timeout_ms / addresses.len() as u64).max(100));
    let mut last = None;
    for addr in addresses {
        // Refuse direct self-loops, including wildcard listeners on a local address.
        ensure!(
            !local_loop(rt, addr, true),
            "target points back to a TCP listener"
        );
        match tokio::time::timeout(each, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = Some(e.to_string()),
            Err(_) => last = Some("connect timeout".into()),
        }
    }
    anyhow::bail!("all backend addresses failed: {}", last.unwrap_or_default())
}
fn local_loop(rt: &Runtime, target: SocketAddr, tcp: bool) -> bool {
    rt.tables.iter().any(|(a, r)| {
        a.port() == target.port()
            && a.is_ipv4() == target.is_ipv4()
            && if tcp { r.tcp_enabled } else { r.udp_enabled }
            && (a.ip() == target.ip()
                || (a.ip().is_unspecified()
                    && (target.ip().is_loopback()
                        || std::net::UdpSocket::bind(SocketAddr::new(target.ip(), 0)).is_ok())))
    })
}

type PeerKey = (SocketAddr, IpAddr);
struct Flow {
    peer: SocketAddr,
    local: IpAddr,
    cids: Vec<Vec<u8>>,
    tx: mpsc::Sender<Packet>,
}
enum Event {
    Reply(u64, Packet),
    Closed(u64),
}
async fn udp_hub(front: Arc<FrontUdp>, s: Arc<Shared>, stop: CancellationToken) {
    let mut flows: HashMap<u64, Flow> = HashMap::new();
    let mut peers: HashMap<PeerKey, Vec<u64>> = HashMap::new();
    let (events, mut rx) = mpsc::channel::<Event>(256);
    let mut sequence = 0u64;
    let mut buf = vec![0u8; net::UDP_RECV_BYTES];
    loop {
        tokio::select! {
            _=stop.cancelled()=>break,
            Some(event)=rx.recv()=>match event{
                Event::Closed(id)=>{
                    if let Some(f)=flows.remove(&id){
                        let key=(f.peer,f.local);
                        if let Some(ids)=peers.get_mut(&key){ids.retain(|v|*v!=id);if ids.is_empty(){peers.remove(&key);}}
                    }
                },
                Event::Reply(id,p)=>{
                    if let Some(f)=flows.get_mut(&id){
                        // Learn server connection IDs only from the connected backend socket.
                        for bytes in p.bytes.chunks(p.stride) {
                            if let Some(h)=quic::header(bytes)
                                && !h.scid.is_empty() && !f.cids.iter().any(|c|c==h.scid) && f.cids.len()<16{f.cids.push(h.scid.to_vec());}
                        }
                        if !matches!(tokio::time::timeout(Duration::from_secs(1),front.send(f.peer,f.local,&p.bytes,p.stride)).await,Ok(Ok(()))) {
                            s.stats.udp_rejected.fetch_add(p.count(),Ordering::Relaxed);
                        }
                    }
                }
            },
            result=front.recv(&mut buf)=>{
                let Ok(meta)=result else {tokio::time::sleep(Duration::from_millis(10)).await;continue};
                let peer=net::normalize(meta.addr);
                let local=meta.dst_ip.unwrap_or(front.addr.ip());
                if local.is_unspecified(){continue}
                let stride=meta.stride.max(1);let end=meta.len.min(buf.len());
                let mut group: Option<(u64,usize,usize)> = None;
                for (index,bytes) in buf[..end].chunks(stride).enumerate() {
                    let offset=index*stride;
                    let key=(peer,local);let ids=peers.get(&key).map(Vec::as_slice).unwrap_or(&[]);
                    let long=quic::header(bytes);
                    let initial=long.as_ref().is_some_and(|h|h.initial);
                    let mut matched=None;let mut ambiguous=false;
                    for id in ids {
                        if let Some(f)=flows.get(id) {
                            let hit=if let Some(h)=&long {f.cids.iter().any(|c|c.as_slice()==h.dcid)}
                                else {(bytes.len()>=18 && bytes.first().is_some_and(|b|b&0x80==0)) &&
                                    f.cids.iter().any(|c|bytes.get(1..1+c.len())==Some(c.as_slice()))};
                            if hit {if matched.is_some(){ambiguous=true;break}matched=Some(*id);}
                        }
                    }
                    if ambiguous {s.stats.udp_rejected.fetch_add(1,Ordering::Relaxed);continue}
                    // CID rotation is encrypted. A stable, unambiguous five-tuple can still be routed.
                    if matched.is_none() && !initial && ids.len()==1 &&
                        (long.is_some() || (bytes.len()>=18 && bytes.first().is_some_and(|b|b&0x80==0))) {
                        matched=Some(ids[0]);
                    }
                    if let Some(id)=matched {
                        if let Some((previous,start,finish))=group.take() {
                            if previous==id && finish==offset {
                                group=Some((id,start,offset+bytes.len()));
                            } else {
                                enqueue_udp(&s,&flows,previous,&buf[start..finish],stride);
                                group=Some((id,offset,offset+bytes.len()));
                            }
                        } else {
                            group=Some((id,offset,offset+bytes.len()));
                        }
                        continue
                    }
                    if let Some((id,start,finish))=group.take() {
                        enqueue_udp(&s,&flows,id,&buf[start..finish],stride);
                    }
                    // Ordinary UDP, unknown QUIC versions and missing Initial packets never create a flow.
                    if !initial || bytes.len()<1200 || ids.len()>=8{
                        s.stats.udp_rejected.fetch_add(1,Ordering::Relaxed);continue
                    }
                    let Some(admission)=s.capacity.enter(Kind::Udp) else{s.stats.udp_rejected.fetch_add(1,Ordering::Relaxed);continue};
                    let Ok(limit)=s.udp.clone().try_acquire_owned() else{s.stats.udp_rejected.fetch_add(1,Ordering::Relaxed);continue};
                    let Some(pending)=s.pending_guard() else{s.stats.udp_rejected.fetch_add(1,Ordering::Relaxed);continue};
                    let Some(ip_guard)=s.ip_guard(peer.ip()) else{s.stats.udp_rejected.fetch_add(1,Ordering::Relaxed);continue};
                    let Some(p)=s.packet(bytes,bytes.len()) else{s.stats.udp_rejected.fetch_add(1,Ordering::Relaxed);continue};
                    let rt=s.snapshot();let Some(routes)=rt.tables.get(&front.addr).cloned() else{continue};
                    if !routes.udp_enabled {continue}
                    let h=long.unwrap();
                    let (tx,queue)=mpsc::channel(64);
                    if tx.try_send(p).is_err(){continue}
                    sequence=sequence.wrapping_add(1);let id=sequence;
                    flows.insert(id,Flow {peer,local,cids:vec![h.dcid.to_vec()],tx});
                    peers.entry(key).or_default().push(id);
                    s.stats.udp_created.fetch_add(1,Ordering::Relaxed);
                    let events=events.clone();let s=s.clone();let stop=stop.clone();let front=front.clone();
                    tokio::spawn(async move{
                        let _limit=limit;let _admission=admission;let _ip=ip_guard;
                        let result=tokio::select!{_=stop.cancelled()=>return,
                            r=udp_flow(id,peer,local,&front,queue,&events,pending,&s,rt,routes)=>r};
                        if result.is_err(){s.stats.udp_rejected.fetch_add(1,Ordering::Relaxed);}
                        tokio::select!{_=stop.cancelled()=>{},_=events.send(Event::Closed(id))=>{}}
                    });
                }
                if let Some((id,start,finish))=group {
                    enqueue_udp(&s,&flows,id,&buf[start..finish],stride);
                }
            }
        }
    }
    // Dropping the front map closes all client queues. Stop token closes backend tasks.
    stop.cancel();
}
fn enqueue_udp(s: &Shared, flows: &HashMap<u64, Flow>, id: u64, bytes: &[u8], stride: usize) {
    let count = bytes.len().div_ceil(stride.max(1)) as u64;
    if let Some(p) = s.packet(bytes, stride)
        && let Some(f) = flows.get(&id)
        && f.tx.try_send(p).is_ok()
    {
        return;
    }
    s.stats.udp_rejected.fetch_add(count, Ordering::Relaxed);
}
#[allow(clippy::too_many_arguments)]
async fn udp_flow(
    id: u64,
    peer: SocketAddr,
    local: IpAddr,
    front: &FrontUdp,
    mut rx: mpsc::Receiver<Packet>,
    events: &mpsc::Sender<Event>,
    pending: OwnedSemaphorePermit,
    s: &Arc<Shared>,
    rt: Arc<Runtime>,
    routes: Arc<crate::config::ListenerRoutes>,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(rt.cfg.sniff_timeout_ms);
    let mut saved = vec![];
    let mut assembler = None;
    let mut size = 0;
    let mut datagrams = 0;
    let host = loop {
        let packet = tokio::time::timeout_at(deadline, rx.recv())
            .await?
            .context("UDP listener closed")?;
        size += packet.bytes.len();
        datagrams += packet.count();
        ensure!(
            size <= 128 * 1024 && datagrams <= 64,
            "QUIC handshake buffering exceeded"
        );
        let mut found = None;
        for bytes in packet.bytes.chunks(packet.stride) {
            if assembler.is_none() {
                assembler = Some(quic::Initial::new(bytes)?);
            }
            match assembler.as_mut().unwrap().feed(bytes)? {
                Probe::Name(host) => {
                    found = Some(host);
                    break;
                }
                Probe::NoName => anyhow::bail!("QUIC SNI required"),
                Probe::Need => {}
            }
        }
        saved.push(packet);
        if let Some(host) = found {
            break host;
        }
    };
    drop(assembler);
    let route = routes
        .udp
        .lookup(Some(&host))
        .context("no QUIC domain route")?;
    let upstream = tokio::time::timeout(Duration::from_millis(rt.cfg.dial_timeout_ms), async {
        let addresses = rt.dns.lookup(&route.host, route.port).await?;
        let mut last = None;
        for addr in addresses {
            ensure!(
                !local_loop(&rt, addr, false),
                "target points back to a UDP listener"
            );
            match net::udp_connect(addr).await {
                Ok(s) => return Ok(s),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| anyhow::anyhow!("no UDP target")))
    })
    .await??;
    drop(pending);
    if rt.cfg.access_log {
        tracing::info!(protocol="quic",client=%peer,domain=%host,target=%route.host,port=route.port,"forward");
    }
    for p in saved {
        send_upstream(&upstream, &p, s).await;
    }
    let mut buf = vec![0u8; net::UDP_RECV_BYTES];
    let idle = Duration::from_secs(rt.cfg.udp_idle_seconds);
    drop(route);
    drop(routes);
    drop(rt);
    let timer = tokio::time::sleep(idle);
    tokio::pin!(timer);
    loop {
        tokio::select! {
            _=&mut timer=>break,
            packet=rx.recv()=>{
                let Some(p)=packet else{break};
                send_upstream(&upstream,&p,s).await;
                timer.as_mut().reset(tokio::time::Instant::now()+idle);
            },
            result=upstream.recv(&mut buf)=>{
                let meta=match result {
                    Ok(meta)=>meta,
                    Err(_)=>{tokio::time::sleep(Duration::from_millis(10)).await;continue}
                };
                let count=meta.len.div_ceil(meta.stride.max(1)) as u64;
                let bytes=&buf[..meta.len];
                // Long headers can introduce a server CID: serialize these through
                // the hub before replying. Encrypted short-header traffic can return
                // directly, avoiding a copy, allocation and cross-task queue hop.
                let needs_cid_update=bytes.chunks(meta.stride.max(1)).any(|b|b.first().is_some_and(|v|v&0x80!=0));
                let sent=if needs_cid_update {
                    if let Some(p)=s.packet(bytes,meta.stride) {
                        events.try_send(Event::Reply(id,p)).is_ok()
                    } else { false }
                } else {
                    matches!(tokio::time::timeout(Duration::from_secs(1),
                        front.send(peer,local,bytes,meta.stride)).await,Ok(Ok(())))
                };
                if !sent{s.stats.udp_rejected.fetch_add(count,Ordering::Relaxed);}
                s.stats.udp_packets.fetch_add(count,Ordering::Relaxed);
                s.stats.udp_bytes.fetch_add(meta.len as u64,Ordering::Relaxed);
                timer.as_mut().reset(tokio::time::Instant::now()+idle);
            }
        }
    }
    Ok(())
}

// UDP errors (including oversized path-MTU probes) must not tear down a QUIC
// connection. Count the loss and let the endpoint retransmit or time out.
async fn send_upstream(upstream: &FrontUdp, p: &Packet, s: &Shared) {
    if !matches!(
        tokio::time::timeout(
            Duration::from_secs(1),
            upstream.send_upstream(&p.bytes, p.stride)
        )
        .await,
        Ok(Ok(()))
    ) {
        s.stats.udp_rejected.fetch_add(p.count(), Ordering::Relaxed);
    }
    s.stats.udp_packets.fetch_add(p.count(), Ordering::Relaxed);
    s.stats
        .udp_bytes
        .fetch_add(p.bytes.len() as u64, Ordering::Relaxed);
}
