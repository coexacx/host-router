#![forbid(unsafe_code)]
mod capacity;
mod config;
mod control;
mod dns;
mod net;
mod quic;
mod relay;
mod release;
mod server;
mod sniff;
use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use config::{Config, Protocol, Rule};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::Mutex;
#[derive(Parser)]
#[command(version, about = "Rust TCP SNI/HTTP + UDP QUIC router")]
struct Cli {
    #[arg(
        short = 'c',
        long,
        global = true,
        default_value = "/etc/host-router/config.json"
    )]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    Serve,
    VerifyRelease {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        signature: PathBuf,
        #[arg(long)]
        asset: String,
    },
    Summary,
    CapacityPlan {
        #[arg(long)]
        systemd: bool,
    },
    Edit {
        id: usize,
        #[arg(long)]
        listen: String,
        #[arg(long)]
        domain: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        offline: bool,
    },
    Set {
        #[arg(long)]
        dns_refresh: Option<u64>,
        #[arg(long)]
        default_port: Option<String>,
        #[arg(long)]
        access_log: Option<bool>,
        #[arg(long)]
        offline: bool,
    },
    PrepareConfig {
        #[arg(long)]
        user: String,
    },
    Check {
        #[arg(long)]
        file: Option<PathBuf>,
    },
    Init,
    Status,
    List,
    Apply {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        offline: bool,
    },
    AddBatch {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        listen: Option<String>,
        #[arg(long, default_value = "both")]
        protocol: String,
        #[arg(long)]
        offline: bool,
    },
    Delete {
        #[arg(required=true,num_args=1..)]
        ids: Vec<usize>,
        #[arg(long)]
        offline: bool,
    },
}
fn read_cfg(path: &std::path::Path) -> Result<Config> {
    let meta = std::fs::metadata(path)?;
    ensure!(
        meta.len() <= config::MAX_CONFIG as u64,
        "configuration too large"
    );
    Config::parse(&std::fs::read(path)?)
}
async fn commit(path: &std::path::Path, cfg: Config, offline: bool, base: Config) -> Result<()> {
    cfg.tables()?;
    if offline {
        let _lock = control::lock(path)?;
        ensure!(
            !control::socket_path(path).exists(),
            "control socket exists; stop the running service before offline editing"
        );
        control::atomic_config(path, &cfg)?;
        println!("Saved. Start/restart the service to bind listeners.");
    } else {
        let response = control::request(
            path,
            control::Request {
                action: "apply".into(),
                config: Some(cfg),
                base: Some(serde_json::to_value(base)?),
            },
        )
        .await
        .context("service unavailable; for an intentionally stopped service use --offline")?;
        ensure!(response.ok, "{}", response.message);
        println!("{}", response.message);
    }
    Ok(())
}
fn batch(text: &str, listen: Option<&str>, protocol: Protocol) -> Result<Vec<Rule>> {
    ensure!(text.len() <= config::MAX_CONFIG, "batch file too large");
    let mut rules = vec![];
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<_> = line.split_ascii_whitespace().collect();
        let (listen, domain, target, port) = if let Some(l) = listen {
            ensure!(
                cols.len() == 3,
                "line {}: expected domain target port",
                i + 1
            );
            (l, cols[0], cols[1], cols[2])
        } else {
            ensure!(
                cols.len() == 4,
                "line {}: expected listen domain target port",
                i + 1
            );
            (cols[0], cols[1], cols[2], cols[3])
        };
        config::port(port)?;
        let (host, _) = config::target(target, config::port(port)?)?;
        // Reject accidentally entering two conflicting ports; a separate port column is authoritative only for host literals.
        ensure!(
            !target.contains(':')
                || target.parse::<std::net::IpAddr>().is_ok()
                || (target.starts_with('[') && target.ends_with(']')),
            "line {}: target column must not contain a port",
            i + 1
        );
        let formatted = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        rules.push(Rule {
            listen: listen.into(),
            domain: domain.into(),
            target: formatted,
            protocol,
            note: String::new(),
        });
    }
    ensure!(!rules.is_empty(), "batch contains no rules");
    Ok(rules)
}
fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(16)
        .enable_all()
        .build()
        .unwrap();
    if let Err(e) = runtime.block_on(run()) {
        eprintln!("host-router: {e:#}");
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();
    let mut args: Vec<_> = std::env::args_os().collect();
    let legacy_check = args.iter().any(|s| s == "-check");
    if legacy_check {
        args.retain(|s| s != "-check");
        args.push("check".into());
    }
    let cli = Cli::parse_from(args);
    match cli.cmd.unwrap_or(Command::Serve) {
        Command::VerifyRelease {
            manifest,
            signature,
            asset,
        } => release::verify(&manifest, &signature, &asset)?,
        Command::CapacityPlan { systemd } => {
            let r = capacity::Sampler::new().sample();
            ensure!(
                r.valid,
                "resource detection failed; check /proc and cgroup visibility"
            );
            if systemd {
                let maximum = std::fs::read_to_string("/proc/sys/fs/nr_open")?
                    .trim()
                    .parse::<u64>()?
                    .min(1048576);
                ensure!(maximum >= 1024, "system descriptor ceiling is too low");
                println!(
                    "LimitNOFILE={maximum}\nMemoryHigh={}\nMemoryMax={}\nCPUWeight=80",
                    r.memory_total_bytes * 70 / 100,
                    r.memory_total_bytes * 80 / 100
                );
            } else {
                let c = if cli.config.exists() {
                    read_cfg(&cli.config)?
                } else {
                    Config::default()
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&capacity::Capacity::new(&c, r).status())?
                );
            }
        }
        Command::Summary => {
            let cfg = read_cfg(&cli.config)?;
            let live = control::request(
                &cli.config,
                control::Request {
                    action: "status".into(),
                    config: None,
                    base: None,
                },
            )
            .await
            .ok()
            .filter(|r| r.ok)
            .and_then(|r| r.data);
            let rt = cfg.tables()?;
            let tcp = rt.values().filter(|r| r.tcp_enabled).count();
            let udp = rt.values().filter(|r| r.udp_enabled).count();
            println!(
                "{} {} {} {} {} {} {} {} {} {} {}",
                if live.is_some() { "running" } else { "stopped" },
                env!("CARGO_PKG_VERSION"),
                live.as_ref()
                    .and_then(|v| v.get("rules"))
                    .and_then(|n| n.as_u64())
                    .unwrap_or(cfg.rules.len() as u64),
                tcp,
                udp,
                cfg.dns_refresh_seconds,
                live.as_ref()
                    .and_then(|v| v.pointer("/capacity/mode"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("-"),
                live.as_ref()
                    .and_then(|v| v.pointer("/tcp_active"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                live.as_ref()
                    .and_then(|v| v.pointer("/capacity/effective/tcp"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                live.as_ref()
                    .and_then(|v| v.pointer("/udp_active"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                live.as_ref()
                    .and_then(|v| v.pointer("/capacity/effective/udp"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            );
        }
        Command::Edit {
            id,
            listen,
            domain,
            target,
            offline,
        } => {
            let mut cfg = read_cfg(&cli.config)?;
            let base = cfg.clone();
            ensure!(id >= 1 && id <= cfg.rules.len(), "rule ID out of range");
            let r = &mut cfg.rules[id - 1];
            r.listen = listen;
            r.domain = domain;
            r.target = target;
            commit(&cli.config, cfg, offline, base).await?;
        }
        Command::Set {
            dns_refresh,
            default_port,
            access_log,
            offline,
        } => {
            let mut cfg = read_cfg(&cli.config)?;
            let base = cfg.clone();
            if let Some(v) = dns_refresh {
                cfg.dns_refresh_seconds = v;
            }
            if let Some(v) = default_port {
                cfg.default_port = v;
            }
            if let Some(v) = access_log {
                cfg.access_log = v;
            }
            commit(&cli.config, cfg, offline, base).await?;
        }
        Command::PrepareConfig { user } => {
            use nix::unistd::{Uid, User, fchown};
            use std::{
                io::Read,
                os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            };
            ensure!(Uid::current().is_root(), "prepare-config requires root");
            let account = User::from_name(&user)?.context("service account missing")?;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&cli.config)?;
            let meta = file.metadata()?;
            ensure!(
                meta.is_file()
                    && meta.nlink() == 1
                    && (meta.uid() == 0 || meta.uid() == account.uid.as_raw()),
                "unsafe configuration file"
            );
            let mut data = Vec::new();
            (&file)
                .take(config::MAX_CONFIG as u64 + 1)
                .read_to_end(&mut data)?;
            Config::parse(&data)?;
            fchown(&file, Some(account.uid), Some(account.gid))?;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            let lockpath = cli.config.with_extension("lock");
            if lockpath.exists() {
                let f = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(lockpath)?;
                let m = f.metadata()?;
                ensure!(
                    m.is_file()
                        && m.nlink() == 1
                        && (m.uid() == 0 || m.uid() == account.uid.as_raw()),
                    "unsafe lock file"
                );
                fchown(&f, Some(account.uid), Some(account.gid))?;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
        }
        Command::Check { file } => {
            let cfg = read_cfg(file.as_ref().unwrap_or(&cli.config))?;
            println!(
                "Valid: {} rules; UDP only accepts routed QUIC",
                cfg.rules.len()
            );
        }
        Command::Init => {
            ensure!(!cli.config.exists(), "configuration already exists");
            let parent = cli.config.parent().context("config parent missing")?;
            let exists = parent.exists();
            std::fs::create_dir_all(parent)?;
            use std::os::unix::fs::PermissionsExt;
            if !exists {
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            }
            control::atomic_config(&cli.config, &Config::default())?;
            println!("Initialized {}", cli.config.display());
        }
        Command::List => {
            let cfg = read_cfg(&cli.config)?;
            println!(
                "{:<5} {:<24} {:<8} {:<32} TARGET",
                "ID", "LISTEN", "PROTO", "DOMAIN"
            );
            for (i, r) in cfg.rules.iter().enumerate() {
                println!(
                    "{:<5} {:<24} {:<8} {:<32} {}",
                    i + 1,
                    r.listen,
                    format!("{:?}", r.protocol),
                    r.domain,
                    r.target
                );
            }
        }
        Command::Status => {
            let r = control::request(
                &cli.config,
                control::Request {
                    action: "status".into(),
                    config: None,
                    base: None,
                },
            )
            .await?;
            ensure!(r.ok, "{}", r.message);
            println!("{}", serde_json::to_string_pretty(&r.data)?);
        }
        Command::Apply { file, offline } => {
            commit(
                &cli.config,
                read_cfg(&file)?,
                offline,
                read_cfg(&cli.config)?,
            )
            .await?
        }
        Command::AddBatch {
            file,
            listen,
            protocol,
            offline,
        } => {
            let p = match protocol.as_str() {
                "both" => Protocol::Both,
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                _ => anyhow::bail!("protocol must be both/tcp/udp"),
            };
            let meta = std::fs::metadata(&file)?;
            ensure!(meta.len() <= config::MAX_CONFIG as u64, "batch too large");
            let added = batch(&std::fs::read_to_string(file)?, listen.as_deref(), p)?;
            let mut cfg = read_cfg(&cli.config)?;
            let base = cfg.clone();
            let n = added.len();
            cfg.rules.extend(added);
            commit(&cli.config, cfg, offline, base).await?;
            println!("Added {n} rules as one transaction.");
        }
        Command::Delete { ids, offline } => {
            let mut cfg = read_cfg(&cli.config)?;
            let base = cfg.clone();
            let ids: std::collections::HashSet<_> = ids.into_iter().collect();
            ensure!(
                ids.iter().all(|i| *i >= 1 && *i <= cfg.rules.len()),
                "rule ID out of range; nothing changed"
            );
            cfg.rules = cfg
                .rules
                .into_iter()
                .enumerate()
                .filter_map(|(i, r)| (!ids.contains(&(i + 1))).then_some(r))
                .collect();
            commit(&cli.config, cfg, offline, base).await?;
            println!("Deleted {} rules as one transaction.", ids.len());
        }
        Command::Serve => {
            let _lock = control::lock(&cli.config)?;
            let cfg = read_cfg(&cli.config)?;
            let mut m = server::Manager::new(cfg.clone())?;
            m.apply(cfg, Some(&cli.config))?;
            let shared = m.shared.clone();
            tokio::spawn(shared.capacity.clone().monitor(shared.shutdown.clone()));
            let m = Arc::new(Mutex::new(m));
            let manager = m.clone();
            let path = cli.config.clone();
            let control = tokio::spawn(async move { control::serve(manager, path).await });
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
            tracing::info!(version=env!("CARGO_PKG_VERSION"),config=%cli.config.display(),"router started");
            tokio::pin!(control);
            loop {
                tokio::select! {
                    r=&mut control=>{shared.shutdown.cancel();r??;return Ok(())},
                    _=tokio::signal::ctrl_c()=>break,
                    _=term.recv()=>break,
                    _=hup.recv()=>{
                        match read_cfg(&cli.config).and_then(|c|m.try_lock().context("configuration busy")?.apply(c,None)){
                            Ok(())=>tracing::info!("configuration reloaded"),
                            Err(e)=>tracing::error!(error=%e,"reload refused; current runtime retained")
                        }
                    }
                }
            }
            shared.shutdown.cancel();
            let _ = control.await?;
            tracing::info!(stats=%shared.status(),"router stopped");
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn batch_is_strict() {
        assert_eq!(
            batch(
                "a.test example.org 443\nb.test 127.0.0.1 8443",
                Some("443"),
                Protocol::Both
            )
            .unwrap()
            .len(),
            2
        );
        assert!(batch("a.test bad:443 8443", Some("443"), Protocol::Both).is_err());
        assert!(batch("443 a.test host 443;id", None, Protocol::Both).is_err());
        assert!(batch("443 a.test ::1 443", None, Protocol::Both).is_ok());
    }
}
