use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let addr: SocketAddr = args.get(2).context("address")?.parse()?;
    let cert = CertificateDer::from(std::fs::read(args.get(3).context("certificate")?)?);
    if args[1] == "server" {
        let key = PrivatePkcs8KeyDer::from(std::fs::read(args.get(4).context("key")?)?);
        let mut config = quinn::ServerConfig::with_single_cert(vec![cert], key.into())?;
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_concurrent_uni_streams(0u8.into())
            .stream_receive_window((16u32 * 1024 * 1024).into())
            .receive_window((64u32 * 1024 * 1024).into());
        config.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::server(config, addr)?;
        let payload: Arc<[u8]> = std::fs::read(args.get(5).context("payload file")?)?.into();
        println!("READY");
        while let Some(incoming) = endpoint.accept().await {
            let payload = payload.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let payload = payload.clone();
                    tokio::spawn(async move {
                        let mut request = [0u8; 9];
                        if recv.read_exact(&mut request).await.is_err() {
                            return;
                        }
                        let len = u64::from_be_bytes(request[1..].try_into().unwrap())
                            .min(64 * 1024 * 1024) as usize;
                        if request[0] == 1 {
                            let mut got = 0usize;
                            let mut buffer = vec![0u8; 65536];
                            loop {
                                match recv.read(&mut buffer).await {
                                    Ok(Some(n)) => got += n,
                                    Ok(None) => break,
                                    Err(_) => return,
                                }
                            }
                            if got != len {
                                return;
                            }
                            if send.write_all(&(got as u64).to_be_bytes()).await.is_err() {
                                return;
                            }
                            let _ = send.finish();
                            return;
                        }
                        let mut remaining = len;
                        while remaining > 0 {
                            let n = remaining.min(payload.len());
                            if send.write_all(&payload[..n]).await.is_err() {
                                return;
                            }
                            remaining -= n;
                        }
                        let _ = send.finish();
                    });
                }
            });
        }
    } else {
        let count: usize = args.get(4).context("concurrency")?.parse()?;
        let seconds: f64 = args.get(5).context("seconds")?.parse()?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert)?;
        let mut config = quinn::ClientConfig::with_root_certificates(Arc::new(roots))?;
        let mut transport = quinn::TransportConfig::default();
        transport
            .stream_receive_window((16u32 * 1024 * 1024).into())
            .receive_window((64u32 * 1024 * 1024).into());
        config.transport_config(Arc::new(transport));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        endpoint.set_default_client_config(config);
        let upload = args.get(6).is_some_and(|s| s == "upload");
        let payload: Arc<[u8]> = if upload {
            std::fs::read(args.get(7).context("upload payload")?)?.into()
        } else {
            Arc::from([])
        };
        let start = Instant::now();
        let deadline = start + Duration::from_secs_f64(seconds);
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..count {
            let connecting = endpoint.connect(addr, "a.test")?;
            let payload = payload.clone();
            tasks.spawn(async move {
                let conn = connecting.await?;
                let mut bytes = 0u64;
                let mut transfers = 0;
                let mut buffer = vec![0u8; 65536];
                while Instant::now() < deadline {
                    let (mut send, mut recv) = conn.open_bi().await?;
                    let amount = 8u64 * 1024 * 1024;
                    let mut request = vec![u8::from(upload)];
                    request.extend_from_slice(&amount.to_be_bytes());
                    send.write_all(&request).await?;
                    if upload {
                        let mut remaining = amount as usize;
                        while remaining > 0 {
                            let n = remaining.min(payload.len());
                            send.write_all(&payload[..n]).await?;
                            remaining -= n;
                        }
                        send.finish()?;
                        let mut response = [0u8; 8];
                        recv.read_exact(&mut response).await?;
                        anyhow::ensure!(
                            u64::from_be_bytes(response) == amount,
                            "incomplete upload"
                        );
                    } else {
                        send.finish()?;
                        let mut got = 0;
                        while let Some(n) = recv.read(&mut buffer).await? {
                            got += n as u64
                        }
                        anyhow::ensure!(got == amount, "truncated stream");
                    }
                    bytes += amount;
                    transfers += 1;
                }
                conn.close(0u8.into(), b"done");
                Ok::<_, anyhow::Error>((bytes, transfers))
            });
        }
        let mut bytes = 0;
        let mut transfers = 0;
        let mut errors = 0;
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok((b, n))) => {
                    bytes += b;
                    transfers += n
                }
                other => {
                    errors += 1;
                    eprintln!("{other:?}");
                }
            }
        }
        let elapsed = start.elapsed().as_secs_f64();
        println!(
            "{}",
            serde_json::json!({"bytes":bytes,"transfers":transfers,"errors":errors,"seconds":elapsed,"gbps":bytes as f64*8.0/elapsed/1e9})
        );
        endpoint.wait_idle().await;
    }
    Ok(())
}
