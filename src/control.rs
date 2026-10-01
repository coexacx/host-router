use crate::{
    config::{Config, MAX_CONFIG},
    server::Manager,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Mutex,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub action: String,
    #[serde(default)]
    pub config: Option<Config>,
    #[serde(default)]
    pub base: Option<serde_json::Value>,
}
#[derive(Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}
pub fn socket_path(config: &Path) -> PathBuf {
    config.with_extension("sock")
}
pub fn lock(path: &Path) -> Result<std::fs::File> {
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path.with_extension("lock"))?;
    lock.try_lock()
        .context("another writer/service holds the config lock")?;
    Ok(lock)
}

pub fn atomic_config(path: &Path, cfg: &Config) -> Result<()> {
    let parent = path.parent().context("config parent missing")?;
    let name = path
        .file_name()
        .context("config name missing")?
        .to_string_lossy();
    // O_EXCL and a same-directory temporary file prevent symlink replacement and partial writes.
    let temp = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    let result = (|| -> Result<()> {
        let mut data = serde_json::to_vec_pretty(cfg)?;
        data.push(b'\n');
        file.write_all(&data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)?;
        if let Err(e) = fs::File::open(parent).and_then(|d| d.sync_all()) {
            tracing::warn!(error=%e,"configuration committed; directory sync failed");
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
async fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let n = stream.read_u32().await? as usize;
    ensure!(n <= MAX_CONFIG, "control frame too large");
    let mut bytes = vec![0; n];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
async fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= MAX_CONFIG, "control response too large");
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    Ok(())
}
pub async fn request(path: &Path, req: Request) -> Result<Response> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut stream = UnixStream::connect(socket_path(path)).await?;
        write_frame(&mut stream, &serde_json::to_vec(&req)?).await?;
        let bytes = read_frame(&mut stream).await?;
        Ok(serde_json::from_slice(&bytes)?)
    })
    .await?
}
pub async fn serve(manager: Arc<Mutex<Manager>>, path: PathBuf) -> Result<()> {
    let socket = socket_path(&path);
    if let Ok(meta) = fs::symlink_metadata(&socket) {
        ensure!(
            meta.file_type().is_socket(),
            "control path exists and is not a socket"
        );
        if UnixStream::connect(&socket).await.is_ok() {
            anyhow::bail!("another host-router is running")
        }
        fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let shutdown = manager.lock().await.shared.shutdown.clone();
    let result = async {
        loop {
            let (mut stream, _) =
                tokio::select! {_=shutdown.cancelled()=>break,r=listener.accept()=>r?};
            // The control socket lives in a private config directory and only its owner/root may connect.
            let cred = stream.peer_cred()?;
            let own = fs::metadata(&socket)?;
            use std::os::unix::fs::MetadataExt;
            if cred.uid() != 0 && cred.uid() != own.uid() {
                continue;
            }
            let response = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let data = read_frame(&mut stream).await?;
                let req: Request = serde_json::from_slice(&data)?;
                let mut m = manager.lock().await;
                match req.action.as_str() {
                    "status" => Ok(Response {
                        ok: true,
                        message: "running".into(),
                        data: Some(m.shared.status()),
                    }),
                    "apply" => {
                        let cfg = req.config.context("configuration missing")?;
                        cfg.tables()?;
                        if let Some(base) = req.base {
                            ensure!(
                                base == serde_json::to_value(&m.shared.snapshot().cfg)?,
                                "configuration changed concurrently; reload and retry"
                            );
                        }
                        m.apply(cfg, Some(&path))?;
                        Ok(Response {
                            ok: true,
                            message: "configuration committed".into(),
                            data: None,
                        })
                    }
                    _ => anyhow::bail!("unknown control action"),
                }
            })
            .await;
            let response = match response {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => Response {
                    ok: false,
                    message: format!("{e:#}"),
                    data: None,
                },
                Err(_) => Response {
                    ok: false,
                    message: "control request timed out".into(),
                    data: None,
                },
            };
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                write_frame(&mut stream, &serde_json::to_vec(&response)?),
            )
            .await;
        }
        Ok(())
    }
    .await;
    let _ = fs::remove_file(&socket);
    result
}
