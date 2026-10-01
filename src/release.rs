use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{collections::BTreeMap, path::Path};
const PUBLIC_KEY: &str = "6fdb995c777fe2483e1e74f4490046d339bf0a6a1c24c3193d8b85ca4bbe321d";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: String,
    assets: BTreeMap<String, Asset>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Asset {
    sha256: String,
    url: String,
}
fn hex(s: &str) -> Result<Vec<u8>> {
    ensure!(s.len().is_multiple_of(2), "invalid hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).context("invalid hex"))
        .collect()
}
fn version(s: &str) -> Result<(u32, u32, u32)> {
    ensure!(
        s.len() <= 32 && s.bytes().all(|b| b.is_ascii_digit() || b == b'.'),
        "invalid release version"
    );
    let v = s
        .split('.')
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(v.len() == 3, "expected stable semantic version");
    Ok((v[0], v[1], v[2]))
}
pub fn verify(manifest: &Path, signature: &Path, asset: &str) -> Result<()> {
    ensure!(
        std::fs::metadata(manifest)?.len() <= 65536,
        "manifest too large"
    );
    ensure!(
        std::fs::metadata(signature)?.len() == 64,
        "invalid signature size"
    );
    let data = std::fs::read(manifest)?;
    let sig = std::fs::read(signature)?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, hex(PUBLIC_KEY)?)
        .verify(&data, &sig)
        .map_err(|_| anyhow::anyhow!("release signature verification failed"))?;
    let m: Manifest = serde_json::from_slice(&data)?;
    let remote = version(&m.version)?;
    let current = version(env!("CARGO_PKG_VERSION"))?;
    ensure!(
        [
            "hostip.sh",
            "host-router-linux-amd64",
            "host-router-linux-arm64",
            "host-router-source.tar.gz"
        ]
        .contains(&asset),
        "unsupported asset"
    );
    let a = m.assets.get(asset).context("release asset missing")?;
    ensure!(
        a.sha256.len() == 64 && a.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid asset digest"
    );
    ensure!(
        a.url
            == format!(
                "https://github.com/coexacx/host-router/releases/download/v{}/{asset}",
                m.version
            ),
        "untrusted release URL"
    );
    let status = if remote > current {
        "new"
    } else if remote == current {
        "current"
    } else {
        "older"
    };
    println!("{status}\t{}\t{}\t{}", m.version, a.sha256, a.url);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_versions() {
        assert!(version("0.1.0;cmd").is_err());
        assert!(version("v0.1.0").is_err());
        assert_eq!(version("2.12.3").unwrap(), (2, 12, 3));
    }
}
