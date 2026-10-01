use anyhow::{Result, bail, ensure};
use tokio::{io::AsyncReadExt, net::TcpStream};
pub const MAX_HELLO: usize = 65536;

#[derive(Debug, PartialEq)]
pub enum Probe {
    Need,
    Name(String),
    NoName,
}
fn u16be(b: &[u8]) -> usize {
    usize::from(u16::from_be_bytes([b[0], b[1]]))
}
fn take<'a>(b: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    ensure!(b.len() >= n, "truncated ClientHello");
    let (a, c) = b.split_at(n);
    *b = c;
    Ok(a)
}
pub fn hello(b: &[u8]) -> Result<Probe> {
    if b.len() < 4 {
        return Ok(Probe::Need);
    }
    ensure!(b[0] == 1, "not a ClientHello");
    let len = ((b[1] as usize) << 16) | ((b[2] as usize) << 8) | b[3] as usize;
    ensure!(
        (38..=MAX_HELLO - 4).contains(&len),
        "invalid ClientHello size"
    );
    if b.len() < 4 + len {
        return Ok(Probe::Need);
    }
    let mut b = &b[4..4 + len];
    take(&mut b, 34)?;
    let n = take(&mut b, 1)?[0] as usize;
    ensure!(n <= 32, "invalid session ID");
    take(&mut b, n)?;
    let n = u16be(take(&mut b, 2)?);
    ensure!(n >= 2 && n.is_multiple_of(2), "invalid cipher list");
    take(&mut b, n)?;
    let n = take(&mut b, 1)?[0] as usize;
    ensure!(n > 0, "invalid compression list");
    take(&mut b, n)?;
    if b.is_empty() {
        return Ok(Probe::NoName);
    }
    let n = u16be(take(&mut b, 2)?);
    ensure!(n == b.len(), "invalid extension length");
    let mut name = None;
    while !b.is_empty() {
        let typ = u16be(take(&mut b, 2)?);
        let n = u16be(take(&mut b, 2)?);
        let mut e = take(&mut b, n)?;
        if typ != 0 {
            continue;
        }
        ensure!(name.is_none(), "duplicate SNI extension");
        let n = u16be(take(&mut e, 2)?);
        ensure!(n == e.len(), "invalid SNI list");
        while !e.is_empty() {
            let t = take(&mut e, 1)?[0];
            let n = u16be(take(&mut e, 2)?);
            let raw = take(&mut e, n)?;
            if t == 0 {
                ensure!(name.is_none(), "duplicate SNI hostname");
                name = Some(crate::config::domain(std::str::from_utf8(raw)?, false)?);
            }
        }
    }
    Ok(name.map(Probe::Name).unwrap_or(Probe::NoName))
}
pub fn tcp_probe(b: &[u8]) -> Result<Probe> {
    if b.is_empty() {
        return Ok(Probe::Need);
    }
    if b[0] == 22 {
        let mut pos = 0;
        let mut h = Vec::new();
        loop {
            if b.len() < pos + 5 {
                return Ok(Probe::Need);
            }
            ensure!(
                b[pos] == 22 && b[pos + 1] == 3,
                "invalid TLS handshake record"
            );
            let n = u16be(&b[pos + 3..pos + 5]);
            ensure!(n > 0 && n <= 18432, "invalid TLS record size");
            ensure!(pos + 5 + n <= MAX_HELLO, "TLS handshake too large");
            if b.len() < pos + 5 + n {
                return Ok(Probe::Need);
            }
            h.extend_from_slice(&b[pos + 5..pos + 5 + n]);
            pos += 5 + n;
            match hello(&h)? {
                Probe::Need => {}
                p => return Ok(p),
            }
        }
    }
    // Detect non-HTTP protocols promptly; a default rule can relay them unchanged.
    let prefix = &b[..b.len().min(16)];
    if prefix
        .iter()
        .any(|c| !c.is_ascii() || (*c < 32 && *c != b'\r' && *c != b'\n' && *c != b'\t'))
    {
        return Ok(Probe::NoName);
    }
    let Some(end) = b.windows(4).position(|w| w == b"\r\n\r\n") else {
        if b.len() >= MAX_HELLO {
            bail!("HTTP headers too large")
        }
        if b.len() >= 16 && !prefix.contains(&b' ') {
            return Ok(Probe::NoName);
        }
        return Ok(Probe::Need);
    };
    let text = std::str::from_utf8(&b[..end])?;
    let mut lines = text.split("\r\n");
    let request = lines.next().unwrap_or("");
    if !request
        .split_ascii_whitespace()
        .last()
        .unwrap_or("")
        .starts_with("HTTP/1.")
    {
        return Ok(Probe::NoName);
    }
    let mut host = None;
    for l in lines {
        ensure!(
            !l.starts_with([' ', '\t']),
            "folded HTTP header unsupported"
        );
        let Some((k, v)) = l.split_once(':') else {
            bail!("invalid HTTP header")
        };
        if k.eq_ignore_ascii_case("host") {
            ensure!(host.is_none(), "duplicate Host header");
            let v = v.trim();
            let h = if v.starts_with('[') {
                let a: std::net::SocketAddr = v.parse()?;
                a.ip().to_string()
            } else if let Some((h, p)) = v.rsplit_once(':') {
                crate::config::port(p)?;
                h.into()
            } else {
                v.into()
            };
            host = Some(crate::config::domain(&h, false)?);
        }
    }
    Ok(host.map(Probe::Name).unwrap_or(Probe::NoName))
}
pub async fn tcp(stream: &mut TcpStream, names: bool) -> Result<(Option<String>, Vec<u8>)> {
    if !names {
        return Ok((None, vec![]));
    }
    let mut bytes = Vec::with_capacity(2048);
    let mut buf = [0u8; 2048];
    loop {
        match tcp_probe(&bytes)? {
            Probe::Name(h) => return Ok((Some(h), bytes)),
            Probe::NoName => return Ok((None, bytes)),
            Probe::Need => {}
        }
        ensure!(bytes.len() < MAX_HELLO, "sniff buffer exceeded");
        let want = buf.len().min(MAX_HELLO - bytes.len());
        let n = stream.read(&mut buf[..want]).await?;
        ensure!(n > 0, "peer closed before routing");
        bytes.extend_from_slice(&buf[..n]);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn http() {
        assert_eq!(
            tcp_probe(b"GET / HTTP/1.1\r\nHost: EXAMPLE.COM:443\r\n\r\n").unwrap(),
            Probe::Name("example.com".into())
        );
        assert!(tcp_probe(b"GET / HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\n\r\n").is_err());
        assert_eq!(tcp_probe(b"GET / HTTP/1.1\r\n").unwrap(), Probe::Need);
        assert_eq!(tcp_probe(&[0, 1, 2]).unwrap(), Probe::NoName);
    }
    #[test]
    fn malformed_never_panics() {
        let mut x = 1u64;
        for n in 0..2048 {
            let b: Vec<u8> = (0..n % 512)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x as u8
                })
                .collect();
            let _ = hello(&b);
            let _ = tcp_probe(&b);
        }
    }
}
