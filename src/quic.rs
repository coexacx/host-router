use crate::sniff::{self, MAX_HELLO, Probe};
use anyhow::{Result, bail, ensure};
use rustls::{Side, quic::Version};

#[derive(Debug)]
pub struct Header<'a> {
    pub version: u32,
    pub dcid: &'a [u8],
    pub scid: &'a [u8],
    pub initial: bool,
    pub offset: usize,
}
pub fn header(b: &[u8]) -> Option<Header<'_>> {
    if b.len() < 7 || b[0] & 0x80 == 0 {
        return None;
    }
    let v = u32::from_be_bytes(b[1..5].try_into().ok()?);
    let n = b[5] as usize;
    if n > 20 || b.len() < 7 + n {
        return None;
    }
    let dcid = &b[6..6 + n];
    let m = b[6 + n] as usize;
    if m > 20 || b.len() < 7 + n + m {
        return None;
    }
    let typ = (b[0] >> 4) & 3;
    Some(Header {
        version: v,
        dcid,
        scid: &b[7 + n..7 + n + m],
        initial: (v == 1 && typ == 0) || (v == 0x6b3343cf && typ == 1),
        offset: 7 + n + m,
    })
}
fn vi(b: &[u8], p: &mut usize) -> Result<u64> {
    ensure!(*p < b.len(), "missing QUIC varint");
    let n = 1usize << (b[*p] >> 6);
    ensure!(b.len() - *p >= n, "truncated QUIC varint");
    let mut v = (b[*p] & 63) as u64;
    for c in &b[*p + 1..*p + n] {
        v = (v << 8) | u64::from(*c)
    }
    *p += n;
    Ok(v)
}
fn packet_number(truncated: u64, bytes: usize, largest: Option<u64>) -> u64 {
    let expected = largest.map_or(0, |n| n + 1);
    let win = 1u64 << (bytes * 8);
    let half = win / 2;
    let candidate = (expected & !(win - 1)) | truncated;
    if candidate + half <= expected && candidate < (1 << 62) - win {
        candidate + win
    } else if candidate > expected + half && candidate >= win {
        candidate - win
    } else {
        candidate
    }
}

pub struct Initial {
    dcid: Vec<u8>,
    version: u32,
    largest: Option<u64>,
    data: Vec<u8>,
    present: Vec<bool>,
    contiguous: usize,
}
impl Initial {
    pub fn new(b: &[u8]) -> Result<Self> {
        let h = header(b).ok_or_else(|| anyhow::anyhow!("invalid QUIC long header"))?;
        ensure!(
            h.initial && !h.dcid.is_empty(),
            "supported QUIC Initial required"
        );
        Ok(Self {
            dcid: h.dcid.to_vec(),
            version: h.version,
            largest: None,
            data: vec![],
            present: vec![],
            contiguous: 0,
        })
    }
    pub fn feed(&mut self, datagram: &[u8]) -> Result<Probe> {
        ensure!(
            datagram.len() >= 1200,
            "QUIC client Initial datagram smaller than 1200"
        );
        let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap()
            .quic_suite()
            .unwrap();
        let version = if self.version == 1 {
            Version::V1
        } else {
            Version::V2
        };
        let keys = suite.keys(&self.dcid, Side::Server, version);
        let mut start = 0;
        let mut count = 0;
        while start < datagram.len() {
            let b = &datagram[start..];
            let Some(h) = header(b) else { break };
            if !h.initial {
                break;
            }
            ensure!(
                h.version == self.version && h.dcid == self.dcid,
                "Initial identity changed"
            );
            count += 1;
            ensure!(count <= 16, "too many coalesced Initial packets");
            let mut pos = h.offset;
            let token = usize::try_from(vi(b, &mut pos)?)?;
            ensure!(token <= b.len() - pos, "truncated Initial token");
            pos += token;
            let len = usize::try_from(vi(b, &mut pos)?)?;
            ensure!(
                len <= b.len() - pos && len >= 20,
                "invalid Initial packet length"
            );
            let end = pos + len;
            ensure!(pos + 20 <= end, "Initial header protection sample missing");
            let mut first = b[0];
            let mut pn: [u8; 4] = b[pos..pos + 4].try_into()?;
            keys.remote
                .header
                .decrypt_in_place(&b[pos + 4..pos + 20], &mut first, &mut pn)?;
            ensure!(first & 0x0c == 0, "nonzero QUIC reserved bits");
            let n = (first as usize & 3) + 1;
            let mut head = b[..pos + n].to_vec();
            head[0] = first;
            head[pos..].copy_from_slice(&pn[..n]);
            let tr = pn[..n].iter().fold(0u64, |a, c| (a << 8) | u64::from(*c));
            let num = packet_number(tr, n, self.largest);
            let mut cipher = b[pos + n..end].to_vec();
            let plain = keys
                .remote
                .packet
                .decrypt_in_place(num, &head, &mut cipher)?;
            self.largest = Some(self.largest.map_or(num, |v| v.max(num)));
            self.frames(plain)?;
            match sniff::hello(&self.data[..self.contiguous])? {
                Probe::Need => {}
                p => return Ok(p),
            }
            start += end;
        }
        Ok(Probe::Need)
    }
    fn frames(&mut self, b: &[u8]) -> Result<()> {
        let mut p = 0;
        while p < b.len() {
            match vi(b, &mut p)? {
                0 => {
                    while p < b.len() && b[p] == 0 {
                        p += 1
                    }
                }
                1 => {}
                t @ (2 | 3) => {
                    vi(b, &mut p)?;
                    vi(b, &mut p)?;
                    let n = vi(b, &mut p)?;
                    ensure!(n <= 256, "too many ACK ranges");
                    vi(b, &mut p)?;
                    for _ in 0..n {
                        vi(b, &mut p)?;
                        vi(b, &mut p)?;
                    }
                    if t == 3 {
                        for _ in 0..3 {
                            vi(b, &mut p)?;
                        }
                    }
                }
                6 => {
                    let off = usize::try_from(vi(b, &mut p)?)?;
                    let n = usize::try_from(vi(b, &mut p)?)?;
                    ensure!(
                        off <= MAX_HELLO && n <= MAX_HELLO - off && n <= b.len() - p,
                        "CRYPTO exceeds bounds"
                    );
                    let end = off + n;
                    if end > self.data.len() {
                        self.data.resize(end, 0);
                        self.present.resize(end, false)
                    }
                    for (i, c) in b[p..p + n].iter().enumerate() {
                        let j = off + i;
                        ensure!(
                            !self.present[j] || self.data[j] == *c,
                            "conflicting CRYPTO retransmission"
                        );
                        self.data[j] = *c;
                        self.present[j] = true;
                    }
                    p += n;
                    while self.contiguous < self.present.len() && self.present[self.contiguous] {
                        self.contiguous += 1
                    }
                }
                _ => bail!("unsupported frame in Initial"),
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn greased_quic_bit_long_headers() {
        let plain = [0xc0, 0, 0, 0, 1, 1, 7, 1, 9];
        let mut greased = plain;
        greased[0] &= !0x40;
        let a = header(&plain).unwrap();
        let b = header(&greased).unwrap();
        assert!(a.initial && b.initial);
        assert_eq!(a.dcid, b.dcid);
        assert_eq!(a.scid, b.scid);
    }
    #[test]
    fn frame_bounds_and_overlaps() {
        let mut a = Initial {
            dcid: vec![],
            version: 1,
            largest: None,
            data: vec![],
            present: vec![],
            contiguous: 0,
        };
        a.frames(&[6, 2, 2, 3, 4]).unwrap();
        assert_eq!(a.contiguous, 0);
        a.frames(&[6, 0, 3, 1, 2, 3]).unwrap();
        assert_eq!(a.contiguous, 4);
        assert!(a.frames(&[6, 2, 1, 5]).is_err());
        assert!(a.frames(&[6, 0x80, 1, 0, 0, 1, 0]).is_err());
    }
    #[test]
    fn packet_numbers() {
        assert_eq!(packet_number(0, 1, None), 0);
        assert_eq!(packet_number(1, 1, Some(255)), 257);
        assert_eq!(packet_number(254, 1, Some(256)), 254);
    }
    #[test]
    fn random_datagrams_do_not_panic() {
        let mut seed = 0xabcdeu64;
        for n in 0..4000 {
            let b: Vec<u8> = (0..n % 1500)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    seed as u8
                })
                .collect();
            let _ = header(&b);
            if let Ok(mut a) = Initial::new(&b) {
                let _ = a.feed(&b);
            }
        }
    }
}
