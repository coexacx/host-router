use anyhow::{Result, ensure};
use quinn_udp::{RecvMeta, Transmit, UdpSocketState};
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use std::{
    io::{self, IoSliceMut},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{Interest, unix::AsyncFd},
    net::{TcpListener, TcpStream},
};

// Covers 64 ordinary-MTU GRO datagrams while keeping per-flow memory bounded.
pub const UDP_RECV_BYTES: usize = 128 * 1024;

pub fn tcp_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let s = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    s.set_reuse_address(true)?;
    s.set_nonblocking(true)?;
    if addr.is_ipv6() {
        s.set_only_v6(true)?
    }
    s.bind(&addr.into())?;
    s.listen(1024)?;
    TcpListener::from_std(s.into())
}
pub fn tune_tcp(s: &TcpStream) -> io::Result<()> {
    s.set_nodelay(true)?;
    socket2::SockRef::from(s).set_tcp_keepalive(
        &TcpKeepalive::new()
            .with_time(Duration::from_secs(30))
            .with_interval(Duration::from_secs(10))
            .with_retries(3),
    )
}
pub fn normalize(a: SocketAddr) -> SocketAddr {
    match a {
        SocketAddr::V6(v) if v.ip().to_ipv4_mapped().is_some() => {
            SocketAddr::new(v.ip().to_ipv4_mapped().unwrap().into(), v.port())
        }
        _ => a,
    }
}

pub struct FrontUdp {
    io: AsyncFd<std::net::UdpSocket>,
    state: UdpSocketState,
    pub addr: SocketAddr,
    peer: Option<SocketAddr>,
}
impl FrontUdp {
    pub fn bind(addr: SocketAddr) -> io::Result<Arc<Self>> {
        Self::open(addr, None)
    }
    fn open(addr: SocketAddr, peer: Option<SocketAddr>) -> io::Result<Arc<Self>> {
        let s = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        s.set_nonblocking(true)?;
        if addr.is_ipv6() {
            s.set_only_v6(true)?
        }
        s.set_recv_buffer_size(1024 * 1024)?;
        s.set_send_buffer_size(1024 * 1024)?;
        s.bind(&addr.into())?;
        if let Some(peer) = peer {
            s.connect(&peer.into())?;
        }
        let socket: std::net::UdpSocket = s.into();
        let state = UdpSocketState::new((&socket).into())?;
        Ok(Arc::new(Self {
            addr: socket.local_addr()?,
            io: AsyncFd::new(socket)?,
            state,
            peer,
        }))
    }
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<RecvMeta> {
        loop {
            let meta = self
                .io
                .async_io(Interest::READABLE, |socket| {
                    let mut meta = [RecvMeta::default()];
                    let n =
                        self.state
                            .recv(socket.into(), &mut [IoSliceMut::new(buf)], &mut meta)?;
                    if n == 0 {
                        return Err(io::Error::from(io::ErrorKind::WouldBlock));
                    }
                    Ok(meta[0])
                })
                .await?;
            // recvmmsg may truncate an unusually large GRO aggregate. Never forward
            // a truncated tail as a valid datagram; QUIC will retransmit dropped data.
            if meta.len < buf.len() {
                return Ok(meta);
            }
            tokio::task::yield_now().await;
        }
    }
    async fn transmit(
        &self,
        peer: SocketAddr,
        local: Option<IpAddr>,
        bytes: &[u8],
        segment: Option<usize>,
    ) -> io::Result<()> {
        self.io
            .async_io(Interest::WRITABLE, |socket| {
                self.state.try_send(
                    socket.into(),
                    &Transmit {
                        destination: peer,
                        ecn: None,
                        contents: bytes,
                        segment_size: segment,
                        src_ip: local,
                    },
                )
            })
            .await
    }
    async fn send_segments(
        &self,
        peer: SocketAddr,
        local: Option<IpAddr>,
        bytes: &[u8],
        stride: usize,
    ) -> io::Result<()> {
        let stride = stride.max(1);
        let max_segments = self.state.max_gso_segments().max(1);
        // Linux GSO is limited both by segment count and the maximum UDP payload.
        let batch = max_segments.min((65507 / stride).max(1)) * stride;
        for chunk in bytes.chunks(batch) {
            if chunk.len() <= stride {
                self.transmit(peer, local, chunk, None).await?;
            } else if self
                .transmit(peer, local, chunk, Some(stride))
                .await
                .is_err()
            {
                // Old kernels / interfaces may not support GSO. Retain exact datagram
                // boundaries and fall back without requiring any system-wide tuning.
                for datagram in chunk.chunks(stride) {
                    self.transmit(peer, local, datagram, None).await?;
                }
            }
        }
        Ok(())
    }
    pub async fn send(
        &self,
        peer: SocketAddr,
        local: IpAddr,
        bytes: &[u8],
        stride: usize,
    ) -> io::Result<()> {
        self.send_segments(peer, Some(local), bytes, stride).await
    }
    pub async fn send_upstream(&self, bytes: &[u8], stride: usize) -> io::Result<()> {
        let peer = self
            .peer
            .ok_or_else(|| io::Error::other("unconnected UDP socket"))?;
        self.send_segments(peer, None, bytes, stride).await
    }
}

pub async fn udp_connect(addr: SocketAddr) -> Result<Arc<FrontUdp>> {
    ensure!(
        !addr.ip().is_multicast() && !addr.ip().is_unspecified(),
        "invalid target"
    );
    let local = SocketAddr::new(
        if addr.is_ipv4() {
            std::net::Ipv4Addr::UNSPECIFIED.into()
        } else {
            std::net::Ipv6Addr::UNSPECIFIED.into()
        },
        0,
    );
    Ok(FrontUdp::open(local, Some(addr))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn batched_datagrams_keep_boundaries_and_content() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let receiver = tokio::net::UdpSocket::bind(bind).await.unwrap();
            let sender = udp_connect(receiver.local_addr().unwrap()).await.unwrap();
            // Exceeds a GSO batch and ends in a short datagram.
            let stride = 1232;
            let mut payload = vec![0; stride * 97 + 317];
            for (index, chunk) in payload.chunks_mut(stride).enumerate() {
                chunk.fill(index as u8);
            }
            let sent = payload.clone();
            let task = tokio::spawn(async move {
                sender.send_upstream(&sent, stride).await.unwrap();
            });
            let mut buf = vec![0; 65536];
            for expected in payload.chunks(stride) {
                let n = tokio::time::timeout(Duration::from_secs(2), receiver.recv(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&buf[..n], expected);
            }
            task.await.unwrap();
        }
    }
}
