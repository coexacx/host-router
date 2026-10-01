use nix::{
    fcntl::{FcntlArg, OFlag, SpliceFFlags, fcntl, splice},
    unistd::pipe2,
};
use std::{io, net::Shutdown};
use tokio::{io::Interest, net::TcpStream};

async fn direction(src: &TcpStream, dst: &TcpStream) -> io::Result<u64> {
    let (read, write) = pipe2(OFlag::O_NONBLOCK | OFlag::O_CLOEXEC)?;
    // The kernel allocates pages as traffic arrives. Keep the maximum bounded per direction.
    let _ = fcntl(&write, FcntlArg::F_SETPIPE_SZ(64 * 1024));
    let flags = SpliceFFlags::SPLICE_F_MOVE | SpliceFFlags::SPLICE_F_NONBLOCK;
    let mut total = 0;
    let mut enlarged = false;
    loop {
        let received = src
            .async_io(Interest::READABLE, || {
                splice(src, None, &write, None, 1024 * 1024, flags).map_err(io::Error::from)
            })
            .await?;
        if received == 0 {
            socket2::SockRef::from(dst).shutdown(Shutdown::Write)?;
            return Ok(total);
        }
        let mut remaining = received;
        while remaining > 0 {
            let n = dst
                .async_io(Interest::WRITABLE, || {
                    splice(&read, None, dst, None, remaining, flags).map_err(io::Error::from)
                })
                .await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "splice returned zero",
                ));
            }
            remaining -= n;
            total += n as u64;
        }
        if !enlarged && total >= 256 * 1024 {
            let _ = fcntl(&write, FcntlArg::F_SETPIPE_SZ(1024 * 1024));
            enlarged = true;
        }
        // TcpStream readiness awaits already participate in Tokio cooperative scheduling.
    }
}
pub async fn copy(a: &TcpStream, b: &TcpStream) -> io::Result<(u64, u64)> {
    tokio::try_join!(direction(a, b), direction(b, a))
}
