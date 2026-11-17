//! Socket options that the `socket2` crate does not expose. Linux only; the
//! functions are no-ops elsewhere.

use std::io;

#[cfg(target_os = "linux")]
fn set_u32(
    fd: std::os::fd::RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: u32,
) -> io::Result<()> {
    // SAFETY: `fd` is an open socket borrowed from a live object for the
    // duration of the call, and the option value is a properly sized and
    // aligned u32 that outlives it.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            std::ptr::from_ref(&value).cast(),
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Caps the rate at which the kernel sends on this socket, in bytes per
/// second (`SO_MAX_PACING_RATE`). `None` removes the cap.
pub fn set_max_pacing_rate<S>(socket: &S, bytes_per_sec: Option<u32>) -> io::Result<()>
where
    S: SocketFd,
{
    #[cfg(target_os = "linux")]
    {
        // The kernel treats the all-ones value as "unlimited".
        set_u32(
            socket.raw(),
            libc::SOL_SOCKET,
            libc::SO_MAX_PACING_RATE,
            bytes_per_sec.unwrap_or(u32::MAX),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (socket, bytes_per_sec);
        Ok(())
    }
}

/// Lets a socket be bound to a source address without reserving a port yet
/// (`IP_BIND_ADDRESS_NO_PORT`). The port is then chosen at connect time, when
/// the destination is known, so one source address is not limited to one
/// ephemeral port range's worth of connections in total.
pub fn set_bind_address_no_port<S>(socket: &S) -> io::Result<()>
where
    S: SocketFd,
{
    #[cfg(target_os = "linux")]
    {
        set_u32(
            socket.raw(),
            libc::IPPROTO_IP,
            libc::IP_BIND_ADDRESS_NO_PORT,
            1,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = socket;
        Ok(())
    }
}

/// A socket that can lend its descriptor.
pub trait SocketFd {
    #[cfg(unix)]
    fn raw(&self) -> std::os::fd::RawFd;
}

#[cfg(unix)]
impl<T: std::os::fd::AsRawFd> SocketFd for T {
    fn raw(&self) -> std::os::fd::RawFd {
        self.as_raw_fd()
    }
}

#[cfg(not(unix))]
impl<T> SocketFd for T {}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn get_u32(fd: i32, level: libc::c_int, name: libc::c_int) -> u32 {
        let mut value: u32 = 0;
        let mut len = std::mem::size_of::<u32>() as libc::socklen_t;
        // SAFETY: `value` and `len` are valid for writes and sized for a u32.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                level,
                name,
                std::ptr::from_mut(&mut value).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
        value
    }

    #[test]
    fn pacing_rate_is_applied_and_removed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let fd = stream.as_raw_fd();

        set_max_pacing_rate(&stream, Some(375_000)).unwrap();
        assert_eq!(
            get_u32(fd, libc::SOL_SOCKET, libc::SO_MAX_PACING_RATE),
            375_000
        );
        set_max_pacing_rate(&stream, None).unwrap();
        assert_eq!(
            get_u32(fd, libc::SOL_SOCKET, libc::SO_MAX_PACING_RATE),
            u32::MAX
        );
    }

    #[test]
    fn bind_address_no_port_is_applied() {
        let socket =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        let fd = socket.as_raw_fd();
        assert_eq!(
            get_u32(fd, libc::IPPROTO_IP, libc::IP_BIND_ADDRESS_NO_PORT),
            0
        );
        set_bind_address_no_port(&socket).unwrap();
        assert_eq!(
            get_u32(fd, libc::IPPROTO_IP, libc::IP_BIND_ADDRESS_NO_PORT),
            1
        );
    }

    #[test]
    fn errors_are_reported() {
        // A regular file is not a socket.
        let file = std::fs::File::open("/proc/self/status").unwrap();
        assert!(set_max_pacing_rate(&file, Some(1)).is_err());
    }
}
