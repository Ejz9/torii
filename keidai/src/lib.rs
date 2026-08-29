use std::net::{IpAddr, Ipv6Addr};

use linux_futex::{Futex, Shared};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(C)]
#[derive(Copy, Clone, Debug, IntoBytes, FromBytes, Immutable, KnownLayout)]
pub struct ConnectionEvent {
    pub latency_ms: u32,
    pub status_code: u16,
    pub path_len: u16,
    pub ip: [u8; 16],
    pub method: [u8; 8],
    pub method_len: u8,
    pub path: [u8; 255],
}

impl ConnectionEvent {
    pub fn path_str(&self) -> &str {
        std::str::from_utf8(&self.path[..self.path_len as usize]).unwrap_or("<invalid-utf8>")
    }

    pub fn method_str(&self) -> &str {
        std::str::from_utf8(&self.method[..self.method_len as usize]).unwrap_or("")
    }

    pub fn ip_addr(&self) -> IpAddr {
        let v6 = Ipv6Addr::from(self.ip);
        if let Some(v4) = v6.to_ipv4_mapped() {
            IpAddr::V4(v4)
        } else {
            IpAddr::V6(v6)
        }
    }
}

#[repr(C)]
pub struct BufferHeader {
    pub write_head: Futex<Shared>,
    pub read_head: Futex<Shared>,
}
