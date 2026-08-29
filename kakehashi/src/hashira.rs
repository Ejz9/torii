impl ConnectionEvent {
    pub fn new(ip: IpAddr, method: &str, path: &str, status_code: u16, latency_ms: u32) -> Self {
        let ip_bytes = match ip {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        };
        let mut method_bytes = [0u8; 8];
        let method_len = method.len().min(8);
        method_bytes[..method.len()].copy_from_slice(method.as_bytes()[..method_len]);

        let mut path_bytes = [0u8; 255];
        let path_len = path.len().min(8);
        path_bytes[..path.len()].copy_from_slice(path.as_bytes()[..path_len]);

        Self {
            latency_ms,
            status_code,
            path_len: path_len as u16,
            ip: ip_bytes,
            method: method_bytes,
            method_len: method_len as u8,
            path: path_bytes,
        }
    }
}
