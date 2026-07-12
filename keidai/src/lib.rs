#![no_std]

#[repr(packed)]
#[derive(Copy, Clone)]
pub struct Ipv4Prefix {
    pub prefix_len: u32,
    pub addr: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Ipv4Prefix {}

#[repr(packed)]
#[derive(Copy, Clone)]
pub struct Ipv6Prefix {
    pub prefix_len: u32,
    pub addr: [u8; 16],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Ipv6Prefix {}