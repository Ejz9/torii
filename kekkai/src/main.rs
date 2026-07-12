#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{lpm_trie::{LpmTrie, Key}, LruHashMap, PerCpuArray},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use keidai::{Ipv4Prefix, Ipv6Prefix};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpError, IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[map]
static CROWDSEC_V4: LpmTrie<u32, u8> = LpmTrie::with_max_entries(250_000, 0);
#[map]
static CROWDSEC_V6: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(250_000, 0);

#[map]
static BLOCKLIST_V4: LruHashMap<u32, u8> = LruHashMap::with_max_entries(125_000, 0);
#[map]
static BLOCKLIST_V6: LruHashMap<[u8; 16], u8> = LruHashMap::with_max_entries(125_000, 0);
#[map]
static BLOCKLIST_V4_PREFIX: LpmTrie<u32, u8> = LpmTrie::with_max_entries(125_000, 0);
#[map]
static BLOCKLIST_V6_PREFIX: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(125_000, 0);

#[map]
static METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);

#[xdp]
pub fn kekkai(ctx: XdpContext) -> u32 {
    match try_kekkai(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[inline(always)]
fn record_metric(index: u32) {
    if let Some(metric) = { METRICS.get_ptr_mut(index) } {
        unsafe { *metric += 1 }
    }
}

fn block_ipv4(address: u32) -> bool {
    unsafe { BLOCKLIST_V4.get(&address).is_some() }
}
fn block_ipv4_prefix(address: u32) -> bool {
    let key = Key::new(32, address);
    unsafe { BLOCKLIST_V4_PREFIX.get(&key).is_some() || CROWDSEC_V4.get(&key).is_some() }
}
fn block_ipv6(address: &[u8; 16]) -> bool {
    unsafe { BLOCKLIST_V6.get(address).is_some() }
}
fn block_ipv6_prefix(address: &[u8; 16]) -> bool {
    let key = Key::new(128, *address);
    unsafe { BLOCKLIST_V6_PREFIX.get(&key).is_some() || CROWDSEC_V6.get(&key).is_some() }
}

fn try_kekkai(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {
            let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });
            let action = if block_ipv4(source_addr) || block_ipv4_prefix(source_addr) {
                info!(&ctx, "XDP_DROP: {:i}", source_addr);
                record_metric(1);
                xdp_action::XDP_DROP
            } else {
                record_metric(0);
                xdp_action::XDP_PASS
            };
            let proto =
                unsafe { (*ipv4hdr).proto() }.map_err(|IpError::InvalidProto(_proto)| ())?;
            let _source_port = match proto {
                IpProto::Tcp => {
                    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    u16::from_be_bytes(unsafe { (*tcphdr).source })
                }
                IpProto::Udp => {
                    let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    unsafe { (*udphdr).src_port() }
                }
                _ => return Err(()),
            };
            Ok(action)
        }
        Ok(EtherType::Ipv6) => {
            let ipv6hdr: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            let source_addr = unsafe { (*ipv6hdr).src_addr };
            let action = if block_ipv6(&source_addr) || block_ipv6_prefix(&source_addr) {
                info!(&ctx, "XDP_DROP: {:i}", source_addr);
                record_metric(1);
                xdp_action::XDP_DROP
            } else {
                record_metric(0);
                xdp_action::XDP_PASS
            };
            Ok(action)
        }
        _ => return Ok(xdp_action::XDP_PASS),
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
