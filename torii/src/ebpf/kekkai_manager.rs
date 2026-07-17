use std::{
    collections::HashSet,
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
};

use tracing::{error, info};

pub enum EbpfEntry {
    InsertIpv4(u32),
    DeleteIpv4(u32),
    InsertIpv6Addr([u8; 16]),
    DeleteIpv6Addr([u8; 16]),
    InsertBulkIpv4Prefix(HashSet<Ipv4Prefix>),
    DeleteBulkIpv4Prefix(HashSet<Ipv4Prefix>),
    InsertBulkIpv6Prefix(HashSet<Ipv6Prefix>),
    DeleteBulkIpv6Prefix(HashSet<Ipv6Prefix>),
}

pub enum MihariEntry {
    UpdateIpv4(HashSet<Ipv4Prefix>, HashSet<Ipv4Prefix>),
    UpdateIpv6(HashSet<Ipv6Prefix>, HashSet<Ipv6Prefix>),
}

#[derive(Copy, Clone)] //may need Hash, Eq, PartialEq for both structs
pub struct Ipv4Prefix {
    pub prefix_len: u32,
    pub addr: u32,
}

#[derive(Copy, Clone)]
pub struct Ipv6Prefix {
    pub prefix_len: u32,
    pub addr: [u8; 16],
}

impl Display for Ipv4Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.addr), self.prefix_len)
    }
}

impl Display for Ipv6Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", Ipv6Addr::from(self.addr), self.prefix_len)
    }
}

unsafe impl aya::Pod for Ipv4Prefix {}
unsafe impl aya::Pod for Ipv6Prefix {}

pub async fn start_ebpf_worker(
    mut kekkai_rx: tokio::sync::mpsc::Receiver<EbpfEntry>,
    mut mihari_rx: tokio::sync::mpsc::Receiver<MihariEntry>,
    interface: String,
) {
    use aya::maps::{
        HashMap, PerCpuArray, PerCpuValues,
        lpm_trie::{Key, LpmTrie},
    };
    macro_rules! insert_bulk {
        ($map:expr, $count:expr, $limit:expr, $items:expr, $map_name:expr) => {
            let mut dropped = 0;
            for item in $items {
                if $count >= $limit {
                    dropped += 1;
                    continue;
                }
                let key = Key::new(item.prefix_len, item.addr);
                if let Err(e) = $map.insert(&key, 1, 0) {
                    error!("Failed to insert prefix into {}: {e}", $map_name);
                } else {
                    $count += 1;
                }
            }
            if dropped > 0 {
                error!(
                    "FIREWALL DEGRADED: {} capacity reached! {} prefixes dropped.",
                    $map_name, dropped
                );
            }
        };
    }
    macro_rules! delete_bulk {
        ($map:expr, $count:expr, $items:expr, $map_name:expr) => {
            for item in $items {
                let key = Key::new(item.prefix_len, item.addr);
                if let Err(e) = $map.remove(&key) {
                    if let aya::maps::MapError::SyscallError(sys_error) = &e {
                        if sys_error.io_error.raw_os_error() == Some(libc::ENOENT) {
                            continue;
                        }
                    }
                    error!(
                        "CRITICAL: Failed to remove IP from {} for abnormal reason: {e}",
                        $map_name
                    );
                } else {
                    $count = $count.saturating_sub(1);
                }
            }
        };
    }
    info!("Kekkai initalizing on {}...", interface);
    let Ok(mut ebpf_guard) = init_ebpf(&interface).await else {
        error!("FATAL: Failed to initialize eBPF");
        std::process::exit(1);
    };
    let Some(blocklist_v4_raw) = ebpf_guard.take_map("BLOCKLIST_V4") else {
        error!("FATAL: Failed to initialize eBPF map BLOCKLIST_V4 from kekkai");
        std::process::exit(1);
    };
    let Ok(mut blocklist_v4) = HashMap::<_, u32, u8>::try_from(blocklist_v4_raw) else {
        error!("FATAL: Failed to extract eBPF map BLOCKLIST_V4 from memory");
        std::process::exit(1);
    };
    let Some(blocklist_v6_raw) = ebpf_guard.take_map("BLOCKLIST_V6") else {
        error!("FATAL: Failed to initialize eBPF map BLOCKLIST_V6 from kekkai");
        std::process::exit(1);
    };
    let Ok(mut blocklist_v6) = HashMap::<_, [u8; 16], u8>::try_from(blocklist_v6_raw) else {
        error!("FATAL: Failed to extract eBPF map BLOCKLIST_V6 from memory");
        std::process::exit(1);
    };
    let Some(blocklist_v4_prefix_raw) = ebpf_guard.take_map("BLOCKLIST_V4_PREFIX") else {
        error!("FATAL: Failed to initialize eBPF map BLOCKLIST_V4_PREFIX from kekkai");
        std::process::exit(1);
    };
    let Ok(mut blocklist_v4_prefix) = LpmTrie::<_, u32, u8>::try_from(blocklist_v4_prefix_raw)
    else {
        error!("FATAL: Failed to extract eBPF map BLOCKLIST_V4_PREFIX from memory");
        std::process::exit(1);
    };
    let Some(blocklist_v6_prefix_raw) = ebpf_guard.take_map("BLOCKLIST_V6_PREFIX") else {
        error!("FATAL: Failed to initialize eBPF map BLOCKLIST_V6_PREFIX from kekkai");
        std::process::exit(1);
    };
    let Ok(mut blocklist_v6_prefix) = LpmTrie::<_, [u8; 16], u8>::try_from(blocklist_v6_prefix_raw)
    else {
        error!("FATAL: Failed to extract eBPF map BLOCKLIST_V6_PREFIX from memory");
        std::process::exit(1);
    };
    let Some(mihari_v4_raw) = ebpf_guard.take_map("MIHARI_V4") else {
        error!("FATAL: Failed to initialize eBPF map CROWDSEC_V4 from kekkai");
        std::process::exit(1);
    };
    let Ok(mut mihari_v4) = LpmTrie::<_, u32, u8>::try_from(mihari_v4_raw) else {
        error!("FATAL: Failed to extract eBPF map CROWDSEC_V4 from memory");
        std::process::exit(1);
    };
    let Some(mihari_v6_raw) = ebpf_guard.take_map("MIHARI_V6") else {
        error!("FATAL: Failed to initialize eBPF map CROWDSEC_V6 from kekkai");
        std::process::exit(1);
    };
    let Ok(mut mihari_v6) = LpmTrie::<_, [u8; 16], u8>::try_from(mihari_v6_raw) else {
        error!("FATAL: Failed to extract eBPF map CROWDSEC_V6 from memory");
        std::process::exit(1);
    };
    let Some(metrics_raw) = ebpf_guard.take_map("METRICS") else {
        error!("FATAL: Failed to initialize eBPF map METRICS from kekkai");
        std::process::exit(1);
    };
    let Ok(mut metrics) = PerCpuArray::<_, u64>::try_from(metrics_raw) else {
        error!("FATAL: Failed to extract eBPF map METRICS from memory");
        std::process::exit(1);
    };
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
    let Ok(nr_cpus) = aya::util::nr_cpus() else {
        error!("FATAL: Failed to get number of CPUs");
        std::process::exit(1);
    };
    let mut ipv4_prefix_count: u32 = 0;
    let mut ipv6_prefix_count: u32 = 0;
    let mut mihari_ipv4_count: u32 = 0;
    let mut mihari_ipv6_count: u32 = 0;
    loop {
        tokio::select! {
            biased;
            Some(entry) = kekkai_rx.recv() => {
                match entry {
                    EbpfEntry::InsertIpv4(addr) => {
                        if let Err(e) = blocklist_v4.insert(addr, 1, 0) {
                            error!("Failed to insert IPv4 address into BLOCKLIST_V4: {e}")
                        }
                    }
                    EbpfEntry::InsertIpv6Addr(addr) => {
                        if let Err(e) = blocklist_v6.insert(addr, 1, 0) {
                            error!("Failed to insert IPv6 address into BLOCKLIST_V6: {e}")
                        }
                    }
                    EbpfEntry::DeleteIpv4(addr) => {
                        if let Err(e) = blocklist_v4.remove(&addr) {
                            error!("Failed to remove IPv4 address from BLOCKLIST_V4: {e}")
                        }
                    }
                    EbpfEntry::DeleteIpv6Addr(addr) => {
                        if let Err(e) = blocklist_v6.remove(&addr) {
                            error!("Failed to remove IPv6 address from BLOCKLIST_V6: {e}")
                        }
                    }
                    EbpfEntry::InsertBulkIpv4Prefix(prefixes) => {
                        insert_bulk!(blocklist_v4_prefix, ipv4_prefix_count, 125_000, prefixes, "BLOCKLIST_V4_PREFIX");
                    }
                    EbpfEntry::InsertBulkIpv6Prefix(prefixes) => {
                        insert_bulk!(blocklist_v6_prefix, ipv6_prefix_count, 125_000, prefixes, "BLOCKLIST_V6_PREFIX");
                    }
                    EbpfEntry::DeleteBulkIpv4Prefix(prefixes) => {
                        delete_bulk!(blocklist_v4_prefix, ipv4_prefix_count, prefixes, "BLOCKLIST_V4_PREFIX");
                    }
                    EbpfEntry::DeleteBulkIpv6Prefix(prefixes) => {
                        delete_bulk!(blocklist_v6_prefix, ipv6_prefix_count, prefixes, "BLOCKLIST_V6_PREFIX");
                    }
                }
            }

            _ = interval.tick() => {
                let Ok(passed_raw) = metrics.get(&0, 0) else {
                    error!("Failed to get pass metrics");
                    continue
                };
                let Ok(dropped_raw) = metrics.get(&1, 0) else {
                    error!("Failed to get drop metrics");
                    continue
                };
                let passed_total: u64 = passed_raw.iter().copied().sum();
                let dropped_total: u64 = dropped_raw.iter().copied().sum();
                if passed_total > 0 || dropped_total > 0 {
                    info!("Traffic last minute: {passed_total} passed, {dropped_total} dropped");
                }
                let Ok(zero_passes) = PerCpuValues::try_from(vec![0u64; nr_cpus]) else {
                    error!("Failed to zero pass metrics");
                    continue
                };
                if let Err(e) = metrics.set(0, zero_passes, 0) {
                    error!("Failed to reset pass metrics: {e}")
                }
                let Ok(zero_drops) = PerCpuValues::try_from(vec![0u64; nr_cpus]) else {
                    error!("Failed to zero drop metrics");
                    continue
                };
                if let Err(e) = metrics.set(1, zero_drops, 0) {
                    error!("Failed to reset drop metrics: {e}")
                }
            }

            Some(diffs) = mihari_rx.recv() => {
                match diffs {
                    MihariEntry::UpdateIpv4(add, remove) => {
                        delete_bulk!(mihari_v4, mihari_ipv4_count, remove, "MIHARI_V4");
                        insert_bulk!(mihari_v4, mihari_ipv4_count, 250_000, add, "MIHARI_V4");
                    }
                    MihariEntry::UpdateIpv6(add, remove) => {
                        delete_bulk!(mihari_v6, mihari_ipv6_count, remove, "MIHARI_V6");
                        insert_bulk!(mihari_v6, mihari_ipv6_count, 250_000, add, "MIHARI_V6");
                    }
                }
            }
        }
    }
    #[cfg(not(feature = "ebpf"))]
    info!("Kekkai disabled");
}

#[cfg(feature = "ebpf")]
async fn init_ebpf(iface: &str) -> anyhow::Result<aya::Ebpf> {
    use anyhow::Context as _;
    use aya::programs::{Xdp, XdpMode};
    use log::{debug, warn};

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/kekkai"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let Ok(mut guard) = logger.readable_mut().await else {
                        log::error!("ebpf logger dropped");
                        break;
                    };
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let program: &mut Xdp = ebpf
        .program_mut("kekkai")
        .context("FATAL: Failed to find named program inside the compiled eBPF ELF file")?
        .try_into()?;
    program.load()?;
    program.attach(iface, XdpMode::Skb)
        .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;

    log::info!("Kekkai eBPF successfully attached to {}", iface);
    Ok(ebpf)
}

#[cfg(not(feature = "ebpf"))]
pub async fn init_ebpf(_iface: &str) -> anyhow::Result<()> {
    log::info!("Kekkai eBPF disabled");
    Ok(())
}
