use std::{
    fmt::Display,
    fs::File,
    io::Write,
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
    str::FromStr,
    sync::Arc,
};

use memmap2::Mmap;
use tracing::{error, info};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::{
    ebpf::{
        hashira::{self, EbpfEntry},
        metrics, mihari,
    },
    error::Error,
    state::AppState,
};

#[repr(C)]
#[derive(
    Copy, Clone, Eq, PartialEq, IntoBytes, FromBytes, Immutable, KnownLayout, Ord, PartialOrd,
)]
pub struct Ipv4Prefix {
    pub prefix_len: u32,
    pub addr: u32,
}

#[repr(C)]
#[derive(
    Copy, Clone, Eq, PartialEq, IntoBytes, FromBytes, Immutable, KnownLayout, Ord, PartialOrd,
)]
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

impl FromStr for Ipv4Prefix {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((addr, prefix_len)) = s.split_once('/') {
            let prefix_len = prefix_len.parse::<u32>()?;
            let addr = addr.parse::<Ipv4Addr>()?;
            if prefix_len > 32 || prefix_len < 8 {
                return Err(Error::InvalidPrefix(s.to_string()));
            }
            return Ok(Self {
                prefix_len,
                addr: addr.into(),
            });
        }
        if let Some(addr) = s.parse::<Ipv4Addr>().ok() {
            return Ok(Self {
                prefix_len: 32,
                addr: addr.into(),
            });
        }
        Err(Error::InvalidPrefix(s.to_string()))
    }
}

impl FromStr for Ipv6Prefix {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((addr, prefix_len)) = s.split_once('/') {
            let prefix_len = prefix_len.parse::<u32>()?;
            let addr = addr.parse::<Ipv6Addr>()?;
            if prefix_len > 128 || prefix_len < 19 {
                return Err(Error::InvalidPrefix(s.to_string()));
            }
            return Ok(Self {
                prefix_len,
                addr: addr.octets(),
            });
        }
        if let Some(addr) = s.parse::<Ipv6Addr>().ok() {
            return Ok(Self {
                prefix_len: 128,
                addr: addr.octets(),
            });
        }
        Err(Error::InvalidPrefix(s.to_string()))
    }
}

unsafe impl aya::Pod for Ipv4Prefix {}
unsafe impl aya::Pod for Ipv6Prefix {}

#[macro_export]
macro_rules! insert_single {
    ($map:expr, $count:expr, $limit:expr, $item:expr, $dropped:expr, $map_name:expr) => {
        if $count >= $limit {
            $dropped += 1;
        } else {
            let key = aya::maps::lpm_trie::Key::new($item.prefix_len, $item.addr);
            if let Err(e) = $map.insert(&key, 1, 0) {
                error!("Failed to insert prefix into {}: {e}", $map_name);
            } else {
                $count += 1;
            }
        }
    };
}

#[macro_export]
macro_rules! delete_single {
    ($map:expr, $count:expr, $item:expr, $map_name:expr) => {
        let key = aya::maps::lpm_trie::Key::new($item.prefix_len, $item.addr);
        if let Err(e) = $map.remove(&key) {
            if let aya::maps::MapError::SyscallError(sys_error) = &e {
                if sys_error.io_error.raw_os_error() == Some(libc::ENOENT) {
                    continue;
                }
            } else {
                error!(
                    "CRITICAL: Failed to remove IP from {} for abnormal reason: {e}",
                    $map_name
                );
            }
        } else {
            $count = $count.saturating_sub(1);
        }
    };
}

#[macro_export]
macro_rules! insert_bulk {
    ($map:expr, $count:expr, $limit:expr, $items:expr, $map_name:expr) => {
        let mut dropped = 0;
        for item in $items {
            insert_single!($map, $count, $limit, item, dropped, $map_name);
        }
        if dropped > 0 {
            error!(
                "FIREWALL DEGRADED: {} capacity reached! {} prefixes dropped.",
                $map_name, dropped
            );
        }
    };
}

pub fn save_sets_to_disk<T: IntoBytes + Immutable, P: AsRef<Path>>(
    slice: &[T],
    path: P,
) -> Result<(), Error> {
    let path = path.as_ref();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut file = tempfile::Builder::new()
        .prefix(".torii_tmp_")
        .tempfile_in(parent)?;
    file.write_all(slice.as_bytes())?;
    file.persist(path)?;
    Ok(())
}

pub fn load_sets_from_disk<P: AsRef<Path>>(path: P) -> Result<Mmap, Error> {
    let file = File::open(path)?;
    Ok(unsafe { Mmap::map(&file)? })
}

pub async fn run(
    state: Arc<AppState>,
    kekkai_rx: tokio::sync::mpsc::Receiver<EbpfEntry>,
    mihari_rx: tokio::sync::mpsc::Receiver<String>,
    interface: String,
) {
    use aya::maps::{HashMap, PerCpuArray, lpm_trie::LpmTrie};
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
    tokio::spawn(metrics::run(metrics));
    tokio::spawn(hashira::run(
        blocklist_v4,
        blocklist_v6,
        blocklist_v4_prefix,
        blocklist_v6_prefix,
        kekkai_rx,
    ));
    if let Some(mihari_provider) = &state.config.mihari_provider {
        tokio::spawn(mihari::run(
            mihari_provider.clone(),
            state.config.mihari_interval,
            state.config.kekkai_path.clone(),
            mihari_v4,
            mihari_v6,
            mihari_rx,
        ));
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
