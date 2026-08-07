use std::{
    net::{IpAddr, UdpSocket},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use arc_swap::ArcSwap;
use aya::maps::{HashMap, LpmTrie, MapData};
use keidai::{BufferHeader, ConnectionEvent};
use memmap2::MmapMut;
use moka::{Expiry, future::Cache};
use tokio::sync::mpsc::{self, Receiver};
use tracing::{error, info, warn};
use zerocopy::FromBytes;

use crate::{config::structs::ToriiConfig, error::Error};

const EVENT_BUDGET: u32 = 256;
const EVENT_SIZE: usize = 288;

pub enum EbpfEntry {
    InsertIpv4(u32),
    DeleteIpv4(u32),
    InsertIpv6Addr([u8; 16]),
    DeleteIpv6Addr([u8; 16]),
    // InsertBulkIpv4Prefix(Vec<Ipv4Prefix>),
    // DeleteBulkIpv4Prefix(Vec<Ipv4Prefix>),
    //InsertBulkIpv6Prefix(Vec<Ipv6Prefix>),
    //DeleteBulkIpv6Prefix(Vec<Ipv6Prefix>),
}

struct LocalSidecarHandle {
    id: u64,
    mmap: MmapMut,
    size: u32,
    read_head: u32,
}

struct FutexWaitv {
    val: u64,
    uaddr: u64,
    flags: u32,
    __reserved: u32,
}

pub async fn run(
    // Change this and other workers to return a result -> Result<(), Error>
    size: u32,
    remote_sidecars: bool,
    addr: String,
    mut blocklist_v4: HashMap<MapData, u32, u8>,
    mut blocklist_v6: HashMap<MapData, [u8; 16], u8>,
    mut blocklist_v4_prefix: LpmTrie<MapData, u32, u8>,
    mut blocklist_v6_prefix: LpmTrie<MapData, [u8; 16], u8>,
    mut kekkai_rx: Receiver<EbpfEntry>,
) {
    let (ebpf_tx, mut ebpf_rx) = tokio::sync::mpsc::channel::<EbpfEntry>(10_000);
    let (shm_register_tx, mut shm_register_rx) =
        tokio::sync::mpsc::channel::<LocalSidecarHandle>(64);
    /*
    let Ok(buffer_file) = std::fs::OpenOptions::new()
        .mode(0o600)
        .read(true)
        .write(true)
        .create(true)
        .open("/dev/shm/torii")
    else {
        error!("Failed to open ring buffer");
        return; //either hard crash or error in a more obvious way ex: ToriiError in error.rs and .map_err on places I want to pass custom text and bubble up the actual error
    };
    if let Err(e) = buffer_file.set_len(8 + (288 * size as u64)) {
        error!("Failed to create ring buffer: {e}");
        return;
    }
    let Ok(mut mmap) = (unsafe { memmap2::MmapMut::map_mut(&buffer_file) }) else {
        error!("Failed to map ring buffer");
        return;
    };
    */
    std::thread::spawn(move || {
        while let Ok(entry) = ebpf_rx.try_recv() {
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
            }
        }
    });
    std::thread::spawn(move || {
        let mut sidecars: Vec<LocalSidecarHandle> = Vec::new();
        loop {
            while let Ok(new_sidecar) = shm_register_rx.try_recv() {
                sidecars.push(new_sidecar);
            }
            if sidecars.is_empty() {
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }

            let mut events_processed = 0;
            for sidecar in sidecars.iter_mut() {
                let (head_bytes, data_bytes) = sidecar.mmap.split_at_mut(16);
                let buffer_head = unsafe { &*(head_bytes.as_ptr() as *const BufferHeader) };
                let write_head = buffer_head.write_head.value.load(Ordering::Acquire);
                if write_head > sidecar.read_head + sidecar.size {
                    warn!("Sidecar {} lapped reader! Snapping head.", sidecar.id); //id or by domain?
                    sidecar.read_head = write_head - sidecar.size;
                }
                let mut processed = 0;
                while sidecar.read_head < write_head && processed < EVENT_BUDGET {
                    let index = ((sidecar.read_head % sidecar.size) as usize) * EVENT_SIZE;
                    let chunk = &data_bytes[index..index + EVENT_SIZE];
                    if let Ok(event) = ConnectionEvent::ref_from_bytes(chunk) {
                        // need to add validation of the bytes here or in the checks
                        evaluate_event(event);
                    } else {
                        error!("Corrupted event at SHM index {index}");
                    }
                    sidecar.read_head += 1;
                    processed += 1;
                }
                if processed > 0 {
                    buffer_head
                        .read_head
                        .value
                        .store(sidecar.read_head, Ordering::Release);
                    events_processed += processed;
                }
            }
            if events_processed == 0 {
                let mut waiters: Vec<FutexWaitv> = Vec::with_capacity(sidecars.len());
                for sidecar in sidecars.iter() {
                    let (head_bytes, data_bytes) = sidecar.mmap.split_at_mut(16);
                    let buffer_head = unsafe { &*(head_bytes.as_ptr() as *const BufferHeader) };
                    let write_head = buffer_head.write_head.value.load(Ordering::Relaxed) as u64;
                    let write_head_ptr = &buffer_head.write_head.value as *const _ as u64;
                    waiters.push(FutexWaitv {
                        val: write_head,
                        uaddr: write_head_ptr,
                        flags: 2,
                        __reserved: 0,
                    })
                }
                unsafe {
                    libc::syscall(
                        libc::SYS_futex_waitv,
                        waiters.as_ptr(),
                        waiters.len() as u32,
                        0,
                        0,
                        0,
                    );
                }
            }
        }
    });
    if remote_sidecars {
        let socket = UdpSocket::bind(addr);
        info!("UDP Sidecar listner active on: {addr}");
        tokio::spawn(async move {
            loop {
                //match socket.recv_from()
                //need to safely handle exposing UDP or use a tunnel (VPN)
                //Need to resize the socket (socket2 crate) so can handle multiple events at once and in large scale.
            }
        });
    }
}

struct PolicyEngine {
    ban_v4: Cache<u32, Duration>,
    ban_v6: Cache<[u8; 16], Duration>,
    dynamic_config: Arc<ArcSwap<ToriiConfig>>,
    ebpf_tx: mpsc::Sender<EbpfEntry>,
}

struct DynamicExpiry;

impl<K> Expiry<K, Duration> for DynamicExpiry {
    fn expire_after_create(
        &self,
        _key: &K,
        value: &Duration,
        _created_at: std::time::Instant,
    ) -> Option<Duration> {
        Some(*value)
    }
    fn expire_after_update(
        &self,
        _key: &K,
        value: &Duration,
        _updated_at: std::time::Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(*value)
    }
    fn expire_after_read(
        &self,
        _key: &K,
        _value: &Duration,
        _read_at: std::time::Instant,
        duration_until_expiry: Option<Duration>,
        _last_modified_at: std::time::Instant,
    ) -> Option<Duration> {
        duration_until_expiry
    }
}

impl PolicyEngine {
    fn new(ebpf_tx: mpsc::Sender<EbpfEntry>, dynamic_config: Arc<ArcSwap<ToriiConfig>>) -> Self {
        let tx_v4 = ebpf_tx.clone();
        let tx_v6 = ebpf_tx.clone();
        let ban_v4: Cache<u32, Duration> = Cache::builder()
            .expire_after(DynamicExpiry)
            .eviction_listener(move |addr: Arc<u32>, _val, _cause| {
                let _ = tx_v4.try_send(EbpfEntry::DeleteIpv4(*addr));
            })
            .build();
        let ban_v6: Cache<[u8; 16], Duration> = Cache::builder()
            .expire_after(DynamicExpiry)
            .eviction_listener(move |addr: Arc<[u8; 16]>, _val, _cause| {
                let _ = tx_v6.try_send(EbpfEntry::DeleteIpv6Addr(*addr));
            })
            .build();
        Self {
            ban_v4,
            ban_v6,
            ebpf_tx,
            dynamic_config,
        }
    }

    async fn evaluate_event(&mut self, event: &ConnectionEvent) {
        let config = self.dynamic_config.load();
        let mut ban_duration = Duration::from_secs(0);

        /*
        if let Some(penalty) = self.check_() {
            ban_duration += penalty;
        }
        */

        if ban_duration.as_secs() > 0 {
            match event.ip_addr() {
                IpAddr::V4(ipv4) => {
                    let ip_u32 = u32::from(ipv4);
                    if !self.ban_v4.contains_key(&ip_u32) {
                        self.ban_v4.insert(ip_u32, ban_duration);
                        let _ = self.ebpf_tx.try_send(EbpfEntry::InsertIpv4(ip_u32));
                    }
                }
                IpAddr::V6(_) => {
                    if !self.ban_v6.contains_key(&event.ip) {
                        self.ban_v6.insert(event.ip, ban_duration);
                        let _ = self.ebpf_tx.try_send(EbpfEntry::InsertIpv6Addr(event.ip));
                    }
                }
            }
        }
    }
}

fn check_path() {}
fn check_govenor() {}
fn check_status() {}
fn check_latency() {}
/*
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
*/
