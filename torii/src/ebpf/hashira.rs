use std::{
    net::IpAddr,
    num::NonZeroU32,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use arc_swap::ArcSwap;
use aya::maps::{HashMap, LpmTrie, MapData};
use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
};
use keidai::{BufferHeader, ConnectionEvent};
use memmap2::MmapMut;
use moka::{Expiry, sync::Cache};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{error, warn};
use zerocopy::FromBytes;

use crate::config::structs::ActiveState;

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
    //remote_sidecars: bool,
    //addr: String,
    mut dynamic_config: Arc<ArcSwap<ActiveState>>,
    mut blocklist_v4: HashMap<MapData, u32, u8>,
    mut blocklist_v6: HashMap<MapData, [u8; 16], u8>,
    mut blocklist_v4_prefix: LpmTrie<MapData, u32, u8>,
    mut blocklist_v6_prefix: LpmTrie<MapData, [u8; 16], u8>,
    mut kekkai_rx: Receiver<EbpfEntry>,
    mut hashira_tx: Sender<EbpfEntry>,
    mut hashira_rx: Receiver<EbpfEntry>,
) {
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
        while let Ok(entry) = hashira_rx.try_recv() {
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
        let mut engine = PolicyEngine::new(hashira_tx, dynamic_config);
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
                let (head_bytes, data_bytes) = sidecar.mmap.split_at(16);
                let buffer_head = unsafe { &*(head_bytes.as_ptr() as *const BufferHeader) };
                let write_head = buffer_head.write_head.value.load(Ordering::Acquire);
                if write_head > sidecar.read_head + sidecar.size {
                    warn!("Sidecar {} lapped reader! Snapping head.", sidecar.id); //id or by domain?
                    sidecar.read_head = write_head - sidecar.size;
                }
                let mut processed = 0;
                while sidecar.read_head < write_head && processed < EVENT_BUDGET {
                    let index = ((sidecar.read_head & (sidecar.size - 1)) as usize) * EVENT_SIZE; // sidecar.size must be power of 2 for bitwise AND
                    let chunk = &data_bytes[index..index + EVENT_SIZE];
                    if let Ok(event) = ConnectionEvent::ref_from_bytes(chunk) {
                        // need to add validation of the bytes here or in the checks
                        engine.evaluate_event(event);
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
                    let (head_bytes, data_bytes) = sidecar.mmap.split_at(16);
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
    /*
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
    */
}

type IpLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

struct PolicyEngine {
    ban_v4: Cache<u32, Duration>,
    ban_v6: Cache<[u8; 16], Duration>,
    offense_history: Cache<IpAddr, u32>,
    velocity_tracker: Cache<IpAddr, u32>,
    strike_limiters: Cache<IpAddr, Arc<IpLimiter>>,
    dynamic_config: Arc<ArcSwap<ActiveState>>,
    hashira_tx: mpsc::Sender<EbpfEntry>,
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
    fn new(hashira_tx: mpsc::Sender<EbpfEntry>, dynamic_config: Arc<ArcSwap<ActiveState>>) -> Self {
        let tx_v4 = hashira_tx.clone();
        let tx_v6 = hashira_tx.clone();
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
        let offense_history: Cache<IpAddr, u32> = Cache::builder()
            .time_to_live(Duration::from_hours(24))
            .max_capacity(100_000)
            .build();
        let velocity_tracker: Cache<IpAddr, u32> = Cache::builder()
            .time_to_live(Duration::from_secs(1))
            .max_capacity(100_000)
            .build();
        let strike_limiters: Cache<IpAddr, Arc<IpLimiter>> = Cache::builder()
            .time_to_live(Duration::from_secs(300))
            .max_capacity(100_000)
            .build();
        Self {
            ban_v4,
            ban_v6,
            offense_history,
            velocity_tracker,
            strike_limiters,
            hashira_tx,
            dynamic_config,
        }
    }

    fn calculate_escalation(&self, ip: &IpAddr, duration_secs: u64) -> Duration {
        let offenses = self.offense_history.get(ip).unwrap_or(0);
        let multiplier = 2u64.pow(offenses.min(10));
        let escalation = duration_secs * multiplier;
        self.offense_history.insert(*ip, offenses + 1);
        Duration::from_secs(escalation)
    }

    fn evaluate_event(&mut self, event: &ConnectionEvent) {
        let security_config = &self.dynamic_config.load().security;
        let mut strikes: u32 = 0;

        let request_count = self.velocity_tracker.get_with(event.ip_addr(), || 0) + 1;
        self.velocity_tracker.insert(event.ip_addr(), request_count);
        if request_count > 150 {
            strikes += security_config.ebpf_strike_threshold as u32;
        }

        strikes += check_latency(event.latency_ms);
        strikes += check_status(event.status_code);
        strikes += check_method(&event.method[..event.method_len as usize]);
        if security_config
            .path_matcher
            .is_match(&event.path[..event.path_len as usize])
        {
            strikes += security_config.ebpf_strike_threshold as u32;
        }

        if strikes > 0 {
            if self.record_strikes(
                event.ip_addr(),
                strikes,
                security_config.ebpf_strike_threshold as u32,
            ) {
                self.strike_limiters.invalidate(&event.ip_addr());

                let escalated_duration = self.calculate_escalation(
                    &event.ip_addr(),
                    security_config.ebpf_lockout_duration_secs,
                );
                match event.ip_addr() {
                    IpAddr::V4(ipv4) => {
                        let ip_u32 = u32::from(ipv4);
                        if !self.ban_v4.contains_key(&ip_u32) {
                            self.ban_v4.insert(ip_u32, escalated_duration);
                            if let Err(e) = self.hashira_tx.try_send(EbpfEntry::InsertIpv4(ip_u32))
                            {
                                self.ban_v4.invalidate(&ip_u32);
                                error!(
                                    "CRITICAL: Failed to send ban to kekkai for {}: {}",
                                    ip_u32, e
                                )
                            }
                        }
                    }
                    IpAddr::V6(_) => {
                        if !self.ban_v6.contains_key(&event.ip) {
                            self.ban_v6.insert(event.ip, escalated_duration);
                            if let Err(e) = self
                                .hashira_tx
                                .try_send(EbpfEntry::InsertIpv6Addr(event.ip))
                            {
                                self.ban_v6.invalidate(&event.ip);
                                error!(
                                    "CRITICAL: Failed to send ban to kekkai for {:?}: {}",
                                    event.ip, e
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    fn record_strikes(&self, ip: IpAddr, strikes: u32, threshold: u32) -> bool {
        let limiter = self.strike_limiters.get_with(ip, || {
            let quota = Quota::with_period(Duration::from_secs(10))
                .expect("Hardcoded duration cannot be zero");
            let safe_threshold = NonZeroU32::new(threshold).unwrap_or(NonZeroU32::MIN);
            Arc::new(RateLimiter::direct(quota.allow_burst(safe_threshold)))
        });

        let Some(cells) = NonZeroU32::new(strikes) else {
            return false;
        };
        limiter.check_n(cells).is_err()
    }
}

const PENALTY_INSTANT: u32 = 10;
const PENALTY_SEVERE: u32 = 5;
const PENALTY_MODERATE: u32 = 2;
const PENALTY_MINOR: u32 = 1;

#[inline]
fn check_latency(latency: u32) -> u32 {
    if latency > 15_000 { PENALTY_SEVERE } else { 0 }
}
#[inline]
fn check_status(status_code: u16) -> u32 {
    match status_code {
        401 | 403 => PENALTY_MODERATE,
        404 | 405 | 500 | 502 | 503 => PENALTY_MINOR,
        _ => 0,
    }
}
#[inline]
fn check_method(method: &[u8]) -> u32 {
    if method == b"TRACE" || method == b"TRACK" {
        return PENALTY_INSTANT;
    }
    match method {
        b"GET" | b"POST" | b"PUT" | b"DELETE" | b"PATCH" | b"OPTIONS" | b"HEAD" => 0,
        _ => PENALTY_INSTANT,
    }
}
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
