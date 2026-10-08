use std::{net::IpAddr, num::NonZeroU32, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use aya::maps::{HashMap, MapData};
use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
};
use keidai::ConnectionEvent;
use moka::{Expiry, sync::Cache};
use tokio::{
    select,
    sync::mpsc::{self, Receiver, Sender},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::cli::config::ActiveState;

pub enum EbpfEntry {
    InsertIpv4(u32),
    DeleteIpv4(u32),
    InsertIpv6Addr([u8; 16]),
    DeleteIpv6Addr([u8; 16]),
}

pub async fn run(
    dynamic_config: Arc<ArcSwap<ActiveState>>,
    mut blocklist_v4: HashMap<MapData, u32, u8>,
    mut blocklist_v6: HashMap<MapData, [u8; 16], u8>,
    hashira_tx: Sender<EbpfEntry>,
    mut hashira_rx: Receiver<EbpfEntry>,
    event_rx: flume::Receiver<ConnectionEvent>,
    cancel_token: CancellationToken,
) -> anyhow::Result<()> {
    let mut child_workers: JoinSet<anyhow::Result<()>> = JoinSet::new();
    child_workers.spawn({
        let cancel_token = cancel_token.clone();
        async move {
            loop {
                let entry = select! {
                    biased;
                    _ = cancel_token.cancelled() => break,
                    res = hashira_rx.recv() => {
                        let Some(entry) = res else { break };
                        entry
                    }
                };
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
            Ok(())
        }
    });
    child_workers.spawn({
        let cancel_token = cancel_token.clone();
        async move {
            let engine = PolicyEngine::new(hashira_tx, dynamic_config);
            loop {
                select! {
                    biased;
                    _ = cancel_token.cancelled() => break,
                    Ok(event) = event_rx.recv_async() => {
                        engine.evaluate_event(&event);
                    }
                }
            }
            Ok(())
        }
    });
    cancel_token.cancelled().await;
    Ok(())
}

type IpLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

pub struct PolicyEngine {
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
            .max_capacity(20_000)
            .build();
        let velocity_tracker: Cache<IpAddr, u32> = Cache::builder()
            .time_to_live(Duration::from_secs(1))
            .max_capacity(20_000)
            .build();
        let strike_limiters: Cache<IpAddr, Arc<IpLimiter>> = Cache::builder()
            .time_to_live(Duration::from_secs(300))
            .max_capacity(20_000)
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

    fn evaluate_event(&self, event: &ConnectionEvent) {
        if event.ip_addr().is_loopback() {
            return;
        }
        let security_config = &self.dynamic_config.load().security;
        let mut strikes: u32 = 0;

        let request_count = self.velocity_tracker.get_with(event.ip_addr(), || 0) + 1;
        self.velocity_tracker.insert(event.ip_addr(), request_count);
        if request_count > security_config.ebpf_velocity_threshhold as u32 {
            strikes += security_config.ebpf_strike_threshold as u32;
        }

        strikes += check_latency(event.status_code, event.latency_ms);
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
                                );
                                return;
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
                                );
                                return;
                            }
                        }
                    }
                }
                info!(
                    "eBPF Ban triggered for {:?} for {:?}",
                    event.ip_addr(),
                    escalated_duration
                )
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
fn check_latency(status_code: u16, latency: u32) -> u32 {
    match status_code {
        408 | 504 if latency > 15_000 => PENALTY_SEVERE,
        _ => 0,
    }
}
#[inline]
fn check_status(status_code: u16) -> u32 {
    match status_code {
        400 | 401 | 403 => PENALTY_MODERATE,
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
        b"GET" | b"POST" | b"PUT" | b"DELETE" | b"PATCH" | b"OPTIONS" | b"HEAD" | b"TLS"
        | b"QUIC" => 0,
        _ => PENALTY_INSTANT,
    }
}
