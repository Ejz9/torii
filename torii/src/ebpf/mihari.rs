use std::{path::PathBuf, sync::Arc, time::Duration};

pub mod crowdsec;

use aya::maps::{LpmTrie, MapData};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use zerocopy::FromBytes;

use crate::{
    ebpf::{
        kekkai_manager::{Ipv4Prefix, Ipv6Prefix, load_sets_from_disk, save_sets_to_disk},
        mihari::crowdsec::CrowdSecProvider,
    },
    error::Error,
    populate_map_from_disk, sync_map_to_disk,
};

#[macro_export]
macro_rules! sync_diff {
    ($old:expr, $new:expr, $map:expr, $count:expr, $limit:expr, $map_name:expr) => {
        let mut old_index = 0;
        let mut new_index = 0;
        let mut dropped = 0;

        while old_index < $old.len() && new_index < $new.len() {
            match &$old[old_index].cmp(&$new[new_index]) {
                std::cmp::Ordering::Equal => {
                    old_index += 1;
                    new_index += 1;
                }
                std::cmp::Ordering::Less => {
                    crate::delete_single!($map, $count, &$old[old_index], $map_name);
                    old_index += 1;
                }
                std::cmp::Ordering::Greater => {
                    crate::insert_single!(
                        $map,
                        $count,
                        $limit,
                        &$new[new_index],
                        dropped,
                        $map_name
                    );
                    new_index += 1;
                }
            }
        }

        for old in &$old[old_index..] {
            crate::delete_single!($map, $count, old, $map_name);
        }
        for new in &$new[new_index..] {
            crate::insert_single!($map, $count, $limit, new, dropped, $map_name);
        }

        if dropped > 0 {
            tracing::error!(
                "FIREWALL DEGRADED: {} capacity reached! {} prefixes dropped.",
                $map_name,
                dropped
            );
        }
    };
}

pub async fn run(
    provider: MihariProviderKind,
    interval: u64,
    kekkai_path: String,
    mut mihari_v4: LpmTrie<MapData, u32, u8>,
    mut mihari_v6: LpmTrie<MapData, [u8; 16], u8>,
    mihari_notify: Arc<tokio::sync::Notify>,
    cancel_token: CancellationToken,
) -> anyhow::Result<()> {
    let mut interval = tokio::time::interval(Duration::from_mins(interval));
    let mihari_ipv4_count: u32 = 0;
    let mihari_ipv6_count: u32 = 0;
    let mihari_path = PathBuf::from(kekkai_path);

    let path_v4 = mihari_path.join("mihari_v4.bin");
    let (mut mihari_v4, mut mmap_v4, mut mihari_ipv4_count) = populate_map_from_disk!(mihari_v4, path_v4, Ipv4Prefix, 250_000, "MIHARI_V4", count => mihari_ipv4_count)?;
    let path_v6 = mihari_path.join("mihari_v6.bin");
    let (mut mihari_v6, mut mmap_v6, mut mihari_ipv6_count) = populate_map_from_disk!(mihari_v6, path_v6, Ipv6Prefix, 250_000, "MIHARI_V6", count => mihari_ipv6_count)?;
    if mmap_v4.is_some() && mmap_v6.is_some() {
        interval.tick().await;
    }
    loop {
        tokio::select! {
            biased;
            _ = cancel_token.cancelled() => {
                info!("eBPF Mihari recieved shutdown signal. Halting.");
                break;
            }
            _ = mihari_notify.notified() => {}
            _ = interval.tick() => {}

        }
        let Ok((mut incoming_ipv4_entries, mut incoming_ipv6_entries)) =
            provider.fetch_lists().await
        else {
            error!("Failed to fetch lists from provider");
            interval.tick().await;
            continue;
        };

        incoming_ipv4_entries.sort_unstable();
        incoming_ipv6_entries.sort_unstable();

        let old_v4_slice: &[Ipv4Prefix] = mmap_v4
            .as_ref()
            .and_then(|m| <[Ipv4Prefix]>::ref_from_bytes(m).ok())
            .unwrap_or(&[]);
        let old_v6_slice: &[Ipv6Prefix] = mmap_v6
            .as_ref()
            .and_then(|m| <[Ipv6Prefix]>::ref_from_bytes(m).ok())
            .unwrap_or(&[]);

        let v4_changed = old_v4_slice != incoming_ipv4_entries.as_slice();
        let v6_changed = old_v6_slice != incoming_ipv6_entries.as_slice();

        if !v4_changed && !v6_changed {
            interval.tick().await;
            continue;
        }

        if v4_changed {
            let path_v4 = mihari_path.join("mihari_v4.bin");
            let returned_pointer;
            (mihari_v4, returned_pointer, mihari_ipv4_count) = sync_map_to_disk!(
                mihari_v4,
                path_v4,
                Ipv4Prefix,
                incoming_ipv4_entries,
                250_000,
                "MIHARI_V4",
                mmap_v4,
                mihari_ipv4_count
            )?;
            if let Some(mmap) = returned_pointer {
                mmap_v4 = Some(mmap);
            }
        }

        if v6_changed {
            let path_v6 = mihari_path.join("mihari_v6.bin");
            let returned_pointer;
            (mihari_v6, returned_pointer, mihari_ipv6_count) = sync_map_to_disk!(
                mihari_v6,
                path_v6,
                Ipv6Prefix,
                incoming_ipv6_entries,
                250_000,
                "MIHARI_V6",
                mmap_v6,
                mihari_ipv6_count
            )?;
            if let Some(mmap) = returned_pointer {
                mmap_v6 = Some(mmap);
            }
        }

        interval.tick().await;
    }
    Ok(())
}

trait MihariProvider: Send + Sync {
    async fn fetch_lists(&self) -> Result<(Vec<Ipv4Prefix>, Vec<Ipv6Prefix>), Error>;
}
#[derive(Clone, Debug)]
pub enum MihariProviderKind {
    CrowdSec(CrowdSecProvider),
}

impl MihariProviderKind {
    async fn fetch_lists(&self) -> Result<(Vec<Ipv4Prefix>, Vec<Ipv6Prefix>), Error> {
        match self {
            MihariProviderKind::CrowdSec(provider) => provider.fetch_lists().await,
        }
    }
}
