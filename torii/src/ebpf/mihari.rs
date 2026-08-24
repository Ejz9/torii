use std::{path::PathBuf, time::Duration};

pub mod crowdsec;

use aya::maps::{LpmTrie, MapData};
use tracing::{error, info};
use zerocopy::FromBytes;

use crate::{
    ebpf::{
        kekkai_manager::{Ipv4Prefix, Ipv6Prefix, load_sets_from_disk, save_sets_to_disk},
        mihari::crowdsec::CrowdSecProvider,
    },
    error::Error,
    insert_bulk, insert_single,
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
    mut rx: tokio::sync::mpsc::Receiver<String>,
) {
    let mut interval = tokio::time::interval(Duration::from_mins(interval));
    let mut mihari_ipv4_count: u32 = 0;
    let mut mihari_ipv6_count: u32 = 0;
    let mihari_path = PathBuf::from(kekkai_path);

    let path = mihari_path.join("mihari_v4.bin");
    let v4_result = tokio::task::spawn_blocking(move || {
        let mut file = None;
        let mut current_count = mihari_ipv4_count;
        if let Ok(v4_file) = load_sets_from_disk(path) {
            if let Ok(prefixes) = <[Ipv4Prefix]>::ref_from_bytes(&v4_file) {
                info!("Using existing mihari v4 blocklist");
                insert_bulk!(mihari_v4, current_count, 250_000, prefixes, "MIHARI_V4");
            }
            file = Some(v4_file);
        }
        (mihari_v4, file, current_count)
    })
    .await;
    let (returned_map, returned_file, returned_count) =
        v4_result.expect("Mihari boot task panicked at v4");
    mihari_v4 = returned_map;
    let mut mmap_v4 = returned_file;
    mihari_ipv4_count = returned_count;

    let path = mihari_path.join("mihari_v6.bin");
    let v6_result = tokio::task::spawn_blocking(move || {
        let mut file = None;
        let mut current_count = mihari_ipv6_count;
        if let Ok(v6_file) = load_sets_from_disk(path) {
            if let Ok(prefixes) = <[Ipv6Prefix]>::ref_from_bytes(&v6_file) {
                info!("Using existing mihari v6 blocklist");
                insert_bulk!(mihari_v6, current_count, 250_000, prefixes, "MIHARI_V6");
            }
            file = Some(v6_file);
        }
        (mihari_v6, file, current_count)
    })
    .await;
    let (returned_map, returned_file, returned_count) =
        v6_result.expect("Mihari boot task panicked at v6");
    mihari_v6 = returned_map;
    let mut mmap_v6 = returned_file;
    mihari_ipv6_count = returned_count;
    if mmap_v4.is_some() && mmap_v6.is_some() {
        interval.tick().await;
    }
    loop {
        tokio::select! {
            biased;
            msg = rx.recv() => {
                if msg.is_none() {
                    error!("Mihari provider disconnected. Worker exiting.");
                    break;
                }
            }
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
            let path = mihari_path.join("mihari_v4.bin");
            let old_mmap = mmap_v4.take();
            let mut current_count = mihari_ipv4_count;
            let task = tokio::task::spawn_blocking(move || {
                let v4_slice: &[Ipv4Prefix] = old_mmap
                    .as_ref()
                    .and_then(|m| <[Ipv4Prefix]>::ref_from_bytes(m).ok())
                    .unwrap_or(&[]);
                sync_diff!(
                    v4_slice,
                    incoming_ipv4_entries,
                    mihari_v4,
                    current_count,
                    250_000,
                    "MIHARI_V4"
                );
                let mut mmap = None;
                if let Err(e) = save_sets_to_disk(&incoming_ipv4_entries, &path) {
                    error!("Failed to save mihari v4 blocklist: {e}");
                } else {
                    mmap = load_sets_from_disk(path)
                        .inspect_err(|e| error!("Failed to load mihari v4 blocklist: {e}"))
                        .ok();
                }
                (mihari_v4, mmap, current_count)
            })
            .await;
            let (returned_map, returned_pointer, returned_count) =
                task.expect("Mihari sync task panicked at v4");
            mihari_v4 = returned_map;
            if let Some(mmap) = returned_pointer {
                mmap_v4 = Some(mmap);
            }
            mihari_ipv4_count = returned_count;
        }

        if v6_changed {
            let path = mihari_path.join("mihari_v6.bin");
            let old_mmap = mmap_v6.take();
            let mut current_count = mihari_ipv6_count;
            let task = tokio::task::spawn_blocking(move || {
                let v6_slice: &[Ipv6Prefix] = old_mmap
                    .as_ref()
                    .and_then(|m| <[Ipv6Prefix]>::ref_from_bytes(m).ok())
                    .unwrap_or(&[]);
                sync_diff!(
                    v6_slice,
                    incoming_ipv6_entries,
                    mihari_v6,
                    current_count,
                    250_000,
                    "MIHARI_V6"
                );
                let mut mmap = None;
                if let Err(e) = save_sets_to_disk(&incoming_ipv6_entries, &path) {
                    error!("Failed to save mihari v6 blocklist: {e}");
                } else {
                    mmap = load_sets_from_disk(path)
                        .inspect_err(|e| error!("Failed to load mihari v6 blocklist: {e}"))
                        .ok();
                }
                (mihari_v6, mmap, current_count)
            })
            .await;
            let (returned_map, returned_pointer, returned_count) =
                task.expect("Mihari sync task panicked at v6");
            mihari_v6 = returned_map;
            if let Some(mmap) = returned_pointer {
                mmap_v6 = Some(mmap);
            }
            mihari_ipv6_count = returned_count;
        }

        interval.tick().await;
    }
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
