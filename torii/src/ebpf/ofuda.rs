use std::path::PathBuf;

use aya::maps::{LpmTrie, MapData};
use tracing::error;
use zerocopy::FromBytes;

use crate::{
    cli::cli::BansArgs,
    delete_single,
    ebpf::kekkai_manager::{IpPrefix, Ipv4Prefix, Ipv6Prefix, save_sets_to_disk},
    insert_single, populate_map_from_disk,
};

pub struct OfudaEntry {
    pub add: Vec<String>,
    pub remove: Vec<String>,
    pub reply: tokio::sync::oneshot::Sender<Result<(), Vec<String>>>,
}

impl
    From<(
        BansArgs,
        tokio::sync::oneshot::Sender<Result<(), Vec<String>>>,
    )> for OfudaEntry
{
    fn from(
        (value, tx): (
            BansArgs,
            tokio::sync::oneshot::Sender<Result<(), Vec<String>>>,
        ),
    ) -> Self {
        Self {
            add: value.add,
            remove: value.remove,
            reply: tx,
        }
    }
}

pub async fn run(
    mut rx: tokio::sync::mpsc::Receiver<OfudaEntry>,
    mut ofuda_v4: LpmTrie<MapData, u32, u8>,
    mut ofuda_v6: LpmTrie<MapData, [u8; 16], u8>,
    ofuda_path: String,
) {
    let ofuda_path = PathBuf::from(ofuda_path);

    let path_v4 = ofuda_path.join("ofuda_v4.bin");
    let (mut ofuda_v4, mut ofuda_v4_entries) = populate_map_from_disk!(
        ofuda_v4,
        path_v4,
        Ipv4Prefix,
        125_000,
        "BLOCKLIST_V4_PREFIX",
        vec => Vec::new()
    );
    let path_v6 = ofuda_path.join("ofuda_v6.bin");
    let (mut ofuda_v6, mut ofuda_v6_entries) = populate_map_from_disk!(
        ofuda_v6,
        path_v6,
        Ipv6Prefix,
        125_000,
        "BLOCKLIST_V6_PREFIX",
        vec => Vec::new()
    );

    while let Some(entry) = rx.recv().await {
        let mut errors: Vec<String> = Vec::new();
        for ip in entry.remove {
            if let Ok(prefix) = ip.parse::<IpPrefix>() {
                match prefix {
                    IpPrefix::V4(v4) => {
                        delete_single!(ofuda_v4, v4, "BLOCKLIST_V4_PREFIX");
                        ofuda_v4_entries.retain(|&ip| ip != v4);
                    }
                    IpPrefix::V6(v6) => {
                        delete_single!(ofuda_v6, v6, "BLOCKLIST_V6_PREFIX");
                        ofuda_v6_entries.retain(|&ip| ip != v6);
                    }
                }
            } else {
                errors.push(format!("Failed to parse: {ip}"));
            }
        }
        let mut dropped_v4: u32 = 0;
        let mut dropped_v6: u32 = 0;
        for ip in entry.add {
            if let Ok(prefix) = ip.parse::<IpPrefix>() {
                match prefix {
                    IpPrefix::V4(v4) => {
                        let mut count = ofuda_v4_entries.len() as u32;
                        insert_single!(
                            ofuda_v4,
                            count,
                            125_000,
                            v4,
                            dropped_v4,
                            "BLOCKLIST_V4_PREFIX"
                        );
                        if count > ofuda_v4_entries.len() as u32 && !ofuda_v4_entries.contains(&v4)
                        {
                            ofuda_v4_entries.push(v4);
                        }
                    }
                    IpPrefix::V6(v6) => {
                        let mut count = ofuda_v6_entries.len() as u32;
                        insert_single!(
                            ofuda_v6,
                            count,
                            125_000,
                            v6,
                            dropped_v6,
                            "BLOCKLIST_V6_PREFIX"
                        );
                        if count > ofuda_v6_entries.len() as u32 && !ofuda_v6_entries.contains(&v6)
                        {
                            ofuda_v6_entries.push(v6);
                        }
                    }
                }
            } else {
                errors.push(format!("Failed to parse: {ip}"));
            }
        }
        if dropped_v4 > 0 {
            error!(
                "FIREWALL DEGRADED: BLOCKLIST_V4_PREFIX capacity reached! {dropped_v4} prefixes dropped."
            );
            errors.push(format!(
                "Dropped {dropped_v4} IPv4 prefixes (capacity reached)"
            ))
        }
        if dropped_v6 > 0 {
            error!(
                "FIREWALL DEGRADED: BLOCKLIST_V6_PREFIX capacity reached! {dropped_v6} prefixes dropped."
            );
            errors.push(format!(
                "Dropped {dropped_v6} IPv6 prefixes (capacity reached)"
            ))
        }
        ofuda_v4_entries.sort_unstable();
        ofuda_v6_entries.sort_unstable();
        let entries_v4 = ofuda_v4_entries.clone();
        let entries_v6 = ofuda_v6_entries.clone();
        let path_v4 = ofuda_path.join("ofuda_v4.bin");
        let path_v6 = ofuda_path.join("ofuda_v6.bin");
        let save_result = tokio::task::spawn_blocking(move || {
            let res_v4 = save_sets_to_disk(&entries_v4, &path_v4);
            let res_v6 = save_sets_to_disk(&entries_v6, &path_v6);
            if let Err(e) = &res_v4 {
                error!("Failed to save ofuda v4 blocklist: {e}");
            }
            if let Err(e) = &res_v6 {
                error!("Failed to save ofuda v6 blocklist: {e}");
            }
            res_v4.and(res_v6)
        })
        .await;
        if let Err(_) | Ok(Err(_)) = save_result {
            errors.push("Failed to sync updated bans to disk".to_string());
        }
        if errors.is_empty() {
            entry.reply.send(Ok(()));
        } else {
            entry.reply.send(Err(errors));
        }
    }
}
