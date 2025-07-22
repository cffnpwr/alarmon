use std::sync::Arc;

use anyhow::Result;
use fxhash::FxHashMap;
use itertools::Itertools;
use log::info;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
pub use worker_pool::WorkerPool;

use crate::config::{Config, TargetHost};
use crate::net_utils::arp_table::ArpTable;
use crate::net_utils::neighbor_discovery::NeighborCache;
use crate::tui::models::UpdateMessage;

pub mod pcap_worker;
pub mod ping_worker;
pub mod routing_worker;
pub mod traceroute_worker;
pub mod worker_pool;

pub(crate) async fn run_ping_monitoring(
    token: CancellationToken,
    config: &Config,
    update_sender: mpsc::Sender<UpdateMessage>,
) -> Result<()> {
    let mut targets = FxHashMap::default();
    for target_config in &config.targets {
        let id = target_config.id;
        let target_ip = match target_config.host {
            TargetHost::IpAddress(ip_addr) => ip_addr,
            TargetHost::Domain(_) => {
                // ドメイン名からIPアドレスを解決する処理を追加
                todo!()
            }
        };
        targets.insert(id, target_ip);
    }
    info!(
        "Starting ping monitoring for targets: [{}]",
        targets.values().join(", ")
    );

    // ARP Tableの初期化
    let arp_table = Arc::new(ArpTable::new(&config.arp));
    // Neighbor Cacheの初期化
    let neighbor_cache = Arc::new(NeighborCache::new(&config.arp));
    // Worker Poolを初期化
    let pool = WorkerPool::new(
        token.clone(),
        arp_table,
        neighbor_cache,
        config,
        targets,
        update_sender,
    );
    // Woker Poolを起動
    let _ = pool.run().await;

    Ok(())
}
