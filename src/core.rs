use std::sync::Arc;

use anyhow::Result;
use fxhash::FxHashMap;
use log::info;
use pcap_worker::{PingTarget, PingTargets};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
pub use worker_pool::WorkerPool;

use crate::config::{Config, TargetHost};
use crate::net_utils::arp_table::ArpTable;
use crate::net_utils::neighbor_discovery::NeighborCache;
use crate::net_utils::netlink::Netlink;
use crate::tui::models::UpdateMessage;

pub mod pcap_worker;
pub mod ping_worker;
pub mod traceroute_worker;
pub mod worker_pool;

pub async fn run_ping_monitoring(
    token: CancellationToken,
    config: &Config,
    update_sender: mpsc::Sender<UpdateMessage>,
) -> Result<()> {
    // 設定から複数のpingターゲットを作成
    let mut ping_targets_by_ni = FxHashMap::<u32, PingTargets>::default();
    for target_config in &config.targets {
        let id = target_config.id;
        let target_ip = match target_config.host {
            TargetHost::IpAddress(ip_addr) => ip_addr,
            TargetHost::Domain(_) => {
                // ドメイン名からIPアドレスを解決する処理を追加
                todo!()
            }
        };

        // LinkTypeを確認
        let netlink = Netlink::new().await?;
        #[cfg(target_os = "linux")]
        let mut netlink = netlink;
        let route = netlink.get_route(target_ip).await?;

        let ping_targets = ping_targets_by_ni
            .entry(route.interface.index)
            .or_insert(PingTargets {
                ni: route.interface.clone(),
                targets: Vec::new(),
            });
        ping_targets.targets.push(PingTarget {
            id,
            host: target_ip,
        });
    }

    // 設定ファイルの順序を保持してターゲットを表示
    let ordered_targets: Vec<String> = config
        .targets
        .iter()
        .map(|target| target.host.to_string())
        .collect();
    info!("ping targets: [{}]", ordered_targets.join(", "));

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
        &ping_targets_by_ni,
        update_sender,
    )?;
    // Woker Poolを起動
    let _ = pool.run().await;

    Ok(())
}
