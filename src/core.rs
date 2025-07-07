use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use fxhash::FxHashMap;
use itertools::Itertools;
use log::{info, warn};
use tokio::signal::ctrl_c;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::net_utils::arp_table::ArpTable;
use crate::net_utils::netlink::{LinkType, Netlink};
use crate::tui::models::UpdateMessage;

pub mod pcap_worker;
pub mod ping_worker;
pub mod traceroute_worker;
pub mod worker_pool;

pub use pcap_worker::PingTargets;
pub use worker_pool::WorkerPool;

pub async fn run_ping_monitoring_with_tui(
    config: Config,
    update_sender: mpsc::Sender<UpdateMessage>,
) -> Result<()> {
    // TUIモードではenv_loggerを無効化（TUI画面と被らないように）

    // 設定から複数のpingターゲットを作成
    let mut ping_targets_by_ni = FxHashMap::<u32, PingTargets>::default();
    for target_config in &config.targets {
        let target_ip = Ipv4Addr::from_str(&target_config.host)?;

        // LinkTypeを確認（Ethernetのみサポート）
        let netlink = Netlink::new()?;
        let route = netlink.get_route(target_ip)?;
        if route.link_type == LinkType::RawIP {
            warn!("{} is not supported LinkType.", route.interface.name);
            continue;
        }

        let ping_targets = ping_targets_by_ni
            .entry(route.interface.index)
            .or_insert(PingTargets {
                ni: route.interface.clone(),
                targets: Vec::new(),
            });
        ping_targets.targets.push(target_ip);
    }
    info!(
        "ping targets: [{}]",
        ping_targets_by_ni
            .values()
            .flat_map(|t| t.targets.clone())
            .map(|ip| ip.to_string())
            .join(", ")
    );

    // ARP Tableの初期化
    let arp_table = Arc::new(ArpTable::new(&config.arp));
    // Worker Poolを初期化
    let token = CancellationToken::new();
    let pool = WorkerPool::new(
        token.clone(),
        arp_table,
        &config,
        &ping_targets_by_ni,
        Some(update_sender),
    )?;

    let _ctrl_c_handle = ctrl_c_handler(token.clone());
    let _ = pool.run().await;

    Ok(())
}

fn ctrl_c_handler(token: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        ctrl_c().await.expect("Failed to listen for Ctrl+C");
        println!();
        info!("Ctrl + C received, shutting down...");
        token.cancel();
    })
}
