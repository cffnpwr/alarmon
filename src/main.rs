use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use env_logger::Env;
use fxhash::FxHashMap;
use itertools::Itertools;
use log::{info, warn};
use tokio::signal::ctrl_c;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::cli::Cli;
use crate::config::Config;
use crate::net_utils::arp_table::ArpTable;
use crate::net_utils::netlink::{LinkType, Netlink};
use crate::network::WorkerPool;
use crate::network::nic_worker::PingTargets;

mod cli;
mod config;
mod net_utils;
mod network;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    let cli = Cli::parse();
    let cfg = Config::load(&cli.config)?;

    // 設定から複数のpingターゲットを作成
    // NICのindexをキー
    let mut ping_targets_by_ni = FxHashMap::<u32, PingTargets>::default();
    for target_config in &cfg.targets {
        let target_ip = Ipv4Addr::from_str(&target_config.host)?;

        // LinkTypeを確認（Ethernetのみサポート）
        // TODO: RawIP, Loopbackのサポート [Issue #17](https://github.com/cffnpwr/alarmon/issues/17)
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
    let arp_table = Arc::new(ArpTable::new(&cfg.arp));
    // Worker Poolを初期化
    let token = CancellationToken::new();
    let pool = WorkerPool::new(token.clone(), arp_table, &cfg, &ping_targets_by_ni)?;

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
