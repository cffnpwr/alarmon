use std::net::IpAddr;
use std::sync::Arc;

use fxhash::FxHashMap;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::ping_worker::PingWorkerError;
use super::routing_worker::{RoutingWorker, RoutingWorkerError};
use super::traceroute_worker::{TracerouteWorker, TracerouteWorkerError};
use crate::config::Config;
use crate::core::ping_worker::PingWorker;
use crate::net_utils::arp_table::ArpTable;
use crate::net_utils::neighbor_discovery::NeighborCache;
#[cfg(target_os = "linux")]
use crate::net_utils::netlink::LinkType;
use crate::net_utils::netlink::NetlinkError;
use crate::tui::models::UpdateMessage;

#[derive(Debug, Error)]
#[allow(clippy::enum_variant_names)]
pub enum WorkerPoolError {
    #[error(transparent)]
    NetworkError(#[from] NetlinkError),
    #[error(transparent)]
    PingWorkerError(#[from] PingWorkerError),
    #[error(transparent)]
    TracerouteWorkerError(#[from] TracerouteWorkerError),
    #[error(transparent)]
    RoutingWorkerError(#[from] RoutingWorkerError),
}

pub struct WorkerPool {
    ping_workers: Vec<PingWorker>,
    traceroute_workers: Vec<TracerouteWorker>,
    routing_worker: RoutingWorker,
}
impl WorkerPool {
    pub fn new(
        token: CancellationToken,
        arp_table: Arc<ArpTable>,
        neighbor_cache: Arc<NeighborCache>,
        cfg: &Config,
        targets: FxHashMap<u16, IpAddr>,
        update_sender: mpsc::Sender<UpdateMessage>,
    ) -> Self {
        // 共有チャネルの事前作成
        let (routing_tx, routing_rx) = mpsc::channel(1000);
        let mut ping_reply_senders = FxHashMap::default();
        let mut traceroute_reply_senders = FxHashMap::default();
        let mut ping_workers = Vec::new();
        let mut traceroute_workers = Vec::new();

        // 各ターゲット用のPing Worker作成
        for (&target_id, &target_ip) in &targets {
            let (reply_tx, reply_rx) = mpsc::channel(1000);
            ping_reply_senders.insert(target_ip, reply_tx);

            let ping_worker = PingWorker::new(
                token.clone(),
                target_id,
                target_ip,
                cfg.interval,
                cfg.timeout,
                routing_tx.clone(), // 共有Sender
                reply_rx,           // 専用Receiver
                update_sender.clone(),
            );

            ping_workers.push(ping_worker);
        }

        // Traceroute Workerの作成
        if cfg.traceroute.enable {
            for (&target_id, &target_ip) in &targets {
                // TracerouteのIDは基本IDから計算（重複を避けるため）
                let traceroute_id = target_id + targets.len() as u16;

                let (reply_tx, reply_rx) = mpsc::channel(1000);
                traceroute_reply_senders.insert(target_ip, reply_tx);

                let traceroute_worker = TracerouteWorker::new(
                    token.clone(),
                    traceroute_id,
                    target_ip,
                    cfg.interval,
                    cfg.traceroute.max_hops,
                    routing_tx.clone(), // 共有Sender
                    reply_rx,           // 専用Receiver
                    update_sender.clone(),
                );

                traceroute_workers.push(traceroute_worker);
            }
        }

        // Routing Worker初期化
        let routing_worker = RoutingWorker::new(
            token.clone(),
            arp_table.clone(),
            neighbor_cache.clone(),
            routing_rx,
            ping_reply_senders,
            traceroute_reply_senders,
            update_sender.clone(),
        );

        Self {
            ping_workers,
            traceroute_workers,
            routing_worker,
        }
    }

    pub async fn run(self) -> Result<(), WorkerPoolError> {
        // 全てのワーカーを並行実行
        let mut tasks = Vec::new();

        // Ping Workerの起動
        for ping_worker in self.ping_workers {
            tasks.push(tokio::spawn(async move {
                ping_worker.run().await.map_err(WorkerPoolError::from)
            }));
        }

        // Traceroute Workerの起動
        for traceroute_worker in self.traceroute_workers {
            tasks.push(tokio::spawn(async move {
                traceroute_worker.run().await.map_err(WorkerPoolError::from)
            }));
        }

        // Routing Workerの起動
        tasks.push(tokio::spawn(async move {
            self.routing_worker
                .run()
                .await
                .map_err(WorkerPoolError::from)
        }));

        // 全てのタスクが完了するまで待機
        for task in tasks {
            task.await.expect("Worker task failed")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::config::{ArpConfig, Config, TracerouteConfig};
    use crate::net_utils::arp_table::ArpTable;

    fn create_test_config() -> Config {
        Config {
            targets: vec![],
            interval: chrono::Duration::seconds(1),
            timeout: chrono::Duration::seconds(5),
            arp: ArpConfig::default(),
            traceroute: TracerouteConfig::default(),
        }
    }

    #[tokio::test]
    async fn test_worker_pool_new() {
        // [正常系] 空のターゲットでのWorkerPool作成
        {
            let token = CancellationToken::new();
            let arp_table = Arc::new(ArpTable::new(&ArpConfig::default()));
            let config = create_test_config();
            let targets = FxHashMap::default();
            let (update_tx, _update_rx) = mpsc::channel(100);

            let neighbor_cache = Arc::new(NeighborCache::new(&ArpConfig::default()));
            let worker_pool = WorkerPool::new(
                token,
                arp_table,
                neighbor_cache,
                &config,
                targets,
                update_tx,
            );
            assert!(worker_pool.ping_workers.is_empty());
        }

        // [正常系] 単一ターゲットでのWorkerPool作成
        {
            let token = CancellationToken::new();
            let arp_table = Arc::new(ArpTable::new(&ArpConfig::default()));
            let config = create_test_config();
            let mut targets = FxHashMap::default();
            targets.insert(1, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
            let (update_tx, _update_rx) = mpsc::channel(100);

            let neighbor_cache = Arc::new(NeighborCache::new(&ArpConfig::default()));
            let worker_pool = WorkerPool::new(
                token,
                arp_table,
                neighbor_cache,
                &config,
                targets,
                update_tx,
            );
            assert_eq!(worker_pool.ping_workers.len(), 1);
        }

        // [正常系] 複数ターゲットでのWorkerPool作成
        {
            let token = CancellationToken::new();
            let arp_table = Arc::new(ArpTable::new(&ArpConfig::default()));
            let config = create_test_config();
            let mut targets = FxHashMap::default();
            targets.insert(1, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
            targets.insert(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
            let (update_tx, _update_rx) = mpsc::channel(100);

            let neighbor_cache = Arc::new(NeighborCache::new(&ArpConfig::default()));
            let worker_pool = WorkerPool::new(
                token,
                arp_table,
                neighbor_cache,
                &config,
                targets,
                update_tx,
            );
            assert_eq!(worker_pool.ping_workers.len(), 2);
        }
    }
}
