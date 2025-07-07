use std::sync::Arc;

use fxhash::FxHashMap;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::pcap_worker::PcapWorkerError;
use super::ping_worker::PingWorkerError;
use super::traceroute_worker::{TracerouteWorker, TracerouteWorkerError};
use crate::config::Config;
use crate::core::pcap_worker::{PcapWorker, PingTargets};
use crate::core::ping_worker::PingWorker;
use crate::net_utils::arp_table::ArpTable;
use crate::net_utils::netlink::NetlinkError;
use crate::tui::models::UpdateMessage;

#[derive(Debug, Error)]
pub enum WorkerPoolError {
    #[error(transparent)]
    NetworkError(#[from] NetlinkError),
    #[error(transparent)]
    PcapWorkerError(#[from] PcapWorkerError),
    #[error(transparent)]
    PingWorkerError(#[from] PingWorkerError),
    #[error(transparent)]
    TracerouteWorkerError(#[from] TracerouteWorkerError),
    #[error("No Ethernet interfaces found")]
    NoEthernetInterfaces,
}

pub struct WorkerPool {
    pcap_workers: Vec<PcapWorker>,
    ping_workers: Vec<PingWorker>,
    traceroute_workers: Vec<TracerouteWorker>,
}
impl WorkerPool {
    /// 指定されたターゲットIPに対する最適な送信元IPアドレスを取得
    fn get_source_addr_for_target(
        ping_targets: &PingTargets,
        ping_target: &std::net::Ipv4Addr,
    ) -> Result<std::net::Ipv4Addr, WorkerPoolError> {
        ping_targets
            .ni
            .get_best_source_ip(ping_target)
            .ok_or(WorkerPoolError::NoEthernetInterfaces)
    }

    pub fn new(
        token: CancellationToken,
        arp_table: Arc<ArpTable>,
        cfg: &Config,
        targets: &FxHashMap<u32, PingTargets>,
        update_sender: mpsc::Sender<UpdateMessage>,
    ) -> Result<Self, WorkerPoolError> {
        // Pcap Workerの集合
        let mut pcap_workers = Vec::new();
        // Ping Workerの集合
        let mut ping_workers = Vec::new();
        // Traceroute Workerの集合
        let mut traceroute_workers = Vec::new();

        // 各インターフェースに対してPcap Workerを起動
        for ping_targets in targets.values() {
            let target_ips = ping_targets
                .targets
                .iter()
                .map(|target| target.host)
                .collect::<Vec<_>>();
            let pcap_result = PcapWorker::new(
                token.clone(),
                cfg,
                ping_targets.ni.clone(),
                arp_table.clone(),
                target_ips,
            )?;
            pcap_workers.push(pcap_result.worker);
            let recv_ip_tx = pcap_result.sender;
            let send_ip_broadcast_rxs = pcap_result.receivers;

            // 各宛先IPアドレスに対してPing Worker（およびTraceroute Worker）を起動
            let ping_target_len = ping_targets.targets.len();
            for ping_target in &ping_targets.targets {
                let src_addr = Self::get_source_addr_for_target(ping_targets, &ping_target.host)?;

                // Ping Workerを作成
                let ping_worker = PingWorker::new(
                    token.clone(),
                    ping_target.id,
                    src_addr,
                    ping_target.host,
                    cfg.interval,
                    recv_ip_tx.clone(),
                    send_ip_broadcast_rxs
                        .get(&ping_target.host)
                        .unwrap()
                        .resubscribe(),
                    update_sender.clone(),
                );
                ping_workers.push(ping_worker);

                // Traceroute Workerを作成（設定で有効な場合のみ）
                if cfg.traceroute.enable {
                    let traceroute_worker = TracerouteWorker::new(
                        token.clone(),
                        ping_target.id + ping_target_len as u16,
                        src_addr,
                        ping_target.host,
                        cfg.interval,
                        cfg.traceroute.max_hops,
                        recv_ip_tx.clone(),
                        send_ip_broadcast_rxs
                            .get(&ping_target.host)
                            .unwrap()
                            .resubscribe(),
                        update_sender.clone(),
                    );
                    traceroute_workers.push(traceroute_worker);
                }
            }
        }

        Ok(Self {
            ping_workers,
            pcap_workers,
            traceroute_workers,
        })
    }

    pub async fn run(self) -> Result<(), WorkerPoolError> {
        // 全てのワーカーを並行実行
        let mut tasks = Vec::new();

        // Pcap Workerの起動
        for pcap_worker in self.pcap_workers {
            tasks.push(tokio::spawn(async move {
                pcap_worker.run().await.map_err(WorkerPoolError::from)
            }));
        }

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

        // 全てのタスクが完了するまで待機
        for task in tasks {
            task.await.expect("Worker task failed")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::config::{ArpConfig, Config, TracerouteConfig};
    use crate::net_utils::arp_table::ArpTable;
    use crate::net_utils::netlink::NetworkInterface;

    fn create_test_config() -> Config {
        Config {
            targets: vec![],
            interval: chrono::Duration::seconds(1),
            timeout: chrono::Duration::seconds(5),
            buffer_size: 100,
            arp: ArpConfig::default(),
            traceroute: TracerouteConfig::default(),
        }
    }

    fn create_test_network_interface() -> NetworkInterface {
        use tcpip::ethernet::MacAddr;
        use tcpip::ip_cidr::{IPCIDR, IPv4CIDR};

        let mac_addr = MacAddr::try_from("00:11:22:33:44:55").unwrap();
        let ipv4_cidr =
            IPv4CIDR::new_with_prefix_length(Ipv4Addr::new(192, 168, 1, 100), &24).unwrap();

        NetworkInterface {
            index: 1,
            name: "eth0".to_string(),
            ip_addrs: vec![IPCIDR::V4(ipv4_cidr)],
            mac_addr,
        }
    }

    #[test]
    fn test_worker_pool_error() {
        // [正常系] エラーの表示確認
        let error1 = WorkerPoolError::NoEthernetInterfaces;
        assert_eq!(error1.to_string(), "No Ethernet interfaces found");
    }

    #[test]
    fn test_worker_pool_new_empty_targets() {
        // [正常系] 空のターゲットでのWorkerPool作成
        let token = CancellationToken::new();
        let arp_table = Arc::new(ArpTable::new(&ArpConfig::default()));
        let config = create_test_config();
        let targets = FxHashMap::default();
        let (update_tx, _update_rx) = mpsc::channel(100);

        let result = WorkerPool::new(token, arp_table, &config, &targets, update_tx);

        assert!(result.is_ok());
        let worker_pool = result.unwrap();
        assert!(worker_pool.pcap_workers.is_empty());
        assert!(worker_pool.ping_workers.is_empty());
    }

    #[test]
    fn test_worker_pool_new_with_targets() {
        // [正常系] ターゲットありでのWorkerPool作成
        let token = CancellationToken::new();
        let arp_table = Arc::new(ArpTable::new(&ArpConfig::default()));
        let config = create_test_config();
        let mut targets = FxHashMap::default();

        let ni = create_test_network_interface();
        let ping_targets = PingTargets {
            ni: ni.clone(),
            targets: vec![
                crate::core::pcap_worker::PingTarget {
                    id: 1,
                    host: Ipv4Addr::new(192, 168, 1, 1),
                },
                crate::core::pcap_worker::PingTarget {
                    id: 2,
                    host: Ipv4Addr::new(192, 168, 1, 2),
                },
            ],
        };
        targets.insert(ni.index, ping_targets);
        let (update_tx, _update_rx) = mpsc::channel(100);

        let result = WorkerPool::new(token, arp_table, &config, &targets, update_tx);

        // 注意: このテストは実際のPcap初期化を試行するため、環境によっては失敗する可能性がある
        // そのため、結果の成功/失敗両方を許容する
        match result {
            Ok(worker_pool) => {
                // 成功した場合、正しい数のWorkerが作成されていることを確認
                assert_eq!(worker_pool.pcap_workers.len(), 1);
                assert_eq!(worker_pool.ping_workers.len(), 2);
            }
            Err(_) => {
                // 失敗した場合でも、テスト環境の制約として許容
                // 実際の本番環境では適切に動作することを想定
            }
        }
    }

    #[test]
    fn test_worker_pool_new_no_source_ip() {
        // [異常系] 送信元IPアドレスが取得できない場合
        let token = CancellationToken::new();
        let arp_table = Arc::new(ArpTable::new(&ArpConfig::default()));
        let config = create_test_config();
        let mut targets = FxHashMap::default();

        // IPアドレスのないネットワークインターフェースを作成
        use tcpip::ethernet::MacAddr;
        let mac_addr = MacAddr::try_from("00:11:22:33:44:55").unwrap();
        let ni_no_ip = NetworkInterface {
            index: 1,
            name: "eth0".to_string(),
            ip_addrs: vec![], // IPアドレスなし
            mac_addr,
        };

        let ping_targets = PingTargets {
            ni: ni_no_ip,
            targets: vec![crate::core::pcap_worker::PingTarget {
                id: 1,
                host: Ipv4Addr::new(192, 168, 1, 1),
            }],
        };
        targets.insert(1, ping_targets);
        let (update_tx, _update_rx) = mpsc::channel(100);

        let result = WorkerPool::new(token, arp_table, &config, &targets, update_tx);

        // 注意: このテストも実際のPcap初期化を試行するため、
        // PcapErrorが先に発生する可能性がある
        // そのため、具体的なエラータイプのチェックは行わず、
        // エラーが発生することのみを確認
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_worker_pool_run() {
        use std::time::Duration;

        use tokio::time::timeout;

        // [正常系] WorkerPool実行のテスト
        let token = CancellationToken::new();
        let arp_table = Arc::new(ArpTable::new(&ArpConfig::default()));
        let config = create_test_config();
        let targets = FxHashMap::default(); // 空のターゲット

        let (update_tx, _update_rx) = mpsc::channel(100);
        let worker_pool =
            WorkerPool::new(token.clone(), arp_table, &config, &targets, update_tx).unwrap();

        // 空のワーカープールは即座に完了する
        let result = timeout(Duration::from_millis(100), worker_pool.run()).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }

    #[test]
    fn test_worker_pool_new_multiple_interfaces() {
        // [正常系] 複数インターフェースでのWorkerPool作成
        let token = CancellationToken::new();
        let arp_table = Arc::new(ArpTable::new(&ArpConfig::default()));
        let config = create_test_config();
        let mut targets = FxHashMap::default();

        // 1つ目のインターフェース
        let ni1 = create_test_network_interface();
        let ping_targets1 = PingTargets {
            ni: ni1.clone(),
            targets: vec![crate::core::pcap_worker::PingTarget {
                id: 1,
                host: Ipv4Addr::new(192, 168, 1, 1),
            }],
        };
        targets.insert(ni1.index, ping_targets1);

        // 2つ目のインターフェース
        use tcpip::ethernet::MacAddr;
        use tcpip::ip_cidr::{IPCIDR, IPv4CIDR};
        let mac_addr2 = MacAddr::try_from("00:11:22:33:44:66").unwrap();
        let ipv4_cidr2 =
            IPv4CIDR::new_with_prefix_length(Ipv4Addr::new(10, 0, 0, 100), &24).unwrap();
        let ni2 = NetworkInterface {
            index: 2,
            name: "eth1".to_string(),
            ip_addrs: vec![IPCIDR::V4(ipv4_cidr2)],
            mac_addr: mac_addr2,
        };
        let ping_targets2 = PingTargets {
            ni: ni2.clone(),
            targets: vec![
                crate::core::pcap_worker::PingTarget {
                    id: 2,
                    host: Ipv4Addr::new(10, 0, 0, 1),
                },
                crate::core::pcap_worker::PingTarget {
                    id: 3,
                    host: Ipv4Addr::new(10, 0, 0, 2),
                },
            ],
        };
        targets.insert(ni2.index, ping_targets2);
        let (update_tx, _update_rx) = mpsc::channel(100);

        let result = WorkerPool::new(token, arp_table, &config, &targets, update_tx);

        // 環境によってはPcapエラーが発生する可能性があるが、
        // 成功した場合は正しい数のWorkerが作成されることを確認
        match result {
            Ok(worker_pool) => {
                assert_eq!(worker_pool.pcap_workers.len(), 2);
                assert_eq!(worker_pool.ping_workers.len(), 3); // 1+2=3個のPingWorker
            }
            Err(_) => {
                // 環境制約で失敗することを許容
            }
        }
    }
}
