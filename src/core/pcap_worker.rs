use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use fxhash::FxHashMap;
#[cfg(target_os = "macos")]
use libc::AF_INET;
use log::{debug, info, warn};
use pcap::{DataLinkReceiver, DataLinkSender, NetworkInterface as PcapNetworkInterface, Pcap as _};
use tcpip::ethernet::{EtherType, EthernetFrame, EthernetFrameError};
use tcpip::ipv4::{IPv4Packet, Protocol};
#[cfg(target_os = "macos")]
use tcpip::loopback::{LoopbackFrame, LoopbackFrameError};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::net_utils::arp_table::{ArpTable, ArpTableError};
use crate::net_utils::netlink::{LinkType, NetlinkError, NetworkInterface};

#[derive(Debug, Clone)]
pub struct TimestampedPacket {
    pub packet: IPv4Packet,
    pub received_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct PcapWorkerResult {
    pub worker: PcapWorker,
    pub sender: mpsc::Sender<IPv4Packet>,
    pub receivers: FxHashMap<Ipv4Addr, broadcast::Receiver<TimestampedPacket>>,
}

#[derive(Debug, Error)]
#[allow(clippy::enum_variant_names)]
pub enum PcapWorkerError {
    #[error(transparent)]
    NetworkError(#[from] NetlinkError),
    #[error(transparent)]
    ArpTableError(#[from] ArpTableError),
    #[error(transparent)]
    PcapError(#[from] pcap::PcapError),
    #[error(transparent)]
    EthernetFrameError(#[from] EthernetFrameError),
    #[cfg(target_os = "macos")]
    #[error(transparent)]
    LoopbackFrameError(#[from] LoopbackFrameError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PingTarget {
    pub(crate) id: u16,
    pub(crate) host: Ipv4Addr,
}

#[derive(Debug, Clone)]
pub(crate) struct PingTargets {
    pub(crate) ni: NetworkInterface,
    pub(crate) targets: Vec<PingTarget>,
}

pub struct DatalinkFrameReceiver {
    /// WorkerがDatalink Frameを受信するNIC
    ni: NetworkInterface,

    /// NICからDatalink Frameを受信するためのチャネル
    datalink_rx: Box<dyn DataLinkReceiver>,

    /// 上位プロトコルWorkerにIPv4パケットを送信するためのチャネル群
    ip_txs: FxHashMap<Ipv4Addr, broadcast::Sender<TimestampedPacket>>,
}

impl std::fmt::Debug for DatalinkFrameReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatalinkFrameReceiver")
            .field("ni", &self.ni)
            .field("datalink_rx", &"<DataLinkReceiver>")
            .field("ip_txs", &self.ip_txs)
            .finish()
    }
}

pub struct DatalinkFrameSender {
    /// WorkerがDatalink Frameを送信するNIC
    ni: NetworkInterface,

    /// ARPテーブル
    arp_table: Arc<ArpTable>,

    /// NICにDatalink Frameを送信するためのチャネル
    datalink_tx: Box<dyn DataLinkSender>,

    /// 上位プロトコルWorkerからIPv4パケットを受信するためのチャネル
    ip_rx: mpsc::Receiver<IPv4Packet>,
}

impl std::fmt::Debug for DatalinkFrameSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatalinkFrameSender")
            .field("ni", &self.ni)
            .field("arp_table", &self.arp_table)
            .field("datalink_tx", &"<DataLinkSender>")
            .field("ip_rx", &"<mpsc::Receiver>")
            .finish()
    }
}

#[derive(Debug)]
pub struct PcapWorker {
    token: CancellationToken,
    receiver: DatalinkFrameReceiver,
    sender: DatalinkFrameSender,
}

impl PcapWorker {
    /// NIC Workerを作成
    ///
    /// # Arguments
    /// * `token` - Worker停止用のCancellationToken
    /// * `cfg` - アプリケーションの設定
    /// * `ni` - 使用するネットワークインターフェース
    /// * `arp_table` - ARPテーブル
    /// * `target_ips` - 送信先IPアドレスのリスト
    ///
    /// # Returns
    /// * `Ok((PcapWorker, mpsc::Sender<IPv4Packet>, FxHashMap<Ipv4Addr, mpsc::Receiver<IPv4Packet>>))` - (Pcap Worker, NICへの送信用チャネル, 宛先IPアドレスごとのNICからの受信用チャネル)
    /// * `Err(PcapWorkerError)` - エラー
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        token: CancellationToken,
        cfg: &Config,
        ni: NetworkInterface,
        arp_table: Arc<ArpTable>,
        target_ips: impl AsRef<[Ipv4Addr]>,
    ) -> Result<PcapWorkerResult, PcapWorkerError> {
        let cap = PcapNetworkInterface::from(&ni).open(false)?;
        let sender: Box<dyn DataLinkSender> = cap.sender;
        let receiver: Box<dyn DataLinkReceiver> = cap.receiver;

        // 上位プロトコルWorkerとの通信チャネルを作成
        let (recv_ip_tx, recv_ip_rx) = mpsc::channel(cfg.buffer_size);
        let (send_ip_txs, send_ip_rxs) = target_ips.as_ref().iter().fold(
            (FxHashMap::default(), FxHashMap::default()),
            |(mut txs, mut rxs), &ip| {
                let (tx, rx) = broadcast::channel::<TimestampedPacket>(cfg.buffer_size);
                txs.insert(ip, tx);
                rxs.insert(ip, rx);
                (txs, rxs)
            },
        );

        let receiver = DatalinkFrameReceiver {
            ni: ni.clone(),
            datalink_rx: receiver,
            ip_txs: send_ip_txs,
        };

        let sender = DatalinkFrameSender {
            ni,
            arp_table,
            datalink_tx: sender,
            ip_rx: recv_ip_rx,
        };

        let worker = Self {
            token,
            receiver,
            sender,
        };
        Ok(PcapWorkerResult {
            worker,
            sender: recv_ip_tx,
            receivers: send_ip_rxs,
        })
    }

    pub async fn run(self) -> Result<(), PcapWorkerError> {
        let interface_name = self.sender.ni.name.clone();
        info!("Starting Pcap Worker for interface: {interface_name}");

        let token = self.token.clone();
        let ip_handle = tokio::spawn(self.sender.listen_ip_packets());
        let datalink_handle = tokio::spawn(self.receiver.listen_datalink_frames());

        tokio::select! {
            _ = token.cancelled() => {
                info!("Pcap Worker for interface {interface_name} is stopping");
            }
            _ = ip_handle => {},
            _ = datalink_handle => {},
        }

        Ok(())
    }
}

impl DatalinkFrameSender {
    async fn listen_ip_packets(mut self) -> Result<(), PcapWorkerError> {
        while let Some(pkt) = self.ip_rx.recv().await {
            if let Err(e) = self.handle_recv_ip_packet(pkt).await {
                warn!("Failed to handle received IP packet: {e}");
            }
        }
        Ok(())
    }

    async fn handle_recv_ip_packet(&mut self, pkt: IPv4Packet) -> Result<(), PcapWorkerError> {
        let frame = match self.ni.linktype {
            #[cfg(target_os = "macos")]
            LinkType::Loopback => {
                let frame = LoopbackFrame::new(AF_INET as u32, Bytes::from(pkt));
                Bytes::from(frame)
            }
            #[cfg(target_os = "linux")]
            LinkType::Loopback => {
                let ethernet_frame = EthernetFrame::new(
                    &self.ni.mac_addr,
                    &self.ni.mac_addr,
                    &EtherType::IPv4,
                    None,
                    Bytes::from(pkt),
                );
                Bytes::try_from(ethernet_frame)?
            }
            LinkType::Ethernet => {
                // ARP解決
                // 宛先IPアドレスが直接接続していなくても内部でNext Hopを解決する
                let target_mac = self.arp_table.get_or_resolve(pkt.dst).await?;

                // Ethernetフレームを作成
                let ethernet_frame = EthernetFrame::new(
                    &self.ni.mac_addr,
                    &target_mac,
                    &EtherType::IPv4,
                    None,
                    Bytes::from(pkt),
                );
                Bytes::try_from(ethernet_frame)?
            }
            LinkType::RawIP => Bytes::from(pkt),
        };

        // フレームを送信
        self.datalink_tx.send_bytes(&frame).await?;

        Ok(())
    }
}

impl DatalinkFrameReceiver {
    async fn listen_datalink_frames(mut self) -> Result<(), PcapWorkerError> {
        while let Ok(frame) = self.datalink_rx.recv().await {
            // パケット受信時刻を記録
            let received_at = Utc::now();
            if let Err(e) = self.handle_recv_datalink_frame(frame, received_at).await {
                debug!("Failed to handle received Datalink frame: {e}");
            }
        }
        Ok(())
    }

    async fn handle_recv_datalink_frame(
        &mut self,
        frame: impl AsRef<[u8]>,
        received_at: DateTime<Utc>,
    ) -> Result<(), PcapWorkerError> {
        let payload = match self.ni.linktype {
            #[cfg(target_os = "macos")]
            LinkType::Loopback => {
                // Loopbackフレームを解析
                let loopback_frame = LoopbackFrame::try_from(frame.as_ref())?;
                // IPv4パケットのみを処理
                if loopback_frame.protocol != AF_INET as u32 {
                    debug!("Loopback protocol is not IPv4: {}", loopback_frame.protocol);
                    return Ok(()); // IPv4以外は無視
                }

                loopback_frame.payload
            }
            #[cfg(target_os = "linux")]
            LinkType::Loopback => match parse_ethernet_payload(frame.as_ref()) {
                Ok(payload) => payload,
                Err(e) => {
                    debug!("Failed to parse Ethernet payload: {e}");
                    return Ok(());
                }
            },
            LinkType::Ethernet => match parse_ethernet_payload(frame.as_ref()) {
                Ok(payload) => payload,
                Err(e) => {
                    debug!("Failed to parse Ethernet payload: {e}");
                    return Ok(());
                }
            },
            LinkType::RawIP => {
                // Raw IPフレームはそのまま使用
                Bytes::copy_from_slice(frame.as_ref())
            }
        };

        // IPv4パケットを解析
        let ipv4_packet = match IPv4Packet::try_from(&payload) {
            Ok(packet) => packet,
            Err(e) => {
                warn!("Failed to parse IPv4 packet: {e}");
                return Ok(()); // 解析失敗は無視
            }
        };
        // ICMPパケットのみを転送
        if ipv4_packet.protocol != Protocol::ICMP {
            debug!("Protocol is not ICMP: {}", ipv4_packet.protocol);
            return Ok(());
        }

        // 受信時刻付きパケットを作成
        let timestamped_packet = TimestampedPacket {
            packet: ipv4_packet.clone(),
            received_at,
        };

        // 上位プロトコルWorkerにIPv4パケットを送信
        if let Some(tx) = self.ip_txs.get(&ipv4_packet.src) {
            // 送信元IPアドレスに対応するWorkerが存在する場合（通常のEcho Reply）
            let _ = tx.send(timestamped_packet); // broadcast::send は Result<usize, SendError<T>> を返すが、受信者がいない場合も正常とする
        } else {
            // 送信元IPアドレスに対応するWorkerが存在しない場合（tracerouteのTime Exceededなど）
            // 全てのWorkerに送信
            for tx in self.ip_txs.values() {
                let _ = tx.send(timestamped_packet.clone());
            }
        }

        Ok(())
    }
}

fn parse_ethernet_payload(frame: &[u8]) -> Result<Bytes, Box<dyn std::error::Error + Send + Sync>> {
    // Ethernetフレームを解析
    let ethernet_frame = EthernetFrame::try_from(frame)?;

    // IPv4パケットのみを処理
    if ethernet_frame.ether_type != EtherType::IPv4 {
        return Err("EtherType is not IPv4".into());
    }

    Ok(ethernet_frame.payload)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use async_trait::async_trait;
    use mockall::mock;
    use tcpip::ethernet::MacAddr;
    use tcpip::icmp::ICMPMessage;
    use tcpip::ip_cidr::{IPCIDR, IPv4CIDR};
    use tcpip::ipv4::{Flags, TypeOfService};
    use tokio::time::timeout;
    use tokio_test::assert_ok;

    use super::*;
    use crate::config::ArpConfig;
    use crate::net_utils::netlink::LinkType;

    // テスト用のモック構造体
    mock! {
        Sender {}

        #[async_trait]
        impl DataLinkSender for Sender {
            async fn send_bytes(&mut self, buf: &[u8]) -> Result<(), pcap::PcapError>;
        }
    }

    mock! {
        Receiver {}

        #[async_trait]
        impl DataLinkReceiver for Receiver {
            async fn recv(&mut self) -> Result<Vec<u8>, pcap::PcapError>;
        }
    }

    fn create_test_network_interface() -> NetworkInterface {
        let mac_addr = MacAddr::try_from("00:11:22:33:44:55").unwrap();
        let ipv4_cidr =
            IPv4CIDR::new_with_prefix_length(Ipv4Addr::new(192, 168, 1, 100), &24).unwrap();

        NetworkInterface {
            index: 1,
            name: "eth0".to_string(),
            ip_addrs: vec![IPCIDR::V4(ipv4_cidr)],
            mac_addr,
            linktype: LinkType::Ethernet,
        }
    }

    #[test]
    fn test_ping_targets() {
        // [正常系] PingTargetsの作成
        let ni = create_test_network_interface();
        let targets = vec![
            PingTarget {
                id: 1,
                host: Ipv4Addr::new(192, 168, 1, 1),
            },
            PingTarget {
                id: 2,
                host: Ipv4Addr::new(192, 168, 1, 2),
            },
        ];

        let ping_targets = PingTargets {
            ni: ni.clone(),
            targets: targets.clone(),
        };

        assert_eq!(ping_targets.ni.index, ni.index);
        assert_eq!(ping_targets.ni.name, ni.name);
        assert_eq!(ping_targets.targets, targets);
    }

    #[test]
    fn test_ethernet_frame_receiver() {
        // [正常系] DatalinkFrameReceiverの作成
        let ni = create_test_network_interface();
        let mut ip_txs = FxHashMap::default();
        let target_ip = Ipv4Addr::new(192, 168, 1, 1);
        let (tx, _rx) = broadcast::channel(100);
        ip_txs.insert(target_ip, tx);

        let mock_receiver = Box::new(MockReceiver::new());

        let receiver = DatalinkFrameReceiver {
            ni: ni.clone(),
            datalink_rx: mock_receiver,
            ip_txs,
        };

        assert_eq!(receiver.ni.index, ni.index);
        assert_eq!(receiver.ni.name, ni.name);
        assert!(receiver.ip_txs.contains_key(&target_ip));
    }

    #[test]
    fn test_ethernet_frame_sender() {
        // [正常系] DatalinkFrameSenderの作成
        let ni = create_test_network_interface();
        let arp_table = Arc::new(ArpTable::new(&ArpConfig::default()));
        let mock_sender = Box::new(MockSender::new());
        let (_tx, rx) = mpsc::channel(100);

        let sender = DatalinkFrameSender {
            ni: ni.clone(),
            arp_table: arp_table.clone(),
            datalink_tx: mock_sender,
            ip_rx: rx,
        };

        assert_eq!(sender.ni.index, ni.index);
        assert_eq!(sender.ni.name, ni.name);
    }

    #[tokio::test]
    async fn test_ethernet_frame_receiver_handle_recv_ethernet_frame() {
        // [正常系] IPv4 ICMPパケットの処理
        let ni = create_test_network_interface();
        let mut ip_txs = FxHashMap::default();
        let target_ip = Ipv4Addr::new(192, 168, 1, 1);
        let (tx, mut rx) = broadcast::channel(100);
        ip_txs.insert(target_ip, tx);

        let mock_receiver = Box::new(MockReceiver::new());

        let mut receiver = DatalinkFrameReceiver {
            ni,
            datalink_rx: mock_receiver,
            ip_txs,
        };

        // テスト用のICMP Echo Replyパケットを作成
        let icmp_msg = ICMPMessage::echo_reply(12345, 1, vec![0; 32]);
        let icmp_bytes: Bytes = icmp_msg.into();
        let ipv4_packet = IPv4Packet::new(
            TypeOfService::default(),
            54321,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            target_ip,
            Ipv4Addr::new(192, 168, 1, 100),
            Vec::new(),
            icmp_bytes.clone(),
        );

        // Ethernetフレームを作成
        let src_mac = MacAddr::try_from("aa:bb:cc:dd:ee:ff").unwrap();
        let dst_mac = MacAddr::try_from("00:11:22:33:44:55").unwrap();
        let ethernet_frame = EthernetFrame::new(
            &src_mac,
            &dst_mac,
            &EtherType::IPv4,
            None,
            Vec::<u8>::from(ipv4_packet.clone()),
        );

        let frame_bytes = Vec::<u8>::try_from(ethernet_frame).unwrap();

        // テスト実行
        let received_at = chrono::Utc::now();
        let result = receiver
            .handle_recv_datalink_frame(frame_bytes, received_at)
            .await;
        assert_ok!(result);

        // 受信されたパケットを確認
        let received_packet = rx.recv().await.unwrap();
        assert_eq!(received_packet.packet.src, ipv4_packet.src);
        assert_eq!(received_packet.packet.dst, ipv4_packet.dst);
        assert_eq!(received_packet.packet.protocol, Protocol::ICMP);

        // [正常系] 非IPv4パケットの無視
        let arp_frame = EthernetFrame::new(
            &src_mac,
            &dst_mac,
            &EtherType::ARP,
            None,
            vec![0; 28], // 最小ARPパケットサイズ
        );

        let arp_frame_bytes = Vec::<u8>::try_from(arp_frame).unwrap();
        let result = receiver
            .handle_recv_datalink_frame(arp_frame_bytes, received_at)
            .await;
        assert_ok!(result);

        // パケットが受信されていないことを確認
        assert!(rx.try_recv().is_err());

        // [正常系] 非ICMPパケットの無視
        let tcp_packet = IPv4Packet::new(
            TypeOfService::default(),
            54321,
            Flags::default(),
            0,
            64,
            Protocol::TCP,
            target_ip,
            Ipv4Addr::new(192, 168, 1, 100),
            Vec::new(),
            Bytes::from(vec![0; 20]), // 最小TCPヘッダ
        );

        let tcp_frame = EthernetFrame::new(
            &src_mac,
            &dst_mac,
            &EtherType::IPv4,
            None,
            Vec::<u8>::from(tcp_packet),
        );

        let tcp_frame_bytes = Vec::<u8>::try_from(tcp_frame).unwrap();
        let result = receiver
            .handle_recv_datalink_frame(tcp_frame_bytes, received_at)
            .await;
        assert_ok!(result);

        // パケットが受信されていないことを確認
        assert!(rx.try_recv().is_err());

        // [異常系] 送信先チャネルが存在しない場合
        let unknown_ip = Ipv4Addr::new(10, 0, 0, 1);
        let unknown_packet = IPv4Packet::new(
            TypeOfService::default(),
            54321,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            unknown_ip,
            Ipv4Addr::new(192, 168, 1, 100),
            Vec::new(),
            icmp_bytes,
        );

        let unknown_frame = EthernetFrame::new(
            &src_mac,
            &dst_mac,
            &EtherType::IPv4,
            None,
            Vec::<u8>::from(unknown_packet),
        );

        let unknown_frame_bytes = Vec::<u8>::try_from(unknown_frame).unwrap();
        let result = receiver
            .handle_recv_datalink_frame(unknown_frame_bytes, received_at)
            .await;
        // 修正後は未知のIPアドレスからのパケットも全receiverに送信されるためエラーにならない
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_nic_worker_run() {
        // [正常系] PcapWorkerの実行とキャンセレーション
        let token = CancellationToken::new();
        let ni = create_test_network_interface();
        let arp_table = Arc::new(ArpTable::new(&ArpConfig::default()));
        let targets = [Ipv4Addr::new(192, 168, 1, 1)];

        let mock_sender = Box::new(MockSender::new());
        let mock_receiver = Box::new(MockReceiver::new());
        let (_tx, rx) = mpsc::channel(100);

        let sender = DatalinkFrameSender {
            ni: ni.clone(),
            arp_table: arp_table.clone(),
            datalink_tx: mock_sender,
            ip_rx: rx,
        };

        let mut ip_txs = FxHashMap::default();
        let (tx, _rx) = broadcast::channel(100);
        ip_txs.insert(targets[0], tx);

        let receiver = DatalinkFrameReceiver {
            ni: ni.clone(),
            datalink_rx: mock_receiver,
            ip_txs,
        };

        let worker = PcapWorker {
            token: token.clone(),
            receiver,
            sender,
        };

        // ワーカーを短時間実行してからキャンセル
        let run_handle = tokio::spawn(worker.run());
        tokio::time::sleep(Duration::from_millis(10)).await;
        token.cancel();

        let result = timeout(Duration::from_millis(100), run_handle).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_ethernet_frame_sender_listen_ip_packets() {
        // [正常系] IPパケット受信処理のテスト
        let ni = create_test_network_interface();
        let arp_table = Arc::new(ArpTable::new(&ArpConfig::default()));
        let (tx, rx) = mpsc::channel(100);

        let mut mock_sender = MockSender::new();
        mock_sender.expect_send_bytes().returning(|_| Ok(()));

        let sender = DatalinkFrameSender {
            ni,
            arp_table,
            datalink_tx: Box::new(mock_sender),
            ip_rx: rx,
        };

        // IPパケットを送信
        let ipv4_packet = IPv4Packet::new(
            TypeOfService::default(),
            12345,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 1),
            Vec::new(),
            bytes::Bytes::from(vec![0; 32]),
        );

        tx.send(ipv4_packet).await.unwrap();
        drop(tx); // チャネルを閉じる

        let sender = sender;
        let result = sender.listen_ip_packets().await;
        assert_ok!(result);
    }

    #[tokio::test]
    async fn test_ethernet_frame_sender_handle_recv_ip_packet() {
        // [正常系] IPパケットの処理とEthernetフレーム送信
        let ni = create_test_network_interface();
        let arp_table = Arc::new(ArpTable::new(&ArpConfig::default()));
        let (_tx, rx) = mpsc::channel(100);

        // 宛先IPアドレスとMACアドレスを事前にARPテーブルに追加
        let target_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_mac = MacAddr::try_from("aa:bb:cc:dd:ee:ff").unwrap();

        // ARPテーブルにエントリを直接追加（テスト用）
        arp_table.insert_for_test(target_ip, target_mac);

        let mut mock_sender = MockSender::new();
        mock_sender
            .expect_send_bytes()
            .times(1)
            .returning(|_| Ok(()));

        let sender = DatalinkFrameSender {
            ni,
            arp_table,
            datalink_tx: Box::new(mock_sender),
            ip_rx: rx,
        };

        let ipv4_packet = IPv4Packet::new(
            TypeOfService::default(),
            12345,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            Ipv4Addr::new(192, 168, 1, 100),
            target_ip,
            Vec::new(),
            Bytes::from(vec![0; 32]),
        );

        let mut sender = sender;
        let result = sender.handle_recv_ip_packet(ipv4_packet).await;
        assert_ok!(result);
    }

    #[tokio::test]
    async fn test_ethernet_frame_receiver_listen_ethernet_frames() {
        // [正常系] Ethernetフレーム受信処理のテスト
        let ni = create_test_network_interface();
        let mut ip_txs = FxHashMap::default();
        let target_ip = Ipv4Addr::new(192, 168, 1, 1);
        let (tx, _rx) = broadcast::channel(100);
        ip_txs.insert(target_ip, tx);

        let mut mock_receiver = MockReceiver::new();
        mock_receiver
            .expect_recv()
            .times(1)
            .returning(|| Ok(vec![0; 14])); // 最小Ethernetフレームサイズ

        let receiver = DatalinkFrameReceiver {
            ni,
            datalink_rx: Box::new(mock_receiver),
            ip_txs,
        };

        // 短時間フレーム受信処理を実行
        let handle = tokio::spawn(receiver.listen_datalink_frames());
        tokio::time::sleep(Duration::from_millis(10)).await;
        handle.abort(); // タスクを中止
        let _ = handle.await; // 結果は無視（中止されるため）
    }
}
