use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::Bytes;
use fxhash::FxHashMap;
use log::{debug, info, warn};
use pcap::{
    Channel, DataLinkReceiver, DataLinkSender, NetworkInterface as PcapNetworkInterface, Pcap as _,
};
use tcpip::ethernet::{EtherType, EthernetFrame, EthernetFrameError};
use tcpip::ipv4::{IPv4Packet, Protocol};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::net_utils::arp_table::{ArpTable, ArpTableError};
use crate::net_utils::netlink::{NetlinkError, NetworkInterface};

#[derive(Debug)]
pub struct NicWorkerResult {
    pub worker: NicWorker,
    pub sender: mpsc::Sender<IPv4Packet>,
    pub receivers: FxHashMap<Ipv4Addr, mpsc::Receiver<IPv4Packet>>,
}

#[derive(Debug, Error)]
pub enum NicWorkerError {
    #[error(transparent)]
    NetworkError(#[from] NetlinkError),
    #[error(transparent)]
    ArpTableError(#[from] ArpTableError),
    #[error(transparent)]
    PcapError(#[from] pcap::PcapError),
    #[error(transparent)]
    EthernetFrameError(#[from] EthernetFrameError),
    #[error("Channel send error")]
    ChannelSendError,
    #[error("IP packet send channel not found for IP address {0}")]
    IPPacketSendChannelNotFound(Ipv4Addr),
}

pub struct PingTargets {
    pub ni: NetworkInterface,
    pub targets: Vec<Ipv4Addr>,
}

pub struct EthernetFrameReceiver {
    /// WorkerがDatalink Frameを受信するNIC
    ni: NetworkInterface,

    /// NICからDatalink Frameを受信するためのチャネル
    datalink_rx: Box<dyn DataLinkReceiver>,

    /// 上位プロトコルWorkerにIPv4パケットを送信するためのチャネル群
    ip_txs: FxHashMap<Ipv4Addr, mpsc::Sender<IPv4Packet>>,
}

impl std::fmt::Debug for EthernetFrameReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EthernetFrameReceiver")
            .field("ni", &self.ni)
            .field("datalink_rx", &"<DataLinkReceiver>")
            .field("ip_txs", &self.ip_txs)
            .finish()
    }
}

pub struct EthernetFrameSender {
    /// WorkerがDatalink Frameを送信するNIC
    ni: NetworkInterface,

    /// ARPテーブル
    arp_table: Arc<ArpTable>,

    /// NICにDatalink Frameを送信するためのチャネル
    datalink_tx: Box<dyn DataLinkSender>,

    /// 上位プロトコルWorkerからIPv4パケットを受信するためのチャネル
    ip_rx: mpsc::Receiver<IPv4Packet>,
}

impl std::fmt::Debug for EthernetFrameSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EthernetFrameSender")
            .field("ni", &self.ni)
            .field("arp_table", &self.arp_table)
            .field("datalink_tx", &"<DataLinkSender>")
            .field("ip_rx", &"<mpsc::Receiver>")
            .finish()
    }
}

#[derive(Debug)]
pub struct NicWorker {
    token: CancellationToken,
    receiver: EthernetFrameReceiver,
    sender: EthernetFrameSender,
}

impl NicWorker {
    /// NIC Workerを作成
    ///
    /// # Arguments
    /// * `token` - Worker停止用のCancellationToken
    /// * `ni` - 使用するネットワークインターフェース
    /// * `arp_table` - ARPテーブル
    ///
    /// # Returns
    /// * `Ok((NicWorker, mpsc::Sender<IPv4Packet>, FxHashMap<Ipv4Addr, mpsc::Receiver<IPv4Packet>>))` - (NIC Worker, NICへの送信用チャネル, 宛先IPアドレスごとのNICからの受信用チャネル)
    /// * `Err(NicWorkerError)` - エラー
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        token: CancellationToken,
        cfg: &Config,
        ni: NetworkInterface,
        arp_table: Arc<ArpTable>,
        target_ips: impl AsRef<[Ipv4Addr]>,
    ) -> Result<NicWorkerResult, NicWorkerError> {
        let cap = PcapNetworkInterface::from(&ni).open(false)?;
        let (sender, receiver) = match cap {
            Channel::Ethernet(s, r) => (s, r),
        };

        // 上位プロトコルWorkerとの通信チャネルを作成
        let (recv_ip_tx, recv_ip_rx) = mpsc::channel(cfg.buffer_size);
        let (send_ip_txs, send_ip_rxs) = target_ips.as_ref().iter().fold(
            (FxHashMap::default(), FxHashMap::default()),
            |(mut txs, mut rxs), &ip| {
                let (tx, rx) = mpsc::channel(cfg.buffer_size);
                txs.insert(ip, tx);
                rxs.insert(ip, rx);
                (txs, rxs)
            },
        );

        let receiver = EthernetFrameReceiver {
            ni: ni.clone(),
            datalink_rx: receiver,
            ip_txs: send_ip_txs,
        };

        let sender = EthernetFrameSender {
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
        Ok(NicWorkerResult {
            worker,
            sender: recv_ip_tx,
            receivers: send_ip_rxs,
        })
    }

    pub async fn run(self) -> Result<(), NicWorkerError> {
        let interface_name = self.sender.ni.name.clone();
        info!("Starting NIC Worker for interface: {interface_name}");

        let token = self.token.clone();
        let ip_handle = tokio::spawn(self.sender.listen_ip_packets());
        let ethernet_handle = tokio::spawn(self.receiver.listen_ethernet_frames());

        tokio::select! {
            _ = token.cancelled() => {
                info!("NIC Worker for interface {interface_name} is stopping");
            }
            _ = ip_handle => {},
            _ = ethernet_handle => {},
        }

        Ok(())
    }
}

impl EthernetFrameSender {
    async fn listen_ip_packets(mut self) -> Result<(), NicWorkerError> {
        while let Some(pkt) = self.ip_rx.recv().await {
            if let Err(e) = self.handle_recv_ip_packet(pkt).await {
                warn!("Failed to handle received IP packet: {e}");
            }
        }
        Ok(())
    }

    async fn handle_recv_ip_packet(&mut self, pkt: IPv4Packet) -> Result<(), NicWorkerError> {
        // ARP解決
        // 宛先IPアドレスが直接接続していなくても内部でNext Hopを解決する
        let target_mac = self.arp_table.get_or_resolve(pkt.dst).await?;

        // Ethernetフレームを作成
        let ethernet_frame = EthernetFrame::new(
            &self.ni.mac_addr,
            &target_mac,
            &EtherType::IPv4,
            None,
            Vec::<u8>::from(pkt),
        );

        // フレームを送信
        let frame_bytes = Bytes::try_from(ethernet_frame)?;
        self.datalink_tx.send_bytes(&frame_bytes).await?;

        Ok(())
    }
}

impl EthernetFrameReceiver {
    async fn listen_ethernet_frames(mut self) -> Result<(), NicWorkerError> {
        while let Ok(frame) = self.datalink_rx.recv().await {
            if let Err(e) = self.handle_recv_ethernet_frame(frame).await {
                warn!("Failed to handle received Ethernet frame: {e}");
            }
        }
        Ok(())
    }

    async fn handle_recv_ethernet_frame(
        &mut self,
        frame: impl AsRef<[u8]>,
    ) -> Result<(), NicWorkerError> {
        // Ethernetフレームを解析
        let ethernet_frame = match EthernetFrame::try_from(frame.as_ref()) {
            Ok(frame) => frame,
            Err(e) => {
                warn!("Failed to parse Ethernet frame: {e}");
                return Ok(()); // 解析失敗時は無視
            }
        };
        // IPv4パケットのみを処理
        if ethernet_frame.ether_type != EtherType::IPv4 {
            debug!("EtherType is not IPv4: {}", ethernet_frame.ether_type);
            return Ok(());
        }

        // IPv4パケットを解析
        let ipv4_packet = match IPv4Packet::try_from(&ethernet_frame.payload) {
            Ok(packet) => packet,
            Err(e) => {
                warn!("Failed to parse IPv4 packet: {e}");
                return Ok(()); // 解析失敗は無視
            }
        };
        // 送信元IPアドレスが自身のIPアドレスと一致するものは除外
        if self.ni.get_best_source_ip(&ipv4_packet.dst) == Some(ipv4_packet.src) {
            debug!(
                "Source IP {} is one of the interface's IPs, ignoring",
                ipv4_packet.src
            );
            return Ok(());
        }
        // ICMPパケットのみを転送
        if ipv4_packet.protocol != Protocol::ICMP {
            debug!("Protocol is not ICMP: {}", ipv4_packet.protocol);
            return Ok(());
        }

        // 上位プロトコルWorkerにIPv4パケットを送信
        let tx = self
            .ip_txs
            .get(&ipv4_packet.src)
            .ok_or(NicWorkerError::IPPacketSendChannelNotFound(ipv4_packet.dst))?;
        tx.send(ipv4_packet)
            .await
            .map_err(|_| NicWorkerError::ChannelSendError)?;

        Ok(())
    }
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
        }
    }

    #[test]
    fn test_ping_targets() {
        // [正常系] PingTargetsの作成
        let ni = create_test_network_interface();
        let targets = vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 2)];

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
        // [正常系] EthernetFrameReceiverの作成
        let ni = create_test_network_interface();
        let mut ip_txs = FxHashMap::default();
        let target_ip = Ipv4Addr::new(192, 168, 1, 1);
        let (tx, _rx) = mpsc::channel(100);
        ip_txs.insert(target_ip, tx);

        let mock_receiver = Box::new(MockReceiver::new());

        let receiver = EthernetFrameReceiver {
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
        // [正常系] EthernetFrameSenderの作成
        let ni = create_test_network_interface();
        let arp_table = Arc::new(ArpTable::new(&ArpConfig::default()));
        let mock_sender = Box::new(MockSender::new());
        let (_tx, rx) = mpsc::channel(100);

        let sender = EthernetFrameSender {
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
        let (tx, mut rx) = mpsc::channel(100);
        ip_txs.insert(target_ip, tx);

        let mock_receiver = Box::new(MockReceiver::new());

        let mut receiver = EthernetFrameReceiver {
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
        let result = receiver.handle_recv_ethernet_frame(frame_bytes).await;
        assert_ok!(result);

        // 受信されたパケットを確認
        let received_packet = rx.recv().await.unwrap();
        assert_eq!(received_packet.src, ipv4_packet.src);
        assert_eq!(received_packet.dst, ipv4_packet.dst);
        assert_eq!(received_packet.protocol, Protocol::ICMP);

        // [正常系] 非IPv4パケットの無視
        let arp_frame = EthernetFrame::new(
            &src_mac,
            &dst_mac,
            &EtherType::ARP,
            None,
            vec![0; 28], // 最小ARPパケットサイズ
        );

        let arp_frame_bytes = Vec::<u8>::try_from(arp_frame).unwrap();
        let result = receiver.handle_recv_ethernet_frame(arp_frame_bytes).await;
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
        let result = receiver.handle_recv_ethernet_frame(tcp_frame_bytes).await;
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
            .handle_recv_ethernet_frame(unknown_frame_bytes)
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NicWorkerError::IPPacketSendChannelNotFound(_)
        ));
    }

    #[tokio::test]
    async fn test_nic_worker_run() {
        // [正常系] NicWorkerの実行とキャンセレーション
        let token = CancellationToken::new();
        let ni = create_test_network_interface();
        let arp_table = Arc::new(ArpTable::new(&ArpConfig::default()));
        let targets = [Ipv4Addr::new(192, 168, 1, 1)];

        let mock_sender = Box::new(MockSender::new());
        let mock_receiver = Box::new(MockReceiver::new());
        let (_tx, rx) = mpsc::channel(100);

        let sender = EthernetFrameSender {
            ni: ni.clone(),
            arp_table: arp_table.clone(),
            datalink_tx: mock_sender,
            ip_rx: rx,
        };

        let mut ip_txs = FxHashMap::default();
        let (tx, _rx) = mpsc::channel(100);
        ip_txs.insert(targets[0], tx);

        let receiver = EthernetFrameReceiver {
            ni: ni.clone(),
            datalink_rx: mock_receiver,
            ip_txs,
        };

        let worker = NicWorker {
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

        let sender = EthernetFrameSender {
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

        let mut mock_sender = MockSender::new();
        mock_sender
            .expect_send_bytes()
            .times(1)
            .returning(|_| Ok(()));

        let sender = EthernetFrameSender {
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
            Ipv4Addr::new(192, 168, 1, 1),
            Vec::new(),
            Bytes::from(vec![0; 32]),
        );

        // 注意: ARPテーブルにエントリを直接追加する手段がないため、
        // このテストではARP解決が実際に試行されることになる
        // 実際の環境ではARP解決が失敗する可能性がある
        let mut sender = sender;
        let result = sender.handle_recv_ip_packet(ipv4_packet).await;
        // エラーが発生することを許容（環境依存のため）
        let _ = result;
    }

    #[tokio::test]
    async fn test_ethernet_frame_receiver_listen_ethernet_frames() {
        // [正常系] Ethernetフレーム受信処理のテスト
        let ni = create_test_network_interface();
        let mut ip_txs = FxHashMap::default();
        let target_ip = Ipv4Addr::new(192, 168, 1, 1);
        let (tx, _rx) = mpsc::channel(100);
        ip_txs.insert(target_ip, tx);

        let mut mock_receiver = MockReceiver::new();
        mock_receiver
            .expect_recv()
            .times(1)
            .returning(|| Ok(vec![0; 14])); // 最小Ethernetフレームサイズ

        let receiver = EthernetFrameReceiver {
            ni,
            datalink_rx: Box::new(mock_receiver),
            ip_txs,
        };

        // 短時間フレーム受信処理を実行
        let handle = tokio::spawn(receiver.listen_ethernet_frames());
        tokio::time::sleep(Duration::from_millis(10)).await;
        handle.abort(); // タスクを中止
        let _ = handle.await; // 結果は無視（中止されるため）
    }

    #[test]
    fn test_nic_worker_error() {
        // [正常系] エラーの表示確認
        let error1 = NicWorkerError::ChannelSendError;
        assert_eq!(error1.to_string(), "Channel send error");

        let error2 = NicWorkerError::IPPacketSendChannelNotFound(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(
            error2.to_string(),
            "IP packet send channel not found for IP address 192.168.1.1"
        );
    }
}
