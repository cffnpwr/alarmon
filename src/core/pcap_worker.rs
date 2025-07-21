use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use fxhash::FxHashMap;
#[cfg(target_os = "macos")]
use libc::{AF_INET, AF_INET6};
use log::{debug, info, warn};
use pcap::{DataLinkReceiver, DataLinkSender, NetworkInterface as PcapNetworkInterface, Pcap as _};
use tcpip::ethernet::{EtherType, EthernetFrame, EthernetFrameError};
use tcpip::ip_packet::IPPacket;
use tcpip::ipv4::Protocol;
#[cfg(target_os = "macos")]
use tcpip::loopback::{LoopbackFrame, LoopbackFrameError};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::net_utils::arp_table::{ArpTable, ArpTableError};
use crate::net_utils::neighbor_discovery::{NeighborCache, NeighborDiscoveryError};
use crate::net_utils::netlink::{LinkType, NetlinkError, NetworkInterface};

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub struct PingTarget {
    pub id: u16,
    pub host: IpAddr,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PingTargets {
    pub ni: NetworkInterface,
    pub targets: Vec<PingTarget>,
}

#[derive(Debug)]
pub struct PcapWorkerResult {
    pub worker: PcapWorker,
    pub sender: mpsc::Sender<IPPacket>,
}

#[derive(Debug, Error)]
#[allow(clippy::enum_variant_names)]
pub enum PcapWorkerError {
    #[error(transparent)]
    NetworkError(#[from] NetlinkError),
    #[error(transparent)]
    ArpTableError(#[from] ArpTableError),
    #[error(transparent)]
    NeighborDiscoveryError(#[from] NeighborDiscoveryError),
    #[error(transparent)]
    PcapError(#[from] pcap::PcapError),
    #[error(transparent)]
    EthernetFrameError(#[from] EthernetFrameError),
    #[cfg(target_os = "macos")]
    #[error(transparent)]
    LoopbackFrameError(#[from] LoopbackFrameError),
}

pub struct DatalinkFrameReceiver {
    /// WorkerがDatalink Frameを受信するNIC
    ni: NetworkInterface,

    /// NICからDatalink Frameを受信するためのチャネル
    datalink_rx: Box<dyn DataLinkReceiver>,

    /// Ping Workerへの応答送信用チャネル（IPアドレス別）
    ping_reply_senders: FxHashMap<IpAddr, mpsc::Sender<IPPacket>>,

    /// Traceroute Workerへの応答送信用チャネル（IPアドレス別）
    traceroute_reply_senders: FxHashMap<IpAddr, mpsc::Sender<IPPacket>>,
}

impl std::fmt::Debug for DatalinkFrameReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatalinkFrameReceiver")
            .field("ni", &self.ni)
            .field("datalink_rx", &"<DataLinkReceiver>")
            .field("ping_reply_senders", &self.ping_reply_senders)
            .field("traceroute_reply_senders", &self.traceroute_reply_senders)
            .finish()
    }
}

pub struct DatalinkFrameSender {
    /// WorkerがDatalink Frameを送信するNIC
    ni: NetworkInterface,

    /// ARPテーブル
    arp_table: Arc<ArpTable>,

    /// IPv6 Neighbor Discovery cache
    neighbor_cache: Arc<NeighborCache>,

    /// NICにDatalink Frameを送信するためのチャネル
    datalink_tx: Box<dyn DataLinkSender>,

    /// 上位プロトコルWorkerからIPパケットを受信するためのチャネル
    ip_rx: mpsc::Receiver<IPPacket>,
}

impl std::fmt::Debug for DatalinkFrameSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatalinkFrameSender")
            .field("ni", &self.ni)
            .field("arp_table", &self.arp_table)
            .field("neighbor_cache", &self.neighbor_cache)
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
    /// * `ni` - 使用するネットワークインターフェース
    /// * `arp_table` - ARPテーブル
    /// * `neighbor_cache` - IPv6 Neighbor Discovery cache
    /// * `ping_reply_senders` - Ping Workerへの応答送信用チャネル
    /// * `traceroute_reply_senders` - Traceroute Workerへの応答送信用チャネル
    ///
    /// # Returns
    /// * `Ok(PcapWorkerResult)` - PcapWorkerとその送信チャネル
    /// * `Err(PcapWorkerError)` - エラー
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        token: CancellationToken,
        ni: NetworkInterface,
        arp_table: Arc<ArpTable>,
        neighbor_cache: Arc<NeighborCache>,
        ping_reply_senders: FxHashMap<IpAddr, mpsc::Sender<IPPacket>>,
        traceroute_reply_senders: FxHashMap<IpAddr, mpsc::Sender<IPPacket>>,
    ) -> Result<PcapWorkerResult, PcapWorkerError> {
        let cap = PcapNetworkInterface::from(&ni).open(false)?;
        let sender: Box<dyn DataLinkSender> = cap.sender;
        let receiver: Box<dyn DataLinkReceiver> = cap.receiver;

        // 上位プロトコルWorkerとの通信チャネルを作成
        let (recv_ip_tx, recv_ip_rx) = mpsc::channel(1024);

        let receiver = DatalinkFrameReceiver {
            ni: ni.clone(),
            datalink_rx: receiver,
            ping_reply_senders: ping_reply_senders.clone(),
            traceroute_reply_senders: traceroute_reply_senders.clone(),
        };

        let sender = DatalinkFrameSender {
            ni,
            arp_table,
            neighbor_cache,
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
        debug!(
            "PcapWorker: Starting to listen for IP packets on interface {}",
            self.ni.name
        );
        while let Some(pkt) = self.ip_rx.recv().await {
            debug!(
                "PcapWorker: Received IP packet for transmission on interface {}",
                self.ni.name
            );
            if let Err(e) = self.handle_recv_ip_packet(pkt).await {
                warn!("Failed to handle received IP packet: {e}");
            }
        }
        debug!(
            "PcapWorker: Stopped listening for IP packets on interface {}",
            self.ni.name
        );
        Ok(())
    }

    async fn handle_recv_ip_packet(&mut self, pkt: IPPacket) -> Result<(), PcapWorkerError> {
        let (src_ip, dst_ip, protocol): (IpAddr, IpAddr, String) = match &pkt {
            IPPacket::V4(ipv4_pkt) => (
                ipv4_pkt.src.into(),
                ipv4_pkt.dst.into(),
                format!("{:?}", ipv4_pkt.protocol),
            ),
            IPPacket::V6(ipv6_pkt) => (
                ipv6_pkt.src.into(),
                ipv6_pkt.dst.into(),
                format!("{:?}", ipv6_pkt.next_header),
            ),
        };
        debug!(
            "PcapWorker: Processing IP packet {} -> {} (protocol: {}) on interface {}",
            src_ip, dst_ip, protocol, self.ni.name
        );

        let frame = match self.ni.linktype {
            #[cfg(target_os = "macos")]
            LinkType::Loopback => {
                let protocol = match pkt {
                    IPPacket::V4(_) => AF_INET as u32,
                    IPPacket::V6(_) => AF_INET6 as u32,
                };
                let frame = LoopbackFrame::new(protocol, Bytes::from(pkt));
                Bytes::from(frame)
            }
            #[cfg(target_os = "linux")]
            LinkType::Loopback => {
                let ether_type = match pkt {
                    IPPacket::V4(_) => EtherType::IPv4,
                    IPPacket::V6(_) => EtherType::IPv6,
                };
                let ethernet_frame = EthernetFrame::new(
                    &self.ni.mac_addr,
                    &self.ni.mac_addr,
                    &ether_type,
                    None,
                    Bytes::from(pkt),
                );
                Bytes::try_from(ethernet_frame)?
            }
            LinkType::Ethernet => {
                let (target_mac, ether_type) = match &pkt {
                    IPPacket::V4(ipv4_pkt) => {
                        // ARP解決
                        // 宛先IPアドレスが直接接続していなくても内部でNext Hopを解決する
                        let target_mac = self.arp_table.get_or_resolve(ipv4_pkt.dst).await?;
                        (target_mac, EtherType::IPv4)
                    }
                    IPPacket::V6(ipv6_pkt) => {
                        // 近傍探索
                        let target_mac = self.neighbor_cache.get_or_resolve(ipv6_pkt.dst).await?;
                        (target_mac, EtherType::IPv6)
                    }
                };

                // Ethernetフレームを作成
                let ethernet_frame = EthernetFrame::new(
                    &self.ni.mac_addr,
                    &target_mac,
                    &ether_type,
                    None,
                    Bytes::from(pkt),
                );
                Bytes::try_from(ethernet_frame)?
            }
            LinkType::RawIP => Bytes::from(pkt),
        };

        // フレームを送信
        debug!(
            "PcapWorker: Sending frame of {} bytes to network on interface {} - first 64 bytes: {:02x?}",
            frame.len(),
            self.ni.name,
            &frame[..std::cmp::min(64, frame.len())]
        );
        match self.datalink_tx.send_bytes(&frame).await {
            Ok(()) => {
                debug!(
                    "PcapWorker: Successfully sent frame to network on interface {}",
                    self.ni.name
                );
            }
            Err(e) => {
                warn!(
                    "PcapWorker: Failed to send frame to network on interface {}: {}",
                    self.ni.name, e
                );
                return Err(PcapWorkerError::PcapError(e));
            }
        }

        Ok(())
    }
}

impl DatalinkFrameReceiver {
    async fn listen_datalink_frames(mut self) -> Result<(), PcapWorkerError> {
        while let Ok(frame) = self.datalink_rx.recv().await {
            if let Err(e) = self.handle_recv_datalink_frame(frame).await {
                debug!("Failed to handle received Datalink frame: {e}");
            }
        }
        Ok(())
    }

    async fn handle_recv_datalink_frame(
        &mut self,
        frame: impl AsRef<[u8]>,
    ) -> Result<(), PcapWorkerError> {
        let payload = match self.ni.linktype {
            #[cfg(target_os = "macos")]
            LinkType::Loopback => {
                // Loopbackフレームを解析
                let loopback_frame = LoopbackFrame::try_from(frame.as_ref())?;
                // IPv4またはIPv6パケットを処理
                if loopback_frame.protocol != AF_INET as u32
                    && loopback_frame.protocol != AF_INET6 as u32
                {
                    debug!(
                        "Loopback protocol is not IPv4 or IPv6: {}",
                        loopback_frame.protocol
                    );
                    return Ok(()); // IPv4/IPv6以外は無視
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

        // IPパケットを解析
        let ip_packet = match IPPacket::try_from(payload) {
            Ok(packet) => packet,
            Err(e) => {
                warn!("Failed to parse IP packet: {e}");
                return Ok(()); // 解析失敗は無視
            }
        };

        // ICMPパケットのみを転送
        let is_icmp = match &ip_packet {
            IPPacket::V4(ipv4_packet) => ipv4_packet.protocol == Protocol::ICMP,
            IPPacket::V6(ipv6_packet) => ipv6_packet.next_header == Protocol::IPv6ICMP,
        };
        if !is_icmp {
            debug!("Protocol is not ICMP/ICMPv6");
            return Ok(());
        }

        // 送信元IPアドレスを取得
        let src_ip = match &ip_packet {
            IPPacket::V4(ipv4_packet) => ipv4_packet.src.into(),
            IPPacket::V6(ipv6_packet) => ipv6_packet.src.into(),
        };

        // Ping Workerへの直接送信
        if let Some(reply_sender) = self.ping_reply_senders.get(&src_ip) {
            // 特定のPing Workerに直接送信（Echo Reply）
            if let Err(e) = reply_sender.send(ip_packet.clone()).await {
                debug!("Failed to send ICMP packet to Ping Worker for {src_ip}: {e}");
            }
        } else {
            // ICMPエラーメッセージの場合、全てのPing Workerに送信
            for reply_sender in self.ping_reply_senders.values() {
                if let Err(e) = reply_sender.send(ip_packet.clone()).await {
                    debug!("Failed to send ICMP error to Ping Worker: {e}");
                }
            }
        }

        // Traceroute Workerへの直接送信
        if let Some(reply_sender) = self.traceroute_reply_senders.get(&src_ip) {
            // 特定のTraceroute Workerに直接送信
            if let Err(e) = reply_sender.send(ip_packet.clone()).await {
                debug!("Failed to send ICMP packet to Traceroute Worker for {src_ip}: {e}");
            }
        } else {
            // ICMPエラーメッセージの場合、全てのTraceroute Workerに送信
            for reply_sender in self.traceroute_reply_senders.values() {
                if let Err(e) = reply_sender.send(ip_packet.clone()).await {
                    debug!("Failed to send ICMP error to Traceroute Worker: {e}");
                }
            }
        }

        Ok(())
    }
}

fn parse_ethernet_payload(frame: &[u8]) -> Result<Bytes, Box<dyn std::error::Error + Send + Sync>> {
    // Ethernetフレームを解析
    let ethernet_frame = EthernetFrame::try_from(frame)?;

    // IPv4またはIPv6パケットを処理
    if ethernet_frame.ether_type != EtherType::IPv4 && ethernet_frame.ether_type != EtherType::IPv6
    {
        return Err("EtherType is not IPv4 or IPv6".into());
    }

    Ok(ethernet_frame.payload)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use async_trait::async_trait;
    use mockall::mock;
    use tcpip::ethernet::MacAddr;
    use tcpip::icmp::ICMPMessage;
    use tcpip::icmpv6::ICMPv6Message;
    use tcpip::ip_cidr::{IPCIDR, IPv4CIDR, IPv6CIDR};
    use tcpip::ipv4::{Flags, IPv4Packet, TypeOfService};
    use tcpip::ipv6::IPv6Packet;
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

    fn create_test_network_interface_ipv6() -> NetworkInterface {
        let mac_addr = MacAddr::try_from("00:11:22:33:44:55").unwrap();
        let ipv6_cidr =
            IPv6CIDR::new(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 100), 64).unwrap();

        NetworkInterface {
            index: 1,
            name: "eth0".to_string(),
            ip_addrs: vec![IPCIDR::V6(ipv6_cidr)],
            mac_addr,
            linktype: LinkType::Ethernet,
        }
    }

    #[test]
    fn test_ping_targets() {
        // [正常系] IPv4を使用したPingTargetsの作成
        let ni = create_test_network_interface();
        let targets = vec![
            PingTarget {
                id: 1,
                host: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            },
            PingTarget {
                id: 2,
                host: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            },
        ];

        let ping_targets = PingTargets {
            ni: ni.clone(),
            targets: targets.clone(),
        };

        assert_eq!(ping_targets.ni.index, ni.index);
        assert_eq!(ping_targets.ni.name, ni.name);
        assert_eq!(ping_targets.targets, targets);

        // [正常系] IPv6を使用したPingTargetsの作成
        let ni_ipv6 = create_test_network_interface_ipv6();
        let targets_ipv6 = vec![
            PingTarget {
                id: 1,
                host: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
            },
            PingTarget {
                id: 2,
                host: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2)),
            },
        ];

        let ping_targets_ipv6 = PingTargets {
            ni: ni_ipv6.clone(),
            targets: targets_ipv6.clone(),
        };

        assert_eq!(ping_targets_ipv6.ni.index, ni_ipv6.index);
        assert_eq!(ping_targets_ipv6.ni.name, ni_ipv6.name);
        assert_eq!(ping_targets_ipv6.targets, targets_ipv6);
    }

    #[test]
    fn test_ethernet_frame_receiver() {
        // [正常系] DatalinkFrameReceiverの作成
        let ni = create_test_network_interface();
        let mock_receiver = Box::new(MockReceiver::new());

        let receiver = DatalinkFrameReceiver {
            ni: ni.clone(),
            datalink_rx: mock_receiver,
            ping_reply_senders: FxHashMap::default(),
            traceroute_reply_senders: FxHashMap::default(),
        };

        assert_eq!(receiver.ni.index, ni.index);
        assert_eq!(receiver.ni.name, ni.name);
    }

    #[test]
    fn test_ethernet_frame_sender() {
        // [正常系] DatalinkFrameSenderの作成
        let ni = create_test_network_interface();
        let arp_table = Arc::new(ArpTable::new(&ArpConfig::default()));
        let neighbor_cache = Arc::new(NeighborCache::new(&ArpConfig::default()));
        let mock_sender = Box::new(MockSender::new());
        let (_tx, rx) = mpsc::channel(100);

        let sender = DatalinkFrameSender {
            ni: ni.clone(),
            arp_table: arp_table.clone(),
            neighbor_cache,
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
        let mock_receiver = Box::new(MockReceiver::new());
        let target_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let (tx, mut rx) = mpsc::channel(1);

        let mut ping_reply_senders = FxHashMap::default();
        ping_reply_senders.insert(target_ip, tx);

        let mut receiver = DatalinkFrameReceiver {
            ni,
            datalink_rx: mock_receiver,
            ping_reply_senders,
            traceroute_reply_senders: FxHashMap::default(),
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
            match target_ip {
                IpAddr::V4(addr) => addr,
                _ => panic!("Expected IPv4 address"),
            },
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
        let result = receiver.handle_recv_datalink_frame(frame_bytes).await;
        assert_ok!(result);

        // 受信されたパケットを確認
        let received_packet = rx.recv().await.unwrap();
        match received_packet {
            IPPacket::V4(ipv4_pkt) => {
                assert_eq!(ipv4_pkt.src, ipv4_packet.src);
                assert_eq!(ipv4_pkt.dst, ipv4_packet.dst);
                assert_eq!(ipv4_pkt.protocol, Protocol::ICMP);
            }
            IPPacket::V6(_) => panic!("Expected IPv4 packet"),
        }

        // [正常系] 非IPv4パケットの無視
        let arp_frame = EthernetFrame::new(
            &src_mac,
            &dst_mac,
            &EtherType::ARP,
            None,
            vec![0; 28], // 最小ARPパケットサイズ
        );

        let arp_frame_bytes = Vec::<u8>::try_from(arp_frame).unwrap();
        let result = receiver.handle_recv_datalink_frame(arp_frame_bytes).await;
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
            match target_ip {
                IpAddr::V4(addr) => addr,
                _ => panic!("Expected IPv4 address"),
            },
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
        let result = receiver.handle_recv_datalink_frame(tcp_frame_bytes).await;
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
            .handle_recv_datalink_frame(unknown_frame_bytes)
            .await;
        // 修正後は未知のIPアドレスからのパケットも全receiverに送信されるためエラーにならない
        assert!(result.is_ok());

        // [正常系] IPv6 ICMPv6パケットの処理
        let ni_ipv6 = create_test_network_interface_ipv6();
        let target_ip_ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        let (tx_ipv6, mut rx_ipv6) = mpsc::channel(1);

        let mock_receiver_ipv6 = Box::new(MockReceiver::new());

        let mut ping_reply_senders_ipv6 = FxHashMap::default();
        ping_reply_senders_ipv6.insert(target_ip_ipv6, tx_ipv6);

        let mut receiver_ipv6 = DatalinkFrameReceiver {
            ni: ni_ipv6,
            datalink_rx: mock_receiver_ipv6,
            ping_reply_senders: ping_reply_senders_ipv6,
            traceroute_reply_senders: FxHashMap::default(),
        };

        // テスト用のICMPv6 Echo Replyパケットを作成
        let src_addr = match target_ip_ipv6 {
            IpAddr::V6(addr) => addr,
            _ => panic!("Expected IPv6 address"),
        };
        let dst_addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 100);
        let icmpv6_msg = ICMPv6Message::echo_reply(12345, 1, vec![0; 32], src_addr, dst_addr);
        let icmpv6_bytes: Bytes = icmpv6_msg.into();
        let ipv6_packet = IPv6Packet::new(
            0, // Traffic Class
            0, // Flow Label
            Protocol::IPv6ICMP,
            64, // Hop Limit
            src_addr,
            dst_addr,
            icmpv6_bytes.clone(),
        )
        .unwrap();

        // Ethernetフレームを作成
        let ethernet_frame_ipv6 = EthernetFrame::new(
            &src_mac,
            &dst_mac,
            &EtherType::IPv6,
            None,
            Bytes::from(ipv6_packet.clone()),
        );

        let frame_bytes_ipv6 = Bytes::try_from(ethernet_frame_ipv6).unwrap().to_vec();

        // テスト実行
        let result = receiver_ipv6
            .handle_recv_datalink_frame(frame_bytes_ipv6)
            .await;
        assert_ok!(result);

        // 受信されたパケットを確認
        let received_packet_ipv6 = rx_ipv6.recv().await.unwrap();
        match received_packet_ipv6 {
            IPPacket::V6(ipv6_pkt) => {
                assert_eq!(ipv6_pkt.src, ipv6_packet.src);
                assert_eq!(ipv6_pkt.dst, ipv6_packet.dst);
                assert_eq!(ipv6_pkt.next_header, Protocol::IPv6ICMP);
            }
            IPPacket::V4(_) => panic!("Expected IPv6 packet"),
        }

        // [正常系] 非ICMPv6パケットの無視
        let tcp_packet_ipv6 = IPv6Packet::new(
            0, // Traffic Class
            0, // Flow Label
            Protocol::TCP,
            64, // Hop Limit
            match target_ip_ipv6 {
                IpAddr::V6(addr) => addr,
                _ => panic!("Expected IPv6 address"),
            },
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 100),
            Bytes::from(vec![0; 20]), // 最小TCPヘッダ
        )
        .unwrap();

        let tcp_frame_ipv6 = EthernetFrame::new(
            &src_mac,
            &dst_mac,
            &EtherType::IPv6,
            None,
            Bytes::from(tcp_packet_ipv6),
        );

        let tcp_frame_bytes_ipv6 = Bytes::try_from(tcp_frame_ipv6).unwrap().to_vec();
        let result = receiver_ipv6
            .handle_recv_datalink_frame(tcp_frame_bytes_ipv6)
            .await;
        assert_ok!(result);

        // パケットが受信されていないことを確認
        assert!(rx_ipv6.try_recv().is_err());

        // [異常系] 送信先チャネルが存在しない場合
        let unknown_ip_ipv6 = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 99);
        let unknown_packet_ipv6 = IPv6Packet::new(
            0, // Traffic Class
            0, // Flow Label
            Protocol::IPv6ICMP,
            64, // Hop Limit
            unknown_ip_ipv6,
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 100),
            icmpv6_bytes,
        )
        .unwrap();

        let unknown_frame_ipv6 = EthernetFrame::new(
            &src_mac,
            &dst_mac,
            &EtherType::IPv6,
            None,
            Bytes::from(unknown_packet_ipv6),
        );

        let unknown_frame_bytes_ipv6 = Bytes::try_from(unknown_frame_ipv6).unwrap().to_vec();
        let result = receiver_ipv6
            .handle_recv_datalink_frame(unknown_frame_bytes_ipv6)
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
        let _targets = [IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];

        let mock_sender = Box::new(MockSender::new());
        let mock_receiver = Box::new(MockReceiver::new());
        let (_tx, rx) = mpsc::channel(100);

        let neighbor_cache = Arc::new(NeighborCache::new(&ArpConfig::default()));
        let sender = DatalinkFrameSender {
            ni: ni.clone(),
            arp_table: arp_table.clone(),
            neighbor_cache,
            datalink_tx: mock_sender,
            ip_rx: rx,
        };

        let receiver = DatalinkFrameReceiver {
            ni: ni.clone(),
            datalink_rx: mock_receiver,
            ping_reply_senders: FxHashMap::default(),
            traceroute_reply_senders: FxHashMap::default(),
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

        let neighbor_cache = Arc::new(NeighborCache::new(&ArpConfig::default()));
        let sender = DatalinkFrameSender {
            ni,
            arp_table,
            neighbor_cache,
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

        tx.send(IPPacket::V4(ipv4_packet)).await.unwrap();
        drop(tx); // チャネルを閉じる

        let sender = sender;
        let result = sender.listen_ip_packets().await;
        assert_ok!(result);
    }

    #[tokio::test]
    async fn test_ethernet_frame_sender_handle_recv_ip_packet() {
        // [正常系] IPv4パケットの処理とEthernetフレーム送信
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

        let neighbor_cache = Arc::new(NeighborCache::new(&ArpConfig::default()));
        let sender = DatalinkFrameSender {
            ni,
            arp_table,
            neighbor_cache,
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
        let result = sender
            .handle_recv_ip_packet(IPPacket::V4(ipv4_packet))
            .await;
        assert_ok!(result);

        // [正常系] IPv6パケットの処理とEthernetフレーム送信
        let ni_ipv6 = create_test_network_interface_ipv6();
        let arp_table_ipv6 = Arc::new(ArpTable::new(&ArpConfig::default()));
        let neighbor_cache_ipv6 = Arc::new(NeighborCache::new(&ArpConfig::default()));
        let (_tx_ipv6, rx_ipv6) = mpsc::channel(100);

        // 宛先IPv6アドレスとMACアドレスを事前にNeighbor Discoveryキャッシュに追加
        let target_ip_ipv6 = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let target_mac_ipv6 = MacAddr::try_from("aa:bb:cc:dd:ee:ff").unwrap();

        // Neighbor Discoveryキャッシュにエントリを直接追加（テスト用）
        {
            use chrono::Duration;
            let mut entries = neighbor_cache_ipv6.entries.write();
            let neighbor_entry = crate::net_utils::neighbor_discovery::NeighborEntry {
                mac_addr: target_mac_ipv6,
                created_at: std::time::Instant::now(),
                ttl: Duration::seconds(30),
            };
            entries.insert(target_ip_ipv6, neighbor_entry);
        }

        let mut mock_sender_ipv6 = MockSender::new();
        mock_sender_ipv6
            .expect_send_bytes()
            .times(1)
            .returning(|_| Ok(()));

        let sender_ipv6 = DatalinkFrameSender {
            ni: ni_ipv6,
            arp_table: arp_table_ipv6,
            neighbor_cache: neighbor_cache_ipv6,
            datalink_tx: Box::new(mock_sender_ipv6),
            ip_rx: rx_ipv6,
        };

        let ipv6_packet = IPv6Packet::new(
            0, // Traffic Class
            0, // Flow Label
            Protocol::IPv6ICMP,
            64, // Hop Limit
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 100),
            target_ip_ipv6,
            Bytes::from(vec![0; 32]),
        )
        .unwrap();

        let mut sender_ipv6 = sender_ipv6;
        let result = sender_ipv6
            .handle_recv_ip_packet(IPPacket::V6(ipv6_packet))
            .await;
        assert_ok!(result);
    }

    #[tokio::test]
    async fn test_ethernet_frame_receiver_listen_ethernet_frames() {
        // [正常系] Ethernetフレーム受信処理のテスト
        let ni = create_test_network_interface();
        let mut mock_receiver = MockReceiver::new();
        mock_receiver
            .expect_recv()
            .times(1)
            .returning(|| Ok(vec![0; 14])); // 最小Ethernetフレームサイズ

        let receiver = DatalinkFrameReceiver {
            ni,
            datalink_rx: Box::new(mock_receiver),
            ping_reply_senders: FxHashMap::default(),
            traceroute_reply_senders: FxHashMap::default(),
        };

        // 短時間フレーム受信処理を実行
        let handle = tokio::spawn(receiver.listen_datalink_frames());
        tokio::time::sleep(Duration::from_millis(10)).await;
        handle.abort(); // タスクを中止
        let _ = handle.await; // 結果は無視（中止されるため）
    }

    #[tokio::test]
    async fn test_mixed_ipv4_ipv6_packet_handling() {
        // [正常系] IPv4とIPv6パケットの混在処理
        let ni = create_test_network_interface();

        // IPv4とIPv6の両方の宛先を設定
        let ipv4_target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ipv6_target = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        let (tx4, mut rx4) = mpsc::channel(1);
        let (tx6, mut rx6) = mpsc::channel(1);

        let mock_receiver = Box::new(MockReceiver::new());

        let mut ping_reply_senders = FxHashMap::default();
        ping_reply_senders.insert(ipv4_target, tx4);
        ping_reply_senders.insert(ipv6_target, tx6);

        let mut receiver = DatalinkFrameReceiver {
            ni,
            datalink_rx: mock_receiver,
            ping_reply_senders,
            traceroute_reply_senders: FxHashMap::default(),
        };

        // IPv4 ICMPパケットを作成
        let icmp_msg = ICMPMessage::echo_reply(12345, 1, vec![0; 32]);
        let icmp_bytes: Bytes = icmp_msg.into();
        let ipv4_packet = IPv4Packet::new(
            TypeOfService::default(),
            54321,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            match ipv4_target {
                IpAddr::V4(addr) => addr,
                _ => panic!("Expected IPv4 address"),
            },
            Ipv4Addr::new(192, 168, 1, 100),
            Vec::new(),
            icmp_bytes,
        );

        let src_mac = MacAddr::try_from("aa:bb:cc:dd:ee:ff").unwrap();
        let dst_mac = MacAddr::try_from("00:11:22:33:44:55").unwrap();

        let ipv4_frame = EthernetFrame::new(
            &src_mac,
            &dst_mac,
            &EtherType::IPv4,
            None,
            Vec::<u8>::from(ipv4_packet.clone()),
        );

        let ipv4_frame_bytes = Vec::<u8>::try_from(ipv4_frame).unwrap();
        let result = receiver.handle_recv_datalink_frame(ipv4_frame_bytes).await;
        assert_ok!(result);

        // IPv4パケットが受信されたことを確認
        let received_ipv4 = rx4.recv().await.unwrap();
        match received_ipv4 {
            IPPacket::V4(pkt) => {
                assert_eq!(pkt.src, ipv4_packet.src);
                assert_eq!(pkt.dst, ipv4_packet.dst);
            }
            IPPacket::V6(_) => panic!("Expected IPv4 packet"),
        }

        // IPv6 ICMPv6パケットを作成
        let ipv6_src = match ipv6_target {
            IpAddr::V6(addr) => addr,
            _ => panic!("Expected IPv6 address"),
        };
        let ipv6_dst = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 100);
        let icmpv6_msg = ICMPv6Message::echo_reply(12345, 1, vec![0; 32], ipv6_src, ipv6_dst);
        let icmpv6_bytes: Bytes = icmpv6_msg.into();
        let ipv6_packet = IPv6Packet::new(
            0, // Traffic Class
            0, // Flow Label
            Protocol::IPv6ICMP,
            64, // Hop Limit
            ipv6_src,
            ipv6_dst,
            icmpv6_bytes,
        )
        .unwrap();

        let ipv6_frame = EthernetFrame::new(
            &src_mac,
            &dst_mac,
            &EtherType::IPv6,
            None,
            Bytes::from(ipv6_packet.clone()),
        );

        let ipv6_frame_bytes = Bytes::try_from(ipv6_frame).unwrap().to_vec();
        let result = receiver.handle_recv_datalink_frame(ipv6_frame_bytes).await;
        assert_ok!(result);

        // IPv6パケットが受信されたことを確認
        let received_ipv6 = rx6.recv().await.unwrap();
        match received_ipv6 {
            IPPacket::V6(pkt) => {
                assert_eq!(pkt.src, ipv6_packet.src);
                assert_eq!(pkt.dst, ipv6_packet.dst);
            }
            IPPacket::V4(_) => panic!("Expected IPv6 packet"),
        }

        // 他の受信チャネルには何も受信されていないことを確認
        assert!(rx4.try_recv().is_err());
        assert!(rx6.try_recv().is_err());
    }
}
