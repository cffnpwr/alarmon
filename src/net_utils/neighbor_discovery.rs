use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration as StdDuration, Instant};

use bytes::{Bytes, BytesMut};
use chrono::Duration;
use fxhash::FxHashMap;
use parking_lot::RwLock;
use pcap::PcapError;
use tcpip::ethernet::{EtherType, EthernetFrame, EthernetFrameError, MacAddr, MacAddrError};
use tcpip::icmpv6::{ICMPv6Message, NeighborSolicitationMessage};
use tcpip::ipv4::Protocol;
use tcpip::ipv6::{IPv6Error, IPv6Packet};
use thiserror::Error;
use tokio::time::timeout;

use super::netlink::{Netlink, NetlinkError, RouteEntry};
use crate::config::ArpConfig;

#[derive(Debug, Error)]
pub enum NeighborDiscoveryError {
    #[error(transparent)]
    NetworkError(#[from] NetlinkError),
    #[error(transparent)]
    FrameConversionError(#[from] EthernetFrameError),
    #[error(transparent)]
    IPv6Error(#[from] IPv6Error),
    #[error(transparent)]
    PcapError(#[from] PcapError),
    #[error(transparent)]
    MacAddressError(#[from] MacAddrError),
    #[error("No IPv6 address found on interface {0}")]
    NoIpv6Address(String),
    #[error("Neighbor Discovery response timeout")]
    Timeout,
}

#[derive(Debug, Clone)]
pub(crate) struct NeighborEntry {
    pub(crate) mac_addr: MacAddr,
    pub(crate) created_at: Instant,
    pub(crate) ttl: Duration,
}

impl NeighborEntry {
    fn new(mac_addr: MacAddr, ttl: Duration) -> Self {
        Self {
            mac_addr,
            created_at: Instant::now(),
            ttl,
        }
    }

    fn is_expired(&self) -> bool {
        let elapsed = self.created_at.elapsed();
        let ttl_std = StdDuration::from_secs(self.ttl.num_seconds() as u64);
        elapsed > ttl_std
    }
}

#[derive(Debug)]
pub struct NeighborCache {
    pub(crate) entries: RwLock<FxHashMap<Ipv6Addr, NeighborEntry>>,
    default_ttl: Duration,
    nd_timeout: Duration,
}

impl NeighborCache {
    pub fn new(config: &ArpConfig) -> Self {
        Self {
            entries: RwLock::new(FxHashMap::default()),
            default_ttl: config.ttl,
            nd_timeout: config.timeout,
        }
    }

    pub async fn get_or_resolve(
        &self,
        target_ip: Ipv6Addr,
    ) -> Result<MacAddr, NeighborDiscoveryError> {
        // 読み取りロックでキャッシュを確認
        {
            let entries = self.entries.read();
            if let Some(entry) = entries.get(&target_ip) {
                if !entry.is_expired() {
                    return Ok(entry.mac_addr);
                }
            }
        }

        // キャッシュにない、または期限切れの場合はNeighbor Discovery解決を実行
        let netlink = Netlink::new().await?;
        #[cfg(target_os = "linux")]
        let mut netlink = netlink;
        let best_route = netlink.get_route(target_ip.into()).await?;
        let ni = pcap::NetworkInterface::from(&best_route.interface);

        let mac_addr =
            resolve_neighbor_with_pcap(target_ip, ni, best_route, self.nd_timeout).await?;

        // 書き込みロックで結果をキャッシュに保存
        let mut entries = self.entries.write();
        // 期限切れエントリを削除してから新しいエントリを追加
        entries.retain(|_, entry| !entry.is_expired());
        entries.insert(target_ip, NeighborEntry::new(mac_addr, self.default_ttl));

        Ok(mac_addr)
    }
}

#[inline]
async fn resolve_neighbor_with_pcap<P: pcap::Pcap>(
    target_ip: Ipv6Addr,
    pcap_interface: P,
    best_route: RouteEntry,
    timeout_duration: Duration,
) -> Result<MacAddr, NeighborDiscoveryError> {
    // Neighbor Discovery対象を決定（直接接続またはゲートウェイ経由）
    let nd_target = if let Some(IpAddr::V6(gateway_ip)) = best_route.via {
        // ゲートウェイ経由の場合、ゲートウェイに対してNeighbor Discovery
        gateway_ip
    } else {
        // 直接接続の場合、対象IPに対してNeighbor Discovery
        target_ip
    };

    // インターフェースから送信元IPを取得
    let src_ip = best_route
        .interface
        .get_best_source_ipv6(&target_ip)
        .ok_or(NeighborDiscoveryError::NoIpv6Address(
            best_route.interface.name.clone(),
        ))?;

    // インターフェースでパケットキャプチャを開始
    let cap = pcap_interface.open(false)?;
    let mut sender = cap.sender;
    let mut receiver = cap.receiver;

    // ICMPv6 Neighbor Solicitationメッセージを作成
    let multicst_addr = calculate_solicited_node_multicast_ipv6(nd_target);
    let src_mac = best_route.interface.mac_addr;
    let mut src_mac_bytes = BytesMut::from(&[1, 1][..]);
    src_mac_bytes.extend_from_slice(&<[u8; 6]>::from(src_mac));
    let ns_message =
        // NeighborSolicitationMessage::new(nd_target, <[u8; 6]>::from(src_mac), src_ip, nd_target);
        NeighborSolicitationMessage::new(nd_target, &src_mac_bytes, src_ip, multicst_addr);

    // IPv6パケットを作成
    let ipv6_packet = IPv6Packet::new(
        0, // Traffic Class
        0, // Flow Label
        Protocol::IPv6ICMP,
        255, // Hop Limit
        src_ip,
        multicst_addr,
        Bytes::from(ICMPv6Message::NeighborSolicitation(ns_message)),
    )?;

    // 宛先MacアドレスはマルチキャストMacアドレス
    // 33:33:ff:xx:xx:xx の形式で、IPv6アドレスの下位24bitを使用
    let multicast_mac = calculate_solicited_node_multicast_mac(nd_target);
    let ethernet_frame = EthernetFrame::new(
        &src_mac,
        &multicast_mac,
        &EtherType::IPv6,
        None,
        Bytes::from(ipv6_packet),
    );

    // Neighbor Solicitationを送信
    let frame_bytes =
        Bytes::try_from(ethernet_frame).map_err(NeighborDiscoveryError::FrameConversionError)?;
    sender
        .send_bytes(&frame_bytes)
        .await
        .map_err(NeighborDiscoveryError::PcapError)?;

    // Neighbor Advertisementを待機
    let timeout_std = timeout_duration
        .to_std()
        .unwrap_or(StdDuration::from_secs(5));
    let result = timeout(timeout_std, async {
        loop {
            let packet = match receiver.recv().await {
                Ok(packet) => packet,
                _ => continue,
            };

            let frame = match EthernetFrame::try_from(packet.as_slice()) {
                Ok(frame) => frame,
                Err(_) => continue,
            };
            if frame.ether_type != EtherType::IPv6 {
                continue;
            }

            let ipv6_packet = match IPv6Packet::try_from(&frame.payload) {
                Ok(packet) => packet,
                Err(_) => continue,
            };
            if ipv6_packet.next_header != Protocol::IPv6ICMP {
                continue;
            }

            let icmpv6_message = match ICMPv6Message::try_from(&ipv6_packet.payload) {
                Ok(message) => message,
                Err(_) => continue,
            };
            if let ICMPv6Message::NeighborAdvertisement(na_message) = icmpv6_message {
                if na_message.solicited && na_message.target_address == nd_target {
                    // Target Link-layer Address option (Type=2)を探す
                    let options = &na_message.options;
                    if options.len() >= 8 && options[0] == 2 && options[1] == 1 {
                        let mac_bytes: [u8; 6] =
                            options[2..8].try_into().expect("Should be 6 bytes");
                        return MacAddr::from(mac_bytes);
                    }
                }
            }
        }
    })
    .await;

    match result {
        Ok(mac_addr) => Ok(mac_addr),
        Err(_) => Err(NeighborDiscoveryError::Timeout),
    }
}

/// RFC 4291: IPv6のSolicited-Node Multicast MACアドレス計算
/// 33:33:xx:xx:xx:xx の形式で、下位24bitはIPv6アドレスの下位24bit
fn calculate_solicited_node_multicast_mac(target_ip: Ipv6Addr) -> MacAddr {
    let octets = target_ip.octets();
    let mut mac_bytes = [0u8; 6];
    mac_bytes[0] = 0x33;
    mac_bytes[1] = 0x33;
    mac_bytes[2] = octets[12];
    mac_bytes[3] = octets[13];
    mac_bytes[4] = octets[14];
    mac_bytes[5] = octets[15];

    MacAddr::from(mac_bytes)
}

/// RFC 4291: IPv6のSolicited-Node Multicastアドレス計算
/// ff02::1:ffxx:xxxx の形式で、下位24bitはIPv6アドレスの下位24bit
fn calculate_solicited_node_multicast_ipv6(target_ip: Ipv6Addr) -> Ipv6Addr {
    let octets = target_ip.octets();
    Ipv6Addr::new(
        0xff02,
        0x0000,
        0x0000,
        0x0000,
        0x0000,
        0x0001,
        0xff00 | (octets[13] as u16),
        (octets[14] as u16) << 8 | (octets[15] as u16),
    )
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::time::Instant;

    use async_trait::async_trait;
    use pcap::{Channel, DataLinkReceiver, DataLinkSender, Pcap};
    use tcpip::icmpv6::NeighborAdvertisementMessage;
    use tcpip::ip_cidr::{IPCIDR, IPv6CIDR};

    use super::*;
    use crate::net_utils::netlink::{LinkType, NetworkInterface};

    // テスト用のモック構造体
    struct MockPcap {
        packets_to_receive: Vec<u8>,
    }

    impl MockPcap {
        fn new() -> Self {
            Self {
                packets_to_receive: Vec::new(),
            }
        }

        fn add_packet_to_receive(&mut self, packet: Vec<u8>) {
            self.packets_to_receive = packet;
        }
    }

    impl Pcap for MockPcap {
        fn open(&self, _promisc: bool) -> Result<Channel, PcapError> {
            let sender = MockSender {};
            let receiver = MockReceiver {
                packet: self.packets_to_receive.clone(),
                returned: false,
            };
            Ok(Channel {
                sender: Box::new(sender),
                receiver: Box::new(receiver),
            })
        }
    }

    struct MockSender {}

    #[async_trait]
    impl DataLinkSender for MockSender {
        async fn send_bytes(&mut self, _buf: &[u8]) -> Result<(), PcapError> {
            Ok(())
        }
    }

    struct MockReceiver {
        packet: Vec<u8>,
        returned: bool,
    }

    #[async_trait]
    impl DataLinkReceiver for MockReceiver {
        async fn recv(&mut self) -> Result<Vec<u8>, PcapError> {
            if !self.returned && !self.packet.is_empty() {
                self.returned = true;
                return Ok(self.packet.clone());
            }
            // パケットがない場合は一度だけエラーを返す
            loop {
                tokio::time::sleep(StdDuration::from_millis(100)).await;
            }
        }
    }

    #[test]
    fn test_neighbor_cache_new() {
        // [正常系] NeighborCacheの作成
        let arp_config = ArpConfig::default();
        let neighbor_cache = NeighborCache::new(&arp_config);

        assert_eq!(neighbor_cache.default_ttl, arp_config.ttl);
        assert_eq!(neighbor_cache.nd_timeout, arp_config.timeout);
    }

    #[tokio::test]
    async fn test_neighbor_cache_cache() {
        // [正常系] キャッシュからの取得
        let arp_config = ArpConfig::default();
        let neighbor_cache = NeighborCache::new(&arp_config);
        let target_ip = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let mac_addr = MacAddr::try_from("aa:bb:cc:dd:ee:ff").unwrap();

        // 手動でキャッシュエントリを追加
        {
            let mut entries = neighbor_cache.entries.write();
            entries.insert(
                target_ip,
                NeighborEntry::new(mac_addr, Duration::seconds(30)),
            );
        }

        // キャッシュから取得できることを確認（実際のネットワーク通信は発生しない）
        let start_time = Instant::now();
        let result = neighbor_cache.get_or_resolve(target_ip).await;
        let elapsed = start_time.elapsed();

        // キャッシュヒットの場合は非常に高速（10ms未満）
        assert!(elapsed < std::time::Duration::from_millis(10));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mac_addr);
    }

    #[tokio::test]
    async fn test_resolve_neighbor_with_pcap() {
        // [正常系] Neighbor Discovery応答受信成功
        let mut mock_pcap = MockPcap::new();
        let target_ip = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let gateway_ip = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0xfe);

        // テスト用のネットワークインターフェースを作成
        let interface_mac = MacAddr::try_from("00:11:22:33:44:55").unwrap();
        let ipv6_cidr =
            IPv6CIDR::new(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 100), 64).unwrap();
        let interface = NetworkInterface {
            index: 1,
            name: "eth0".to_string(),
            ip_addrs: vec![IPCIDR::V6(ipv6_cidr)],
            mac_addr: interface_mac,
            linktype: LinkType::Ethernet,
        };

        // ゲートウェイ経由のルートエントリを作成
        let route_entry = RouteEntry {
            interface,
            to: IpAddr::V6(target_ip),
            via: Some(IpAddr::V6(gateway_ip)),
        };

        // Neighbor Advertisement応答パケットを作成
        let response_mac = MacAddr::try_from("aa:bb:cc:dd:ee:ff").unwrap();
        let mac_option = {
            let mut option = vec![2, 1]; // Type=2 (Target Link-layer Address), Length=1
            option.extend_from_slice(&<[u8; 6]>::from(response_mac));
            option
        };
        let src_ip = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 100);
        let na_message = NeighborAdvertisementMessage::new(
            false, // router
            true,  // solicited
            true,  // override
            gateway_ip, mac_option, gateway_ip, src_ip,
        );

        let icmpv6_message = ICMPv6Message::NeighborAdvertisement(na_message);
        let ipv6_packet = IPv6Packet::new(
            0, // Traffic Class
            0, // Flow Label
            Protocol::IPv6ICMP,
            255, // Hop Limit
            gateway_ip,
            src_ip,
            Bytes::from(icmpv6_message),
        )
        .unwrap();

        let ethernet_response = EthernetFrame::new(
            &response_mac,
            &interface_mac,
            &EtherType::IPv6,
            None,
            Bytes::from(ipv6_packet),
        );

        let response_bytes = Bytes::try_from(ethernet_response).unwrap().to_vec();
        mock_pcap.add_packet_to_receive(response_bytes);

        // テスト実行
        let timeout = Duration::milliseconds(100);
        let result = resolve_neighbor_with_pcap(target_ip, mock_pcap, route_entry, timeout).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), response_mac);

        // [異常系] タイムアウト（応答パケットなし）
        let mock_pcap_timeout = MockPcap::new();
        let interface_timeout = NetworkInterface {
            index: 1,
            name: "eth0".to_string(),
            ip_addrs: vec![IPCIDR::V6(ipv6_cidr)],
            mac_addr: interface_mac,
            linktype: LinkType::Ethernet,
        };
        let route_entry_timeout = RouteEntry {
            interface: interface_timeout,
            to: IpAddr::V6(target_ip),
            via: None, // 直接接続
        };

        let timeout_short = Duration::milliseconds(50);
        let result_timeout = resolve_neighbor_with_pcap(
            target_ip,
            mock_pcap_timeout,
            route_entry_timeout,
            timeout_short,
        )
        .await;
        assert!(result_timeout.is_err());
        assert!(matches!(
            result_timeout.unwrap_err(),
            NeighborDiscoveryError::Timeout
        ));
    }

    #[test]
    fn test_neighbor_entry_expiration() {
        // [正常系] 有効期限内のエントリ
        let mac = MacAddr::try_from("00:11:22:33:44:55").unwrap();
        let entry = NeighborEntry::new(mac, Duration::seconds(30));
        assert!(!entry.is_expired());

        // [正常系] 有効期限切れのエントリ（TTLを0にして即座に期限切れにする）
        let expired_entry = NeighborEntry::new(mac, Duration::seconds(0));
        // わずかに待機して期限切れにする
        std::thread::sleep(StdDuration::from_millis(1));
        assert!(expired_entry.is_expired());
    }

    #[test]
    fn test_calculate_solicited_node_multicast_mac() {
        // [正常系] Solicited-Node Multicast MACアドレスの計算
        let target_ip = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let result = calculate_solicited_node_multicast_mac(target_ip);

        // 33:33:xx:xx:xx:xx の形式で、下位24bitはIPv6アドレスの下位24bit
        let expected = MacAddr::from([0x33, 0x33, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(result, expected);

        // [正常系] 異なるIPv6アドレスでの計算
        let target_ip2 = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0x1234, 0x5678);
        let result2 = calculate_solicited_node_multicast_mac(target_ip2);

        let expected2 = MacAddr::from([0x33, 0x33, 0x56, 0x78, 0x78, 0x78]);
        assert_eq!(result2, expected2);
    }
}
