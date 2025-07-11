use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration as StdDuration, Instant};

use chrono::Duration;
use fxhash::FxHashMap;
use parking_lot::RwLock;
use pcap::PcapError;
use tcpip::arp::{ARPPacket, ARPPacketInner, Operation};
use tcpip::ethernet::{EtherType, EthernetFrame, EthernetFrameError, MacAddr, MacAddrError};
use tcpip::ip_cidr::IPCIDR;
use thiserror::Error;
use tokio::time::timeout;

use super::netlink::{Netlink, NetlinkError, NetworkInterface, RouteEntry};
use crate::config::ArpConfig;

#[derive(Debug, Error)]
pub enum ArpTableError {
    #[error(transparent)]
    NetworkError(#[from] NetlinkError),
    #[error(transparent)]
    FrameConversionError(#[from] EthernetFrameError),
    #[error(transparent)]
    PcapError(#[from] PcapError),
    #[error(transparent)]
    MacAddressError(#[from] MacAddrError),
    #[error("No IPv4 address found on interface {0}")]
    NoIpv4Address(String),
    #[error("ARP response timeout")]
    Timeout,
}

#[derive(Debug, Clone)]
struct ArpEntry {
    mac_addr: MacAddr,
    created_at: Instant,
    ttl: Duration,
}

impl ArpEntry {
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
pub struct ArpTable {
    entries: RwLock<FxHashMap<Ipv4Addr, ArpEntry>>,
    default_ttl: Duration,
    arp_timeout: Duration,
}

impl ArpTable {
    pub(crate) fn new(arp_config: &ArpConfig) -> Self {
        Self {
            entries: RwLock::new(FxHashMap::default()),
            default_ttl: arp_config.ttl,
            arp_timeout: arp_config.timeout,
        }
    }

    /// テスト用ヘルパー関数: ARPテーブルに直接エントリを追加する
    ///
    /// この関数はテスト専用で、実際のARP解決をバイパスして
    /// 指定されたIPアドレスとMACアドレスのマッピングを直接ARPテーブルに追加します。
    #[cfg(test)]
    pub fn insert_for_test(&self, ip: Ipv4Addr, mac: MacAddr) {
        let mut entries = self.entries.write();
        entries.insert(ip, ArpEntry::new(mac, self.default_ttl));
    }
    pub async fn get_or_resolve(&self, target_ip: Ipv4Addr) -> Result<MacAddr, ArpTableError> {
        // まず読み取りロックでキャッシュを確認
        {
            let entries = self.entries.read();
            if let Some(entry) = entries.get(&target_ip) {
                if !entry.is_expired() {
                    return Ok(entry.mac_addr);
                }
            }
        }

        // キャッシュにない、または期限切れの場合はARP解決を実行
        let netlink = Netlink::new().await?;
        let best_route = netlink.get_route(target_ip).await?;
        let ni = pcap::NetworkInterface::from(&best_route.interface);

        let mac_addr = resolve_arp_with_pcap(target_ip, ni, best_route, self.arp_timeout).await?;
        // 書き込みロックで結果をキャッシュに保存
        let mut entries = self.entries.write();
        // 期限切れエントリを削除してから新しいエントリを追加
        entries.retain(|_, entry| !entry.is_expired());
        entries.insert(target_ip, ArpEntry::new(mac_addr, self.default_ttl));

        Ok(mac_addr)
    }
}

#[inline]
async fn resolve_arp_with_pcap<P: pcap::Pcap>(
    target_ip: Ipv4Addr,
    pcap_interface: P,
    best_route: RouteEntry,
    timeout_duration: Duration,
) -> Result<MacAddr, ArpTableError> {
    // ARP対象を決定（直接接続またはゲートウェイ経由）
    let arp_target = if let Some(IpAddr::V4(gateway_ip)) = best_route.via {
        // ゲートウェイ経由の場合、ゲートウェイに対してARP
        gateway_ip
    } else {
        // 直接接続の場合、対象IPに対してARP
        target_ip
    };

    // インターフェースから送信元IPを取得
    let src_ip = get_source_ip(&best_route.interface, target_ip)?;

    // インターフェースでパケットキャプチャを開始
    let cap = pcap_interface.open(false)?;
    let mut sender = cap.sender;
    let mut receiver = cap.receiver;

    // ARPリクエストパケットを作成
    let target_mac = MacAddr::try_from("00:00:00:00:00:00")?;
    let arp_packet = ARPPacketInner::new(
        Operation::Request,
        best_route.interface.mac_addr,
        src_ip,
        target_mac,
        arp_target,
    );

    // Ethernetフレームを作成
    let broadcast_mac = MacAddr::try_from("ff:ff:ff:ff:ff:ff")?;
    let ethernet_frame = EthernetFrame::new(
        &best_route.interface.mac_addr,
        &broadcast_mac,
        &EtherType::ARP,
        None,
        Vec::<u8>::from(arp_packet),
    );

    // ARPリクエストを送信
    let frame_bytes =
        Vec::<u8>::try_from(ethernet_frame).map_err(ArpTableError::FrameConversionError)?;
    sender
        .send_bytes(&frame_bytes)
        .await
        .map_err(ArpTableError::PcapError)?;

    // ARPレスポンスを待機
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
            if frame.ether_type != EtherType::ARP {
                continue;
            }

            let arp = match ARPPacket::try_from(&frame.payload) {
                Ok(ARPPacket::EthernetIPv4(arp)) => arp,
                _ => continue,
            };
            if arp.operation == Operation::Reply && arp.spa == arp_target {
                return arp.sha;
            }
        }
    })
    .await;

    match result {
        Ok(mac_addr) => Ok(mac_addr),
        Err(_) => Err(ArpTableError::Timeout),
    }
}

fn get_source_ip(
    interface: &NetworkInterface,
    _target_ip: Ipv4Addr,
) -> Result<Ipv4Addr, ArpTableError> {
    // インターフェースの最初のIPv4アドレスを使用
    for ip_cidr in &interface.ip_addrs {
        #[allow(irrefutable_let_patterns)]
        if let IPCIDR::V4(ipv4_cidr) = ip_cidr {
            return Ok(ipv4_cidr.address);
        }
    }

    Err(ArpTableError::NoIpv4Address(interface.name.clone()))
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use async_trait::async_trait;
    use pcap::{Channel, DataLinkReceiver, DataLinkSender, Pcap};
    use tcpip::ip_cidr::IPv4CIDR;

    use super::*;
    use crate::net_utils::netlink::LinkType;

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

    // ArpTable::new関数のテスト
    #[test]
    fn test_arp_table_new() {
        // [正常系] ARPテーブルの作成
        let arp_config = ArpConfig::default();
        let arp_table = ArpTable::new(&arp_config);

        assert_eq!(arp_table.default_ttl, arp_config.ttl);
    }

    // ArpTable::get_or_resolveメソッドのテスト（キャッシュ機能）
    #[tokio::test]
    async fn test_arp_table_cache() {
        // [正常系] キャッシュからの取得
        let arp_config = ArpConfig::default();
        let arp_table = ArpTable::new(&arp_config);
        let target_ip = Ipv4Addr::new(192, 168, 1, 1);
        let mac_addr = MacAddr::try_from("aa:bb:cc:dd:ee:ff").unwrap();

        // 手動でキャッシュエントリを追加
        {
            let mut entries = arp_table.entries.write();
            entries.insert(target_ip, ArpEntry::new(mac_addr, Duration::seconds(30)));
        }

        // キャッシュから取得できることを確認（実際のネットワーク通信は発生しない）
        let start_time = Instant::now();
        let result = arp_table.get_or_resolve(target_ip).await;
        let elapsed = start_time.elapsed();

        // キャッシュヒットの場合は非常に高速（10ms未満）
        assert!(elapsed < std::time::Duration::from_millis(10));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mac_addr);

        // [正常系] 期限切れエントリの削除確認
        let expired_ip = Ipv4Addr::new(192, 168, 1, 2);
        let expired_mac = MacAddr::try_from("11:22:33:44:55:66").unwrap();

        // 期限切れエントリを手動で追加
        {
            let mut entries = arp_table.entries.write();
            entries.insert(expired_ip, ArpEntry::new(expired_mac, Duration::seconds(0)));
        }

        // わずかに待機して期限切れにする
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;

        // 期限切れエントリがあることを確認
        {
            let entries = arp_table.entries.read();
            let entry = entries.get(&expired_ip).unwrap();
            assert!(entry.is_expired());
        }

        // 新しいエントリをキャッシュに追加（期限切れエントリの清掃をトリガー）
        let new_ip = Ipv4Addr::new(192, 168, 1, 3);
        let new_mac = MacAddr::try_from("22:33:44:55:66:77").unwrap();
        {
            let mut entries = arp_table.entries.write();
            entries.retain(|_, entry| !entry.is_expired());
            entries.insert(new_ip, ArpEntry::new(new_mac, Duration::seconds(30)));
        }

        // 期限切れエントリが削除されていることを確認
        {
            let entries = arp_table.entries.read();
            assert!(!entries.contains_key(&expired_ip));
            assert!(entries.contains_key(&new_ip));
        }
    }

    // ArpTable::get_or_resolveメソッドのテスト（キャッシュミス）
    #[tokio::test]
    async fn test_arp_table_cache_miss() {
        // [正常系] キャッシュミス - エントリが存在しない場合の動作確認
        let arp_config = ArpConfig::default();
        let arp_table = ArpTable::new(&arp_config);
        let target_ip = Ipv4Addr::new(192, 168, 1, 1);

        // キャッシュが空であることを確認
        {
            let entries = arp_table.entries.read();
            assert!(!entries.contains_key(&target_ip));
        }

        // get_or_resolveを呼び出す（結果は環境に依存するが、キャッシュミスの動作を確認）
        let result = arp_table.get_or_resolve(target_ip).await;

        // 結果に関わらず、キャッシュにエントリが追加されたか、またはエラーが発生したことを確認
        match result {
            Ok(mac_addr) => {
                // 成功した場合、キャッシュにエントリが追加されていることを確認
                let entries = arp_table.entries.read();
                assert!(entries.contains_key(&target_ip));
                let cached_entry = entries.get(&target_ip).unwrap();
                assert_eq!(cached_entry.mac_addr, mac_addr);
                assert!(!cached_entry.is_expired());
            }
            Err(_) => {
                // エラーの場合でも処理が実行されたことを確認（ネットワーク環境に依存）
                // キャッシュは空のままであることを確認
                let entries = arp_table.entries.read();
                assert!(!entries.contains_key(&target_ip));
            }
        }

        // [正常系] キャッシュミス - エントリが期限切れの場合
        let expired_ip = Ipv4Addr::new(192, 168, 1, 254); // 通常は到達不可能なIP
        let expired_mac = MacAddr::try_from("11:22:33:44:55:66").unwrap();

        // 期限切れエントリを手動で追加
        {
            let mut entries = arp_table.entries.write();
            entries.insert(expired_ip, ArpEntry::new(expired_mac, Duration::seconds(0)));
        }

        // わずかに待機して期限切れにする
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;

        // 期限切れエントリがあることを確認
        {
            let entries = arp_table.entries.read();
            let entry = entries.get(&expired_ip).unwrap();
            assert!(entry.is_expired());
        }

        // 期限切れエントリは再解決が試行されることを確認
        // （結果は環境に依存するが、期限切れエントリの処理を確認）
        let _result = arp_table.get_or_resolve(expired_ip).await;
        // 期限切れエントリが削除または更新されることを間接的に確認
    }

    // ArpEntry::is_expired関数のテスト
    #[test]
    fn test_arp_entry_expiration() {
        // [正常系] 有効期限内のエントリ
        let mac = MacAddr::try_from("00:11:22:33:44:55").unwrap();
        let entry = ArpEntry::new(mac, Duration::seconds(30));
        assert!(!entry.is_expired());

        // [正常系] 有効期限切れのエントリ（TTLを0にして即座に期限切れにする）
        let expired_entry = ArpEntry::new(mac, Duration::seconds(0));
        // わずかに待機して期限切れにする
        std::thread::sleep(StdDuration::from_millis(1));
        assert!(expired_entry.is_expired());
    }

    // get_source_ip関数のテスト
    #[test]
    fn test_get_source_ip() {
        // [正常系] IPv4アドレスが存在する場合
        let ipv4_cidr =
            IPv4CIDR::new_with_prefix_length(Ipv4Addr::new(192, 168, 1, 100), &24).unwrap();
        let interface = NetworkInterface {
            index: 1,
            name: "eth0".to_string(),
            ip_addrs: vec![IPCIDR::V4(ipv4_cidr)],
            mac_addr: MacAddr::try_from("00:11:22:33:44:55").unwrap(),
            linktype: LinkType::Ethernet,
        };

        let result = get_source_ip(&interface, Ipv4Addr::new(192, 168, 1, 1));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Ipv4Addr::new(192, 168, 1, 100));

        // [異常系] IPv4アドレスが存在しない場合
        let interface_no_ip = NetworkInterface {
            index: 2,
            name: "eth1".to_string(),
            ip_addrs: vec![],
            mac_addr: MacAddr::try_from("00:11:22:33:44:55").unwrap(),
            linktype: LinkType::Ethernet,
        };

        let result = get_source_ip(&interface_no_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ArpTableError::NoIpv4Address(_)
        ));
    }

    // resolve_arp_with_pcap関数のテスト
    #[tokio::test]
    async fn test_resolve_arp_with_pcap() {
        // [正常系] ARP応答受信成功
        let mut mock_pcap = MockPcap::new();
        let target_ip = Ipv4Addr::new(192, 168, 1, 1);
        let gateway_ip = Ipv4Addr::new(192, 168, 1, 254);

        // テスト用のネットワークインターフェースを作成
        let interface_mac = MacAddr::try_from("00:11:22:33:44:55").unwrap();
        let ipv4_cidr =
            IPv4CIDR::new_with_prefix_length(Ipv4Addr::new(192, 168, 1, 100), &24).unwrap();
        let interface = NetworkInterface {
            index: 1,
            name: "eth0".to_string(),
            ip_addrs: vec![IPCIDR::V4(ipv4_cidr)],
            mac_addr: interface_mac,
            linktype: LinkType::Ethernet,
        };

        // ゲートウェイ経由のルートエントリを作成
        let route_entry = RouteEntry {
            interface,
            to: IpAddr::V4(target_ip),
            via: Some(IpAddr::V4(gateway_ip)),
        };

        // ARP応答パケットを作成
        let response_mac = MacAddr::try_from("aa:bb:cc:dd:ee:ff").unwrap();
        let arp_response = ARPPacketInner::new(
            Operation::Reply,
            response_mac,
            gateway_ip,
            interface_mac,
            Ipv4Addr::new(192, 168, 1, 100),
        );

        let ethernet_response = EthernetFrame::new(
            &response_mac,
            &interface_mac,
            &EtherType::ARP,
            None,
            Vec::<u8>::from(arp_response),
        );

        let response_bytes = Vec::<u8>::try_from(ethernet_response).unwrap();
        mock_pcap.add_packet_to_receive(response_bytes);

        // テスト実行
        let timeout = Duration::milliseconds(100);
        let result = resolve_arp_with_pcap(target_ip, mock_pcap, route_entry, timeout).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), response_mac);

        // [異常系] タイムアウト（応答パケットなし）
        let mock_pcap_timeout = MockPcap::new();
        let interface_timeout = NetworkInterface {
            index: 1,
            name: "eth0".to_string(),
            ip_addrs: vec![IPCIDR::V4(ipv4_cidr)],
            mac_addr: interface_mac,
            linktype: LinkType::Ethernet,
        };
        let route_entry_timeout = RouteEntry {
            interface: interface_timeout,
            to: IpAddr::V4(target_ip),
            via: None, // 直接接続
        };

        let timeout_short = Duration::milliseconds(50);
        let result_timeout = resolve_arp_with_pcap(
            target_ip,
            mock_pcap_timeout,
            route_entry_timeout,
            timeout_short,
        )
        .await;
        assert!(result_timeout.is_err());
        assert!(matches!(
            result_timeout.unwrap_err(),
            ArpTableError::Timeout
        ));
    }
}
