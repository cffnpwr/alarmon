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
use tcpip::ipv6::ipv6_address::IPv6AddrExt;
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
    let multicst_addr = nd_target.into_multicast_ipv6();
    let src_mac = best_route.interface.mac_addr;
    let mut src_mac_bytes = BytesMut::from(&[1, 1][..]);
    src_mac_bytes.extend_from_slice(&<[u8; 6]>::from(src_mac));
    let ns_message =
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
    let multicast_mac = nd_target.into_multicast_mac();
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

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::time::Instant;

    use super::*;

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
}
