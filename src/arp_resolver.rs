use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use pcap::PcapError;
use tcpip::arp::{ARPPacket, ARPPacketInner, Operation};
use tcpip::ethernet::{EtherType, EthernetFrame, EthernetFrameError, MacAddr, MacAddrError};
use tcpip::ip_cidr::IPCIDR;
use thiserror::Error;
use tokio::time::Instant;

use crate::net_utils::netlink::{Netlink, NetlinkError};

#[derive(Debug, Error)]
pub enum ArpResolverError {
    #[error(transparent)]
    NetworkError(#[from] NetlinkError),
    #[error(transparent)]
    FrameConversionError(#[from] EthernetFrameError),
    #[error(transparent)]
    PcapError(#[from] PcapError),
    #[error(transparent)]
    MacAddressError(#[from] MacAddrError),
    #[error("Network interface '{0}' not found")]
    InterfaceNotFound(String),
    #[error("Invalid gateway IP address")]
    InvalidGatewayIp,
    #[error("No IPv4 address found on interface {0}")]
    NoIpv4Address(String),
    #[error("ARP response timeout")]
    Timeout,
}

pub struct ArpResolver;

impl ArpResolver {
    pub async fn resolve(target_ip: Ipv4Addr) -> Result<MacAddr, ArpResolverError> {
        // ルーティング情報を取得（カーネルが最適ルートを自動選択）
        let netlink = Netlink::new()?;
        let best_route = netlink.get_route(target_ip)?;

        // ARP対象を決定（直接接続またはゲートウェイ経由）
        let arp_target = if best_route.is_gateway() {
            // ゲートウェイ経由の場合、ゲートウェイに対してARP
            match best_route.via {
                Some(IpAddr::V4(gateway_ip)) => gateway_ip,
                _ => return Err(ArpResolverError::InvalidGatewayIp),
            }
        } else {
            // 直接接続の場合、対象IPに対してARP
            target_ip
        };

        // インターフェースから送信元IPを取得
        let src_ip = Self::get_source_ip(&best_route.interface, target_ip)?;

        // インターフェースでパケットキャプチャを開始
        let ni =
            pcap::NetworkInterface::find_by_name(&best_route.interface.name).ok_or_else(|| {
                ArpResolverError::InterfaceNotFound(best_route.interface.name.clone())
            })?;

        let cap = pcap::open(&ni, false).map_err(ArpResolverError::PcapError)?;
        let (mut sender, mut receiver) = match cap {
            pcap::Channel::Ethernet(s, r) => (s, r),
        };

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
            Vec::<u8>::try_from(ethernet_frame).map_err(ArpResolverError::FrameConversionError)?;
        sender
            .send_bytes(&frame_bytes)
            .map_err(ArpResolverError::PcapError)?;

        println!(
            "ARPリクエストを送信しました: {} -> {} (インターフェース: {})",
            src_ip, arp_target, best_route.interface.name
        );

        // ARPレスポンスを待機
        let timeout_duration = Duration::from_secs(5);
        let start_time = Instant::now();

        while start_time.elapsed() < timeout_duration {
            let packet = match receiver.recv() {
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
                println!("ARPレスポンスを受信: {} -> {}", arp.spa, arp.sha);
                return Ok(arp.sha);
            }
        }

        Err(ArpResolverError::Timeout)
    }

    fn get_source_ip(
        interface: &crate::net_utils::netlink::NetworkInterface,
        _target_ip: Ipv4Addr,
    ) -> Result<Ipv4Addr, ArpResolverError> {
        // インターフェースの最初のIPv4アドレスを使用
        for ip_cidr in &interface.ip_addrs {
            #[allow(irrefutable_let_patterns)]
            if let IPCIDR::V4(ipv4_cidr) = ip_cidr {
                return Ok(ipv4_cidr.address);
            }
        }

        Err(ArpResolverError::NoIpv4Address(interface.name.clone()))
    }
}
