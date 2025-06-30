use std::net::Ipv4Addr;
use std::time::Duration;

use pcap::PcapError;
use tcpip::ethernet::{EtherType, EthernetFrame, EthernetFrameError, MacAddr, MacAddrError};
use tcpip::icmp::{ICMPError, ICMPMessage};
use tcpip::ipv4::{Flags, IPv4Packet, Protocol, TypeOfService};
use thiserror::Error;
use tokio::time::{Instant, timeout};

use crate::net_utils::netlink::{Netlink, NetlinkError};

#[derive(Debug, Error)]
pub enum PingError {
    #[error(transparent)]
    NetworkError(#[from] NetlinkError),
    #[error(transparent)]
    FrameConversionError(#[from] EthernetFrameError),
    #[error(transparent)]
    PcapError(#[from] PcapError),
    #[error(transparent)]
    MacAddressError(#[from] MacAddrError),
    #[error(transparent)]
    ICMPError(#[from] ICMPError),
    #[error("Network interface '{0}' not found")]
    InterfaceNotFound(String),
    #[error("No IPv4 address found on interface {0}")]
    NoIpv4Address(String),
    #[error("Ping response timeout")]
    Timeout,
}

pub struct Ping;

impl Ping {
    pub async fn ping(
        target_ip: Ipv4Addr,
        target_mac: MacAddr,
        timeout_sec: u64,
    ) -> Result<Duration, PingError> {
        let start_time = Instant::now();

        // ルーティング情報を取得
        let netlink = Netlink::new()?;
        let best_route = netlink.get_route(target_ip)?;

        // インターフェースから送信元IPを取得
        let src_ip = Self::get_source_ip(&best_route.interface, target_ip)?;

        // インターフェースでパケットキャプチャを開始
        let ni = pcap::NetworkInterface::find_by_name(&best_route.interface.name)
            .ok_or_else(|| PingError::InterfaceNotFound(best_route.interface.name.clone()))?;

        let cap = pcap::open(&ni, false).map_err(PingError::PcapError)?;
        let (mut sender, mut receiver) = match cap {
            pcap::Channel::Ethernet(s, r) => (s, r),
        };

        // ICMP Echo Requestパケットを作成
        let identifier = 0x1234;
        let sequence_number = 1;
        let ping_data = b"Hello, ping!";
        let icmp_message = ICMPMessage::echo_request(identifier, sequence_number, ping_data);

        // IPv4パケットを作成
        let icmp_bytes: Vec<u8> = icmp_message.into();
        let ipv4_packet = IPv4Packet::new(
            TypeOfService::default(),
            20 + icmp_bytes.len() as u16, // IPv4ヘッダー(20) + ICMPペイロード
            1,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            src_ip,
            target_ip,
            vec![],
            icmp_bytes,
        );

        // Ethernetフレームを作成
        let ipv4_bytes: Vec<u8> = ipv4_packet.into();
        let ethernet_frame = EthernetFrame::new(
            &best_route.interface.mac_addr,
            &target_mac,
            &EtherType::IPv4,
            None,
            ipv4_bytes,
        );

        // ICMP Echo Requestを送信
        let frame_bytes =
            Vec::<u8>::try_from(ethernet_frame).map_err(PingError::FrameConversionError)?;
        sender
            .send_bytes(&frame_bytes)
            .await
            .map_err(PingError::PcapError)?;

        println!(
            "Pingリクエストを送信しました: {} -> {} (インターフェース: {})",
            src_ip, target_ip, best_route.interface.name
        );

        // ICMP Echo Replyを待機
        let timeout_duration = Duration::from_secs(timeout_sec);
        let result = timeout(timeout_duration, async {
            loop {
                let packet = match receiver.recv().await {
                    Ok(packet) => packet,
                    _ => continue,
                };

                let frame = match EthernetFrame::try_from(packet.as_slice()) {
                    Ok(frame) => frame,
                    Err(_) => continue,
                };

                if frame.ether_type != EtherType::IPv4 {
                    continue;
                }

                let ipv4_packet = match IPv4Packet::try_from(&frame.payload) {
                    Ok(packet) => packet,
                    Err(_) => continue,
                };

                if ipv4_packet.protocol != Protocol::ICMP {
                    continue;
                }

                let icmp_message = match ICMPMessage::try_from(&ipv4_packet.payload) {
                    Ok(message) => message,
                    Err(_) => continue,
                };

                if let ICMPMessage::EchoReply(echo_reply) = icmp_message {
                    if echo_reply.identifier == identifier
                        && echo_reply.sequence_number == sequence_number
                        && ipv4_packet.src == target_ip
                    {
                        println!("Pingレスポンスを受信: {} -> {}", target_ip, src_ip);
                        return start_time.elapsed();
                    }
                }
            }
        })
        .await;

        match result {
            Ok(duration) => Ok(duration),
            Err(_) => Err(PingError::Timeout),
        }
    }

    fn get_source_ip(
        interface: &crate::net_utils::netlink::NetworkInterface,
        _target_ip: Ipv4Addr,
    ) -> Result<Ipv4Addr, PingError> {
        // インターフェースの最初のIPv4アドレスを使用
        for ip_cidr in &interface.ip_addrs {
            #[allow(irrefutable_let_patterns)]
            if let tcpip::ip_cidr::IPCIDR::V4(ipv4_cidr) = ip_cidr {
                return Ok(ipv4_cidr.address);
            }
        }

        Err(PingError::NoIpv4Address(interface.name.clone()))
    }
}
