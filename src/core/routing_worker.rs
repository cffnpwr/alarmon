use core::panic;
use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use fxhash::FxHashMap;
use log::{debug, warn};
use tcpip::icmp::{self, ICMPMessage};
use tcpip::icmpv6::{self, ICMPv6Message, Message};
use tcpip::ip_packet::IPPacket;
use tcpip::ipv4::{Flags, IPv4Packet, Protocol, TypeOfService};
use tcpip::ipv6::IPv6Packet;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::core::pcap_worker::{PcapWorker, PcapWorkerError};
use crate::net_utils::arp_table::{ArpTable, ArpTableError};
use crate::net_utils::neighbor_discovery::{NeighborCache, NeighborDiscoveryError};
use crate::net_utils::netlink::{Netlink, NetlinkError, NetworkInterface};
use crate::tui::models::{NetworkErrorType, PingUpdate, UpdateMessage};

#[derive(Debug, Error)]
pub enum RoutingWorkerError {
    #[error(transparent)]
    NetworkError(#[from] NetlinkError),
    #[error(transparent)]
    ArpTableError(#[from] ArpTableError),
    #[error(transparent)]
    NeighborDiscoveryError(#[from] NeighborDiscoveryError),
    #[error(transparent)]
    IPv6Error(#[from] tcpip::ipv6::IPv6Error),
    #[error(transparent)]
    PcapWorkerError(#[from] PcapWorkerError),
    #[error("No valid source address found")]
    NoValidSourceAddress,
    #[error("Failed to send packet")]
    SendError,
    #[error("Invalid ICMP payload for IP version")]
    InvalidPayload,
}

#[derive(Debug, Clone)]
pub enum EchoRequest {
    /// IPv4 ICMP Echo Request
    V4 {
        message: icmp::EchoMessage,
        ttl: Option<u8>,
    },

    /// IPv6 ICMPv6 Echo Request
    V6 {
        message: icmpv6::EchoMessage,
        ttl: Option<u8>,
    },
}

/// ネットワークルーティングとパケット配送を担当するWorker
pub struct RoutingWorker {
    /// キャンセレーショントークン
    token: CancellationToken,

    /// ARP解決用テーブル
    arp_table: Arc<ArpTable>,

    /// IPv6 Neighbor Discovery用キャッシュ
    neighbor_cache: Arc<NeighborCache>,

    /// (宛先IP, EchoRequest)のタプルを受信するチャネル
    request_rx: mpsc::Receiver<(IpAddr, EchoRequest)>,

    /// Ping Workerへの応答送信用チャネル（IPアドレス別）
    ping_reply_senders: FxHashMap<IpAddr, mpsc::Sender<IPPacket>>,

    /// Traceroute Workerへの応答送信用チャネル（IPアドレス別）
    traceroute_reply_senders: FxHashMap<IpAddr, mpsc::Sender<IPPacket>>,

    /// TUIにエラーを送信するチャネル
    update_tx: mpsc::Sender<UpdateMessage>,

    /// インターフェース別PcapWorker送信チャネル
    tx: FxHashMap<u32, mpsc::Sender<IPPacket>>,

    /// 管理中のPcapWorkerのハンドル
    pcap_worker_handles: Vec<tokio::task::JoinHandle<Result<(), PcapWorkerError>>>,
}

impl RoutingWorker {
    /// 新しいRoutingWorkerを作成
    pub fn new(
        token: CancellationToken,
        arp_table: Arc<ArpTable>,
        neighbor_cache: Arc<NeighborCache>,
        request_rx: mpsc::Receiver<(IpAddr, EchoRequest)>,
        ping_reply_senders: FxHashMap<IpAddr, mpsc::Sender<IPPacket>>,
        traceroute_reply_senders: FxHashMap<IpAddr, mpsc::Sender<IPPacket>>,
        update_tx: mpsc::Sender<UpdateMessage>,
    ) -> Self {
        Self {
            token,
            arp_table,
            neighbor_cache,
            request_rx,
            ping_reply_senders,
            traceroute_reply_senders,
            update_tx,
            tx: FxHashMap::default(),
            pcap_worker_handles: Vec::new(),
        }
    }

    /// Workerのメインループを開始
    pub async fn run(mut self) -> Result<(), RoutingWorkerError> {
        debug!("RoutingWorker: Starting main loop");

        loop {
            tokio::select! {
                _ = self.token.cancelled() => {
                    debug!("RoutingWorker is stopping");
                    break;
                }
                Some((destination, echo_request)) = self.request_rx.recv() => {
                    if let Err(e) = self.handle_echo_request(destination, echo_request).await {
                        warn!("RoutingWorker: Failed to handle echo request: {e}");
                    }
                }
            }
        }
        Ok(())
    }

    /// EchoRequestを処理してIPパケットとしてPcapWorkerに送信
    async fn handle_echo_request(
        &mut self,
        destination: IpAddr,
        echo_request: EchoRequest,
    ) -> Result<(), RoutingWorkerError> {
        // 既存の完璧なroute_icmp_internalメソッドを使用
        match self.route_icmp_internal(destination, echo_request).await {
            Ok(src_ip) => {
                debug!("RoutingWorker: Successfully routed packet from {src_ip} to {destination}");
                Ok(())
            }
            Err(e) => {
                warn!("RoutingWorker: Routing failed: {e}");

                // NetlinkErrorをTUIに送信
                if let RoutingWorkerError::NetworkError(ref netlink_error) = e {
                    self.send_network_error_to_tui(destination, netlink_error)
                        .await;
                }

                Err(e)
            }
        }
    }

    /// ICMPメッセージのルーティング送信（内部実装）
    async fn route_icmp_internal(
        &mut self,
        dst: IpAddr,
        mut icmp_payload: EchoRequest,
    ) -> Result<IpAddr, RoutingWorkerError> {
        // 宛先までのルートを取得
        let netlink = Netlink::new().await?;
        #[cfg(target_os = "linux")]
        let mut netlink = netlink;
        let route = netlink.get_route(dst).await?;

        // 送信元IP決定
        let src_ip = route
            .interface
            .get_best_source_ip(&dst)
            .ok_or(RoutingWorkerError::NoValidSourceAddress)?;

        // ICMPv6の場合、送信元IPアドレスを使用してChecksumを更新
        if let EchoRequest::V6 {
            message: mut msg,
            ttl,
        } = icmp_payload
        {
            let src = if let IpAddr::V6(src_v6) = src_ip {
                src_v6
            } else {
                panic!("Expected IPv6 source address for ICMPv6 message");
            };
            let dst = if let IpAddr::V6(dst_v6) = dst {
                dst_v6
            } else {
                panic!("Expected IPv6 destination address for ICMPv6 message");
            };
            msg.checksum = 0;
            msg.checksum = msg.calculate_checksum(src, dst);
            icmp_payload = EchoRequest::V6 { message: msg, ttl };
        }

        // IPパケットを構築
        let ip_packet = self.build_ip_packet(src_ip, dst, icmp_payload)?;
        debug!("RoutingWorker: Built IP packet successfully");

        // 適切なPcapWorkerに送信（存在しない場合は作成）
        let sender = match self.tx.get(&route.interface.index) {
            Some(sender) => sender.clone(),
            None => {
                // インターフェース用のPcapWorkerが存在しない場合、新しく作成
                debug!(
                    "RoutingWorker: Creating new PcapWorker for interface {}",
                    route.interface.index
                );
                self.create_pcap_worker(&route.interface).await?
            }
        };

        debug!(
            "RoutingWorker: Sending IP packet to PcapWorker via interface {}",
            route.interface.index
        );
        sender
            .send(ip_packet)
            .await
            .map_err(|_| RoutingWorkerError::SendError)?;

        Ok(src_ip)
    }

    async fn create_pcap_worker(
        &mut self,
        interface: &NetworkInterface,
    ) -> Result<mpsc::Sender<IPPacket>, RoutingWorkerError> {
        debug!(
            "RoutingWorker: Creating PcapWorker for interface {} ({})",
            interface.name, interface.index
        );

        // PcapWorkerを作成
        let pcap_result = PcapWorker::new(
            self.token.clone(),
            interface.clone(),
            self.arp_table.clone(),
            self.neighbor_cache.clone(),
            self.ping_reply_senders.clone(),
            self.traceroute_reply_senders.clone(),
        )?;

        // 送信チャネルを保存
        let sender = pcap_result.sender.clone();
        self.tx.insert(interface.index, sender.clone());

        // PcapWorkerを直接起動して管理
        let pcap_worker = pcap_result.worker;
        let handle = tokio::spawn(async move { pcap_worker.run().await });
        self.pcap_worker_handles.push(handle);

        debug!(
            "RoutingWorker: Successfully created and started PcapWorker for interface {}",
            interface.index
        );

        Ok(sender)
    }

    /// IPパケットを構築
    fn build_ip_packet(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        icmp_payload: EchoRequest,
    ) -> Result<IPPacket, RoutingWorkerError> {
        match (src_ip, dst_ip, icmp_payload) {
            (
                IpAddr::V4(src_v4),
                IpAddr::V4(dst_v4),
                EchoRequest::V4 {
                    message: echo_msg,
                    ttl,
                },
            ) => {
                // IPv4 ICMP Echo Requestを作成
                let icmp_bytes: Bytes = ICMPMessage::Echo(echo_msg).into();

                let ipv4_packet = IPv4Packet::new(
                    TypeOfService::default(),
                    0,
                    Flags::default(),
                    0,
                    ttl.unwrap_or(64), // TTL値を使用（デフォルトは64）
                    Protocol::ICMP,
                    src_v4,
                    dst_v4,
                    Vec::new(),
                    icmp_bytes,
                );

                Ok(IPPacket::V4(ipv4_packet))
            }
            (
                IpAddr::V6(src_v6),
                IpAddr::V6(dst_v6),
                EchoRequest::V6 {
                    message: echo_msg,
                    ttl,
                },
            ) => {
                // IPv6 ICMPv6 Echo Requestを作成
                let icmpv6_msg = ICMPv6Message::echo_request(
                    echo_msg.identifier,
                    echo_msg.sequence_number,
                    echo_msg.data.clone(),
                    src_v6,
                    dst_v6,
                );
                let icmpv6_bytes: Bytes = icmpv6_msg.into();

                let ipv6_packet = IPv6Packet::new(
                    0,
                    0,
                    Protocol::IPv6ICMP,
                    ttl.unwrap_or(64),
                    src_v6,
                    dst_v6,
                    icmpv6_bytes,
                )?;

                Ok(IPPacket::V6(ipv6_packet))
            }
            _ => Err(RoutingWorkerError::InvalidPayload),
        }
    }

    /// NetlinkErrorをTUIに送信
    async fn send_network_error_to_tui(&self, destination: IpAddr, netlink_error: &NetlinkError) {
        let network_error = match netlink_error {
            NetlinkError::NoRouteToHost => NetworkErrorType::NoRouteToHost,
            _ => return, // 他のNetlinkErrorは現在TUIに送信しない
        };

        let ping_update = PingUpdate {
            id: 0,
            host: destination,
            latency: Err(network_error),
        };

        if let Err(e) = self.update_tx.send(UpdateMessage::Ping(ping_update)).await {
            warn!("Failed to send network error to TUI: {e}");
        } else {
            debug!("Sent network error to TUI: {netlink_error:?} for {destination}");
        }
    }
}

#[cfg(test)]
mod tests {
    use tcpip::icmp;

    use super::*;

    #[test]
    fn test_echo_request() {
        // [正常系] EchoRequestの作成と基本機能確認

        let echo_request_v4 = EchoRequest::V4 {
            message: icmp::EchoMessage::new_request(1234, 5678, vec![0; 32]),
            ttl: Some(64),
        };

        match echo_request_v4 {
            EchoRequest::V4 { message, ttl } => {
                assert_eq!(message.identifier, 1234);
                assert_eq!(message.sequence_number, 5678);
                assert_eq!(ttl, Some(64));
            }
            _ => std::panic!("Expected V4 variant"),
        }
    }

    #[test]
    fn test_routing_worker_error() {
        // [正常系] エラーの表示確認
        let error1 = RoutingWorkerError::NoValidSourceAddress;
        assert_eq!(error1.to_string(), "No valid source address found");

        let error2 = RoutingWorkerError::SendError;
        assert_eq!(error2.to_string(), "Failed to send packet");

        let error3 = RoutingWorkerError::InvalidPayload;
        assert_eq!(error3.to_string(), "Invalid ICMP payload for IP version");
    }
}
