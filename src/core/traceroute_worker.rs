use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration as StdDuration;

use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use log::{debug, info, warn};
use tcpip::icmp::{ICMPError, ICMPMessage, TimeExceededCode};
use tcpip::icmpv6::{ICMPv6Error, ICMPv6Message};
use tcpip::ip_packet::IPPacket;
use tcpip::ipv4::{Flags, IPv4Packet, Protocol, TypeOfService};
use tcpip::ipv6::IPv6Packet;
use thiserror::Error;
use tokio::sync::{broadcast, mpsc};
use tokio::time::{interval, timeout};
use tokio_util::sync::CancellationToken;

use crate::net_utils::netlink::NetlinkError;
use crate::tui::models::{NetworkErrorType, TracerouteHop, TracerouteUpdate, UpdateMessage};

#[derive(Debug, Error)]
pub enum TracerouteWorkerError {
    #[error(transparent)]
    NetworkFailed(#[from] NetlinkError),
    #[error(transparent)]
    IcmpError(#[from] ICMPError),
    #[error(transparent)]
    ICMPv6Error(#[from] ICMPv6Error),
    #[error(transparent)]
    IPv6Error(#[from] tcpip::ipv6::IPv6Error),
    #[error("Channel send error")]
    ChannelSendError,
}

/// 各ホップの情報
#[derive(Debug, Clone, PartialEq, Eq)]
struct HopInfo {
    /// ホップ番号（TTL値）
    hop_number: u8,
    /// ホップのIPアドレス（タイムアウト時はNone）
    ip_address: Option<IpAddr>,
    /// 応答時間（タイムアウト時はNone）
    rtt: Option<Duration>,
    /// 応答を受信した時刻（タイムアウト時はNone）
    received_at: Option<DateTime<Utc>>,
    /// ICMPエラー情報
    error_info: Option<NetworkErrorType>,
}

/// Tracerouteの応答タイプ
#[derive(Debug)]
enum TracerouteResponse {
    /// Time Exceeded応答（中間ホップ）
    TimeExceeded(HopInfo),
    /// Echo Reply応答（最終ホップ）
    EchoReply(HopInfo),
    /// ICMPエラー応答
    Error(HopInfo),
    /// タイムアウト
    Timeout { ttl: u8 },
}

pub struct TracerouteWorker {
    /// キャンセレーショントークン
    token: CancellationToken,
    /// ICMP Echo Requestの送信元識別子
    identifier: u16,
    /// 送信元IPアドレス
    src: IpAddr,
    /// 宛先IPアドレス
    target: IpAddr,
    /// traceroute実行間隔
    interval: Duration,
    /// 最大ホップ数
    max_hops: u8,
    /// IPパケットを送信するためのチャネル
    tx: mpsc::Sender<IPPacket>,
    /// IPパケットを受信するためのチャネル
    rx: broadcast::Receiver<IPPacket>,
    /// UpdateMessage送信用チャネル
    update_tx: mpsc::Sender<UpdateMessage>,
}

impl TracerouteWorker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token: CancellationToken,
        id: u16,
        src: IpAddr,
        target: IpAddr,
        interval: Duration,
        max_hops: u8,
        tx: mpsc::Sender<IPPacket>,
        rx: broadcast::Receiver<IPPacket>,
        update_tx: mpsc::Sender<UpdateMessage>,
    ) -> Self {
        Self {
            token,
            identifier: id,
            src,
            target,
            interval,
            max_hops,
            tx,
            rx,
            update_tx,
        }
    }

    pub async fn run(mut self) -> Result<(), TracerouteWorkerError> {
        info!("Starting Traceroute Worker for target: {}", self.target);

        let mut interval = interval(self.interval.to_std().expect("Invalid duration"));

        loop {
            tokio::select! {
                _ = self.token.cancelled() => {
                    info!("Traceroute Worker for target {} is stopping", self.target);
                    break;
                }
                _ = interval.tick() => {
                    if let Err(e) = self.run_single_traceroute().await {
                        warn!("Traceroute to {} failed: {}", self.target, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// 1回のtracerouteを実行
    async fn run_single_traceroute(&mut self) -> Result<(), TracerouteWorkerError> {
        info!("Starting traceroute to {}", self.target);
        let mut hops = Vec::new();

        for ttl in 1..=self.max_hops {
            // キャンセレーション確認
            if self.token.is_cancelled() {
                debug!("Traceroute cancelled during TTL {ttl}");
                return Ok(());
            }

            match self.send_and_wait_for_response(ttl).await? {
                TracerouteResponse::TimeExceeded(hop_info) => {
                    match (hop_info.ip_address, hop_info.rtt) {
                        (Some(ip), Some(rtt)) => {
                            debug!(
                                "Hop {}: {} ({}ms)",
                                hop_info.hop_number,
                                ip,
                                rtt.num_milliseconds()
                            );
                        }
                        _ => {
                            debug!("Hop {}: * * *", hop_info.hop_number);
                        }
                    }
                    hops.push(hop_info);
                }
                TracerouteResponse::EchoReply(hop_info) => {
                    match (hop_info.ip_address, hop_info.rtt) {
                        (Some(ip), Some(rtt)) => {
                            debug!(
                                "Target reached at hop {}: {} ({}ms)",
                                hop_info.hop_number,
                                ip,
                                rtt.num_milliseconds()
                            );
                        }
                        _ => {
                            debug!("Target reached at hop {}: * * *", hop_info.hop_number);
                        }
                    }
                    hops.push(hop_info);
                    break; // 宛先に到達したので終了
                }
                TracerouteResponse::Error(hop_info) => {
                    debug!(
                        "Error at hop {}: {:?}",
                        hop_info.hop_number, hop_info.error_info
                    );
                    hops.push(hop_info.clone());
                    // エラーの種類によってはtracerouteを継続するか終了するかを判定
                    if let Some(NetworkErrorType::DestinationUnreachable(_)) = hop_info.error_info {
                        break; // Destination Unreachableの場合は終了
                    }
                    // その他のエラーは継続
                }
                TracerouteResponse::Timeout { ttl } => {
                    debug!("Timeout at hop {ttl}");
                    // タイムアウトもホップとして記録（*で表示するため）
                    let timeout_hop = HopInfo {
                        hop_number: ttl,
                        ip_address: None,
                        rtt: None,
                        received_at: None,
                        error_info: None,
                    };
                    hops.push(timeout_hop);
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        self.send_traceroute_update(&hops).await;
        Ok(())
    }

    /// 指定されたTTLでICMP Echo Requestを送信し、応答を待つ
    async fn send_and_wait_for_response(
        &mut self,
        ttl: u8,
    ) -> Result<TracerouteResponse, TracerouteWorkerError> {
        let sent_at = Utc::now();

        match (self.src, self.target) {
            (IpAddr::V4(src_v4), IpAddr::V4(target_v4)) => {
                self.send_ipv4_traceroute(src_v4, target_v4, ttl, sent_at)
                    .await
            }
            (IpAddr::V6(src_v6), IpAddr::V6(target_v6)) => {
                self.send_ipv6_traceroute(src_v6, target_v6, ttl, sent_at)
                    .await
            }
            _ => {
                Err(TracerouteWorkerError::ChannelSendError) // IP版本不匹配
            }
        }
    }

    async fn send_ipv4_traceroute(
        &mut self,
        src: Ipv4Addr,
        target: Ipv4Addr,
        ttl: u8,
        sent_at: DateTime<Utc>,
    ) -> Result<TracerouteResponse, TracerouteWorkerError> {
        // ICMP Echo Requestを作成
        let icmp_msg = ICMPMessage::echo_request(self.identifier, ttl as u16, vec![0; 32]);
        let icmp_bytes: Bytes = icmp_msg.into();

        // IPv4パケットを作成
        let pkt = IPv4Packet::new(
            TypeOfService::default(),
            self.identifier,
            Flags::default(),
            0,
            ttl,
            Protocol::ICMP,
            src,
            target,
            Vec::new(),
            icmp_bytes,
        );

        // パケットを送信
        self.tx
            .send(IPPacket::V4(pkt))
            .await
            .map_err(|_| TracerouteWorkerError::ChannelSendError)?;

        debug!("Sent ICMP Echo Request with TTL {ttl} to {target}");

        // 応答を待機（タイムアウト付き）
        let timeout_duration = StdDuration::from_secs(3);

        match timeout(timeout_duration, self.wait_for_response(ttl, sent_at)).await {
            Ok(Ok(Some(response))) => Ok(response),
            Ok(Ok(None)) => Ok(TracerouteResponse::Timeout { ttl }),
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(TracerouteResponse::Timeout { ttl }),
        }
    }

    async fn send_ipv6_traceroute(
        &mut self,
        src: Ipv6Addr,
        target: Ipv6Addr,
        ttl: u8,
        sent_at: DateTime<Utc>,
    ) -> Result<TracerouteResponse, TracerouteWorkerError> {
        // ICMPv6 Echo Requestを作成
        let icmpv6_msg =
            ICMPv6Message::echo_request(self.identifier, ttl as u16, vec![0; 32], src, target);
        let icmpv6_bytes: Bytes = icmpv6_msg.into();

        // IPv6パケットを作成、Hop LimitをTTLとして使用
        let pkt = IPv6Packet::new(0, 0, Protocol::IPv6ICMP, ttl, src, target, icmpv6_bytes)?;

        // パケットを送信
        self.tx
            .send(IPPacket::V6(pkt))
            .await
            .map_err(|_| TracerouteWorkerError::ChannelSendError)?;

        debug!("Sent ICMPv6 Echo Request with Hop Limit {ttl} to {target}");

        // 応答を待機（タイムアウト付き）
        let timeout_duration = StdDuration::from_secs(3);

        match timeout(timeout_duration, self.wait_for_response(ttl, sent_at)).await {
            Ok(Ok(Some(response))) => Ok(response),
            Ok(Ok(None)) => Ok(TracerouteResponse::Timeout { ttl }),
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(TracerouteResponse::Timeout { ttl }),
        }
    }

    /// 応答パケットを待機
    async fn wait_for_response(
        &mut self,
        expected_ttl: u8,
        sent_at: DateTime<Utc>,
    ) -> Result<Option<TracerouteResponse>, TracerouteWorkerError> {
        loop {
            tokio::select! {
                _ = self.token.cancelled() => {
                    return Ok(None);
                }
                Ok(ip_pkt) = self.rx.recv() => {
                    let received_at = Utc::now();
                    if let Some(response) = self.process_received_packet(ip_pkt, expected_ttl, sent_at, received_at)? {
                        return Ok(Some(response));
                    }
                    // 関係ないパケットの場合は継続
                }
            }
        }
    }

    /// 受信したパケットを処理
    fn process_received_packet(
        &self,
        ip_pkt: IPPacket,
        expected_ttl: u8,
        sent_at: DateTime<Utc>,
        received_at: DateTime<Utc>,
    ) -> Result<Option<TracerouteResponse>, TracerouteWorkerError> {
        match ip_pkt {
            IPPacket::V4(ipv4_pkt) => {
                self.process_ipv4_packet(ipv4_pkt, expected_ttl, sent_at, received_at)
            }
            IPPacket::V6(ipv6_pkt) => {
                self.process_ipv6_packet(ipv6_pkt, expected_ttl, sent_at, received_at)
            }
        }
    }

    /// IPv4パケットを処理
    fn process_ipv4_packet(
        &self,
        pkt: IPv4Packet,
        expected_ttl: u8,
        sent_at: DateTime<Utc>,
        received_at: DateTime<Utc>,
    ) -> Result<Option<TracerouteResponse>, TracerouteWorkerError> {
        let icmp_msg = ICMPMessage::try_from(&pkt.payload)?;
        let rtt = received_at - sent_at;

        match icmp_msg {
            // Time Exceeded応答（中間ホップ）
            ICMPMessage::TimeExceeded(time_exceeded) => {
                if time_exceeded.code == TimeExceededCode::TtlExceeded {
                    let echo_req = if let Ok(ICMPMessage::Echo(echo_req)) =
                        ICMPMessage::try_from(&time_exceeded.original_datagram.payload)
                    {
                        echo_req
                    } else {
                        return Ok(None);
                    };
                    if echo_req.identifier != self.identifier
                        || echo_req.sequence_number != expected_ttl as u16
                    {
                        return Ok(None);
                    }
                    let hop_info = HopInfo {
                        hop_number: expected_ttl,
                        ip_address: Some(pkt.src.into()),
                        rtt: Some(rtt),
                        received_at: Some(received_at),
                        error_info: None,
                    };
                    return Ok(Some(TracerouteResponse::TimeExceeded(hop_info)));
                }
            }
            // Echo Reply応答（宛先到達）
            ICMPMessage::EchoReply(echo) => {
                if echo.identifier != self.identifier
                    || IpAddr::V4(pkt.src) != self.target
                    || echo.sequence_number != expected_ttl as u16
                {
                    return Ok(None);
                }
                let hop_info = HopInfo {
                    hop_number: expected_ttl,
                    ip_address: Some(pkt.src.into()),
                    rtt: Some(rtt),
                    received_at: Some(received_at),
                    error_info: None,
                };
                return Ok(Some(TracerouteResponse::EchoReply(hop_info)));
            }
            // Destination Unreachable処理
            ICMPMessage::DestinationUnreachable(dest_unreachable) => {
                let echo_req = if let Ok(ICMPMessage::Echo(echo_req)) =
                    ICMPMessage::try_from(&dest_unreachable.original_datagram.payload)
                {
                    echo_req
                } else {
                    return Ok(None);
                };
                if echo_req.identifier != self.identifier
                    || echo_req.sequence_number != expected_ttl as u16
                {
                    return Ok(None);
                }
                let hop_info = HopInfo {
                    hop_number: expected_ttl,
                    ip_address: Some(pkt.src.into()),
                    rtt: Some(rtt),
                    received_at: Some(received_at),
                    error_info: Some(NetworkErrorType::DestinationUnreachable(
                        dest_unreachable.code,
                    )),
                };
                return Ok(Some(TracerouteResponse::Error(hop_info)));
            }
            // Parameter Problem処理
            ICMPMessage::ParameterProblem(param_problem) => {
                let echo_req = if let Ok(ICMPMessage::Echo(echo_req)) =
                    ICMPMessage::try_from(&param_problem.original_datagram.payload)
                {
                    echo_req
                } else {
                    return Ok(None);
                };
                if echo_req.identifier != self.identifier
                    || echo_req.sequence_number != expected_ttl as u16
                {
                    return Ok(None);
                }
                let hop_info = HopInfo {
                    hop_number: expected_ttl,
                    ip_address: Some(pkt.src.into()),
                    rtt: Some(rtt),
                    received_at: Some(received_at),
                    error_info: Some(NetworkErrorType::ParameterProblem),
                };
                return Ok(Some(TracerouteResponse::Error(hop_info)));
            }
            // Redirect処理
            ICMPMessage::Redirect(redirect) => {
                let echo_req = if let Ok(ICMPMessage::Echo(echo_req)) =
                    ICMPMessage::try_from(&redirect.original_datagram.payload)
                {
                    echo_req
                } else {
                    return Ok(None);
                };
                if echo_req.identifier != self.identifier
                    || echo_req.sequence_number != expected_ttl as u16
                {
                    return Ok(None);
                }
                let hop_info = HopInfo {
                    hop_number: expected_ttl,
                    ip_address: Some(pkt.src.into()),
                    rtt: Some(rtt),
                    received_at: Some(received_at),
                    error_info: Some(NetworkErrorType::Redirect(redirect.code)),
                };
                return Ok(Some(TracerouteResponse::Error(hop_info)));
            }
            _ => {}
        }

        Ok(None)
    }

    /// IPv6パケットを処理
    fn process_ipv6_packet(
        &self,
        pkt: IPv6Packet,
        expected_ttl: u8,
        sent_at: DateTime<Utc>,
        received_at: DateTime<Utc>,
    ) -> Result<Option<TracerouteResponse>, TracerouteWorkerError> {
        let icmpv6_msg = ICMPv6Message::try_from(&pkt.payload)?;
        let rtt = received_at - sent_at;

        match icmpv6_msg {
            // Time Exceeded応答（中間ホップ）
            ICMPv6Message::TimeExceeded(time_exceeded) => {
                let echo_req = if let Ok(ICMPv6Message::EchoRequest(echo_req)) =
                    ICMPv6Message::try_from(&time_exceeded.original_packet.payload)
                {
                    echo_req
                } else {
                    return Ok(None);
                };
                if echo_req.identifier != self.identifier
                    || echo_req.sequence_number != expected_ttl as u16
                {
                    return Ok(None);
                }
                let hop_info = HopInfo {
                    hop_number: expected_ttl,
                    ip_address: Some(pkt.src.into()),
                    rtt: Some(rtt),
                    received_at: Some(received_at),
                    error_info: None,
                };
                return Ok(Some(TracerouteResponse::TimeExceeded(hop_info)));
            }
            // Echo Reply応答（宛先到達）
            ICMPv6Message::EchoReply(echo) => {
                if echo.identifier != self.identifier
                    || IpAddr::V6(pkt.src) != self.target
                    || echo.sequence_number != expected_ttl as u16
                {
                    return Ok(None);
                }
                let hop_info = HopInfo {
                    hop_number: expected_ttl,
                    ip_address: Some(pkt.src.into()),
                    rtt: Some(rtt),
                    received_at: Some(received_at),
                    error_info: None,
                };
                return Ok(Some(TracerouteResponse::EchoReply(hop_info)));
            }
            // Destination Unreachable処理
            ICMPv6Message::DestinationUnreachable(dest_unreachable) => {
                let echo_req = if let Ok(ICMPv6Message::EchoRequest(echo_req)) =
                    ICMPv6Message::try_from(&dest_unreachable.original_packet.payload)
                {
                    echo_req
                } else {
                    return Ok(None);
                };
                if echo_req.identifier != self.identifier
                    || echo_req.sequence_number != expected_ttl as u16
                {
                    return Ok(None);
                }
                let hop_info = HopInfo {
                    hop_number: expected_ttl,
                    ip_address: Some(pkt.src.into()),
                    rtt: Some(rtt),
                    received_at: Some(received_at),
                    error_info: Some(NetworkErrorType::DestinationUnreachableV6(
                        dest_unreachable.code,
                    )),
                };
                return Ok(Some(TracerouteResponse::Error(hop_info)));
            }
            // Parameter Problem処理
            ICMPv6Message::ParameterProblem(param_problem) => {
                let echo_req = if let Ok(ICMPv6Message::EchoRequest(echo_req)) =
                    ICMPv6Message::try_from(&param_problem.original_packet.payload)
                {
                    echo_req
                } else {
                    return Ok(None);
                };
                if echo_req.identifier != self.identifier
                    || echo_req.sequence_number != expected_ttl as u16
                {
                    return Ok(None);
                }
                let hop_info = HopInfo {
                    hop_number: expected_ttl,
                    ip_address: Some(pkt.src.into()),
                    rtt: Some(rtt),
                    received_at: Some(received_at),
                    error_info: Some(NetworkErrorType::ParameterProblem),
                };
                return Ok(Some(TracerouteResponse::Error(hop_info)));
            }
            // Packet Too Big処理
            ICMPv6Message::PacketTooBig(packet_too_big) => {
                let echo_req = if let Ok(ICMPv6Message::EchoRequest(echo_req)) =
                    ICMPv6Message::try_from(&packet_too_big.original_packet.payload)
                {
                    echo_req
                } else {
                    return Ok(None);
                };
                if echo_req.identifier != self.identifier
                    || echo_req.sequence_number != expected_ttl as u16
                {
                    return Ok(None);
                }
                let hop_info = HopInfo {
                    hop_number: expected_ttl,
                    ip_address: Some(pkt.src.into()),
                    rtt: Some(rtt),
                    received_at: Some(received_at),
                    error_info: Some(NetworkErrorType::PacketTooBig(packet_too_big.mtu)),
                };
                return Ok(Some(TracerouteResponse::Error(hop_info)));
            }
            _ => {}
        }

        Ok(None)
    }

    /// TUIにtraceroute結果を送信
    async fn send_traceroute_update(&self, hops: &[HopInfo]) {
        let traceroute_hops = hops
            .iter()
            .map(|hop| TracerouteHop {
                hop_number: hop.hop_number,
                success: hop.ip_address.is_some(),
                address: hop.ip_address,
                latency: hop.rtt,
                error: None,
            })
            .collect();

        let traceroute_update = TracerouteUpdate {
            id: self.identifier,
            hops: traceroute_hops,
        };

        if let Err(e) = self
            .update_tx
            .send(UpdateMessage::Traceroute(traceroute_update))
            .await
        {
            warn!("Failed to send traceroute update to TUI: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration as StdDuration;

    use bytes::Bytes;
    use tcpip::icmp::{DestinationUnreachableCode, ICMPMessage, TimeExceededCode};
    use tcpip::ipv4::{Flags, IPv4Packet, Protocol, TypeOfService};
    use tokio::sync::{broadcast, mpsc};
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    use super::*;

    #[test]
    fn test_hop_info() {
        // [正常系] HopInfoの作成
        let hop_info = HopInfo {
            hop_number: 1,
            ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            rtt: Some(Duration::milliseconds(10)),
            received_at: Some(Utc::now()),
            error_info: None,
        };

        assert_eq!(hop_info.hop_number, 1);
        assert_eq!(
            hop_info.ip_address,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
        assert_eq!(hop_info.rtt, Some(Duration::milliseconds(10)));
    }

    #[test]
    fn test_traceroute_worker_new() {
        // [正常系] TracerouteWorkerの作成
        let token = CancellationToken::new();
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let interval = Duration::seconds(1);
        let max_hops = 30;
        let (tx, _rx1) = mpsc::channel(100);
        let (_tx2, rx) = broadcast::channel(100);

        let (update_tx, _update_rx) = mpsc::channel(100);
        let traceroute_worker = TracerouteWorker::new(
            token, 12345, src, target, interval, max_hops, tx, rx, update_tx,
        );

        assert_eq!(traceroute_worker.src, src);
        assert_eq!(traceroute_worker.target, target);
        assert_eq!(traceroute_worker.interval, interval);
    }

    #[tokio::test]
    async fn test_traceroute_worker_run() {
        // [正常系] TracerouteWorkerの実行とキャンセレーション
        let token = CancellationToken::new();
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let interval = chrono::Duration::seconds(1);
        let max_hops = 3;
        let (tx, _rx1) = mpsc::channel(100);
        let (_tx2, rx) = broadcast::channel(100);

        let (update_tx, _update_rx) = mpsc::channel(100);
        let traceroute_worker = TracerouteWorker::new(
            token.clone(),
            12345,
            src,
            target,
            interval,
            max_hops,
            tx,
            rx,
            update_tx,
        );

        // ワーカーを短時間実行してからキャンセル
        let run_handle = tokio::spawn(traceroute_worker.run());
        tokio::time::sleep(StdDuration::from_millis(10)).await;
        token.cancel();

        let result = timeout(StdDuration::from_millis(500), run_handle).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_process_received_packet() {
        let token = CancellationToken::new();
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let interval = Duration::seconds(1);
        let max_hops = 30;
        let (tx, _rx1) = mpsc::channel(100);
        let (_tx2, rx) = broadcast::channel(100);

        let (update_tx, _update_rx) = mpsc::channel(100);
        let worker = TracerouteWorker::new(
            token, 12345, src, target, interval, max_hops, tx, rx, update_tx,
        );
        let sent_at = Utc::now() - Duration::milliseconds(100);
        let expected_ttl = 3;

        // [正常系] Time Exceeded応答の処理
        {
            // 元のEcho Requestを作成
            let original_echo =
                ICMPMessage::echo_request(worker.identifier, expected_ttl as u16, vec![0; 32]);
            let original_echo_bytes: Bytes = original_echo.into();

            let original_packet = IPv4Packet::new(
                TypeOfService::default(),
                worker.identifier,
                Flags::default(),
                0,
                1, // TTL=1（ルータで破棄される直前）
                Protocol::ICMP,
                match src {
                    IpAddr::V4(addr) => addr,
                    _ => panic!("Expected IPv4 address"),
                },
                match target {
                    IpAddr::V4(addr) => addr,
                    _ => panic!("Expected IPv4 address"),
                },
                Vec::new(),
                original_echo_bytes,
            );

            let time_exceeded_msg =
                ICMPMessage::time_exceeded(TimeExceededCode::TtlExceeded, original_packet).unwrap();
            let time_exceeded_bytes: Bytes = time_exceeded_msg.into();

            let response_packet = IPv4Packet::new(
                TypeOfService::default(),
                12345,
                Flags::default(),
                0,
                64,
                Protocol::ICMP,
                Ipv4Addr::new(10, 0, 0, 1), // ルータのIP
                match src {
                    IpAddr::V4(addr) => addr,
                    _ => panic!("Expected IPv4 address"),
                },
                Vec::new(),
                time_exceeded_bytes,
            );

            let ip_response_packet = IPPacket::V4(response_packet);
            let received_at = chrono::Utc::now();
            let result = worker
                .process_received_packet(ip_response_packet, expected_ttl, sent_at, received_at)
                .unwrap();
            match result {
                Some(TracerouteResponse::TimeExceeded(hop_info)) => {
                    assert_eq!(hop_info.hop_number, expected_ttl);
                    assert_eq!(
                        hop_info.ip_address,
                        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
                    );
                    assert!(hop_info.rtt.unwrap().num_milliseconds() >= 100);
                }
                _ => panic!("Expected TimeExceeded response"),
            }
        }

        // [正常系] Echo Reply応答の処理
        {
            let echo_reply =
                ICMPMessage::echo_reply(worker.identifier, expected_ttl as u16, vec![0; 32]);
            let echo_reply_bytes: Bytes = echo_reply.into();

            let reply_packet = IPv4Packet::new(
                TypeOfService::default(),
                12346,
                Flags::default(),
                0,
                64,
                Protocol::ICMP,
                match target {
                    IpAddr::V4(addr) => addr,
                    _ => panic!("Expected IPv4 address"),
                },
                match src {
                    IpAddr::V4(addr) => addr,
                    _ => panic!("Expected IPv4 address"),
                },
                Vec::new(),
                echo_reply_bytes,
            );

            let ip_reply_packet = IPPacket::V4(reply_packet);
            let received_at = chrono::Utc::now();
            let result = worker
                .process_received_packet(ip_reply_packet, expected_ttl, sent_at, received_at)
                .unwrap();
            match result {
                Some(TracerouteResponse::EchoReply(hop_info)) => {
                    assert_eq!(hop_info.hop_number, expected_ttl);
                    assert_eq!(hop_info.ip_address, Some(target));
                    assert!(hop_info.rtt.unwrap().num_milliseconds() >= 100);
                }
                _ => panic!("Expected EchoReply response"),
            }
        }

        // [異常系] 異なる識別子のEcho Reply
        {
            let wrong_echo_reply =
                ICMPMessage::echo_reply(worker.identifier + 1, expected_ttl as u16, vec![0; 32]);
            let wrong_echo_reply_bytes: Bytes = wrong_echo_reply.into();

            let wrong_reply_packet = IPv4Packet::new(
                TypeOfService::default(),
                12347,
                Flags::default(),
                0,
                64,
                Protocol::ICMP,
                match target {
                    IpAddr::V4(addr) => addr,
                    _ => panic!("Expected IPv4 address"),
                },
                match src {
                    IpAddr::V4(addr) => addr,
                    _ => panic!("Expected IPv4 address"),
                },
                Vec::new(),
                wrong_echo_reply_bytes,
            );

            let ip_wrong_reply_packet = IPPacket::V4(wrong_reply_packet);
            let received_at = chrono::Utc::now();
            let result = worker
                .process_received_packet(ip_wrong_reply_packet, expected_ttl, sent_at, received_at)
                .unwrap();
            assert!(result.is_none());
        }

        // [異常系] 異なるsequence numberのEcho Reply
        {
            let wrong_seq_echo_reply =
                ICMPMessage::echo_reply(worker.identifier, (expected_ttl + 1) as u16, vec![0; 32]);
            let wrong_seq_echo_reply_bytes: Bytes = wrong_seq_echo_reply.into();

            let wrong_seq_reply_packet = IPv4Packet::new(
                TypeOfService::default(),
                12348,
                Flags::default(),
                0,
                64,
                Protocol::ICMP,
                match target {
                    IpAddr::V4(addr) => addr,
                    _ => panic!("Expected IPv4 address"),
                },
                match src {
                    IpAddr::V4(addr) => addr,
                    _ => panic!("Expected IPv4 address"),
                },
                Vec::new(),
                wrong_seq_echo_reply_bytes,
            );

            let ip_wrong_seq_reply_packet = IPPacket::V4(wrong_seq_reply_packet);
            let received_at = chrono::Utc::now();
            let result = worker
                .process_received_packet(
                    ip_wrong_seq_reply_packet,
                    expected_ttl,
                    sent_at,
                    received_at,
                )
                .unwrap();
            assert!(result.is_none());
        }

        // [異常系] 関係ないICMPメッセージ
        {
            let dummy_icmp = ICMPMessage::echo_request(999, 1, vec![0; 32]);
            let dummy_icmp_bytes: Bytes = dummy_icmp.into();
            let dummy_packet = IPv4Packet::new(
                TypeOfService::default(),
                999,
                Flags::default(),
                0,
                1,
                Protocol::ICMP,
                match src {
                    IpAddr::V4(addr) => addr,
                    _ => panic!("Expected IPv4 address"),
                },
                match target {
                    IpAddr::V4(addr) => addr,
                    _ => panic!("Expected IPv4 address"),
                },
                Vec::new(),
                dummy_icmp_bytes,
            );
            let other_icmp = ICMPMessage::destination_unreachable(
                DestinationUnreachableCode::HostUnreachable,
                None,
                dummy_packet,
            )
            .unwrap();
            let other_icmp_bytes: Bytes = other_icmp.into();

            let other_packet = IPv4Packet::new(
                TypeOfService::default(),
                12349,
                Flags::default(),
                0,
                64,
                Protocol::ICMP,
                Ipv4Addr::new(8, 8, 8, 8),
                match src {
                    IpAddr::V4(addr) => addr,
                    _ => panic!("Expected IPv4 address"),
                },
                Vec::new(),
                other_icmp_bytes,
            );

            let ip_other_packet = IPPacket::V4(other_packet);
            let received_at = chrono::Utc::now();
            let result = worker
                .process_received_packet(ip_other_packet, expected_ttl, sent_at, received_at)
                .unwrap();
            assert!(result.is_none());
        }
    }

    #[test]
    fn test_traceroute_worker_error() {
        // [正常系] エラーの表示確認
        let error1 = TracerouteWorkerError::ChannelSendError;
        assert_eq!(error1.to_string(), "Channel send error");
    }
}
