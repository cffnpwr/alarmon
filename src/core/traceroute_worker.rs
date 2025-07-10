use std::net::Ipv4Addr;
use std::time::Duration as StdDuration;

use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use log::{debug, info, warn};
use tcpip::icmp::{ICMPError, ICMPMessage, TimeExceededCode};
use tcpip::ipv4::{Flags, IPv4Packet, Protocol, TypeOfService};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc};
use tokio::time::{interval, timeout};
use tokio_util::sync::CancellationToken;

use crate::core::pcap_worker::TimestampedPacket;
use crate::net_utils::netlink::NetlinkError;
use crate::tui::models::{TracerouteHop, TracerouteUpdate, UpdateMessage};

#[derive(Debug, Error)]
pub enum TracerouteWorkerError {
    #[error(transparent)]
    NetworkFailed(#[from] NetlinkError),
    #[error(transparent)]
    IcmpError(#[from] ICMPError),
    #[error("Channel send error")]
    ChannelSendError,
}

/// 各ホップの情報
#[derive(Debug, Clone, PartialEq, Eq)]
struct HopInfo {
    /// ホップ番号（TTL値）
    hop_number: u8,
    /// ホップのIPアドレス（タイムアウト時はNone）
    ip_address: Option<Ipv4Addr>,
    /// 応答時間（タイムアウト時はNone）
    rtt: Option<Duration>,
    /// 応答を受信した時刻（タイムアウト時はNone）
    received_at: Option<DateTime<Utc>>,
}

/// Tracerouteの応答タイプ
#[derive(Debug)]
enum TracerouteResponse {
    /// Time Exceeded応答（中間ホップ）
    TimeExceeded(HopInfo),
    /// Echo Reply応答（最終ホップ）
    EchoReply(HopInfo),
    /// タイムアウト
    Timeout { ttl: u8 },
}

pub struct TracerouteWorker {
    /// キャンセレーショントークン
    token: CancellationToken,
    /// ICMP Echo Requestの送信元識別子
    identifier: u16,
    /// 送信元IPアドレス
    src: Ipv4Addr,
    /// 宛先IPアドレス
    target: Ipv4Addr,
    /// traceroute実行間隔
    interval: Duration,
    /// 最大ホップ数
    max_hops: u8,
    /// IPパケットを送信するためのチャネル
    tx: mpsc::Sender<IPv4Packet>,
    /// IPパケットを受信するためのチャネル
    rx: broadcast::Receiver<TimestampedPacket>,
    /// UpdateMessage送信用チャネル
    update_tx: mpsc::Sender<UpdateMessage>,
}

impl TracerouteWorker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token: CancellationToken,
        id: u16,
        src: Ipv4Addr,
        target: Ipv4Addr,
        interval: Duration,
        max_hops: u8,
        tx: mpsc::Sender<IPv4Packet>,
        rx: broadcast::Receiver<TimestampedPacket>,
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
                TracerouteResponse::Timeout { ttl } => {
                    debug!("Timeout at hop {ttl}");
                    // タイムアウトもホップとして記録（*で表示するため）
                    let timeout_hop = HopInfo {
                        hop_number: ttl,
                        ip_address: None,
                        rtt: None,
                        received_at: None,
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
            self.src,
            self.target,
            Vec::new(),
            icmp_bytes,
        );

        // パケットを送信
        self.tx
            .send(pkt)
            .await
            .map_err(|_| TracerouteWorkerError::ChannelSendError)?;

        debug!("Sent ICMP Echo Request with TTL {} to {}", ttl, self.target);

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
                Ok(timestamped_pkt) = self.rx.recv() => {
                    if let Some(response) = self.process_received_packet(timestamped_pkt, expected_ttl, sent_at)? {
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
        timestamped_pkt: TimestampedPacket,
        expected_ttl: u8,
        sent_at: DateTime<Utc>,
    ) -> Result<Option<TracerouteResponse>, TracerouteWorkerError> {
        let pkt = timestamped_pkt.packet;
        let received_at = timestamped_pkt.received_at;
        let icmp_msg = ICMPMessage::try_from(&pkt.payload)?;
        let rtt = received_at - sent_at;

        match icmp_msg {
            // Time Exceeded応答（中間ホップ）
            ICMPMessage::TimeExceeded(time_exceeded) => {
                if time_exceeded.code == TimeExceededCode::TtlExceeded {
                    // 元のICMPパケットの識別子とsequence numberをチェック
                    if let Ok(ICMPMessage::Echo(echo_req)) =
                        ICMPMessage::try_from(&time_exceeded.original_datagram.payload)
                    {
                        // 識別子とsequence number（TTLとして使用）で照合
                        if echo_req.identifier == self.identifier
                            && echo_req.sequence_number == expected_ttl as u16
                        {
                            let hop_info = HopInfo {
                                hop_number: expected_ttl,
                                ip_address: Some(pkt.src),
                                rtt: Some(rtt),
                                received_at: Some(received_at),
                            };
                            return Ok(Some(TracerouteResponse::TimeExceeded(hop_info)));
                        }
                    }
                }
            }
            // Echo Reply応答（宛先到達）
            ICMPMessage::EchoReply(echo) => {
                if echo.identifier == self.identifier
                    && pkt.src == self.target
                    && echo.sequence_number == expected_ttl as u16
                {
                    let hop_info = HopInfo {
                        hop_number: expected_ttl,
                        ip_address: Some(pkt.src),
                        rtt: Some(rtt),
                        received_at: Some(received_at),
                    };
                    return Ok(Some(TracerouteResponse::EchoReply(hop_info)));
                }
            }
            _ => {
                // その他のICMPメッセージは無視
            }
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

    use tokio::sync::{broadcast, mpsc};
    use tokio_util::sync::CancellationToken;

    use super::*;

    #[test]
    fn test_hop_info() {
        // [正常系] HopInfoの作成
        let hop_info = HopInfo {
            hop_number: 1,
            ip_address: Some(Ipv4Addr::new(192, 168, 1, 1)),
            rtt: Some(Duration::milliseconds(10)),
            received_at: Some(Utc::now()),
        };

        assert_eq!(hop_info.hop_number, 1);
        assert_eq!(hop_info.ip_address, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(hop_info.rtt, Some(Duration::milliseconds(10)));
    }

    #[test]
    fn test_traceroute_worker_new() {
        // [正常系] TracerouteWorkerの作成
        let token = CancellationToken::new();
        let src = Ipv4Addr::new(192, 168, 1, 100);
        let target = Ipv4Addr::new(192, 168, 1, 1);
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
        use std::time::Duration;

        use tokio::time::timeout;

        // [正常系] TracerouteWorkerの実行とキャンセレーション
        let token = CancellationToken::new();
        let src = Ipv4Addr::new(192, 168, 1, 100);
        let target = Ipv4Addr::new(192, 168, 1, 1);
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
        tokio::time::sleep(Duration::from_millis(10)).await;
        token.cancel();

        let result = timeout(Duration::from_millis(500), run_handle).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_process_received_packet() {
        use bytes::Bytes;
        use tcpip::icmp::{DestinationUnreachableCode, ICMPMessage, TimeExceededCode};
        use tcpip::ipv4::{Flags, IPv4Packet, Protocol, TypeOfService};

        let token = CancellationToken::new();
        let src = Ipv4Addr::new(192, 168, 1, 100);
        let target = Ipv4Addr::new(192, 168, 1, 1);
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
                src,
                target,
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
                src,
                Vec::new(),
                time_exceeded_bytes,
            );

            let timestamped_response_packet = crate::core::pcap_worker::TimestampedPacket {
                packet: response_packet,
                received_at: chrono::Utc::now(),
            };
            let result = worker
                .process_received_packet(timestamped_response_packet, expected_ttl, sent_at)
                .unwrap();
            match result {
                Some(TracerouteResponse::TimeExceeded(hop_info)) => {
                    assert_eq!(hop_info.hop_number, expected_ttl);
                    assert_eq!(hop_info.ip_address, Some(Ipv4Addr::new(10, 0, 0, 1)));
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
                target,
                src,
                Vec::new(),
                echo_reply_bytes,
            );

            let timestamped_reply_packet = crate::core::pcap_worker::TimestampedPacket {
                packet: reply_packet,
                received_at: chrono::Utc::now(),
            };
            let result = worker
                .process_received_packet(timestamped_reply_packet, expected_ttl, sent_at)
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
                target,
                src,
                Vec::new(),
                wrong_echo_reply_bytes,
            );

            let timestamped_wrong_reply_packet = crate::core::pcap_worker::TimestampedPacket {
                packet: wrong_reply_packet,
                received_at: chrono::Utc::now(),
            };
            let result = worker
                .process_received_packet(timestamped_wrong_reply_packet, expected_ttl, sent_at)
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
                target,
                src,
                Vec::new(),
                wrong_seq_echo_reply_bytes,
            );

            let timestamped_wrong_seq_reply_packet = crate::core::pcap_worker::TimestampedPacket {
                packet: wrong_seq_reply_packet,
                received_at: chrono::Utc::now(),
            };
            let result = worker
                .process_received_packet(timestamped_wrong_seq_reply_packet, expected_ttl, sent_at)
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
                src,
                target,
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
                src,
                Vec::new(),
                other_icmp_bytes,
            );

            let timestamped_other_packet = crate::core::pcap_worker::TimestampedPacket {
                packet: other_packet,
                received_at: chrono::Utc::now(),
            };
            let result = worker
                .process_received_packet(timestamped_other_packet, expected_ttl, sent_at)
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
