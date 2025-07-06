use std::net::Ipv4Addr;
use std::time::Duration as StdDuration;

use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use log::{debug, info, warn};
use rand::Rng;
use tcpip::icmp::{ICMPError, ICMPMessage, TimeExceededCode};
use tcpip::ipv4::{Flags, IPv4Packet, Protocol, TypeOfService};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc};
use tokio::time::{interval, timeout};
use tokio_util::sync::CancellationToken;

use crate::net_utils::netlink::NetlinkError;

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
    /// ホップのIPアドレス
    ip_address: Ipv4Addr,
    /// 応答時間
    rtt: Duration,
    /// 応答を受信した時刻
    received_at: DateTime<Utc>,
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
    rx: broadcast::Receiver<IPv4Packet>,
}

impl TracerouteWorker {
    pub fn new(
        token: CancellationToken,
        src: Ipv4Addr,
        target: Ipv4Addr,
        interval: Duration,
        max_hops: u8,
        tx: mpsc::Sender<IPv4Packet>,
        rx: broadcast::Receiver<IPv4Packet>,
    ) -> Self {
        let mut rng = rand::rng();
        let id = rng.random::<u16>();

        Self {
            token,
            identifier: id,
            src,
            target,
            interval,
            max_hops,
            tx,
            rx,
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
                    debug!(
                        "Hop {}: {} ({}ms)",
                        hop_info.hop_number,
                        hop_info.ip_address,
                        hop_info.rtt.num_milliseconds()
                    );
                    hops.push(hop_info);
                }
                TracerouteResponse::EchoReply(hop_info) => {
                    debug!(
                        "Target reached at hop {}: {} ({}ms)",
                        hop_info.hop_number,
                        hop_info.ip_address,
                        hop_info.rtt.num_milliseconds()
                    );
                    hops.push(hop_info);
                    break; // 宛先に到達したので終了
                }
                TracerouteResponse::Timeout { ttl } => {
                    debug!("Timeout at hop {ttl}");
                    // タイムアウトは記録しないが、処理は継続
                }
            }
        }

        self.print_traceroute_result(&hops);
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
                Ok(pkt) = self.rx.recv() => {
                    if let Some(response) = self.process_received_packet(pkt, expected_ttl, sent_at)? {
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
        pkt: IPv4Packet,
        expected_ttl: u8,
        sent_at: DateTime<Utc>,
    ) -> Result<Option<TracerouteResponse>, TracerouteWorkerError> {
        let icmp_msg = ICMPMessage::try_from(&pkt.payload)?;
        let received_at = Utc::now();
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
                                ip_address: pkt.src,
                                rtt,
                                received_at,
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
                        ip_address: pkt.src,
                        rtt,
                        received_at,
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

    /// tracerouteの結果を表示
    fn print_traceroute_result(&self, hops: &[HopInfo]) {
        if !hops.is_empty() {
            info!("=== Traceroute to {} ===", self.target);
            for hop in hops {
                info!(
                    "{} -> {} {} {}ms",
                    hop.hop_number,
                    hop.ip_address,
                    self.target,
                    hop.rtt.num_milliseconds()
                );
            }
            info!("=== End traceroute to {} ===", self.target);
        } else {
            info!("No hops discovered for traceroute to {}", self.target);
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
            ip_address: Ipv4Addr::new(192, 168, 1, 1),
            rtt: Duration::milliseconds(10),
            received_at: Utc::now(),
        };

        assert_eq!(hop_info.hop_number, 1);
        assert_eq!(hop_info.ip_address, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hop_info.rtt, Duration::milliseconds(10));
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

        let traceroute_worker =
            TracerouteWorker::new(token, src, target, interval, max_hops, tx, rx);

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

        let traceroute_worker =
            TracerouteWorker::new(token.clone(), src, target, interval, max_hops, tx, rx);

        // ワーカーを短時間実行してからキャンセル
        let run_handle = tokio::spawn(traceroute_worker.run());
        tokio::time::sleep(Duration::from_millis(10)).await;
        token.cancel();

        let result = timeout(Duration::from_millis(100), run_handle).await;
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

        let worker = TracerouteWorker::new(token, src, target, interval, max_hops, tx, rx);
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

            let result = worker
                .process_received_packet(response_packet, expected_ttl, sent_at)
                .unwrap();
            match result {
                Some(TracerouteResponse::TimeExceeded(hop_info)) => {
                    assert_eq!(hop_info.hop_number, expected_ttl);
                    assert_eq!(hop_info.ip_address, Ipv4Addr::new(10, 0, 0, 1));
                    assert!(hop_info.rtt.num_milliseconds() >= 100);
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

            let result = worker
                .process_received_packet(reply_packet, expected_ttl, sent_at)
                .unwrap();
            match result {
                Some(TracerouteResponse::EchoReply(hop_info)) => {
                    assert_eq!(hop_info.hop_number, expected_ttl);
                    assert_eq!(hop_info.ip_address, target);
                    assert!(hop_info.rtt.num_milliseconds() >= 100);
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

            let result = worker
                .process_received_packet(wrong_reply_packet, expected_ttl, sent_at)
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

            let result = worker
                .process_received_packet(wrong_seq_reply_packet, expected_ttl, sent_at)
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

            let result = worker
                .process_received_packet(other_packet, expected_ttl, sent_at)
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
