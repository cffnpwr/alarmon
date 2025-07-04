use std::net::Ipv4Addr;

use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use fxhash::FxHashMap;
use log::{debug, info, warn};
use rand::Rng;
use tcpip::icmp::{ICMPError, ICMPMessage};
use tcpip::ipv4::{Flags, IPv4Packet, Protocol, TypeOfService};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;

use crate::net_utils::netlink::NetlinkError;

#[derive(Debug, Error)]
pub enum PingWorkerError {
    #[error(transparent)]
    NetworkFailed(#[from] NetlinkError),
    #[error(transparent)]
    IcmpError(#[from] ICMPError),
    #[error("Channel send error")]
    ChannelSendError,
}

#[derive(Debug)]
struct PendingPing {
    target_ip: Ipv4Addr,
    sequence_number: u16,
    sent_at: DateTime<Utc>,
}

pub struct PingRequestSender {
    /// ICMP Echo Requestの送信元識別子
    identifier: u16,

    /// ICMP Echo Requestの送信シーケンス番号
    sequence_counter: u16,

    /// 送信元IPアドレス
    src: Ipv4Addr,

    /// 宛先IPアドレス
    target: Ipv4Addr,

    /// 送信間隔
    interval: Duration,

    /// IPパケットを送信するためのチャネル
    tx: mpsc::Sender<IPv4Packet>,

    /// 送信通知用チャネル
    ping_tx: mpsc::Sender<PendingPing>,
}

pub struct PingResponseReceiver {
    /// ICMP Echo Requestの送信元識別子
    identifier: u16,

    /// 送信済みのPingの情報
    pending_pings: FxHashMap<u16, PendingPing>,

    /// IPパケットを受信するためのチャネル
    rx: mpsc::Receiver<IPv4Packet>,

    /// 送信通知受信用チャネル
    ping_rx: mpsc::Receiver<PendingPing>,
}

pub struct PingWorker {
    token: CancellationToken,
    sender: PingRequestSender,
    receiver: PingResponseReceiver,
}

impl PingWorker {
    pub fn new(
        token: CancellationToken,
        src: Ipv4Addr,
        target: Ipv4Addr,
        interval: Duration,
        tx: mpsc::Sender<IPv4Packet>,
        rx: mpsc::Receiver<IPv4Packet>,
    ) -> Self {
        let mut rng = rand::rng();
        let id = rng.random::<u16>();
        let pendings = FxHashMap::default();

        // 送信通知用チャネルを作成
        let (ping_tx, ping_rx) = mpsc::channel(1000);

        let sender = PingRequestSender {
            identifier: id,
            sequence_counter: 0,
            src,
            target,
            interval,
            tx,
            ping_tx,
        };

        let receiver = PingResponseReceiver {
            identifier: id,
            pending_pings: pendings,
            rx,
            ping_rx,
        };

        Self {
            token,
            sender,
            receiver,
        }
    }

    pub async fn run(self) -> Result<(), PingWorkerError> {
        info!("Starting Ping Worker for target: {}", self.sender.target);

        let token = self.token.clone();
        let target_display = self.sender.target;
        let send_handle = tokio::spawn(self.sender.run_send_echo_req());
        let recv_handle = tokio::spawn(self.receiver.listen_recv_ip_packets());

        tokio::select! {
            _ = token.cancelled() => {
                info!("Ping Worker for target {target_display} is stopping");
            }
            _ = send_handle => {},
            _ = recv_handle => {},
        }

        Ok(())
    }
}

impl PingRequestSender {
    async fn run_send_echo_req(mut self) -> Result<(), PingWorkerError> {
        let mut interval = interval(self.interval.to_std().expect("Invalid duration"));
        loop {
            self.handle_send_ip_packet().await?;
            interval.tick().await;
        }
    }

    async fn handle_send_ip_packet(&mut self) -> Result<(), PingWorkerError> {
        // ICMP Echo Requestを送信
        let sequence_number = self.sequence_counter;
        self.sequence_counter = self.sequence_counter.wrapping_add(1);
        let sent_at = Utc::now();
        let icmp_msg = ICMPMessage::echo_request(self.identifier, sequence_number, vec![0; 32]);
        let pending_ping = PendingPing {
            target_ip: self.target,
            sequence_number,
            sent_at,
        };

        // 送信通知をreceiverに送る
        self.ping_tx
            .send(pending_ping)
            .await
            .map_err(|_| PingWorkerError::ChannelSendError)?;

        let icmp_bytes: Bytes = icmp_msg.into();
        let pkt = IPv4Packet::new(
            TypeOfService::default(),
            self.identifier,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            self.src,
            self.target,
            Vec::new(),
            icmp_bytes,
        );
        // IPパケットを送信チャネルに送る
        self.tx
            .send(pkt)
            .await
            .map_err(|_| PingWorkerError::ChannelSendError)?;

        Ok(())
    }
}

impl PingResponseReceiver {
    async fn listen_recv_ip_packets(mut self) -> Result<(), PingWorkerError> {
        loop {
            tokio::select! {
                // 送信通知を受信
                Some(pending_ping) = self.ping_rx.recv() => {
                    self.pending_pings.insert(pending_ping.sequence_number, pending_ping);
                }
                // IPパケットを受信
                Some(pkt) = self.rx.recv() => {
                    if let Err(e) = self.handle_recv_ip_packet(pkt).await {
                        warn!("Failed to handle received IP packet: {e}");
                    }
                }
                else => break,
            }
        }
        Ok(())
    }

    async fn handle_recv_ip_packet(&mut self, pkt: IPv4Packet) -> Result<(), PingWorkerError> {
        // ICMP Echo Replyを受信
        let icmp_msg = ICMPMessage::try_from(&pkt.payload)?;
        if let ICMPMessage::EchoReply(msg) = icmp_msg {
            let id = msg.identifier;
            if id != self.identifier {
                debug!(
                    "Received Echo Reply with different identifier. Expected: {}, Received: {}",
                    id, self.identifier
                );
                return Ok(());
            }

            let seq = msg.sequence_number;
            if !self.pending_pings.contains_key(&seq) {
                debug!("Received Echo Reply with unknown sequence number: {seq}");
                return Ok(());
            }
            let pending_ping = self.pending_pings.remove(&seq).unwrap();

            let latency = Utc::now() - pending_ping.sent_at;
            info!(
                "Ping response received: {} (seq: {}, rtt: {} ms)",
                pending_ping.target_ip,
                seq,
                latency.num_milliseconds()
            );
        } else {
            debug!(
                "Received message is not Echo Reply: {}",
                icmp_msg.message_type()
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::sync::mpsc;
    use tokio_test::assert_ok;
    use tokio_util::sync::CancellationToken;

    use super::*;

    #[test]
    fn test_pending_ping() {
        // [正常系] PendingPingの作成
        let target_ip = Ipv4Addr::new(192, 168, 1, 1);
        let sequence_number = 1234;
        let sent_at = Utc::now();

        let pending_ping = PendingPing {
            target_ip,
            sequence_number,
            sent_at,
        };

        assert_eq!(pending_ping.target_ip, target_ip);
        assert_eq!(pending_ping.sequence_number, sequence_number);
        assert_eq!(pending_ping.sent_at, sent_at);
    }

    #[test]
    fn test_ping_worker_new() {
        // [正常系] PingWorkerの作成
        let token = CancellationToken::new();
        let src = Ipv4Addr::new(192, 168, 1, 100);
        let target = Ipv4Addr::new(192, 168, 1, 1);
        let interval = Duration::seconds(1);
        let (tx, _rx1) = mpsc::channel(100);
        let (_tx2, rx) = mpsc::channel(100);

        let ping_worker = PingWorker::new(token, src, target, interval, tx, rx);

        assert_eq!(ping_worker.sender.src, src);
        assert_eq!(ping_worker.sender.target, target);
        assert_eq!(ping_worker.sender.interval, interval);
        assert_eq!(
            ping_worker.sender.identifier,
            ping_worker.receiver.identifier
        );
        assert_eq!(ping_worker.sender.sequence_counter, 0);
    }

    #[test]
    fn test_ping_request_sender() {
        // [正常系] PingRequestSenderの作成
        let identifier = 12345;
        let sequence_counter = 0;
        let src = Ipv4Addr::new(192, 168, 1, 100);
        let target = Ipv4Addr::new(192, 168, 1, 1);
        let interval = Duration::seconds(1);
        let (tx, _rx1) = mpsc::channel(100);
        let (ping_tx, _ping_rx) = mpsc::channel(100);

        let sender = PingRequestSender {
            identifier,
            sequence_counter,
            src,
            target,
            interval,
            tx,
            ping_tx,
        };

        assert_eq!(sender.identifier, identifier);
        assert_eq!(sender.sequence_counter, sequence_counter);
        assert_eq!(sender.src, src);
        assert_eq!(sender.target, target);
        assert_eq!(sender.interval, interval);
    }

    #[test]
    fn test_ping_response_receiver() {
        // [正常系] PingResponseReceiverの作成
        let identifier = 12345;
        let pending_pings = FxHashMap::default();
        let (_tx1, rx) = mpsc::channel(100);
        let (_ping_tx, ping_rx) = mpsc::channel(100);

        let receiver = PingResponseReceiver {
            identifier,
            pending_pings,
            rx,
            ping_rx,
        };

        assert_eq!(receiver.identifier, identifier);
        assert!(receiver.pending_pings.is_empty());
    }

    #[tokio::test]
    async fn test_ping_request_sender_handle_send_ip_packet() {
        // [正常系] ICMP Echo Requestの送信
        let identifier = 12345;
        let sequence_counter = 0;
        let src = Ipv4Addr::new(192, 168, 1, 100);
        let target = Ipv4Addr::new(192, 168, 1, 1);
        let interval = Duration::seconds(1);
        let (tx, mut rx) = mpsc::channel(100);
        let (ping_tx, mut ping_rx) = mpsc::channel(100);

        let mut sender = PingRequestSender {
            identifier,
            sequence_counter,
            src,
            target,
            interval,
            tx,
            ping_tx,
        };

        // テスト実行
        let result = sender.handle_send_ip_packet().await;
        assert_ok!(result);

        // シーケンス番号が増加していることを確認
        assert_eq!(sender.sequence_counter, 1);

        // 送信されたIPパケットを確認
        let sent_packet = rx.recv().await.unwrap();
        assert_eq!(sent_packet.src, src);
        assert_eq!(sent_packet.dst, target);
        assert_eq!(sent_packet.protocol, Protocol::ICMP);
        assert_eq!(sent_packet.identification, identifier);

        // 送信通知を確認
        let pending_ping = ping_rx.recv().await.unwrap();
        assert_eq!(pending_ping.target_ip, target);
        assert_eq!(pending_ping.sequence_number, 0);
    }

    #[tokio::test]
    async fn test_ping_response_receiver_handle_recv_ip_packet() {
        // [正常系] ICMP Echo Replyの受信
        let identifier = 12345;
        let sequence_number = 100;
        let mut pending_pings = FxHashMap::default();
        let target_ip = Ipv4Addr::new(192, 168, 1, 1);
        let sent_at = Utc::now();

        // 送信済みPingを追加
        pending_pings.insert(
            sequence_number,
            PendingPing {
                target_ip,
                sequence_number,
                sent_at,
            },
        );

        let (_tx, rx) = mpsc::channel(100);
        let (_ping_tx, ping_rx) = mpsc::channel(100);

        let mut receiver = PingResponseReceiver {
            identifier,
            pending_pings,
            rx,
            ping_rx,
        };

        // ICMP Echo Replyパケットを作成
        let icmp_msg = ICMPMessage::echo_reply(identifier, sequence_number, vec![0; 32]);
        let icmp_bytes: Bytes = icmp_msg.into();
        let ipv4_packet = IPv4Packet::new(
            TypeOfService::default(),
            54321,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            target_ip,
            Ipv4Addr::new(192, 168, 1, 100),
            Vec::new(),
            icmp_bytes,
        );

        // テスト実行
        let result = receiver.handle_recv_ip_packet(ipv4_packet).await;
        assert_ok!(result);

        // 送信済みPingが削除されていることを確認
        assert!(!receiver.pending_pings.contains_key(&sequence_number));

        // [正常系] 異なるidentifierのEcho Replyの無視
        let wrong_identifier = 54321;
        let wrong_icmp =
            ICMPMessage::echo_reply(wrong_identifier, sequence_number + 1, vec![0; 32]);
        let wrong_icmp_bytes: Bytes = wrong_icmp.into();
        let wrong_packet = IPv4Packet::new(
            TypeOfService::default(),
            54321,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            target_ip,
            Ipv4Addr::new(192, 168, 1, 100),
            Vec::new(),
            wrong_icmp_bytes,
        );

        let result = receiver.handle_recv_ip_packet(wrong_packet).await;
        assert_ok!(result);

        // [正常系] 未知のsequence numberのEcho Replyの無視
        let unknown_seq = 999;
        let unknown_icmp = ICMPMessage::echo_reply(identifier, unknown_seq, vec![0; 32]);
        let unknown_icmp_bytes: Bytes = unknown_icmp.into();
        let unknown_packet = IPv4Packet::new(
            TypeOfService::default(),
            54321,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            target_ip,
            Ipv4Addr::new(192, 168, 1, 100),
            Vec::new(),
            unknown_icmp_bytes,
        );

        let result = receiver.handle_recv_ip_packet(unknown_packet).await;
        assert_ok!(result);

        // [正常系] 非Echo ReplyのICMPメッセージの無視
        let echo_request = ICMPMessage::echo_request(identifier, sequence_number + 2, vec![0; 32]);
        let echo_request_bytes: Bytes = echo_request.into();
        let request_packet = IPv4Packet::new(
            TypeOfService::default(),
            54321,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            target_ip,
            Ipv4Addr::new(192, 168, 1, 100),
            Vec::new(),
            echo_request_bytes,
        );

        let result = receiver.handle_recv_ip_packet(request_packet).await;
        assert_ok!(result);
    }

    #[tokio::test]
    async fn test_ping_worker_run() {
        use std::time::Duration;

        use tokio::time::timeout;

        // [正常系] PingWorkerの実行とキャンセレーション
        let token = CancellationToken::new();
        let src = Ipv4Addr::new(192, 168, 1, 100);
        let target = Ipv4Addr::new(192, 168, 1, 1);
        let interval = chrono::Duration::seconds(1);
        let (tx, _rx1) = mpsc::channel(100);
        let (_tx2, rx) = mpsc::channel(100);

        let ping_worker = PingWorker::new(token.clone(), src, target, interval, tx, rx);

        // ワーカーを短時間実行してからキャンセル
        let run_handle = tokio::spawn(ping_worker.run());
        tokio::time::sleep(Duration::from_millis(10)).await;
        token.cancel();

        let result = timeout(Duration::from_millis(100), run_handle).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_ping_request_sender_run_send_echo_req() {
        use std::time::Duration;

        use tokio::time::timeout;

        // [正常系] Echo Request送信ループのテスト
        let identifier = 12345;
        let sequence_counter = 0;
        let src = Ipv4Addr::new(192, 168, 1, 100);
        let target = Ipv4Addr::new(192, 168, 1, 1);
        let interval = chrono::Duration::milliseconds(50); // 短い間隔でテスト
        let (tx, mut rx) = mpsc::channel(100);
        let (ping_tx, mut ping_rx) = mpsc::channel(100);

        let sender = PingRequestSender {
            identifier,
            sequence_counter,
            src,
            target,
            interval,
            tx,
            ping_tx,
        };

        // 短時間で複数回送信されることを確認
        let send_handle = tokio::spawn(sender.run_send_echo_req());

        // 最初のパケットを受信
        let first_packet = timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(first_packet.is_ok());
        assert!(first_packet.unwrap().is_some());

        let first_ping = timeout(Duration::from_millis(100), ping_rx.recv()).await;
        assert!(first_ping.is_ok());
        assert!(first_ping.unwrap().is_some());

        // 2番目のパケットを受信
        let second_packet = timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(second_packet.is_ok());
        assert!(second_packet.unwrap().is_some());

        send_handle.abort(); // タスクを中止
    }

    #[tokio::test]
    async fn test_ping_response_receiver_listen_recv_ip_packets() {
        use std::time::Duration;

        use tokio::time::timeout;

        // [正常系] select!ループでの受信処理テスト
        let identifier = 12345;
        let pending_pings = FxHashMap::default();
        let (tx, rx) = mpsc::channel(100);
        let (ping_tx, ping_rx) = mpsc::channel(100);

        let receiver = PingResponseReceiver {
            identifier,
            pending_pings,
            rx,
            ping_rx,
        };

        // 送信通知を送る
        let pending_ping = PendingPing {
            target_ip: Ipv4Addr::new(192, 168, 1, 1),
            sequence_number: 100,
            sent_at: Utc::now(),
        };
        ping_tx.send(pending_ping).await.unwrap();

        // ICMP Echo Replyパケットを送る
        let icmp_msg = ICMPMessage::echo_reply(identifier, 100, vec![0; 32]);
        let icmp_bytes: Bytes = icmp_msg.into();
        let ipv4_packet = IPv4Packet::new(
            TypeOfService::default(),
            54321,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 100),
            Vec::new(),
            icmp_bytes,
        );
        tx.send(ipv4_packet).await.unwrap();

        // チャネルを閉じてループを終了させる
        drop(tx);
        drop(ping_tx);

        let result = timeout(
            Duration::from_millis(100),
            receiver.listen_recv_ip_packets(),
        )
        .await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_ping_response_receiver_handle_recv_ip_packet_error_cases() {
        // [異常系] 不正なICMPメッセージの処理
        let identifier = 12345;
        let pending_pings = FxHashMap::default();
        let (_tx, rx) = mpsc::channel(100);
        let (_ping_tx, ping_rx) = mpsc::channel(100);

        let mut receiver = PingResponseReceiver {
            identifier,
            pending_pings,
            rx,
            ping_rx,
        };

        // 不正なICMPペイロードのIPパケット
        let invalid_packet = IPv4Packet::new(
            TypeOfService::default(),
            54321,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 100),
            Vec::new(),
            Bytes::from(vec![0; 4]), // 不正に短いICMPペイロード
        );

        let result = receiver.handle_recv_ip_packet(invalid_packet).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PingWorkerError::IcmpError(_)));
    }

    #[test]
    fn test_ping_worker_error() {
        // [正常系] エラーの表示確認
        let error1 = PingWorkerError::ChannelSendError;
        assert_eq!(error1.to_string(), "Channel send error");
    }
}
