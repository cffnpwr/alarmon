use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use fxhash::FxHashMap;
use log::{debug, info, warn};
use parking_lot::Mutex;
use tcpip::icmp::{
    self, ICMPError, ICMPMessage, RedirectCode, TimeExceededCode as TimeExceededCodeV4,
};
use tcpip::icmpv6::{self, ICMPv6Error, ICMPv6Message, TimeExceededCode as TimeExceededCodeV6};
use tcpip::ip_packet::IPPacket;
use tcpip::ipv4::IPv4Packet;
use tcpip::ipv6::IPv6Packet;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;

use crate::core::routing_worker::{EchoRequest, RoutingWorkerError};
use crate::net_utils::netlink::NetlinkError;
use crate::tui::models::{NetworkErrorType, PingUpdate, UpdateMessage};

#[derive(Debug, Error)]
pub enum PingWorkerError {
    #[error(transparent)]
    NetworkFailed(#[from] NetlinkError),
    #[error(transparent)]
    IcmpError(#[from] ICMPError),
    #[error(transparent)]
    ICMPv6Error(#[from] ICMPv6Error),
    #[error(transparent)]
    IPv6Error(#[from] tcpip::ipv6::IPv6Error),
    #[error(transparent)]
    RoutingWorkerError(#[from] RoutingWorkerError),
    #[error("Channel send error")]
    ChannelSendError,
    #[error("Invalid source IP address")]
    #[allow(dead_code)]
    InvalidSourceIp,
}

#[derive(Debug, Clone, Copy)]
struct PendingPing {
    target_ip: IpAddr,
    sent_at: DateTime<Utc>,
}

pub struct PingRequestSender {
    /// ICMP Echo Requestの送信元識別子
    identifier: u16,

    /// ICMP Echo Requestの送信シーケンス番号
    sequence_counter: u16,

    /// 宛先IPアドレス
    target: IpAddr,

    /// 送信間隔
    interval: Duration,

    /// (宛先IP, ICMP/ICMPv6 Echo Request)のタプルを送信するためのチャネル
    tx: mpsc::Sender<(IpAddr, EchoRequest)>,

    /// 送信済みのPingの情報
    pendings: Arc<Mutex<FxHashMap<u16, PendingPing>>>,
}

pub struct PingResponseReceiver {
    /// ICMP Echo Requestの送信元識別子
    identifier: u16,

    /// タイムアウトチェックのインターバル
    interval: Duration,

    /// Pingのタイムアウト時間
    timeout: Duration,

    /// IPパケットを受信するためのチャネル
    rx: mpsc::Receiver<IPPacket>,

    /// UpdateMessage送信用チャネル
    update_tx: mpsc::Sender<UpdateMessage>,

    /// 送信済みのPingの情報
    pendings: Arc<Mutex<FxHashMap<u16, PendingPing>>>,
}

pub struct PingWorker {
    token: CancellationToken,
    sender: PingRequestSender,
    receiver: PingResponseReceiver,
}

impl PingWorker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token: CancellationToken,
        id: u16,
        target: IpAddr,
        interval: Duration,
        timeout: Duration,
        tx: mpsc::Sender<(IpAddr, EchoRequest)>,
        rx: mpsc::Receiver<IPPacket>,
        update_tx: mpsc::Sender<UpdateMessage>,
    ) -> Self {
        let pendings = FxHashMap::default();
        let pendings = Arc::new(Mutex::new(pendings));

        let sender = PingRequestSender {
            identifier: id,
            sequence_counter: 0,
            target,
            interval,
            tx,
            pendings: pendings.clone(),
        };
        let receiver = PingResponseReceiver {
            identifier: id,
            interval,
            timeout,
            rx,
            update_tx,
            pendings,
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
        debug!(
            "PingWorker: Starting to send ICMP packet to {}",
            self.target
        );

        let sequence_number = self.sequence_counter;
        self.sequence_counter = self.sequence_counter.wrapping_add(1);
        let sent_at = Utc::now();
        let pending_ping = PendingPing {
            target_ip: self.target,
            sent_at,
        };
        // 受信待ちリストに追加
        self.pendings.lock().insert(sequence_number, pending_ping);

        // ICMP Echo Requestを作成
        let echo_req = match self.target {
            IpAddr::V4(_) => EchoRequest::V4 {
                message: icmp::EchoMessage::new_request(
                    self.identifier,
                    sequence_number,
                    vec![0; 32],
                ),
                ttl: None, // Pingでは通常のTTL値を使用
            },
            IpAddr::V6(target) => EchoRequest::V6 {
                message: icmpv6::EchoMessage::new_request(
                    self.identifier,
                    sequence_number,
                    vec![0; 32],
                    Ipv6Addr::UNSPECIFIED, // 送信時に書き換える
                    target,
                ),
                ttl: None, // Pingでは通常のTTL値を使用
            },
        };

        // (宛先IP, ICMP Echo Request)のタプルを送信
        let result = self.tx.send((self.target, echo_req)).await;
        match result {
            Ok(_) => {
                debug!(
                    "PingWorker: Successfully sent ICMP packet to {}",
                    self.target
                );
            }
            Err(e) => {
                warn!(
                    "PingWorker: Failed to send ICMP packet to {}: {}",
                    self.target, e
                );
                return Err(PingWorkerError::ChannelSendError);
            }
        }

        Ok(())
    }
}

impl PingResponseReceiver {
    async fn listen_recv_ip_packets(mut self) -> Result<(), PingWorkerError> {
        let mut check_interval = interval(self.interval.to_std().expect("Invalid duration"));

        loop {
            tokio::select! {
                // IPパケットを受信
                Some(ip_pkt) = self.rx.recv() => {
                    let received_at = Utc::now();
                    if let Err(e) = self.handle_recv_ip_packet(ip_pkt, received_at).await {
                        warn!("Failed to handle received IP packet: {e}");
                    }
                }
                // タイムアウトチェック
                _ = check_interval.tick() => {
                    self.check_timeouts().await;
                }
                else => break,
            }
        }
        Ok(())
    }

    /// 受信したIPパケットを処理
    async fn handle_recv_ip_packet(
        &mut self,
        ip_pkt: IPPacket,
        received_at: DateTime<Utc>,
    ) -> Result<(), PingWorkerError> {
        match ip_pkt {
            IPPacket::V4(ipv4_pkt) => self.handle_recv_ipv4_packet(ipv4_pkt, received_at).await,
            IPPacket::V6(ipv6_pkt) => self.handle_recv_ipv6_packet(ipv6_pkt, received_at).await,
        }
    }

    /// 受信したIPv4パケットを処理
    async fn handle_recv_ipv4_packet(
        &mut self,
        pkt: IPv4Packet,
        received_at: DateTime<Utc>,
    ) -> Result<(), PingWorkerError> {
        let icmp_msg = ICMPMessage::try_from(&pkt.payload)?;
        match icmp_msg {
            ICMPMessage::EchoReply(msg) => {
                self.handle_icmp_echo_reply(msg.identifier, msg.sequence_number, received_at)
                    .await;
            }
            ICMPMessage::DestinationUnreachable(dest_msg) => {
                self.handle_ipv4_destination_unreachable_error(
                    &dest_msg.original_datagram,
                    dest_msg.code,
                )
                .await;
            }
            ICMPMessage::TimeExceeded(time_msg) => {
                self.handle_ipv4_time_exceeded_error(&time_msg.original_datagram, time_msg.code)
                    .await;
            }
            ICMPMessage::ParameterProblem(param_msg) => {
                self.handle_ipv4_parameter_problem_error(&param_msg.original_datagram)
                    .await;
            }
            ICMPMessage::Redirect(redirect_msg) => {
                self.handle_ipv4_redirect_error(&redirect_msg.original_datagram, redirect_msg.code)
                    .await;
            }
            msg => {
                debug!("Received message is not Echo Reply: {}", msg.message_type());
            }
        }

        Ok(())
    }

    async fn handle_recv_ipv6_packet(
        &mut self,
        pkt: IPv6Packet,
        received_at: DateTime<Utc>,
    ) -> Result<(), PingWorkerError> {
        let icmpv6_msg = ICMPv6Message::try_from(&pkt.payload)?;
        match icmpv6_msg {
            ICMPv6Message::EchoReply(msg) => {
                self.handle_icmp_echo_reply(msg.identifier, msg.sequence_number, received_at)
                    .await;
            }
            ICMPv6Message::DestinationUnreachable(dest_msg) => {
                self.handle_ipv6_destination_unreachable_error(
                    &dest_msg.original_packet,
                    dest_msg.code,
                )
                .await;
            }
            ICMPv6Message::TimeExceeded(time_msg) => {
                self.handle_ipv6_time_exceeded_error(&time_msg.original_packet, time_msg.code)
                    .await;
            }
            ICMPv6Message::ParameterProblem(param_msg) => {
                self.handle_ipv6_parameter_problem_error(&param_msg.original_packet)
                    .await;
            }
            ICMPv6Message::PacketTooBig(ptb_msg) => {
                self.handle_ipv6_packet_too_big_error(&ptb_msg.original_packet, ptb_msg.mtu)
                    .await;
            }
            ICMPv6Message::Redirect(redirect_msg) => {
                debug!(
                    "ICMPv6 Redirect received: {} -> {}",
                    redirect_msg.destination_address, redirect_msg.target_address
                );
            }
            msg => {
                debug!("Received message is not Echo Reply: {}", msg.message_type());
            }
        }

        Ok(())
    }

    async fn check_timeouts(&mut self) {
        let now = Utc::now();
        let mut pendings = { self.pendings.lock().clone() };

        // タイムアウトしたpingを処理
        for (seq, pending_ping) in pendings.clone().into_iter() {
            if now - pending_ping.sent_at < self.timeout {
                continue;
            }
            pendings.remove(&seq);
            warn!("Ping timeout for {}, seq: {}", pending_ping.target_ip, seq);
            // TUIへのタイムアウト通知
            let ping_update = PingUpdate {
                id: self.identifier,
                host: pending_ping.target_ip,
                latency: Err(NetworkErrorType::Timeout),
            };

            if let Err(e) = self.update_tx.send(UpdateMessage::Ping(ping_update)).await {
                warn!("Failed to send ping timeout update to TUI: {e}");
            }
        }

        *self.pendings.lock() = pendings;
    }

    async fn handle_icmp_echo_reply(
        &mut self,
        identifier: u16,
        sequence_number: u16,
        received_at: DateTime<Utc>,
    ) {
        if identifier != self.identifier {
            debug!(
                "Received Echo Reply with different identifier. Expected: {}, Received: {}",
                self.identifier, identifier
            );
            return;
        }

        let pending_ping = {
            let mut locked = self.pendings.lock();
            match locked.remove(&sequence_number) {
                Some(pending) => pending,
                None => {
                    debug!("Received Echo Reply with unknown sequence number: {sequence_number}");
                    return;
                }
            }
        };
        let latency = received_at - pending_ping.sent_at;
        info!(
            "Received Echo Reply from {}: seq={}, latency={}ms",
            pending_ping.target_ip,
            sequence_number,
            latency.num_milliseconds()
        );

        // TUIへのUpdateMessage送信
        let ping_update = PingUpdate {
            id: self.identifier,
            host: pending_ping.target_ip,
            latency: Ok(latency),
        };

        if let Err(e) = self.update_tx.send(UpdateMessage::Ping(ping_update)).await {
            warn!("Failed to send ping update to TUI: {e}");
        }
    }

    // IPv4 ICMPエラー処理メソッド
    async fn handle_ipv4_destination_unreachable_error(
        &mut self,
        original_datagram: &IPv4Packet,
        code: icmp::DestinationUnreachableCode,
    ) {
        if let Some(pending_ping) = self
            .extract_pending_ping_from_ipv4_error(original_datagram)
            .unwrap_or_else(|e| {
                warn!("Failed to extract pending ping from IPv4 error: {e}");
                None
            })
        {
            let error_info = NetworkErrorType::DestinationUnreachable(code);
            if let Err(e) = self
                .send_error_update_with_info(pending_ping, error_info)
                .await
            {
                warn!("Failed to send error update: {e}");
            }
        }
    }

    async fn handle_ipv4_time_exceeded_error(
        &mut self,
        original_datagram: &IPv4Packet,
        code: TimeExceededCodeV4,
    ) {
        if let Some(pending_ping) = self
            .extract_pending_ping_from_ipv4_error(original_datagram)
            .unwrap_or_else(|e| {
                warn!("Failed to extract pending ping from IPv4 error: {e}");
                None
            })
        {
            let error_info = NetworkErrorType::TimeExceeded(code);
            if let Err(e) = self
                .send_error_update_with_info(pending_ping, error_info)
                .await
            {
                warn!("Failed to send error update: {e}");
            }
        }
    }

    async fn handle_ipv4_parameter_problem_error(&mut self, original_datagram: &IPv4Packet) {
        if let Some(pending_ping) = self
            .extract_pending_ping_from_ipv4_error(original_datagram)
            .unwrap_or_else(|e| {
                warn!("Failed to extract pending ping from IPv4 error: {e}");
                None
            })
        {
            let error_info = NetworkErrorType::ParameterProblem;
            if let Err(e) = self
                .send_error_update_with_info(pending_ping, error_info)
                .await
            {
                warn!("Failed to send error update: {e}");
            }
        }
    }

    async fn handle_ipv4_redirect_error(
        &mut self,
        original_datagram: &IPv4Packet,
        code: RedirectCode,
    ) {
        if let Some(pending_ping) = self
            .extract_pending_ping_from_ipv4_error(original_datagram)
            .unwrap_or_else(|e| {
                warn!("Failed to extract pending ping from IPv4 error: {e}");
                None
            })
        {
            let error_info = NetworkErrorType::Redirect(code);
            if let Err(e) = self
                .send_error_update_with_info(pending_ping, error_info)
                .await
            {
                warn!("Failed to send error update: {e}");
            }
        }
    }

    // IPv6 ICMPエラー処理メソッド
    async fn handle_ipv6_destination_unreachable_error(
        &mut self,
        original_packet: &IPv6Packet,
        code: tcpip::icmpv6::DestinationUnreachableCode,
    ) {
        if let Some(pending_ping) = self
            .extract_pending_ping_from_ipv6_error(original_packet)
            .unwrap_or_else(|e| {
                warn!("Failed to extract pending ping from IPv6 error: {e}");
                None
            })
        {
            let error_info = NetworkErrorType::DestinationUnreachableV6(code);
            if let Err(e) = self
                .send_error_update_with_info(pending_ping, error_info)
                .await
            {
                warn!("Failed to send error update: {e}");
            }
        }
    }

    async fn handle_ipv6_time_exceeded_error(
        &mut self,
        original_packet: &IPv6Packet,
        code: TimeExceededCodeV6,
    ) {
        if let Some(pending_ping) = self
            .extract_pending_ping_from_ipv6_error(original_packet)
            .unwrap_or_else(|e| {
                warn!("Failed to extract pending ping from IPv6 error: {e}");
                None
            })
        {
            let error_info = NetworkErrorType::TimeExceededV6(code);
            if let Err(e) = self
                .send_error_update_with_info(pending_ping, error_info)
                .await
            {
                warn!("Failed to send error update: {e}");
            }
        }
    }

    async fn handle_ipv6_parameter_problem_error(&mut self, original_packet: &IPv6Packet) {
        if let Some(pending_ping) = self
            .extract_pending_ping_from_ipv6_error(original_packet)
            .unwrap_or_else(|e| {
                warn!("Failed to extract pending ping from IPv6 error: {e}");
                None
            })
        {
            let error_info = NetworkErrorType::ParameterProblem;
            if let Err(e) = self
                .send_error_update_with_info(pending_ping, error_info)
                .await
            {
                warn!("Failed to send error update: {e}");
            }
        }
    }

    async fn handle_ipv6_packet_too_big_error(&mut self, original_packet: &IPv6Packet, mtu: u32) {
        if let Some(pending_ping) = self
            .extract_pending_ping_from_ipv6_error(original_packet)
            .unwrap_or_else(|e| {
                warn!("Failed to extract pending ping from IPv6 error: {e}");
                None
            })
        {
            let error_info = NetworkErrorType::PacketTooBig(mtu);
            if let Err(e) = self
                .send_error_update_with_info(pending_ping, error_info)
                .await
            {
                warn!("Failed to send error update: {e}");
            }
        }
    }

    fn extract_pending_ping_from_ipv4_error(
        &mut self,
        original_datagram: &IPv4Packet,
    ) -> Result<Option<PendingPing>, PingWorkerError> {
        let Ok(icmp_payload) = ICMPMessage::try_from(&original_datagram.payload) else {
            return Ok(None); // 解析失敗時は無視
        };

        let ICMPMessage::Echo(echo_msg) = icmp_payload else {
            return Ok(None); // Echo以外の元パケットは無視
        };

        if echo_msg.identifier != self.identifier {
            return Ok(None); // 異なるidentifierは無視
        }

        Ok(self.pendings.lock().remove(&echo_msg.sequence_number))
    }

    fn extract_pending_ping_from_ipv6_error(
        &mut self,
        original_packet: &IPv6Packet,
    ) -> Result<Option<PendingPing>, PingWorkerError> {
        let Ok(icmpv6_payload) = ICMPv6Message::try_from(&original_packet.payload) else {
            return Ok(None); // 解析失敗時は無視
        };

        let ICMPv6Message::EchoRequest(echo_msg) = icmpv6_payload else {
            return Ok(None); // EchoRequest以外の元パケットは無視
        };

        if echo_msg.identifier != self.identifier {
            return Ok(None); // 異なるidentifierは無視
        }

        Ok(self.pendings.lock().remove(&echo_msg.sequence_number))
    }

    async fn send_error_update_with_info(
        &self,
        pending_ping: PendingPing,
        error_info: NetworkErrorType,
    ) -> Result<(), PingWorkerError> {
        let ping_update = PingUpdate {
            id: self.identifier,
            host: pending_ping.target_ip,
            latency: Err(error_info),
        };

        if let Err(e) = self.update_tx.send(UpdateMessage::Ping(ping_update)).await {
            warn!("Failed to send ping error update to TUI: {e}");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration as StdDuration;

    use chrono::Duration;
    use tokio::sync::mpsc;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::core::routing_worker::EchoRequest;

    #[test]
    fn test_pending_ping() {
        // [正常系] PendingPing構造体の作成と基本フィールドアクセス
        let target_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let _sequence_number = 1234;
        let sent_at = Utc::now();

        let pending_ping = PendingPing { target_ip, sent_at };

        assert_eq!(pending_ping.target_ip, target_ip);
        assert_eq!(pending_ping.sent_at, sent_at);
    }

    #[tokio::test]
    async fn test_ping_worker_new() {
        // [正常系] PingWorkerの正常な作成
        let token = CancellationToken::new();
        let id = 12345;
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let interval = chrono::Duration::seconds(1);
        let timeout = chrono::Duration::seconds(5);
        let (tx, _) = mpsc::channel(100);
        let rx = mpsc::channel(100).1;
        let (update_tx, _update_rx) = mpsc::channel(100);

        let ping_worker = PingWorker::new(token, id, target, interval, timeout, tx, rx, update_tx);
        assert_eq!(ping_worker.sender.target, target);
        assert_eq!(ping_worker.sender.interval, interval);
        assert_eq!(
            ping_worker.sender.identifier,
            ping_worker.receiver.identifier
        );
        assert_eq!(ping_worker.sender.sequence_counter, 0);
    }

    #[tokio::test]
    async fn test_handle_send_ip_packet() {
        // [正常系] ICMP Echo Requestの正常送信
        let identifier = 12345;
        let sequence_counter = 0;
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let interval = Duration::seconds(1);
        let (tx, mut rx) = mpsc::channel::<(IpAddr, EchoRequest)>(100);
        let pendings = Arc::new(parking_lot::Mutex::new(FxHashMap::default()));

        let mut sender = PingRequestSender {
            identifier,
            sequence_counter,
            target,
            interval,
            tx,
            pendings: pendings.clone(),
        };

        let result = sender.handle_send_ip_packet().await;
        assert!(result.is_ok());

        // [正常系] シーケンス番号の増加確認
        assert_eq!(sender.sequence_counter, 1);

        // [正常系] pending_pingsへの追加確認
        let locked_pendings = pendings.lock();
        assert_eq!(locked_pendings.len(), 1);
        assert!(locked_pendings.contains_key(&0));

        // [正常系] チャネルへのEchoRequest送信確認
        let (_target_ip, echo_request) = rx.try_recv().unwrap();
        match echo_request {
            EchoRequest::V4 { message: msg, ttl } => {
                assert_eq!(msg.identifier, identifier);
                assert_eq!(msg.sequence_number, 0);
                assert_eq!(ttl, None);
            }
            EchoRequest::V6 { .. } => panic!("Expected IPv4 Echo Request"),
        }
    }

    #[tokio::test]
    async fn test_handle_icmp_echo_reply() {
        // [正常系] ICMP Echo Replyの正常処理
        let identifier = 12345;
        let sequence_number = 100;
        let interval = chrono::Duration::seconds(1);
        let timeout = chrono::Duration::seconds(5);
        let target_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let sent_at = Utc::now();

        let pendings = Arc::new(parking_lot::Mutex::new(FxHashMap::default()));
        let rx = mpsc::channel(100).1;
        let (update_tx, mut update_rx) = mpsc::channel(100);

        // 送信済みPingを追加
        pendings
            .lock()
            .insert(sequence_number, PendingPing { target_ip, sent_at });

        let mut receiver = PingResponseReceiver {
            identifier,
            interval,
            timeout,
            rx,
            update_tx,
            pendings: pendings.clone(),
        };

        // handle_icmp_echo_replyメソッドをテスト
        let received_at = chrono::Utc::now();
        receiver
            .handle_icmp_echo_reply(identifier, sequence_number, received_at)
            .await;

        // 送信済みPingが削除されていることを確認
        assert!(!pendings.lock().contains_key(&sequence_number));

        // UpdateMessageが送信されていることを確認
        let update = update_rx.try_recv().unwrap();
        if let UpdateMessage::Ping(ping_update) = update {
            assert_eq!(ping_update.id, identifier);
            assert_eq!(ping_update.host, target_ip);
            assert!(ping_update.latency.is_ok());
        } else {
            panic!("Expected Ping update");
        }
    }

    #[tokio::test]
    async fn test_run() {
        // [正常系] PingWorkerの正常実行とキャンセレーション処理
        let token = CancellationToken::new();
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let interval = chrono::Duration::seconds(1);
        let (tx, _) = mpsc::channel(100);
        let rx = mpsc::channel(100).1;
        let (update_tx, _update_rx) = mpsc::channel(100);

        let ping_worker = PingWorker::new(
            token.clone(),
            12345,
            target,
            interval,
            chrono::Duration::seconds(5),
            tx,
            rx,
            update_tx,
        );

        // ワーカーを短時間実行してからキャンセル
        let run_handle = tokio::spawn(ping_worker.run());
        tokio::time::sleep(StdDuration::from_millis(10)).await;
        token.cancel();

        let result = timeout(StdDuration::from_millis(100), run_handle).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }

    #[test]
    fn test_ping_worker_error() {
        // [正常系] PingWorkerErrorの正常な表示
        let error1 = PingWorkerError::ChannelSendError;
        assert_eq!(error1.to_string(), "Channel send error");
    }

    #[tokio::test]
    async fn test_check_timeouts() {
        // [正常系] タイムアウトチェックの正常処理
        let identifier = 12345;
        let interval = chrono::Duration::seconds(1);
        let timeout = chrono::Duration::milliseconds(100); // 短いタイムアウト
        let target_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let pendings = Arc::new(Mutex::new(FxHashMap::default()));
        let rx = mpsc::channel(100).1;
        let (update_tx, mut update_rx) = mpsc::channel(100);

        // 期限切れのPingを追加
        let sent_at = Utc::now() - chrono::Duration::seconds(1); // 1秒前
        pendings
            .lock()
            .insert(1, PendingPing { target_ip, sent_at });

        let mut receiver = PingResponseReceiver {
            identifier,
            interval,
            timeout,
            rx,
            update_tx,
            pendings: pendings.clone(),
        };

        // タイムアウトチェックを実行
        receiver.check_timeouts().await;

        // pending_pingsから削除されていることを確認
        assert!(pendings.lock().is_empty());

        // タイムアウトUpdateMessageが送信されていることを確認
        let update = update_rx.try_recv().unwrap();
        if let UpdateMessage::Ping(ping_update) = update {
            assert_eq!(ping_update.id, identifier);
            assert_eq!(ping_update.host, target_ip);
            assert!(ping_update.latency.is_err());
        } else {
            panic!("Expected Ping update");
        }
    }
}
