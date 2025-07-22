use std::net::IpAddr;
use std::time::Instant;

use chrono::Duration;
use crossterm::event;
use fxhash::FxHashMap;
use ratatui::widgets::TableState;
use tcpip::icmp::{
    DestinationUnreachableCode as DestinationUnreachableCodeV4, RedirectCode,
    TimeExceededCode as TimeExceededCodeV4,
};
use tcpip::icmpv6::{
    DestinationUnreachableCode as DestinationUnreachableCodeV6,
    TimeExceededCode as TimeExceededCodeV6,
};

use crate::config::{Config, Target, TargetHost};
use crate::tui::styles::{ERROR_MARKER, MAX_HISTORY_SIZE};

#[derive(Debug, Clone)]
pub(crate) enum Event {
    Init,
    Quit,
    Error,
    Render,
    Key(event::KeyEvent),
}

#[derive(Debug, Clone)]
pub(crate) enum UpdateMessage {
    Ping(PingUpdate),
    Traceroute(TracerouteUpdate),
}

#[derive(Debug, Clone)]
pub(crate) struct PingUpdate {
    pub(crate) id: u16,
    pub(crate) host: IpAddr,
    /// レイテンシ
    /// エラーの場合はエラー情報が入る
    pub(crate) latency: Result<Duration, NetworkErrorType>,
}

#[derive(Debug, Clone)]
pub(crate) struct TracerouteUpdate {
    pub(crate) id: u16,
    pub(crate) hops: Vec<TracerouteHop>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NetworkErrorType {
    DestinationUnreachable(DestinationUnreachableCodeV4),
    DestinationUnreachableV6(DestinationUnreachableCodeV6),
    TimeExceeded(TimeExceededCodeV4),
    TimeExceededV6(TimeExceededCodeV6),
    ParameterProblem,
    Redirect(RedirectCode),
    PacketTooBig(u32),
    Timeout,
    NoRouteToHost,
}

impl NetworkErrorType {
    pub(crate) fn icon(&self) -> &'static str {
        match self {
            NetworkErrorType::DestinationUnreachable(code) => match code {
                DestinationUnreachableCodeV4::NetworkUnreachable => "\u{f0319}",
                DestinationUnreachableCodeV4::HostUnreachable => "\u{f0319}",
                DestinationUnreachableCodeV4::ProtocolUnreachable => "\u{f071e}",
                DestinationUnreachableCodeV4::PortUnreachable => "\u{f0675}",
                DestinationUnreachableCodeV4::FragmentationNeededAndDFSet => "\u{f0721}",
                DestinationUnreachableCodeV4::SourceRouteFailed => "\u{f071f}",
            },
            NetworkErrorType::DestinationUnreachableV6(code) => match code {
                DestinationUnreachableCodeV6::NoRouteToDestination => "\u{f0202}",
                DestinationUnreachableCodeV6::CommunicationProhibited => "\u{f0653}",
                DestinationUnreachableCodeV6::BeyondScopeOfSourceAddress => "\u{f071f}",
                DestinationUnreachableCodeV6::AddressUnreachable => "\u{f0319}",
                DestinationUnreachableCodeV6::PortUnreachable => "\u{f0675}",
                DestinationUnreachableCodeV6::SourceAddressPolicyViolation => "\u{f0653}",
                DestinationUnreachableCodeV6::RejectRouteToDestination => "\u{f0653}",
            },
            NetworkErrorType::TimeExceeded(_) => "\u{f0953}",
            NetworkErrorType::TimeExceededV6(_) => "\u{f0953}",
            NetworkErrorType::ParameterProblem => "\u{f071e}",
            NetworkErrorType::Redirect(_) => "\u{f0720}",
            NetworkErrorType::PacketTooBig(_) => "\u{f0721}",
            NetworkErrorType::Timeout => "\u{f199f}",
            NetworkErrorType::NoRouteToHost => "\u{f0202}",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TracerouteHop {
    pub(crate) hop_number: u8,
    pub(crate) success: bool,
    pub(crate) address: Option<IpAddr>,
    pub(crate) latency: Option<Duration>,
    pub(crate) error: Option<NetworkErrorType>,
}

/// Traceroute履歴管理用の内部構造体
#[derive(Debug, Clone)]
pub(crate) struct TracerouteHopHistory {
    pub(crate) hop_number: u8,
    pub(crate) success: bool,
    pub(crate) address: Option<IpAddr>,
    pub(crate) latency: Option<Duration>,
    pub(crate) error: Option<NetworkErrorType>,
    /// レスポンス時間の履歴（sparkline用）
    pub(crate) latency_history: Vec<f64>,
}

#[derive(Debug, Clone)]
pub(crate) struct PingResult {
    pub(crate) target: String,
    pub(crate) host: String,
    pub(crate) status: PingStatus,
    pub(crate) response_time: Option<Duration>,
    pub(crate) last_updated: Instant,
    pub(crate) packet_loss: f64,
    pub(crate) avg_response_time: Option<Duration>,
    pub(crate) latency_history: Vec<f64>,
    pub(crate) total_sent: u64,
    pub(crate) total_received: u64,
}

#[derive(Debug, Clone)]
pub(crate) enum PingStatus {
    Success,
    NetworkError(NetworkErrorType),
}

pub(crate) struct AppState {
    pub(crate) ping_results: FxHashMap<TargetHost, PingResult>,
    pub(crate) targets: Vec<TargetHost>,
    pub(crate) selected_index: usize,
    pub(crate) traceroute_results: FxHashMap<TargetHost, Vec<TracerouteHopHistory>>,
    pub(crate) show_details: bool,
    pub(crate) table_state: TableState,
    /// ConfigのTargetsへの参照（IDマッチング用）
    pub(crate) target_configs: Vec<Target>,
}

impl AppState {
    pub(crate) fn new(config: &Config) -> Self {
        let mut ping_results = FxHashMap::default();
        let targets: Vec<TargetHost> = config.targets.iter().map(|t| t.host.clone()).collect();

        for target_config in &config.targets {
            ping_results.insert(
                target_config.host.clone(),
                PingResult {
                    target: target_config.name.clone(),
                    host: target_config.host.to_string(),
                    status: PingStatus::Success,
                    response_time: None,
                    last_updated: Instant::now(),
                    packet_loss: 0.0,
                    avg_response_time: None,
                    latency_history: Vec::new(),
                    total_sent: 0,
                    total_received: 0,
                },
            );
        }

        let mut table_state = TableState::default();
        if !config.targets.is_empty() {
            table_state.select(Some(0));
        }

        Self {
            ping_results,
            targets,
            selected_index: 0,
            traceroute_results: FxHashMap::default(),
            show_details: false,
            table_state,
            target_configs: config.targets.clone(),
        }
    }

    pub(crate) fn update_ping_result(&mut self, update: PingUpdate) {
        // idに基づいてターゲットを見つける（id=0の場合はhostで特定）
        let target_key = if update.id == 0 {
            // RoutingWorkerからのエラーの場合、hostアドレスでターゲットを特定
            self.target_configs
                .iter()
                .find(|config_target| config_target.host.to_string() == update.host.to_string())
                .map(|config_target| config_target.host.clone())
        } else {
            // 通常のPingWorkerからの更新の場合、idで特定
            self.target_configs
                .iter()
                .find(|config_target| config_target.id == update.id)
                .map(|config_target| config_target.host.clone())
        };

        let target = if let Some(target) = target_key {
            target
        } else {
            return;
        };
        if let Some(result) = self.ping_results.get_mut(&target) {
            result.total_sent += 1;
            result.last_updated = Instant::now();
            // hostの情報を更新
            result.host = update.host.to_string();

            match update.latency {
                Ok(rtt) => {
                    // 成功時の処理
                    result.total_received += 1;
                    result.status = PingStatus::Success;
                    result.response_time = Some(rtt);
                    result.latency_history.push(rtt.num_milliseconds() as f64);

                    if result.latency_history.len() > MAX_HISTORY_SIZE {
                        result.latency_history.remove(0);
                    }

                    // タイムアウトマーカーを除外して平均を計算
                    let valid_values: Vec<f64> = result
                        .latency_history
                        .iter()
                        .filter(|&&v| v != ERROR_MARKER)
                        .cloned()
                        .collect();
                    let avg = if valid_values.is_empty() {
                        0.0
                    } else {
                        valid_values.iter().sum::<f64>() / valid_values.len() as f64
                    };
                    result.avg_response_time = Some(Duration::milliseconds(avg as i64));
                }
                Err(error) => {
                    // エラー時の処理
                    result.response_time = None;
                    // ネットワークエラー時は履歴にエラーマーカーを追加
                    result.latency_history.push(ERROR_MARKER);

                    if result.latency_history.len() > MAX_HISTORY_SIZE {
                        result.latency_history.remove(0);
                    }
                    result.status = PingStatus::NetworkError(error);
                }
            }

            result.packet_loss = if result.total_sent > 0 {
                (1.0 - (result.total_received as f64 / result.total_sent as f64)) * 100.0
            } else {
                0.0
            };
        }
    }

    pub(crate) fn update_traceroute_result(&mut self, update: TracerouteUpdate) {
        // TracerouteのIDはping_target.id + total_target_countで計算されている
        // 元のping_target.idを逆算する
        let total_target_count = self.target_configs.len() as u16;
        let original_ping_id = update.id - total_target_count;

        let target_key = self
            .target_configs
            .iter()
            .find(|config_target| config_target.id == original_ping_id)
            .map(|config_target| config_target.host.clone());

        let target = if let Some(target) = target_key {
            target
        } else {
            return;
        };
        // 既存のhopデータと新しいhopデータをマージして履歴を更新
        if let Some(existing_hops) = self.traceroute_results.get_mut(&target) {
            for new_hop in update.hops {
                // 同じhop_numberの既存hopを探す
                if let Some(existing_hop) = existing_hops
                    .iter_mut()
                    .find(|h| h.hop_number == new_hop.hop_number)
                {
                    // 新しい情報で既存hopを更新
                    existing_hop.success = new_hop.success;
                    existing_hop.latency = new_hop.latency;
                    existing_hop.error = new_hop.error.clone();
                    // addressが新しく取得できた場合は更新
                    if new_hop.address.is_some() {
                        existing_hop.address = new_hop.address;
                    }

                    // レスポンス時間の履歴を更新
                    if let Some(latency) = new_hop.latency {
                        existing_hop
                            .latency_history
                            .push(latency.num_milliseconds() as f64);
                    } else {
                        // エラーの場合はマーカーを追加
                        existing_hop.latency_history.push(ERROR_MARKER);
                    }

                    // 履歴がMAX_HISTORY_SIZEを超えたら古いデータを削除
                    if existing_hop.latency_history.len() > MAX_HISTORY_SIZE {
                        existing_hop.latency_history.remove(0);
                    }
                } else {
                    // 新しいhop番号の場合は追加（TracerouteHopをTracerouteHopHistoryに変換）
                    let latency_history = if let Some(latency) = new_hop.latency {
                        vec![latency.num_milliseconds() as f64]
                    } else {
                        vec![ERROR_MARKER]
                    };

                    let hop_history = TracerouteHopHistory {
                        hop_number: new_hop.hop_number,
                        success: new_hop.success,
                        address: new_hop.address,
                        latency: new_hop.latency,
                        error: new_hop.error,
                        latency_history,
                    };
                    existing_hops.push(hop_history);
                }
            }
            // hop_numberでソート
            existing_hops.sort_by_key(|h| h.hop_number);
        } else {
            // 初回の場合は新規作成、履歴データも初期化
            let mut initial_hops = Vec::new();
            for hop in update.hops {
                let latency_history = if let Some(latency) = hop.latency {
                    vec![latency.num_milliseconds() as f64]
                } else {
                    vec![ERROR_MARKER]
                };

                let hop_history = TracerouteHopHistory {
                    hop_number: hop.hop_number,
                    success: hop.success,
                    address: hop.address,
                    latency: hop.latency,
                    error: hop.error,
                    latency_history,
                };
                initial_hops.push(hop_history);
            }
            self.traceroute_results.insert(target, initial_hops);
        }
    }

    pub(crate) fn get_traceroute_hops(&self, target: &TargetHost) -> Vec<TracerouteHopHistory> {
        self.traceroute_results
            .get(target)
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn get_ping_results_sorted(&self) -> Vec<&PingResult> {
        // 設定ファイルの順序を保持するため、target_configsの順序に従って結果を返す
        self.target_configs
            .iter()
            .filter_map(|config| self.ping_results.get(&config.host))
            .collect()
    }

    pub(crate) fn move_up(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
            self.table_state.select(Some(self.selected_index));
        }
    }

    pub(crate) fn move_down(&mut self) {
        if self.selected_index < self.target_configs.len().saturating_sub(1) {
            self.selected_index += 1;
            self.table_state.select(Some(self.selected_index));
        }
    }

    pub(crate) fn toggle_details(&mut self) {
        self.show_details = !self.show_details;
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::time::Instant;

    use chrono::Duration;
    use tcpip::icmp::TimeExceededCode;

    use super::*;
    use crate::config::{Config, Target};

    #[test]
    fn test_get_ping_results_sorted_preserves_order() {
        // [正常系] 設定ファイルの順序が保持されることを確認
        let config = Config {
            targets: vec![
                Target {
                    id: 1,
                    name: "DNS1".to_string(),
                    host: TargetHost::Domain("8.8.8.8".to_string()),
                },
                Target {
                    id: 2,
                    name: "Router".to_string(),
                    host: TargetHost::Domain("192.168.1.1".to_string()),
                },
                Target {
                    id: 3,
                    name: "DNS2".to_string(),
                    host: TargetHost::Domain("1.1.1.1".to_string()),
                },
            ],
            ..Config::default()
        };

        let mut app_state = AppState::new(&config);
        let now = Instant::now();

        // Ping結果を追加（順序と異なる順番で追加）
        app_state.ping_results.insert(
            TargetHost::Domain("1.1.1.1".to_string()),
            PingResult {
                target: "1.1.1.1".to_string(),
                host: "1.1.1.1".to_string(),
                status: PingStatus::Success,
                response_time: Some(Duration::milliseconds(10)),
                last_updated: now,
                packet_loss: 0.0,
                avg_response_time: Some(Duration::milliseconds(10)),
                total_sent: 1,
                total_received: 1,
                latency_history: vec![10.0],
            },
        );

        app_state.ping_results.insert(
            TargetHost::Domain("192.168.1.1".to_string()),
            PingResult {
                target: "192.168.1.1".to_string(),
                host: "192.168.1.1".to_string(),
                status: PingStatus::Success,
                response_time: Some(Duration::milliseconds(5)),
                last_updated: now,
                packet_loss: 0.0,
                avg_response_time: Some(Duration::milliseconds(5)),
                total_sent: 1,
                total_received: 1,
                latency_history: vec![5.0],
            },
        );

        app_state.ping_results.insert(
            TargetHost::Domain("8.8.8.8".to_string()),
            PingResult {
                target: "8.8.8.8".to_string(),
                host: "8.8.8.8".to_string(),
                status: PingStatus::Success,
                response_time: Some(Duration::milliseconds(20)),
                last_updated: now,
                packet_loss: 0.0,
                avg_response_time: Some(Duration::milliseconds(20)),
                total_sent: 1,
                total_received: 1,
                latency_history: vec![20.0],
            },
        );

        // 結果を取得
        let results = app_state.get_ping_results_sorted();

        // 設定ファイルの順序（8.8.8.8, 192.168.1.1, 1.1.1.1）が保持されていることを確認
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].target, "8.8.8.8");
        assert_eq!(results[1].target, "192.168.1.1");
        assert_eq!(results[2].target, "1.1.1.1");

        // レスポンス時間も正しく設定されていることを確認
        assert_eq!(results[0].response_time.unwrap().num_milliseconds(), 20);
        assert_eq!(results[1].response_time.unwrap().num_milliseconds(), 5);
        assert_eq!(results[2].response_time.unwrap().num_milliseconds(), 10);
    }

    #[test]
    fn test_update_traceroute_result_with_error_info() {
        // [正常系] Tracerouteの結果更新時にエラー情報が正しく処理されることを確認
        let config = Config {
            targets: vec![Target {
                id: 1,
                name: "Test Host".to_string(),
                host: TargetHost::Domain("example.com".to_string()),
            }],
            ..Config::default()
        };

        let mut app_state = AppState::new(&config);

        // エラー情報を含むTracerouteUpdateを作成
        // TracerouteのIDはping_target.id + total_target_countで計算されるため、1 + 1 = 2を使用
        let traceroute_update = TracerouteUpdate {
            id: 2,
            hops: vec![TracerouteHop {
                hop_number: 1,
                success: false,
                address: Some(IpAddr::from_str("192.168.1.1").unwrap()),
                latency: None,
                error: Some(NetworkErrorType::TimeExceeded(
                    TimeExceededCode::TtlExceeded,
                )),
            }],
        };

        // 結果を更新
        app_state.update_traceroute_result(traceroute_update);

        // 結果を取得
        let hops = app_state.get_traceroute_hops(&TargetHost::Domain("example.com".to_string()));

        // エラー情報が正しく保存されていることを確認
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].hop_number, 1);
        assert!(!hops[0].success);
        assert_eq!(
            hops[0].address,
            Some(IpAddr::from_str("192.168.1.1").unwrap())
        );
        assert_eq!(hops[0].latency, None);
        assert_eq!(
            hops[0].error,
            Some(NetworkErrorType::TimeExceeded(
                TimeExceededCode::TtlExceeded
            ))
        );
    }
}
