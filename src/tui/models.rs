use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

use chrono::Duration;
use crossterm::event;
use ratatui::widgets::TableState;

use crate::config::{Config, Target};

// タイムアウトを表すマーカー値
pub const TIMEOUT_MARKER: f64 = -1.0;

#[derive(Debug, Clone)]
pub enum Event {
    Init,
    Quit,
    Error,
    Render,
    Key(event::KeyEvent),
}

#[derive(Debug, Clone)]
pub enum UpdateMessage {
    Ping(PingUpdate),
    Traceroute(TracerouteUpdate),
}

#[derive(Debug, Clone)]
pub struct PingUpdate {
    pub id: u16,
    pub success: bool,
    pub host: Ipv4Addr,
    pub latency: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct TracerouteUpdate {
    pub id: u16,
    pub hops: Vec<TracerouteHop>,
}

#[derive(Debug, Clone)]
pub struct TracerouteHop {
    pub hop_number: u8,
    pub success: bool,
    pub address: Option<Ipv4Addr>,
    pub latency: Option<Duration>,
}

/// Traceroute履歴管理用の内部構造体
#[derive(Debug, Clone)]
pub struct TracerouteHopHistory {
    pub hop_number: u8,
    pub success: bool,
    pub address: Option<Ipv4Addr>,
    pub latency: Option<Duration>,
    /// レスポンス時間の履歴（sparkline用）
    pub latency_history: Vec<f64>,
}

#[derive(Debug, Clone)]
pub struct PingResult {
    pub target: String,
    pub host: String,
    pub status: PingStatus,
    pub response_time: Option<Duration>,
    pub last_updated: Instant,
    pub packet_loss: f64,
    pub avg_response_time: Option<Duration>,
    pub latency_history: Vec<f64>,
    pub total_sent: u64,
    pub total_received: u64,
}

#[derive(Debug, Clone)]
pub enum PingStatus {
    Success,
    Timeout,
    #[allow(dead_code)]
    Error(String),
}

pub struct AppState {
    pub ping_results: HashMap<String, PingResult>,
    pub targets: Vec<String>,
    pub selected_index: usize,
    pub traceroute_results: HashMap<String, Vec<TracerouteHopHistory>>,
    pub show_details: bool,
    pub table_state: TableState,
    /// ConfigのTargetsへの参照（IDマッチング用）
    pub target_configs: Vec<Target>,
}

impl AppState {
    pub fn new(targets: Vec<String>, config: &Config) -> Self {
        let mut ping_results = HashMap::new();

        for target in &targets {
            // targetがドメイン名の場合でもhostにはIPアドレスのみを表示したいが、
            // ここでは一旦targetをそのまま使用し、実際のPing処理でIPアドレスに更新される
            ping_results.insert(
                target.clone(),
                PingResult {
                    target: target.clone(),
                    host: target.clone(), // Ping処理でIPアドレスに更新される
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
        if !targets.is_empty() {
            table_state.select(Some(0));
        }

        Self {
            ping_results,
            targets,
            selected_index: 0,
            traceroute_results: HashMap::new(),
            show_details: false,
            table_state,
            target_configs: config.targets.clone(),
        }
    }

    pub fn update_ping_result(&mut self, update: PingUpdate) {
        // idに基づいてターゲットを見つける
        let target_key = self
            .target_configs
            .iter()
            .find(|config_target| config_target.id == update.id)
            .and_then(|config_target| {
                // Configから対応するターゲット文字列を見つける
                self.targets
                    .iter()
                    .find(|target| target.contains(&config_target.name))
                    .cloned()
            });

        if let Some(target) = target_key {
            if let Some(result) = self.ping_results.get_mut(&target) {
                result.total_sent += 1;
                result.last_updated = Instant::now();

                // hostの情報を更新
                result.host = update.host.to_string();

                if update.success {
                    result.total_received += 1;
                    result.status = PingStatus::Success;
                    if let Some(rtt) = update.latency {
                        result.response_time = Some(rtt);
                        result.latency_history.push(rtt.num_milliseconds() as f64);

                        if result.latency_history.len() > 50 {
                            result.latency_history.remove(0);
                        }

                        // タイムアウトマーカーを除外して平均を計算
                        let valid_values: Vec<f64> = result
                            .latency_history
                            .iter()
                            .filter(|&&v| v != TIMEOUT_MARKER)
                            .cloned()
                            .collect();
                        let avg = if valid_values.is_empty() {
                            0.0
                        } else {
                            valid_values.iter().sum::<f64>() / valid_values.len() as f64
                        };
                        result.avg_response_time = Some(Duration::milliseconds(avg as i64));
                    }
                } else {
                    result.response_time = None;
                    // タイムアウト時は履歴にマーカーを追加
                    result.latency_history.push(TIMEOUT_MARKER);

                    if result.latency_history.len() > 50 {
                        result.latency_history.remove(0);
                    }

                    result.status = PingStatus::Timeout;
                }

                result.packet_loss = if result.total_sent > 0 {
                    (1.0 - (result.total_received as f64 / result.total_sent as f64)) * 100.0
                } else {
                    0.0
                };
            }
        }

        // Traceroute結果の更新はTracerouteUpdateで行う
    }

    pub fn update_traceroute_result(&mut self, update: TracerouteUpdate) {
        // TracerouteのIDはping_target.id + ping_target_lenで計算されている
        // 元のping_target.idを逆算する
        let ping_target_len = self.target_configs.len() as u16;
        let original_ping_id = if update.id >= ping_target_len {
            update.id - ping_target_len
        } else {
            update.id
        };

        let target_key = self
            .target_configs
            .iter()
            .find(|config_target| config_target.id == original_ping_id)
            .and_then(|config_target| {
                // Configから対応するターゲット文字列を見つける
                self.targets
                    .iter()
                    .find(|target| target.contains(&config_target.name))
                    .cloned()
            });

        if let Some(target) = target_key {
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
                            // タイムアウトの場合はマーカーを追加
                            existing_hop.latency_history.push(TIMEOUT_MARKER);
                        }

                        // 履歴が50を超えたら古いデータを削除
                        if existing_hop.latency_history.len() > 50 {
                            existing_hop.latency_history.remove(0);
                        }
                    } else {
                        // 新しいhop番号の場合は追加（TracerouteHopをTracerouteHopHistoryに変換）
                        let latency_history = if let Some(latency) = new_hop.latency {
                            vec![latency.num_milliseconds() as f64]
                        } else {
                            vec![TIMEOUT_MARKER]
                        };

                        let hop_history = TracerouteHopHistory {
                            hop_number: new_hop.hop_number,
                            success: new_hop.success,
                            address: new_hop.address,
                            latency: new_hop.latency,
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
                        vec![TIMEOUT_MARKER]
                    };

                    let hop_history = TracerouteHopHistory {
                        hop_number: hop.hop_number,
                        success: hop.success,
                        address: hop.address,
                        latency: hop.latency,
                        latency_history,
                    };
                    initial_hops.push(hop_history);
                }
                self.traceroute_results.insert(target, initial_hops);
            }
        }
    }

    pub fn get_traceroute_hops(&self, target: &str) -> Vec<TracerouteHopHistory> {
        self.traceroute_results
            .get(target)
            .cloned()
            .unwrap_or_default()
    }

    pub fn get_ping_results_sorted(&self) -> Vec<&PingResult> {
        let mut results: Vec<&PingResult> = self
            .targets
            .iter()
            .filter_map(|target| self.ping_results.get(target))
            .collect();
        results.sort_by(|a, b| a.target.cmp(&b.target));
        results
    }

    pub fn move_up(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
            self.table_state.select(Some(self.selected_index));
        }
    }

    pub fn move_down(&mut self) {
        if self.selected_index < self.targets.len().saturating_sub(1) {
            self.selected_index += 1;
            self.table_state.select(Some(self.selected_index));
        }
    }

    pub fn toggle_details(&mut self) {
        self.show_details = !self.show_details;
    }
}
