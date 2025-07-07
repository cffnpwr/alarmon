use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

use chrono::Duration;
use crossterm::event;
use ratatui::widgets::TableState;

// タイムアウトを表すマーカー値
pub const TIMEOUT_MARKER: f64 = -1.0;

#[derive(Debug, Clone)]
pub enum Event {
    Init,
    Quit,
    Error,
    Tick,
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
    pub target: String,
    pub host: Option<String>, // IPアドレスを含むhost情報
    pub success: bool,
    pub latency: Option<Duration>,
    pub error: Option<String>,
    pub traceroute_hops: Option<Vec<TracerouteHop>>,
}

#[derive(Debug, Clone)]
pub struct TracerouteUpdate {
    pub target: String,
    pub hops: Vec<TracerouteHop>,
}

#[derive(Debug, Clone)]
pub struct TracerouteHop {
    pub hop_number: u8,
    pub address: Option<Ipv4Addr>,
    pub response_time: Option<Duration>,
    pub latency_history: Vec<f64>,
    pub avg_response_time: Option<Duration>,
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
    pub traceroute_results: HashMap<String, Vec<TracerouteHop>>,
    pub show_details: bool,
    pub table_state: TableState,
}

impl AppState {
    pub fn new(targets: Vec<String>) -> Self {
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
        }
    }

    pub fn update_ping_result(&mut self, update: PingUpdate) {
        if let Some(result) = self.ping_results.get_mut(&update.target) {
            result.total_sent += 1;
            result.last_updated = Instant::now();

            // hostの情報が提供されている場合は更新
            if let Some(host) = update.host {
                result.host = host;
            }

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

                if let Some(error) = update.error {
                    result.status = PingStatus::Error(error);
                } else {
                    result.status = PingStatus::Timeout;
                }
            }

            result.packet_loss = if result.total_sent > 0 {
                (1.0 - (result.total_received as f64 / result.total_sent as f64)) * 100.0
            } else {
                0.0
            };
        }

        // Traceroute結果の更新
        if let Some(hops) = update.traceroute_hops {
            self.traceroute_results.insert(update.target.clone(), hops);
        }
    }

    pub fn update_traceroute_result(&mut self, update: TracerouteUpdate) {
        let target = &update.target;

        // 既存のhopデータと新しいhopデータをマージして履歴を更新
        if let Some(existing_hops) = self.traceroute_results.get_mut(target) {
            for new_hop in update.hops {
                // 同じhop_numberの既存hopを探す
                if let Some(existing_hop) = existing_hops
                    .iter_mut()
                    .find(|h| h.hop_number == new_hop.hop_number)
                {
                    // レスポンス時間がある場合のみ履歴を更新
                    if let Some(rtt) = new_hop.response_time {
                        existing_hop.response_time = Some(rtt);
                        existing_hop
                            .latency_history
                            .push(rtt.num_milliseconds() as f64);

                        // 履歴を50個に制限
                        if existing_hop.latency_history.len() > 50 {
                            existing_hop.latency_history.remove(0);
                        }

                        // タイムアウトマーカーを除外して平均を計算
                        let valid_values: Vec<f64> = existing_hop
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
                        existing_hop.avg_response_time = Some(Duration::milliseconds(avg as i64));
                    } else {
                        // タイムアウトの場合はマーカーを追加
                        existing_hop.latency_history.push(TIMEOUT_MARKER);

                        if existing_hop.latency_history.len() > 50 {
                            existing_hop.latency_history.remove(0);
                        }
                    }
                    // addressが新しく取得できた場合は更新
                    if new_hop.address.is_some() {
                        existing_hop.address = new_hop.address;
                    }
                } else {
                    // 新しいhop番号の場合は追加
                    let mut hop = new_hop;
                    if let Some(rtt) = hop.response_time {
                        hop.latency_history = vec![rtt.num_milliseconds() as f64];
                        hop.avg_response_time = Some(rtt);
                    } else {
                        // タイムアウトの場合
                        hop.latency_history = vec![TIMEOUT_MARKER];
                        hop.avg_response_time = None;
                    }
                    existing_hops.push(hop);
                }
            }
            // hop_numberでソート
            existing_hops.sort_by_key(|h| h.hop_number);
        } else {
            // 初回の場合は新規作成
            let mut hops = update.hops;
            for hop in &mut hops {
                if let Some(rtt) = hop.response_time {
                    hop.latency_history = vec![rtt.num_milliseconds() as f64];
                    hop.avg_response_time = Some(rtt);
                } else {
                    // タイムアウトの場合
                    hop.latency_history = vec![TIMEOUT_MARKER];
                    hop.avg_response_time = None;
                }
            }
            self.traceroute_results.insert(target.clone(), hops);
        }
    }

    pub fn get_traceroute_hops(&self, target: &str) -> Vec<TracerouteHop> {
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
