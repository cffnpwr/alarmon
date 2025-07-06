use std::time::{Duration, Instant};

use ratatui::widgets::TableState;

#[derive(Debug, Clone)]
pub enum Event {
    Init,
    Quit,
    Error,
    Tick,
    Render,
    Key(crossterm::event::KeyEvent),
}

#[derive(Debug, Clone)]
pub struct PingResult {
    pub target: String,
    pub status: PingStatus,
    pub response_time: Option<Duration>,
    pub last_updated: Instant,
    pub packet_loss: f64,
    pub avg_response_time: Option<Duration>,
    pub latency_history: Vec<f64>,
}

#[derive(Debug, Clone)]
pub enum PingStatus {
    Success,
    Timeout,
    Error(String),
}

#[derive(Debug, Clone)]
pub struct TracerouteHop {
    pub hop_number: u8,
    pub address: String,
    pub response_time: Option<Duration>,
}

pub struct AppState {
    pub ping_results: Vec<PingResult>,
    pub selected_index: usize,
    pub traceroute_hops: Vec<TracerouteHop>,
    pub show_details: bool,
    pub table_state: TableState,
}

impl AppState {
    pub fn new() -> Self {
        let ping_results = vec![
            PingResult {
                target: "google.com (8.8.8.8)".to_string(),
                status: PingStatus::Success,
                response_time: Some(Duration::from_millis(12)),
                last_updated: Instant::now(),
                packet_loss: 0.0,
                avg_response_time: Some(Duration::from_millis(15)),
                latency_history: vec![12.0, 15.0, 10.0, 18.0, 14.0, 16.0, 11.0, 13.0],
            },
            PingResult {
                target: "cloudflare.com (1.1.1.1)".to_string(),
                status: PingStatus::Success,
                response_time: Some(Duration::from_millis(8)),
                last_updated: Instant::now(),
                packet_loss: 0.0,
                avg_response_time: Some(Duration::from_millis(9)),
                latency_history: vec![8.0, 9.0, 7.0, 11.0, 8.0, 10.0, 6.0, 9.0],
            },
            PingResult {
                target: "example.com (93.184.216.34)".to_string(),
                status: PingStatus::Timeout,
                response_time: None,
                last_updated: Instant::now(),
                packet_loss: 25.0,
                avg_response_time: Some(Duration::from_millis(45)),
                latency_history: vec![45.0, 50.0, 42.0, 48.0, 44.0, 46.0, 43.0, 47.0],
            },
            PingResult {
                target: "github.com (140.82.121.4)".to_string(),
                status: PingStatus::Success,
                response_time: Some(Duration::from_millis(28)),
                last_updated: Instant::now(),
                packet_loss: 0.0,
                avg_response_time: Some(Duration::from_millis(32)),
                latency_history: vec![28.0, 30.0, 35.0, 32.0, 29.0, 31.0, 33.0, 34.0],
            },
            PingResult {
                target: "unreachable.local".to_string(),
                status: PingStatus::Error("Network unreachable".to_string()),
                response_time: None,
                last_updated: Instant::now(),
                packet_loss: 100.0,
                avg_response_time: None,
                latency_history: vec![],
            },
        ];

        let traceroute_hops = vec![
            TracerouteHop {
                hop_number: 1,
                address: "192.168.1.1".to_string(),
                response_time: Some(Duration::from_millis(1)),
            },
            TracerouteHop {
                hop_number: 2,
                address: "10.0.0.1".to_string(),
                response_time: Some(Duration::from_millis(5)),
            },
            TracerouteHop {
                hop_number: 3,
                address: "203.0.113.1".to_string(),
                response_time: Some(Duration::from_millis(12)),
            },
            TracerouteHop {
                hop_number: 4,
                address: "8.8.8.8".to_string(),
                response_time: Some(Duration::from_millis(15)),
            },
        ];

        let mut table_state = TableState::default();
        table_state.select(Some(0));

        Self {
            ping_results,
            selected_index: 0,
            traceroute_hops,
            show_details: false,
            table_state,
        }
    }

    pub fn move_up(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
            self.table_state.select(Some(self.selected_index));
        }
    }

    pub fn move_down(&mut self) {
        if self.selected_index < self.ping_results.len() - 1 {
            self.selected_index += 1;
            self.table_state.select(Some(self.selected_index));
        }
    }

    pub fn toggle_details(&mut self) {
        self.show_details = !self.show_details;
    }
}
