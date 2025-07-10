use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Row};

use crate::tui::models::{PingResult, PingStatus, TIMEOUT_MARKER, TracerouteHopHistory};

fn create_block_chart(value: f64, min_val: f64, max_val: f64) -> char {
    let blocks = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

    if min_val == max_val {
        return blocks[0];
    }

    let range = max_val - min_val;
    let normalized = ((value - min_val) / range) * (blocks.len() - 1) as f64;
    let block_index = normalized.round() as usize;
    blocks[block_index.min(blocks.len() - 1)]
}

fn create_sparkline_with_timeouts(data: &[f64], max_width: usize) -> String {
    if data.is_empty() {
        return "-".to_string();
    }

    // 利用可能な幅に合わせてデータを調整（最新データを左に表示）
    let display_data: Vec<f64> = if data.len() > max_width {
        data.iter().rev().take(max_width).cloned().collect()
    } else {
        data.iter().rev().cloned().collect()
    };

    // タイムアウト以外の値のみで正規化用の最小値・最大値を計算
    let valid_values: Vec<f64> = display_data
        .iter()
        .filter(|&&v| v != TIMEOUT_MARKER)
        .cloned()
        .collect();

    if valid_values.is_empty() {
        // 全部タイムアウトの場合
        return "✗".repeat(display_data.len());
    }

    let min_val = *valid_values
        .iter()
        .min_by(|a, b| a.partial_cmp(b).unwrap())
        .unwrap_or(&0.0);
    let max_val = *valid_values
        .iter()
        .max_by(|a, b| a.partial_cmp(b).unwrap())
        .unwrap_or(&0.0);

    let mut sparkline = String::new();

    for &value in &display_data {
        if value == TIMEOUT_MARKER {
            sparkline.push('✗');
        } else {
            sparkline.push(create_block_chart(value, min_val, max_val));
        }
    }

    sparkline
}

pub fn build_table_rows_data(
    ping_results: &[PingResult],
    selected_index: usize,
    show_details: bool,
    traceroute_hops: &[TracerouteHopHistory],
    chart_width: usize,
) -> Vec<Row<'static>> {
    let mut rows: Vec<Row<'static>> = Vec::new();

    for (index, result) in ping_results.iter().enumerate() {
        let (status_icon, status_color) = match &result.status {
            PingStatus::Success => ("✓", Color::Green),
            PingStatus::Timeout => ("⚠", Color::Yellow),
            PingStatus::Error(_) => ("✗", Color::Red),
        };

        let name_with_status = format!("{} {}", status_icon, result.target);
        let host = result.host.clone();
        let loss = {
            let rounded = (result.packet_loss * 100.0).round() / 100.0;
            if rounded == 0.0 {
                "0%".to_string()
            } else if rounded == rounded.trunc() {
                format!("{}%", rounded as i32)
            } else {
                format!("{rounded:.2}%")
                    .trim_end_matches('0')
                    .trim_end_matches('.')
                    .to_string()
                    + "%"
            }
        };

        let latency = if let Some(rtt) = result.response_time {
            format!("{}ms", rtt.num_milliseconds())
        } else {
            "-".to_string()
        };

        let avg = if let Some(avg) = result.avg_response_time {
            format!("{}ms", avg.num_milliseconds())
        } else {
            "-".to_string()
        };

        let chart = if !result.latency_history.is_empty() {
            // latency_historyをそのまま使用（タイムアウトマーカーを含む）
            create_sparkline_with_timeouts(&result.latency_history, chart_width)
        } else {
            match &result.status {
                PingStatus::Success => "-".to_string(),
                PingStatus::Timeout | PingStatus::Error(_) => "✗".to_string(),
            }
        };

        let chart_cell = if !result.latency_history.is_empty() {
            // タイムアウトを含むチャートは色分けされたスパンで表示
            let mut spans = Vec::new();
            let chart_chars: Vec<char> = chart.chars().collect();

            for ch in chart_chars {
                if ch == '✗' {
                    spans.push(Span::styled(
                        ch.to_string(),
                        Style::default().fg(Color::Red),
                    ));
                } else {
                    spans.push(Span::styled(
                        ch.to_string(),
                        Style::default().fg(Color::Green),
                    ));
                }
            }

            Cell::from(Line::from(spans))
        } else {
            match &result.status {
                PingStatus::Success => Cell::from(chart).style(Style::default().fg(Color::Green)),
                PingStatus::Timeout | PingStatus::Error(_) => {
                    Cell::from(chart).style(Style::default().fg(Color::Red))
                }
            }
        };

        // Add main ping result row
        rows.push(Row::new(vec![
            Cell::from(name_with_status).style(Style::default().fg(status_color)),
            Cell::from(host),
            Cell::from(loss),
            Cell::from(latency),
            Cell::from(avg),
            chart_cell,
        ]));

        // Add traceroute details if this row is selected and details are shown
        if show_details && index == selected_index {
            for hop in traceroute_hops {
                let (address_text, rtt_text, avg_text, hop_chart_cell) =
                    match (hop.address, hop.latency) {
                        (Some(addr), Some(rtt)) => {
                            let rtt_ms = rtt.num_milliseconds();
                            let avg_text = format!("{rtt_ms}ms");

                            // Tracerouteのsparklineを作成
                            let hop_chart = if !hop.latency_history.is_empty() {
                                create_sparkline_with_timeouts(&hop.latency_history, chart_width)
                            } else {
                                "-".to_string()
                            };

                            // Tracerouteチャートセルを色分けして作成
                            let chart_cell = if !hop.latency_history.is_empty() {
                                let mut spans = Vec::new();
                                let chart_chars: Vec<char> = hop_chart.chars().collect();

                                for ch in chart_chars {
                                    if ch == '✗' {
                                        spans.push(Span::styled(
                                            ch.to_string(),
                                            Style::default().fg(Color::Red),
                                        ));
                                    } else {
                                        spans.push(Span::styled(
                                            ch.to_string(),
                                            Style::default().fg(Color::Blue),
                                        ));
                                    }
                                }

                                Cell::from(Line::from(spans))
                            } else {
                                Cell::from("-").style(Style::default().fg(Color::Gray))
                            };

                            (
                                addr.to_string(),
                                format!("{rtt_ms}ms"),
                                avg_text,
                                chart_cell,
                            )
                        }
                        _ => (
                            "*".to_string(),
                            "*".to_string(),
                            "*".to_string(),
                            Cell::from("*").style(Style::default().fg(Color::Red)),
                        ),
                    };

                rows.push(Row::new(vec![
                    Cell::from(format!("  {:2}. {}", hop.hop_number, address_text))
                        .style(Style::default().fg(Color::Cyan)),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(rtt_text).style(Style::default().fg(Color::Cyan)),
                    Cell::from(avg_text).style(Style::default().fg(Color::Cyan)),
                    hop_chart_cell,
                ]));
            }
        }
    }

    rows
}
