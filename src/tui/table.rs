use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Row};

use crate::tui::models::{PingResult, PingStatus, TracerouteHop};

fn create_sparkline(data: &[u64]) -> String {
    if data.is_empty() {
        return "-".to_string();
    }

    let blocks = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let min_val = *data.iter().min().unwrap_or(&0);
    let max_val = *data.iter().max().unwrap_or(&0);

    if min_val == max_val {
        return blocks[0].to_string().repeat(data.len());
    }

    let range = max_val - min_val;
    let mut sparkline = String::new();

    for &value in data {
        let normalized = ((value - min_val) as f64 / range as f64) * (blocks.len() - 1) as f64;
        let block_index = normalized.round() as usize;
        sparkline.push(blocks[block_index.min(blocks.len() - 1)]);
    }

    sparkline
}

pub fn build_table_rows_data(
    ping_results: &[PingResult],
    selected_index: usize,
    show_details: bool,
    traceroute_hops: &[TracerouteHop],
) -> Vec<Row<'static>> {
    let mut rows: Vec<Row<'static>> = Vec::new();

    for (index, result) in ping_results.iter().enumerate() {
        let (status_icon, status_color) = match &result.status {
            PingStatus::Success => ("✓", Color::Green),
            PingStatus::Timeout => ("⚠", Color::Yellow),
            PingStatus::Error(_) => ("✗", Color::Red),
        };

        let name_with_status = format!("{} {}", status_icon, result.target);
        let host = result.target.clone();
        let loss = if result.packet_loss > 0.0 {
            format!("{}%", result.packet_loss)
        } else {
            "0%".to_string()
        };

        let latency = if let Some(rtt) = result.response_time {
            format!("{}ms", rtt.as_millis())
        } else {
            "-".to_string()
        };

        let avg = if let Some(avg) = result.avg_response_time {
            format!("{}ms", avg.as_millis())
        } else {
            "-".to_string()
        };

        let chart = if !result.latency_history.is_empty() {
            let sparkline_data: Vec<u64> = result
                .latency_history
                .iter()
                .map(|&val| val as u64)
                .collect();

            match &result.status {
                PingStatus::Success => create_sparkline(&sparkline_data),
                PingStatus::Timeout | PingStatus::Error(_) => {
                    format!("✗ {}", create_sparkline(&sparkline_data))
                }
            }
        } else {
            match &result.status {
                PingStatus::Success => "-".to_string(),
                PingStatus::Timeout | PingStatus::Error(_) => "✗".to_string(),
            }
        };

        let chart_cell = if !result.latency_history.is_empty() {
            match &result.status {
                PingStatus::Success => Cell::from(chart).style(Style::default().fg(Color::Green)),
                PingStatus::Timeout | PingStatus::Error(_) => {
                    // ✗部分は赤、チャート部分は緑で分割表示
                    let sparkline_part = create_sparkline(
                        &result
                            .latency_history
                            .iter()
                            .map(|&val| val as u64)
                            .collect::<Vec<_>>(),
                    );
                    let line = Line::from(vec![
                        Span::styled("✗ ", Style::default().fg(Color::Red)),
                        Span::styled(sparkline_part, Style::default().fg(Color::Green)),
                    ]);
                    Cell::from(line)
                }
            }
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
                let rtt_text = if let Some(rtt) = hop.response_time {
                    format!("{}ms", rtt.as_millis())
                } else {
                    "*".to_string()
                };

                rows.push(Row::new(vec![
                    Cell::from(format!("  {:2}. {}", hop.hop_number, hop.address))
                        .style(Style::default().fg(Color::Cyan)),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(rtt_text).style(Style::default().fg(Color::Cyan)),
                    Cell::from(""),
                    Cell::from(""),
                ]));
            }
        }
    }

    rows
}
