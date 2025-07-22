use ratatui::style::Style;
use ratatui::widgets::{Cell, Row};

use crate::tui::components::table::chart::{
    create_sparkline_with_timeouts, create_sparkline_with_timeouts_and_width,
    create_traceroute_chart_cell,
};
use crate::tui::models::TracerouteHopHistory;
use crate::tui::styles::{SELECTED_COLOR, SUCCESS_ICON, TIMEOUT_ICON};

/// 指定したチャート幅でtraceroute詳細行を作成
pub fn create_traceroute_rows_with_chart_width(
    traceroute_hops: &[TracerouteHopHistory],
    chart_width: Option<usize>,
) -> Vec<Row<'static>> {
    let mut rows = Vec::new();

    for hop in traceroute_hops {
        let (address_text, rtt_text, avg_text, hop_chart_cell) = match (hop.address, hop.latency) {
            (Some(addr), Some(rtt)) => {
                let rtt_ms = rtt.num_milliseconds();
                let avg_text = format!("{rtt_ms}ms");

                // 動的幅でtracerouteスパークラインを作成
                let hop_chart = if !hop.latency_history.is_empty() {
                    if let Some(width) = chart_width {
                        create_sparkline_with_timeouts_and_width(&hop.latency_history, Some(width))
                    } else {
                        create_sparkline_with_timeouts(&hop.latency_history)
                    }
                } else {
                    "-".to_string()
                };

                let chart_cell = create_traceroute_chart_cell(&hop_chart);

                (
                    format!("{SUCCESS_ICON} {addr}"),
                    format!("{rtt_ms}ms"),
                    avg_text,
                    chart_cell,
                )
            }
            _ => {
                // 動的幅での通信失敗ケース
                let hop_chart = if !hop.latency_history.is_empty() {
                    if let Some(width) = chart_width {
                        create_sparkline_with_timeouts_and_width(&hop.latency_history, Some(width))
                    } else {
                        create_sparkline_with_timeouts(&hop.latency_history)
                    }
                } else {
                    "-".to_string()
                };

                let chart_cell = create_traceroute_chart_cell(&hop_chart);

                (
                    format!("{TIMEOUT_ICON} *"),
                    "*".to_string(),
                    "*".to_string(),
                    chart_cell,
                )
            }
        };

        rows.push(Row::new(vec![
            Cell::from(format!("  {:2}. {}", hop.hop_number, address_text))
                .style(Style::default().fg(SELECTED_COLOR)),
            Cell::from(""),
            Cell::from(""),
            Cell::from(rtt_text).style(Style::default().fg(SELECTED_COLOR)),
            Cell::from(avg_text).style(Style::default().fg(SELECTED_COLOR)),
            hop_chart_cell,
        ]));
    }

    rows
}
