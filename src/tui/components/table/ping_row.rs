use ratatui::style::Style;
use ratatui::widgets::{Cell, Row};

use crate::tui::components::table::chart::{
    create_ping_chart_cell, create_sparkline_with_timeouts,
    create_sparkline_with_timeouts_and_width,
};
use crate::tui::models::{PingResult, PingStatus};
use crate::tui::styles::{ERROR_COLOR, SUCCESS_COLOR, SUCCESS_ICON};

/// パケットロス率をフォーマット
fn format_packet_loss(packet_loss: f64) -> String {
    let rounded = (packet_loss * 100.0).round() / 100.0;
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
}

/// レイテンシ値をフォーマット
fn format_latency(latency: Option<chrono::Duration>) -> String {
    if let Some(rtt) = latency {
        format!("{}ms", rtt.num_milliseconds())
    } else {
        "-".to_string()
    }
}

/// 指定したチャート幅でテーブル用のping結果行を作成
pub fn create_ping_row_with_chart_width(
    result: &PingResult,
    chart_width: Option<usize>,
) -> Row<'static> {
    let (status_icon, status_color) = match &result.status {
        PingStatus::Success => (SUCCESS_ICON, SUCCESS_COLOR),
        PingStatus::NetworkError(network_error) => (network_error.icon(), ERROR_COLOR),
    };

    let name_with_status = format!("{} {}", status_icon, result.target);
    let host = result.host.clone();
    let loss = format_packet_loss(result.packet_loss);
    let latency = format_latency(result.response_time);
    let avg = format_latency(result.avg_response_time);

    // 動的幅でチャートを作成
    let chart = if !result.latency_history.is_empty() {
        if let Some(width) = chart_width {
            create_sparkline_with_timeouts_and_width(&result.latency_history, Some(width))
        } else {
            create_sparkline_with_timeouts(&result.latency_history)
        }
    } else {
        match &result.status {
            PingStatus::Success => "-".to_string(),
            PingStatus::NetworkError(_) => "✗".to_string(),
        }
    };

    let chart_cell = create_ping_chart_cell(&chart, &result.status);

    Row::new(vec![
        Cell::from(name_with_status).style(Style::default().fg(status_color)),
        Cell::from(host),
        Cell::from(loss),
        Cell::from(latency),
        Cell::from(avg),
        chart_cell,
    ])
}
