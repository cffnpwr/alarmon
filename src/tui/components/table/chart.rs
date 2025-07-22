use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Cell;

use crate::tui::models::PingStatus;
use crate::tui::styles::{
    ERROR_COLOR, ERROR_ICON, ERROR_MARKER, PING_ERROR_COLOR, SUCCESS_COLOR, TRACEROUTE_COLOR,
    TRACEROUTE_ERROR_COLOR,
};

/// min-max範囲内の値に基づいてブロックチャート文字を作成
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

/// タイムアウトマーカーをサポートするスパークラインを作成、利用可能幅に最適化
pub fn create_sparkline_with_timeouts(data: &[f64]) -> String {
    create_sparkline_with_timeouts_and_width(data, None)
}

/// タイムアウトマーカーとカスタム幅をサポートするスパークラインを作成
pub fn create_sparkline_with_timeouts_and_width(data: &[f64], max_width: Option<usize>) -> String {
    if data.is_empty() {
        return "-".to_string();
    }

    // 利用可能なデータを使用、max_widthが指定されている場合は制限
    let display_data: Vec<f64> = if let Some(width) = max_width {
        // 最新のデータポイントをmax_widthまで取得
        data.iter().rev().take(width).cloned().collect()
    } else {
        // 利用可能なすべてのデータを使用（既存の動作）
        data.iter().rev().cloned().collect()
    };

    // タイムアウト値以外からmin/maxを計算
    let valid_values: Vec<f64> = display_data
        .iter()
        .filter(|&&v| v != ERROR_MARKER)
        .cloned()
        .collect();

    if valid_values.is_empty() {
        // すべてタイムアウトの場合
        return ERROR_ICON
            .chars()
            .cycle()
            .take(display_data.len())
            .collect();
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
        if value == ERROR_MARKER {
            sparkline.push_str(ERROR_ICON);
        } else {
            sparkline.push(create_block_chart(value, min_val, max_val));
        }
    }

    sparkline
}

/// ping結果用の色付きチャートセルを作成
pub fn create_ping_chart_cell(chart: &str, status: &PingStatus) -> Cell<'static> {
    if chart == "-" || chart == "✗" {
        // シンプルなテキストチャート
        match status {
            PingStatus::Success => {
                Cell::from(chart.to_string()).style(Style::default().fg(SUCCESS_COLOR))
            }
            PingStatus::NetworkError(_) => {
                Cell::from(chart.to_string()).style(Style::default().fg(PING_ERROR_COLOR))
            }
        }
    } else {
        // エラーマーカー付きの複雑なチャート
        let mut spans = Vec::new();
        let chart_chars: Vec<char> = chart.chars().collect();

        for ch in chart_chars {
            if ch == ERROR_ICON.chars().next().unwrap() {
                spans.push(Span::styled(
                    ch.to_string(),
                    Style::default().fg(ERROR_COLOR),
                ));
            } else {
                let color = match status {
                    PingStatus::Success => SUCCESS_COLOR,
                    PingStatus::NetworkError(_) => PING_ERROR_COLOR,
                };
                spans.push(Span::styled(ch.to_string(), Style::default().fg(color)));
            }
        }

        Cell::from(Line::from(spans))
    }
}

/// traceroute結果用の色付きチャートセルを作成
pub fn create_traceroute_chart_cell(chart: &str) -> Cell<'static> {
    if chart == "-" {
        return Cell::from("-").style(Style::default().fg(crate::tui::styles::MUTED_COLOR));
    }

    let mut spans = Vec::new();
    let chart_chars: Vec<char> = chart.chars().collect();

    for ch in chart_chars {
        if ch == ERROR_ICON.chars().next().unwrap() {
            spans.push(Span::styled(
                ch.to_string(),
                Style::default().fg(TRACEROUTE_ERROR_COLOR),
            ));
        } else {
            spans.push(Span::styled(
                ch.to_string(),
                Style::default().fg(TRACEROUTE_COLOR),
            ));
        }
    }

    Cell::from(Line::from(spans))
}
