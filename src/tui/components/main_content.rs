use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Cell, Row, Table};

use crate::tui::components::fallback::render_fallback_content;
use crate::tui::components::table::{
    create_ping_row_with_chart_width, create_traceroute_rows_with_chart_width,
};
use crate::tui::models::AppState;
use crate::tui::styles::{
    MIN_CHART_WIDTH, TABLE_AVG_COLUMN_WIDTH, TABLE_HEADER_COLOR, TABLE_HIGHLIGHT_COLOR,
    TABLE_HIGHLIGHT_SYMBOL, TABLE_LATENCY_COLUMN_WIDTH, TABLE_LOSS_COLUMN_WIDTH,
};

pub(crate) fn render_table_content(frame: &mut Frame, app_state: &mut AppState, area: Rect) {
    // 動的な列幅を計算するため最初にデータを抽出
    let ping_results = app_state.get_ping_results_sorted();

    // コンテンツとスクリーンサイズに基づく動的列幅の計算
    let name_width = ping_results
        .iter()
        .map(|result| result.target.chars().count() as u16 + 4u16)
        .max()
        .unwrap_or(4);

    let host_width = ping_results
        .iter()
        .map(|&result| result.host.chars().count() as u16 + 4u16)
        .max()
        .unwrap_or(4);

    // 動的レイアウトに基づく利用可能なチャート幅を計算
    let columns_width = name_width
        + host_width
        + TABLE_LOSS_COLUMN_WIDTH
        + TABLE_LATENCY_COLUMN_WIDTH
        + TABLE_AVG_COLUMN_WIDTH;
    let available_width = area.width.saturating_sub(columns_width);
    // 画面幅が不足している場合はFallback画面を表示
    if available_width < MIN_CHART_WIDTH {
        let required_width = columns_width + MIN_CHART_WIDTH;
        render_fallback_content(frame, area, required_width);
        return;
    }

    let chart_width = std::cmp::max(available_width as usize, MIN_CHART_WIDTH as usize);
    let content_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0)])
        .split(area);

    // UI描画のためアプリ状態データを取得
    let selected_index = app_state.selected_index;
    let show_details = app_state.show_details;

    // 選択されたターゲットのtraceroute結果を取得
    let selected_target = if selected_index < app_state.targets.len() {
        Some(&app_state.targets[selected_index])
    } else {
        None
    };
    let traceroute_hops = if let Some(target) = selected_target {
        app_state.get_traceroute_hops(target)
    } else {
        Vec::new()
    };

    // テーブル行を構築
    let mut rows: Vec<Row<'static>> = Vec::new();

    // 計算されたチャート幅でping結果行を追加
    for (index, result) in ping_results.iter().enumerate() {
        rows.push(create_ping_row_with_chart_width(result, Some(chart_width)));

        // この行が選択されて詳細表示が有効な場合traceroute詳細を追加
        if show_details && index == selected_index {
            let mut traceroute_rows =
                create_traceroute_rows_with_chart_width(&traceroute_hops, Some(chart_width));
            rows.append(&mut traceroute_rows);
        }
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(name_width), // 名前列
            Constraint::Length(host_width), // ホスト列
            Constraint::Length(TABLE_LOSS_COLUMN_WIDTH),
            Constraint::Length(TABLE_LATENCY_COLUMN_WIDTH),
            Constraint::Length(TABLE_AVG_COLUMN_WIDTH),
            Constraint::Fill(1), // チャート列
        ],
    )
    .block(Block::default())
    .header(
        Row::new(vec![
            Cell::from("Name").style(Style::default().add_modifier(Modifier::BOLD)),
            Cell::from("Host").style(Style::default().add_modifier(Modifier::BOLD)),
            Cell::from("Loss").style(Style::default().add_modifier(Modifier::BOLD)),
            Cell::from("Latency").style(Style::default().add_modifier(Modifier::BOLD)),
            Cell::from("Avg").style(Style::default().add_modifier(Modifier::BOLD)),
            Cell::from("Chart").style(Style::default().add_modifier(Modifier::BOLD)),
        ])
        .style(Style::default().fg(TABLE_HEADER_COLOR))
        .bottom_margin(1),
    )
    .row_highlight_style(Style::default().bg(TABLE_HIGHLIGHT_COLOR))
    .highlight_symbol(TABLE_HIGHLIGHT_SYMBOL);

    frame.render_stateful_widget(table, content_layout[0], &mut app_state.table_state);
}
