use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};

use crate::tui::models::{AppState, PingResult};
use crate::tui::table::build_table_rows_data;

pub fn render(frame: &mut Frame, app_state: &mut AppState) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Header
            Constraint::Length(1), // Padding
            Constraint::Min(8),    // Main content
            Constraint::Length(3), // Footer
        ])
        .split(frame.area());

    render_header(frame, main_layout[0]);
    // main_layout[1] is padding space
    render_main_content(frame, app_state, main_layout[2]);
    render_footer(frame, app_state, main_layout[3]);
}

fn render_header(frame: &mut Frame, area: ratatui::layout::Rect) {
    const VERSION: &str = env!("CARGO_PKG_VERSION");

    let title = "Alarmon - Alive and Route Monitoring Tool";
    let version_text = format!("v{VERSION}");

    // Calculate padding for center alignment
    let total_width = area.width as usize;
    let title_len = title.len();
    let version_len = version_text.len();

    // Center the title
    let title_padding = (total_width.saturating_sub(title_len)) / 2;

    // Calculate remaining space for version alignment
    let remaining_space = total_width.saturating_sub(title_padding + title_len + version_len);

    let line = Line::from(vec![
        Span::raw(" ".repeat(title_padding)),
        Span::styled(
            title,
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" ".repeat(remaining_space)),
        Span::raw(version_text),
    ]);

    let header = Paragraph::new(line).block(Block::default());
    frame.render_widget(header, area);
}

fn render_main_content(frame: &mut Frame, app_state: &mut AppState, area: ratatui::layout::Rect) {
    use ratatui::widgets::Table;

    let content_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0)])
        .split(area);

    // Extract data first to avoid borrowing conflicts
    let ping_results = app_state.get_ping_results_sorted();
    let selected_index = app_state.selected_index;
    let show_details = app_state.show_details;

    // 選択されたターゲットのTraceroute結果を取得
    let selected_target = if selected_index < app_state.targets.len() {
        &app_state.targets[selected_index]
    } else {
        ""
    };
    let traceroute_hops = app_state.get_traceroute_hops(selected_target);

    let ping_results_slice: Vec<PingResult> = ping_results.into_iter().cloned().collect();

    // チャート幅を画面幅の30%として計算（最小20文字）
    let chart_width = ((area.width as f32 * 0.30) as usize).max(20);

    let rows = build_table_rows_data(
        &ping_results_slice,
        selected_index,
        show_details,
        &traceroute_hops,
        chart_width,
    );

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(35), // Name column - 可変幅でフル表示
            Constraint::Percentage(15), // Host column
            Constraint::Length(6),      // Loss column - 最小固定
            Constraint::Length(8),      // Latency column - 最小固定
            Constraint::Length(8),      // Avg column - 最小固定
            Constraint::Percentage(30), // Chart column - 可変幅で拡張
        ],
    )
    .block(Block::default())
    .header(
        ratatui::widgets::Row::new(vec![
            ratatui::widgets::Cell::from("Name")
                .style(Style::default().add_modifier(ratatui::style::Modifier::BOLD)),
            ratatui::widgets::Cell::from("Host")
                .style(Style::default().add_modifier(ratatui::style::Modifier::BOLD)),
            ratatui::widgets::Cell::from("Loss")
                .style(Style::default().add_modifier(ratatui::style::Modifier::BOLD)),
            ratatui::widgets::Cell::from("Latency")
                .style(Style::default().add_modifier(ratatui::style::Modifier::BOLD)),
            ratatui::widgets::Cell::from("Avg")
                .style(Style::default().add_modifier(ratatui::style::Modifier::BOLD)),
            ratatui::widgets::Cell::from("Chart")
                .style(Style::default().add_modifier(ratatui::style::Modifier::BOLD)),
        ])
        .style(Style::default().fg(Color::Yellow))
        .bottom_margin(1),
    )
    .row_highlight_style(Style::default().bg(Color::DarkGray))
    .highlight_symbol("► ");

    frame.render_stateful_widget(table, content_layout[0], &mut app_state.table_state);
}

fn render_footer(frame: &mut Frame, app_state: &AppState, area: ratatui::layout::Rect) {
    let footer_text = if app_state.show_details {
        "Press Ctrl-C to quit | ↑/↓: Navigate | Enter/Space: Hide details"
    } else {
        "Press Ctrl-C to quit | ↑/↓: Navigate | Enter/Space: Show details"
    };

    let footer = Paragraph::new(footer_text)
        .style(Style::default().fg(Color::Gray))
        .block(Block::default());
    frame.render_widget(footer, area);
}
