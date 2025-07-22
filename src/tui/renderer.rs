use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};

use crate::tui::components::{footer, header, main_content};
use crate::tui::models::AppState;
use crate::tui::styles::{FOOTER_HEIGHT, HEADER_HEIGHT, PADDING_HEIGHT};

/// 全UIコンポーネントを統制するメインレンダー関数
pub(crate) fn render(frame: &mut Frame, app_state: &mut AppState) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(HEADER_HEIGHT),  // ヘッダー
            Constraint::Length(PADDING_HEIGHT), // パディング
            Constraint::Min(0),                 // メインコンテンツ
            Constraint::Length(FOOTER_HEIGHT),  // フッター
        ])
        .split(frame.area());

    // 各コンポーネントを指定されたエリアにレンダリング
    header::render_header_content(frame, main_layout[0]);
    main_content::render_table_content(frame, app_state, main_layout[2]);
    footer::render_footer_in_area(frame, app_state, main_layout[3]);
}
