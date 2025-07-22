use ratatui::Frame;
// エリアベースレンダリングではLayoutのインポートは不要
use ratatui::style::Style;
use ratatui::widgets::{Block, Paragraph};

use crate::tui::models::AppState;
use crate::tui::styles::{FOOTER_COLOR, FOOTER_TEXT_HIDE, FOOTER_TEXT_SHOW};

pub fn render_footer_in_area(frame: &mut Frame, app_state: &AppState, area: ratatui::layout::Rect) {
    render_footer_content(frame, app_state, area);
}

fn render_footer_content(frame: &mut Frame, app_state: &AppState, area: ratatui::layout::Rect) {
    let footer_text = if app_state.show_details {
        FOOTER_TEXT_HIDE
    } else {
        FOOTER_TEXT_SHOW
    };

    let footer = Paragraph::new(footer_text)
        .style(Style::default().fg(FOOTER_COLOR))
        .block(Block::default());
    frame.render_widget(footer, area);
}
