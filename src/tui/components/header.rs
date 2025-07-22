use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};

use crate::tui::styles::{APP_TITLE, HEADER_COLOR};

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) fn render_header_content(frame: &mut Frame, area: Rect) {
    let version_text = format!("v{VERSION}");

    // 中央寄せのためのパディング計算
    let total_width = area.width as usize;
    let title_len = APP_TITLE.len();
    let version_len = version_text.len();

    // タイトルを中央寄せ
    let title_padding = (total_width.saturating_sub(title_len)) / 2;

    // バージョン表示の残りスペース計算
    let remaining_space = total_width.saturating_sub(title_padding + title_len + version_len);

    let line = Line::from(vec![
        Span::raw(" ".repeat(title_padding)),
        Span::styled(
            APP_TITLE,
            Style::default()
                .fg(HEADER_COLOR)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" ".repeat(remaining_space)),
        Span::raw(version_text),
    ]);

    let header = Paragraph::new(line).block(Block::default());
    frame.render_widget(header, area);
}
