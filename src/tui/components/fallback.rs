use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::widgets::{Block, Borders, Paragraph};

pub(crate) fn render_fallback_content(frame: &mut Frame, area: Rect, required_width: u16) {
    let content_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(7),
            Constraint::Fill(1),
        ])
        .split(area);

    let horizontal_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(50),
            Constraint::Fill(1),
        ])
        .split(content_layout[1]);

    let fallback_text = "Screen width insufficient\n\n";
    let instruction_text = "Table display requires at least\n";
    let requirement_text = format!("{} characters width\n\n", required_width);
    let current_text = format!("Current: {} characters\n", area.width);
    let guidance_text = "Please expand terminal size";

    let full_text = format!(
        "{}{}{}{}{}",
        fallback_text, instruction_text, requirement_text, current_text, guidance_text
    );

    let paragraph = Paragraph::new(full_text)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default())
        .alignment(Alignment::Center);

    frame.render_widget(paragraph, horizontal_layout[1]);
}
