use std::time::Duration;

use color_eyre::Result;
use ratatui::DefaultTerminal;

pub mod events;
pub mod models;
pub mod table;
pub mod ui;

use events::{EventHandler, handle_key_event};
use models::{AppState, Event};
use ui::render;

pub async fn run_tui() -> Result<()> {
    let terminal = ratatui::init();
    let result = run(terminal).await;
    ratatui::restore();
    result
}

async fn run(mut terminal: DefaultTerminal) -> Result<()> {
    let mut events = EventHandler::new(Duration::from_millis(250), Duration::from_millis(16));
    let mut app_state = AppState::new();

    loop {
        if let Some(event) = events.next().await {
            match event {
                Event::Quit => break,
                Event::Render => {
                    terminal.draw(|frame| render(frame, &mut app_state))?;
                }
                Event::Key(key) => {
                    if handle_key_event(&mut app_state, key) {
                        break; // quit requested
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}
