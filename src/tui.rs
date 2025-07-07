use std::time::Duration;

use color_eyre::Result;
use ratatui::DefaultTerminal;

pub mod events;
pub mod models;
pub mod table;
pub mod ui;

use events::{EventHandler, handle_key_event};
use models::{AppState, Event, UpdateMessage};
use ui::render;

pub async fn run_tui(
    targets: Vec<String>,
    update_receiver: tokio::sync::mpsc::Receiver<UpdateMessage>,
) -> Result<()> {
    let terminal = ratatui::init();
    let result = run(terminal, targets, update_receiver).await;
    ratatui::restore();
    result
}

async fn run(
    mut terminal: DefaultTerminal,
    targets: Vec<String>,
    mut update_receiver: tokio::sync::mpsc::Receiver<UpdateMessage>,
) -> Result<()> {
    let mut events = EventHandler::new(Duration::from_millis(250), Duration::from_millis(16));
    let mut app_state = AppState::new(targets);

    loop {
        tokio::select! {
            Some(event) = events.next() => {
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
            Some(update_message) = update_receiver.recv() => {
                match update_message {
                    UpdateMessage::Ping(ping_update) => {
                        app_state.update_ping_result(ping_update);
                    }
                    UpdateMessage::Traceroute(traceroute_update) => {
                        app_state.update_traceroute_result(traceroute_update);
                    }
                }
            }
        }
    }
    Ok(())
}
