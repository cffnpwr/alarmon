use color_eyre::Result;
use ratatui::DefaultTerminal;

pub mod events;
pub mod models;
pub mod table;
pub mod ui;

use events::{EventHandler, handle_key_event};
use models::{AppState, Event, UpdateMessage};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use ui::render;

pub async fn run_tui(
    token: CancellationToken,
    targets: Vec<String>,
    update_receiver: mpsc::Receiver<UpdateMessage>,
    config: &crate::config::Config,
) -> Result<()> {
    let terminal = ratatui::init();
    let result = run(token, terminal, targets, update_receiver, config).await;
    ratatui::restore();
    result
}

async fn run(
    token: CancellationToken,
    mut terminal: DefaultTerminal,
    targets: Vec<String>,
    mut update_receiver: mpsc::Receiver<UpdateMessage>,
    config: &crate::config::Config,
) -> Result<()> {
    let mut events = EventHandler::new();
    let event_sender = events.get_sender();
    let mut app_state = AppState::new(targets, config);

    loop {
        tokio::select! {
            Some(event) = events.next() => {
                match event {
                    Event::Quit => {
                        token.cancel();
                        break;
                    },
                    Event::Render => {
                        terminal.draw(|frame| render(frame, &mut app_state))?;
                    },
                    Event::Key(key) => handle_key_event(&mut app_state, key, &event_sender),
                    _ => {}
                }
            }
            Some(update_message) = update_receiver.recv() => {
                match update_message {
                    UpdateMessage::Ping(ping_update) => {
                        app_state.update_ping_result(ping_update);
                        event_sender.send(Event::Render).unwrap();
                    }
                    UpdateMessage::Traceroute(traceroute_update) => {
                        app_state.update_traceroute_result(traceroute_update);
                        event_sender.send(Event::Render).unwrap();
                    }
                }
            }
        }
    }
    Ok(())
}
