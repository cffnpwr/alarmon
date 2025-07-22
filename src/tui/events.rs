use crossterm::event::{Event as CrosstermEvent, EventStream, KeyCode, KeyEvent, KeyModifiers};
use futures::{FutureExt, StreamExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::tui::models::{AppState, Event};

pub struct EventHandler {
    rx: mpsc::UnboundedReceiver<Event>,
    tx: mpsc::UnboundedSender<Event>,
    task: tokio::task::JoinHandle<()>,
}

impl EventHandler {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let task_tx = tx.clone();
        let token = CancellationToken::new();
        let task = tokio::spawn(async move {
            let mut reader = EventStream::new();

            task_tx.send(Event::Init).unwrap();
            loop {
                tokio::select! {
                    _ = token.cancelled() => {
                        break;
                    }
                    maybe_event = reader.next().fuse() => {
                        match maybe_event {
                            Some(Ok(CrosstermEvent::Key(key))) => {
                                if key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL {
                                    task_tx.send(Event::Quit).unwrap();
                                } else {
                                    task_tx.send(Event::Key(key)).unwrap();
                                }
                            }
                            Some(Err(_)) => {
                                task_tx.send(Event::Error).unwrap();
                            }
                            _ => {}
                        }
                    }
                }
            }
        });
        Self { rx, tx, task }
    }

    pub async fn next(&mut self) -> Option<Event> {
        self.rx.recv().await
    }

    pub fn get_sender(&self) -> mpsc::UnboundedSender<Event> {
        self.tx.clone()
    }
}

impl Drop for EventHandler {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn handle_key_event(
    app_state: &mut AppState,
    key: KeyEvent,
    event_sender: &mpsc::UnboundedSender<Event>,
) {
    match key.code {
        KeyCode::Up => {
            app_state.move_up();
            event_sender.send(Event::Render).unwrap();
        }
        KeyCode::Down => {
            app_state.move_down();
            event_sender.send(Event::Render).unwrap();
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            app_state.toggle_details();
            event_sender.send(Event::Render).unwrap();
        }
        KeyCode::Char('r') | KeyCode::Char('R') => {
            // リフレッシュ機能は現在未実装
        }
        _ => {}
    }
}
