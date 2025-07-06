use std::time::Duration;

use crossterm::event::{Event as CrosstermEvent, EventStream, KeyCode, KeyModifiers};
use futures::{FutureExt, StreamExt};
use tokio::sync::mpsc;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;

use crate::tui::models::{AppState, Event};

pub struct EventHandler {
    rx: mpsc::UnboundedReceiver<Event>,
    task: tokio::task::JoinHandle<()>,
}

impl EventHandler {
    pub fn new(tick_rate: Duration, render_rate: Duration) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let token = CancellationToken::new();
        let task = tokio::spawn(async move {
            let mut reader = EventStream::new();
            let mut tick_interval = interval(tick_rate);
            let mut render_interval = interval(render_rate);

            tx.send(Event::Init).unwrap();

            loop {
                tokio::select! {
                    _ = token.cancelled() => {
                        break;
                    }
                    maybe_event = reader.next().fuse() => {
                        match maybe_event {
                            Some(Ok(CrosstermEvent::Key(key))) => {
                                if key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL {
                                    tx.send(Event::Quit).unwrap();
                                } else {
                                    tx.send(Event::Key(key)).unwrap();
                                }
                            }
                            Some(Err(_)) => {
                                tx.send(Event::Error).unwrap();
                            }
                            _ => {}
                        }
                    }
                    _ = tick_interval.tick() => {
                        tx.send(Event::Tick).unwrap();
                    }
                    _ = render_interval.tick() => {
                        tx.send(Event::Render).unwrap();
                    }
                }
            }
        });
        Self { rx, task }
    }

    pub async fn next(&mut self) -> Option<Event> {
        self.rx.recv().await
    }
}

impl Drop for EventHandler {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn handle_key_event(app_state: &mut AppState, key: crossterm::event::KeyEvent) -> bool {
    match key.code {
        // KeyCode::Char('q') => return true, // quit
        KeyCode::Up => app_state.move_up(),
        KeyCode::Down => app_state.move_down(),
        KeyCode::Enter | KeyCode::Char(' ') => app_state.toggle_details(),
        _ => {}
    }
    false // continue
}
