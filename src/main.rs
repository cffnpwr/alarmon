use color_eyre::Result;

mod cli;
mod config;
mod core;
mod net_utils;
mod tui;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    tui::run_tui().await
}
