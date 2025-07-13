use anyhow::Result;
use config::Config;
use env_logger::Env;
use log::error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tui::models::UpdateMessage;

use crate::cli::Cli;

mod cli;
mod config;
mod core;
mod net_utils;
mod tui;

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(all(debug_assertions, feature = "tokio-console"))]
    console_subscriber::init();
    env_logger::init_from_env(Env::default().default_filter_or("error"));
    color_eyre::install().map_err(|e| {
        error!("Failed to install color_eyre: {e}");
        anyhow::anyhow!("Failed to install color_eyre")
    })?;

    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;

    // UpdateMessage用のチャネルを作成
    let (update_sender, update_receiver) = mpsc::channel::<UpdateMessage>(1000);
    let token = CancellationToken::new();

    // Ping監視タスクを起動
    let ping_token = token.clone();
    let config_for_ping = config.clone();
    let ping_handle = tokio::spawn(async move {
        if let Err(e) = core::run_ping_monitoring(ping_token, &config_for_ping, update_sender).await
        {
            let err_msg = format!("Error has occurred in ping monitoring: {e}");
            ratatui::restore();
            error!("{err_msg}");
        }
    });

    // TUIタスクを起動
    let config_for_tui = config.clone();
    let tui_handle = tokio::spawn(async move {
        if let Err(e) = tui::run_tui(token.clone(), update_receiver, &config_for_tui).await {
            let err_msg = format!("Error has occurred in TUI: {e}");
            ratatui::restore();
            error!("{err_msg}");
        }
    });

    // どちらかのタスクが終了するまで待機
    tokio::select! {
        _ = ping_handle => {},
        _ = tui_handle => {},
    }

    Ok(())
}
