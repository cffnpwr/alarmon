use color_eyre::Result;
use tokio::sync::mpsc;

mod cli;
mod config;
mod core;
mod net_utils;
mod tui;

use config::Config;
use tui::models::UpdateMessage;

use crate::cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;

    let targets: Vec<String> = config
        .targets
        .iter()
        .map(|t| format!("{} ({})", t.name, t.host))
        .collect();

    // UpdateMessage用のチャネルを作成
    let (update_sender, update_receiver) = mpsc::channel::<UpdateMessage>(1000);

    // Ping監視タスクを起動
    let ping_handle = tokio::spawn(async move {
        if let Err(e) = core::run_ping_monitoring_with_tui(config, update_sender).await {
            eprintln!("Ping監視でエラーが発生しました: {e}");
        }
    });

    // TUIタスクを起動
    let tui_handle = tokio::spawn(async move {
        if let Err(e) = tui::run_tui(targets, update_receiver).await {
            eprintln!("TUIでエラーが発生しました: {e}");
        }
    });

    // どちらかのタスクが終了するまで待機
    tokio::select! {
        _ = ping_handle => {},
        _ = tui_handle => {},
    }

    Ok(())
}
