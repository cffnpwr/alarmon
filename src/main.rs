use color_eyre::Result;
use config::Config;
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
    color_eyre::install()?;

    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;

    let targets: Vec<String> = config.targets.iter().map(|t| t.name.to_string()).collect();

    // UpdateMessage用のチャネルを作成
    let (update_sender, update_receiver) = mpsc::channel::<UpdateMessage>(1000);
    let token = CancellationToken::new();

    // 複数のタスクでconfigを使用するためクローンを作成
    let config_for_ping = config.clone();
    let config_for_tui = config.clone();

    // Ping監視タスクを起動
    let ping_token = token.clone();
    let ping_handle = tokio::spawn(async move {
        if let Err(e) = core::run_ping_monitoring(ping_token, &config_for_ping, update_sender).await
        {
            eprintln!("Ping監視でエラーが発生しました: {e}");
        }
    });

    // TUIタスクを起動
    let tui_handle = tokio::spawn(async move {
        if let Err(e) = tui::run_tui(token.clone(), targets, update_receiver, &config_for_tui).await
        {
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
