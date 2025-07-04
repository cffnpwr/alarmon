use std::net::Ipv4Addr;
use std::str::FromStr;

use anyhow::Result;
use env_logger::Env;

use crate::cli::Cli;
use crate::config::Config;
use crate::net_utils::netlink::{LinkType, Netlink};
use crate::ping::Ping;

mod cli;
mod config;
mod net_utils;
mod ping;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    let cli = Cli::parse();
    let cfg = Config::load(&cli.config)?;
    dbg!(&cfg);

    let target_ip = Ipv4Addr::from_str(&cfg.targets[0].host)
        .map_err(|_| anyhow::anyhow!("無効なIPアドレス: {}", cfg.targets[0].host))?;

    // Pingを初期化
    let ping = Ping::new(&cfg.arp);

    // リンクタイプを確認
    println!("ステップ1: ルート情報を確認します...");
    let netlink = Netlink::new()?;
    let route = netlink.get_route(target_ip)?;
    println!("成功: {target_ip} のルート情報は {route:#?}");

    if route.link_type == LinkType::RawIP {
        println!("{target_ip} はRawIPリンクタイプです。pingのみ実行します。");
        // RawIPの場合もpingは実行可能（ARPは内部で自動処理）
    } else {
        println!("{target_ip} はEthernetリンクタイプです。ARP解決を含むpingを実行します。");
    }

    // ICMP pingを実行（ARP解決は自動で行われる）
    println!("\nステップ2: ICMP pingを実行します...");
    match ping.ping(target_ip, 5).await {
        Ok(duration) => {
            println!("成功: {target_ip} からの応答時間 {duration:?}");
        }
        Err(e) => {
            eprintln!("Pingエラー: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}
