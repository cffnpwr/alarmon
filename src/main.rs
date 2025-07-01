use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use anyhow::Result;
use arp_resolver::ArpResolver;
use env_logger::Env;
use ping::Ping;

use crate::cli::Cli;
use crate::config::Config;
use crate::net_utils::netlink::{LinkType, Netlink};

mod arp_resolver;
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

    // まずARPでMACアドレスを解決
    println!("ステップ1: ARPでMACアドレスを解決します...");
    let netlink = Netlink::new()?;
    let route = netlink.get_route(target_ip)?;
    println!("成功: {target_ip} のルート情報は {route:#?}");

    if route.link_type == LinkType::RawIP {
        println!("{target_ip} はRawIPリンクタイプです。ARPは不要です。");
        return Ok(());
    }

    println!(
        "{} はEthernetリンクタイプです。ARPを実行します。",
        route.via.expect("ルート情報にviaがありません")
    );
    let IpAddr::V4(arp_target_ip) = route.via.expect("ルート情報にviaがありません")
    else {
        return Err(anyhow::anyhow!(
            "ルート情報のIPアドレスがIPv4ではありません"
        ));
    };

    let mac_addr = ArpResolver::resolve(arp_target_ip).await?;
    println!("成功: {arp_target_ip} のMACアドレスは {mac_addr} です");

    // 次にICMP pingを実行
    println!("\nステップ2: ICMP pingを実行します...");
    match Ping::ping(target_ip, mac_addr, 5).await {
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
