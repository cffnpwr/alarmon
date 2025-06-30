mod arp_resolver;
mod net_utils;
mod ping;

use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use anyhow::Result;
use arp_resolver::ArpResolver;
use ping::Ping;

use crate::net_utils::netlink::{LinkType, Netlink};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("使用方法: {} <IPアドレス>", args[0]);
        eprintln!("例: {} 192.168.1.2", args[0]);
        std::process::exit(1);
    }

    let target_ip = Ipv4Addr::from_str(&args[1])
        .map_err(|_| anyhow::anyhow!("無効なIPアドレス: {}", args[1]))?;

    // まずARPでMACアドレスを解決
    println!("ステップ1: ARPでMACアドレスを解決します...");
    let netlink = Netlink::new()?;
    let route = netlink.get_route(target_ip)?;
    println!("成功: {} のルート情報は {:#?}", target_ip, route);

    if route.link_type == LinkType::RawIP {
        println!("{} はRawIPリンクタイプです。ARPは不要です。", target_ip);
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
    println!("成功: {} のMACアドレスは {} です", arp_target_ip, mac_addr);

    // 次にICMP pingを実行
    println!("\nステップ2: ICMP pingを実行します...");
    match Ping::ping(target_ip, mac_addr, 5).await {
        Ok(duration) => {
            println!("成功: {} からの応答時間 {:?}", target_ip, duration);
        }
        Err(e) => {
            eprintln!("Pingエラー: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
