use anyhow::Result;
use tcpip::ethernet::EthernetFrame;

#[tokio::main]
async fn main() -> Result<()> {
    let ni = pcap::NetworkInterface::find_by_name("en0").expect("Network interface not found");
    let cap = pcap::open(&ni, true).expect("Failed to open network interface");
    let (_, mut receiver) = match cap {
        pcap::Channel::Ethernet(s, r) => (s, r),
    };

    while let Ok(packet) = receiver.recv() {
        let result = EthernetFrame::try_from(packet.as_slice());
        if let Err(e) = result {
            eprintln!("Failed to parse Ethernet frame: {}", e);
            eprintln!("Packet len: {}", packet.len());
            continue;
        }
        let frame = result.unwrap();

        println!(
            "src MAC: {}, dst MAC: {}, EtherType: {}",
            frame.src, frame.dst, frame.ether_type,
        );
    }

    Ok(())
}
