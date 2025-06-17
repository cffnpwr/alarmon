use anyhow::Result;
use tcpip::ethernet::{EtherType, EthernetFrame};
use tcpip::ipv4::IPv4Packet;

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
            eprintln!(
                "Failed to parse Ethernet frame: {}, Frame len: {}",
                e,
                packet.len()
            );
            continue;
        }
        let frame = result.unwrap();
        if frame.ether_type != EtherType::IPv4 {
            continue;
        }

        let result = IPv4Packet::try_from(&frame.payload);
        if let Err(e) = result {
            eprintln!(
                "Failed to parse IPv4 packet: {}, Packet len: {}",
                e,
                frame.payload.len()
            );
            continue;
        }
        let ipv4_packet = result.unwrap();
        println!(
            "Captured IPv4 packet: {} -> {}, Protocol: {}",
            ipv4_packet.src, ipv4_packet.dst, ipv4_packet.protocol
        );
    }

    Ok(())
}
