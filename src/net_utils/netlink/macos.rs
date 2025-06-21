use std::collections::HashMap;

use nix::ifaddrs::getifaddrs;
use nix::net::if_::if_nametoindex;
use tcpip::ethernet::MacAddr;
use tcpip::ip_cidr::{IPCIDR, IPv4CIDR, IPv4Netmask};

use super::{NetlinkError, NetworkInterface};

pub(crate) struct Netlink;
impl Netlink {
    pub(crate) fn new() -> Self {
        Netlink
    }

    pub(crate) fn get_interfaces(&self) -> Result<Vec<NetworkInterface>, NetlinkError> {
        let ifaddrs = getifaddrs()?;
        let mut interfaces: HashMap<String, NetworkInterface> = HashMap::new();

        for ifaddr in ifaddrs {
            let iface_name = ifaddr.interface_name.clone();

            // 既存インターフェースを取得または新規作成
            let iface = interfaces.entry(iface_name.clone()).or_insert_with(|| {
                let index = if_nametoindex(iface_name.as_str())
                    .map_err(NetlinkError::FailedToGetIfAddrs)
                    .unwrap_or(0);
                NetworkInterface {
                    index,
                    name: iface_name,
                    mac_addr: MacAddr::default(),
                    ip_addrs: Vec::new(),
                }
            });
            let Some(address) = ifaddr.address else {
                continue;
            };

            // Macアドレスの処理
            if let Some(mac_addr) = address.as_link_addr() {
                if let Some(mac_bytes) = mac_addr.addr() {
                    iface.mac_addr = mac_bytes.into();
                }
                continue;
            }

            // IPv4アドレスの処理
            let Some(ipv4_addr) = address.as_sockaddr_in() else {
                continue;
            };

            let Some(netmask) = ifaddr.netmask else {
                continue;
            };
            let Some(netmask_addr) = netmask.as_sockaddr_in() else {
                continue;
            };
            let Ok(netmask) = IPv4Netmask::try_from(netmask_addr.ip()) else {
                continue;
            };
            let cidr = IPCIDR::V4(IPv4CIDR::new(ipv4_addr.ip(), netmask));
            iface.ip_addrs.push(cidr);
        }

        Ok(interfaces.into_values().collect())
    }
}
