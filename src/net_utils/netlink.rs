use std::net::{IpAddr, Ipv4Addr};

use tcpip::ethernet::MacAddr;
use tcpip::ip_cidr::IPCIDR;

#[cfg(target_os = "macos")]
pub use self::macos::{Netlink, NetlinkError};

#[cfg(target_os = "macos")]
mod macos;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkInterface {
    pub index: u32,
    pub name: String,
    pub mac_addr: MacAddr,
    pub ip_addrs: Vec<IPCIDR>,
    pub linktype: LinkType,
}
impl NetworkInterface {
    pub fn get_best_source_ip(&self, target_ip: &Ipv4Addr) -> Option<Ipv4Addr> {
        let mut best_match: Option<(Ipv4Addr, u8)> = None;

        for ip_cidr in &self.ip_addrs {
            let IPCIDR::V4(ipv4_cidr) = ip_cidr;
            if ipv4_cidr.contains(target_ip) {
                let prefix_length = ipv4_cidr.netmask.prefix_length();

                match best_match {
                    None => {
                        best_match = Some((ipv4_cidr.address, prefix_length));
                    }
                    Some((_, current_prefix)) => {
                        if prefix_length > current_prefix {
                            best_match = Some((ipv4_cidr.address, prefix_length));
                        }
                    }
                }
            }
        }

        match best_match {
            Some((ip, _)) => Some(ip),
            None => {
                if let Some(ip_cidr) = self.ip_addrs.first() {
                    let IPCIDR::V4(ipv4_cidr) = ip_cidr;
                    Some(ipv4_cidr.address)
                } else {
                    None
                }
            }
        }
    }
}
impl From<NetworkInterface> for pcap::NetworkInterface {
    fn from(ni: NetworkInterface) -> Self {
        pcap::NetworkInterface::new(ni.index, ni.name)
    }
}

impl From<&NetworkInterface> for pcap::NetworkInterface {
    fn from(ni: &NetworkInterface) -> Self {
        pcap::NetworkInterface::new(ni.index, ni.name.clone())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Loopback,
    Ethernet,
    RawIP,
}
impl Default for LinkType {
    fn default() -> Self {
        Self::Loopback
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub interface: NetworkInterface,
    pub to: IpAddr,
    pub via: Option<IpAddr>,
}
impl RouteEntry {
    #[allow(dead_code)]
    pub fn new(interface: &NetworkInterface, to: &IpAddr, via: Option<&IpAddr>) -> Self {
        Self {
            interface: interface.clone(),
            to: *to,
            via: via.cloned(),
        }
    }

    #[allow(dead_code)]
    pub fn is_gateway(&self) -> bool {
        self.via.is_some()
    }
}
impl Default for RouteEntry {
    fn default() -> Self {
        Self {
            interface: NetworkInterface::default(),
            to: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            via: None,
        }
    }
}
