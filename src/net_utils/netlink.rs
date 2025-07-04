use std::net::{IpAddr, Ipv4Addr};

use tcpip::ethernet::MacAddr;
use tcpip::ip_cidr::IPCIDR;

#[cfg(target_os = "macos")]
pub(crate) use self::macos::{Netlink, NetlinkError};

#[cfg(target_os = "macos")]
mod macos;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct NetworkInterface {
    pub(crate) index: u32,
    pub(crate) name: String,
    pub(crate) mac_addr: MacAddr,
    pub(crate) ip_addrs: Vec<IPCIDR>,
}
impl NetworkInterface {
    pub(crate) fn get_best_source_ip(&self, target_ip: &Ipv4Addr) -> Option<Ipv4Addr> {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LinkType {
    Ethernet,
    RawIP,
}
impl Default for LinkType {
    fn default() -> Self {
        Self::Ethernet
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouteEntry {
    pub(crate) interface: NetworkInterface,
    pub(crate) to: IpAddr,
    pub(crate) via: Option<IpAddr>,
    pub(crate) link_type: LinkType,
}
impl RouteEntry {
    #[allow(dead_code)]
    pub(crate) fn new(
        interface: &NetworkInterface,
        to: &IpAddr,
        via: Option<&IpAddr>,
        link_type: &LinkType,
    ) -> Self {
        Self {
            interface: interface.clone(),
            to: *to,
            via: via.cloned(),
            link_type: link_type.clone(),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn is_gateway(&self) -> bool {
        self.via.is_some()
    }
}
impl Default for RouteEntry {
    fn default() -> Self {
        Self {
            interface: NetworkInterface::default(),
            to: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            via: None,
            link_type: LinkType::default(),
        }
    }
}
