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
