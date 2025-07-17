use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tcpip::ethernet::MacAddr;
use tcpip::ip_cidr::IPCIDR;
use tcpip::ipv6::ipv6_address::IPv6AddrExt;

pub use self::common::NetlinkError;
#[cfg(target_os = "linux")]
pub use self::linux::Netlink;
#[cfg(target_os = "macos")]
pub use self::macos::Netlink;

mod common;
#[cfg(target_os = "linux")]
mod linux;
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
    pub fn get_best_source_ip(&self, target_ip: &IpAddr) -> Option<IpAddr> {
        match target_ip {
            IpAddr::V4(ipv4_addr) => self.get_best_source_ipv4(ipv4_addr).map(IpAddr::V4),
            IpAddr::V6(ipv6_addr) => self.get_best_source_ipv6(ipv6_addr).map(IpAddr::V6),
        }
    }

    pub fn get_best_source_ipv4(&self, target_ip: &Ipv4Addr) -> Option<Ipv4Addr> {
        let mut best_match: Option<(Ipv4Addr, u8)> = None;

        for ip_cidr in &self.ip_addrs {
            if let IPCIDR::V4(ipv4_cidr) = ip_cidr {
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
        }

        match best_match {
            Some((ip, _)) => Some(ip),
            None => {
                for ip_cidr in &self.ip_addrs {
                    if let IPCIDR::V4(ipv4_cidr) = ip_cidr {
                        return Some(ipv4_cidr.address);
                    }
                }
                None
            }
        }
    }

    pub fn get_best_source_ipv6(&self, target_ip: &Ipv6Addr) -> Option<Ipv6Addr> {
        let mut best_match: Option<(Ipv6Addr, u8)> = None;

        for ip_cidr in &self.ip_addrs {
            if let IPCIDR::V6(ipv6_cidr) = ip_cidr {
                if ipv6_cidr.contains(target_ip) {
                    let prefix_length = ipv6_cidr.prefix_length;

                    match best_match {
                        None => {
                            best_match = Some((ipv6_cidr.address, prefix_length));
                        }
                        Some((_, current_prefix)) => {
                            if prefix_length > current_prefix {
                                best_match = Some((ipv6_cidr.address, prefix_length));
                            }
                        }
                    }
                }
            }
        }

        match best_match {
            Some((ip, _)) => Some(ip),
            None => {
                for ip_cidr in &self.ip_addrs {
                    if let IPCIDR::V6(ipv6_cidr) = ip_cidr {
                        return Some(ipv6_cidr.address);
                    }
                }
                None
            }
        }
    }

    /// IPv6アドレスの中からルーティングに適した最適なアドレスを選択
    /// RFC 3484のSource Address Selection規則に基づいて優先順位を決定
    pub fn get_preferred_ipv6_address(&self) -> Option<Ipv6Addr> {
        let mut candidates: Vec<Ipv6Addr> = self
            .ip_addrs
            .iter()
            .filter_map(|cidr| {
                if let IPCIDR::V6(ipv6_cidr) = cidr {
                    Some(ipv6_cidr.address)
                } else {
                    None
                }
            })
            .collect();

        if candidates.is_empty() {
            return None;
        }

        // RFC 3484のSource Address Selection規則に基づいて優先順位を決定
        candidates.sort_by(|a, b| {
            self.ipv6_address_priority(a)
                .cmp(&self.ipv6_address_priority(b))
        });

        candidates.into_iter().next()
    }

    /// IPv6アドレスの優先順位を返す（数値が小さいほど優先度が高い）
    fn ipv6_address_priority(&self, addr: &Ipv6Addr) -> u8 {
        // ループバックアドレスは除外
        if addr.is_loopback() {
            return 100;
        }

        // リンクローカルアドレスは最低優先度
        if addr.is_link_local() {
            return 90;
        }

        // グローバルユニキャストアドレスが最優先
        if addr.is_global_unicast() {
            return 1;
        }

        // ユニークローカルアドレスは2番目の優先度
        if addr.is_unique_local() {
            return 2;
        }

        // その他のアドレスは低優先度
        80
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
