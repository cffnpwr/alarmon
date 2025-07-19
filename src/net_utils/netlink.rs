use std::cmp::Ordering;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tcpip::ethernet::MacAddr;
use tcpip::ip_cidr::IPCIDR;

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

#[derive(Debug, Clone, Copy)]
pub struct IPv6AddressFlags {
    pub deprecated: bool,
    pub temporary: bool,
}

#[derive(Debug, Clone)]
struct IPv6AddressInfo {
    address: Ipv6Addr,
    flags: IPv6AddressFlags,
}

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
        #[cfg(target_os = "linux")]
        if self.linktype == LinkType::Loopback {
            // Linuxかつループバックインターフェースを使用する場合は、ターゲットIPアドレスをそのまま返す
            return Ok(*ping_target);
        }

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

    /// グローバルユニキャストIPv6アドレスの中から最適なソースアドレスを選択
    /// RFC 6724のSource Address Selection規則に基づいて優先順位を決定
    pub fn get_best_source_ipv6(&self, destination: &Ipv6Addr) -> Option<Ipv6Addr> {
        // 1. 全IPv6アドレスのフラグを取得
        let mut candidates: Vec<IPv6AddressInfo> = self
            .ip_addrs
            .iter()
            .filter_map(|cidr| {
                if let IPCIDR::V6(ipv6_cidr) = cidr {
                    let addr = ipv6_cidr.address;
                    let flags = self.get_ipv6_flags(addr).ok()?;
                    Some(IPv6AddressInfo {
                        address: addr,
                        flags,
                    })
                } else {
                    None
                }
            })
            .collect();

        if candidates.is_empty() {
            return None;
        }

        // 2. RFC 6724でソート
        candidates.sort_by(|a, b| self.compare_ipv6(a, b, destination));

        // 3. 先頭を返す
        Some(candidates[0].address)
    }

    fn compare_ipv6(&self, a: &IPv6AddressInfo, b: &IPv6AddressInfo, dest: &Ipv6Addr) -> Ordering {
        // Rule 1: Same address
        if a.address == *dest && b.address != *dest {
            return Ordering::Less;
        }
        if b.address == *dest && a.address != *dest {
            return Ordering::Greater;
        }

        // Rule 3: Avoid deprecated
        match (a.flags.deprecated, b.flags.deprecated) {
            (false, true) => return Ordering::Less,
            (true, false) => return Ordering::Greater,
            _ => {}
        }

        // Rule 7: Prefer temporary
        match (a.flags.temporary, b.flags.temporary) {
            (true, false) => return Ordering::Less,
            (false, true) => return Ordering::Greater,
            _ => {}
        }

        // Rule 8: Longest prefix
        let prefix_a = self.common_prefix_length(&a.address, dest);
        let prefix_b = self.common_prefix_length(&b.address, dest);
        prefix_b.cmp(&prefix_a)
    }

    /// 2つのIPv6アドレス間の共通プレフィックス長を計算
    fn common_prefix_length(&self, addr1: &Ipv6Addr, addr2: &Ipv6Addr) -> u32 {
        let octets1 = addr1.octets();
        let octets2 = addr2.octets();

        let mut common_bits = 0;
        for i in 0..16 {
            let xor = octets1[i] ^ octets2[i];
            if xor == 0 {
                common_bits += 8;
            } else {
                common_bits += xor.leading_zeros();
                break;
            }
        }

        common_bits
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
