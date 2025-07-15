use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::u128;

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IPCIDR {
    V4(IPv4CIDR),
    V6(IPv6CIDR),
}
impl Display for IPCIDR {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IPCIDR::V4(cidr) => write!(f, "{cidr}"),
            IPCIDR::V6(cidr) => write!(f, "{cidr}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum IPv4NetmaskError {
    #[error("Invalid prefix length. Must be between 0 and 32, but got {0}")]
    InvalidPrefixLength(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IPv4Netmask(u8);
impl IPv4Netmask {
    pub const fn prefix_length(self) -> u8 {
        self.0
    }

    fn into_address(self) -> Ipv4Addr {
        let mask = 0xFFFFFFFFu32 << (32 - self.0);
        Ipv4Addr::from(mask.to_be_bytes())
    }

    fn try_from_prefix_length(prefix_length: &u8) -> Result<Self, IPv4NetmaskError> {
        if *prefix_length > 32 {
            Err(IPv4NetmaskError::InvalidPrefixLength(*prefix_length))
        } else {
            Ok(IPv4Netmask(*prefix_length))
        }
    }

    fn try_from_ipv4_addr(addr: &Ipv4Addr) -> Result<Self, IPv4NetmaskError> {
        let mask = !u32::from_be_bytes(addr.octets());
        let prefix_length = mask.leading_zeros() as u8;
        if prefix_length > 32 {
            Err(IPv4NetmaskError::InvalidPrefixLength(prefix_length))
        } else {
            Ok(IPv4Netmask(prefix_length))
        }
    }
}
impl Display for IPv4Netmask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.into_address())
    }
}
impl TryFrom<Ipv4Addr> for IPv4Netmask {
    type Error = IPv4NetmaskError;

    fn try_from(addr: Ipv4Addr) -> Result<Self, Self::Error> {
        IPv4Netmask::try_from_ipv4_addr(&addr)
    }
}
impl TryFrom<&Ipv4Addr> for IPv4Netmask {
    type Error = IPv4NetmaskError;

    fn try_from(addr: &Ipv4Addr) -> Result<Self, Self::Error> {
        IPv4Netmask::try_from_ipv4_addr(addr)
    }
}
impl From<IPv4Netmask> for Ipv4Addr {
    fn from(netmask: IPv4Netmask) -> Self {
        netmask.into_address()
    }
}
impl From<&IPv4Netmask> for Ipv4Addr {
    fn from(netmask: &IPv4Netmask) -> Self {
        netmask.into_address()
    }
}
impl TryFrom<u8> for IPv4Netmask {
    type Error = IPv4NetmaskError;

    fn try_from(prefix_length: u8) -> Result<Self, Self::Error> {
        IPv4Netmask::try_from_prefix_length(&prefix_length)
    }
}
impl TryFrom<&u8> for IPv4Netmask {
    type Error = IPv4NetmaskError;

    fn try_from(prefix_length: &u8) -> Result<Self, Self::Error> {
        IPv4Netmask::try_from_prefix_length(prefix_length)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum IPv4CIDRError {
    #[error(transparent)]
    InvalidNetmask(#[from] IPv4NetmaskError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IPv4CIDR {
    pub address: Ipv4Addr,
    pub netmask: IPv4Netmask,
}
impl IPv4CIDR {
    pub fn new(address: impl Into<Ipv4Addr>, netmask: impl Into<IPv4Netmask>) -> Self {
        IPv4CIDR {
            address: address.into(),
            netmask: netmask.into(),
        }
    }

    pub fn new_with_prefix_length(
        address: impl Into<Ipv4Addr>,
        prefix_length: &u8,
    ) -> Result<Self, IPv4NetmaskError> {
        let netmask = IPv4Netmask::try_from(prefix_length)?;
        Ok(IPv4CIDR {
            address: address.into(),
            netmask,
        })
    }

    pub fn contains(&self, ip: &Ipv4Addr) -> bool {
        let network_mask = self.netmask.into_address();
        let network_addr = Ipv4Addr::from(u32::from(self.address) & u32::from(network_mask));
        let target_network_addr = Ipv4Addr::from(u32::from(*ip) & u32::from(network_mask));
        network_addr == target_network_addr
    }
}
impl Default for IPv4CIDR {
    fn default() -> Self {
        IPv4CIDR {
            address: Ipv4Addr::UNSPECIFIED,
            netmask: IPv4Netmask::default(),
        }
    }
}
impl Display for IPv4CIDR {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.netmask.prefix_length())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum IPv6CIDRError {
    #[error("Invalid prefix length. Must be between 0 and 128, but got {0}")]
    InvalidPrefixLength(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IPv6CIDR {
    pub address: Ipv6Addr,
    pub prefix_length: u8,
}
impl IPv6CIDR {
    pub fn new(address: Ipv6Addr, prefix_length: u8) -> Result<Self, IPv6CIDRError> {
        if prefix_length > 128 {
            return Err(IPv6CIDRError::InvalidPrefixLength(prefix_length));
        }
        Ok(IPv6CIDR {
            address,
            prefix_length,
        })
    }

    pub fn contains(&self, ip: &Ipv6Addr) -> bool {
        let mask = (u128::MAX << (128 - self.prefix_length)) as u128;
        let network_addr = u128::from(self.address) & mask;
        let target_network_addr = u128::from(*ip) & mask;
        network_addr == target_network_addr
    }
}
impl Default for IPv6CIDR {
    fn default() -> Self {
        IPv6CIDR {
            address: Ipv6Addr::UNSPECIFIED,
            prefix_length: 0,
        }
    }
}
impl Display for IPv6CIDR {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_length)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_ipv4_netmask_prefix_length() {
        // [正常系] プレフィックス長の取得
        let netmask = IPv4Netmask(24);
        assert_eq!(netmask.prefix_length(), 24);
    }

    #[test]
    fn test_ipv4_netmask_into_address() {
        // [正常系] IPv4Addrへの変換
        let netmask = IPv4Netmask(24);
        let addr = netmask.into_address();
        assert_eq!(addr, Ipv4Addr::new(255, 255, 255, 0));

        let netmask = IPv4Netmask(16);
        let addr = netmask.into_address();
        assert_eq!(addr, Ipv4Addr::new(255, 255, 0, 0));
    }

    #[test]
    fn test_ipv4_netmask_try_from_prefix_length_invalid() {
        // [異常系] 不正なプレフィックス長
        let result = IPv4Netmask::try_from(33u8);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv4_netmask_try_from_ipv4_addr() {
        // [正常系] IPv4Addrからの変換
        let addr = Ipv4Addr::new(255, 255, 255, 0);
        let netmask = IPv4Netmask::try_from(addr).unwrap();
        assert_eq!(netmask.prefix_length(), 24);
    }

    #[test]
    fn test_ipv4_cidr_new_with_prefix_length() {
        // [正常系] 正常なプレフィックス長
        let addr = Ipv4Addr::new(192, 168, 1, 0);
        let cidr = IPv4CIDR::new_with_prefix_length(addr, &24).unwrap();
        assert_eq!(cidr.address, addr);
        assert_eq!(cidr.netmask.prefix_length(), 24);
    }

    #[test]
    fn test_ipv4_cidr_new_with_prefix_length_invalid() {
        // [異常系] 不正なプレフィックス長
        let addr = Ipv4Addr::new(10, 0, 0, 0);
        let result = IPv4CIDR::new_with_prefix_length(addr, &33);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv4_cidr_display() {
        // [正常系] 表示形式
        let cidr = IPv4CIDR::new(Ipv4Addr::new(192, 168, 1, 0), IPv4Netmask(24));
        assert_eq!(format!("{}", cidr), "192.168.1.0/24");
    }

    #[test]
    fn test_ipv4_cidr_contains() {
        // [正常系] 同じネットワーク内のIPアドレス
        let cidr = IPv4CIDR::new(Ipv4Addr::new(192, 168, 1, 0), IPv4Netmask(24));
        assert!(cidr.contains(&Ipv4Addr::new(192, 168, 1, 100)));
        assert!(cidr.contains(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(cidr.contains(&Ipv4Addr::new(192, 168, 1, 255)));

        // [異常系] 異なるネットワークのIPアドレス
        assert!(!cidr.contains(&Ipv4Addr::new(192, 168, 2, 100)));
        assert!(!cidr.contains(&Ipv4Addr::new(10, 0, 0, 1)));
    }
}
