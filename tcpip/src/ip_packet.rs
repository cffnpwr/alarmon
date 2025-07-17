use bytes::Bytes;
use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;
pub use crate::ipv4::{IPv4Error, IPv4Packet};
pub use crate::ipv6::{IPv6Error, IPv6Packet};

#[derive(Debug, Error)]
pub enum IPPacketError {
    #[error(
        "Invalid packet length. Expected at least 20 bytes for IPv4 or 40 bytes for IPv6, but got {0} bytes."
    )]
    InvalidPacketLength(usize),
    #[error("Invalid IP version. IP version must be 4 or 6, but got {0}")]
    InvalidVersion(u8),
    #[error(transparent)]
    IPv4Error(#[from] IPv4Error),
    #[error(transparent)]
    IPv6Error(#[from] IPv6Error),
}

#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = IPPacketError, types = [&[u8], Vec<u8>, Box<[u8]>, Bytes])]
pub enum IPPacket {
    V4(IPv4Packet),
    V6(IPv6Packet),
}

impl TryFromBytes for IPPacket {
    type Error = IPPacketError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();
        if bytes.is_empty() {
            return Err(IPPacketError::InvalidPacketLength(0));
        }

        let version = bytes[0] >> 4;
        match version {
            4 => Ok(IPPacket::V4(IPv4Packet::try_from_bytes(bytes)?)),
            6 => Ok(IPPacket::V6(IPv6Packet::try_from_bytes(bytes)?)),
            _ => Err(IPPacketError::InvalidVersion(version)),
        }
    }
}

impl From<IPPacket> for Bytes {
    fn from(packet: IPPacket) -> Self {
        (&packet).into()
    }
}

impl From<&IPPacket> for Bytes {
    fn from(packet: &IPPacket) -> Self {
        match packet {
            IPPacket::V4(ipv4) => ipv4.into(),
            IPPacket::V6(ipv6) => ipv6.into(),
        }
    }
}

impl From<IPPacket> for Vec<u8> {
    fn from(packet: IPPacket) -> Self {
        Bytes::from(packet).to_vec()
    }
}

impl From<&IPPacket> for Vec<u8> {
    fn from(packet: &IPPacket) -> Self {
        Bytes::from(packet).to_vec()
    }
}

impl From<IPv4Packet> for IPPacket {
    fn from(packet: IPv4Packet) -> Self {
        IPPacket::V4(packet)
    }
}

impl From<IPv6Packet> for IPPacket {
    fn from(packet: IPv6Packet) -> Self {
        IPPacket::V6(packet)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::ipv4::{Flags, Protocol, TypeOfService};

    #[test]
    fn test_ippacket_ipv4_creation() {
        // [正常系] IPv4PacketからIPPacketへの変換
        let ipv4_packet = IPv4Packet::new(
            TypeOfService::default(),
            1,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            vec![],
            vec![0; 8],
        );

        let ip_packet = IPPacket::from(ipv4_packet.clone());
        match ip_packet {
            IPPacket::V4(packet) => assert_eq!(packet, ipv4_packet),
            IPPacket::V6(_) => panic!("Expected IPv4 packet"),
        }
    }

    #[test]
    fn test_ippacket_ipv6_creation() {
        // [正常系] IPv6PacketからIPPacketへの変換
        let ipv6_packet = IPv6Packet::new(
            0,
            0,
            Protocol::IPv6ICMP,
            64,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            vec![0; 8],
        )
        .unwrap();

        let ip_packet = IPPacket::from(ipv6_packet.clone());
        match ip_packet {
            IPPacket::V6(packet) => assert_eq!(packet, ipv6_packet),
            IPPacket::V4(_) => panic!("Expected IPv6 packet"),
        }
    }

    #[test]
    fn test_ippacket_try_from_bytes_ipv4() {
        // [正常系] IPv4バイト列からのIPPacket作成
        let ipv4_packet = IPv4Packet::new(
            TypeOfService::default(),
            1,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            vec![],
            vec![0; 8],
        );

        let bytes: Vec<u8> = ipv4_packet.clone().into();
        let ip_packet = IPPacket::try_from_bytes(&bytes).unwrap();

        match ip_packet {
            IPPacket::V4(packet) => {
                assert_eq!(packet.src, ipv4_packet.src);
                assert_eq!(packet.dst, ipv4_packet.dst);
                assert_eq!(packet.protocol, ipv4_packet.protocol);
            }
            IPPacket::V6(_) => panic!("Expected IPv4 packet"),
        }
    }

    #[test]
    fn test_ippacket_try_from_bytes_ipv6() {
        // [正常系] IPv6バイト列からのIPPacket作成
        let ipv6_packet = IPv6Packet::new(
            0,
            0,
            Protocol::IPv6ICMP,
            64,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            vec![0; 8],
        )
        .unwrap();

        let bytes: Vec<u8> = ipv6_packet.clone().into();
        let ip_packet = IPPacket::try_from_bytes(&bytes).unwrap();

        match ip_packet {
            IPPacket::V6(packet) => {
                assert_eq!(packet.src, ipv6_packet.src);
                assert_eq!(packet.dst, ipv6_packet.dst);
                assert_eq!(packet.next_header, ipv6_packet.next_header);
            }
            IPPacket::V4(_) => panic!("Expected IPv6 packet"),
        }
    }

    #[test]
    fn test_ippacket_try_from_bytes_invalid_version() {
        // [異常系] 無効なIPバージョン
        let invalid_bytes = [0x50, 0x00, 0x00, 0x00]; // バージョン5
        let result = IPPacket::try_from_bytes(&invalid_bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IPPacketError::InvalidVersion(5)
        ));
    }

    #[test]
    fn test_ippacket_try_from_bytes_empty() {
        // [異常系] 空のバイト列
        let empty_bytes: &[u8] = &[];
        let result = IPPacket::try_from_bytes(empty_bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IPPacketError::InvalidPacketLength(0)
        ));
    }

    #[test]
    fn test_ippacket_to_bytes_ipv4() {
        // [正常系] IPv4 IPPacketからバイト列への変換
        let ipv4_packet = IPv4Packet::new(
            TypeOfService::default(),
            1,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            vec![],
            vec![0; 8],
        );

        let ip_packet = IPPacket::V4(ipv4_packet.clone());
        let bytes: Vec<u8> = ip_packet.into();
        let expected_bytes: Vec<u8> = ipv4_packet.into();
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_ippacket_to_bytes_ipv6() {
        // [正常系] IPv6 IPPacketからバイト列への変換
        let ipv6_packet = IPv6Packet::new(
            0,
            0,
            Protocol::IPv6ICMP,
            64,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            vec![0; 8],
        )
        .unwrap();

        let ip_packet = IPPacket::V6(ipv6_packet.clone());
        let bytes: Vec<u8> = ip_packet.into();
        let expected_bytes: Vec<u8> = ipv6_packet.into();
        assert_eq!(bytes, expected_bytes);
    }
}
