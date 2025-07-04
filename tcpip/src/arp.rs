mod hardware_type;
mod operation;
mod protocol_type;

use std::fmt::Debug;
use std::net::Ipv4Addr;

use bytes::{Bytes, BytesMut};
use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

pub use self::hardware_type::{HardwareType, HardwareTypeError};
pub use self::operation::{Operation, OperationError};
pub use self::protocol_type::{ProtocolType, ProtocolTypeError};
use crate::TryFromBytes;
use crate::address::{IntoAddressType, SizedAddress};
use crate::ethernet::{MacAddr, MacAddrError};
use crate::ipv4::ipv4_address::IPv4AddressError;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HardwareAddressError {
    #[error(transparent)]
    InvalidMacAddress(#[from] MacAddrError),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolAddressError {
    #[error(transparent)]
    InvalidIpv4Address(#[from] IPv4AddressError),
}

/// ARPパケット処理に関するエラー
///
/// ARPパケットのパース・検証で発生する可能性のあるエラーを定義します。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ARPError {
    #[error("Invalid ARP packet length. Expected at least {0} bytes, but got {1} bytes.")]
    InvalidPacketLength(usize, usize),
    #[error("Invalid Hardware and Protocol combination: {0} and {1}")]
    InvalidHardwareAndProtocolCombination(HardwareType, ProtocolType),
    #[error(transparent)]
    InvalidHardwareType(#[from] HardwareTypeError),
    #[error(transparent)]
    InvalidProtocolType(#[from] ProtocolTypeError),
    #[error(transparent)]
    InvalidOperation(#[from] OperationError),
    #[error(transparent)]
    InvalidHardwareAddress(#[from] HardwareAddressError),
    #[error(transparent)]
    InvalidProtocolAddress(#[from] ProtocolAddressError),
}

/// ARPパケット
///
/// Address Resolution Protocol (ARP)パケットを表現します。
/// 現在はEthernetとIPv4の組み合わせのみをサポートしています。
///
/// 参照:
/// - [RFC 826 - Ethernet Address Resolution Protocol](https://tools.ietf.org/rfc/rfc826.txt)
/// - [IANA ARP Parameters](https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml)
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = ARPError, types = [&[u8], Vec<u8>, Box<[u8]>, bytes::Bytes])]
pub enum ARPPacket {
    EthernetIPv4(ARPPacketInner<MacAddr, Ipv4Addr>),
}
impl ARPPacket {
    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, ARPError> {
        let value = value.as_ref();
        if value.len() < 8 {
            return Err(ARPError::InvalidPacketLength(8, value.len()));
        }

        let htype = HardwareType::try_from(&value[0..2])?;
        let ptype = ProtocolType::try_from(&value[2..4])?;
        match (htype, ptype) {
            (HardwareType::Ethernet, ProtocolType::IPv4) => {
                ARPPacketInner::<MacAddr, Ipv4Addr>::try_from(value).map(Self::EthernetIPv4)
            }
            #[allow(unreachable_patterns)] // 今後の拡張のため
            _ => Err(ARPError::InvalidHardwareAndProtocolCombination(
                htype, ptype,
            )),
        }
    }
}

/// ARPパケットの内部構造
///
/// ハードウェアアドレス型とプロトコルアドレス型をジェネリックで扱います。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ARPPacketInner<H, P> {
    /// Operation
    /// ARPの操作
    pub operation: Operation,

    /// Sender Hardware Address
    /// 送信元のL2アドレス
    pub sha: H,

    /// Sender Protocol Address
    /// 送信元のL3アドレス
    pub spa: P,

    /// Target Hardware Address
    /// 宛先のL2アドレス
    pub tha: H,

    /// Target Protocol Address
    /// 宛先のL3アドレス
    pub tpa: P,
}
impl<H, P> ARPPacketInner<H, P>
where
    H: SizedAddress + const IntoAddressType<HardwareType>,
    P: SizedAddress + const IntoAddressType<ProtocolType>,
{
    /// Hardware Address Length
    /// L2アドレスの長さ
    pub const HLEN: u8 = H::BITS / 8;

    /// Protocol Address Length
    /// L3アドレスの長さ
    pub const PLEN: u8 = P::BITS / 8;

    /// Hardware Type
    /// L2のプロトコルの種類
    pub const HTYPE: HardwareType = H::into_address_type();

    /// Protocol Type
    /// L3のプロトコルの種類
    pub const PTYPE: ProtocolType = P::into_address_type();

    /// EthernetとIPv4の組み合わせのARPパケットを生成する
    pub fn new(op: Operation, sha: H, spa: P, tha: H, tpa: P) -> Self {
        ARPPacketInner {
            operation: op,
            sha,
            spa,
            tha,
            tpa,
        }
    }
}
impl<H, P> TryFromBytes for ARPPacketInner<H, P>
where
    H: SizedAddress + const IntoAddressType<HardwareType> + TryFromBytes,
    H::Error: Into<HardwareAddressError>,
    P: SizedAddress + const IntoAddressType<ProtocolType> + TryFromBytes,
    P::Error: Into<ProtocolAddressError>,
{
    type Error = ARPError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, ARPError> {
        let value = value.as_ref();
        let expected_len = 8 + (Self::HLEN + Self::PLEN) as usize * 2;
        if value.len() < expected_len {
            return Err(ARPError::InvalidPacketLength(expected_len, value.len()));
        }

        let htype = HardwareType::try_from(&value[0..2])?;
        let ptype = ProtocolType::try_from(&value[2..4])?;
        if htype != Self::HTYPE || ptype != Self::PTYPE {
            return Err(ARPError::InvalidHardwareAndProtocolCombination(
                htype, ptype,
            ));
        }
        let operation = Operation::try_from(&value[6..8])?;

        let (source, target) = value[8..expected_len].split_at((Self::HLEN + Self::PLEN) as usize);
        let (sha, spa) = source.split_at(Self::HLEN as usize);
        let (tha, tpa) = target.split_at(Self::HLEN as usize);
        let sha = H::try_from_bytes(sha).map_err(|e| ARPError::InvalidHardwareAddress(e.into()))?;
        let spa = P::try_from_bytes(spa).map_err(|e| ARPError::InvalidProtocolAddress(e.into()))?;
        let tha = H::try_from_bytes(tha).map_err(|e| ARPError::InvalidHardwareAddress(e.into()))?;
        let tpa = P::try_from_bytes(tpa).map_err(|e| ARPError::InvalidProtocolAddress(e.into()))?;

        Ok(ARPPacketInner {
            operation,
            sha,
            spa,
            tha,
            tpa,
        })
    }
}
impl TryFrom<&[u8]> for ARPPacketInner<MacAddr, Ipv4Addr> {
    type Error = ARPError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        ARPPacketInner::<MacAddr, Ipv4Addr>::try_from_bytes(value)
    }
}
impl From<ARPPacketInner<MacAddr, Ipv4Addr>> for Bytes {
    fn from(value: ARPPacketInner<MacAddr, Ipv4Addr>) -> Self {
        let mut bytes = BytesMut::with_capacity(28);

        // Hardware Type (Ethernet = 1)
        bytes.extend_from_slice(&(ARPPacketInner::<MacAddr, Ipv4Addr>::HTYPE as u16).to_be_bytes());
        // Protocol Type (IPv4 = 0x0800)
        bytes.extend_from_slice(&(ARPPacketInner::<MacAddr, Ipv4Addr>::PTYPE as u16).to_be_bytes());
        // Hardware Address Length (6 bytes for MAC)
        bytes.extend_from_slice(&[ARPPacketInner::<MacAddr, Ipv4Addr>::HLEN]);
        // Protocol Address Length (4 bytes for IPv4)
        bytes.extend_from_slice(&[ARPPacketInner::<MacAddr, Ipv4Addr>::PLEN]);
        // Operation
        bytes.extend_from_slice(&(value.operation as u16).to_be_bytes());

        // Sender Hardware Address (MAC)
        let sha_bytes: [u8; 6] = value.sha.into();
        bytes.extend_from_slice(&sha_bytes);

        // Sender Protocol Address (IPv4)
        bytes.extend_from_slice(&value.spa.octets());

        // Target Hardware Address (MAC)
        let tha_bytes: [u8; 6] = value.tha.into();
        bytes.extend_from_slice(&tha_bytes);

        // Target Protocol Address (IPv4)
        bytes.extend_from_slice(&value.tpa.octets());

        bytes.freeze()
    }
}

impl From<&ARPPacketInner<MacAddr, Ipv4Addr>> for Bytes {
    fn from(value: &ARPPacketInner<MacAddr, Ipv4Addr>) -> Self {
        value.clone().into()
    }
}

impl From<ARPPacket> for Bytes {
    fn from(value: ARPPacket) -> Self {
        match value {
            ARPPacket::EthernetIPv4(inner) => inner.into(),
        }
    }
}

impl From<&ARPPacket> for Bytes {
    fn from(value: &ARPPacket) -> Self {
        match value {
            ARPPacket::EthernetIPv4(inner) => inner.into(),
        }
    }
}

impl From<ARPPacketInner<MacAddr, Ipv4Addr>> for Vec<u8> {
    fn from(value: ARPPacketInner<MacAddr, Ipv4Addr>) -> Self {
        Bytes::from(value).to_vec()
    }
}

impl From<&ARPPacketInner<MacAddr, Ipv4Addr>> for Vec<u8> {
    fn from(value: &ARPPacketInner<MacAddr, Ipv4Addr>) -> Self {
        Bytes::from(value).to_vec()
    }
}

impl From<ARPPacket> for Vec<u8> {
    fn from(value: ARPPacket) -> Self {
        Bytes::from(value).to_vec()
    }
}

impl From<&ARPPacket> for Vec<u8> {
    fn from(value: &ARPPacket) -> Self {
        Bytes::from(value).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const VALID_ARP_REQUEST_BYTES: [u8; 28] = [
        0x00, 0x01, // Hardware Type (Ethernet)
        0x08, 0x00, // Protocol Type (IPv4)
        0x06, // Hardware Address Length
        0x04, // Protocol Address Length
        0x00, 0x01, // Operation (Request)
        // Sender Hardware Address (MAC)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Sender Protocol Address (IP)
        0xC0, 0xA8, 0x01, 0x01, // 192.168.1.1
        // Target Hardware Address (MAC)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target Protocol Address (IP)
        0xC0, 0xA8, 0x01, 0x02, // 192.168.1.2
    ];

    // ARPPacketInner::new関数のテスト
    #[test]
    fn test_arp_packet_inner_new() {
        // [正常系] ARPパケットの生成
        let sha = MacAddr::try_from("00:11:22:33:44:55").unwrap();
        let spa = Ipv4Addr::new(192, 168, 1, 1);
        let tha = MacAddr::try_from("00:00:00:00:00:00").unwrap();
        let tpa = Ipv4Addr::new(192, 168, 1, 2);

        let arp = ARPPacketInner::new(Operation::Request, sha, spa, tha, tpa);

        assert_eq!(arp.operation, Operation::Request);
        assert_eq!(arp.sha, sha);
        assert_eq!(arp.spa, spa);
        assert_eq!(arp.tha, tha);
        assert_eq!(arp.tpa, tpa);
    }

    // ARPPacketInner::try_from_bytes関数のテスト
    #[test]
    fn test_arp_packet_inner_try_from_bytes_valid() {
        // [正常系] 有効なARPパケットのパース
        let arp =
            ARPPacketInner::<MacAddr, Ipv4Addr>::try_from_bytes(&VALID_ARP_REQUEST_BYTES).unwrap();

        assert_eq!(arp.operation, Operation::Request);
        assert_eq!(arp.sha, MacAddr::try_from("00:11:22:33:44:55").unwrap());
        assert_eq!(arp.spa, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(arp.tha, MacAddr::try_from("00:00:00:00:00:00").unwrap());
        assert_eq!(arp.tpa, Ipv4Addr::new(192, 168, 1, 2));
    }

    #[test]
    fn test_arp_packet_inner_try_from_bytes_invalid_length() {
        // [異常系] 不正なパケット長
        let short_packet = [0u8; 27];
        assert!(matches!(
            ARPPacketInner::<MacAddr, Ipv4Addr>::try_from_bytes(&short_packet).unwrap_err(),
            ARPError::InvalidPacketLength(_, _)
        ));
    }

    #[test]
    fn test_arp_packet_inner_try_from_bytes_invalid_hardware_type() {
        // [異常系] 無効なハードウェアタイプ
        let mut invalid_packet = VALID_ARP_REQUEST_BYTES;
        invalid_packet[0] = 0x00;
        invalid_packet[1] = 0x02;

        assert!(matches!(
            ARPPacketInner::<MacAddr, Ipv4Addr>::try_from_bytes(&invalid_packet).unwrap_err(),
            ARPError::InvalidHardwareType(_)
        ));
    }

    // ARPPacket::try_from_bytes関数のテスト
    #[test]
    fn test_arp_packet_try_from_bytes_valid() {
        // [正常系] 有効なARPPacketのパース
        let arp = ARPPacket::try_from_bytes(&VALID_ARP_REQUEST_BYTES).unwrap();

        match arp {
            ARPPacket::EthernetIPv4(inner) => {
                assert_eq!(inner.operation, Operation::Request);
            }
        }
    }

    #[test]
    fn test_arp_packet_try_from_bytes_too_short() {
        // [異常系] パケットが短すぎる場合
        let short_packet = [0u8; 7];
        assert!(matches!(
            ARPPacket::try_from_bytes(&short_packet).unwrap_err(),
            ARPError::InvalidPacketLength(_, _)
        ));
    }

    // TryFrom<&[u8]>トレイト実装のテスト
    #[test]
    fn test_arp_packet_inner_try_from_slice() {
        // [正常系] &[u8]からの変換
        let arp =
            ARPPacketInner::<MacAddr, Ipv4Addr>::try_from(&VALID_ARP_REQUEST_BYTES[..]).unwrap();
        assert_eq!(arp.operation, Operation::Request);
    }
}
