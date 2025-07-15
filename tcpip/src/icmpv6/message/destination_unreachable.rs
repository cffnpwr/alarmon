use std::fmt::{self, Display};
use std::net::Ipv6Addr;

use bytes::{BufMut, Bytes, BytesMut};
use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;
use crate::icmpv6::message::Message;
use crate::icmpv6::message_type::ICMPv6MessageType;
use crate::ipv6::IPv6Packet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DestinationUnreachableCodeError {
    #[error("Invalid destination unreachable code value: {0}")]
    InvalidValue(u8),
    #[error(
        "Invalid destination unreachable code bytes length. Expected 1 byte, but got {0} bytes."
    )]
    InvalidBytesLength(usize),
}

/// Destination Unreachable Code
///
/// RFC 4443で定義されたDestination Unreachableメッセージのコード
#[derive(Debug, Clone, Copy, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = DestinationUnreachableCodeError, types = [&[u8], [u8; 1], Vec<u8>, Box<[u8]>])]
pub enum DestinationUnreachableCode {
    /// No route to destination
    /// 宛先へのルートなし
    NoRouteToDestination = 0,

    /// Communication with destination administratively prohibited
    /// 宛先との通信が管理上禁止されている
    CommunicationProhibited = 1,

    /// Beyond scope of source address
    /// ソースアドレスのスコープを超えている
    BeyondScopeOfSourceAddress = 2,

    /// Address unreachable
    /// 宛先アドレスに到達できない
    AddressUnreachable = 3,

    /// Port unreachable
    /// 宛先ポートに到達できない
    PortUnreachable = 4,

    /// Source address failed ingress/egress policy
    /// ソースアドレスがポリシーに違反している
    SourceAddressPolicyViolation = 5,

    /// Reject route to destination
    /// 宛先へのルートが拒否された
    RejectRouteToDestination = 6,
}
impl Display for DestinationUnreachableCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DestinationUnreachableCode::NoRouteToDestination => {
                write!(f, "No Route to Destination")
            }
            DestinationUnreachableCode::CommunicationProhibited => {
                write!(f, "Communication Prohibited")
            }
            DestinationUnreachableCode::BeyondScopeOfSourceAddress => {
                write!(f, "Beyond Scope of Source Address")
            }
            DestinationUnreachableCode::AddressUnreachable => write!(f, "Address Unreachable"),
            DestinationUnreachableCode::PortUnreachable => write!(f, "Port Unreachable"),
            DestinationUnreachableCode::SourceAddressPolicyViolation => {
                write!(f, "Source address failed ingress/egress policy")
            }
            DestinationUnreachableCode::RejectRouteToDestination => {
                write!(f, "Reject Route to Destination")
            }
        }
    }
}
impl TryFromBytes for DestinationUnreachableCode {
    type Error = DestinationUnreachableCodeError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();
        if bytes.len() != 1 {
            return Err(DestinationUnreachableCodeError::InvalidBytesLength(
                bytes.len(),
            ));
        }

        match bytes[0] {
            0 => Ok(DestinationUnreachableCode::NoRouteToDestination),
            1 => Ok(DestinationUnreachableCode::CommunicationProhibited),
            2 => Ok(DestinationUnreachableCode::BeyondScopeOfSourceAddress),
            3 => Ok(DestinationUnreachableCode::AddressUnreachable),
            4 => Ok(DestinationUnreachableCode::PortUnreachable),
            5 => Ok(DestinationUnreachableCode::SourceAddressPolicyViolation),
            6 => Ok(DestinationUnreachableCode::RejectRouteToDestination),
            code => Err(DestinationUnreachableCodeError::InvalidValue(code)),
        }
    }
}
impl TryFrom<&u8> for DestinationUnreachableCode {
    type Error = DestinationUnreachableCodeError;

    fn try_from(value: &u8) -> Result<Self, Self::Error> {
        Self::try_from_bytes([*value])
    }
}
impl TryFrom<u8> for DestinationUnreachableCode {
    type Error = DestinationUnreachableCodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::try_from_bytes([value])
    }
}
impl From<DestinationUnreachableCode> for u8 {
    fn from(value: DestinationUnreachableCode) -> Self {
        value as u8
    }
}
impl From<&DestinationUnreachableCode> for u8 {
    fn from(value: &DestinationUnreachableCode) -> Self {
        *value as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DestinationUnreachableMessageError {
    #[error("Invalid destination unreachable message type. Expected 1, but got {0}.")]
    InvalidMessageType(u8),
    #[error(
        "Invalid destination unreachable message length. Expected at least 8 bytes, but got {0} bytes."
    )]
    InvalidMessageLength(usize),
    #[error(transparent)]
    InvalidCode(#[from] DestinationUnreachableCodeError),
}

/// ICMPv6 Destination Unreachable メッセージ
///
/// RFC 4443で定義されたDestination Unreachable (Type 1) のメッセージ構造
/// 宛先に到達できない場合に送信されるエラーメッセージ
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = DestinationUnreachableMessageError, types = [&[u8], Vec<u8>, Box<[u8]>, bytes::Bytes])]
pub struct DestinationUnreachableMessage {
    /// Code
    /// Destination Unreachableのコード
    pub code: DestinationUnreachableCode,

    /// Checksum
    pub checksum: u16,

    /// Unused field
    /// MUST: 送信時は0で埋める必要がある
    /// MUST: 受信側には無視される必要がある
    pub unused: [u8; 4],

    /// Original packet that caused the error (up to minimum IPv6 MTU)
    pub original_packet: IPv6Packet,
}

impl DestinationUnreachableMessage {
    /// 新しいDestination Unreachableメッセージを作成
    pub fn new(
        code: DestinationUnreachableCode,
        original_packet: IPv6Packet,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        let mut msg = Self {
            code,
            checksum: 0, // チェックサムは後で計算する
            unused: [0; 4],
            original_packet,
        };
        msg.checksum = msg.calculate_checksum(src, dst);
        msg
    }
}

impl TryFromBytes for DestinationUnreachableMessage {
    type Error = DestinationUnreachableMessageError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();
        if bytes.len() < 8 {
            return Err(DestinationUnreachableMessageError::InvalidMessageLength(
                bytes.len(),
            ));
        }

        if bytes[0] != 1 {
            return Err(DestinationUnreachableMessageError::InvalidMessageType(
                bytes[0],
            ));
        }
        let code = bytes[1]
            .try_into()
            .map_err(DestinationUnreachableMessageError::InvalidCode)?;
        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        let unused = [bytes[4], bytes[5], bytes[6], bytes[7]];
        let original_packet = IPv6Packet::try_from_bytes(&bytes[8..])
            .map_err(|_| DestinationUnreachableMessageError::InvalidMessageLength(bytes.len()))?;

        Ok(DestinationUnreachableMessage {
            code,
            checksum,
            unused,
            original_packet,
        })
    }
}

impl Message for DestinationUnreachableMessage {
    fn message_type(&self) -> ICMPv6MessageType {
        ICMPv6MessageType::DestinationUnreachable
    }

    fn code(&self) -> u8 {
        self.code.into()
    }

    fn total_length(&self) -> usize {
        // 8 bytes for header + original packet length
        8 + self.original_packet.total_length()
    }
}

impl From<&DestinationUnreachableMessage> for Bytes {
    fn from(value: &DestinationUnreachableMessage) -> Self {
        let mut data = BytesMut::with_capacity(value.total_length());

        // Type (1 byte)
        data.put_u8(value.message_type().into());
        // Code (1 byte)
        data.put_u8(value.code.into());
        // Checksum (2 bytes)
        data.put_u16(value.checksum);
        // Unused field (4 bytes)
        data.extend_from_slice(&value.unused);
        // Original packet (variable length)
        data.extend_from_slice(&Bytes::from(value.original_packet.clone()));

        data.freeze()
    }
}

impl From<DestinationUnreachableMessage> for Bytes {
    fn from(value: DestinationUnreachableMessage) -> Self {
        (&value).into()
    }
}

impl From<DestinationUnreachableMessage> for Vec<u8> {
    fn from(value: DestinationUnreachableMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

impl From<&DestinationUnreachableMessage> for Vec<u8> {
    fn from(value: &DestinationUnreachableMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_destination_unreachable_message_creation() {
        // [正常系] Destination Unreachableメッセージの作成
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let original_packet = IPv6Packet::new(
            0,
            0,
            crate::ipv4::Protocol::TCP,
            64,
            src,
            dst,
            b"test payload",
        )
        .unwrap();
        let message = DestinationUnreachableMessage::new(
            DestinationUnreachableCode::CommunicationProhibited,
            original_packet.clone(),
            src,
            dst,
        );

        assert_eq!(
            message.code,
            DestinationUnreachableCode::CommunicationProhibited
        );
        assert_eq!(message.original_packet, original_packet);
    }

    #[test]
    fn test_destination_unreachable_message_try_from_bytes() {
        // [正常系] バイト列からのパース
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let original_packet =
            IPv6Packet::new(0, 0, crate::ipv4::Protocol::TCP, 64, src, dst, b"test").unwrap();
        let packet_bytes: Vec<u8> = original_packet.clone().into();

        let mut bytes = vec![
            1, 3, 0, 0, // Type: 1, Code: 3, Checksum: 0
            0, 0, 0, 0, // Unused
        ];
        bytes.extend_from_slice(&packet_bytes);

        let message = DestinationUnreachableMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(message.code, DestinationUnreachableCode::AddressUnreachable);
        assert_eq!(message.original_packet, original_packet);

        // [異常系] 不正な長さ
        let short_bytes = [1, 0, 0, 0, 0, 0, 0]; // 7バイト（8バイト未満）
        assert!(matches!(
            DestinationUnreachableMessage::try_from_bytes(&short_bytes).unwrap_err(),
            DestinationUnreachableMessageError::InvalidMessageLength(7)
        ));
    }

    #[test]
    fn test_destination_unreachable_message_checksum_calculation() {
        // [正常系] ICMPv6チェックサム計算
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let original_packet = IPv6Packet::new(
            0,
            0,
            crate::ipv4::Protocol::TCP,
            64,
            src,
            dst,
            b"test packet",
        )
        .unwrap();
        let message = DestinationUnreachableMessage::new(
            DestinationUnreachableCode::CommunicationProhibited,
            original_packet,
            src,
            dst,
        );
        assert_ne!(message.checksum, 0); // チェックサムが計算されていることを確認

        // 計算されたチェックサムで検証
        assert!(message.validate_checksum(src, dst));

        // 間違ったソース/デスティネーションでは検証失敗
        let wrong_dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        assert!(!message.validate_checksum(src, wrong_dst));
    }

    #[test]
    fn test_destination_unreachable_message_round_trip() {
        // [正常系] バイト列変換のラウンドトリップテスト
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let original_packet = IPv6Packet::new(
            0,
            0,
            crate::ipv4::Protocol::TCP,
            64,
            src,
            dst,
            b"original data",
        )
        .unwrap();
        let original = DestinationUnreachableMessage::new(
            DestinationUnreachableCode::PortUnreachable,
            original_packet,
            src,
            dst,
        );

        let bytes: Vec<u8> = original.clone().into();
        let parsed = DestinationUnreachableMessage::try_from_bytes(&bytes).unwrap();

        assert_eq!(original, parsed);
    }
}
