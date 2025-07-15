use std::fmt::Display;
use std::net::Ipv6Addr;

use bytes::{BufMut, Bytes, BytesMut};
use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;
use crate::icmpv6::ICMPv6MessageType;
use crate::icmpv6::message::Message;
use crate::ipv6::{IPv6Error, IPv6Packet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TimeExceededCodeError {
    #[error("Invalid time exceeded message type. Expected 0 or 1, but got {0}.")]
    InvalidCode(u8),
    #[error(
        "Invalid time exceeded code bytes length. Expected at least 1 bytes, but got {0} bytes."
    )]
    InvalidBytesLength(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = TimeExceededCodeError, types = [&[u8], Vec<u8>, Box<[u8]>, Bytes])]
pub enum TimeExceededCode {
    /// Hop limit exceeded in transit
    /// ホップリミット超過
    HopLimitExceeded = 0,

    /// Fragment reassembly time exceeded
    /// フラグメント再構築時間超過
    FragmentReassemblyTimeExceeded = 1,
}
impl Display for TimeExceededCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimeExceededCode::HopLimitExceeded => write!(f, "Hop Limit Exceeded"),
            TimeExceededCode::FragmentReassemblyTimeExceeded => {
                write!(f, "Fragment Reassembly Time Exceeded")
            }
        }
    }
}
impl TryFromBytes for TimeExceededCode {
    type Error = TimeExceededCodeError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();
        if bytes.len() < 1 {
            return Err(TimeExceededCodeError::InvalidBytesLength(bytes.len()));
        }

        bytes[0].try_into()
    }
}
impl TryFrom<u8> for TimeExceededCode {
    type Error = TimeExceededCodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}
impl TryFrom<&u8> for TimeExceededCode {
    type Error = TimeExceededCodeError;

    fn try_from(value: &u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TimeExceededCode::HopLimitExceeded),
            1 => Ok(TimeExceededCode::FragmentReassemblyTimeExceeded),
            code => Err(TimeExceededCodeError::InvalidCode(*code)),
        }
    }
}
impl From<TimeExceededCode> for u8 {
    fn from(value: TimeExceededCode) -> Self {
        value as u8
    }
}
impl From<&TimeExceededCode> for u8 {
    fn from(value: &TimeExceededCode) -> Self {
        *value as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TimeExceededMessageError {
    #[error("Invalid time exceeded message type. Expected 3, but got {0}.")]
    InvalidMessageType(u8),
    #[error("Invalid time exceeded message length. Expected at least 8 bytes, but got {0} bytes.")]
    InvalidMessageLength(usize),
    #[error(transparent)]
    InvalidCode(#[from] TimeExceededCodeError),
    #[error(transparent)]
    IPv6PacketError(#[from] IPv6Error),
}

/// ICMPv6 Time Exceeded メッセージ
///
/// RFC 4443で定義されたTime Exceeded (Type 3) のメッセージ構造
/// Hop Limitが0になった場合やフラグメント再組み立てがタイムアウトした場合に送信されるエラーメッセージ
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = TimeExceededMessageError, types = [&[u8], Vec<u8>, Box<[u8]>, bytes::Bytes])]
pub struct TimeExceededMessage {
    /// Code
    /// Time Exceededのコード
    pub code: TimeExceededCode,

    /// Checksum
    pub checksum: u16,

    /// Unused
    /// MUST: 送信時は0で埋める必要がある
    /// MUST: 受信側には無視される必要がある
    pub unused: u32,

    /// Original packet that caused the error (up to minimum IPv6 MTU)
    /// 元のパケットデータ (最小IPv6 MTUまで)
    pub original_packet: IPv6Packet,
}

impl TimeExceededMessage {
    /// 新しいTime Exceededメッセージを作成
    pub fn new(
        code: TimeExceededCode,
        original_packet: impl Into<IPv6Packet>,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        let mut msg = TimeExceededMessage {
            code,
            checksum: 0, // チェックサムは後で計算する
            unused: 0,
            original_packet: original_packet.into(),
        };

        msg.checksum = msg.calculate_checksum(src, dst);
        msg
    }
}

impl TryFromBytes for TimeExceededMessage {
    type Error = TimeExceededMessageError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();
        if bytes.len() < 8 {
            return Err(TimeExceededMessageError::InvalidMessageLength(bytes.len()));
        }

        if bytes[0] != 3 {
            return Err(TimeExceededMessageError::InvalidMessageType(bytes[0]));
        }

        let code =
            TimeExceededCode::try_from(bytes[1]).map_err(TimeExceededMessageError::InvalidCode)?;
        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        let unused = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let original_packet = IPv6Packet::try_from_bytes(&bytes[8..])
            .map_err(TimeExceededMessageError::IPv6PacketError)?;

        Ok(TimeExceededMessage {
            code,
            checksum,
            unused,
            original_packet,
        })
    }
}

impl Message for TimeExceededMessage {
    fn message_type(&self) -> ICMPv6MessageType {
        ICMPv6MessageType::TimeExceeded
    }

    fn code(&self) -> u8 {
        self.code.into()
    }

    fn total_length(&self) -> usize {
        8 + self.original_packet.total_length()
    }
}

impl From<TimeExceededMessage> for Bytes {
    fn from(value: TimeExceededMessage) -> Self {
        let mut bytes = BytesMut::with_capacity(8 + value.original_packet.total_length());

        // Type (1 byte)
        bytes.put_u8(3);
        // Code (1 byte)
        bytes.put_u8(value.code.into());
        // Checksum (2 bytes)
        bytes.put_u16(value.checksum);
        // Unused (4 bytes)
        bytes.put_u32(value.unused);
        // Original packet (variable length)
        bytes.extend_from_slice(&Bytes::from(&value.original_packet));

        bytes.freeze()
    }
}

impl From<&TimeExceededMessage> for Bytes {
    fn from(value: &TimeExceededMessage) -> Self {
        value.clone().into()
    }
}

impl From<TimeExceededMessage> for Vec<u8> {
    fn from(value: TimeExceededMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

impl From<&TimeExceededMessage> for Vec<u8> {
    fn from(value: &TimeExceededMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    #[test]
    fn test_time_exceeded_message_creation() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // [正常系] Time Exceededメッセージの作成
        let original_data = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6f, 0x72,
            0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c, 0x20, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x20,
            0x64, 0x61, 0x74, 0x61,
        ];
        let original = IPv6Packet::try_from_bytes(&original_data[..]).unwrap();
        let message = TimeExceededMessage::new(
            TimeExceededCode::HopLimitExceeded,
            original.clone(),
            src,
            dst,
        );
        assert_eq!(message.code, TimeExceededCode::HopLimitExceeded);
        assert_eq!(message.original_packet, original);
        assert_eq!(message.unused, 0);
        assert_ne!(message.checksum, 0);

        // [正常系] Hop limit exceededメッセージの作成
        let hop_limit_message = TimeExceededMessage::new(
            TimeExceededCode::HopLimitExceeded,
            original.clone(),
            src,
            dst,
        );
        assert_eq!(hop_limit_message.code, TimeExceededCode::HopLimitExceeded);
        assert_eq!(hop_limit_message.original_packet, original);

        // [正常系] Fragment reassembly time exceededメッセージの作成
        let fragment_message = TimeExceededMessage::new(
            TimeExceededCode::FragmentReassemblyTimeExceeded,
            original.clone(),
            src,
            dst,
        );
        assert_eq!(
            fragment_message.code,
            TimeExceededCode::FragmentReassemblyTimeExceeded
        );
        assert_eq!(fragment_message.original_packet, original);
    }

    #[test]
    fn test_time_exceeded_message_try_from_bytes() {
        // [正常系] バイト列からのパース - Hop limit exceeded
        let original_data = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00,
            0x00, 0x00,
        ];
        let original_packet = IPv6Packet::try_from_bytes(&original_data[..]).unwrap();
        let mut bytes = Vec::new();
        bytes.push(3); // Type
        bytes.push(0); // Code
        bytes.extend_from_slice(&0u16.to_be_bytes()); // Checksum
        bytes.extend_from_slice(&0u32.to_be_bytes()); // Unused
        bytes.extend_from_slice(&Bytes::from(&original_packet));

        let message = TimeExceededMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(message.code, TimeExceededCode::HopLimitExceeded);
        assert_eq!(message.checksum, 0);
        assert_eq!(message.unused, 0);
        assert_eq!(message.original_packet, original_packet);

        // [正常系] バイト列からのパース - Fragment reassembly time exceeded
        let original_data = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00,
            0x00, 0x00,
        ];
        let original_packet = IPv6Packet::try_from_bytes(&original_data[..]).unwrap();
        let mut bytes = Vec::new();
        bytes.push(3); // Type
        bytes.push(1); // Code
        bytes.extend_from_slice(&0u16.to_be_bytes()); // Checksum
        bytes.extend_from_slice(&0u32.to_be_bytes()); // Unused
        bytes.extend_from_slice(&Bytes::from(&original_packet));

        let message = TimeExceededMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(
            message.code,
            TimeExceededCode::FragmentReassemblyTimeExceeded
        );
        assert_eq!(message.original_packet, original_packet);

        // [異常系] 不正な長さ
        let short_bytes = [3, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            TimeExceededMessage::try_from_bytes(&short_bytes).unwrap_err(),
            TimeExceededMessageError::InvalidMessageLength(7)
        ));

        // [異常系] 不正なメッセージタイプ
        let bytes = [4, 0, 0, 0, 0, 0, 0, 0]; // Type: 4 (正しくは3)
        assert!(matches!(
            TimeExceededMessage::try_from_bytes(&bytes).unwrap_err(),
            TimeExceededMessageError::InvalidMessageType(4)
        ));
    }

    #[test]
    fn test_time_exceeded_message_checksum_calculation() {
        // [正常系] ICMPv6チェックサム計算
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let original_data = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x65,
            0x73, 0x74, 0x20, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74,
        ];
        let original_packet = IPv6Packet::try_from_bytes(&original_data[..]).unwrap();
        let message = TimeExceededMessage::new(
            TimeExceededCode::HopLimitExceeded,
            original_packet,
            src,
            dst,
        );

        assert_ne!(message.checksum, 0); // チェックサムが計算されていることを確認

        // 計算されたチェックサムで検証
        assert!(message.validate_checksum(src, dst));

        // 間違った送信元アドレスでは検証失敗
        let wrong_src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        assert!(!message.validate_checksum(wrong_src, dst));
    }

    #[test]
    fn test_time_exceeded_message_round_trip() {
        // [正常系] バイト列変換のラウンドトリップテスト
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let original_data = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6f, 0x72,
            0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c, 0x20, 0x64, 0x61, 0x74, 0x61,
        ];
        let original_packet = IPv6Packet::try_from_bytes(&original_data[..]).unwrap();
        let original = TimeExceededMessage::new(
            TimeExceededCode::FragmentReassemblyTimeExceeded,
            original_packet,
            src,
            dst,
        );

        let bytes: Vec<u8> = original.clone().into();
        let parsed = TimeExceededMessage::try_from_bytes(&bytes).unwrap();

        assert_eq!(original.code, parsed.code);
        assert_eq!(original.unused, parsed.unused);
        assert_eq!(original.original_packet, parsed.original_packet);
        // チェックサムは再計算される場合があるため、個別に検証
        assert_eq!(original.checksum, parsed.checksum);
    }

    #[test]
    fn test_time_exceeded_code_conversion() {
        // [正常系] コード値の変換テスト
        assert_eq!(TimeExceededCode::HopLimitExceeded as u8, 0);
        assert_eq!(TimeExceededCode::FragmentReassemblyTimeExceeded as u8, 1);

        // [正常系] バイト列からのコード変換
        assert_eq!(
            TimeExceededCode::try_from_bytes(&[0]).unwrap(),
            TimeExceededCode::HopLimitExceeded
        );
        assert_eq!(
            TimeExceededCode::try_from_bytes(&[1]).unwrap(),
            TimeExceededCode::FragmentReassemblyTimeExceeded
        );

        // [異常系] 不正なコード値
        assert!(matches!(
            TimeExceededCode::try_from_bytes(&[2]).unwrap_err(),
            TimeExceededCodeError::InvalidCode(2)
        ));

        // [異常系] 不正な長さ
        assert!(matches!(
            TimeExceededCode::try_from_bytes(&[]).unwrap_err(),
            TimeExceededCodeError::InvalidBytesLength(0)
        ));
    }
}
