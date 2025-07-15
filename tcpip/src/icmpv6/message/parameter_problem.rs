use std::fmt;
use std::net::Ipv6Addr;

use bytes::{BufMut, Bytes, BytesMut};
use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;
use crate::icmpv6::message::Message;
use crate::icmpv6::message_type::ICMPv6MessageType;
use crate::ipv6::IPv6Packet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ParameterProblemCodeError {
    #[error("Invalid parameter problem code value: {0}")]
    InvalidValue(u8),
    #[error("Invalid parameter problem code bytes length. Expected 1 byte, but got {0} bytes.")]
    InvalidBytesLength(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterProblemCode {
    /// Erroneous header field encountered
    /// ヘッダーフィールドにエラーが検出された
    ErroneousHeaderField = 0,

    /// Unrecognized Next Header type encountered
    /// 認識できないNext Headerタイプが検出された
    UnrecognizedNextHeader = 1,

    /// Unrecognized IPv6 option encountered
    /// 認識できないIPv6オプションが検出された
    UnrecognizedOption = 2,
}

impl From<ParameterProblemCode> for u8 {
    fn from(value: ParameterProblemCode) -> Self {
        value as u8
    }
}

impl From<&ParameterProblemCode> for u8 {
    fn from(value: &ParameterProblemCode) -> Self {
        *value as u8
    }
}

impl fmt::Display for ParameterProblemCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParameterProblemCode::ErroneousHeaderField => {
                write!(f, "Erroneous header field encountered")
            }
            ParameterProblemCode::UnrecognizedNextHeader => {
                write!(f, "Unrecognized Next Header type encountered")
            }
            ParameterProblemCode::UnrecognizedOption => {
                write!(f, "Unrecognized IPv6 option encountered")
            }
        }
    }
}

impl TryFromBytes for ParameterProblemCode {
    type Error = ParameterProblemCodeError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();
        if bytes.len() != 1 {
            return Err(ParameterProblemCodeError::InvalidBytesLength(bytes.len()));
        }

        match bytes[0] {
            0 => Ok(ParameterProblemCode::ErroneousHeaderField),
            1 => Ok(ParameterProblemCode::UnrecognizedNextHeader),
            2 => Ok(ParameterProblemCode::UnrecognizedOption),
            code => Err(ParameterProblemCodeError::InvalidValue(code)),
        }
    }
}

impl TryFrom<&u8> for ParameterProblemCode {
    type Error = ParameterProblemCodeError;

    fn try_from(value: &u8) -> Result<Self, Self::Error> {
        Self::try_from_bytes([*value])
    }
}

impl TryFrom<u8> for ParameterProblemCode {
    type Error = ParameterProblemCodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::try_from_bytes([value])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParameterProblemMessageError {
    #[error("Invalid parameter problem message type. Expected 4, but got {0}.")]
    InvalidMessageType(u8),
    #[error("Invalid parameter problem message code: {0}")]
    InvalidCode(#[from] ParameterProblemCodeError),
    #[error(
        "Invalid parameter problem message length. Expected at least 8 bytes, but got {0} bytes."
    )]
    InvalidMessageLength(usize),
}

/// ICMPv6 Parameter Problem メッセージ
///
/// RFC 4443で定義されたParameter Problem (Type 4) のメッセージ構造
/// IPv6ヘッダーまたは拡張ヘッダーに問題がある場合に送信されるエラーメッセージ
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = ParameterProblemMessageError, types = [&[u8], Vec<u8>, Box<[u8]>, bytes::Bytes])]
pub struct ParameterProblemMessage {
    /// Code field indicating the reason for the parameter problem
    pub code: ParameterProblemCode,

    /// Checksum
    pub checksum: u16,

    /// Pointer to the byte in the original packet where the problem was detected
    pub pointer: u32,

    /// Original packet that caused the error (up to minimum IPv6 MTU)
    pub original_packet: IPv6Packet,
}

impl ParameterProblemMessage {
    /// 新しいParameter Problemメッセージを作成
    pub fn new(
        code: ParameterProblemCode,
        pointer: u32,
        original_packet: IPv6Packet,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        let mut msg = Self {
            code,
            checksum: 0, // チェックサムは後で計算する
            pointer,
            original_packet,
        };

        msg.checksum = msg.calculate_checksum(src, dst);
        msg
    }

    /// Erroneous header field encounteredのParameter Problemメッセージを作成
    pub fn new_erroneous_header_field(
        pointer: u32,
        original_packet: IPv6Packet,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        Self::new(
            ParameterProblemCode::ErroneousHeaderField,
            pointer,
            original_packet,
            src,
            dst,
        )
    }

    /// Unrecognized Next Header type encounteredのParameter Problemメッセージを作成
    pub fn new_unrecognized_next_header(
        pointer: u32,
        original_packet: IPv6Packet,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        Self::new(
            ParameterProblemCode::UnrecognizedNextHeader,
            pointer,
            original_packet,
            src,
            dst,
        )
    }

    /// Unrecognized IPv6 option encounteredのParameter Problemメッセージを作成
    pub fn new_unrecognized_option(
        pointer: u32,
        original_packet: IPv6Packet,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        Self::new(
            ParameterProblemCode::UnrecognizedOption,
            pointer,
            original_packet,
            src,
            dst,
        )
    }

    /// メッセージの全体サイズを計算
    pub fn total_length(&self) -> usize {
        8 + self.original_packet.total_length() // Type(1) + Code(1) + Checksum(2) + Pointer(4) + OriginalPacket
    }
}

impl TryFromBytes for ParameterProblemMessage {
    type Error = ParameterProblemMessageError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();
        if bytes.len() < 8 {
            return Err(ParameterProblemMessageError::InvalidMessageLength(
                bytes.len(),
            ));
        }

        if bytes[0] != 4 {
            return Err(ParameterProblemMessageError::InvalidMessageType(bytes[0]));
        }

        let code = ParameterProblemCode::try_from(bytes[1])?;
        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        let pointer = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let original_packet = IPv6Packet::try_from_bytes(&bytes[8..])
            .map_err(|_| ParameterProblemMessageError::InvalidMessageLength(bytes.len()))?;

        Ok(ParameterProblemMessage {
            code,
            checksum,
            pointer,
            original_packet,
        })
    }
}

impl Message for ParameterProblemMessage {
    fn message_type(&self) -> ICMPv6MessageType {
        ICMPv6MessageType::ParameterProblem
    }

    fn code(&self) -> u8 {
        self.code.into()
    }

    fn total_length(&self) -> usize {
        // 4 bytes for Type + Code + Checksum + 4 bytes pointer + original packet
        8 + self.original_packet.total_length()
    }
}

impl From<&ParameterProblemMessage> for Bytes {
    fn from(value: &ParameterProblemMessage) -> Self {
        let mut data = BytesMut::with_capacity(value.total_length());

        // Type (1 byte)
        data.put_u8(value.message_type().into());
        // Code (1 byte)
        data.put_u8(value.code());
        // Checksum (2 bytes)
        data.put_u16(value.checksum);
        // Pointer (4 bytes)
        data.put_u32(value.pointer);
        // Original packet (variable length)
        data.extend_from_slice(&Bytes::from(value.original_packet.clone()));

        data.freeze()
    }
}

impl From<ParameterProblemMessage> for Bytes {
    fn from(value: ParameterProblemMessage) -> Self {
        (&value).into()
    }
}

impl From<ParameterProblemMessage> for Vec<u8> {
    fn from(value: ParameterProblemMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

impl From<&ParameterProblemMessage> for Vec<u8> {
    fn from(value: &ParameterProblemMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipv4::Protocol;

    #[test]
    fn test_parameter_problem_message_creation() {
        // [正常系] Parameter Problemメッセージの作成
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let original_packet =
            IPv6Packet::new(0, 0, Protocol::TCP, 64, src, dst, b"original packet data").unwrap();
        let message = ParameterProblemMessage::new(
            ParameterProblemCode::ErroneousHeaderField,
            0x12345678,
            original_packet.clone(),
            src,
            dst,
        );
        assert_eq!(message.code, ParameterProblemCode::ErroneousHeaderField);
        assert_eq!(message.pointer, 0x12345678);
        assert_eq!(message.original_packet, original_packet);
        assert_ne!(message.checksum, 0); // チェックサムが計算されていることを確認

        // [正常系] Erroneous header fieldメッセージの作成
        let header_error_message = ParameterProblemMessage::new_erroneous_header_field(
            0x40,
            original_packet.clone(),
            src,
            dst,
        );
        assert_eq!(
            header_error_message.code,
            ParameterProblemCode::ErroneousHeaderField
        );
        assert_eq!(header_error_message.pointer, 0x40);
        assert_eq!(header_error_message.original_packet, original_packet);

        // [正常系] Unrecognized Next Headerメッセージの作成
        let next_header_message = ParameterProblemMessage::new_unrecognized_next_header(
            0x06,
            original_packet.clone(),
            src,
            dst,
        );
        assert_eq!(
            next_header_message.code,
            ParameterProblemCode::UnrecognizedNextHeader
        );
        assert_eq!(next_header_message.pointer, 0x06);
        assert_eq!(next_header_message.original_packet, original_packet);

        // [正常系] Unrecognized optionメッセージの作成
        let option_message = ParameterProblemMessage::new_unrecognized_option(
            0x2A,
            original_packet.clone(),
            src,
            dst,
        );
        assert_eq!(
            option_message.code,
            ParameterProblemCode::UnrecognizedOption
        );
        assert_eq!(option_message.pointer, 0x2A);
        assert_eq!(option_message.original_packet, original_packet);
    }

    #[test]
    fn test_parameter_problem_message_try_from_bytes() {
        // [正常系] バイト列からのパース - Erroneous header field
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let original_packet = IPv6Packet::new(0, 0, Protocol::TCP, 64, src, dst, b"test").unwrap();
        let packet_bytes: Vec<u8> = original_packet.clone().into();

        let mut bytes = vec![
            4, 0, 0, 0, // Type: 4, Code: 0, Checksum: 0
            0x00, 0x00, 0x00, 0x40, // Pointer: 0x40
        ];
        bytes.extend_from_slice(&packet_bytes);

        let message = ParameterProblemMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(message.code, ParameterProblemCode::ErroneousHeaderField);
        assert_eq!(message.pointer, 0x40);
        assert_eq!(message.original_packet, original_packet);

        // [異常系] 不正な長さ
        let short_bytes = [4, 0, 0, 0, 0x00, 0x00, 0x00]; // 7バイト（8バイト未満）
        assert!(matches!(
            ParameterProblemMessage::try_from_bytes(&short_bytes).unwrap_err(),
            ParameterProblemMessageError::InvalidMessageLength(7)
        ));
    }

    #[test]
    fn test_parameter_problem_message_checksum_calculation() {
        // [正常系] ICMPv6チェックサム計算
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let original_packet =
            IPv6Packet::new(0, 0, Protocol::TCP, 64, src, dst, b"test packet").unwrap();
        let message =
            ParameterProblemMessage::new_erroneous_header_field(0x40, original_packet, src, dst);

        assert_ne!(message.checksum, 0); // チェックサムが計算されていることを確認

        // 計算されたチェックサムで検証
        assert!(message.validate_checksum(src, dst));

        // 間違った送信元・宛先では検証失敗
        let wrong_dst = Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 2);
        assert!(!message.validate_checksum(src, wrong_dst));
    }

    #[test]
    fn test_parameter_problem_message_round_trip() {
        // [正常系] バイト列変換のラウンドトリップテスト
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let original_packet =
            IPv6Packet::new(0, 0, Protocol::TCP, 64, src, dst, b"original data").unwrap();
        let original =
            ParameterProblemMessage::new_unrecognized_option(0xDEADBEEF, original_packet, src, dst);

        let bytes: Vec<u8> = original.clone().into();
        let parsed = ParameterProblemMessage::try_from_bytes(&bytes).unwrap();

        assert_eq!(original, parsed);
    }
}
