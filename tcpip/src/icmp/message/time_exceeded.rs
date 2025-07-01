use std::fmt::{self, Display};

use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;
use crate::icmp::MessageType;
use crate::icmp::message::Message;
use crate::ipv4::{IPv4Error, IPv4Packet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TimeExceededCodeError {
    #[error("Invalid time exceeded code value. Expected 0 or 1, but got {0}.")]
    InvalidValue(u8),
    #[error("Invalid time exceeded code bytes length. Expected 1 byte, but got {0} bytes.")]
    InvalidBytesLength(usize),
}

/// Time Exceededメッセージのコード
///
/// RFC 792で定義されたTime Exceededの詳細コード
#[derive(Debug, Clone, Copy, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = TimeExceededCodeError, types = [&[u8], [u8; 1], Vec<u8>, Box<[u8]>])]
pub enum TimeExceededCode {
    /// Time to Live exceeded in Transit
    /// TTL超過（転送中）
    TtlExceeded = 0,

    /// Fragment Reassembly Time Exceeded
    /// フラグメント再構成時間超過
    FragmentReassemblyTimeExceeded = 1,
}

impl Display for TimeExceededCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeExceededCode::TtlExceeded => write!(f, "TTL Exceeded"),
            TimeExceededCode::FragmentReassemblyTimeExceeded => {
                write!(f, "Fragment Reassembly Time Exceeded")
            }
        }
    }
}

impl TryFromBytes for TimeExceededCode {
    type Error = TimeExceededCodeError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, TimeExceededCodeError> {
        let bytes = value.as_ref();
        if bytes.len() != 1 {
            return Err(TimeExceededCodeError::InvalidBytesLength(bytes.len()));
        }

        Self::try_from(bytes[0])
    }
}

impl TryFrom<u8> for TimeExceededCode {
    type Error = TimeExceededCodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TimeExceededCode::TtlExceeded),
            1 => Ok(TimeExceededCode::FragmentReassemblyTimeExceeded),
            value => Err(TimeExceededCodeError::InvalidValue(value)),
        }
    }
}

impl From<TimeExceededCode> for u8 {
    fn from(value: TimeExceededCode) -> Self {
        value as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TimeExceededMessageError {
    #[error("Invalid time exceeded message type. Expected 11, but got {0}.")]
    InvalidMessageType(u8),
    #[error("Invalid time exceeded message length. Expected at least 36 bytes, but got {0} bytes.")]
    InvalidMessageLength(usize),
    #[error(
        "Original datagram payload is too short. Expected at least 8 bytes, but got {0} bytes."
    )]
    OriginalDatagramTooShort(usize),
    #[error(transparent)]
    InvalidCode(#[from] TimeExceededCodeError),
    #[error(transparent)]
    InvalidOriginalDatagram(#[from] IPv4Error),
}

/// Time Exceeded メッセージ
///
/// RFC 792で定義されたTime Exceeded (Type 11) のメッセージ構造
/// TTLが0になった場合やフラグメント再構成時間が超過した場合に送信される
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = TimeExceededMessageError, types = [&[u8], Vec<u8>, Box<[u8]>])]
pub struct TimeExceededMessage {
    /// Code
    /// Time Exceededの詳細な理由を示すコード
    pub code: TimeExceededCode,

    /// Checksum
    pub checksum: u16,

    /// Unused field
    /// 未使用フィールド（4バイト、通常はゼロ）
    pub unused: [u8; 4],

    /// Original Datagram
    /// 元のIPヘッダー + 最初の64ビットのデータ
    /// 便宜上[`IPv4Packet`]を使用する
    pub original_datagram: IPv4Packet,
}

impl TimeExceededMessage {
    /// 新しいTime Exceededメッセージを作成
    pub fn new(
        code: TimeExceededCode,
        original_datagram: IPv4Packet,
    ) -> Result<Self, TimeExceededMessageError> {
        let mut original_datagram = original_datagram;
        // 元のIPパケットからIPv4ヘッダーとデータ部の先頭の64ビット（8バイト）を取得
        if original_datagram.payload.len() < 8 {
            return Err(TimeExceededMessageError::OriginalDatagramTooShort(
                original_datagram.payload.len(),
            ));
        }
        original_datagram.payload.truncate(8); // 最初の64ビット（8バイト）を使用

        let mut msg = TimeExceededMessage {
            code,
            checksum: 0, // チェックサムは後で計算する
            unused: [0; 4],
            original_datagram,
        };
        msg.checksum = msg.calculate_checksum();

        Ok(msg)
    }
}

impl Message for TimeExceededMessage {
    fn msg_type(&self) -> u8 {
        MessageType::TimeExceeded.into()
    }

    fn code(&self) -> u8 {
        self.code.into()
    }
}

impl TryFromBytes for TimeExceededMessage {
    type Error = TimeExceededMessageError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();

        // Time Exceededメッセージタイプは11
        if bytes[0] != 11 {
            return Err(TimeExceededMessageError::InvalidMessageType(bytes[0]));
        }
        // Time Exceededメッセージは36バイト以上
        // Type (1 byte) + Code (1 byte) + Checksum (2 bytes) + Unused (4 bytes) + Original Datagram (IPv4 header (20 bytes or more) + 64 bits of data)
        if bytes.len() < 36 {
            return Err(TimeExceededMessageError::InvalidMessageLength(bytes.len()));
        }

        let code = TimeExceededCode::try_from(bytes[1])?;
        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);

        let mut unused = [0u8; 4];
        unused.copy_from_slice(&bytes[4..8]);

        let original_datagram = IPv4Packet::try_from(&bytes[8..])?;

        Ok(TimeExceededMessage {
            code,
            checksum,
            unused,
            original_datagram,
        })
    }
}

impl From<TimeExceededMessage> for Vec<u8> {
    fn from(value: TimeExceededMessage) -> Self {
        (&value).into()
    }
}

impl From<&TimeExceededMessage> for Vec<u8> {
    fn from(value: &TimeExceededMessage) -> Self {
        let mut bytes = Vec::with_capacity(8 + value.original_datagram.total_size());

        // Type (1 byte)
        bytes.push(MessageType::TimeExceeded.into());
        // Code (1 byte)
        bytes.push(value.code.into());
        // Checksum (2 bytes)
        bytes.extend_from_slice(&value.checksum.to_be_bytes());
        // Unused field (4 bytes)
        bytes.extend_from_slice(&value.unused);
        // Original datagram (variable length)
        bytes.extend_from_slice(&Vec::from(&value.original_datagram));

        bytes
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::ipv4::{Flags, Protocol, TypeOfService};

    /// テスト用のIPv4パケット作成ヘルパー
    fn create_test_ipv4_packet(payload: &[u8]) -> IPv4Packet {
        IPv4Packet::new(
            TypeOfService::default(),
            20 + payload.len() as u16,
            1,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            vec![],
            payload,
        )
    }

    #[test]
    fn test_time_exceeded_message_new() {
        // [正常系] TimeExceededMessageの生成
        let original_packet = create_test_ipv4_packet(b"Original IP header and 64 bits of data");
        let msg = TimeExceededMessage::new(TimeExceededCode::TtlExceeded, original_packet.clone())
            .unwrap();

        assert_eq!(msg.code, TimeExceededCode::TtlExceeded);
        assert_eq!(msg.unused, [0; 4]);
        assert_eq!(msg.original_datagram.payload.len(), 8); // 最初の8バイトのみ

        // [異常系] 8バイト未満のペイロードでエラー
        let original_packet = create_test_ipv4_packet(b"1234567"); // 7バイト（8バイト未満）

        let result = TimeExceededMessage::new(TimeExceededCode::TtlExceeded, original_packet);

        assert!(matches!(
            result,
            Err(TimeExceededMessageError::OriginalDatagramTooShort(7))
        ));
    }

    #[test]
    fn test_time_exceeded_message_try_from_bytes() {
        // [正常系] 有効なバイト列からのパース
        let bytes = [
            11,   // Type: Time Exceeded
            0x00, // Code: TTL Exceeded
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x00, // Unused field
            0x45, 0x00, 0x00, 0x20, // Original IP header start
            0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xf7, 0x67, // More IP header
            0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, // IP addresses
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 8 bytes of original data
        ];

        let msg = TimeExceededMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(msg.code, TimeExceededCode::TtlExceeded);
        assert_eq!(msg.unused, [0x00, 0x00, 0x00, 0x00]);

        // [異常系] 不正な長さ
        let short_bytes = [11, 0x00, 0x00, 0x00]; // 4バイト（36バイト未満）

        assert!(matches!(
            TimeExceededMessage::try_from_bytes(&short_bytes).unwrap_err(),
            TimeExceededMessageError::InvalidMessageLength(4)
        ));

        // [異常系] 無効なメッセージタイプ
        let bytes = [
            5,    // Type: 5 (不正、Time Exceededは11)
            0x00, // Code: TTL Exceeded
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x00, // Unused field
            0x45, 0x00, 0x00, 0x20, // Original IP header start
            0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xf7, 0x67, // More IP header
            0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, // IP addresses
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 8 bytes of original data
        ];

        assert!(matches!(
            TimeExceededMessage::try_from_bytes(&bytes).unwrap_err(),
            TimeExceededMessageError::InvalidMessageType(5)
        ));

        // [異常系] 不正なコード値
        let invalid_code_bytes = [
            11,   // Type: Time Exceeded
            0x02, // Code: 2 (不正、Time Exceededは0または1のみ)
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x00, // Unused field
            0x45, 0x00, 0x00, 0x20, // Original IP header start
            0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xf7, 0x67, // More IP header
            0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, // IP addresses
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 8 bytes of original data
        ];

        assert!(matches!(
            TimeExceededMessage::try_from_bytes(&invalid_code_bytes).unwrap_err(),
            TimeExceededMessageError::InvalidCode(_)
        ));

        // [異常系] 不正なIPv4パケット
        let invalid_ipv4_bytes = [
            11,   // Type: Time Exceeded
            0x00, // Code: TTL Exceeded
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x00, // Unused field
            0xFF, 0xFF, 0xFF, 0xFF, // 不正なIPヘッダー
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];

        assert!(matches!(
            TimeExceededMessage::try_from_bytes(&invalid_ipv4_bytes).unwrap_err(),
            TimeExceededMessageError::InvalidOriginalDatagram(_)
        ));
    }

    #[test]
    fn test_time_exceeded_message_into_vec_u8() {
        // [正常系] Vec<u8>への変換
        let original_packet = create_test_ipv4_packet(b"IP header + 64 bits");
        let msg = TimeExceededMessage::new(
            TimeExceededCode::FragmentReassemblyTimeExceeded,
            original_packet,
        )
        .unwrap();

        let bytes: Vec<u8> = msg.into();
        assert_eq!(bytes[0], 11); // Type: Time Exceeded
        assert_eq!(bytes[1], 1); // Code: Fragment Reassembly Time Exceeded
        // bytes[2..4] はchecksum
        assert_eq!(&bytes[4..8], &[0x00, 0x00, 0x00, 0x00]); // Unused field
        // 残りの部分はIPv4パケットのバイナリ表現
    }

    // TimeExceededCode::try_from_bytesのテスト
    #[test]
    fn test_time_exceeded_code_try_from_bytes_invalid_length() {
        // [異常系] 不正なバイト長
        let empty_bytes = [];
        assert!(matches!(
            TimeExceededCode::try_from_bytes(&empty_bytes).unwrap_err(),
            TimeExceededCodeError::InvalidBytesLength(0)
        ));

        let long_bytes = [0, 1];
        assert!(matches!(
            TimeExceededCode::try_from_bytes(&long_bytes).unwrap_err(),
            TimeExceededCodeError::InvalidBytesLength(2)
        ));
    }
}
