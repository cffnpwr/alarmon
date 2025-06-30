use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;
use crate::icmp::MessageType;
use crate::icmp::message::Message;
use crate::ipv4::{IPv4Error, IPv4Packet};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParameterProblemMessageError {
    #[error("Invalid parameter problem message type. Expected 12, but got {0}.")]
    InvalidMessageType(u8),
    #[error("Invalid parameter problem code. Expected 0, but got {0}.")]
    InvalidCode(u8),
    #[error(
        "Invalid parameter problem message length. Expected at least 36 bytes, but got {0} bytes."
    )]
    InvalidMessageLength(usize),
    #[error("Original datagram is too short. Expected at least 8 bytes, but got {0} bytes.")]
    OriginalDatagramTooShort(usize),
    #[error(transparent)]
    InvalidOriginalDatagram(#[from] IPv4Error),
}

/// Parameter Problem メッセージ
///
/// RFC 792で定義されたParameter Problem (Type 12) のメッセージ構造
/// IPヘッダーパラメータエラーを通知する
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = ParameterProblemMessageError, types = [&[u8], Vec<u8>, Box<[u8]>])]
pub struct ParameterProblemMessage {
    /// Checksum
    pub checksum: u16,

    /// Pointer
    /// エラーが発生したバイトの位置を示すポインタ
    pub pointer: u8,

    /// Unused field
    /// 未使用フィールド（3バイト、通常はゼロ）
    pub unused: [u8; 3],

    /// Original Datagram
    /// 元のデータグラム（IPヘッダー + 最初の8バイト）
    /// 便宜上[`IPv4Packet`]を使用する
    pub original_datagram: IPv4Packet,
}

impl ParameterProblemMessage {
    /// 新しいParameter Problemメッセージを作成
    pub fn new(
        pointer: u8,
        original_datagram: IPv4Packet,
    ) -> Result<Self, ParameterProblemMessageError> {
        let mut original_datagram = original_datagram;
        // 元のIPパケットからIPv4ヘッダーとデータ部の先頭の64ビット（8バイト）を取得
        if original_datagram.payload.len() < 8 {
            return Err(ParameterProblemMessageError::OriginalDatagramTooShort(
                original_datagram.payload.len(),
            ));
        }
        original_datagram.payload.truncate(8); // 最初の64ビット（8バイト）を使用

        let mut msg = ParameterProblemMessage {
            checksum: 0, // チェックサムは後で計算する
            pointer,
            unused: [0; 3],
            original_datagram,
        };
        msg.checksum = msg.calculate_checksum();

        Ok(msg)
    }
}

impl Message for ParameterProblemMessage {
    fn msg_type(&self) -> u8 {
        MessageType::ParameterProblem.into()
    }

    fn code(&self) -> u8 {
        0 // RFC 792: Parameter Problemのコードは常に0
    }
}

impl TryFromBytes for ParameterProblemMessage {
    type Error = ParameterProblemMessageError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();

        // Parameter Problemメッセージタイプは12
        if bytes[0] != 12 {
            return Err(ParameterProblemMessageError::InvalidMessageType(bytes[0]));
        }
        // Parameter Problemメッセージは36バイト以上
        // Type (1 byte) + Code (1 byte) + Checksum (2 bytes) + Pointer (1 byte) + Unused (3 bytes) + Original Datagram (IPv4 header (20 bytes or more) + 64 bits of data)
        if bytes.len() < 36 {
            return Err(ParameterProblemMessageError::InvalidMessageLength(
                bytes.len(),
            ));
        }

        if bytes[1] != 0 {
            return Err(ParameterProblemMessageError::InvalidCode(bytes[1]));
        }
        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        let pointer = bytes[4];

        let mut unused = [0u8; 3];
        unused.copy_from_slice(&bytes[5..8]);

        let original_datagram = IPv4Packet::try_from(&bytes[8..])?;

        Ok(ParameterProblemMessage {
            checksum,
            pointer,
            unused,
            original_datagram,
        })
    }
}

impl From<ParameterProblemMessage> for Vec<u8> {
    fn from(value: ParameterProblemMessage) -> Self {
        (&value).into()
    }
}

impl From<&ParameterProblemMessage> for Vec<u8> {
    fn from(value: &ParameterProblemMessage) -> Self {
        let mut bytes = Vec::with_capacity(8 + value.original_datagram.len());

        // Type (1 byte)
        bytes.push(MessageType::ParameterProblem.into());
        // Code (1 byte) - RFC 792: Parameter Problemのコードは常に0
        bytes.push(0);
        // Checksum (2 bytes)
        bytes.extend_from_slice(&value.checksum.to_be_bytes());
        // Pointer (1 byte)
        bytes.push(value.pointer);
        // Unused (3 bytes)
        bytes.extend_from_slice(&value.unused);
        // Original Datagram (variable length)
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
    fn test_parameter_problem_message_new() {
        // [正常系] Parameter Problemメッセージの生成
        let original_packet = create_test_ipv4_packet(b"original packet");
        let message = ParameterProblemMessage::new(20, original_packet.clone()).unwrap();
        assert_eq!(message.pointer, 20);
        assert_eq!(message.unused, [0; 3]);
        assert_eq!(message.original_datagram.payload.len(), 8); // 最初の8バイトのみ

        // [異常系] 8バイト未満のペイロードでエラー
        let original_packet = create_test_ipv4_packet(b"1234567"); // 7バイト（8バイト未満）

        let result = ParameterProblemMessage::new(20, original_packet);

        assert!(matches!(
            result,
            Err(ParameterProblemMessageError::OriginalDatagramTooShort(7))
        ));
    }

    #[test]
    fn test_parameter_problem_message_try_from_bytes() {
        // [正常系] 有効なバイト列からのパース
        let bytes = [
            12,   // Type: Parameter Problem
            0x00, // Code: Pointer Indicates Error
            0x00, 0x00, // Checksum
            20,   // Pointer
            0x00, 0x00, 0x00, // Unused
            0x45, 0x00, 0x00, 0x20, // Original IP header start
            0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xf7, 0x67, // More IP header
            0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, // IP addresses
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 8 bytes of original data
        ];

        let message = ParameterProblemMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(message.pointer, 20);
        assert_eq!(message.unused, [0x00, 0x00, 0x00]);

        // [異常系] 不正な長さ
        let short_bytes = [12, 0x00, 0x00, 0x00]; // 4バイト（36バイト未満）

        assert!(matches!(
            ParameterProblemMessage::try_from_bytes(&short_bytes).unwrap_err(),
            ParameterProblemMessageError::InvalidMessageLength(4)
        ));

        // [異常系] 無効なメッセージタイプ
        let bytes = [
            5,    // Type: 5 (不正、Parameter Problemは12)
            0x00, // Code: Pointer Indicates Error
            0x00, 0x00, // Checksum
            20,   // Pointer
            0x00, 0x00, 0x00, // Unused
            0x45, 0x00, 0x00, 0x20, // Original IP header start
            0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xf7, 0x67, // More IP header
            0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, // IP addresses
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 8 bytes of original data
        ];

        assert!(matches!(
            ParameterProblemMessage::try_from_bytes(&bytes).unwrap_err(),
            ParameterProblemMessageError::InvalidMessageType(5)
        ));

        // [異常系] 無効なコード（RFC 792では0のみ有効）
        let bytes = [
            12,   // Type: Parameter Problem
            0x01, // Code: 1 (無効、RFC 792では0のみ)
            0x00, 0x00, // Checksum
            20,   // Pointer
            0x00, 0x00, 0x00, // Unused
            0x45, 0x00, 0x00, 0x20, // Original IP header start
            0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xf7, 0x67, // More IP header
            0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, // IP addresses
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 8 bytes of original data
        ];

        assert!(matches!(
            ParameterProblemMessage::try_from_bytes(&bytes).unwrap_err(),
            ParameterProblemMessageError::InvalidCode(1)
        ));
    }

    #[test]
    fn test_parameter_problem_message_into_vec_u8() {
        // [正常系] Vec<u8>への変換
        let original_packet = create_test_ipv4_packet(b"test data");
        let message = ParameterProblemMessage::new(15, original_packet).unwrap();

        let bytes: Vec<u8> = message.into();
        assert_eq!(bytes[0], 12); // Type: Parameter Problem
        assert_eq!(bytes[1], 0); // Code: Pointer Indicates Error
        // bytes[2..4] はchecksum
        assert_eq!(bytes[4], 15); // Pointer
        assert_eq!(&bytes[5..8], &[0x00, 0x00, 0x00]); // Unused
        // 残りの部分はIPv4パケットのバイナリ表現
    }
}
