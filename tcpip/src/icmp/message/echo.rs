use bytes::Bytes;
use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;
use crate::icmp::MessageType;
use crate::icmp::message::Message;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EchoMessageError {
    #[error("Invalid echo message type. Expected 8 or 0, but got {0}.")]
    InvalidMessageType(u8),
    #[error("Invalid echo message length. Expected at least 8 bytes, but got {0} bytes.")]
    InvalidMessageLength(usize),
    #[error("Invalid identifier bytes length. Expected 2 bytes, but got {0} bytes.")]
    InvalidIdentifierLength(usize),
    #[error("Invalid sequence number bytes length. Expected 2 bytes, but got {0} bytes.")]
    InvalidSequenceNumberLength(usize),
}

/// Echo Request/Reply メッセージ
///
/// RFC 792で定義されたEcho Request (Type 8) とEcho Reply (Type 0) のメッセージ構造
/// pingコマンドで使用されるICMPメッセージ
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = EchoMessageError, types = [&[u8], Vec<u8>, Box<[u8]>, bytes::Bytes])]
pub struct EchoMessage {
    /// Is reply
    /// Echo RequestかEcho Replyかを示すフラグ
    pub is_reply: bool,

    /// Checksum
    pub checksum: u16,

    /// Identifier
    /// Echo Request/Replyペアを識別するための識別子
    pub identifier: u16,

    /// Sequence Number
    /// Echo Request/Replyのシーケンス番号
    pub sequence_number: u16,

    /// Data
    /// Echoメッセージのデータ部分（可変長）
    pub data: Bytes,
}

impl EchoMessage {
    /// 新しいEchoメッセージを作成
    pub fn new(
        is_reply: bool,
        identifier: u16,
        sequence_number: u16,
        data: impl AsRef<[u8]>,
    ) -> Self {
        let mut msg = EchoMessage {
            is_reply,
            checksum: 0, // チェックサムは後で計算するため、初期値は0
            identifier,
            sequence_number,
            data: Bytes::copy_from_slice(data.as_ref()),
        };

        // チェックサムを計算して設定
        msg.checksum = msg.calculate_checksum();
        msg
    }

    /// 新しいEcho Requestメッセージを作成
    pub fn new_request(identifier: u16, sequence_number: u16, data: impl AsRef<[u8]>) -> Self {
        Self::new(false, identifier, sequence_number, data)
    }

    /// 新しいEcho Replyメッセージを作成
    pub fn new_reply(identifier: u16, sequence_number: u16, data: impl AsRef<[u8]>) -> Self {
        Self::new(true, identifier, sequence_number, data)
    }
}
impl TryFromBytes for EchoMessage {
    type Error = EchoMessageError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();
        if bytes.len() < 8 {
            return Err(EchoMessageError::InvalidMessageLength(bytes.len()));
        }
        let is_reply = match bytes[0] {
            0 => true,  // Echo Reply
            8 => false, // Echo Request
            msg_type => return Err(EchoMessageError::InvalidMessageType(msg_type)),
        };

        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        let identifier = u16::from_be_bytes([bytes[4], bytes[5]]);
        let sequence_number = u16::from_be_bytes([bytes[6], bytes[7]]);
        let data = Bytes::copy_from_slice(&bytes[8..]);

        Ok(EchoMessage {
            is_reply,
            checksum,
            identifier,
            sequence_number,
            data,
        })
    }
}
impl Message for EchoMessage {
    fn msg_type(&self) -> u8 {
        match self.is_reply {
            true => MessageType::EchoReply.into(),
            false => MessageType::Echo.into(),
        }
    }

    fn code(&self) -> u8 {
        0
    }
}

impl From<EchoMessage> for Vec<u8> {
    fn from(value: EchoMessage) -> Self {
        (&value).into()
    }
}

impl From<&EchoMessage> for Vec<u8> {
    fn from(value: &EchoMessage) -> Self {
        let mut bytes = Vec::with_capacity(8 + value.data.len());

        // Type (1 byte)
        bytes.push(value.msg_type());
        // Code (1 byte)
        bytes.push(value.code());
        // Checksum (2 bytes)
        bytes.extend_from_slice(&value.checksum.to_be_bytes());
        // Identifier (2 bytes)
        bytes.extend_from_slice(&value.identifier.to_be_bytes());
        // Sequence Number (2 bytes)
        bytes.extend_from_slice(&value.sequence_number.to_be_bytes());
        // Data (variable length)
        bytes.extend_from_slice(&value.data);

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_message_try_from_bytes() {
        // [正常系] 有効なバイト列からのパース
        let bytes = [
            0x08, // Type: Echo Request
            0x00, // Code: 0
            0x00, 0x00, // Checksum: placeholder
            0x12, 0x34, // Identifier
            0x56, 0x78, // Sequence Number
            0x48, 0x65, 0x6C, 0x6C, 0x6F, // "Hello"
        ];

        let echo = EchoMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(echo.identifier, 0x1234);
        assert_eq!(echo.sequence_number, 0x5678);
        assert_eq!(echo.data.as_ref(), b"Hello");

        // [正常系] 最小サイズ（データなし）のパース
        let bytes = [
            0x08, // Type: Echo Request
            0x00, // Code: 0
            0x00, 0x00, // Checksum: placeholder
            0x12, 0x34, // Identifier
            0x56, 0x78, // Sequence Number
        ];

        let echo = EchoMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(echo.identifier, 0x1234);
        assert_eq!(echo.sequence_number, 0x5678);
        assert_eq!(echo.data, Bytes::new());

        // [異常系] 不正な長さ
        let short_bytes = [0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56]; // 7バイト（8バイト未満）

        assert!(matches!(
            EchoMessage::try_from_bytes(&short_bytes).unwrap_err(),
            EchoMessageError::InvalidMessageLength(7)
        ));

        // [異常系] 不正なメッセージタイプ
        let invalid_type_bytes = [
            0x01, // Type: 無効な値（0と8以外）
            0x00, // Code: 0
            0x00, 0x00, // Checksum: placeholder
            0x12, 0x34, // Identifier
            0x56, 0x78, // Sequence Number
        ];

        assert!(matches!(
            EchoMessage::try_from_bytes(&invalid_type_bytes).unwrap_err(),
            EchoMessageError::InvalidMessageType(1)
        ));
    }

    // Into<Vec<u8>>のテスト
    #[test]
    fn test_echo_message_into_vec_u8() {
        // [正常系] Vec<u8>への変換
        let data = b"Test Data".to_vec();
        let echo = EchoMessage::new(false, 0xABCD, 0xEF01, data.clone());

        let bytes: Vec<u8> = echo.into();

        // チェックサムが正しく計算されることを確認
        assert_eq!(bytes[0], 0x08); // Type: Echo Request
        assert_eq!(bytes[1], 0x00); // Code: 0
        assert_eq!(&bytes[4..6], &[0xAB, 0xCD]); // Identifier
        assert_eq!(&bytes[6..8], &[0xEF, 0x01]); // Sequence Number
        assert_eq!(&bytes[8..], b"Test Data"); // Data

        // チェックサムが計算されている（0以外）ことを確認
        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        assert_ne!(checksum, 0);

        // [正常系] データなしのVec<u8>への変換
        let echo = EchoMessage::new(false, 0x1111, 0x2222, Vec::new());

        let bytes: Vec<u8> = echo.into();

        // チェックサムが正しく計算されることを確認
        assert_eq!(bytes[0], 0x08); // Type: Echo Request
        assert_eq!(bytes[1], 0x00); // Code: 0
        assert_eq!(&bytes[4..6], &[0x11, 0x11]); // Identifier
        assert_eq!(&bytes[6..8], &[0x22, 0x22]); // Sequence Number
        assert_eq!(bytes.len(), 8); // データなし

        // チェックサムが計算されている（0以外）ことを確認
        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        assert_ne!(checksum, 0);

        // [正常系] バイト列変換のラウンドトリップテスト
        let original = EchoMessage::new(false, 0x9999, 0xAAAA, b"Round Trip Test".to_vec());

        let bytes: Vec<u8> = original.clone().into();
        let parsed = EchoMessage::try_from_bytes(&bytes).unwrap();

        // チェックサム以外のフィールドを比較
        assert_eq!(original.is_reply, parsed.is_reply);
        assert_eq!(original.identifier, parsed.identifier);
        assert_eq!(original.sequence_number, parsed.sequence_number);
        assert_eq!(original.data, parsed.data);
    }
}
