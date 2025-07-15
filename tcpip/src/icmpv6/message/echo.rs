use std::net::Ipv6Addr;

use bytes::{BufMut, Bytes, BytesMut};
use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;
use crate::icmpv6::message::Message;
use crate::icmpv6::message_type::ICMPv6MessageType;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EchoMessageError {
    #[error("Invalid echo message type. Expected 128 or 129, but got {0}.")]
    InvalidMessageType(u8),
    #[error("Invalid echo message length. Expected at least 8 bytes, but got {0} bytes.")]
    InvalidMessageLength(usize),
}

/// ICMPv6 Echo Request/Reply メッセージ
///
/// RFC 4443で定義されたEcho Request (Type 128) とEcho Reply (Type 129) のメッセージ構造
/// IPv6版のpingコマンドで使用されるICMPv6メッセージ
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
    /// 新しいEcho Requestメッセージを作成
    pub fn new_request(
        identifier: u16,
        sequence_number: u16,
        data: impl AsRef<[u8]>,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        let mut msg = EchoMessage {
            is_reply: false,
            checksum: 0, // チェックサムは後で計算する
            identifier,
            sequence_number,
            data: Bytes::copy_from_slice(data.as_ref()),
        };
        msg.checksum = msg.calculate_checksum(src, dst);
        msg
    }

    /// 新しいEcho Replyメッセージを作成
    pub fn new_reply(
        identifier: u16,
        sequence_number: u16,
        data: impl AsRef<[u8]>,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        let mut msg = EchoMessage {
            is_reply: true,
            checksum: 0, // チェックサムは後で計算する
            identifier,
            sequence_number,
            data: Bytes::copy_from_slice(data.as_ref()),
        };
        msg.checksum = msg.calculate_checksum(src, dst);
        msg
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
            128 => false,
            129 => true,
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
    fn message_type(&self) -> ICMPv6MessageType {
        match self.is_reply {
            true => ICMPv6MessageType::EchoReply,
            false => ICMPv6MessageType::EchoRequest,
        }
    }

    fn code(&self) -> u8 {
        0 // Echoメッセージにはコードは常に0
    }

    fn total_length(&self) -> usize {
        // 8 bytes for header + data length
        8 + self.data.len()
    }
}

impl From<&EchoMessage> for Bytes {
    fn from(value: &EchoMessage) -> Self {
        let mut bytes = BytesMut::with_capacity(8 + value.data.len());

        // Type (1 byte)
        bytes.put_u8(value.message_type().into());
        // Code (1 byte)
        bytes.put_u8(value.code().into());
        // Checksum (2 bytes)
        bytes.put_u16(value.checksum);
        // Identifier (2 bytes)
        bytes.put_u16(value.identifier);
        // Sequence Number (2 bytes)
        bytes.put_u16(value.sequence_number);
        bytes.extend_from_slice(&value.data);

        bytes.freeze()
    }
}

impl From<EchoMessage> for Bytes {
    fn from(value: EchoMessage) -> Self {
        Bytes::from(&value)
    }
}

impl From<EchoMessage> for Vec<u8> {
    fn from(value: EchoMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

impl From<&EchoMessage> for Vec<u8> {
    fn from(value: &EchoMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_message_creation() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // [正常系] Echo Requestメッセージの作成
        let echo_request = EchoMessage::new_request(0x1234, 0x5678, b"Hello", src, dst);
        assert_eq!(echo_request.message_type(), ICMPv6MessageType::EchoRequest);
        assert_eq!(echo_request.identifier, 0x1234);
        assert_eq!(echo_request.sequence_number, 0x5678);
        assert_eq!(echo_request.data.as_ref(), b"Hello");
        assert_eq!(echo_request.total_length(), 13);

        // [正常系] Echo Replyメッセージの作成
        let echo_reply = EchoMessage::new_reply(0xABCD, 0xEF01, b"World", src, dst);
        assert_eq!(echo_reply.message_type(), ICMPv6MessageType::EchoReply);
        assert_eq!(echo_reply.identifier, 0xABCD);
        assert_eq!(echo_reply.sequence_number, 0xEF01);
        assert_eq!(echo_reply.data.as_ref(), b"World");
        assert_eq!(echo_reply.total_length(), 13);
    }

    #[test]
    fn test_echo_message_try_from_bytes() {
        // [正常系] Echo Request
        let bytes = [
            128, 0, 0, 0, // Type: Echo Request, Code: 0, Checksum: 0
            0x12, 0x34, // Identifier
            0x56, 0x78, // Sequence Number
            0x48, 0x65, 0x6C, 0x6C, 0x6F, // "Hello"
        ];

        let echo = EchoMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(echo.message_type(), ICMPv6MessageType::EchoRequest);
        assert_eq!(echo.identifier, 0x1234);
        assert_eq!(echo.sequence_number, 0x5678);
        assert_eq!(echo.data.as_ref(), b"Hello");

        // [正常系] Echo Reply
        let bytes = [
            129, 0, 0, 0, // Type: Echo Reply, Code: 0, Checksum: 0
            0xAB, 0xCD, // Identifier
            0xEF, 0x01, // Sequence Number
        ];

        let echo = EchoMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(echo.message_type(), ICMPv6MessageType::EchoReply);
        assert_eq!(echo.identifier, 0xABCD);
        assert_eq!(echo.sequence_number, 0xEF01);
        assert_eq!(echo.data, Bytes::new());

        // [異常系] 不正な長さ
        let short_bytes = [128, 0, 0, 0, 0x12, 0x34, 0x56]; // 7バイト（8バイト未満）
        assert!(matches!(
            EchoMessage::try_from_bytes(&short_bytes).unwrap_err(),
            EchoMessageError::InvalidMessageLength(7)
        ));

        // [異常系] 不正なメッセージタイプ
        let invalid_type_bytes = [
            130, 0, 0, 0, // Type: 無効な値（128と129以外）
            0x12, 0x34, // Identifier
            0x56, 0x78, // Sequence Number
        ];
        assert!(matches!(
            EchoMessage::try_from_bytes(&invalid_type_bytes).unwrap_err(),
            EchoMessageError::InvalidMessageType(130)
        ));
    }

    #[test]
    fn test_echo_message_checksum_calculation() {
        // [正常系] ICMPv6チェックサム計算
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let message = EchoMessage::new_request(0x1234, 0x5678, b"test", src, dst);

        assert_ne!(message.checksum, 0); // チェックサムが計算されていることを確認

        // 計算されたチェックサムで検証
        assert!(message.validate_checksum(src, dst));

        // 間違ったソース/デスティネーションでは検証失敗
        let wrong_dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        assert!(!message.validate_checksum(src, wrong_dst));
    }

    #[test]
    fn test_echo_message_round_trip() {
        // [正常系] バイト列変換のラウンドトリップテスト
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let original = EchoMessage::new_request(0x9999, 0xAAAA, b"Round Trip Test", src, dst);

        let bytes: Vec<u8> = original.clone().into();
        let parsed = EchoMessage::try_from_bytes(&bytes).unwrap();

        assert_eq!(original, parsed);
    }
}
