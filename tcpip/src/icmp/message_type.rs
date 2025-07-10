use std::fmt::{self, Display};

use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MessageTypeError {
    #[error("Invalid message type value: {0}")]
    InvalidValue(u8),
    #[error("Invalid message type bytes length. Expected 1 byte, but got {0} bytes.")]
    InvalidBytesLength(usize),
}

/// ICMPメッセージタイプ
///
/// RFC 792で定義されたICMPメッセージタイプの定義
#[derive(Debug, Clone, Copy, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = MessageTypeError, types = [&[u8], [u8; 1], Vec<u8>, Box<[u8]>])]
pub enum MessageType {
    /// Echo Reply
    /// Echoリクエストへの応答
    EchoReply = 0,

    /// Destination Unreachable
    /// 宛先到達不可
    DestinationUnreachable = 3,

    /// Redirect
    /// リダイレクト
    Redirect = 5,

    /// Echo
    /// Echoリクエスト
    Echo = 8,

    /// Time Exceeded
    /// TTL超過
    TimeExceeded = 11,

    /// Parameter Problem
    /// パラメータ問題
    ParameterProblem = 12,

    /// Timestamp
    /// タイムスタンプリクエスト
    Timestamp = 13,

    /// Timestamp Reply
    /// タイムスタンプ応答
    TimestampReply = 14,
}

impl MessageType {
    fn try_from_u8(value: &u8) -> Result<Self, MessageTypeError> {
        match *value {
            0 => Ok(MessageType::EchoReply),
            3 => Ok(MessageType::DestinationUnreachable),
            5 => Ok(MessageType::Redirect),
            8 => Ok(MessageType::Echo),
            11 => Ok(MessageType::TimeExceeded),
            12 => Ok(MessageType::ParameterProblem),
            13 => Ok(MessageType::Timestamp),
            14 => Ok(MessageType::TimestampReply),
            value => Err(MessageTypeError::InvalidValue(value)),
        }
    }
}

impl Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageType::EchoReply => write!(f, "Echo Reply"),
            MessageType::DestinationUnreachable => write!(f, "Destination Unreachable"),
            MessageType::Redirect => write!(f, "Redirect"),
            MessageType::Echo => write!(f, "Echo Request"),
            MessageType::TimeExceeded => write!(f, "Time Exceeded"),
            MessageType::ParameterProblem => write!(f, "Parameter Problem"),
            MessageType::Timestamp => write!(f, "Timestamp"),
            MessageType::TimestampReply => write!(f, "Timestamp Reply"),
        }
    }
}

impl TryFromBytes for MessageType {
    type Error = MessageTypeError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, MessageTypeError> {
        let bytes = value.as_ref();
        if bytes.len() != 1 {
            return Err(MessageTypeError::InvalidBytesLength(bytes.len()));
        }

        Self::try_from_u8(&bytes[0])
    }
}

impl TryFrom<u8> for MessageType {
    type Error = MessageTypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::try_from_u8(&value)
    }
}

impl TryFrom<&u8> for MessageType {
    type Error = MessageTypeError;

    fn try_from(value: &u8) -> Result<Self, Self::Error> {
        Self::try_from_u8(value)
    }
}

impl From<MessageType> for u8 {
    fn from(value: MessageType) -> Self {
        value as u8
    }
}

impl From<&MessageType> for u8 {
    fn from(value: &MessageType) -> Self {
        *value as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_try_from_u8() {
        // [正常系] 定義済みの値から正常に変換
        assert_eq!(MessageType::try_from(0u8).unwrap(), MessageType::EchoReply);
        assert_eq!(
            MessageType::try_from(3u8).unwrap(),
            MessageType::DestinationUnreachable
        );
        assert_eq!(MessageType::try_from(8u8).unwrap(), MessageType::Echo);
        assert_eq!(
            MessageType::try_from(11u8).unwrap(),
            MessageType::TimeExceeded
        );

        // [異常系] 未定義の値からの変換エラー
        assert!(matches!(
            MessageType::try_from(1u8).unwrap_err(),
            MessageTypeError::InvalidValue(1)
        ));
        assert!(matches!(
            MessageType::try_from(255u8).unwrap_err(),
            MessageTypeError::InvalidValue(255)
        ));
    }

    #[test]
    fn test_message_type_try_from_bytes() {
        // [正常系] 1バイトの値から正常に変換
        assert_eq!(
            MessageType::try_from_bytes(&[0]).unwrap(),
            MessageType::EchoReply
        );
        assert_eq!(
            MessageType::try_from_bytes(&[8]).unwrap(),
            MessageType::Echo
        );

        // [異常系] 不正なバイト長
        assert!(matches!(
            MessageType::try_from_bytes(&[]).unwrap_err(),
            MessageTypeError::InvalidBytesLength(0)
        ));
        assert!(matches!(
            MessageType::try_from_bytes(&[0, 1]).unwrap_err(),
            MessageTypeError::InvalidBytesLength(2)
        ));

        // [異常系] 未定義の値
        assert!(matches!(
            MessageType::try_from_bytes(&[2]).unwrap_err(),
            MessageTypeError::InvalidValue(2)
        ));
    }

    #[test]
    fn test_message_type_display() {
        // [正常系] 表示文字列のテスト
        assert_eq!(format!("{}", MessageType::EchoReply), "Echo Reply");
        assert_eq!(format!("{}", MessageType::Echo), "Echo Request");
        assert_eq!(
            format!("{}", MessageType::DestinationUnreachable),
            "Destination Unreachable"
        );
        assert_eq!(format!("{}", MessageType::TimeExceeded), "Time Exceeded");
    }

    #[test]
    fn test_message_type_into_u8() {
        // [正常系] u8への変換
        assert_eq!(u8::from(MessageType::EchoReply), 0);
        assert_eq!(u8::from(MessageType::Echo), 8);
        assert_eq!(u8::from(&MessageType::DestinationUnreachable), 3);
        assert_eq!(u8::from(&MessageType::TimeExceeded), 11);
    }
}
