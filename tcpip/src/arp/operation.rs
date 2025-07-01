use std::fmt::{self, Display};

use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OperationError {
    #[error("Invalid operation value: {0}")]
    InvalidValue(u16),
    #[error("Invalid operation bytes length. Expected 2 bytes, but got {0} bytes.")]
    InvalidBytesLength(usize),
}

/// ARPの操作
///
/// - Request: ARPリクエスト
/// - Reply: ARPリプライ
#[derive(Debug, Clone, Copy, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = OperationError, types = [&[u8], [u8; 2], Vec<u8>, Box<[u8]>])]
pub enum Operation {
    /// Request
    /// ARPリクエスト
    Request = 1,

    /// Reply
    /// ARPリプライ
    Reply = 2,
}
impl Operation {
    fn try_from_u16(value: &u16) -> Result<Self, OperationError> {
        match *value {
            1 => Ok(Operation::Request),
            2 => Ok(Operation::Reply),
            value => Err(OperationError::InvalidValue(value)),
        }
    }
}
impl Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operation::Request => write!(f, "ARP Request"),
            Operation::Reply => write!(f, "ARP Reply"),
        }
    }
}
impl TryFromBytes for Operation {
    type Error = OperationError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();
        if bytes.len() != 2 {
            return Err(OperationError::InvalidBytesLength(bytes.len()));
        }

        let value = u16::from_be_bytes([bytes[0], bytes[1]]);
        Self::try_from_u16(&value)
    }
}
impl TryFrom<u16> for Operation {
    type Error = OperationError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::try_from_u16(&value)
    }
}
impl TryFrom<&u16> for Operation {
    type Error = OperationError;

    fn try_from(value: &u16) -> Result<Self, Self::Error> {
        Self::try_from_u16(value)
    }
}
impl From<Operation> for u16 {
    fn from(value: Operation) -> Self {
        value as u16
    }
}
impl From<&Operation> for u16 {
    fn from(value: &Operation) -> Self {
        *value as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_try_from_u16() {
        // [正常系] Request(1)とReply(2)の値から正常に変換
        assert_eq!(Operation::try_from(1u16).unwrap(), Operation::Request);
        assert_eq!(Operation::try_from(2u16).unwrap(), Operation::Reply);

        // [異常系] 無効な値からの変換エラー
        assert!(matches!(
            Operation::try_from(0u16).unwrap_err(),
            OperationError::InvalidValue(0)
        ));
        assert!(matches!(
            Operation::try_from(3u16).unwrap_err(),
            OperationError::InvalidValue(3)
        ));
    }

    #[test]
    fn test_operation_try_from_bytes() {
        // [正常系] 2バイトのRequest/Reply値から正常に変換
        assert_eq!(
            Operation::try_from_bytes(&[0x00, 0x01]).unwrap(),
            Operation::Request
        );
        assert_eq!(
            Operation::try_from_bytes(&[0x00, 0x02]).unwrap(),
            Operation::Reply
        );

        // [異常系] 不正なバイト長
        assert!(matches!(
            Operation::try_from_bytes(&[0x00]).unwrap_err(),
            OperationError::InvalidBytesLength(1)
        ));
        assert!(matches!(
            Operation::try_from_bytes(&[0x00, 0x01, 0x02]).unwrap_err(),
            OperationError::InvalidBytesLength(3)
        ));

        // [異常系] 無効な値
        assert!(matches!(
            Operation::try_from_bytes(&[0x00, 0x00]).unwrap_err(),
            OperationError::InvalidValue(0)
        ));
        assert!(matches!(
            Operation::try_from_bytes(&[0x00, 0x03]).unwrap_err(),
            OperationError::InvalidValue(3)
        ));
    }

    #[test]
    fn test_operation_display() {
        // [正常系] 表示文字列のテスト
        assert_eq!(format!("{}", Operation::Request), "ARP Request");
        assert_eq!(format!("{}", Operation::Reply), "ARP Reply");
    }

    #[test]
    fn test_operation_into_u16() {
        // [正常系] u16への変換
        assert_eq!(u16::from(Operation::Request), 1);
        assert_eq!(u16::from(Operation::Reply), 2);
        assert_eq!(u16::from(&Operation::Request), 1);
        assert_eq!(u16::from(&Operation::Reply), 2);
    }
}
