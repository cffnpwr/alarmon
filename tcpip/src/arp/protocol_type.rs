use std::fmt::{self, Display};

use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::address::IntoAddressType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProtocolTypeError {
    #[error("Invalid protocol type value: {0:#x}")]
    InvalidValue(u16),
    #[error("Invalid protocol type bytes length. Expected 2 bytes, but got {0} bytes.")]
    InvalidBytesLength(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = ProtocolTypeError, types = [&[u8], [u8; 2], Vec<u8>, Box<[u8]>])]
pub enum ProtocolType {
    /// IPv4
    /// Internet Protocol version 4
    IPv4 = 0x0800,
}
impl ProtocolType {
    pub fn address_size(&self) -> u8 {
        match self {
            ProtocolType::IPv4 => 4, // IPv4のアドレス長は4バイト
        }
    }

    fn try_from_u16(value: &u16) -> Result<Self, ProtocolTypeError> {
        match *value {
            0x0800 => Ok(ProtocolType::IPv4),
            value => Err(ProtocolTypeError::InvalidValue(value)),
        }
    }

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, ProtocolTypeError> {
        let bytes = value.as_ref();
        if bytes.len() != 2 {
            return Err(ProtocolTypeError::InvalidBytesLength(bytes.len()));
        }

        let value = u16::from_be_bytes([bytes[0], bytes[1]]);
        Self::try_from_u16(&value)
    }
}
impl Display for ProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolType::IPv4 => write!(f, "IPv4"),
        }
    }
}
impl TryFrom<u16> for ProtocolType {
    type Error = ProtocolTypeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::try_from_u16(&value)
    }
}
impl TryFrom<&u16> for ProtocolType {
    type Error = ProtocolTypeError;

    fn try_from(value: &u16) -> Result<Self, Self::Error> {
        Self::try_from_u16(value)
    }
}
impl From<ProtocolType> for u16 {
    fn from(value: ProtocolType) -> Self {
        value as u16
    }
}
impl From<&ProtocolType> for u16 {
    fn from(value: &ProtocolType) -> Self {
        *value as u16
    }
}
impl const IntoAddressType<ProtocolType> for ProtocolType {
    fn into_address_type() -> ProtocolType {
        ProtocolType::IPv4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_type_try_from_u16() {
        // [正常系] IPv4の値(0x0800)から正常に変換
        assert_eq!(
            ProtocolType::try_from(0x0800u16).unwrap(),
            ProtocolType::IPv4
        );

        // [異常系] 無効な値からの変換エラー
        assert!(matches!(
            ProtocolType::try_from(0x0000u16).unwrap_err(),
            ProtocolTypeError::InvalidValue(0x0000)
        ));
        assert!(matches!(
            ProtocolType::try_from(0x0806u16).unwrap_err(),
            ProtocolTypeError::InvalidValue(0x0806)
        ));
    }

    #[test]
    fn test_protocol_type_try_from_bytes() {
        // [正常系] 2バイトのIPv4値から正常に変換
        assert_eq!(
            ProtocolType::try_from_bytes(&[0x08, 0x00]).unwrap(),
            ProtocolType::IPv4
        );

        // [異常系] 不正なバイト長
        assert!(matches!(
            ProtocolType::try_from_bytes(&[0x08]).unwrap_err(),
            ProtocolTypeError::InvalidBytesLength(1)
        ));
        assert!(matches!(
            ProtocolType::try_from_bytes(&[0x08, 0x00, 0x00]).unwrap_err(),
            ProtocolTypeError::InvalidBytesLength(3)
        ));

        // [異常系] 無効な値
        assert!(matches!(
            ProtocolType::try_from_bytes(&[0x00, 0x00]).unwrap_err(),
            ProtocolTypeError::InvalidValue(0x0000)
        ));
        assert!(matches!(
            ProtocolType::try_from_bytes(&[0x08, 0x06]).unwrap_err(),
            ProtocolTypeError::InvalidValue(0x0806)
        ));
    }

    #[test]
    fn test_protocol_type_address_size() {
        // [正常系] IPv4のアドレスサイズは4バイト
        assert_eq!(ProtocolType::IPv4.address_size(), 4);
    }

    #[test]
    fn test_protocol_type_display() {
        // [正常系] 表示文字列のテスト
        assert_eq!(format!("{}", ProtocolType::IPv4), "IPv4");
    }

    #[test]
    fn test_protocol_type_into_u16() {
        // [正常系] u16への変換
        assert_eq!(u16::from(ProtocolType::IPv4), 0x0800);
        assert_eq!(u16::from(&ProtocolType::IPv4), 0x0800);
    }
}
