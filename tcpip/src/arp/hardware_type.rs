use std::fmt::{self, Display};

use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HardwareTypeError {
    #[error("Invalid hardware type value: {0}")]
    InvalidValue(u16),
    #[error("Invalid hardware type bytes length. Expected 2 bytes, but got {0} bytes.")]
    InvalidBytesLength(usize),
}

/// Layer 2のプロトコルの種類
///
/// - Ethernet: 1
#[derive(Debug, Clone, Copy, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = HardwareTypeError, types = [&[u8], [u8; 2], Vec<u8>, Box<[u8]>])]
pub enum HardwareType {
    /// Ethernet
    /// イーサネット
    Ethernet = 1,
}
impl HardwareType {
    pub fn address_size(&self) -> u8 {
        match self {
            HardwareType::Ethernet => 6, // Ethernetのアドレス長は6バイト
        }
    }

    fn try_from_u16(value: &u16) -> Result<Self, HardwareTypeError> {
        match *value {
            1 => Ok(HardwareType::Ethernet),
            value => Err(HardwareTypeError::InvalidValue(value)),
        }
    }
}
impl Display for HardwareType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HardwareType::Ethernet => write!(f, "Ethernet"),
        }
    }
}
impl TryFromBytes for HardwareType {
    type Error = HardwareTypeError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, HardwareTypeError> {
        let bytes = value.as_ref();
        if bytes.len() != 2 {
            return Err(HardwareTypeError::InvalidBytesLength(bytes.len()));
        }

        let value = u16::from_be_bytes([bytes[0], bytes[1]]);
        Self::try_from_u16(&value)
    }
}
impl TryFrom<u16> for HardwareType {
    type Error = HardwareTypeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::try_from_u16(&value)
    }
}
impl TryFrom<&u16> for HardwareType {
    type Error = HardwareTypeError;

    fn try_from(value: &u16) -> Result<Self, Self::Error> {
        Self::try_from_u16(value)
    }
}
impl From<HardwareType> for u16 {
    fn from(value: HardwareType) -> Self {
        value as u16
    }
}
impl From<&HardwareType> for u16 {
    fn from(value: &HardwareType) -> Self {
        *value as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardware_type_try_from_u16() {
        // [正常系] Ethernetの値(1)から正常に変換
        assert_eq!(HardwareType::try_from(1u16).unwrap(), HardwareType::Ethernet);
        
        // [異常系] 無効な値からの変換エラー
        assert!(matches!(
            HardwareType::try_from(2u16).unwrap_err(),
            HardwareTypeError::InvalidValue(2)
        ));
        assert!(matches!(
            HardwareType::try_from(0u16).unwrap_err(),
            HardwareTypeError::InvalidValue(0)
        ));
    }

    #[test]
    fn test_hardware_type_try_from_bytes() {
        // [正常系] 2バイトのEthernet値から正常に変換
        let ethernet_bytes = [0x00, 0x01];
        assert_eq!(
            HardwareType::try_from_bytes(&ethernet_bytes).unwrap(),
            HardwareType::Ethernet
        );
        
        // [異常系] 不正なバイト長
        assert!(matches!(
            HardwareType::try_from_bytes(&[0x00]).unwrap_err(),
            HardwareTypeError::InvalidBytesLength(1)
        ));
        assert!(matches!(
            HardwareType::try_from_bytes(&[0x00, 0x01, 0x02]).unwrap_err(),
            HardwareTypeError::InvalidBytesLength(3)
        ));
        
        // [異常系] 無効な値
        assert!(matches!(
            HardwareType::try_from_bytes(&[0x00, 0x02]).unwrap_err(),
            HardwareTypeError::InvalidValue(2)
        ));
    }

    #[test]
    fn test_hardware_type_address_size() {
        // [正常系] Ethernetのアドレスサイズは6バイト
        assert_eq!(HardwareType::Ethernet.address_size(), 6);
    }

    #[test]
    fn test_hardware_type_display() {
        // [正常系] 表示文字列のテスト
        assert_eq!(format!("{}", HardwareType::Ethernet), "Ethernet");
    }

    #[test]
    fn test_hardware_type_into_u16() {
        // [正常系] u16への変換
        assert_eq!(u16::from(HardwareType::Ethernet), 1);
        assert_eq!(u16::from(&HardwareType::Ethernet), 1);
    }
}
