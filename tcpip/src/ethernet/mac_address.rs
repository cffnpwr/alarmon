use std::fmt::{self, Display};
use std::num::ParseIntError;

use bytes::Bytes;
use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;
use crate::address::{IntoAddressType, SizedAddress};
use crate::arp::HardwareType;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MacAddrError {
    #[error("Invalid MAC address length. Expected 6 bytes, but got {0} bytes.")]
    InvalidMacAddrLength(usize),
    #[error("Failed to parse MAC address: {0}")]
    MacAddrParseError(#[from] ParseIntError),
    #[error("Failed to convert slice to [u8; 6]")]
    SliceToArrayError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = MacAddrError, types = [&[u8], Vec<u8>, Box<[u8]>, Bytes])]
pub struct MacAddr([u8; 6]);
impl SizedAddress for MacAddr {
    const BITS: u8 = 48;
}
impl Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}
impl From<[u8; 6]> for MacAddr {
    fn from(value: [u8; 6]) -> Self {
        MacAddr(value)
    }
}
impl From<&[u8; 6]> for MacAddr {
    fn from(value: &[u8; 6]) -> Self {
        MacAddr(*value)
    }
}
impl TryFromBytes for MacAddr {
    type Error = MacAddrError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let value = value.as_ref();
        if value.len() != 6 {
            return Err(MacAddrError::InvalidMacAddrLength(value.len()));
        }
        value
            .try_into()
            .map(MacAddr)
            .map_err(|_| MacAddrError::SliceToArrayError)
    }
}
impl TryFrom<&str> for MacAddr {
    type Error = MacAddrError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = value.split(':').collect();
        if parts.len() != 6 {
            return Err(MacAddrError::InvalidMacAddrLength(parts.len()));
        }

        let parts = parts
            .iter()
            .map(|part| u8::from_str_radix(part, 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(MacAddrError::MacAddrParseError)?;

        parts.try_into()
    }
}
impl From<MacAddr> for [u8; 6] {
    fn from(value: MacAddr) -> [u8; 6] {
        value.0
    }
}
impl From<&MacAddr> for [u8; 6] {
    fn from(value: &MacAddr) -> [u8; 6] {
        value.0
    }
}
impl const IntoAddressType<HardwareType> for MacAddr {
    fn into_address_type() -> HardwareType {
        HardwareType::Ethernet
    }
}

impl MacAddr {
    /// 未指定MACアドレス (00:00:00:00:00:00)
    pub const UNSPECIFIED: Self = MacAddr([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    /// ブロードキャストMACアドレス (FF:FF:FF:FF:FF:FF)
    pub const BROADCAST: Self = MacAddr([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC_BYTES: [u8; 6] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB];
    const MAC_BYTES_INVALID_SHORT: [u8; 5] = [0x01, 0x23, 0x45, 0x67, 0x89];
    const MAC_BYTES_INVALID_LONG: [u8; 7] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD];
    const MAC_STR: &str = "01:23:45:67:89:ab";
    const MAC_STR_INVALID: &str = "invalid_mac";

    #[test]
    fn test_mac_address_to_string() {
        let mac = MacAddr::from(MAC_BYTES);
        assert_eq!(mac.to_string(), MAC_STR);
    }

    #[test]
    fn test_into_mac_address() {
        // From &[u8; 6]
        let mac = MacAddr::from(&MAC_BYTES);
        assert_eq!(mac.to_string(), MAC_STR);

        // TryFrom &[u8]
        let mac_result = MacAddr::try_from(&MAC_BYTES[..]);
        assert!(mac_result.is_ok());
        assert_eq!(mac_result.unwrap().to_string(), MAC_STR);

        let mac_result = MacAddr::try_from(&MAC_BYTES_INVALID_SHORT[..]);
        assert!(mac_result.is_err());
        assert!(matches!(
            mac_result.unwrap_err(),
            MacAddrError::InvalidMacAddrLength(_)
        ));

        let mac_result = MacAddr::try_from(&MAC_BYTES_INVALID_LONG[..]);
        assert!(mac_result.is_err());
        assert!(matches!(
            mac_result.unwrap_err(),
            MacAddrError::InvalidMacAddrLength(_)
        ));

        // TryFrom Vec<u8>
        let mac_result = MacAddr::try_from(MAC_BYTES.to_vec());
        assert!(mac_result.is_ok());
        assert_eq!(mac_result.unwrap().to_string(), MAC_STR);

        let mac_result = MacAddr::try_from(MAC_BYTES_INVALID_SHORT.to_vec());
        assert!(mac_result.is_err());
        assert!(matches!(
            mac_result.unwrap_err(),
            MacAddrError::InvalidMacAddrLength(_)
        ));

        let mac_result = MacAddr::try_from(MAC_BYTES_INVALID_LONG.to_vec());
        assert!(mac_result.is_err());
        assert!(matches!(
            mac_result.unwrap_err(),
            MacAddrError::InvalidMacAddrLength(_)
        ));

        // TryFrom &str
        let mac_result = MacAddr::try_from(MAC_STR);
        assert!(mac_result.is_ok());
        assert_eq!(mac_result.unwrap().to_string(), MAC_STR);

        let mac_result = MacAddr::try_from(MAC_STR_INVALID);
        assert!(mac_result.is_err());
        assert!(matches!(
            mac_result.unwrap_err(),
            MacAddrError::InvalidMacAddrLength(_)
        ));
    }

    #[test]
    fn test_from_mac_address() {
        let mac = MacAddr::from(MAC_BYTES);

        // Into [u8; 6]
        let mac_bytes: [u8; 6] = mac.into();
        assert_eq!(mac_bytes, MAC_BYTES);
    }
}
