use std::fmt::Display;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Error)]
pub enum MacAddrError {
    #[error("Invalid MAC address")]
    InvalidMacAddr,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MacAddr([u8; 6]);
impl Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
impl TryFrom<&[u8]> for MacAddr {
    type Error = MacAddrError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 6 {
            return Err(MacAddrError::InvalidMacAddr);
        }
        value
            .try_into()
            .map(MacAddr)
            .map_err(|_| MacAddrError::InvalidMacAddr)
    }
}
impl TryFrom<Vec<u8>> for MacAddr {
    type Error = MacAddrError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 6 {
            return Err(MacAddrError::InvalidMacAddr);
        }
        value.as_slice().try_into()
    }
}
impl TryFrom<&str> for MacAddr {
    type Error = MacAddrError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = value.split(':').collect();
        if parts.len() != 6 {
            return Err(MacAddrError::InvalidMacAddr);
        }

        let parts = parts
            .iter()
            .map(|part| u8::from_str_radix(part, 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|_| MacAddrError::InvalidMacAddr)?;

        parts.try_into()
    }
}
impl From<MacAddr> for [u8; 6] {
    fn from(value: MacAddr) -> [u8; 6] {
        value.0
    }
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
        assert_eq!(mac_result.unwrap_err(), MacAddrError::InvalidMacAddr);

        let mac_result = MacAddr::try_from(&MAC_BYTES_INVALID_LONG[..]);
        assert!(mac_result.is_err());
        assert_eq!(mac_result.unwrap_err(), MacAddrError::InvalidMacAddr);

        // TryFrom Vec<u8>
        let mac_result = MacAddr::try_from(MAC_BYTES.to_vec());
        assert!(mac_result.is_ok());
        assert_eq!(mac_result.unwrap().to_string(), MAC_STR);

        let mac_result = MacAddr::try_from(MAC_BYTES_INVALID_SHORT.to_vec());
        assert!(mac_result.is_err());
        assert_eq!(mac_result.unwrap_err(), MacAddrError::InvalidMacAddr);

        let mac_result = MacAddr::try_from(MAC_BYTES_INVALID_LONG.to_vec());
        assert!(mac_result.is_err());
        assert_eq!(mac_result.unwrap_err(), MacAddrError::InvalidMacAddr);

        // TryFrom &str
        let mac_result = MacAddr::try_from(MAC_STR);
        assert!(mac_result.is_ok());
        assert_eq!(mac_result.unwrap().to_string(), MAC_STR);

        let mac_result = MacAddr::try_from(MAC_STR_INVALID);
        assert!(mac_result.is_err());
        assert_eq!(mac_result.unwrap_err(), MacAddrError::InvalidMacAddr);
    }

    #[test]
    fn test_from_mac_address() {
        let mac = MacAddr::from(MAC_BYTES);

        // Into [u8; 6]
        let mac_bytes: [u8; 6] = mac.into();
        assert_eq!(mac_bytes, MAC_BYTES);
    }
}
