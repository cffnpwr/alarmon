use std::fmt::{self, Display};

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Error)]
pub enum EtherTypeError {
    #[error("Unsupported EtherType")]
    UnsupportedEtherType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EtherType {
    IPv4 = 0x0800,
    ARP = 0x0806,
    RARP = 0x8035,
    IPv6 = 0x86DD,
    VLAN = 0x8100,
    QinQ = 0x88A8,
}
impl Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EtherType::IPv4 => write!(f, "IPv4"),
            EtherType::ARP => write!(f, "ARP"),
            EtherType::RARP => write!(f, "RARP"),
            EtherType::IPv6 => write!(f, "IPv6"),
            EtherType::VLAN => write!(f, "VLAN"),
            EtherType::QinQ => write!(f, "QinQ"),
        }
    }
}
impl TryFrom<u16> for EtherType {
    type Error = EtherTypeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0800 => Ok(EtherType::IPv4),
            0x0806 => Ok(EtherType::ARP),
            0x8035 => Ok(EtherType::RARP),
            0x86DD => Ok(EtherType::IPv6),
            0x8100 => Ok(EtherType::VLAN),
            0x88A8 => Ok(EtherType::QinQ),
            _ => Err(EtherTypeError::UnsupportedEtherType),
        }
    }
}
impl TryFrom<&[u8; 2]> for EtherType {
    type Error = EtherTypeError;

    fn try_from(value: &[u8; 2]) -> Result<Self, Self::Error> {
        let value = u16::from_be_bytes(*value);
        EtherType::try_from(value)
    }
}
impl TryFrom<&[u8]> for EtherType {
    type Error = EtherTypeError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 2 {
            return Err(EtherTypeError::UnsupportedEtherType);
        }
        let value = u16::from_be_bytes([value[0], value[1]]);
        EtherType::try_from(value)
    }
}
impl TryFrom<Vec<u8>> for EtherType {
    type Error = EtherTypeError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 2 {
            return Err(EtherTypeError::UnsupportedEtherType);
        }
        let value = u16::from_be_bytes([value[0], value[1]]);
        EtherType::try_from(value)
    }
}
impl From<EtherType> for u16 {
    fn from(val: EtherType) -> Self {
        val as u16
    }
}
impl From<EtherType> for [u8; 2] {
    fn from(value: EtherType) -> Self {
        let value = value as u16;
        value.to_be_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_into_ether_type() {
        // TryFrom u16
        let ether_type = EtherType::try_from(0x0800);
        assert!(ether_type.is_ok());
        assert_eq!(ether_type.unwrap(), EtherType::IPv4);

        let ether_type = EtherType::try_from(0x0806);
        assert!(ether_type.is_ok());
        assert_eq!(ether_type.unwrap(), EtherType::ARP);

        let ether_type = EtherType::try_from(0x8035);
        assert!(ether_type.is_ok());
        assert_eq!(ether_type.unwrap(), EtherType::RARP);

        let ether_type = EtherType::try_from(0x86DD);
        assert!(ether_type.is_ok());
        assert_eq!(ether_type.unwrap(), EtherType::IPv6);

        let ether_type = EtherType::try_from(0x8100);
        assert!(ether_type.is_ok());
        assert_eq!(ether_type.unwrap(), EtherType::VLAN);

        let ether_type = EtherType::try_from(0x88A8);
        assert!(ether_type.is_ok());
        assert_eq!(ether_type.unwrap(), EtherType::QinQ);

        let ether_type = EtherType::try_from(0x1234);
        assert!(ether_type.is_err());
        assert_eq!(
            ether_type.unwrap_err(),
            EtherTypeError::UnsupportedEtherType
        );

        // TryFrom &[u8; 2]
        let ether_type = EtherType::try_from(&[0x08, 0x00]);
        assert!(ether_type.is_ok());
        assert_eq!(ether_type.unwrap(), EtherType::IPv4);

        // TryFrom &[u8]
        let ether_type = EtherType::try_from(&[0x08, 0x00][..]);
        assert!(ether_type.is_ok());
        assert_eq!(ether_type.unwrap(), EtherType::IPv4);

        let ether_type = EtherType::try_from(&[0x12, 0x34, 0x56][..]);
        assert!(ether_type.is_err());
        assert_eq!(
            ether_type.unwrap_err(),
            EtherTypeError::UnsupportedEtherType
        );

        // TryFrom Vec<u8>
        let ether_type = EtherType::try_from(vec![0x08, 0x00]);
        assert!(ether_type.is_ok());
        assert_eq!(ether_type.unwrap(), EtherType::IPv4);

        let ether_type = EtherType::try_from(vec![0x12, 0x34, 0x56]);
        assert!(ether_type.is_err());
        assert_eq!(
            ether_type.unwrap_err(),
            EtherTypeError::UnsupportedEtherType
        );
    }

    #[test]
    fn test_from_ether_type() {
        let ether_type = EtherType::IPv4;

        // Into u16
        let ether_type_value: u16 = ether_type.clone().into();
        assert_eq!(ether_type_value, 0x0800);

        // Into [u8; 2]
        let ether_type_bytes: [u8; 2] = ether_type.clone().into();
        assert_eq!(ether_type_bytes, [0x08, 0x00]);
    }
}
