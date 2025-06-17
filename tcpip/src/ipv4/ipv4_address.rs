use std::net::{AddrParseError, Ipv4Addr};

use thiserror::Error;

use crate::TryFromBytes;
use crate::address::{IntoAddressType, SizedAddress};
use crate::arp::ProtocolType;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IPv4AddressError {
    #[error("Invalid IPv4 address: {0}")]
    InvalidIPv4Address(#[from] AddrParseError),
    #[error("Invalid IPv4 address length. Expected 4 bytes, but got {0} bytes.")]
    InvalidIPv4AddressLength(usize),
}

impl SizedAddress for Ipv4Addr {
    const BITS: u8 = Ipv4Addr::BITS as u8;
}
impl const IntoAddressType<ProtocolType> for Ipv4Addr {
    fn into_address_type() -> ProtocolType {
        ProtocolType::IPv4
    }
}
impl TryFromBytes for Ipv4Addr {
    type Error = IPv4AddressError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let value = value.as_ref();
        let octets: [u8; 4] = value
            .try_into()
            .map_err(|_| IPv4AddressError::InvalidIPv4AddressLength(value.len()))?;
        Ok(Ipv4Addr::from(octets))
    }
}
