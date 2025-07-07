use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LinkTypeError {
    #[error("Invalid linktype")]
    InvalidLinkType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Loopback,
    Ethernet,
    RawIP,
}
#[cfg(feature = "libpcap")]
impl TryFrom<libpcap::Linktype> for LinkType {
    type Error = LinkTypeError;

    fn try_from(value: libpcap::Linktype) -> Result<Self, Self::Error> {
        match value {
            libpcap::Linktype::NULL => Ok(LinkType::Loopback),
            libpcap::Linktype::ETHERNET => Ok(LinkType::Ethernet),
            libpcap::Linktype::RAW => Ok(LinkType::RawIP),
            _ => Err(LinkTypeError::InvalidLinkType),
        }
    }
}
