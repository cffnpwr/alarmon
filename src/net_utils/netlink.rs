use tcpip::ethernet::MacAddr;
use tcpip::ip_cidr::IPCIDR;
use thiserror::Error;

#[cfg(target_os = "macos")]
#[path = "./netlink/macos.rs"]
mod backend;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetworkInterface {
    pub(crate) index: u32,
    pub(crate) name: String,
    pub(crate) mac_addr: MacAddr,
    pub(crate) ip_addrs: Vec<IPCIDR>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum NetlinkError {
    #[error(transparent)]
    FailedToGetIfAddrs(#[from] nix::Error),
}

pub(crate) struct Netlink {
    inner: backend::Netlink,
}
impl Netlink {
    pub(crate) fn new() -> Self {
        Netlink {
            inner: backend::Netlink::new(),
        }
    }

    pub(crate) fn get_interfaces(&self) -> Result<Vec<NetworkInterface>, NetlinkError> {
        self.inner.get_interfaces()
    }
}
