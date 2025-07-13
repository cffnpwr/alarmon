use std::io;

use fxhash::FxHashMap;
#[cfg(target_os = "linux")]
use netlink_packet_route::link::LinkLayerType;
use nix::ifaddrs::getifaddrs;
use nix::net::if_::{InterfaceFlags, if_nametoindex};
use tcpip::ethernet::MacAddr;
use tcpip::ip_cidr::{IPCIDR, IPv4CIDR, IPv4Netmask, IPv4NetmaskError};
use thiserror::Error;

use super::{Netlink, NetworkInterface};
use crate::net_utils::netlink::LinkType;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NetlinkError {
    #[error("Failed to get network interfaces: {0}")]
    FailedToGetIfAddrs(#[source] nix::Error),
    #[error("Failed to open socket: {0}")]
    FailedToOpenSocket(io::ErrorKind),
    #[error("No such network interface: index = {0}")]
    NoSuchInterfaceIdx(u32),
    #[error(transparent)]
    InvalidNetmask(#[from] IPv4NetmaskError),
    #[cfg(target_os = "linux")]
    #[allow(clippy::enum_variant_names)]
    #[error(transparent)]
    RTNetlinkError(#[from] rtnetlink::Error),
    #[cfg(target_os = "linux")]
    #[error("Failed to get route message")]
    FailedToGetRouteMessage,
    #[cfg(target_os = "linux")]
    #[error("Unsupported link type: {0}")]
    UnsupportedLinkType(LinkLayerType),
    #[cfg(target_os = "macos")]
    #[error("PF_ROUTE send error: {0}")]
    PfRouteSendError(io::ErrorKind),
    #[cfg(target_os = "macos")]
    #[error("PF_ROUTE receive error: {0}")]
    PfRouteReceiveError(io::ErrorKind),
    #[cfg(target_os = "macos")]
    #[error("Unsupported link type: {0}")]
    UnsupportedLinkType(u8),
}

impl Netlink {
    pub(super) fn get_interfaces(&self) -> Result<Vec<NetworkInterface>, NetlinkError> {
        let ifaddrs = getifaddrs().map_err(NetlinkError::FailedToGetIfAddrs)?;
        let mut interfaces: FxHashMap<String, NetworkInterface> = FxHashMap::default();

        for ifaddr in ifaddrs {
            let iface_name = ifaddr.interface_name.clone();

            // 既存インターフェースを取得または新規作成
            let iface = interfaces.entry(iface_name.clone()).or_insert_with(|| {
                let index = if_nametoindex(iface_name.as_str())
                    .map_err(NetlinkError::FailedToGetIfAddrs)
                    .unwrap_or(0);
                let linktype = if ifaddr.flags.contains(InterfaceFlags::IFF_LOOPBACK) {
                    LinkType::Loopback
                } else {
                    // EthernetとRawIPをここで判別できない
                    LinkType::Ethernet
                };

                NetworkInterface {
                    index,
                    name: iface_name,
                    mac_addr: MacAddr::default(),
                    ip_addrs: Vec::new(),
                    linktype,
                }
            });
            let Some(address) = ifaddr.address else {
                continue;
            };

            // MACアドレスの処理
            if let Some(mac_addr) = address.as_link_addr() {
                if let Some(mac_bytes) = mac_addr.addr() {
                    iface.mac_addr = mac_bytes.into();
                }
                continue;
            }

            // IPv4アドレスの処理
            let Some(ipv4_addr) = address.as_sockaddr_in() else {
                continue;
            };
            let Some(netmask) = ifaddr.netmask else {
                continue;
            };
            let Some(netmask_addr) = netmask.as_sockaddr_in() else {
                continue;
            };
            let Ok(netmask) = IPv4Netmask::try_from(netmask_addr.ip()) else {
                continue;
            };
            let cidr = IPCIDR::V4(IPv4CIDR::new(ipv4_addr.ip(), netmask));
            iface.ip_addrs.push(cidr);
        }

        Ok(interfaces.into_values().collect())
    }

    pub(super) fn get_interface_from_index(
        &self,
        index: u32,
    ) -> Result<NetworkInterface, NetlinkError> {
        let ifaces = self.get_interfaces()?;
        ifaces
            .into_iter()
            .find(|iface| iface.index == index)
            .ok_or(NetlinkError::NoSuchInterfaceIdx(index))
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;

    #[tokio::test]
    async fn test_get_interfaces() -> Result<()> {
        // [正常系] インターフェース一覧の取得
        let netlink = Netlink::new().await?;
        let interfaces = netlink.get_interfaces()?;

        // 最低1つはインターフェースが存在するはず（loopbackなど）
        assert!(!interfaces.is_empty());

        // 各インターフェースの基本的な構造を確認
        for interface in interfaces {
            assert!(!interface.name.is_empty());
            assert!(interface.index > 0);
        }

        Ok(())
    }
}
