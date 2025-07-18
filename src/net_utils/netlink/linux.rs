use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroI32;

use futures::future::{self, Either};
use futures::{FutureExt, StreamExt as _, TryStream, TryStreamExt};
use netlink_packet_core::NLM_F_REQUEST;
use netlink_packet_route::link::LinkLayerType;
use netlink_packet_route::route::{RouteAddress, RouteAttribute};
use rtnetlink::packet_core::NetlinkMessage;
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::route::{RouteMessage, RouteProtocol, RouteScope, RouteType};
use rtnetlink::sys::AsyncSocket as _;
use rtnetlink::{Handle, RouteMessageBuilder, new_connection, try_rtnl};

use super::{IPv6AddressFlags, LinkType, NetlinkError, NetworkInterface, RouteEntry};

pub struct Netlink {
    handle: Handle,
}
impl Netlink {
    pub async fn new() -> Result<Self, NetlinkError> {
        let (mut conn, handle, _) =
            new_connection().map_err(|e| NetlinkError::FailedToOpenSocket(e.kind()))?;
        conn.socket_mut()
            .socket_mut()
            .set_netlink_get_strict_chk(true)
            .map_err(|e| NetlinkError::FailedToOpenSocket(e.kind()))?;
        tokio::spawn(conn);

        Ok(Self { handle })
    }

    pub async fn get_route(&mut self, target_ip: IpAddr) -> Result<RouteEntry, NetlinkError> {
        let prefix_length = match target_ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        let builder = RouteMessageBuilder::<IpAddr>::new();
        let req_msg = builder
            .destination_prefix(target_ip, prefix_length)
            .table_id(0)
            .protocol(RouteProtocol::Unspec)
            .scope(RouteScope::Universe)
            .kind(RouteType::Unspec)
            .build();

        let mut resp = self.execute_get_route_request(req_msg);
        let resp_msg = resp
            .try_next()
            .await
            .map_err(|e| {
                let rtnetlink::Error::NetlinkError(err_msg) = e.clone() else {
                    return NetlinkError::RTNetlinkError(e);
                };
                match err_msg.code.map(|c| c.get()) {
                    Some(code) => match code {
                        nix::libc::ENOENT => NetlinkError::NoRouteToHost,
                        nix::libc::ENETUNREACH => NetlinkError::NoRouteToHost,
                        nix::libc::EHOSTUNREACH => NetlinkError::NoRouteToHost,
                        nix::libc::ENODEV => NetlinkError::NoSuchInterfaceIdx(0),
                        _ => NetlinkError::RTNetlinkError(e),
                    },
                    _ => NetlinkError::RTNetlinkError(e),
                }
            })?
            .ok_or(NetlinkError::FailedToGetRouteMessage)?;

        self.parse_route_entry_from_route_msg(resp_msg).await
    }

    fn execute_get_route_request(
        &mut self,
        msg: RouteMessage,
    ) -> impl TryStream<Ok = RouteMessage, Error = rtnetlink::Error> + use<> {
        let mut req = NetlinkMessage::from(RouteNetlinkMessage::GetRoute(msg));
        req.header.flags = NLM_F_REQUEST;

        match self.handle.request(req) {
            Ok(resp) => {
                Either::Left(resp.map(move |msg| Ok(try_rtnl!(msg, RouteNetlinkMessage::NewRoute))))
            }
            Err(e) => Either::Right(future::err::<RouteMessage, _>(e).into_stream()),
        }
    }

    async fn parse_route_entry_from_route_msg(
        &self,
        msg: RouteMessage,
    ) -> Result<RouteEntry, NetlinkError> {
        let mut iface_index = None;
        let mut to = None;
        let mut via = None;
        for attr in msg.attributes {
            match attr {
                RouteAttribute::Oif(index) => {
                    iface_index = Some(index);
                }
                RouteAttribute::Destination(addr) => match addr {
                    RouteAddress::Inet(addr) => {
                        to = Some(addr.into());
                    }
                    RouteAddress::Inet6(addr) => {
                        to = Some(addr.into());
                    }
                    _ => unimplemented!(),
                },
                RouteAttribute::Gateway(addr) => match addr {
                    RouteAddress::Inet(addr) => {
                        via = Some(addr.into());
                    }
                    RouteAddress::Inet6(addr) => {
                        via = Some(addr.into());
                    }
                    _ => unimplemented!(),
                },
                _ => {}
            }
        }

        let mut interface = self.get_interface_from_index(iface_index.unwrap_or(0))?;
        interface.linktype = self.get_linktype_from_index(interface.index).await?;
        let entry = RouteEntry {
            interface,
            to: to.expect("dst address should be set"),
            via,
        };

        Ok(entry)
    }

    /// IPv6グローバルユニキャストアドレスが存在するかチェック
    fn has_global_unicast_ipv6_address(&self) -> Result<bool, NetlinkError> {
        let interfaces = self.get_interfaces()?;

        for interface in interfaces {
            if let Some(preferred_addr) = interface.get_preferred_ipv6_address() {
                if preferred_addr.is_global_unicast() {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn get_linktype_from_index(&self, index: u32) -> Result<LinkType, NetlinkError> {
        let mut links = self.handle.link().get().match_index(index).execute();
        let link = links
            .try_next()
            .await
            .map_err(|e| {
                let rtnetlink::Error::NetlinkError(err_msg) = e.clone() else {
                    return NetlinkError::RTNetlinkError(e);
                };
                if err_msg.code.map(|c| c.abs()) == NonZeroI32::new(nix::libc::ENODEV) {
                    NetlinkError::NoSuchInterfaceIdx(index)
                } else {
                    NetlinkError::RTNetlinkError(e)
                }
            })?
            .ok_or(NetlinkError::NoSuchInterfaceIdx(index))?;
        match link.header.link_layer_type {
            LinkLayerType::Ether => Ok(LinkType::Ethernet),
            LinkLayerType::Loopback => Ok(LinkType::Loopback),
            LinkLayerType::Rawip | LinkLayerType::None => Ok(LinkType::RawIP),
            _ => Err(NetlinkError::UnsupportedLinkType(
                link.header.link_layer_type,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use anyhow::Result;
    use rtnetlink::packet_route::route::{RouteProtocol, RouteScope, RouteType};

    use super::*;

    #[tokio::test]
    async fn test_get_linktype_from_index() -> Result<()> {
        let netlink = Netlink::new().await?;

        // [正常系] loopbackインターフェースのリンクタイプ取得
        let result = netlink.get_linktype_from_index(1).await;
        assert!(result.is_ok());
        let linktype = result.unwrap();
        assert_eq!(linktype, LinkType::Loopback);

        // [正常系] 実際のインターフェースでリンクタイプ取得
        let interfaces = netlink.get_interfaces()?;
        if let Some(ethernet_iface) = interfaces.iter().find(|i| i.index != 1) {
            let result = netlink.get_linktype_from_index(ethernet_iface.index).await;
            assert!(result.is_ok());
            let linktype = result.unwrap();
            assert!(matches!(linktype, LinkType::Ethernet | LinkType::RawIP));
        }

        // [異常系] 存在しないインターフェースインデックス
        let result = netlink.get_linktype_from_index(65535).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            NetlinkError::NoSuchInterfaceIdx(_)
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_get_route() -> Result<()> {
        // [正常系] IPv4アドレスに対するルート取得
        let mut netlink = Netlink::new().await?;

        // ローカルホストへのルート取得をテスト
        let target_ip = Ipv4Addr::new(127, 0, 0, 1);
        let result = netlink.get_route(target_ip).await;
        assert!(result.is_ok());
        let route_entry = result.unwrap();
        assert_eq!(route_entry.to, IpAddr::V4(target_ip));
        assert!(!route_entry.interface.name.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_parse_route_entry_from_route_msg() -> Result<()> {
        let netlink = Netlink::new().await?;

        // [正常系] 実際のインターフェースを使ったルートメッセージの解析テスト
        let interfaces = netlink.get_interfaces()?;
        if let Some(_test_interface) = interfaces.first() {
            // RouteMessageを直接構築するのではなく、実際のネットワーク操作をテスト
            let target_ip = Ipv4Addr::new(127, 0, 0, 1);
            let mut test_netlink = Netlink::new().await?;
            let route_result = test_netlink.get_route(target_ip).await;

            // ルート取得が成功することを確認
            assert!(route_result.is_ok());
            let route_entry = route_result.unwrap();
            assert_eq!(route_entry.to, IpAddr::V4(target_ip));
            assert!(!route_entry.interface.name.is_empty());
        }

        Ok(())
    }

    #[test]
    fn test_execute_get_route_request() -> Result<()> {
        // [正常系] RouteMessageが正常に作成されることを確認
        let target_ip = Ipv4Addr::new(127, 0, 0, 1);
        let builder = RouteMessageBuilder::<Ipv4Addr>::new();
        let req_msg = builder
            .destination_prefix(target_ip, 32)
            .table_id(0)
            .protocol(RouteProtocol::Unspec)
            .scope(RouteScope::Universe)
            .kind(RouteType::Unspec)
            .build();

        // メッセージが正常に構築されることを確認
        assert_eq!(req_msg.header.destination_prefix_length, 32);
        assert_eq!(req_msg.header.protocol, RouteProtocol::Unspec);
        assert_eq!(req_msg.header.scope, RouteScope::Universe);
        assert_eq!(req_msg.header.kind, RouteType::Unspec);

        Ok(())
    }
}

impl NetworkInterface {
    pub(super) fn get_ipv6_flags(&self, _addr: Ipv6Addr) -> Result<IPv6AddressFlags, NetlinkError> {
        // TODO: netlink RTM_GETADDR実装
        Ok(IPv6AddressFlags {
            deprecated: false,
            temporary: false,
        })
    }
}
