use std::net::Ipv4Addr;

use futures::future::{self, Either};
use futures::{FutureExt, StreamExt as _, TryStream, TryStreamExt};
use netlink_packet_core::NLM_F_REQUEST;
use netlink_packet_route::route::{RouteAddress, RouteAttribute};
use rtnetlink::packet_core::NetlinkMessage;
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::route::{RouteMessage, RouteProtocol, RouteScope, RouteType};
use rtnetlink::sys::AsyncSocket as _;
use rtnetlink::{Handle, RouteMessageBuilder, new_connection, try_rtnl};

use super::{NetlinkError, RouteEntry};

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

    pub async fn get_route(&mut self, target_ip: Ipv4Addr) -> Result<RouteEntry, NetlinkError> {
        let builder = RouteMessageBuilder::<Ipv4Addr>::new();
        let req_msg = builder
            .destination_prefix(target_ip, 32)
            .table_id(0) // RT_TABLE_UNSPEC（C言語と同じ）
            .protocol(RouteProtocol::Unspec) // RTPROT_UNSPEC（C言語と同じ）
            .scope(RouteScope::Universe) // RT_SCOPE_UNIVERSE（C言語と同じ）
            .kind(RouteType::Unspec) // RTN_UNSPEC（C言語と同じ）
            .build();

        let mut resp = self.execute_get_route_request(req_msg);
        let resp_msg = resp
            .try_next()
            .await?
            .ok_or(NetlinkError::FailedToGetRouteMessage)?;

        self.parse_route_entry_from_route_msg(resp_msg)
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

    fn parse_route_entry_from_route_msg(
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
                        to = Some(addr);
                    }
                    _ => unimplemented!(),
                },
                RouteAttribute::Gateway(addr) => match addr {
                    RouteAddress::Inet(addr) => {
                        via = Some(addr);
                    }
                    _ => unimplemented!(),
                },
                _ => {}
            }
        }

        let interface = self.get_interface_from_index(iface_index.unwrap_or(0))?;
        let entry = RouteEntry {
            interface,
            to: to.expect("dst address should be set").into(),
            via: via.map(Into::into),
        };

        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use anyhow::Result;

    use super::*;

    #[tokio::test]
    async fn test_get_route() -> Result<()> {
        // [正常系] IPv4アドレスに対するルート取得
        let mut netlink = Netlink::new().await?;

        // ローカルホストへのルート取得をテスト
        // let target_ip = Ipv4Addr::new(1, 1, 1, 1);
        let target_ip = Ipv4Addr::new(10, 88, 0, 1);
        // let target_ip = Ipv4Addr::new(127, 0, 0, 1);
        let result = netlink.get_route(target_ip).await;
        assert!(result.is_ok());
        let route_entry = result.unwrap();
        assert_eq!(route_entry.to, IpAddr::V4(target_ip));
        assert!(!route_entry.interface.name.is_empty());

        Ok(())
    }
}
