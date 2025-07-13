use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr};
use std::{mem, process, slice};

use fxhash::FxHashMap;
use libc::{
    AF_INET, AF_LINK, PF_ROUTE, RTA_DST, RTA_GATEWAY, RTA_IFP, RTAX_DST, RTAX_GATEWAY, RTAX_IFP,
    RTAX_MAX, RTF_GATEWAY, RTF_HOST, RTF_STATIC, RTF_UP, RTM_GET, RTM_VERSION, SOCK_RAW, c_int,
    in_addr, rt_msghdr, sockaddr, sockaddr_dl, sockaddr_in,
};
use nix::ifaddrs::getifaddrs;
use nix::net::if_::if_nametoindex;
use socket2::{Domain, Protocol, Socket, Type};
use tcpip::ethernet::MacAddr;
use tcpip::ip_cidr::{IPCIDR, IPv4CIDR, IPv4Netmask};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use super::{LinkType, NetlinkError, NetworkInterface, RouteEntry};

const RTM_MSGHDR_LEN: usize = mem::size_of::<rt_msghdr>();
const ATTR_LEN: usize = 128;

// インターフェイスのリンクタイプを表す定数
// 定義: https://github.com/openbsd/src/blob/master/sys/net/if_types.h#
const IFT_OTHER: u8 = 1;
const IFT_ETHER: u8 = 6;
const IFT_LOOP: u8 = 24;

#[inline]
const fn align(len: usize) -> usize {
    const NLA_ALIGNTO: usize = 4;
    (len + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
}
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct rt_msg {
    hdr: rt_msghdr,
    attrs: [u8; ATTR_LEN],
}

pub struct Netlink {
    pf_route_sock_fd: AsyncFd<Socket>,
}
impl Netlink {
    // NOTE: Linuxとの互換性のため非同期関数
    pub async fn new() -> Result<Self, NetlinkError> {
        let sock = Socket::new(
            Domain::from(PF_ROUTE),
            Type::from(SOCK_RAW),
            Some(Protocol::from(0)),
        )
        .map_err(|e| NetlinkError::FailedToOpenSocket(e.kind()))?;
        sock.set_nonblocking(true)
            .map_err(|e| NetlinkError::FailedToOpenSocket(e.kind()))?;
        let fd = AsyncFd::new(sock).map_err(|e| NetlinkError::FailedToOpenSocket(e.kind()))?;

        Ok(Netlink {
            pf_route_sock_fd: fd,
        })
    }

    fn get_interface_from_sockaddr_dl(
        &self,
        addr: &sockaddr_dl,
    ) -> Result<NetworkInterfaceInner, NetlinkError> {
        let index = addr.sdl_index as u32;
        let ifaces = self.get_interfaces()?;
        ifaces
            .into_iter()
            .find(|iface| iface.index == index)
            .ok_or(NetlinkError::NoSuchInterfaceIdx(index))
    }

    /// 特定の宛先IPアドレスに対する最適ルートを取得
    pub async fn get_route(&self, target_ip: Ipv4Addr) -> Result<RouteEntry, NetlinkError> {
        // PF_ROUTEで送信するデータ
        let mut rt_msg = rt_msg {
            hdr: rt_msghdr {
                rtm_msglen: RTM_MSGHDR_LEN as u16,
                rtm_version: RTM_VERSION as u8,
                rtm_type: RTM_GET as u8,
                rtm_index: 0,
                rtm_flags: RTF_UP | RTF_STATIC | RTF_GATEWAY | RTF_HOST,
                rtm_addrs: RTA_DST | RTA_IFP | RTA_GATEWAY,
                rtm_pid: process::id() as i32,
                rtm_seq: 1,
                rtm_errno: 0,
                rtm_use: 0,
                rtm_inits: 0,
                rtm_rmx: libc::rt_metrics {
                    rmx_locks: 0,
                    rmx_mtu: 0,
                    rmx_hopcount: 0,
                    rmx_expire: 0,
                    rmx_recvpipe: 0,
                    rmx_sendpipe: 0,
                    rmx_ssthresh: 0,
                    rmx_rtt: 0,
                    rmx_rttvar: 0,
                    rmx_pksent: 0,
                    rmx_state: 0,
                    rmx_filler: [0, 0, 0],
                },
            },
            attrs: [0; ATTR_LEN],
        };
        let mut attr_offset = 0;

        // 宛先IPアドレスの設定
        attr_offset = Self::ipv4_to_sockaddr_in_bytes(&mut rt_msg, attr_offset, target_ip);
        // ネットマスクの設定
        Self::ipv4_to_sockaddr_in_bytes(
            &mut rt_msg,
            attr_offset + 4,
            Ipv4Addr::new(255, 255, 255, 255),
        );
        let rt_msg_len = RTM_MSGHDR_LEN + ATTR_LEN;
        rt_msg.hdr.rtm_msglen = rt_msg_len as u16;

        // PF_ROUTEソケットにメッセージを送信
        let buf =
            unsafe { slice::from_raw_parts(&rt_msg as *const rt_msg as *const u8, rt_msg_len) };

        self.pf_route_sock_fd
            .async_io(Interest::WRITABLE, |sock| {
                sock.send(buf)?;
                Ok(())
            })
            .await
            .map_err(|e| NetlinkError::PfRouteSendError(e.kind()))?;

        // PF_ROUTEソケットからの応答を受信
        let buf = unsafe {
            slice::from_raw_parts_mut(&rt_msg as *const rt_msg as *mut MaybeUninit<u8>, rt_msg_len)
        };
        let recv_len = self
            .pf_route_sock_fd
            .async_io(Interest::READABLE, |sock| sock.recv(buf))
            .await
            .map_err(|e| NetlinkError::PfRouteReceiveError(e.kind()))?;

        self.parse_route_entry_from_rt_msg(&mut rt_msg, recv_len)
    }

    /// IPv4アドレスをsockaddr_inのバイト配列に変換
    fn ipv4_to_sockaddr_in_bytes(
        rt_msg: &mut rt_msg,
        attr_offset: usize,
        target_ip: Ipv4Addr,
    ) -> usize {
        let sa_len = mem::size_of::<sockaddr_in>();
        let sa_in = sockaddr_in {
            sin_len: sa_len as u8,
            sin_family: AF_INET as u8,
            sin_port: 0,
            sin_addr: in_addr {
                s_addr: u32::from(target_ip).to_be(),
            },
            sin_zero: [0; 8],
        };
        // sockaddr_inのバイト配列をコピー
        let sa_ptr = &sa_in as *const sockaddr_in as *const u8;
        let sa_bytes = unsafe { slice::from_raw_parts(sa_ptr, sa_len) };
        rt_msg.attrs[attr_offset..attr_offset + sa_len].copy_from_slice(sa_bytes);
        attr_offset + align(sa_len)
    }

    /// rt_msgからルートエントリを解析
    fn parse_route_entry_from_rt_msg(
        &self,
        rt_msg: &mut rt_msg,
        len: usize,
    ) -> Result<RouteEntry, NetlinkError> {
        let rtm_addrs = rt_msg.hdr.rtm_addrs;
        let mut payload = rt_msg.attrs[..len - RTM_MSGHDR_LEN].as_mut();

        let mut linktype = None;
        let mut route_entry = RouteEntry::default();
        for i in 0..RTAX_MAX {
            if (rtm_addrs & (1 << i)) == 0 {
                continue; // このアドレスは存在しない
            }

            let sa = unsafe { &*payload.as_ptr().cast::<sockaddr>() };
            let mut sa_len = sa.sa_len as usize;
            if sa_len == 0 {
                sa_len = 4; // sockaddr_inの最小サイズ
            }
            match i {
                RTAX_DST => match sa.sa_family as c_int {
                    AF_INET => {
                        // 宛先IPアドレス
                        let dst = unsafe { *(sa as *const sockaddr as *const sockaddr_in) };
                        let dst_addr = Ipv4Addr::from(u32::from_be(dst.sin_addr.s_addr));
                        route_entry.to = IpAddr::V4(dst_addr);
                    }
                    _ => unimplemented!("Unsupported address family: {}", sa.sa_family),
                },
                RTAX_GATEWAY => match sa.sa_family as c_int {
                    AF_INET => {
                        // ゲートウェイIPアドレス
                        let gateway = unsafe { *(sa as *const sockaddr as *const sockaddr_in) };
                        let gateway_addr = Ipv4Addr::from(u32::from_be(gateway.sin_addr.s_addr));
                        route_entry.via = Some(IpAddr::V4(gateway_addr));
                        linktype = Some(LinkType::Ethernet);
                    }
                    AF_LINK => {
                        linktype = Some(LinkType::RawIP);
                    }
                    _ => unimplemented!("Unsupported address family: {}", sa.sa_family),
                },
                RTAX_IFP => {
                    let ifp = unsafe { *(sa as *const sockaddr as *const sockaddr_dl) };
                    let iface = self.get_interface_from_sockaddr_dl(&ifp)?;
                    // LinkType判別ロジック
                    let linktype = match (ifp.sdl_type, linktype) {
                        (IFT_ETHER, _) => LinkType::Ethernet, // sockaddr_dl->sdl_typeがIFT_ETHERの場合
                        (IFT_LOOP, _) => LinkType::Loopback, // sockaddr_dl->sdl_typeがIFT_LOOPの場合
                        (IFT_OTHER, Some(LinkType::RawIP)) => LinkType::RawIP, // sockaddr_dl->sdl_typeがIFT_OTHERでLinkTypeがRawIPの場合
                        _ => {
                            // その他のリンクタイプはサポートされていない
                            return Err(NetlinkError::UnsupportedLinkType(ifp.sdl_type));
                        }
                    };

                    route_entry.interface = NetworkInterface {
                        index: iface.index,
                        name: iface.name,
                        mac_addr: iface.mac_addr,
                        linktype,
                        ip_addrs: iface.ip_addrs,
                    };
                }
                _ => {} // 他のアドレスタイプは無視
            }

            payload = &mut payload[align(sa_len)..];
        }
        Ok(route_entry)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;

    #[tokio::test]
    async fn test_get_interface_from_sockaddr_dl() -> Result<()> {
        let netlink = Netlink::new().await?;
        let interfaces = netlink.get_interfaces()?;

        // [正常系] 存在するインデックスでインターフェース取得
        if let Some(first_interface) = interfaces.first() {
            let addr = sockaddr_dl {
                sdl_len: mem::size_of::<sockaddr_dl>() as u8,
                sdl_family: AF_LINK as u8,
                sdl_index: first_interface.index as u16,
                sdl_type: 0,
                sdl_nlen: 0,
                sdl_alen: 0,
                sdl_slen: 0,
                sdl_data: [0; 12],
            };
            let interface = netlink.get_interface_from_sockaddr_dl(&addr)?;
            assert_eq!(interface.index, first_interface.index);
        }

        // [異常系] 存在しないインデックスでNoSuchInterfaceIdxエラー
        let addr = sockaddr_dl {
            sdl_len: mem::size_of::<sockaddr_dl>() as u8,
            sdl_family: AF_LINK as u8,
            sdl_index: 65535,
            sdl_type: 0,
            sdl_nlen: 0,
            sdl_alen: 0,
            sdl_slen: 0,
            sdl_data: [0; 12],
        };
        let result = netlink.get_interface_from_sockaddr_dl(&addr);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, NetlinkError::NoSuchInterfaceIdx(65535)));
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_get_route() -> Result<()> {
        // [正常系] IPv4アドレスに対するルート取得
        let netlink = Netlink::new().await?;

        // ローカルホストへのルート取得をテスト
        let target_ip = Ipv4Addr::new(127, 0, 0, 1);
        let result = netlink.get_route(target_ip).await;
        assert!(result.is_ok());
        let route_entry = result.unwrap();
        assert_eq!(route_entry.to, IpAddr::V4(target_ip));
        assert!(!route_entry.interface.name.is_empty());

        Ok(())
    }

    #[test]
    fn test_ipv4_to_sockaddr_in_bytes() -> Result<()> {
        // [正常系] IPv4アドレスの変換とオフセット計算
        let mut rt_msg = rt_msg {
            hdr: unsafe { std::mem::zeroed() },
            attrs: [0; ATTR_LEN],
        };

        let test_ip = Ipv4Addr::new(192, 168, 1, 1);
        let initial_offset = 0;

        let new_offset = Netlink::ipv4_to_sockaddr_in_bytes(&mut rt_msg, initial_offset, test_ip);

        // オフセットが適切に計算されているか確認
        assert!(new_offset > initial_offset);
        assert_eq!(new_offset, align(mem::size_of::<sockaddr_in>()));

        // sockaddr_inの構造が正しく設定されているか確認
        let sa_in = unsafe { *(rt_msg.attrs.as_ptr() as *const sockaddr_in) };
        assert_eq!(sa_in.sin_family, AF_INET as u8);
        assert_eq!(sa_in.sin_len, mem::size_of::<sockaddr_in>() as u8);
        assert_eq!(u32::from_be(sa_in.sin_addr.s_addr), u32::from(test_ip));

        // [正常系] 異なるIPアドレスでの変換テスト
        let test_ip2 = Ipv4Addr::new(10, 0, 0, 1);
        let offset2 = Netlink::ipv4_to_sockaddr_in_bytes(&mut rt_msg, 32, test_ip2);

        assert_eq!(offset2, 32 + align(mem::size_of::<sockaddr_in>()));

        let sa_in2 = unsafe { *((rt_msg.attrs.as_ptr() as usize + 32) as *const sockaddr_in) };
        assert_eq!(u32::from_be(sa_in2.sin_addr.s_addr), u32::from(test_ip2));

        Ok(())
    }

    #[tokio::test]
    async fn test_parse_route_entry_from_rt_msg() -> Result<()> {
        let netlink = Netlink::new().await?;

        // [正常系] RTAX_DSTのみの場合
        let mut rt_msg = rt_msg {
            hdr: rt_msghdr {
                rtm_msglen: RTM_MSGHDR_LEN as u16,
                rtm_version: RTM_VERSION as u8,
                rtm_type: RTM_GET as u8,
                rtm_index: 0,
                rtm_flags: RTF_UP,
                rtm_addrs: RTA_DST,
                rtm_pid: 0,
                rtm_seq: 0,
                rtm_errno: 0,
                rtm_use: 0,
                rtm_inits: 0,
                rtm_rmx: unsafe { std::mem::zeroed() },
            },
            attrs: [0; ATTR_LEN],
        };

        // 宛先アドレス（192.168.1.1）を設定
        let dst_addr = sockaddr_in {
            sin_len: mem::size_of::<sockaddr_in>() as u8,
            sin_family: AF_INET as u8,
            sin_port: 0,
            sin_addr: in_addr {
                s_addr: u32::from(Ipv4Addr::new(192, 168, 1, 1)).to_be(),
            },
            sin_zero: [0; 8],
        };

        let dst_bytes = unsafe {
            slice::from_raw_parts(
                &dst_addr as *const sockaddr_in as *const u8,
                mem::size_of::<sockaddr_in>(),
            )
        };
        rt_msg.attrs[..dst_bytes.len()].copy_from_slice(dst_bytes);

        let test_len = RTM_MSGHDR_LEN + mem::size_of::<sockaddr_in>();
        let result = netlink.parse_route_entry_from_rt_msg(&mut rt_msg, test_len);
        assert!(result.is_ok());
        let route_entry = result.unwrap();
        assert_eq!(route_entry.to, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(route_entry.via.is_none());

        // [正常系] RTAX_GATEWAYでAF_LINKの場合
        let mut rt_msg = rt_msg {
            hdr: rt_msghdr {
                rtm_msglen: RTM_MSGHDR_LEN as u16,
                rtm_version: RTM_VERSION as u8,
                rtm_type: RTM_GET as u8,
                rtm_index: 0,
                rtm_flags: RTF_UP,
                rtm_addrs: RTA_DST | RTA_GATEWAY,
                rtm_pid: 0,
                rtm_seq: 0,
                rtm_errno: 0,
                rtm_use: 0,
                rtm_inits: 0,
                rtm_rmx: unsafe { std::mem::zeroed() },
            },
            attrs: [0; ATTR_LEN],
        };

        // 宛先アドレス（192.168.1.2）を設定
        let dst_addr = sockaddr_in {
            sin_len: mem::size_of::<sockaddr_in>() as u8,
            sin_family: AF_INET as u8,
            sin_port: 0,
            sin_addr: in_addr {
                s_addr: u32::from(Ipv4Addr::new(192, 168, 1, 2)).to_be(),
            },
            sin_zero: [0; 8],
        };

        let dst_bytes = unsafe {
            slice::from_raw_parts(
                &dst_addr as *const sockaddr_in as *const u8,
                mem::size_of::<sockaddr_in>(),
            )
        };
        rt_msg.attrs[..dst_bytes.len()].copy_from_slice(dst_bytes);

        // AF_LINKゲートウェイアドレスを設定
        let offset = align(mem::size_of::<sockaddr_in>());
        let gateway_addr = sockaddr_dl {
            sdl_len: mem::size_of::<sockaddr_dl>() as u8,
            sdl_family: AF_LINK as u8,
            sdl_index: 1,
            sdl_type: 0,
            sdl_nlen: 0,
            sdl_alen: 6,
            sdl_slen: 0,
            sdl_data: [0; 12],
        };

        let gateway_bytes = unsafe {
            slice::from_raw_parts(
                &gateway_addr as *const sockaddr_dl as *const u8,
                mem::size_of::<sockaddr_dl>(),
            )
        };
        rt_msg.attrs[offset..offset + gateway_bytes.len()].copy_from_slice(gateway_bytes);

        let test_len = RTM_MSGHDR_LEN + offset + mem::size_of::<sockaddr_dl>();
        let result = netlink.parse_route_entry_from_rt_msg(&mut rt_msg, test_len);
        assert!(result.is_ok());
        let route_entry = result.unwrap();
        assert_eq!(route_entry.to, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
        assert!(route_entry.via.is_none());

        Ok(())
    }
}
