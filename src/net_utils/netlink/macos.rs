use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{cmp, io, mem, process, slice};

use libc::{
    AF_INET, AF_INET6, AF_LINK, PF_ROUTE, RTA_DST, RTA_GATEWAY, RTA_IFP, RTAX_DST, RTAX_GATEWAY,
    RTAX_IFP, RTAX_MAX, RTF_GATEWAY, RTF_HOST, RTF_STATIC, RTF_UP, RTM_GET, RTM_VERSION,
    SOCK_DGRAM, SOCK_RAW, c_int, c_ulong, close, in_addr, in6_addr, ioctl, rt_msghdr, sockaddr,
    sockaddr_dl, sockaddr_in, sockaddr_in6, socket,
};
use log::warn;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use super::{IPv6AddressFlags, LinkType, NetlinkError, NetworkInterface, RouteEntry};

const RTM_MSGHDR_LEN: usize = mem::size_of::<rt_msghdr>();
const ATTR_LEN: usize = 128;

// IPv6フラグ関連の定数
const SIOCGIFAFLAG_IN6: c_ulong = 0xc1206949;
const IN6_IFF_DEPRECATED: u32 = 0x0010;
const IN6_IFF_TEMPORARY: u32 = 0x0080;

// インターフェイスのリンクタイプを表す定数
// 定義: https://github.com/openbsd/src/blob/master/sys/net/if_types.h#
const IFT_OTHER: u8 = 1;
const IFT_ETHER: u8 = 6;

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

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy)]
union ifr_ifru {
    ifru_addr: sockaddr_in6,
    ifru_flags6: u32,
}

impl std::fmt::Debug for ifr_ifru {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ifr_ifru")
            .field("ifru_addr", unsafe { &self.ifru_addr })
            .field("ifru_flags6", unsafe { &self.ifru_flags6 })
            .finish()
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct in6_ifreq {
    ifr_name: [i8; 16],
    ifr_ifru: ifr_ifru,
}

impl NetworkInterface {
    pub(super) fn get_ipv6_flags(&self, addr: Ipv6Addr) -> Result<IPv6AddressFlags, NetlinkError> {
        let sock_fd = unsafe { socket(AF_INET6, SOCK_DGRAM, 0) };
        if sock_fd < 0 {
            return Err(NetlinkError::FailedToOpenSocket(io::ErrorKind::Other));
        }

        let mut ifreq = in6_ifreq {
            ifr_name: [0; 16],
            ifr_ifru: ifr_ifru { ifru_flags6: 0 },
        };

        // インターフェース名設定
        let name_bytes = self.name.as_bytes();
        let copy_len = cmp::min(name_bytes.len(), 15);
        for (i, &b) in name_bytes[..copy_len].iter().enumerate() {
            ifreq.ifr_name[i] = b as i8;
        }
        ifreq.ifr_name[copy_len] = 0;

        // IPv6アドレスをsockaddr_in6構造体に設定
        let octets = addr.octets();
        let sa_in6 = sockaddr_in6 {
            sin6_len: mem::size_of::<sockaddr_in6>() as u8,
            sin6_family: AF_INET6 as u8,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: in6_addr { s6_addr: octets },
            sin6_scope_id: 0,
        };
        ifreq.ifr_ifru.ifru_addr = sa_in6;

        let ioctl_result = unsafe { ioctl(sock_fd, SIOCGIFAFLAG_IN6, &mut ifreq) };
        unsafe { close(sock_fd) };

        if ioctl_result < 0 {
            Err(NetlinkError::FailedToGetIfAddrs(nix::Error::last()))
        } else {
            let flags = IPv6AddressFlags {
                deprecated: unsafe { (ifreq.ifr_ifru.ifru_flags6 & IN6_IFF_DEPRECATED) != 0 },
                temporary: unsafe { (ifreq.ifr_ifru.ifru_flags6 & IN6_IFF_TEMPORARY) != 0 },
            };
            Ok(flags)
        }
    }
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

    /// 特定の宛先IPアドレスに対する最適ルートを取得
    pub async fn get_route(&self, target_ip: IpAddr) -> Result<RouteEntry, NetlinkError> {
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
                rtm_rmx: unsafe { mem::zeroed() },
            },
            attrs: [0; ATTR_LEN],
        };
        let mut attr_offset = 0;

        // 宛先IPアドレスの設定
        match target_ip {
            IpAddr::V4(ipv4_addr) => {
                attr_offset = Self::ipv4_to_sockaddr_in_bytes(&mut rt_msg, attr_offset, ipv4_addr);
                Self::ipv4_to_sockaddr_in_bytes(
                    &mut rt_msg,
                    attr_offset + 4,
                    Ipv4Addr::new(0xff, 0xff, 0xff, 0xff),
                );
            }
            IpAddr::V6(ipv6_addr) => {
                attr_offset = Self::ipv6_to_sockaddr_in6_bytes(&mut rt_msg, attr_offset, ipv6_addr);
                Self::ipv6_to_sockaddr_in6_bytes(
                    &mut rt_msg,
                    attr_offset + 4,
                    Ipv6Addr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
                );
            }
        };

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
            .map_err(|e| match e.kind() {
                io::ErrorKind::AddrNotAvailable => NetlinkError::NoRouteToHost,
                io::ErrorKind::NetworkUnreachable => NetlinkError::NoRouteToHost,
                io::ErrorKind::HostUnreachable => NetlinkError::NoRouteToHost,
                _ => {
                    match e.raw_os_error() {
                        // ESRCHの場合、No Route To Hostとして返す
                        Some(3) => NetlinkError::NoRouteToHost,
                        _ => NetlinkError::PfRouteSendError(e.kind()),
                    }
                }
            })?;

        // PF_ROUTEソケットからの応答を受信
        let buf = unsafe {
            slice::from_raw_parts_mut(&rt_msg as *const rt_msg as *mut MaybeUninit<u8>, rt_msg_len)
        };
        let recv_len = self
            .pf_route_sock_fd
            .async_io(Interest::READABLE, |sock| sock.recv(buf))
            .await
            .map_err(|e| match e.kind() {
                io::ErrorKind::AddrNotAvailable => NetlinkError::NoRouteToHost,
                io::ErrorKind::NetworkUnreachable => NetlinkError::NoRouteToHost,
                io::ErrorKind::HostUnreachable => NetlinkError::NoRouteToHost,
                _ => {
                    match e.raw_os_error() {
                        // ESRCHの場合、No Route To Hostとして返す
                        Some(3) => NetlinkError::NoRouteToHost,
                        _ => NetlinkError::PfRouteReceiveError(e.kind()),
                    }
                }
            })?;

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

    /// IPv6アドレスをsockaddr_in6のバイト配列に変換
    fn ipv6_to_sockaddr_in6_bytes(
        rt_msg: &mut rt_msg,
        attr_offset: usize,
        target_ip: Ipv6Addr,
    ) -> usize {
        let sa_len = mem::size_of::<sockaddr_in6>();
        let octets = target_ip.octets();

        let sa_in6 = sockaddr_in6 {
            sin6_len: sa_len as u8,
            sin6_family: AF_INET6 as u8,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: in6_addr { s6_addr: octets },
            sin6_scope_id: 0,
        };
        // sockaddr_in6のバイト配列をコピー
        let sa_ptr = &sa_in6 as *const sockaddr_in6 as *const u8;
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
                        // 宛先IPv4アドレス
                        let dst = unsafe { *(sa as *const sockaddr as *const sockaddr_in) };
                        let dst_addr = Ipv4Addr::from(u32::from_be(dst.sin_addr.s_addr));
                        route_entry.to = IpAddr::V4(dst_addr);
                    }
                    AF_INET6 => {
                        // 宛先IPv6アドレス
                        let dst = unsafe { *(sa as *const sockaddr as *const sockaddr_in6) };
                        let mut addr_bytes = dst.sin6_addr.s6_addr;
                        // リンクローカルアドレスの場合、scope_idが3-4バイト目に格納される
                        // 正規化してscope_idを除去
                        if addr_bytes[0] == 0xfe && (addr_bytes[1] & 0xc0) == 0x80 {
                            addr_bytes[2] = 0x00;
                            addr_bytes[3] = 0x00;
                        }

                        let dst_addr = Ipv6Addr::from(addr_bytes);
                        route_entry.to = IpAddr::V6(dst_addr);
                    }
                    _ => {
                        warn!("Unsupported address family: {}", sa.sa_family)
                    }
                },
                RTAX_GATEWAY => match sa.sa_family as c_int {
                    AF_INET => {
                        // ゲートウェイIPv4アドレス
                        let gateway = unsafe { *(sa as *const sockaddr as *const sockaddr_in) };
                        let gateway_addr = Ipv4Addr::from(u32::from_be(gateway.sin_addr.s_addr));
                        route_entry.via = Some(IpAddr::V4(gateway_addr));
                    }
                    AF_INET6 => {
                        // ゲートウェイIPv6アドレス
                        let gateway = unsafe { *(sa as *const sockaddr as *const sockaddr_in6) };
                        let mut addr_bytes = gateway.sin6_addr.s6_addr;
                        // リンクローカルアドレスの場合、scope_idが3-4バイト目に格納される
                        // 正規化してscope_idを除去
                        if addr_bytes[0] == 0xfe && (addr_bytes[1] & 0xc0) == 0x80 {
                            addr_bytes[2] = 0x00;
                            addr_bytes[3] = 0x00;
                        }

                        let gateway_addr = Ipv6Addr::from(addr_bytes);
                        route_entry.via = Some(IpAddr::V6(gateway_addr));
                    }
                    AF_LINK => {}
                    _ => {
                        warn!("Unsupported address family: {}", sa.sa_family);
                    }
                },
                RTAX_IFP => {
                    let ifp = unsafe { *(sa as *const sockaddr as *const sockaddr_dl) };
                    let iface = self.get_interface_from_index(ifp.sdl_index as u32)?;
                    // LinkType判別ロジック
                    let linktype = if iface.linktype == LinkType::Loopback {
                        LinkType::Loopback
                    } else {
                        match ifp.sdl_type {
                            IFT_ETHER => LinkType::Ethernet, // sockaddr_dl->sdl_typeがIFT_ETHERの場合
                            IFT_OTHER => LinkType::RawIP, // sockaddr_dl->sdl_typeがIFT_OTHERの場合
                            _ => {
                                // その他のリンクタイプはサポートされていない
                                return Err(NetlinkError::UnsupportedLinkType(ifp.sdl_type));
                            }
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
    use tcpip::ethernet::MacAddr;

    use super::*;

    #[tokio::test]
    async fn test_get_route() -> Result<()> {
        // [正常系] IPv4アドレスに対するルート取得
        let netlink = Netlink::new().await?;
        let target_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result = netlink.get_route(target_ip).await;
        assert!(result.is_ok());
        let route_entry = result.unwrap();
        assert_eq!(route_entry.to, target_ip);
        assert!(!route_entry.interface.name.is_empty());

        // [正常系] IPv6アドレスに対するルート取得
        let target_ip_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));
        let result_v6 = netlink.get_route(target_ip_v6).await;
        match result_v6 {
            Ok(route_entry) => {
                assert_eq!(route_entry.to, target_ip_v6);
                assert!(!route_entry.interface.name.is_empty());
            }
            Err(_) => {
                // IPv6が設定されていない環境ではエラーも許容
            }
        }

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

        assert!(new_offset > initial_offset);
        assert_eq!(new_offset, align(mem::size_of::<sockaddr_in>()));

        let sa_in = unsafe { *(rt_msg.attrs.as_ptr() as *const sockaddr_in) };
        assert_eq!(sa_in.sin_family, AF_INET as u8);
        assert_eq!(sa_in.sin_len, mem::size_of::<sockaddr_in>() as u8);
        assert_eq!(u32::from_be(sa_in.sin_addr.s_addr), u32::from(test_ip));

        // [正常系] 異なるオフセットでの変換
        let test_ip2 = Ipv4Addr::new(10, 0, 0, 1);
        let offset2 = Netlink::ipv4_to_sockaddr_in_bytes(&mut rt_msg, 32, test_ip2);
        assert_eq!(offset2, 32 + align(mem::size_of::<sockaddr_in>()));

        Ok(())
    }

    #[test]
    fn test_ipv6_to_sockaddr_in6_bytes() -> Result<()> {
        // [正常系] IPv6アドレスの変換とオフセット計算
        let mut rt_msg = rt_msg {
            hdr: unsafe { std::mem::zeroed() },
            attrs: [0; ATTR_LEN],
        };
        let test_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let initial_offset = 0;

        let new_offset = Netlink::ipv6_to_sockaddr_in6_bytes(&mut rt_msg, initial_offset, test_ip);

        assert!(new_offset > initial_offset);
        assert_eq!(new_offset, align(mem::size_of::<sockaddr_in6>()));

        let sa_in6 = unsafe { *(rt_msg.attrs.as_ptr() as *const sockaddr_in6) };
        assert_eq!(sa_in6.sin6_family, AF_INET6 as u8);
        assert_eq!(sa_in6.sin6_len, mem::size_of::<sockaddr_in6>() as u8);
        assert_eq!(sa_in6.sin6_addr.s6_addr, test_ip.octets());
        assert_eq!(sa_in6.sin6_scope_id, 0);

        // [正常系] リンクローカルアドレスのテスト
        let link_local_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let offset2 = Netlink::ipv6_to_sockaddr_in6_bytes(&mut rt_msg, 32, link_local_ip);
        assert_eq!(offset2, 32 + align(mem::size_of::<sockaddr_in6>()));

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
        let mut rt_msg2 = rt_msg {
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

        let dst_addr2 = sockaddr_in {
            sin_len: mem::size_of::<sockaddr_in>() as u8,
            sin_family: AF_INET as u8,
            sin_port: 0,
            sin_addr: in_addr {
                s_addr: u32::from(Ipv4Addr::new(192, 168, 1, 2)).to_be(),
            },
            sin_zero: [0; 8],
        };

        let dst_bytes2 = unsafe {
            slice::from_raw_parts(
                &dst_addr2 as *const sockaddr_in as *const u8,
                mem::size_of::<sockaddr_in>(),
            )
        };
        rt_msg2.attrs[..dst_bytes2.len()].copy_from_slice(dst_bytes2);

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
        rt_msg2.attrs[offset..offset + gateway_bytes.len()].copy_from_slice(gateway_bytes);

        let test_len2 = RTM_MSGHDR_LEN + offset + mem::size_of::<sockaddr_dl>();
        let result2 = netlink.parse_route_entry_from_rt_msg(&mut rt_msg2, test_len2);
        assert!(result2.is_ok());
        let route_entry2 = result2.unwrap();
        assert_eq!(route_entry2.to, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
        assert!(route_entry2.via.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_get_ipv6_flags() -> Result<(), Box<dyn std::error::Error>> {
        // [正常系] LoopbackアドレスでIPv6フラグ取得のテスト
        let interface = NetworkInterface {
            index: 1,
            name: "lo0".to_string(),
            mac_addr: MacAddr::from([0, 0, 0, 0, 0, 0]),
            ip_addrs: vec![],
            linktype: LinkType::Loopback,
        };

        let loopback_addr = Ipv6Addr::LOCALHOST;
        let result = interface.get_ipv6_flags(loopback_addr);

        match result {
            Ok(flags) => {
                // 成功時はLoopbackアドレスがPermanentであることを確認
                assert!(
                    !flags.deprecated,
                    "Loopback address should not be deprecated"
                );
                assert!(!flags.temporary, "Loopback address should not be temporary");
            }
            Err(e) => {
                // エラーが発生した場合でもテストを続行し、具体的なエラーを確認
                panic!("IPv6フラグ取得に失敗: {e:?}");
            }
        }

        // [異常系] 存在しないインターフェース名でのテスト
        let invalid_interface = NetworkInterface {
            index: 999,
            name: "nonexistent".to_string(),
            mac_addr: MacAddr::from([0, 0, 0, 0, 0, 0]),
            ip_addrs: vec![],
            linktype: LinkType::Ethernet,
        };

        let result = invalid_interface.get_ipv6_flags(loopback_addr);
        assert!(
            result.is_err(),
            "Non-existent interface should return error"
        );

        Ok(())
    }
}
