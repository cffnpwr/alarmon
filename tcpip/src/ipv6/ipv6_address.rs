use std::net::Ipv6Addr;

use crate::ethernet::MacAddr;

/// IPv6アドレスタイプ判定用のヘルパー関数
pub trait IPv6AddrExt {
    /// IPv6アドレスがグローバルユニキャストアドレス（2000::/3）かを判定
    fn is_global_unicast(&self) -> bool;

    /// IPv6アドレスがリンクローカルアドレス（fe80::/10）かを判定
    fn is_link_local(&self) -> bool;

    /// IPv6アドレスがプライベートアドレス（fc00::/7）かを判定
    #[allow(dead_code)]
    fn is_unique_local(&self) -> bool;

    /// IPv6アドレスがルーティングに適したアドレスかを判定
    /// グローバルユニキャストアドレスまたはユニークローカルアドレスを優先
    #[allow(dead_code)]
    fn is_routable(&self) -> bool;

    /// RFC 4291: IPv6のSolicited-Node Multicast MACアドレス計算
    /// 33:33:xx:xx:xx:xx の形式で、下位24bitはIPv6アドレスの下位24bit
    fn into_multicast_mac(&self) -> MacAddr;

    /// RFC 4291: IPv6のSolicited-Node Multicastアドレス計算
    /// ff02::1:ffxx:xxxx の形式で、下位24bitはIPv6アドレスの下位24bit
    fn into_multicast_ipv6(&self) -> Ipv6Addr;
}

impl IPv6AddrExt for Ipv6Addr {
    fn is_global_unicast(&self) -> bool {
        let octets = self.octets();
        // グローバルユニキャストアドレスは2000::/3の範囲
        (octets[0] & 0xe0) == 0x20
    }

    fn is_link_local(&self) -> bool {
        let octets = self.octets();
        // リンクローカルアドレスはfe80::/10の範囲
        octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
    }

    fn is_unique_local(&self) -> bool {
        let octets = self.octets();
        // ユニークローカルアドレスはfc00::/7の範囲
        (octets[0] & 0xfe) == 0xfc
    }

    fn is_routable(&self) -> bool {
        self.is_global_unicast() || self.is_unique_local()
    }

    fn into_multicast_mac(&self) -> MacAddr {
        let octets = self.octets();
        let mut mac_bytes = [0u8; 6];
        mac_bytes[0] = 0x33;
        mac_bytes[1] = 0x33;
        mac_bytes[2] = octets[12];
        mac_bytes[3] = octets[13];
        mac_bytes[4] = octets[14];
        mac_bytes[5] = octets[15];

        MacAddr::from(mac_bytes)
    }

    fn into_multicast_ipv6(&self) -> Ipv6Addr {
        let octets = self.octets();
        Ipv6Addr::new(
            0xff02,
            0x0000,
            0x0000,
            0x0000,
            0x0000,
            0x0001,
            0xff00 | (octets[13] as u16),
            (octets[14] as u16) << 8 | (octets[15] as u16),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_into_multicast_mac() {
        // [正常系] Solicited-Node Multicast MACアドレスの計算
        let target_ip = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let result = target_ip.into_multicast_mac();

        // 33:33:xx:xx:xx:xx の形式で、下位24bitはIPv6アドレスの下位24bit
        let expected = MacAddr::from([0x33, 0x33, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_into_multicast_ipv6() {
        // [正常系] Solicited-Node Multicast IPv6アドレスの計算
        let target_ip = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let result = target_ip.into_multicast_ipv6();

        // ff02::1:ffxx:xxxx の形式で、下位24bitはIPv6アドレスの下位24bit
        let expected = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x0001);
        assert_eq!(result, expected);
    }
}
