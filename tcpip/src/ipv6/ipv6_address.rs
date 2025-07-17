use std::net::Ipv6Addr;

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
}
