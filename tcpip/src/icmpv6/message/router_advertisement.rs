use std::net::Ipv6Addr;

use bytes::{BufMut, Bytes, BytesMut};
use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;
use crate::icmpv6::message::Message;
use crate::icmpv6::message_type::ICMPv6MessageType;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RouterAdvertisementMessageError {
    #[error(
        "Invalid router advertisement message length. Expected at least 16 bytes, but got {0} bytes."
    )]
    InvalidMessageLength(usize),
}

/// ICMPv6 Router Advertisement メッセージ
///
/// RFC 4861で定義されたRouter Advertisement (Type 134) のメッセージ構造
/// ルーターがRouter Solicitationに応答するか、定期的に送信するメッセージ
///
/// Router Advertisementメッセージは、リンク上のルーターの存在を通知し、
/// ネットワーク設定情報を提供する。
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = RouterAdvertisementMessageError, types = [&[u8], Vec<u8>, Box<[u8]>, bytes::Bytes])]
pub struct RouterAdvertisementMessage {
    /// Current Hop Limit
    /// このルーターから送信されるパケットのHop Limitの初期値
    pub current_hop_limit: u8,

    /// M flag (Managed address configuration)
    /// DHCPv6による自動アドレス設定を使用するかどうか
    pub managed_address_configuration: bool,

    /// O flag (Other configuration)
    /// DHCPv6による自動設定を使用するかどうか（アドレス以外）
    pub other_configuration: bool,

    /// Checksum
    pub checksum: u16,

    /// Router Lifetime
    /// このルーターをデフォルトルーターとして使用できる時間（秒）
    pub router_lifetime: u16,

    /// Reachable Time
    /// 近隣ノードが到達可能と判断する時間（ミリ秒）
    pub reachable_time: u32,

    /// Retrans Timer
    /// 近隣要請メッセージの再送間隔（ミリ秒）
    pub retrans_timer: u32,

    /// Options (variable length)
    /// 可能なオプション:
    /// - Source Link-layer Address (Type 1)
    /// - MTU (Type 5)
    /// - Prefix Information (Type 3)
    /// オプションは8バイト境界でアライメントされる
    pub options: Bytes,
}

impl RouterAdvertisementMessage {
    /// 新しいRouter Advertisementメッセージを作成
    pub fn new(
        current_hop_limit: u8,
        managed_address_configuration: bool,
        other_configuration: bool,
        router_lifetime: u16,
        reachable_time: u32,
        retrans_timer: u32,
        options: impl AsRef<[u8]>,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        let optins = options.as_ref();
        let options = if optins.len() % 8 != 0 {
            let pad_len = 8 - (optins.len() % 8);
            let mut padded_options = BytesMut::with_capacity(optins.len() + pad_len);
            padded_options.extend_from_slice(optins);
            padded_options.resize(optins.len() + pad_len, 0);
            padded_options.freeze()
        } else {
            Bytes::copy_from_slice(optins)
        };

        let mut msg = Self {
            current_hop_limit,
            managed_address_configuration,
            other_configuration,
            checksum: 0, // チェックサムは後で計算する
            router_lifetime,
            reachable_time,
            retrans_timer,
            options,
        };

        msg.checksum = msg.calculate_checksum(src, dst);
        msg
    }
}

impl TryFromBytes for RouterAdvertisementMessage {
    type Error = RouterAdvertisementMessageError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();
        if bytes.len() < 16 {
            return Err(RouterAdvertisementMessageError::InvalidMessageLength(
                bytes.len(),
            ));
        }

        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        let current_hop_limit = bytes[4];
        let flags = bytes[5];
        let managed_address_configuration = (flags & 0x80) != 0;
        let other_configuration = (flags & 0x40) != 0;
        let router_lifetime = u16::from_be_bytes([bytes[6], bytes[7]]);
        let reachable_time = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let retrans_timer = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let options = Bytes::copy_from_slice(&bytes[16..]);

        Ok(RouterAdvertisementMessage {
            current_hop_limit,
            managed_address_configuration,
            other_configuration,
            checksum,
            router_lifetime,
            reachable_time,
            retrans_timer,
            options,
        })
    }
}

impl Message for RouterAdvertisementMessage {
    fn message_type(&self) -> ICMPv6MessageType {
        ICMPv6MessageType::RouterAdvertisement
    }

    fn code(&self) -> u8 {
        0 // Router Advertisement always has code 0
    }

    fn total_length(&self) -> usize {
        // 4 bytes for Type + Code + Checksum + HopLimit(1) + Flags(1) + RouterLifetime(2) + ReachableTime(4) + RetransTimer(4) + Options
        16 + self.options.len()
    }
}

impl From<&RouterAdvertisementMessage> for Bytes {
    fn from(value: &RouterAdvertisementMessage) -> Self {
        let mut data = BytesMut::with_capacity(value.total_length());

        // Type (1 byte)
        data.put_u8(value.message_type().into());
        // Code (1 byte)
        data.put_u8(value.code());
        // Checksum (2 bytes)
        data.put_u16(value.checksum);
        // Current Hop Limit (1 byte)
        data.put_u8(value.current_hop_limit);
        // Flags (1 byte)
        let flags = if value.managed_address_configuration {
            0x80
        } else {
            0
        } | if value.other_configuration { 0x40 } else { 0 };
        data.put_u8(flags);
        // Router Lifetime (2 bytes)
        data.put_u16(value.router_lifetime);
        // Reachable Time (4 bytes)
        data.put_u32(value.reachable_time);
        // Retrans Timer (4 bytes)
        data.put_u32(value.retrans_timer);
        // Options (variable length)
        data.extend_from_slice(value.options.as_ref());

        data.freeze()
    }
}

impl From<RouterAdvertisementMessage> for Bytes {
    fn from(value: RouterAdvertisementMessage) -> Self {
        (&value).into()
    }
}

impl From<RouterAdvertisementMessage> for Vec<u8> {
    fn from(value: RouterAdvertisementMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

impl From<&RouterAdvertisementMessage> for Vec<u8> {
    fn from(value: &RouterAdvertisementMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_advertisement_message_creation() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 2);

        // [正常系] オプションなしのRouter Advertisementメッセージの作成
        let message = RouterAdvertisementMessage::new(
            64,    // current_hop_limit
            true,  // managed_address_configuration
            false, // other_configuration
            1800,  // router_lifetime
            30000, // reachable_time
            1000,  // retrans_timer
            &[],
            src,
            dst,
        );
        assert_eq!(message.current_hop_limit, 64);
        assert!(message.managed_address_configuration);
        assert!(!message.other_configuration);
        assert_eq!(message.router_lifetime, 1800);
        assert_eq!(message.reachable_time, 30000);
        assert_eq!(message.retrans_timer, 1000);
        assert_eq!(message.options, Bytes::new());
        assert_eq!(message.total_length(), 16);

        // [正常系] Source Link-layer Addressオプション付きのメッセージ作成
        let mac_address = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let message = RouterAdvertisementMessage::new(
            64,    // current_hop_limit
            false, // managed_address_configuration
            true,  // other_configuration
            7200,  // router_lifetime
            60000, // reachable_time
            2000,  // retrans_timer
            &mac_address,
            src,
            dst,
        );
        assert_eq!(message.current_hop_limit, 64);
        assert!(!message.managed_address_configuration);
        assert!(message.other_configuration);
        assert_eq!(message.router_lifetime, 7200);
        assert_eq!(message.reachable_time, 60000);
        assert_eq!(message.retrans_timer, 2000);
        assert_eq!(message.options.len(), 8); // optionsの長さは8バイト単位
        assert_eq!(&message.options[..6], &mac_address);
        assert_eq!(message.total_length(), 24);
    }

    #[test]
    fn test_router_advertisement_message_try_from_bytes() {
        // [正常系] オプションなしのメッセージのパース
        let bytes = [
            134, 0, 0, 0,    // Type: 134, Code: 0, Checksum: 0
            64,   // Current Hop Limit: 64
            0x80, // Flags: M=1, O=0
            0x07, 0x08, // Router Lifetime: 1800
            0x00, 0x00, 0x75, 0x30, // Reachable Time: 30000
            0x00, 0x00, 0x03, 0xE8, // Retrans Timer: 1000
        ];

        let message = RouterAdvertisementMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(message.current_hop_limit, 64);
        assert!(message.managed_address_configuration);
        assert!(!message.other_configuration);
        assert_eq!(message.router_lifetime, 1800);
        assert_eq!(message.reachable_time, 30000);
        assert_eq!(message.retrans_timer, 1000);
        assert_eq!(message.options, Bytes::new());

        // [正常系] オプション付きのメッセージのパース
        let bytes = [
            134, 0, 0, 0,    // Type: 134, Code: 0, Checksum: 0
            64,   // Current Hop Limit: 64
            0x40, // Flags: M=0, O=1
            0x1C, 0x20, // Router Lifetime: 7200
            0x00, 0x00, 0xEA, 0x60, // Reachable Time: 60000
            0x00, 0x00, 0x07, 0xD0, // Retrans Timer: 2000
            1, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Source Link-layer Address Option
        ];

        let message = RouterAdvertisementMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(message.current_hop_limit, 64);
        assert!(!message.managed_address_configuration);
        assert!(message.other_configuration);
        assert_eq!(message.router_lifetime, 7200);
        assert_eq!(message.reachable_time, 60000);
        assert_eq!(message.retrans_timer, 2000);
        assert_eq!(message.options.len(), 8);
        assert_eq!(message.options[0], 1); // Type
        assert_eq!(message.options[1], 1); // Length
        assert_eq!(
            &message.options[2..8],
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        );

        // [異常系] 不正な長さ
        let short_bytes = [
            134, 0, 0, 0, 64, 0x80, 0x07, 0x08, 0x00, 0x00, 0x75, 0x30, 0x00, 0x00, 0x03,
        ]; // 15バイト（16バイト未満）
        assert!(matches!(
            RouterAdvertisementMessage::try_from_bytes(&short_bytes).unwrap_err(),
            RouterAdvertisementMessageError::InvalidMessageLength(15)
        ));
    }

    #[test]
    fn test_router_advertisement_message_checksum_calculation() {
        // [正常系] ICMPv6チェックサム計算
        let src = Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 1);
        let message =
            RouterAdvertisementMessage::new(64, false, false, 1800, 30000, 1000, &[], src, dst);

        assert_ne!(message.checksum, 0); // チェックサムが計算されていることを確認

        // 計算されたチェックサムで検証
        assert!(message.validate_checksum(src, dst));

        // 間違った送信元・宛先では検証失敗
        let wrong_dst = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 3);
        assert!(!message.validate_checksum(src, wrong_dst));
    }

    #[test]
    fn test_router_advertisement_message_round_trip() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 2);

        // [正常系] バイト列変換のラウンドトリップテスト - オプションなし
        let original =
            RouterAdvertisementMessage::new(64, true, true, 1800, 30000, 1000, &[], src, dst);

        let bytes: Vec<u8> = original.clone().into();
        let parsed = RouterAdvertisementMessage::try_from_bytes(&bytes).unwrap();

        assert_eq!(original, parsed);

        // [正常系] バイト列変換のラウンドトリップテスト - オプション付き
        let mac_address = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let original = RouterAdvertisementMessage::new(
            64,
            false,
            true,
            7200,
            60000,
            2000,
            &mac_address,
            src,
            dst,
        );

        let bytes: Vec<u8> = original.clone().into();
        let parsed = RouterAdvertisementMessage::try_from_bytes(&bytes).unwrap();

        assert_eq!(original, parsed);
    }
}
