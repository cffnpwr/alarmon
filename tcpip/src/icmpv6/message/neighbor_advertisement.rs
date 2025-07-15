use std::net::Ipv6Addr;

use bytes::{BufMut, Bytes, BytesMut};
use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;
use crate::icmpv6::message::Message;
use crate::icmpv6::message_type::ICMPv6MessageType;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NeighborAdvertisementMessageError {
    #[error("Invalid neighbor advertisement message type. Expected 136, but got {0}.")]
    InvalidMessageType(u8),
    #[error(
        "Invalid neighbor advertisement message length. Expected at least 24 bytes, but got {0} bytes."
    )]
    InvalidMessageLength(usize),
}

/// ICMPv6 Neighbor Advertisement メッセージ
///
/// RFC 4861で定義されたNeighbor Advertisement (Type 136) のメッセージ構造
/// Neighbor Solicitationへの応答として送信されるメッセージ
///
/// Neighbor Advertisementメッセージは、近隣ノードのリンクレイヤアドレスを通知し、
/// 到達可能性を確認するために使用される。
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = NeighborAdvertisementMessageError, types = [&[u8], Vec<u8>, Box<[u8]>, bytes::Bytes])]
pub struct NeighborAdvertisementMessage {
    /// R flag (Router)
    /// 送信者がルーターかどうか
    pub router: bool,

    /// S flag (Solicited)
    /// このAdvertisementがSolicitationに対する応答かどうか
    pub solicited: bool,

    /// O flag (Override)
    /// 既存のキャッシュエントリを上書きするかどうか
    pub override_flag: bool,

    /// Checksum
    pub checksum: u16,

    /// Reserved field (29 bits)
    /// MUST: 送信時は0で埋める必要がある
    /// MUST: 受信側には無視される必要がある
    pub reserved: u32,

    /// Target Address
    /// 対象となるIPv6アドレス
    pub target_address: Ipv6Addr,

    /// Options (variable length)
    /// 可能なオプション:
    /// - Target Link-layer Address (Type 2)
    /// オプションは8バイト境界でアライメントされる
    pub options: Bytes,
}

impl NeighborAdvertisementMessage {
    /// 新しいNeighbor Advertisementメッセージを作成
    pub fn new(
        router: bool,
        solicited: bool,
        override_flag: bool,
        target_address: Ipv6Addr,
        options: impl AsRef<[u8]>,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        let mut msg = Self {
            router,
            solicited,
            override_flag,
            checksum: 0, // チェックサムは後で計算する
            reserved: 0,
            target_address,
            options: Bytes::copy_from_slice(options.as_ref()),
        };

        msg.checksum = msg.calculate_checksum(src, dst);
        msg
    }
}

impl TryFromBytes for NeighborAdvertisementMessage {
    type Error = NeighborAdvertisementMessageError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();
        if bytes.len() < 24 {
            return Err(NeighborAdvertisementMessageError::InvalidMessageLength(
                bytes.len(),
            ));
        }

        if bytes[0] != 136 {
            return Err(NeighborAdvertisementMessageError::InvalidMessageType(
                bytes[0],
            ));
        }

        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        let flags = bytes[4];
        let router = (flags & 0x80) != 0;
        let solicited = (flags & 0x40) != 0;
        let override_flag = (flags & 0x20) != 0;

        // Reserved field (29 bits) - flagsと一緒に4バイトで格納されている
        let reserved_bytes = [bytes[4], bytes[5], bytes[6], bytes[7]];
        let reserved = u32::from_be_bytes(reserved_bytes) & 0x1FFFFFFF; // 29ビットをマスク

        let target_address = Ipv6Addr::from([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        let options = Bytes::copy_from_slice(&bytes[24..]);

        Ok(NeighborAdvertisementMessage {
            router,
            solicited,
            override_flag,
            checksum,
            reserved,
            target_address,
            options,
        })
    }
}

impl Message for NeighborAdvertisementMessage {
    fn message_type(&self) -> ICMPv6MessageType {
        ICMPv6MessageType::NeighborAdvertisement
    }

    fn code(&self) -> u8 {
        0 // Neighbor Advertisement always has code 0
    }

    fn total_length(&self) -> usize {
        // 4 bytes for Type + Code + Checksum + 4 bytes flags + 16 bytes target address + options
        24 + self.options.len()
    }
}

impl From<&NeighborAdvertisementMessage> for Bytes {
    fn from(value: &NeighborAdvertisementMessage) -> Self {
        let mut data = BytesMut::with_capacity(value.total_length());

        // Type (1 byte)
        data.put_u8(value.message_type().into());
        // Code (1 byte)
        data.put_u8(value.code());
        // Checksum (2 bytes)
        data.put_u16(value.checksum);
        // Flags and Reserved (4 bytes total)
        let flags = if value.router { 0x80 } else { 0 }
            | if value.solicited { 0x40 } else { 0 }
            | if value.override_flag { 0x20 } else { 0 };
        let flags_and_reserved = ((flags as u32) << 24) | (value.reserved & 0x1FFFFFFF);
        data.put_u32(flags_and_reserved);
        // Target Address (16 bytes)
        data.extend_from_slice(&value.target_address.octets());
        // Options (variable length)
        data.extend_from_slice(value.options.as_ref());

        data.freeze()
    }
}

impl From<NeighborAdvertisementMessage> for Bytes {
    fn from(value: NeighborAdvertisementMessage) -> Self {
        (&value).into()
    }
}

impl From<NeighborAdvertisementMessage> for Vec<u8> {
    fn from(value: NeighborAdvertisementMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

impl From<&NeighborAdvertisementMessage> for Vec<u8> {
    fn from(value: &NeighborAdvertisementMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_neighbor_advertisement_message_creation() {
        let target_address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // [正常系] オプションなしのNeighbor Advertisementメッセージの作成
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let message = NeighborAdvertisementMessage::new(
            true,  // router
            true,  // solicited
            false, // override
            target_address,
            &[], // no options
            src,
            dst,
        );
        assert!(message.router);
        assert!(message.solicited);
        assert!(!message.override_flag);
        assert_eq!(message.target_address, target_address);
        assert_eq!(message.options, Bytes::new());
        assert_eq!(message.total_length(), 24);

        // [正常系] Target Link-layer Addressオプション付きのメッセージ作成
        let mac_address = [2, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]; // Type, Length, MAC
        let message = NeighborAdvertisementMessage::new(
            false, // router
            true,  // solicited
            true,  // override
            target_address,
            &mac_address,
            src,
            dst,
        );
        assert!(!message.router);
        assert!(message.solicited);
        assert!(message.override_flag);
        assert_eq!(message.target_address, target_address);
        assert_eq!(message.options.len(), 8);
        assert_eq!(message.options[0], 2); // Type
        assert_eq!(message.options[1], 1); // Length
        assert_eq!(
            &message.options[2..8],
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        );
        assert_eq!(message.total_length(), 32);
    }

    #[test]
    fn test_neighbor_advertisement_message_try_from_bytes() {
        let target_address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // [正常系] オプションなしのメッセージのパース
        let bytes = [
            136, 0, 0, 0, // Type: 136, Code: 0, Checksum: 0
            0xE0, 0, 0, 0, // Flags: R=1, S=1, O=1, Reserved
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, // Target Address: 2001:db8::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];

        let message = NeighborAdvertisementMessage::try_from_bytes(&bytes).unwrap();
        assert!(message.router);
        assert!(message.solicited);
        assert!(message.override_flag);
        assert_eq!(message.target_address, target_address);
        assert_eq!(message.options, Bytes::new());

        // [正常系] オプション付きのメッセージのパース
        let bytes = [
            136, 0, 0, 0, // Type: 136, Code: 0, Checksum: 0
            0x40, 0, 0, 0, // Flags: R=0, S=1, O=0, Reserved
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, // Target Address: 2001:db8::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 2, 1, 0x00, 0x11, 0x22, 0x33, 0x44,
            0x55, // Target Link-layer Address Option
        ];

        let message = NeighborAdvertisementMessage::try_from_bytes(&bytes).unwrap();
        assert!(!message.router);
        assert!(message.solicited);
        assert!(!message.override_flag);
        assert_eq!(message.target_address, target_address);
        assert_eq!(message.options.len(), 8);
        assert_eq!(message.options[0], 2); // Type
        assert_eq!(message.options[1], 1); // Length
        assert_eq!(
            &message.options[2..8],
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        );

        // [異常系] 不正な長さ
        let short_bytes = [
            136, 0, 0, 0, // Type: 136, Code: 0, Checksum: 0
            0x40, 0, 0, 0, // Flags: R=0, S=1, O=0, Reserved
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00,
            0x00, // Target Address: 2001:db8::1 (incomplete)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 23バイト（24バイト未満）
        ];
        assert!(matches!(
            NeighborAdvertisementMessage::try_from_bytes(&short_bytes).unwrap_err(),
            NeighborAdvertisementMessageError::InvalidMessageLength(23)
        ));
    }

    #[test]
    fn test_neighbor_advertisement_message_checksum_calculation() {
        let target_address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // [正常系] ICMPv6チェックサム計算
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 1);
        let message = NeighborAdvertisementMessage::new(
            false, // router
            true,  // solicited
            true,  // override
            target_address,
            &[], // no options
            src,
            dst,
        );

        assert_ne!(message.checksum, 0); // チェックサムが計算されていることを確認

        // 計算されたチェックサムで検証
        assert!(message.validate_checksum(src, dst));

        // 間違った送信元・宛先では検証失敗
        let wrong_dst = Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 2);
        assert!(!message.validate_checksum(src, wrong_dst));
    }

    #[test]
    fn test_neighbor_advertisement_message_round_trip() {
        let target_address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // [正常系] バイト列変換のラウンドトリップテスト - オプションなし
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let original = NeighborAdvertisementMessage::new(
            true,  // router
            false, // solicited
            true,  // override
            target_address,
            &[], // no options
            src,
            dst,
        );

        let bytes: Vec<u8> = original.clone().into();
        let parsed = NeighborAdvertisementMessage::try_from_bytes(&bytes).unwrap();

        assert_eq!(original, parsed);

        // [正常系] バイト列変換のラウンドトリップテスト - オプション付き
        let mac_address = [2, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]; // Type, Length, MAC
        let original = NeighborAdvertisementMessage::new(
            false, // router
            true,  // solicited
            true,  // override
            target_address,
            &mac_address,
            src,
            dst,
        );

        let bytes: Vec<u8> = original.clone().into();
        let parsed = NeighborAdvertisementMessage::try_from_bytes(&bytes).unwrap();

        assert_eq!(original, parsed);
    }
}
