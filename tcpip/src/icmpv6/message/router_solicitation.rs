use std::net::Ipv6Addr;

use bytes::{BufMut, Bytes, BytesMut};
use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;
use crate::checksum::calculate_internet_checksum;
use crate::icmpv6::message::Message;
use crate::icmpv6::message_type::ICMPv6MessageType;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RouterSolicitationMessageError {
    #[error(
        "Invalid router solicitation message length. Expected at least 8 bytes, but got {0} bytes."
    )]
    InvalidMessageLength(usize),
}

/// ICMPv6 Router Solicitation メッセージ
///
/// RFC 4861で定義されたRouter Solicitation (Type 133) のメッセージ構造
/// ホストがリンク上のルーターを発見するために送信するメッセージ
///
/// Router Solicitationメッセージは、ホストがリンク上のルーターを発見するために送信される。
/// ルーターはRouter Advertisementメッセージで応答する。
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = RouterSolicitationMessageError, types = [&[u8], Vec<u8>, Box<[u8]>, bytes::Bytes])]
pub struct RouterSolicitationMessage {
    /// Checksum
    pub checksum: u16,

    /// Reserved field (32 bits)
    /// MUST: 送信時は0で埋める必要がある
    /// MUST: 受信側には無視される必要がある
    pub reserved: u32,

    /// Options (variable length)
    /// 可能なオプション:
    /// - Source Link-layer Address (Type 1)
    /// オプションは8バイト境界でアライメントされる
    pub options: Bytes,
}

impl RouterSolicitationMessage {
    /// 新しいRouter Solicitationメッセージを作成
    pub fn new(
        options: impl AsRef<[u8]>,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        let mut msg = Self {
            checksum: 0, // チェックサムは後で計算する
            reserved: 0,
            options: Bytes::copy_from_slice(options.as_ref()),
        };

        msg.checksum = msg.calculate_checksum(src, dst);
        msg
    }

    /// ICMPv6チェックサムを計算する
    pub fn calculate_checksum(&self, src: impl Into<Ipv6Addr>, dst: impl Into<Ipv6Addr>) -> u16 {
        let src = src.into();
        let dst = dst.into();
        let mut packet_data = Vec::new();

        // Type (1 byte)
        packet_data.push(self.message_type().into());
        // Code (1 byte)
        packet_data.push(self.code());
        // Checksum (2 bytes) - チェックサム計算時は0で埋める
        packet_data.extend_from_slice(&[0, 0]);
        // Reserved (4 bytes)
        packet_data.extend_from_slice(&self.reserved.to_be_bytes());
        // Options
        packet_data.extend_from_slice(self.options.as_ref());

        calculate_icmpv6_checksum(src, dst, &packet_data)
    }

    /// ICMPv6チェックサムを検証する
    pub fn validate_checksum(&self, src: impl Into<Ipv6Addr>, dst: impl Into<Ipv6Addr>) -> bool {
        let calculated_checksum = self.calculate_checksum(src, dst);
        self.checksum == calculated_checksum
    }
}

impl TryFromBytes for RouterSolicitationMessage {
    type Error = RouterSolicitationMessageError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();
        if bytes.len() < 8 {
            return Err(RouterSolicitationMessageError::InvalidMessageLength(
                bytes.len(),
            ));
        }

        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        let reserved = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let options = Bytes::copy_from_slice(&bytes[8..]);

        Ok(RouterSolicitationMessage {
            checksum,
            reserved,
            options,
        })
    }
}

impl Message for RouterSolicitationMessage {
    fn message_type(&self) -> ICMPv6MessageType {
        ICMPv6MessageType::RouterSolicitation
    }

    fn code(&self) -> u8 {
        0 // Router Solicitation always has code 0
    }

    fn total_length(&self) -> usize {
        // 4 bytes for Type + Code + Checksum + 4 bytes reserved + options
        8 + self.options.len()
    }
}

/// ICMPv6チェックサム計算
///
/// IPv6疑似ヘッダーを含むICMPv6チェックサムを計算します。
/// RFC 4443 Section 2.3に準拠した実装です。
fn calculate_icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, icmp_packet: &[u8]) -> u16 {
    let mut checksum_data = Vec::new();

    // IPv6疑似ヘッダー
    checksum_data.extend_from_slice(&src.octets()); // Source Address (128 bits)
    checksum_data.extend_from_slice(&dst.octets()); // Destination Address (128 bits)
    checksum_data.extend_from_slice(&(icmp_packet.len() as u32).to_be_bytes()); // ICMPv6 Length (32 bits)
    checksum_data.extend_from_slice(&[0, 0, 0, 58]); // Next Header = 58 (ICMPv6) (32 bits)

    // ICMPv6メッセージ
    checksum_data.extend_from_slice(icmp_packet);

    calculate_internet_checksum(&checksum_data)
}

impl From<&RouterSolicitationMessage> for Bytes {
    fn from(value: &RouterSolicitationMessage) -> Self {
        let mut data = BytesMut::with_capacity(value.total_length());

        // Type (1 byte)
        data.put_u8(value.message_type().into());
        // Code (1 byte)
        data.put_u8(value.code());
        // Checksum (2 bytes)
        data.put_u16(value.checksum);
        // Reserved (4 bytes)
        data.put_u32(value.reserved);
        // Options (variable length)
        data.extend_from_slice(value.options.as_ref());

        data.freeze()
    }
}

impl From<RouterSolicitationMessage> for Bytes {
    fn from(value: RouterSolicitationMessage) -> Self {
        (&value).into()
    }
}

impl From<RouterSolicitationMessage> for Vec<u8> {
    fn from(value: RouterSolicitationMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

impl From<&RouterSolicitationMessage> for Vec<u8> {
    fn from(value: &RouterSolicitationMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_solicitation_message_creation() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 2); // All-routers multicast address

        // [正常系] オプションなしのRouter Solicitationメッセージの作成
        let message = RouterSolicitationMessage::new(&[], src, dst);
        assert_eq!(message.options, Bytes::new());
        assert_eq!(message.reserved, 0);
        assert_ne!(message.checksum, 0); // チェックサムが計算されていることを確認
        assert_eq!(message.total_length(), 8);

        // [正常系] オプション付きのRouter Solicitationメッセージの作成
        let options = [1, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]; // Source Link-layer Address
        let message = RouterSolicitationMessage::new(&options, src, dst);
        assert_eq!(message.options.as_ref(), &options);
        assert_eq!(message.reserved, 0);
        assert_ne!(message.checksum, 0);
        assert_eq!(message.total_length(), 16);
    }

    #[test]
    fn test_router_solicitation_message_try_from_bytes() {
        // [正常系] オプションなしのメッセージのパース
        let bytes = [
            133, 0, 0x12, 0x34, // Type: 133, Code: 0, Checksum: 0x1234
            0, 0, 0, 0, // Reserved
        ];

        let message = RouterSolicitationMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(message.checksum, 0x1234);
        assert_eq!(message.reserved, 0);
        assert_eq!(message.options, Bytes::new());

        // [正常系] オプション付きのメッセージのパース
        let bytes = [
            133, 0, 0x56, 0x78, // Type: 133, Code: 0, Checksum: 0x5678
            0, 0, 0, 0, // Reserved
            1, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Source Link-layer Address Option
        ];

        let message = RouterSolicitationMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(message.checksum, 0x5678);
        assert_eq!(message.reserved, 0);
        assert_eq!(message.options.len(), 8);
        assert_eq!(message.options[0], 1); // Type
        assert_eq!(message.options[1], 1); // Length
        assert_eq!(
            &message.options[2..8],
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        );

        // [異常系] 不正な長さ
        let short_bytes = [133, 0, 0, 0, 0, 0, 0]; // 7バイト（8バイト未満）
        assert!(matches!(
            RouterSolicitationMessage::try_from_bytes(&short_bytes).unwrap_err(),
            RouterSolicitationMessageError::InvalidMessageLength(7)
        ));
    }

    #[test]
    fn test_router_solicitation_message_checksum_calculation() {
        // [正常系] ICMPv6チェックサム計算
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 2); // All-routers multicast address
        let message = RouterSolicitationMessage::new(&[], src, dst);

        let checksum = message.calculate_checksum(src, dst);
        assert_ne!(checksum, 0); // チェックサムが計算されていることを確認
        assert_eq!(message.checksum, checksum); // newで計算されたチェックサムが正しい

        // 計算されたチェックサムで検証
        assert!(message.validate_checksum(src, dst));

        // 間違った送信元・宛先では検証失敗
        let wrong_dst = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 3);
        assert!(!message.validate_checksum(src, wrong_dst));
    }

    #[test]
    fn test_router_solicitation_message_round_trip() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 2);

        // [正常系] バイト列変換のラウンドトリップテスト - オプションなし
        let original = RouterSolicitationMessage::new(&[], src, dst);

        let bytes: Vec<u8> = original.clone().into();
        let parsed = RouterSolicitationMessage::try_from_bytes(&bytes).unwrap();

        assert_eq!(original, parsed);

        // [正常系] バイト列変換のラウンドトリップテスト - オプション付き
        let options = [1, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let original = RouterSolicitationMessage::new(&options, src, dst);

        let bytes: Vec<u8> = original.clone().into();
        let parsed = RouterSolicitationMessage::try_from_bytes(&bytes).unwrap();

        assert_eq!(original, parsed);
    }
}
