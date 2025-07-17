use std::net::Ipv6Addr;

use bytes::{BufMut, Bytes, BytesMut};
use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;
use crate::icmpv6::message::Message;
use crate::icmpv6::message_type::ICMPv6MessageType;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RedirectMessageError {
    #[error("Invalid redirect message type. Expected 137, but got {0}.")]
    InvalidMessageType(u8),
    #[error("Invalid redirect message length. Expected at least 40 bytes, but got {0} bytes.")]
    InvalidMessageLength(usize),
}

/// ICMPv6 Redirect メッセージ
///
/// RFC 4861で定義されたRedirect (Type 137) のメッセージ構造
/// より良いルートを通知するためにルーターが送信するメッセージ
///
/// Redirectメッセージは、ホストに対してより良いルートを通知するために使用される。
/// ルーターは、より効率的なルートが存在することを検出した場合にこのメッセージを送信する。
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = RedirectMessageError, types = [&[u8], Vec<u8>, Box<[u8]>, bytes::Bytes])]
pub struct RedirectMessage {
    /// Checksum
    pub checksum: u16,

    /// Reserved field (32 bits)
    /// MUST: 送信時は0で埋める必要がある
    /// MUST: 受信側には無視される必要がある
    pub reserved: u32,

    /// Target Address
    /// リダイレクト先のアドレス
    /// 宛先と同じルートにある場合は、宛先アドレスと同じ値
    /// より良いルーターが存在する場合は、そのルーターのアドレス
    pub target_address: Ipv6Addr,

    /// Destination Address
    /// リダイレクトされる宛先アドレス
    pub destination_address: Ipv6Addr,

    /// Options (variable length)
    /// 可能なオプション:
    /// - Target Link-layer Address (Type 2)
    /// - Redirected Header (Type 4)
    ///   オプションは8バイト境界でアライメントされる
    pub options: Bytes,
}

impl RedirectMessage {
    /// 新しいRedirectメッセージを作成
    pub fn new(
        target_address: Ipv6Addr,
        destination_address: Ipv6Addr,
        options: impl AsRef<[u8]>,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        let mut msg = Self {
            checksum: 0, // チェックサムは後で計算する
            reserved: 0,
            target_address,
            destination_address,
            options: Bytes::copy_from_slice(options.as_ref()),
        };

        msg.checksum = msg.calculate_checksum(src, dst);
        msg
    }
}

impl TryFromBytes for RedirectMessage {
    type Error = RedirectMessageError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();
        if bytes.len() < 40 {
            return Err(RedirectMessageError::InvalidMessageLength(bytes.len()));
        }

        let target_address = Ipv6Addr::from([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);

        let destination_address = Ipv6Addr::from([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
            bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37], bytes[38], bytes[39],
        ]);

        let options = Bytes::copy_from_slice(&bytes[40..]);

        if bytes[0] != 137 {
            return Err(RedirectMessageError::InvalidMessageType(bytes[0]));
        }

        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        let reserved = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        Ok(RedirectMessage {
            checksum,
            reserved,
            target_address,
            destination_address,
            options,
        })
    }
}

impl Message for RedirectMessage {
    fn message_type(&self) -> ICMPv6MessageType {
        ICMPv6MessageType::Redirect
    }

    fn code(&self) -> u8 {
        0 // Redirect always has code 0
    }

    fn total_length(&self) -> usize {
        // 4 bytes for Type + Code + Checksum + 4 bytes reserved + 16 bytes target address + 16 bytes destination address + options
        40 + self.options.len()
    }
}

impl From<&RedirectMessage> for Bytes {
    fn from(value: &RedirectMessage) -> Self {
        let mut data = BytesMut::with_capacity(value.total_length());

        // Type (1 byte)
        data.put_u8(value.message_type().into());
        // Code (1 byte)
        data.put_u8(value.code());
        // Checksum (2 bytes)
        data.put_u16(value.checksum);
        // Reserved (4 bytes)
        data.put_u32(value.reserved);
        // Target Address (16 bytes)
        data.extend_from_slice(&value.target_address.octets());
        // Destination Address (16 bytes)
        data.extend_from_slice(&value.destination_address.octets());
        // Options (variable length)
        data.extend_from_slice(value.options.as_ref());

        data.freeze()
    }
}

impl From<RedirectMessage> for Bytes {
    fn from(value: RedirectMessage) -> Self {
        (&value).into()
    }
}

impl From<RedirectMessage> for Vec<u8> {
    fn from(value: RedirectMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

impl From<&RedirectMessage> for Vec<u8> {
    fn from(value: &RedirectMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redirect_message_creation() {
        let target_address = Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 1);
        let destination_address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // [正常系] オプションなしのRedirectメッセージの作成
        let src = Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let message = RedirectMessage::new(
            target_address,
            destination_address,
            &[], // no options
            src,
            dst,
        );
        assert_eq!(message.target_address, target_address);
        assert_eq!(message.destination_address, destination_address);
        assert_eq!(message.options, Bytes::new());
        assert_eq!(message.total_length(), 40);

        // [正常系] Target Link-layer Addressオプション付きのメッセージ作成
        let mac_address = [2, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]; // Type, Length, MAC
        let message =
            RedirectMessage::new(target_address, destination_address, &mac_address, src, dst);
        assert_eq!(message.target_address, target_address);
        assert_eq!(message.destination_address, destination_address);
        assert_eq!(message.options.len(), 8);
        assert_eq!(message.options[0], 2); // Type
        assert_eq!(message.options[1], 1); // Length
        assert_eq!(
            &message.options[2..8],
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        );
        assert_eq!(message.total_length(), 48);
    }

    #[test]
    fn test_redirect_message_with_redirected_header() {
        let target_address = Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 1);
        let destination_address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // [正常系] Redirected Headerオプション付きのメッセージ作成
        let redirected_header = [
            4, 6, 0, 0, 0, 0, 0, 0, // Type: 4, Length: 6, Reserved
            0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3A, 0x40, // IPv6 header
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, // Source address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00, // Destination address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x80, 0x00, 0x00, 0x00, 0x12, 0x34,
            0x56, 0x78, // ICMP Echo Request
        ];

        let src = Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let message = RedirectMessage::new(
            target_address,
            destination_address,
            &redirected_header,
            src,
            dst,
        );

        assert_eq!(message.target_address, target_address);
        assert_eq!(message.destination_address, destination_address);
        assert_eq!(message.options.len(), redirected_header.len());
        assert_eq!(message.options[0], 4); // Type: Redirected Header
        assert_eq!(message.options[1], 6); // Length should be calculated
    }

    #[test]
    fn test_redirect_message_try_from_bytes() {
        let target_address = Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 1);
        let destination_address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // [正常系] オプションなしのメッセージのパース
        let bytes = [
            137, 0, 0, 0, // Type: 137, Code: 0, Checksum: 0
            0, 0, 0, 0, // Reserved
            0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target Address: fe80::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00, // Destination Address: 2001:db8::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];

        let message = RedirectMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(message.target_address, target_address);
        assert_eq!(message.destination_address, destination_address);
        assert_eq!(message.options, Bytes::new());

        // [正常系] オプション付きのメッセージのパース
        let bytes = [
            137, 0, 0, 0, // Type: 137, Code: 0, Checksum: 0
            0, 0, 0, 0, // Reserved
            0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target Address: fe80::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00, // Destination Address: 2001:db8::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 2, 1, 0x00, 0x11, 0x22, 0x33, 0x44,
            0x55, // Target Link-layer Address Option
        ];

        let message = RedirectMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(message.target_address, target_address);
        assert_eq!(message.destination_address, destination_address);
        assert_eq!(message.options.len(), 8);
        assert_eq!(message.options[0], 2); // Type
        assert_eq!(message.options[1], 1); // Length
        assert_eq!(
            &message.options[2..8],
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        );

        // [異常系] 不正な長さ
        let short_bytes = [
            137, 0, 0, 0, // Type: 137, Code: 0, Checksum: 0
            0, 0, 0, 0, // Reserved
            0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target Address: fe80::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00, // Destination Address: 2001:db8::1 (incomplete)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 39バイト（40バイト未満）
        ];
        assert!(matches!(
            RedirectMessage::try_from_bytes(&short_bytes).unwrap_err(),
            RedirectMessageError::InvalidMessageLength(39)
        ));
    }

    #[test]
    fn test_redirect_message_checksum_calculation() {
        let target_address = Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 1);
        let destination_address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // [正常系] ICMPv6チェックサム計算
        let src = Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let message = RedirectMessage::new(
            target_address,
            destination_address,
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
    fn test_redirect_message_round_trip() {
        let target_address = Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 1);
        let destination_address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // [正常系] バイト列変換のラウンドトリップテスト - オプションなし
        let src = Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let original = RedirectMessage::new(
            target_address,
            destination_address,
            &[], // no options
            src,
            dst,
        );

        let bytes: Vec<u8> = original.clone().into();
        let parsed = RedirectMessage::try_from_bytes(&bytes).unwrap();

        assert_eq!(original, parsed);

        // [正常系] バイト列変換のラウンドトリップテスト - オプション付き
        let mac_address = [2, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]; // Type, Length, MAC
        let original =
            RedirectMessage::new(target_address, destination_address, &mac_address, src, dst);

        let bytes: Vec<u8> = original.clone().into();
        let parsed = RedirectMessage::try_from_bytes(&bytes).unwrap();

        assert_eq!(original, parsed);
    }
}
