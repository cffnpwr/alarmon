use std::net::Ipv6Addr;

use bytes::{BufMut, Bytes, BytesMut};
use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;
use crate::icmpv6::message::Message;
use crate::icmpv6::message_type::ICMPv6MessageType;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NeighborSolicitationMessageError {
    #[error("Invalid neighbor solicitation message type. Expected 135, but got {0}.")]
    InvalidMessageType(u8),
    #[error(
        "Invalid neighbor solicitation message length. Expected at least 24 bytes, but got {0} bytes."
    )]
    InvalidMessageLength(usize),
}

/// ICMPv6 Neighbor Solicitation メッセージ
///
/// RFC 4861で定義されたNeighbor Solicitation (Type 135) のメッセージ構造
/// 隣接ノードのリンクレイヤアドレスを解決するか、隣接ノードの到達可能性を確認するために送信されるメッセージ
///
/// Neighbor Solicitationメッセージは、ARPに相当するIPv6の機能を提供し、
/// IPv6アドレスに対応するリンクレイヤアドレスを取得する。
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = NeighborSolicitationMessageError, types = [&[u8], Vec<u8>, Box<[u8]>, bytes::Bytes])]
pub struct NeighborSolicitationMessage {
    /// Checksum
    pub checksum: u16,

    /// Reserved field (32 bits)
    /// MUST: 送信時は0で埋める必要がある
    /// MUST: 受信側には無視される必要がある
    pub reserved: u32,

    /// Target Address
    /// 解決しようとするIPv6アドレス
    pub target_address: Ipv6Addr,

    /// Options (variable length)
    /// 可能なオプション:
    /// - Source Link-layer Address (Type 1)
    /// オプションは8バイト境界でアライメントされる
    pub options: Bytes,
}

impl NeighborSolicitationMessage {
    /// 新しいNeighbor Solicitationメッセージを作成
    pub fn new(
        target_address: Ipv6Addr,
        options: impl AsRef<[u8]>,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        let mut msg = Self {
            checksum: 0, // チェックサムは後で計算する
            reserved: 0,
            target_address,
            options: Bytes::copy_from_slice(options.as_ref()),
        };

        msg.checksum = msg.calculate_checksum(src, dst);
        msg
    }
}

impl TryFromBytes for NeighborSolicitationMessage {
    type Error = NeighborSolicitationMessageError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();
        if bytes.len() < 24 {
            return Err(NeighborSolicitationMessageError::InvalidMessageLength(
                bytes.len(),
            ));
        }

        if bytes[0] != 135 {
            return Err(NeighborSolicitationMessageError::InvalidMessageType(
                bytes[0],
            ));
        }

        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        let reserved = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        let target_address = Ipv6Addr::from([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        let options = Bytes::copy_from_slice(&bytes[24..]);

        Ok(NeighborSolicitationMessage {
            checksum,
            reserved,
            target_address,
            options,
        })
    }
}

impl Message for NeighborSolicitationMessage {
    fn message_type(&self) -> ICMPv6MessageType {
        ICMPv6MessageType::NeighborSolicitation
    }

    fn code(&self) -> u8 {
        0 // Neighbor Solicitation always has code 0
    }

    fn total_length(&self) -> usize {
        // 4 bytes for Type + Code + Checksum + 4 bytes reserved + 16 bytes target address + options
        24 + self.options.len()
    }
}

impl From<&NeighborSolicitationMessage> for Bytes {
    fn from(value: &NeighborSolicitationMessage) -> Self {
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
        // Options (variable length)
        data.extend_from_slice(value.options.as_ref());

        data.freeze()
    }
}

impl From<NeighborSolicitationMessage> for Bytes {
    fn from(value: NeighborSolicitationMessage) -> Self {
        (&value).into()
    }
}

impl From<NeighborSolicitationMessage> for Vec<u8> {
    fn from(value: NeighborSolicitationMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

impl From<&NeighborSolicitationMessage> for Vec<u8> {
    fn from(value: &NeighborSolicitationMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_neighbor_solicitation_message_creation() {
        let target_address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // [正常系] オプションなしのNeighbor Solicitationメッセージの作成
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let message = NeighborSolicitationMessage::new(target_address, &[], src, dst);
        assert_ne!(message.checksum, 0);
        assert_eq!(message.reserved, 0);
        assert_eq!(message.target_address, target_address);
        assert_eq!(message.options, Bytes::new());
        assert_eq!(message.total_length(), 24);

        // [正常系] オプション付きのNeighbor Solicitationメッセージの作成
        let options = [1, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]; // Source Link-layer Address
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let message = NeighborSolicitationMessage::new(target_address, &options, src, dst);
        assert_ne!(message.checksum, 0); // チェックサムが計算されている
        assert_eq!(message.reserved, 0);
        assert_eq!(message.target_address, target_address);
        assert_eq!(message.options.as_ref(), &options);
        assert_eq!(message.total_length(), 32);

        // [正常系] Source Link-layer Addressオプション付きのメッセージ作成
        let mac_options = [1, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let message = NeighborSolicitationMessage::new(target_address, &mac_options, src, dst);
        assert_ne!(message.checksum, 0); // チェックサムが計算されている
        assert_eq!(message.reserved, 0);
        assert_eq!(message.target_address, target_address);
        assert_eq!(message.options.len(), 8);
        assert_eq!(message.options[0], 1); // Type
        assert_eq!(message.options[1], 1); // Length
        assert_eq!(
            &message.options[2..8],
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        );
    }

    #[test]
    fn test_neighbor_solicitation_message_try_from_bytes() {
        let target_address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // [正常系] オプションなしのメッセージのパース
        let bytes = [
            135, 0, 0, 0, // Type: 135, Code: 0, Checksum: 0
            0, 0, 0, 0, // Reserved
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, // Target Address: 2001:db8::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];

        let message = NeighborSolicitationMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(message.checksum, 0);
        assert_eq!(message.reserved, 0);
        assert_eq!(message.target_address, target_address);
        assert_eq!(message.options, Bytes::new());

        // [正常系] オプション付きのメッセージのパース
        let bytes = [
            135, 0, 0, 0, // Type: 135, Code: 0, Checksum: 0
            0, 0, 0, 0, // Reserved
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, // Target Address: 2001:db8::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 1, 1, 0x00, 0x11, 0x22, 0x33, 0x44,
            0x55, // Source Link-layer Address Option
        ];

        let message = NeighborSolicitationMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(message.checksum, 0);
        assert_eq!(message.reserved, 0);
        assert_eq!(message.target_address, target_address);
        assert_eq!(message.options.len(), 8);
        assert_eq!(message.options[0], 1); // Type
        assert_eq!(message.options[1], 1); // Length
        assert_eq!(
            &message.options[2..8],
            &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        );

        // [異常系] 不正な長さ
        let short_bytes = [
            135, 0, 0, 0, // Type: 135, Code: 0, Checksum: 0
            0, 0, 0, 0, // Reserved
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00,
            0x00, // Target Address: 2001:db8::1 (incomplete)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 23バイト（24バイト未満）
        ];
        assert!(matches!(
            NeighborSolicitationMessage::try_from_bytes(&short_bytes).unwrap_err(),
            NeighborSolicitationMessageError::InvalidMessageLength(23)
        ));
    }

    #[test]
    fn test_neighbor_solicitation_message_checksum_calculation() {
        let target_address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // [正常系] ICMPv6チェックサム計算
        let src = Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 1, 0xFF00, 0x0001); // Solicited-node multicast address
        let message = NeighborSolicitationMessage::new(target_address, &[], src, dst);

        assert_ne!(message.checksum, 0); // チェックサムが計算されていることを確認

        // 計算されたチェックサムで検証
        assert!(message.validate_checksum(src, dst));

        // 間違った送信元・宛先では検証失敗
        let wrong_dst = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 1, 0xFF00, 0x0002);
        assert!(!message.validate_checksum(src, wrong_dst));
    }

    #[test]
    fn test_neighbor_solicitation_message_round_trip() {
        let target_address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // [正常系] バイト列変換のラウンドトリップテスト - オプションなし
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let original = NeighborSolicitationMessage::new(
            target_address,
            &[], // no options
            src,
            dst,
        );

        let bytes: Vec<u8> = original.clone().into();
        let parsed = NeighborSolicitationMessage::try_from_bytes(&bytes).unwrap();

        assert_eq!(original, parsed);

        // [正常系] バイト列変換のラウンドトリップテスト - オプション付き
        let options = [1, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let original = NeighborSolicitationMessage::new(target_address, &options, src, dst);

        let bytes: Vec<u8> = original.clone().into();
        let parsed = NeighborSolicitationMessage::try_from_bytes(&bytes).unwrap();

        assert_eq!(original, parsed);
    }
}
