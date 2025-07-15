use std::net::Ipv6Addr;

use bytes::{BufMut, Bytes, BytesMut};
use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;
use crate::icmpv6::message::Message;
use crate::icmpv6::message_type::ICMPv6MessageType;
use crate::ipv6::IPv6Packet;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PacketTooBigMessageError {
    #[error("Invalid packet too big message type. Expected 2, but got {0}.")]
    InvalidMessageType(u8),
    #[error("Invalid packet too big message code. Expected 0, but got {0}.")]
    InvalidMessageCode(u8),
    #[error("Invalid packet too big message length. Expected at least 8 bytes, but got {0} bytes.")]
    InvalidMessageLength(usize),
}

/// ICMPv6 Packet Too Big メッセージ
///
/// RFC 4443で定義されたPacket Too Big (Type 2) のメッセージ構造
/// パケットサイズが大きすぎる場合に送信されるエラーメッセージ
///
/// Packet Too Bigメッセージは、パケットサイズがリンクのMTUを超えている場合に
/// 送信されるICMPv6エラーメッセージである。
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = PacketTooBigMessageError, types = [&[u8], Vec<u8>, Box<[u8]>, bytes::Bytes])]
pub struct PacketTooBigMessage {
    /// Checksum
    pub checksum: u16,

    /// MTU of the next-hop link
    /// パケットが通過できる最大サイズ
    pub mtu: u32,

    /// Original packet that caused the error
    /// エラーの原因となった元のパケット（可能な限り）
    pub original_packet: IPv6Packet,
}

impl PacketTooBigMessage {
    /// 新しいPacket Too Bigメッセージを作成
    pub fn new(
        mtu: u32,
        original_packet: IPv6Packet,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        let mut msg = Self {
            checksum: 0, // チェックサムは後で計算する
            mtu,
            original_packet,
        };

        msg.checksum = msg.calculate_checksum(src, dst);
        msg
    }

    /// メッセージの全体サイズを計算
    pub fn total_length(&self) -> usize {
        8 + self.original_packet.total_length() // Type(1) + Code(1) + Checksum(2) + MTU(4) + OriginalPacket
    }
}

impl TryFromBytes for PacketTooBigMessage {
    type Error = PacketTooBigMessageError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();
        if bytes.len() < 8 {
            return Err(PacketTooBigMessageError::InvalidMessageLength(bytes.len()));
        }

        if bytes[0] != 2 {
            return Err(PacketTooBigMessageError::InvalidMessageType(bytes[0]));
        }

        if bytes[1] != 0 {
            return Err(PacketTooBigMessageError::InvalidMessageCode(bytes[1]));
        }

        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        let mtu = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let original_packet = IPv6Packet::try_from_bytes(&bytes[8..])
            .map_err(|_| PacketTooBigMessageError::InvalidMessageLength(bytes.len()))?;

        Ok(PacketTooBigMessage {
            checksum,
            mtu,
            original_packet,
        })
    }
}

impl Message for PacketTooBigMessage {
    fn message_type(&self) -> ICMPv6MessageType {
        ICMPv6MessageType::PacketTooBig
    }

    fn code(&self) -> u8 {
        0 // Packet Too Big always has code 0
    }

    fn total_length(&self) -> usize {
        // 4 bytes for Type + Code + Checksum + 4 bytes MTU + original packet
        8 + self.original_packet.total_length()
    }
}

impl From<&PacketTooBigMessage> for Bytes {
    fn from(value: &PacketTooBigMessage) -> Self {
        let mut data = BytesMut::with_capacity(value.total_length());

        // Type (1 byte)
        data.put_u8(value.message_type().into());
        // Code (1 byte)
        data.put_u8(value.code());
        // Checksum (2 bytes)
        data.put_u16(value.checksum);
        // MTU (4 bytes)
        data.put_u32(value.mtu);
        // Original packet (variable length)
        data.extend_from_slice(&Bytes::from(value.original_packet.clone()));

        data.freeze()
    }
}

impl From<PacketTooBigMessage> for Bytes {
    fn from(value: PacketTooBigMessage) -> Self {
        (&value).into()
    }
}

impl From<PacketTooBigMessage> for Vec<u8> {
    fn from(value: PacketTooBigMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

impl From<&PacketTooBigMessage> for Vec<u8> {
    fn from(value: &PacketTooBigMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipv4::Protocol;

    #[test]
    fn test_packet_too_big_message_creation() {
        // [正常系] Packet Too Bigメッセージの作成
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let original_packet =
            IPv6Packet::new(0, 0, Protocol::TCP, 64, src, dst, b"original packet data").unwrap();
        let message = PacketTooBigMessage::new(1280, original_packet.clone(), src, dst);

        assert_eq!(message.mtu, 1280);
        assert_eq!(message.original_packet, original_packet);
        assert_ne!(message.checksum, 0); // チェックサムが計算されていることを確認
        assert_eq!(message.total_length(), 8 + original_packet.total_length());
    }

    #[test]
    fn test_packet_too_big_message_try_from_bytes() {
        // [正常系] バイト列からのパース
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let original_packet = IPv6Packet::new(0, 0, Protocol::TCP, 64, src, dst, b"test").unwrap();
        let packet_bytes: Vec<u8> = original_packet.clone().into();

        let mut bytes = vec![
            2, 0, 0, 0, // Type: 2, Code: 0, Checksum: 0
            0x00, 0x00, 0x05, 0x00, // MTU: 1280
        ];
        bytes.extend_from_slice(&packet_bytes);

        let message = PacketTooBigMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(message.mtu, 1280);
        assert_eq!(message.original_packet, original_packet);

        // [異常系] 不正な長さ
        let short_bytes = [2, 0, 0, 0, 0x00, 0x00, 0x05]; // 7バイト（8バイト未満）
        assert!(matches!(
            PacketTooBigMessage::try_from_bytes(&short_bytes).unwrap_err(),
            PacketTooBigMessageError::InvalidMessageLength(7)
        ));
    }

    #[test]
    fn test_packet_too_big_message_checksum_calculation() {
        // [正常系] ICMPv6チェックサム計算
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let original_packet =
            IPv6Packet::new(0, 0, Protocol::TCP, 64, src, dst, b"test packet").unwrap();
        let message = PacketTooBigMessage::new(1500, original_packet, src, dst);

        assert_ne!(message.checksum, 0); // チェックサムが計算されていることを確認

        // 計算されたチェックサムで検証
        assert!(message.validate_checksum(src, dst));

        // 間違った送信元・宛先では検証失敗
        let wrong_dst = Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 2);
        assert!(!message.validate_checksum(src, wrong_dst));
    }

    #[test]
    fn test_packet_too_big_message_round_trip() {
        // [正常系] バイト列変換のラウンドトリップテスト
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let original_packet =
            IPv6Packet::new(0, 0, Protocol::TCP, 64, src, dst, b"big packet").unwrap();
        let original = PacketTooBigMessage::new(1280, original_packet, src, dst);

        let bytes: Vec<u8> = original.clone().into();
        let parsed = PacketTooBigMessage::try_from_bytes(&bytes).unwrap();

        assert_eq!(original, parsed);
    }
}
