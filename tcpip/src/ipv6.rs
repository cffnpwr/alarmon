use std::net::Ipv6Addr;

use bytes::{Bytes, BytesMut};
use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;
use crate::ipv4::{Protocol, ProtocolError};

pub mod ipv6_address;

/// IPv6パケット処理に関するエラー
///
/// IPv6パケットのパース・検証で発生する可能性のあるエラーを定義します。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum IPv6Error {
    #[error("Invalid IPv6 packet length: must be at least 40 bytes, but got {0} bytes")]
    InvalidPacketLength(usize),
    #[error("Invalid IPv6 Version: must be 6 but {0}")]
    InvalidVersion(u8),
    #[error("Invalid Flow Label: must be 20 bits but {0}")]
    InvalidFlowLabel(u32),
    #[error(transparent)]
    InvalidProtocol(#[from] ProtocolError),
}

/// IPv6パケット
///
/// IPv6プロトコルに基づくパケット構造を表現します。
/// RFC 8200に準拠した固定長40バイトのヘッダーを持ちます。
///
/// 参照:
/// - [RFC 8200 - Internet Protocol, Version 6 (IPv6) Specification](https://tools.ietf.org/rfc/rfc8200.html)
/// - [RFC 2460 - Internet Protocol, Version 6 (IPv6) Specification](https://tools.ietf.org/rfc/rfc2460.txt) (Obsoleted by RFC 8200)
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = IPv6Error, types = [&[u8], Vec<u8>, Box<[u8]>, bytes::Bytes])]
pub struct IPv6Packet {
    /// Traffic Class
    /// パケットのトラフィッククラス（8ビット）
    /// IPv4のType of Serviceに相当
    pub traffic_class: u8,

    /// Flow Label
    /// 特定のフローを識別するラベル（20ビット）
    /// IPv6固有の機能
    pub flow_label: u32,

    /// Payload Length
    /// IPv6ヘッダー後のペイロード長（16ビット）
    /// 拡張ヘッダーも含む（IPv4のTotal Lengthとは異なる）
    pub payload_length: u16,

    /// Next Header
    /// 次のヘッダーまたは上位プロトコルを示す（8ビット）
    /// 拡張ヘッダーまたは上位プロトコル（TCP、UDP等）
    pub next_header: Protocol,

    /// Hop Limit
    /// パケットが通過可能なルーターの最大数（8ビット）
    /// IPv4のTime to Liveに相当
    pub hop_limit: u8,

    /// Source Address
    /// 送信元IPv6アドレス（128ビット）
    pub src: Ipv6Addr,

    /// Destination Address
    /// 宛先IPv6アドレス（128ビット）
    pub dst: Ipv6Addr,

    /// Payload
    /// ペイロード（拡張ヘッダー + 上位プロトコルデータ）
    pub payload: Bytes,
}

impl IPv6Packet {
    /// バージョン
    /// 常に6
    pub const VERSION: u8 = 6;

    /// IPv6ヘッダーの固定長（40バイト）
    pub const HEADER_LENGTH: usize = 40;

    /// Flow Labelの最大値（20ビット）
    pub const MAX_FLOW_LABEL: u32 = 0xFFFFF;

    pub fn new(
        traffic_class: u8,
        flow_label: u32,
        next_header: Protocol,
        hop_limit: u8,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        payload: impl AsRef<[u8]>,
    ) -> Result<Self, IPv6Error> {
        if flow_label > Self::MAX_FLOW_LABEL {
            return Err(IPv6Error::InvalidFlowLabel(flow_label));
        }

        let payload_bytes = Bytes::copy_from_slice(payload.as_ref());
        let payload_length = payload_bytes.len() as u16;

        Ok(Self {
            traffic_class,
            flow_label,
            payload_length,
            next_header,
            hop_limit,
            src,
            dst,
            payload: payload_bytes,
        })
    }

    /// IPv6パケットの実際の長さを計算
    /// ヘッダー長（40バイト） + ペイロード長
    pub fn total_length(&self) -> usize {
        Self::HEADER_LENGTH + self.payload.len()
    }
}

impl TryFromBytes for IPv6Packet {
    type Error = IPv6Error;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, IPv6Error> {
        let value = value.as_ref();
        if value.len() < Self::HEADER_LENGTH {
            return Err(IPv6Error::InvalidPacketLength(value.len()));
        }

        // Version (4ビット) + Traffic Class (8ビット) + Flow Label (20ビット)
        let version = value[0] >> 4;
        if version != Self::VERSION {
            return Err(IPv6Error::InvalidVersion(version));
        }

        let traffic_class = ((value[0] & 0x0F) << 4) | ((value[1] & 0xF0) >> 4);
        let flow_label = u32::from_be_bytes([0, value[1] & 0x0F, value[2], value[3]]);

        let payload_length = u16::from_be_bytes([value[4], value[5]]);
        let next_header = Protocol::try_from(value[6]).map_err(IPv6Error::InvalidProtocol)?;
        let hop_limit = value[7];

        // Source Address (128ビット)
        let src_bytes: [u8; 16] = value[8..24].try_into().unwrap();
        let src = Ipv6Addr::from(src_bytes);

        // Destination Address (128ビット)
        let dst_bytes: [u8; 16] = value[24..40].try_into().unwrap();
        let dst = Ipv6Addr::from(dst_bytes);

        // Payload
        let payload = Bytes::copy_from_slice(&value[Self::HEADER_LENGTH..]);

        Ok(Self {
            traffic_class,
            flow_label,
            payload_length,
            next_header,
            hop_limit,
            src,
            dst,
            payload,
        })
    }
}

impl From<IPv6Packet> for Bytes {
    fn from(packet: IPv6Packet) -> Self {
        let mut bytes = BytesMut::with_capacity(packet.total_length());

        // Version (4ビット) + Traffic Class上位4ビット
        bytes.extend_from_slice(&[IPv6Packet::VERSION << 4 | (packet.traffic_class >> 4)]);
        // Traffic Class下位4ビット + Flow Label上位4ビット
        bytes.extend_from_slice(&[
            (packet.traffic_class << 4) | ((packet.flow_label >> 16) as u8 & 0x0F)
        ]);
        // Flow Label下位16ビット
        bytes.extend_from_slice(&((packet.flow_label & 0xFFFF) as u16).to_be_bytes());
        // Payload Length
        bytes.extend_from_slice(&packet.payload_length.to_be_bytes());
        // Next Header
        bytes.extend_from_slice(&[packet.next_header.into()]);
        // Hop Limit
        bytes.extend_from_slice(&[packet.hop_limit]);
        // Source Address
        bytes.extend_from_slice(&packet.src.octets());
        // Destination Address
        bytes.extend_from_slice(&packet.dst.octets());
        // Payload
        bytes.extend_from_slice(&packet.payload);

        bytes.freeze()
    }
}

impl From<&IPv6Packet> for Bytes {
    fn from(packet: &IPv6Packet) -> Self {
        packet.clone().into()
    }
}

impl From<IPv6Packet> for Vec<u8> {
    fn from(packet: IPv6Packet) -> Self {
        Bytes::from(packet).to_vec()
    }
}

impl From<&IPv6Packet> for Vec<u8> {
    fn from(packet: &IPv6Packet) -> Self {
        Bytes::from(packet).to_vec()
    }
}

impl From<IPv6Packet> for Box<[u8]> {
    fn from(packet: IPv6Packet) -> Self {
        Bytes::from(packet).to_vec().into_boxed_slice()
    }
}

impl From<&IPv6Packet> for Box<[u8]> {
    fn from(packet: &IPv6Packet) -> Self {
        Bytes::from(packet).to_vec().into_boxed_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // IPv6パケットのテストデータ
    // Version: 6, Traffic Class: 0, Flow Label: 0
    // Payload Length: 8, Next Header: 17 (UDP), Hop Limit: 64
    // Source: ::1, Destination: ::1
    // Payload: 8バイトのダミーデータ
    const DEFAULT_IPV6_PACKET_BYTES: [u8; 48] = [
        0x60, 0x00, 0x00, 0x00, // Version, Traffic Class, Flow Label
        0x00, 0x08, // Payload Length
        0x11, // Next Header (UDP)
        0x40, // Hop Limit
        // Source Address (::1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, // Destination Address (::1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, // Payload
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    ];

    #[test]
    fn test_ipv6_packet_creation() {
        // [正常系] 基本的なIPv6パケットの作成
        let packet = IPv6Packet::new(
            0,
            0,
            Protocol::UDP,
            64,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::LOCALHOST,
            vec![0, 1, 2, 3, 4, 5, 6, 7],
        )
        .unwrap();

        assert_eq!(packet.traffic_class, 0);
        assert_eq!(packet.flow_label, 0);
        assert_eq!(packet.payload_length, 8);
        assert_eq!(packet.next_header, Protocol::UDP);
        assert_eq!(packet.hop_limit, 64);
        assert_eq!(packet.src, Ipv6Addr::LOCALHOST);
        assert_eq!(packet.dst, Ipv6Addr::LOCALHOST);
        assert_eq!(packet.total_length(), 48);

        // [異常系] Flow Labelが20ビットを超える場合
        let result = IPv6Packet::new(
            0,
            0x100000, // 20ビットの最大値を超える
            Protocol::UDP,
            64,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::LOCALHOST,
            vec![],
        );
        assert!(result.is_err());
        assert_eq!(result.err(), Some(IPv6Error::InvalidFlowLabel(0x100000)));
    }

    #[test]
    fn test_ipv6_packet_into_bytes() {
        // [正常系] IPv6パケットをバイト配列に変換
        let packet = IPv6Packet::new(
            0,
            0,
            Protocol::UDP,
            64,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::LOCALHOST,
            vec![0, 1, 2, 3, 4, 5, 6, 7],
        )
        .unwrap();

        let bytes: Vec<u8> = packet.into();
        assert_eq!(bytes.as_slice(), &DEFAULT_IPV6_PACKET_BYTES);
    }

    #[test]
    fn test_ipv6_packet_from_bytes() {
        // [正常系] バイト配列からIPv6パケットを作成
        let result = IPv6Packet::try_from_bytes(&DEFAULT_IPV6_PACKET_BYTES);
        assert!(result.is_ok());

        let packet = result.unwrap();
        assert_eq!(packet.traffic_class, 0);
        assert_eq!(packet.flow_label, 0);
        assert_eq!(packet.payload_length, 8);
        assert_eq!(packet.next_header, Protocol::UDP);
        assert_eq!(packet.hop_limit, 64);
        assert_eq!(packet.src, Ipv6Addr::LOCALHOST);
        assert_eq!(packet.dst, Ipv6Addr::LOCALHOST);
        assert_eq!(packet.payload.len(), 8);

        // [異常系] パケットサイズが40バイト未満の場合
        let short_packet = [0u8; 39];
        let result = IPv6Packet::try_from_bytes(&short_packet);
        assert!(result.is_err());
        assert_eq!(result.err(), Some(IPv6Error::InvalidPacketLength(39)));

        // [異常系] バージョンが6以外の場合
        let mut invalid_version_packet = DEFAULT_IPV6_PACKET_BYTES.clone();
        invalid_version_packet[0] = 0x50; // Version 5
        let result = IPv6Packet::try_from_bytes(&invalid_version_packet);
        assert!(result.is_err());
        assert_eq!(result.err(), Some(IPv6Error::InvalidVersion(5)));

        // [異常系] プロトコルが無効な場合
        let mut invalid_protocol_packet = DEFAULT_IPV6_PACKET_BYTES.clone();
        invalid_protocol_packet[6] = 200; // 無効なプロトコル
        let result = IPv6Packet::try_from_bytes(&invalid_protocol_packet);
        assert!(result.is_err());
        assert!(matches!(result.err(), Some(IPv6Error::InvalidProtocol(_))));
    }

    #[test]
    fn test_ipv6_packet_traffic_class_and_flow_label() {
        // [正常系] Traffic ClassとFlow Labelの複雑なビット操作をテスト
        let packet = IPv6Packet::new(
            0xAB,    // Traffic Class: 10101011
            0x12345, // Flow Label: 0x12345 (20ビット)
            Protocol::TCP,
            255,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            vec![0xFF; 10],
        )
        .unwrap();

        let bytes: Vec<u8> = packet.clone().into();
        let restored = IPv6Packet::try_from_bytes(&bytes).unwrap();

        assert_eq!(restored.traffic_class, 0xAB);
        assert_eq!(restored.flow_label, 0x12345);
        assert_eq!(restored.next_header, Protocol::TCP);
        assert_eq!(restored.hop_limit, 255);
        assert_eq!(restored.payload.len(), 10);
    }
}
