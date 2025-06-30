mod flags;
pub(crate) mod ipv4_address;
mod protocol;
mod type_of_service;

use std::net::Ipv4Addr;

use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

pub use self::flags::Flags;
pub use self::protocol::Protocol;
use self::protocol::ProtocolError;
pub use self::type_of_service::TypeOfService;
use crate::checksum::calculate_internet_checksum;

const FLAG_MASK: u8 = 0b1110_0000;
const FRAGMENT_OFFSET_MASK: u16 = 0b0001_1111_1111_1111;

/// IPv4パケット処理に関するエラー
///
/// IPv4パケットのパース・検証で発生する可能性のあるエラーを定義します。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IPv4Error {
    #[error("Invalid IPv4 packet length: mut be at least 20 bytes, but got {0} bytes")]
    InvalidPacketLength(usize),

    #[error("Invalid IPv4 Version: must be 4 but {0}")]
    InvalidVersion(u8),

    #[error("Invalid IPv4 Header Length: must be at least 5 (20 bytes) but {0}")]
    InvalidHeaderLength(u8),

    #[error(transparent)]
    InvalidProtocol(#[from] ProtocolError),
}

/// IPv4パケット
///
/// IPv4プロトコルに基づくパケット構造を表現します。
///
/// 参照:
/// - [RFC 791 - Internet Protocol](https://tools.ietf.org/rfc/rfc791.txt)
/// - [IANA Protocol Numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = IPv4Error, types = [&[u8], Vec<u8>, Box<[u8]>])]
pub struct IPv4Packet {
    /// IP Headerの長さ
    /// ４Byte単位で表される
    /// 最大値は15
    /// 例: 20ByteのIP Headerは5
    pub internet_header_length: u8,

    /// Type of Service
    pub type_of_service: TypeOfService,

    /// Total Length
    /// IPパケット全体の長さ
    pub total_length: u16,

    /// Identification
    /// フラグメントの識別子
    pub identification: u16,

    /// Fragment Flags
    /// フラグメントのフラグ
    pub flags: Flags,

    /// Fragment Offset
    /// フラグメントのオフセット
    pub fragment_offset: u16,

    /// Time to Live
    /// パケットの生存時間
    pub time_to_live: u8,

    /// Protocol
    /// 上位プロトコル
    pub protocol: Protocol,

    /// Header Checksum
    /// ヘッダーのチェックサム
    pub header_checksum: u16,

    /// Source IP Address
    /// 送信元IPアドレス
    pub src: Ipv4Addr,

    /// Destination IP Address
    /// 宛先IPアドレス
    pub dst: Ipv4Addr,

    /// Options
    /// オプションフィールド
    pub options: Vec<u8>,

    /// Payload
    /// ペイロード
    pub payload: Vec<u8>,
}
impl IPv4Packet {
    /// バージョン
    /// 常に4
    pub const VERSION: u8 = 4;

    pub fn new(
        type_of_service: TypeOfService,
        total_length: u16,
        identification: u16,
        flags: Flags,
        fragment_offset: u16,
        time_to_live: u8,
        protocol: Protocol,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        options: impl AsRef<[u8]>,
        payload: impl AsRef<[u8]>,
    ) -> Self {
        let mut options = options.as_ref().to_vec();
        let opts_padding_size = options.len() % 4;
        if opts_padding_size != 0 {
            // オプションフィールドは4バイト境界でパディングする必要がある
            let padding_size = 4 - opts_padding_size;
            options.extend(vec![0; padding_size]);
        }
        let ihl = (20 + options.len()) / 4; // IPヘッダーの長さは20バイト（5 * 4） + オプションの長さ

        let mut packet = Self {
            internet_header_length: ihl as u8,
            type_of_service,
            total_length,
            identification,
            flags,
            fragment_offset,
            time_to_live,
            protocol,
            header_checksum: 0, // checksumは後で計算する
            src,
            dst,
            options,
            payload: payload.as_ref().to_vec(),
        };
        packet.header_checksum = packet.calculate_checksum();
        packet
    }

    fn calculate_checksum(&self) -> u16 {
        let data = Vec::<u8>::from(self);
        calculate_internet_checksum(&data)
    }

    pub fn validate_checksum(&self) -> bool {
        self.calculate_checksum() == 0
    }

    /// IPv4パケットの実際の長さを計算
    /// ヘッダー長 + オプション長 + ペイロード長
    pub fn len(&self) -> usize {
        let header_len = (self.internet_header_length as usize) * 4;
        header_len + self.payload.len()
    }

    pub fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, IPv4Error> {
        let value = value.as_ref();
        if value.len() < 20 {
            // IPv4パケットは最低でも20バイトのヘッダーが必要
            return Err(IPv4Error::InvalidPacketLength(value.len()));
        }

        let version = value[0] >> 4;
        if version != Self::VERSION {
            // IPv4のバージョンは常に4でなければならない
            return Err(IPv4Error::InvalidVersion(version));
        }
        let ihl = value[0] & 0x0F; // IPヘッダーの長さは4バイト単位
        if ihl < 5 {
            // ヘッダー長は5以上でなければならない
            return Err(IPv4Error::InvalidHeaderLength(ihl));
        }
        let tos = TypeOfService::from(value[1]);
        let total_length = u16::from_be_bytes([value[2], value[3]]);
        let identification = u16::from_be_bytes([value[4], value[5]]);
        let flags_value = Flags::from((value[6] & FLAG_MASK) >> 5);
        let fragment_offset = u16::from_be_bytes([value[6] & !FLAG_MASK, value[7]]);
        let ttl = value[8];
        let protocol = Protocol::try_from(value[9]).map_err(IPv4Error::InvalidProtocol)?;
        let checksum = u16::from_be_bytes([value[10], value[11]]);
        let src = Ipv4Addr::new(value[12], value[13], value[14], value[15]);
        let dst = Ipv4Addr::new(value[16], value[17], value[18], value[19]);
        let header_end = (ihl as usize) * 4;
        let options = value[20..header_end].to_vec();
        let payload = value[header_end..].to_vec();

        Ok(Self {
            internet_header_length: ihl,
            type_of_service: tos,
            total_length,
            identification,
            flags: flags_value,
            fragment_offset,
            time_to_live: ttl,
            protocol,
            header_checksum: checksum,
            src,
            dst,
            options,
            payload,
        })
    }

    fn into_bytes(&self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(self.total_length as usize);

        vec.push(Self::VERSION << 4 | self.internet_header_length);
        vec.push(self.type_of_service.into());
        vec.extend_from_slice(&self.total_length.to_be_bytes());
        vec.extend_from_slice(&self.identification.to_be_bytes());

        let flags_byte: u8 = self.flags.into();
        let flags_and_offset =
            (flags_byte as u16) << 8 | (self.fragment_offset & FRAGMENT_OFFSET_MASK);
        vec.extend_from_slice(&flags_and_offset.to_be_bytes());
        vec.push(self.time_to_live);
        vec.push(self.protocol.into());
        vec.extend_from_slice(&self.header_checksum.to_be_bytes());
        vec.extend_from_slice(&self.src.octets());
        vec.extend_from_slice(&self.dst.octets());
        vec.extend(self.options.iter().cloned());
        vec.extend(self.payload.iter().cloned());
        vec
    }
}
impl From<IPv4Packet> for Vec<u8> {
    fn from(packet: IPv4Packet) -> Self {
        packet.into_bytes()
    }
}
impl From<&IPv4Packet> for Vec<u8> {
    fn from(packet: &IPv4Packet) -> Self {
        packet.into_bytes()
    }
}
impl From<IPv4Packet> for Box<[u8]> {
    fn from(packet: IPv4Packet) -> Self {
        packet.into_bytes().into_boxed_slice()
    }
}
impl From<&IPv4Packet> for Box<[u8]> {
    fn from(packet: &IPv4Packet) -> Self {
        packet.into_bytes().into_boxed_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_IPV4_PACKET_BYTES: [u8; 60] = [
        0x45, // Version and IHL
        0x00, // Type of Service
        0x00, 0x3c, // Total Length
        0x00, 0x01, // Identification
        0x00, 0x00, // Flags and Fragment Offset
        0x40, // Time to Live
        0x06, // Protocol
        0xf7, 0x67, // Header Checksum
        0xc0, 0xa8, 0x01, 0x01, // Source Address
        0xc0, 0xa8, 0x01, 0x02, // Destination Address
        // Options (empty)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Payload (empty)
    ];

    #[test]
    fn test_ipv4_packet_creation() {
        let packet = IPv4Packet::new(
            TypeOfService::default(),
            60,
            1,
            Flags::default(),
            0,
            64,
            Protocol::TCP,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            vec![0; 0],
            vec![0; 40],
        );
        assert_eq!(packet.internet_header_length, 5);
        assert_eq!(packet.total_length, 60);
        assert!(packet.validate_checksum());

        // オプションフィールドが４の倍数のサイズでない場合、パディングを追加
        let packet = IPv4Packet::new(
            TypeOfService::default(),
            60,
            1,
            Flags::default(),
            0,
            64,
            Protocol::TCP,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            vec![0; 3], // オプションフィールドのサイズは3バイト
            vec![0; 40],
        );
        assert_eq!(packet.options.len(), 4); // パディングにより4バイトに調整される
    }

    #[test]
    fn test_ipv4_packet_into_bytes() {
        let packet = IPv4Packet::new(
            TypeOfService::default(),
            60,
            1,
            Flags::default(),
            0,
            64,
            Protocol::TCP,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            vec![0; 0],
            vec![0; 40],
        );
        let bytes = packet.into_bytes();
        assert_eq!(bytes.as_slice(), &DEFAULT_IPV4_PACKET_BYTES);
    }

    #[test]
    fn test_ipv4_packet_from_bytes() {
        // Try From u8 slice
        let result = IPv4Packet::try_from_bytes(&DEFAULT_IPV4_PACKET_BYTES);
        assert!(result.is_ok());

        let packet = result.unwrap();
        assert_eq!(packet.internet_header_length, 5);
        assert_eq!(packet.total_length, 60);
        assert!(packet.validate_checksum());
        assert_eq!(packet.src, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(packet.dst, Ipv4Addr::new(192, 168, 1, 2));

        // パケットサイズが20バイト未満の場合はエラー
        let short_packet = [0u8; 19];
        let result = IPv4Packet::try_from_bytes(&short_packet);
        assert!(result.is_err());
        assert_eq!(result.err(), Some(IPv4Error::InvalidPacketLength(19)));

        // バージョンが4以外の場合はエラー
        let mut invalid_version_packet = DEFAULT_IPV4_PACKET_BYTES.clone();
        invalid_version_packet[0] = 0x55; // 5に設定
        let result = IPv4Packet::try_from_bytes(&invalid_version_packet);
        assert!(result.is_err());
        assert_eq!(result.err(), Some(IPv4Error::InvalidVersion(5)));

        // IHLが5未満の場合はエラー
        let mut invalid_ihl_packet = DEFAULT_IPV4_PACKET_BYTES.clone();
        invalid_ihl_packet[0] = 0x44; // IHLを4に設定
        let result = IPv4Packet::try_from_bytes(&invalid_ihl_packet);
        assert!(result.is_err());
        assert_eq!(result.err(), Some(IPv4Error::InvalidHeaderLength(4)));

        // プロトコルが無効な場合はエラー
        let mut invalid_protocol_packet = DEFAULT_IPV4_PACKET_BYTES.clone();
        invalid_protocol_packet[9] = 200; // 無効なプロトコル
        let result = IPv4Packet::try_from_bytes(&invalid_protocol_packet);
        assert!(result.is_err());
        assert!(matches!(result.err(), Some(IPv4Error::InvalidProtocol(_))));
    }
}
