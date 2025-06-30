use std::fmt::{self, Display};

use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;
use crate::icmp::MessageType;
use crate::icmp::message::Message;
use crate::ipv4::{IPv4Error, IPv4Packet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DestinationUnreachableCodeError {
    #[error("Invalid destination unreachable code value: {0}")]
    InvalidValue(u8),
    #[error(
        "Invalid destination unreachable code bytes length. Expected 1 byte, but got {0} bytes."
    )]
    InvalidBytesLength(usize),
}

/// Destination Unreachableメッセージのコード
///
/// RFC 792で定義されたDestination Unreachableの詳細コード
#[derive(Debug, Clone, Copy, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = DestinationUnreachableCodeError, types = [&[u8], [u8; 1], Vec<u8>, Box<[u8]>])]
pub enum DestinationUnreachableCode {
    /// Network Unreachable
    /// ネットワーク到達不可
    NetworkUnreachable = 0,

    /// Host Unreachable
    /// ホスト到達不可
    HostUnreachable = 1,

    /// Protocol Unreachable
    /// プロトコル到達不可
    ProtocolUnreachable = 2,

    /// Port Unreachable
    /// ポート到達不可
    PortUnreachable = 3,

    /// Fragmentation Needed and Don't Fragment was Set
    /// フラグメンテーション必要だがDF bit設定済み
    FragmentationNeededAndDFSet = 4,

    /// Source Route Failed
    /// ソースルート失敗
    SourceRouteFailed = 5,
}

impl Display for DestinationUnreachableCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DestinationUnreachableCode::NetworkUnreachable => write!(f, "Network Unreachable"),
            DestinationUnreachableCode::HostUnreachable => write!(f, "Host Unreachable"),
            DestinationUnreachableCode::ProtocolUnreachable => write!(f, "Protocol Unreachable"),
            DestinationUnreachableCode::PortUnreachable => write!(f, "Port Unreachable"),
            DestinationUnreachableCode::FragmentationNeededAndDFSet => {
                write!(f, "Fragmentation Needed and DF Set")
            }
            DestinationUnreachableCode::SourceRouteFailed => write!(f, "Source Route Failed"),
        }
    }
}
impl TryFromBytes for DestinationUnreachableCode {
    type Error = DestinationUnreachableCodeError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, DestinationUnreachableCodeError> {
        let bytes = value.as_ref();
        if bytes.len() != 1 {
            return Err(DestinationUnreachableCodeError::InvalidBytesLength(
                bytes.len(),
            ));
        }

        Self::try_from(bytes[0])
    }
}
impl TryFrom<&u8> for DestinationUnreachableCode {
    type Error = DestinationUnreachableCodeError;

    fn try_from(value: &u8) -> Result<Self, Self::Error> {
        match *value {
            0 => Ok(DestinationUnreachableCode::NetworkUnreachable),
            1 => Ok(DestinationUnreachableCode::HostUnreachable),
            2 => Ok(DestinationUnreachableCode::ProtocolUnreachable),
            3 => Ok(DestinationUnreachableCode::PortUnreachable),
            4 => Ok(DestinationUnreachableCode::FragmentationNeededAndDFSet),
            5 => Ok(DestinationUnreachableCode::SourceRouteFailed),
            value => Err(DestinationUnreachableCodeError::InvalidValue(value)),
        }
    }
}
impl TryFrom<u8> for DestinationUnreachableCode {
    type Error = DestinationUnreachableCodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}
impl From<DestinationUnreachableCode> for u8 {
    fn from(value: DestinationUnreachableCode) -> Self {
        value as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DestinationUnreachableMessageError {
    #[error("Invalid destination unreachable message type. Expected 3, but got {0}.")]
    InvalidMessageType(u8),
    #[error("Original datagram is too short. Expected at least 8 bytes, but got {0} bytes.")]
    OriginalDatagramTooShort(usize),
    #[error(
        "Invalid destination unreachable message length. Expected at least 36 bytes, but got {0} bytes."
    )]
    InvalidMessageLength(usize),
    #[error(transparent)]
    InvalidCode(#[from] DestinationUnreachableCodeError),
    #[error("Invalid unused field size. Expected 4 bytes, but got {0} bytes.")]
    InvalidUnusedFieldSize(usize),
    #[error("Next hop MTU is required for code 4, but was not provided.")]
    NextHopMTUIsRequired,
    #[error(transparent)]
    InvalidOriginalDatagram(#[from] IPv4Error),
}

/// Unusedフィールドの構造
///
/// Destination UnreachableメッセージのUnusedフィールドは、通常は0で埋められています。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestinationUnreachableMessageUnused {
    /// Unused field
    /// MUST: 送信時は0で埋める必要がある
    /// SHOULD NOT: 受信時はこのフィールドを使用するべきではない（チェックサム計算時を除く）
    Unused([u8; 4]),

    /// Next Hop MTU
    /// [`DestinationUnreachableCode::FragmentationNeededAndDFSet`]の場合に使用される
    NextHopMTU {
        /// Unused field
        /// MUST: 送信時は0で埋める必要がある
        /// SHOULD NOT: 受信時はこのフィールドを使用するべきではない（チェックサム計算時を除く）
        unused: [u8; 2],

        /// Next Hop MTU
        /// [`DestinationUnreachableCode::FragmentationNeededAndDFSet`]の場合に使用される
        next_hop_mtu: u16,
    },
}
impl From<&DestinationUnreachableMessageUnused> for [u8; 4] {
    fn from(value: &DestinationUnreachableMessageUnused) -> Self {
        match value {
            DestinationUnreachableMessageUnused::Unused(unused) => *unused,
            DestinationUnreachableMessageUnused::NextHopMTU {
                unused,
                next_hop_mtu,
            } => {
                let mut bytes = [0; 4];
                bytes[0..2].copy_from_slice(unused);
                bytes[2..4].copy_from_slice(&next_hop_mtu.to_be_bytes());
                bytes
            }
        }
    }
}
impl From<DestinationUnreachableMessageUnused> for [u8; 4] {
    fn from(value: DestinationUnreachableMessageUnused) -> Self {
        (&value).into()
    }
}

/// Destination Unreachable メッセージ
///
/// RFC 792で定義されたDestination Unreachable (Type 3) のメッセージ構造
/// パケットが宛先に到達できない場合に送信される
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = DestinationUnreachableMessageError, types = [&[u8], Vec<u8>, Box<[u8]>])]
pub struct DestinationUnreachableMessage {
    /// Code
    /// Destination Unreachableの詳細な理由を示すコード
    pub code: DestinationUnreachableCode,

    /// Unused
    pub unused: DestinationUnreachableMessageUnused,

    // Checksum
    pub checksum: u16,

    /// Original Datagram
    /// 元のIPヘッダー + 最初の64ビットのデータ
    /// 便宜上[`IPv4Packet`]を使用する
    pub original_datagram: IPv4Packet,
}

impl DestinationUnreachableMessage {
    /// 新しいDestination Unreachableメッセージを作成
    ///
    /// `next_hop_mtu`は`code`が`DestinationUnreachableCode::FragmentationNeededAndDFSet`の場合に必須
    pub fn new(
        code: DestinationUnreachableCode,
        next_hop_mtu: Option<u16>,
        original_datagram: IPv4Packet,
    ) -> Result<Self, DestinationUnreachableMessageError> {
        let unused = if code == DestinationUnreachableCode::FragmentationNeededAndDFSet {
            if next_hop_mtu.is_none() {
                return Err(DestinationUnreachableMessageError::NextHopMTUIsRequired);
            }
            DestinationUnreachableMessageUnused::NextHopMTU {
                unused: [0; 2],
                next_hop_mtu: next_hop_mtu.unwrap(),
            }
        } else {
            DestinationUnreachableMessageUnused::Unused([0; 4])
        };
        let mut original_datagram = original_datagram;
        // 元のIPパケットからIPｖ４ヘッダーとデータ部の先頭の64ビット（8バイト）を取得
        if original_datagram.payload.len() < 8 {
            return Err(
                DestinationUnreachableMessageError::OriginalDatagramTooShort(
                    original_datagram.payload.len(),
                ),
            );
        }
        original_datagram.payload.truncate(8); // 最初の64ビット（8バイト）を使用

        let mut msg = DestinationUnreachableMessage {
            code,
            unused,
            checksum: 0, // チェックサムは後で計算する
            original_datagram,
        };
        msg.checksum = msg.calculate_checksum();

        Ok(msg)
    }
}
impl TryFromBytes for DestinationUnreachableMessage {
    type Error = DestinationUnreachableMessageError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();

        // Destination Unreachableメッセージタイプは3
        if bytes[0] != 3 {
            return Err(DestinationUnreachableMessageError::InvalidMessageType(
                bytes[0],
            ));
        }
        // Destination Unreachableメッセージは36バイト以上
        // Type (1 byte) + Code (1 byte) + Checksum (2 bytes) + Unused (4 bytes) + Original Datagram (IPv4 header (20 bytes or more) + 64 bits of data)
        if bytes.len() < 36 {
            return Err(DestinationUnreachableMessageError::InvalidMessageLength(
                bytes.len(),
            ));
        }

        let code = DestinationUnreachableCode::try_from(bytes[1])?;
        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);

        let unused = if code == DestinationUnreachableCode::FragmentationNeededAndDFSet {
            let next_hop_mtu = u16::from_be_bytes([bytes[6], bytes[7]]);
            DestinationUnreachableMessageUnused::NextHopMTU {
                unused: [bytes[4], bytes[5]],
                next_hop_mtu,
            }
        } else {
            DestinationUnreachableMessageUnused::Unused([bytes[4], bytes[5], bytes[6], bytes[7]])
        };

        let original_datagram = IPv4Packet::try_from(&bytes[8..])?;

        Ok(DestinationUnreachableMessage {
            code,
            checksum,
            unused,
            original_datagram,
        })
    }
}
impl Message for DestinationUnreachableMessage {
    fn msg_type(&self) -> u8 {
        MessageType::DestinationUnreachable.into()
    }

    fn code(&self) -> u8 {
        self.code.into()
    }
}

impl From<DestinationUnreachableMessage> for Vec<u8> {
    fn from(value: DestinationUnreachableMessage) -> Self {
        (&value).into()
    }
}

impl From<&DestinationUnreachableMessage> for Vec<u8> {
    fn from(value: &DestinationUnreachableMessage) -> Self {
        let mut bytes = Vec::with_capacity(8 + value.original_datagram.len());

        // Type (1 byte)
        bytes.push(MessageType::DestinationUnreachable.into());
        // Code (1 byte)
        bytes.push(value.code.into());
        // Checksum (2 bytes)
        bytes.extend_from_slice(&value.checksum.to_be_bytes());
        // Unused field (4 bytes)
        bytes.extend_from_slice(&Into::<[u8; 4]>::into(&value.unused));
        // Original datagram (variable length)
        bytes.extend_from_slice(&Vec::from(&value.original_datagram));

        bytes
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::ipv4::{Flags, Protocol, TypeOfService};

    /// テスト用のIPv4パケット作成ヘルパー
    fn create_test_ipv4_packet(payload: &[u8]) -> IPv4Packet {
        IPv4Packet::new(
            TypeOfService::default(),
            20 + payload.len() as u16,
            1,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            vec![],
            payload,
        )
    }

    #[test]
    fn test_destination_unreachable_message_new() {
        // [正常系] DestinationUnreachableMessageの生成
        let original_packet = create_test_ipv4_packet(b"Original IP header and 64 bits of data");
        let msg = DestinationUnreachableMessage::new(
            DestinationUnreachableCode::HostUnreachable,
            None,
            original_packet.clone(),
        )
        .unwrap();

        assert_eq!(msg.code, DestinationUnreachableCode::HostUnreachable);
        assert_eq!(
            msg.unused,
            DestinationUnreachableMessageUnused::Unused([0; 4])
        );
        assert_eq!(msg.original_datagram.payload.len(), 8); // 最初の8バイトのみ

        // [正常系] NextHopMTU付きのDestinationUnreachableMessage生成
        let original_packet = create_test_ipv4_packet(b"Test data for fragmentation");
        let msg = DestinationUnreachableMessage::new(
            DestinationUnreachableCode::FragmentationNeededAndDFSet,
            Some(1500),
            original_packet,
        )
        .unwrap();

        assert_eq!(
            msg.code,
            DestinationUnreachableCode::FragmentationNeededAndDFSet
        );
        match msg.unused {
            DestinationUnreachableMessageUnused::NextHopMTU {
                unused,
                next_hop_mtu,
            } => {
                assert_eq!(unused, [0; 2]);
                assert_eq!(next_hop_mtu, 1500);
            }
            _ => panic!("Expected NextHopMTU variant"),
        }

        // [異常系] NextHopMTUが必要なのに提供されない場合
        let original_packet = create_test_ipv4_packet(b"Test data");

        let result = DestinationUnreachableMessage::new(
            DestinationUnreachableCode::FragmentationNeededAndDFSet,
            None, // NextHopMTUが必要なのに提供されない
            original_packet,
        );

        assert!(matches!(
            result,
            Err(DestinationUnreachableMessageError::NextHopMTUIsRequired)
        ));

        // [異常系] 8バイト未満のペイロードでエラー
        let original_packet = create_test_ipv4_packet(b"1234567"); // 7バイト（8バイト未満）

        let result = DestinationUnreachableMessage::new(
            DestinationUnreachableCode::ProtocolUnreachable,
            None,
            original_packet,
        );

        assert!(matches!(
            result,
            Err(DestinationUnreachableMessageError::OriginalDatagramTooShort(7))
        ));
    }

    #[test]
    fn test_destination_unreachable_message_try_from_bytes() {
        // [正常系] 有効なバイト列からのパース
        let bytes = [
            3,    // Type: Destination Unreachable
            0x01, // Code: Host Unreachable
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x00, // Unused field
            0x45, 0x00, 0x00, 0x20, // Original IP header start
            0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xf7, 0x67, // More IP header
            0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, // IP addresses
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 8 bytes of original data
        ];

        let msg = DestinationUnreachableMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(msg.code, DestinationUnreachableCode::HostUnreachable);
        assert_eq!(
            msg.unused,
            DestinationUnreachableMessageUnused::Unused([0x00, 0x00, 0x00, 0x00])
        );

        // [正常系] NextHopMTU付きのバイト列からのパース
        let bytes = [
            3,    // Type: Destination Unreachable
            0x04, // Code: Fragmentation Needed and DF Set
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x05, 0xDC, // Unused (2 bytes) + Next Hop MTU (1500 = 0x05DC)
            0x45, 0x00, 0x00, 0x20, // Original IP header start
            0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xf7, 0x67, // More IP header
            0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, // IP addresses
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 8 bytes of original data
        ];

        let msg = DestinationUnreachableMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(
            msg.code,
            DestinationUnreachableCode::FragmentationNeededAndDFSet
        );
        match msg.unused {
            DestinationUnreachableMessageUnused::NextHopMTU {
                unused,
                next_hop_mtu,
            } => {
                assert_eq!(unused, [0x00, 0x00]);
                assert_eq!(next_hop_mtu, 1500);
            }
            _ => panic!("Expected NextHopMTU variant"),
        }

        // [異常系] 不正な長さ
        let short_bytes = [3, 0x01, 0x00, 0x00]; // 4バイト（36バイト未満）

        assert!(matches!(
            DestinationUnreachableMessage::try_from_bytes(&short_bytes).unwrap_err(),
            DestinationUnreachableMessageError::InvalidMessageLength(4)
        ));

        // [異常系] 無効なメッセージタイプ
        let bytes = [
            5,    // Type: 5 (不正、Destination Unreachableは3)
            0x01, // Code: Host Unreachable
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x00, // Unused field
            0x45, 0x00, 0x00, 0x20, // Original IP header start
            0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xf7, 0x67, // More IP header
            0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, // IP addresses
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 8 bytes of original data
        ];

        assert!(matches!(
            DestinationUnreachableMessage::try_from_bytes(&bytes).unwrap_err(),
            DestinationUnreachableMessageError::InvalidMessageType(5)
        ));

        // [異常系] 不正なコード値
        let invalid_code_bytes = [
            3,    // Type: Destination Unreachable
            0x06, // Code: 6 (不正、Destination Unreachableは0-5のみ)
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x00, // Unused field
            0x45, 0x00, 0x00, 0x20, // Original IP header start
            0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xf7, 0x67, // More IP header
            0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, // IP addresses
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 8 bytes of original data
        ];

        assert!(matches!(
            DestinationUnreachableMessage::try_from_bytes(&invalid_code_bytes).unwrap_err(),
            DestinationUnreachableMessageError::InvalidCode(_)
        ));

        // [異常系] 不正なIPv4パケット
        let invalid_ipv4_bytes = [
            3,    // Type: Destination Unreachable
            0x01, // Code: Host Unreachable
            0x00, 0x00, // Checksum
            0x00, 0x00, 0x00, 0x00, // Unused field
            0xFF, 0xFF, 0xFF, 0xFF, // 不正なIPヘッダー
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];

        assert!(matches!(
            DestinationUnreachableMessage::try_from_bytes(&invalid_ipv4_bytes).unwrap_err(),
            DestinationUnreachableMessageError::InvalidOriginalDatagram(_)
        ));
    }

    #[test]
    fn test_destination_unreachable_message_into_vec_u8() {
        // [正常系] Vec<u8>への変換
        let original_packet = create_test_ipv4_packet(b"IP header + 64 bits");
        let msg = DestinationUnreachableMessage::new(
            DestinationUnreachableCode::NetworkUnreachable,
            None,
            original_packet,
        )
        .unwrap();

        let bytes: Vec<u8> = msg.into();
        assert_eq!(bytes[0], 3); // Type: Destination Unreachable
        assert_eq!(bytes[1], 0); // Code: Network Unreachable
        // bytes[2..4] はchecksum
        assert_eq!(&bytes[4..8], &[0x00, 0x00, 0x00, 0x00]); // Unused field
        // 残りの部分はIPv4パケットのバイナリ表現
    }
}
