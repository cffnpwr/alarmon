use std::net::Ipv4Addr;

use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;
use crate::icmp::MessageType;
use crate::icmp::message::Message;
use crate::ipv4::{IPv4Error, IPv4Packet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RedirectCodeError {
    #[error("Invalid redirect code value: {0}")]
    InvalidValue(u8),
}

/// Redirectメッセージのコードタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectCode {
    /// Redirect for Network
    Network = 0,
    /// Redirect for Host
    Host = 1,
    /// Redirect for Type of Service and Network
    TypeOfServiceNetwork = 2,
    /// Redirect for Type of Service and Host
    TypeOfServiceHost = 3,
}

impl TryFrom<u8> for RedirectCode {
    type Error = RedirectCodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(RedirectCode::Network),
            1 => Ok(RedirectCode::Host),
            2 => Ok(RedirectCode::TypeOfServiceNetwork),
            3 => Ok(RedirectCode::TypeOfServiceHost),
            value => Err(RedirectCodeError::InvalidValue(value)),
        }
    }
}

impl From<RedirectCode> for u8 {
    fn from(value: RedirectCode) -> Self {
        value as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RedirectMessageError {
    #[error("Invalid redirect message type. Expected 5, but got {0}.")]
    InvalidMessageType(u8),
    #[error("Invalid redirect message length. Expected at least 36 bytes, but got {0} bytes.")]
    InvalidMessageLength(usize),
    #[error("Original datagram is too short. Expected at least 8 bytes, but got {0} bytes.")]
    OriginalDatagramTooShort(usize),
    #[error(transparent)]
    InvalidCode(#[from] RedirectCodeError),
    #[error(transparent)]
    InvalidOriginalDatagram(#[from] IPv4Error),
}

/// ICMPリダイレクトメッセージ
///
/// RFC 792で定義されたRedirectメッセージの構造
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = RedirectMessageError, types = [&[u8], Vec<u8>, Box<[u8]>])]
pub struct RedirectMessage {
    /// Code
    /// リダイレクトのタイプ
    pub code: RedirectCode,

    /// Checksum
    pub checksum: u16,

    /// Gateway Internet Address
    /// リダイレクト先のゲートウェイIPアドレス
    pub gateway_address: Ipv4Addr,

    /// Original Datagram
    /// 元のデータグラム（IPヘッダー + 最初の8バイト）
    /// 便宜上[`IPv4Packet`]を使用する
    pub original_datagram: IPv4Packet,
}

impl RedirectMessage {
    /// 新しいRedirectメッセージを作成
    pub fn new(
        code: RedirectCode,
        gateway_address: Ipv4Addr,
        original_datagram: IPv4Packet,
    ) -> Result<Self, RedirectMessageError> {
        let mut original_datagram = original_datagram;
        // 元のIPパケットからIPv4ヘッダーとデータ部の先頭の64ビット（8バイト）を取得
        if original_datagram.payload.len() < 8 {
            return Err(RedirectMessageError::OriginalDatagramTooShort(
                original_datagram.payload.len(),
            ));
        }
        original_datagram.payload.truncate(8); // 最初の64ビット（8バイト）を使用

        let mut msg = RedirectMessage {
            code,
            checksum: 0, // チェックサムは後で計算する
            gateway_address,
            original_datagram,
        };
        msg.checksum = msg.calculate_checksum();

        Ok(msg)
    }
}

impl Message for RedirectMessage {
    fn msg_type(&self) -> u8 {
        MessageType::Redirect.into()
    }

    fn code(&self) -> u8 {
        self.code.into()
    }
}

impl TryFromBytes for RedirectMessage {
    type Error = RedirectMessageError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();

        // Redirectメッセージタイプは5
        if bytes[0] != 5 {
            return Err(RedirectMessageError::InvalidMessageType(bytes[0]));
        }
        // Redirectメッセージは36バイト以上
        // Type (1 byte) + Code (1 byte) + Checksum (2 bytes) + Gateway Address (4 bytes) + Original Datagram (IPv4 header (20 bytes or more) + 64 bits of data)
        if bytes.len() < 36 {
            return Err(RedirectMessageError::InvalidMessageLength(bytes.len()));
        }

        let code = RedirectCode::try_from(bytes[1])?;
        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        let gateway_address = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
        let original_datagram = IPv4Packet::try_from(&bytes[8..])?;

        Ok(RedirectMessage {
            code,
            checksum,
            gateway_address,
            original_datagram,
        })
    }
}

impl From<RedirectMessage> for Vec<u8> {
    fn from(value: RedirectMessage) -> Self {
        (&value).into()
    }
}

impl From<&RedirectMessage> for Vec<u8> {
    fn from(value: &RedirectMessage) -> Self {
        let mut bytes = Vec::with_capacity(8 + value.original_datagram.len());

        // Type (1 byte)
        bytes.push(MessageType::Redirect.into());
        // Code (1 byte)
        bytes.push(value.code.into());
        // Checksum (2 bytes)
        bytes.extend_from_slice(&value.checksum.to_be_bytes());
        // Gateway Address (4 bytes)
        bytes.extend_from_slice(&value.gateway_address.octets());
        // Original Datagram (variable length)
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
    fn test_redirect_message_new() {
        // [正常系] Redirectメッセージの生成
        let gateway = Ipv4Addr::new(192, 168, 1, 1);
        let original_packet = create_test_ipv4_packet(b"original packet");
        let message =
            RedirectMessage::new(RedirectCode::Host, gateway, original_packet.clone()).unwrap();

        assert_eq!(message.code, RedirectCode::Host);
        assert_eq!(message.gateway_address, gateway);
        assert_eq!(message.original_datagram.payload.len(), 8); // 最初の8バイトのみ

        // [異常系] 8バイト未満のペイロードでエラー
        let original_packet = create_test_ipv4_packet(b"1234567"); // 7バイト（8バイト未満）

        let result = RedirectMessage::new(RedirectCode::Host, gateway, original_packet);

        assert!(matches!(
            result,
            Err(RedirectMessageError::OriginalDatagramTooShort(7))
        ));
    }

    #[test]
    fn test_redirect_message_try_from_bytes() {
        // [正常系] 有効なバイト列からのパース
        let bytes = [
            5,    // Type: Redirect
            0x01, // Code: Host
            0x00, 0x00, // Checksum
            192, 168, 1, 1, // Gateway Address
            0x45, 0x00, 0x00, 0x20, // Original IP header start
            0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xf7, 0x67, // More IP header
            0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, // IP addresses
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 8 bytes of original data
        ];

        let message = RedirectMessage::try_from_bytes(&bytes).unwrap();
        assert_eq!(message.code, RedirectCode::Host);
        assert_eq!(message.gateway_address, Ipv4Addr::new(192, 168, 1, 1));

        // [異常系] 不正な長さ
        let short_bytes = [5, 0x01, 0x00, 0x00]; // 4バイト（36バイト未満）

        assert!(matches!(
            RedirectMessage::try_from_bytes(&short_bytes).unwrap_err(),
            RedirectMessageError::InvalidMessageLength(4)
        ));

        // [異常系] 無効なメッセージタイプ
        let bytes = [
            6,    // Type: 6 (不正、Redirectは5)
            0x01, // Code: Host
            0x00, 0x00, // Checksum
            192, 168, 1, 1, // Gateway Address
            0x45, 0x00, 0x00, 0x20, // Original IP header start
            0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xf7, 0x67, // More IP header
            0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, // IP addresses
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 8 bytes of original data
        ];

        assert!(matches!(
            RedirectMessage::try_from_bytes(&bytes).unwrap_err(),
            RedirectMessageError::InvalidMessageType(6)
        ));

        // [異常系] 不正なコード値
        let invalid_code_bytes = [
            5,    // Type: Redirect
            0x04, // Code: 4 (不正、Redirectは0-3のみ)
            0x00, 0x00, // Checksum
            192, 168, 1, 1, // Gateway Address
            0x45, 0x00, 0x00, 0x20, // Original IP header start
            0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xf7, 0x67, // More IP header
            0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02, // IP addresses
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 8 bytes of original data
        ];

        assert!(matches!(
            RedirectMessage::try_from_bytes(&invalid_code_bytes).unwrap_err(),
            RedirectMessageError::InvalidCode(_)
        ));

        // [異常系] 不正なIPv4パケット
        let invalid_ipv4_bytes = [
            5,    // Type: Redirect
            0x01, // Code: Host
            0x00, 0x00, // Checksum
            192, 168, 1, 1, // Gateway Address
            0xFF, 0xFF, 0xFF, 0xFF, // 不正なIPヘッダー
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];

        assert!(matches!(
            RedirectMessage::try_from_bytes(&invalid_ipv4_bytes).unwrap_err(),
            RedirectMessageError::InvalidOriginalDatagram(_)
        ));
    }

    #[test]
    fn test_redirect_message_into_vec_u8() {
        // [正常系] Vec<u8>への変換
        let gateway = Ipv4Addr::new(172, 16, 0, 1);
        let original_packet = create_test_ipv4_packet(b"test data");
        let message =
            RedirectMessage::new(RedirectCode::TypeOfServiceHost, gateway, original_packet)
                .unwrap();

        let bytes: Vec<u8> = message.into();
        assert_eq!(bytes[0], 5); // Type: Redirect
        assert_eq!(bytes[1], 3); // Code: Type Of Service Host
        // bytes[2..4] はchecksum
        assert_eq!(&bytes[4..8], &[172, 16, 0, 1]); // Gateway Address
        // 残りの部分はIPv4パケットのバイナリ表現
    }
}
