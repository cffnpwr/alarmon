use std::fmt::{self, Display};

use thiserror::Error;

/// ICMPv6メッセージタイプエラー
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ICMPv6MessageTypeError {
    #[error("Unsupported ICMPv6 message type: {0}")]
    UnsupportedMessageType(u8),
}

/// ICMPv6メッセージタイプ
///
/// RFC 4443とRFC 4861で定義されるICMPv6メッセージタイプを表現します。
/// エラーメッセージ（0-127）と情報メッセージ（128-255）に分類されます。
///
/// 参照:
/// - [RFC 4443 - Internet Control Message Protocol (ICMPv6) for IPv6](https://tools.ietf.org/rfc/rfc4443.txt)
/// - [RFC 4861 - Neighbor Discovery for IP version 6 (IPv6)](https://tools.ietf.org/rfc/rfc4861.txt)
/// - [IANA ICMPv6 Parameters](https://www.iana.org/assignments/icmpv6-parameters/)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ICMPv6MessageType {
    // エラーメッセージ（0-127）
    /// Destination Unreachable
    /// 宛先に到達できない場合に送信される
    DestinationUnreachable = 1,

    /// Packet Too Big
    /// パケットサイズが大きすぎる場合に送信される
    /// IPv4のFragmentation Needed and DF Setに相当
    PacketTooBig = 2,

    /// Time Exceeded
    /// TTL/Hop Limitが0になった場合やフラグメント再組み立てタイムアウト時に送信される
    TimeExceeded = 3,

    /// Parameter Problem
    /// IPv6ヘッダーまたは拡張ヘッダーに問題がある場合に送信される
    ParameterProblem = 4,

    // 情報メッセージ（128-255）
    /// Echo Request
    /// ピングリクエスト
    EchoRequest = 128,

    /// Echo Reply
    /// ピング応答
    EchoReply = 129,

    // Neighbor Discovery メッセージ（RFC 4861）
    /// Router Solicitation
    /// ルーター発見のためのリクエスト
    RouterSolicitation = 133,

    /// Router Advertisement
    /// ルーターからのアドバタイズメント
    RouterAdvertisement = 134,

    /// Neighbor Solicitation
    /// 近隣ノードの発見・到達性確認
    NeighborSolicitation = 135,

    /// Neighbor Advertisement
    /// 近隣ノードからの応答
    NeighborAdvertisement = 136,

    /// Redirect
    /// より良いルートの通知
    Redirect = 137,
}

impl ICMPv6MessageType {
    /// メッセージタイプがエラーメッセージかどうかを判定
    /// エラーメッセージは上位ビットが0（値が0-127）
    pub fn is_error_message(&self) -> bool {
        (*self as u8) < 128
    }

    /// メッセージタイプが情報メッセージかどうかを判定
    /// 情報メッセージは上位ビットが1（値が128-255）
    pub fn is_informational_message(&self) -> bool {
        (*self as u8) >= 128
    }
}

impl Display for ICMPv6MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ICMPv6MessageType::DestinationUnreachable => write!(f, "Destination Unreachable"),
            ICMPv6MessageType::PacketTooBig => write!(f, "Packet Too Big"),
            ICMPv6MessageType::TimeExceeded => write!(f, "Time Exceeded"),
            ICMPv6MessageType::ParameterProblem => write!(f, "Parameter Problem"),
            ICMPv6MessageType::EchoRequest => write!(f, "Echo Request"),
            ICMPv6MessageType::EchoReply => write!(f, "Echo Reply"),
            ICMPv6MessageType::RouterSolicitation => write!(f, "Router Solicitation"),
            ICMPv6MessageType::RouterAdvertisement => write!(f, "Router Advertisement"),
            ICMPv6MessageType::NeighborSolicitation => write!(f, "Neighbor Solicitation"),
            ICMPv6MessageType::NeighborAdvertisement => write!(f, "Neighbor Advertisement"),
            ICMPv6MessageType::Redirect => write!(f, "Redirect"),
        }
    }
}

impl From<ICMPv6MessageType> for u8 {
    fn from(message_type: ICMPv6MessageType) -> Self {
        message_type as u8
    }
}

impl TryFrom<u8> for ICMPv6MessageType {
    type Error = ICMPv6MessageTypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ICMPv6MessageType::DestinationUnreachable),
            2 => Ok(ICMPv6MessageType::PacketTooBig),
            3 => Ok(ICMPv6MessageType::TimeExceeded),
            4 => Ok(ICMPv6MessageType::ParameterProblem),
            128 => Ok(ICMPv6MessageType::EchoRequest),
            129 => Ok(ICMPv6MessageType::EchoReply),
            133 => Ok(ICMPv6MessageType::RouterSolicitation),
            134 => Ok(ICMPv6MessageType::RouterAdvertisement),
            135 => Ok(ICMPv6MessageType::NeighborSolicitation),
            136 => Ok(ICMPv6MessageType::NeighborAdvertisement),
            137 => Ok(ICMPv6MessageType::Redirect),
            _ => Err(ICMPv6MessageTypeError::UnsupportedMessageType(value)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmpv6_message_type_try_from_u8() {
        // [正常系] 有効なメッセージタイプ - エラーメッセージ
        assert_eq!(
            ICMPv6MessageType::try_from(1),
            Ok(ICMPv6MessageType::DestinationUnreachable)
        );
        assert_eq!(
            ICMPv6MessageType::try_from(2),
            Ok(ICMPv6MessageType::PacketTooBig)
        );
        assert_eq!(
            ICMPv6MessageType::try_from(3),
            Ok(ICMPv6MessageType::TimeExceeded)
        );
        assert_eq!(
            ICMPv6MessageType::try_from(4),
            Ok(ICMPv6MessageType::ParameterProblem)
        );

        // [正常系] 有効なメッセージタイプ - 情報メッセージ
        assert_eq!(
            ICMPv6MessageType::try_from(128),
            Ok(ICMPv6MessageType::EchoRequest)
        );
        assert_eq!(
            ICMPv6MessageType::try_from(129),
            Ok(ICMPv6MessageType::EchoReply)
        );

        // [正常系] 有効なメッセージタイプ - Neighbor Discovery
        assert_eq!(
            ICMPv6MessageType::try_from(133),
            Ok(ICMPv6MessageType::RouterSolicitation)
        );
        assert_eq!(
            ICMPv6MessageType::try_from(134),
            Ok(ICMPv6MessageType::RouterAdvertisement)
        );
        assert_eq!(
            ICMPv6MessageType::try_from(135),
            Ok(ICMPv6MessageType::NeighborSolicitation)
        );
        assert_eq!(
            ICMPv6MessageType::try_from(136),
            Ok(ICMPv6MessageType::NeighborAdvertisement)
        );
        assert_eq!(
            ICMPv6MessageType::try_from(137),
            Ok(ICMPv6MessageType::Redirect)
        );

        // [異常系] 無効なメッセージタイプ
        let result = ICMPv6MessageType::try_from(255);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ICMPv6MessageTypeError::UnsupportedMessageType(255)
        );

        let result = ICMPv6MessageType::try_from(0);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ICMPv6MessageTypeError::UnsupportedMessageType(0)
        );
    }

    #[test]
    fn test_icmpv6_message_type_from_u8() {
        // [正常系] ICMPv6MessageType -> u8の変換
        assert_eq!(u8::from(ICMPv6MessageType::DestinationUnreachable), 1);
        assert_eq!(u8::from(ICMPv6MessageType::PacketTooBig), 2);
        assert_eq!(u8::from(ICMPv6MessageType::TimeExceeded), 3);
        assert_eq!(u8::from(ICMPv6MessageType::ParameterProblem), 4);
        assert_eq!(u8::from(ICMPv6MessageType::EchoRequest), 128);
        assert_eq!(u8::from(ICMPv6MessageType::EchoReply), 129);
    }

    #[test]
    fn test_icmpv6_message_type_classification() {
        // [正常系] エラーメッセージの判定
        assert!(ICMPv6MessageType::DestinationUnreachable.is_error_message());
        assert!(ICMPv6MessageType::PacketTooBig.is_error_message());
        assert!(ICMPv6MessageType::TimeExceeded.is_error_message());
        assert!(ICMPv6MessageType::ParameterProblem.is_error_message());
        assert!(!ICMPv6MessageType::DestinationUnreachable.is_informational_message());

        // [正常系] 情報メッセージの判定
        assert!(ICMPv6MessageType::EchoRequest.is_informational_message());
        assert!(ICMPv6MessageType::EchoReply.is_informational_message());
        assert!(!ICMPv6MessageType::EchoRequest.is_error_message());
        assert!(!ICMPv6MessageType::EchoReply.is_error_message());
    }

    #[test]
    fn test_icmpv6_message_type_display() {
        // [正常系] Displayトレイトのテスト
        assert_eq!(
            format!("{}", ICMPv6MessageType::DestinationUnreachable),
            "Destination Unreachable"
        );
        assert_eq!(
            format!("{}", ICMPv6MessageType::PacketTooBig),
            "Packet Too Big"
        );
        assert_eq!(
            format!("{}", ICMPv6MessageType::TimeExceeded),
            "Time Exceeded"
        );
        assert_eq!(
            format!("{}", ICMPv6MessageType::ParameterProblem),
            "Parameter Problem"
        );
        assert_eq!(
            format!("{}", ICMPv6MessageType::EchoRequest),
            "Echo Request"
        );
        assert_eq!(format!("{}", ICMPv6MessageType::EchoReply), "Echo Reply");
    }
}
