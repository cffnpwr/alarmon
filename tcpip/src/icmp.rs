mod message;
mod message_type;

use std::net::Ipv4Addr;

use chrono::NaiveTime;
use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

pub use self::message::destination_unreachable::DestinationUnreachableCode;
pub use self::message::redirect::RedirectCode;
pub use self::message::time_exceeded::TimeExceededCode;
pub use self::message::{
    DestinationUnreachableMessage, DestinationUnreachableMessageError, EchoMessage,
    EchoMessageError, ParameterProblemMessage, ParameterProblemMessageError, RedirectMessage,
    RedirectMessageError, TimeExceededMessage, TimeExceededMessageError, TimestampMessage,
    TimestampMessageError,
};
pub use self::message_type::{MessageType, MessageTypeError};
use crate::TryFromBytes;
pub use crate::icmp::message::Message;
use crate::ipv4::IPv4Packet;

/// ICMPメッセージ処理に関するエラー
///
/// ICMPメッセージのパース・検証で発生する可能性のあるエラーを定義します。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ICMPError {
    #[error("Invalid ICMP packet length. Expected at least {0} bytes, but got {1} bytes.")]
    InvalidPacketLength(usize, usize),
    #[error("ICMP checksum verification failed")]
    ChecksumVerificationFailed,
    #[error(transparent)]
    InvalidMessageType(#[from] MessageTypeError),
    #[error(transparent)]
    InvalidEchoMessage(#[from] EchoMessageError),
    #[error(transparent)]
    InvalidDestinationUnreachableMessage(#[from] DestinationUnreachableMessageError),
    #[error(transparent)]
    InvalidTimeExceededMessage(#[from] TimeExceededMessageError),
    #[error(transparent)]
    InvalidRedirectMessage(#[from] RedirectMessageError),
    #[error(transparent)]
    InvalidParameterProblemMessage(#[from] ParameterProblemMessageError),
    #[error(transparent)]
    InvalidTimestampMessage(#[from] TimestampMessageError),
}

/// ICMPメッセージ
///
/// Internet Control Message Protocol (ICMP)メッセージを表現します。
/// 各メッセージタイプ固有の構造体を統合するenumです。
///
/// 参照:
/// - [RFC 792 - Internet Control Message Protocol](https://tools.ietf.org/rfc/rfc792.txt)
/// - [IANA ICMP Type Numbers](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = ICMPError, types = [&[u8], Vec<u8>, Box<[u8]>])]
pub enum ICMPMessage {
    EchoReply(EchoMessage),
    DestinationUnreachable(DestinationUnreachableMessage),
    Redirect(RedirectMessage),
    Echo(EchoMessage),
    TimeExceeded(TimeExceededMessage),
    ParameterProblem(ParameterProblemMessage),
    Timestamp(TimestampMessage),
    TimestampReply(TimestampMessage),
}

impl ICMPMessage {
    /// Echo Requestメッセージを作成
    pub fn echo_request(identifier: u16, sequence_number: u16, data: impl AsRef<[u8]>) -> Self {
        let echo_msg = EchoMessage::new(false, identifier, sequence_number, data);
        ICMPMessage::Echo(echo_msg)
    }

    /// Echo Replyメッセージを作成
    pub fn echo_reply(identifier: u16, sequence_number: u16, data: impl AsRef<[u8]>) -> Self {
        let echo_msg = EchoMessage::new(true, identifier, sequence_number, data);
        ICMPMessage::EchoReply(echo_msg)
    }

    /// Destination Unreachableメッセージを作成
    ///
    /// - `next_hop_mtu`: `code`が`DestinationUnreachableCode::FragmentationNeededAndDFSet`の場合に必須。
    /// - `original_datagram`: 元のデータグラム（IPヘッダー + 最初の8バイトを使用）
    pub fn destination_unreachable(
        code: DestinationUnreachableCode,
        next_hop_mtu: Option<u16>,
        original_datagram: IPv4Packet,
    ) -> Result<Self, DestinationUnreachableMessageError> {
        let dest_msg = DestinationUnreachableMessage::new(code, next_hop_mtu, original_datagram)?;
        Ok(ICMPMessage::DestinationUnreachable(dest_msg))
    }

    /// Redirectメッセージを作成
    pub fn redirect(
        code: RedirectCode,
        gateway_address: Ipv4Addr,
        original_datagram: IPv4Packet,
    ) -> Result<Self, RedirectMessageError> {
        let redirect_msg = RedirectMessage::new(code, gateway_address, original_datagram)?;
        Ok(ICMPMessage::Redirect(redirect_msg))
    }

    /// Time Exceededメッセージを作成
    pub fn time_exceeded(
        code: TimeExceededCode,
        original_datagram: IPv4Packet,
    ) -> Result<Self, TimeExceededMessageError> {
        let time_msg = TimeExceededMessage::new(code, original_datagram)?;
        Ok(ICMPMessage::TimeExceeded(time_msg))
    }

    /// Parameter Problemメッセージを作成
    /// RFC 792により、Parameter Problemのコードは常に0
    pub fn parameter_problem(
        pointer: u8,
        original_datagram: IPv4Packet,
    ) -> Result<Self, ParameterProblemMessageError> {
        let param_msg = ParameterProblemMessage::new(pointer, original_datagram)?;
        Ok(ICMPMessage::ParameterProblem(param_msg))
    }

    /// Timestampメッセージを作成
    pub fn timestamp(
        identifier: u16,
        sequence_number: u16,
        originate_timestamp: NaiveTime,
    ) -> Self {
        let timestamp_msg =
            TimestampMessage::new_request(identifier, sequence_number, originate_timestamp);
        ICMPMessage::Timestamp(timestamp_msg)
    }

    /// Timestamp Replyメッセージを作成
    pub fn timestamp_reply(
        identifier: u16,
        sequence_number: u16,
        originate_timestamp: NaiveTime,
        receive_timestamp: NaiveTime,
        transmit_timestamp: NaiveTime,
    ) -> Self {
        let timestamp_msg = TimestampMessage::new_reply(
            identifier,
            sequence_number,
            originate_timestamp,
            receive_timestamp,
            transmit_timestamp,
        );
        ICMPMessage::TimestampReply(timestamp_msg)
    }

    /// チェックサムを検証
    pub fn validate_checksum(&self) -> bool {
        // 各メッセージタイプのMessage traitの実装を使用
        match self {
            ICMPMessage::Echo(echo) => echo.validate_checksum(),
            ICMPMessage::EchoReply(echo) => echo.validate_checksum(),
            ICMPMessage::DestinationUnreachable(dest) => dest.validate_checksum(),
            ICMPMessage::Redirect(redirect) => redirect.validate_checksum(),
            ICMPMessage::TimeExceeded(time) => time.validate_checksum(),
            ICMPMessage::ParameterProblem(param) => param.validate_checksum(),
            ICMPMessage::Timestamp(timestamp) => timestamp.validate_checksum(),
            ICMPMessage::TimestampReply(timestamp) => timestamp.validate_checksum(),
        }
    }
}

impl TryFromBytes for ICMPMessage {
    type Error = ICMPError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();

        let message_type = MessageType::try_from(&bytes[0])?;

        match message_type {
            MessageType::Echo => EchoMessage::try_from(bytes)
                .map(ICMPMessage::Echo)
                .map_err(ICMPError::from),
            MessageType::EchoReply => EchoMessage::try_from(bytes)
                .map(ICMPMessage::EchoReply)
                .map_err(ICMPError::from),
            MessageType::DestinationUnreachable => DestinationUnreachableMessage::try_from(bytes)
                .map(ICMPMessage::DestinationUnreachable)
                .map_err(ICMPError::from),
            MessageType::Redirect => RedirectMessage::try_from(bytes)
                .map(ICMPMessage::Redirect)
                .map_err(ICMPError::from),
            MessageType::TimeExceeded => TimeExceededMessage::try_from(bytes)
                .map(ICMPMessage::TimeExceeded)
                .map_err(ICMPError::from),
            MessageType::ParameterProblem => ParameterProblemMessage::try_from(bytes)
                .map(ICMPMessage::ParameterProblem)
                .map_err(ICMPError::from),
            MessageType::Timestamp => TimestampMessage::try_from(bytes)
                .map(ICMPMessage::Timestamp)
                .map_err(ICMPError::from),
            MessageType::TimestampReply => TimestampMessage::try_from(bytes)
                .map(ICMPMessage::TimestampReply)
                .map_err(ICMPError::from),
        }
    }
}

impl From<ICMPMessage> for Vec<u8> {
    fn from(value: ICMPMessage) -> Self {
        (&value).into()
    }
}

impl From<&ICMPMessage> for Vec<u8> {
    fn from(value: &ICMPMessage) -> Self {
        match value {
            ICMPMessage::Echo(echo) => echo.into(),
            ICMPMessage::EchoReply(echo) => echo.into(),
            ICMPMessage::DestinationUnreachable(dest) => dest.into(),
            ICMPMessage::Redirect(redirect) => redirect.into(),
            ICMPMessage::TimeExceeded(time) => time.into(),
            ICMPMessage::ParameterProblem(param) => param.into(),
            ICMPMessage::Timestamp(timestamp) => timestamp.into(),
            ICMPMessage::TimestampReply(timestamp) => timestamp.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipv4::{Flags, Protocol, TypeOfService};

    const VALID_ECHO_REQUEST_BYTES: [u8; 13] = [
        0x08, 0x00, // Type: Echo Request, Code: 0
        0x6B, 0x81, // Checksum (calculated)
        0x12, 0x34, // Identifier
        0x56, 0x78, // Sequence Number
        0x48, 0x65, 0x6C, 0x6C, 0x6F, // "Hello"
    ];

    #[test]
    fn test_icmp_message_echo_request() {
        // [正常系] Echo Requestメッセージの生成
        let data = b"ping data".to_vec();
        let message = ICMPMessage::echo_request(0x1234, 0x5678, data.clone());

        match &message {
            ICMPMessage::Echo(echo) => {
                assert_eq!(echo.identifier, 0x1234);
                assert_eq!(echo.sequence_number, 0x5678);
                assert_eq!(echo.data, data);
            }
            _ => panic!("Expected Echo message"),
        }
        assert!(message.validate_checksum());
    }

    #[test]
    fn test_icmp_message_echo_reply() {
        // [正常系] Echo Replyメッセージの生成
        let data = b"pong data".to_vec();
        let message = ICMPMessage::echo_reply(0xABCD, 0xEF01, data.clone());
        dbg!(&message);

        match &message {
            ICMPMessage::EchoReply(echo) => {
                assert_eq!(echo.identifier, 0xABCD);
                assert_eq!(echo.sequence_number, 0xEF01);
                assert_eq!(echo.data, data);
            }
            _ => panic!("Expected EchoReply message"),
        }
        assert!(message.validate_checksum());
    }

    #[test]
    fn test_icmp_message_destination_unreachable() {
        // [正常系] Destination Unreachableメッセージの生成
        use std::net::Ipv4Addr;

        let original_packet = IPv4Packet::new(
            TypeOfService::default(),
            28,
            1,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            vec![],
            b"original packet",
        );

        let message = ICMPMessage::destination_unreachable(
            DestinationUnreachableCode::HostUnreachable,
            None,
            original_packet,
        )
        .unwrap();

        match &message {
            ICMPMessage::DestinationUnreachable(dest) => {
                assert_eq!(dest.code, DestinationUnreachableCode::HostUnreachable);
                assert_eq!(dest.original_datagram.payload.len(), 8); // 最初の8バイトのみ
            }
            _ => panic!("Expected DestinationUnreachable message"),
        }
        assert!(message.validate_checksum());
    }

    #[test]
    fn test_icmp_message_redirect() {
        // [正常系] Redirectメッセージの生成
        let gateway = std::net::Ipv4Addr::new(192, 168, 1, 1);
        let original_packet = IPv4Packet::new(
            TypeOfService::default(),
            28,
            1,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            vec![],
            b"redirect packet",
        );
        let message = ICMPMessage::redirect(RedirectCode::Host, gateway, original_packet).unwrap();

        match &message {
            ICMPMessage::Redirect(redirect) => {
                assert_eq!(redirect.code, RedirectCode::Host);
                assert_eq!(redirect.gateway_address, gateway);
                assert_eq!(redirect.original_datagram.payload.len(), 8); // 最初の8バイトのみ
            }
            _ => panic!("Expected Redirect message"),
        }
        assert!(message.validate_checksum());
    }

    #[test]
    fn test_icmp_message_time_exceeded() {
        // [正常系] Time Exceededメッセージの生成
        let original_packet = IPv4Packet::new(
            TypeOfService::default(),
            28,
            1,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            vec![],
            b"expired packet",
        );
        let message =
            ICMPMessage::time_exceeded(TimeExceededCode::TtlExceeded, original_packet).unwrap();

        match &message {
            ICMPMessage::TimeExceeded(time) => {
                assert_eq!(time.code, TimeExceededCode::TtlExceeded);
                assert_eq!(time.original_datagram.payload.len(), 8); // 最初の8バイトのみ
            }
            _ => panic!("Expected TimeExceeded message"),
        }
        assert!(message.validate_checksum());
    }

    #[test]
    fn test_icmp_message_parameter_problem() {
        // [正常系] Parameter Problemメッセージの生成
        let original_packet = IPv4Packet::new(
            TypeOfService::default(),
            28,
            1,
            Flags::default(),
            0,
            64,
            Protocol::ICMP,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            vec![],
            b"problem packet",
        );
        let message = ICMPMessage::parameter_problem(20, original_packet).unwrap();

        match &message {
            ICMPMessage::ParameterProblem(param) => {
                assert_eq!(param.pointer, 20);
                assert_eq!(param.original_datagram.payload.len(), 8); // 最初の8バイトのみ
            }
            _ => panic!("Expected ParameterProblem message"),
        }
        assert!(message.validate_checksum());
    }

    #[test]
    fn test_icmp_message_timestamp() {
        // [正常系] Timestampメッセージの生成
        let originate_time = NaiveTime::from_hms_milli_opt(10, 30, 45, 123).unwrap();
        let message = ICMPMessage::timestamp(0x1234, 0x5678, originate_time);

        match &message {
            ICMPMessage::Timestamp(timestamp) => {
                assert_eq!(timestamp.identifier, 0x1234);
                assert_eq!(timestamp.sequence_number, 0x5678);
                assert_eq!(timestamp.originate_timestamp, originate_time);
                assert_eq!(timestamp.receive_timestamp, NaiveTime::MIN);
                assert_eq!(timestamp.transmit_timestamp, NaiveTime::MIN);
            }
            _ => panic!("Expected Timestamp message"),
        }
        assert!(message.validate_checksum());
    }

    #[test]
    fn test_icmp_message_timestamp_reply() {
        // [正常系] Timestamp Replyメッセージの生成
        let originate_time = NaiveTime::from_hms_milli_opt(10, 30, 45, 123).unwrap();
        let receive_time = NaiveTime::from_hms_milli_opt(10, 30, 45, 223).unwrap();
        let transmit_time = NaiveTime::from_hms_milli_opt(10, 30, 45, 323).unwrap();
        let message = ICMPMessage::timestamp_reply(
            0xABCD,
            0xEF01,
            originate_time,
            receive_time,
            transmit_time,
        );

        match &message {
            ICMPMessage::TimestampReply(timestamp) => {
                assert_eq!(timestamp.identifier, 0xABCD);
                assert_eq!(timestamp.sequence_number, 0xEF01);
                assert_eq!(timestamp.originate_timestamp, originate_time);
                assert_eq!(timestamp.receive_timestamp, receive_time);
                assert_eq!(timestamp.transmit_timestamp, transmit_time);
            }
            _ => panic!("Expected TimestampReply message"),
        }
        assert!(message.validate_checksum());
    }

    #[test]
    fn test_icmp_message_into_vec_u8() {
        // [正常系] Vec<u8>への変換
        let message = ICMPMessage::echo_request(0x1234, 0x5678, b"Hello".to_vec());
        let bytes: Vec<u8> = message.into();
        assert_eq!(bytes, VALID_ECHO_REQUEST_BYTES);
    }

    #[test]
    fn test_icmp_message_round_trip() {
        // [正常系] バイト列変換のラウンドトリップテスト
        let original = ICMPMessage::echo_request(0x9999, 0xAAAA, b"Round Trip".to_vec());

        let bytes: Vec<u8> = original.clone().into();
        let parsed = ICMPMessage::try_from_bytes(&bytes).unwrap();

        assert_eq!(original, parsed);
    }

    // ICMPMessageのテスト
    #[test]
    fn test_icmp_message_try_from_bytes_echo() {
        // [正常系] Echoメッセージのパース
        let message = ICMPMessage::try_from_bytes(&VALID_ECHO_REQUEST_BYTES).unwrap();

        match message {
            ICMPMessage::Echo(echo_msg) => {
                assert_eq!(echo_msg.identifier, 0x1234);
                assert_eq!(echo_msg.sequence_number, 0x5678);
                assert_eq!(echo_msg.data, b"Hello");
            }
            _ => panic!("Expected Echo message"),
        }
    }
}
