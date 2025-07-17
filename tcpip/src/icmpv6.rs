mod message;
mod message_type;

use std::net::Ipv6Addr;

use bytes::Bytes;
use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

pub use self::message::{
    DestinationUnreachableCode, DestinationUnreachableCodeError, DestinationUnreachableMessage,
    DestinationUnreachableMessageError, EchoMessage, EchoMessageError, Message,
    NeighborAdvertisementMessage, NeighborAdvertisementMessageError, NeighborSolicitationMessage,
    NeighborSolicitationMessageError, PacketTooBigMessage, PacketTooBigMessageError,
    ParameterProblemMessage, ParameterProblemMessageError, RedirectMessage, RedirectMessageError,
    RouterAdvertisementMessage, RouterAdvertisementMessageError, RouterSolicitationMessage,
    RouterSolicitationMessageError, TimeExceededMessage, TimeExceededMessageError,
};
pub use self::message_type::{ICMPv6MessageType, ICMPv6MessageTypeError};
use crate::TryFromBytes;
use crate::ipv6::IPv6Packet;

/// ICMPv6メッセージ処理に関するエラー
///
/// ICMPv6メッセージのパース・検証で発生する可能性のあるエラーを定義します。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ICMPv6Error {
    #[error("Invalid ICMPv6 packet length: must be at least 4 bytes, but got {0} bytes")]
    InvalidPacketLength(usize),
    #[error("ICMPv6 checksum verification failed")]
    ChecksumVerificationFailed,
    #[error(transparent)]
    InvalidMessageType(#[from] ICMPv6MessageTypeError),
    #[error(transparent)]
    InvalidEchoMessage(#[from] EchoMessageError),
    #[error(transparent)]
    InvalidDestinationUnreachableMessage(#[from] DestinationUnreachableMessageError),
    #[error(transparent)]
    InvalidPacketTooBigMessage(#[from] PacketTooBigMessageError),
    #[error(transparent)]
    InvalidTimeExceededMessage(#[from] TimeExceededMessageError),
    #[error(transparent)]
    InvalidParameterProblemMessage(#[from] ParameterProblemMessageError),
    #[error(transparent)]
    InvalidRouterSolicitationMessage(#[from] RouterSolicitationMessageError),
    #[error(transparent)]
    InvalidRouterAdvertisementMessage(#[from] RouterAdvertisementMessageError),
    #[error(transparent)]
    InvalidNeighborSolicitationMessage(#[from] NeighborSolicitationMessageError),
    #[error(transparent)]
    InvalidNeighborAdvertisementMessage(#[from] NeighborAdvertisementMessageError),
    #[error(transparent)]
    InvalidRedirectMessage(#[from] RedirectMessageError),
}

/// ICMPv6メッセージ
///
/// Internet Control Message Protocol version 6 (ICMPv6)メッセージを表現します。
/// RFC 4443とRFC 4861に準拠した実装です。
///
/// 参照:
/// - [RFC 4443 - Internet Control Message Protocol (ICMPv6) for IPv6](https://tools.ietf.org/rfc/rfc4443.txt)
/// - [RFC 4861 - Neighbor Discovery for IP version 6 (IPv6)](https://tools.ietf.org/rfc/rfc4861.txt)
/// - [IANA ICMPv6 Parameters](https://www.iana.org/assignments/icmpv6-parameters/)
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = ICMPv6Error, types = [&[u8], Vec<u8>, Box<[u8]>, bytes::Bytes])]
pub enum ICMPv6Message {
    DestinationUnreachable(DestinationUnreachableMessage),
    PacketTooBig(PacketTooBigMessage),
    TimeExceeded(TimeExceededMessage),
    ParameterProblem(ParameterProblemMessage),
    EchoRequest(EchoMessage),
    EchoReply(EchoMessage),
    RouterSolicitation(RouterSolicitationMessage),
    RouterAdvertisement(RouterAdvertisementMessage),
    NeighborSolicitation(NeighborSolicitationMessage),
    NeighborAdvertisement(NeighborAdvertisementMessage),
    Redirect(RedirectMessage),
}

impl ICMPv6Message {
    /// Echo Requestメッセージを作成
    pub fn echo_request(
        identifier: u16,
        sequence_number: u16,
        data: impl AsRef<[u8]>,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        let echo_msg = EchoMessage::new_request(identifier, sequence_number, data, src, dst);
        ICMPv6Message::EchoRequest(echo_msg)
    }

    /// Echo Replyメッセージを作成
    pub fn echo_reply(
        identifier: u16,
        sequence_number: u16,
        data: impl AsRef<[u8]>,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        let echo_msg = EchoMessage::new_reply(identifier, sequence_number, data, src, dst);
        ICMPv6Message::EchoReply(echo_msg)
    }

    /// Destination Unreachableメッセージを作成
    pub fn destination_unreachable(
        code: DestinationUnreachableCode,
        original_packet: impl AsRef<[u8]>,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        let original_packet = IPv6Packet::try_from_bytes(original_packet.as_ref()).unwrap();
        let msg = DestinationUnreachableMessage::new(code, original_packet, src, dst);
        ICMPv6Message::DestinationUnreachable(msg)
    }

    /// Packet Too Bigメッセージを作成
    pub fn packet_too_big(
        mtu: u32,
        original_packet: impl AsRef<[u8]>,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        let original_packet =
            crate::ipv6::IPv6Packet::try_from_bytes(original_packet.as_ref()).unwrap();
        let msg = PacketTooBigMessage::new(mtu, original_packet, src, dst);
        ICMPv6Message::PacketTooBig(msg)
    }

    /// Router Solicitationメッセージを作成
    pub fn router_solicitation(
        options: impl AsRef<[u8]>,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        let msg = RouterSolicitationMessage::new(options, src, dst);
        ICMPv6Message::RouterSolicitation(msg)
    }

    /// Router Advertisementメッセージを作成
    #[allow(clippy::too_many_arguments)]
    pub fn router_advertisement(
        current_hop_limit: u8,
        managed_address_configuration: bool,
        other_configuration: bool,
        router_lifetime: u16,
        reachable_time: u32,
        retrans_timer: u32,
        options: impl AsRef<[u8]>,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        let msg = RouterAdvertisementMessage::new(
            current_hop_limit,
            managed_address_configuration,
            other_configuration,
            router_lifetime,
            reachable_time,
            retrans_timer,
            options,
            src,
            dst,
        );
        ICMPv6Message::RouterAdvertisement(msg)
    }

    /// Neighbor Solicitationメッセージを作成
    pub fn neighbor_solicitation(
        target_address: Ipv6Addr,
        options: impl AsRef<[u8]>,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        let msg = NeighborSolicitationMessage::new(target_address, options, src, dst);
        ICMPv6Message::NeighborSolicitation(msg)
    }

    /// Neighbor Advertisementメッセージを作成
    pub fn neighbor_advertisement(
        router: bool,
        solicited: bool,
        override_flag: bool,
        target_address: Ipv6Addr,
        options: impl AsRef<[u8]>,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        let msg = NeighborAdvertisementMessage::new(
            router,
            solicited,
            override_flag,
            target_address,
            options,
            src,
            dst,
        );
        ICMPv6Message::NeighborAdvertisement(msg)
    }

    /// Redirectメッセージを作成
    pub fn redirect(
        target_address: Ipv6Addr,
        destination_address: Ipv6Addr,
        options: impl AsRef<[u8]>,
        src: impl Into<Ipv6Addr>,
        dst: impl Into<Ipv6Addr>,
    ) -> Self {
        let msg = RedirectMessage::new(target_address, destination_address, options, src, dst);
        ICMPv6Message::Redirect(msg)
    }

    /// チェックサムを検証
    pub fn validate_checksum(&self, src: impl Into<Ipv6Addr>, dst: impl Into<Ipv6Addr>) -> bool {
        // 各メッセージタイプのMessage traitの実装使用
        match self {
            ICMPv6Message::DestinationUnreachable(msg) => msg.validate_checksum(src, dst),
            ICMPv6Message::PacketTooBig(msg) => msg.validate_checksum(src, dst),
            ICMPv6Message::TimeExceeded(msg) => msg.validate_checksum(src, dst),
            ICMPv6Message::ParameterProblem(msg) => msg.validate_checksum(src, dst),
            ICMPv6Message::EchoRequest(msg) => msg.validate_checksum(src, dst),
            ICMPv6Message::EchoReply(msg) => msg.validate_checksum(src, dst),
            ICMPv6Message::RouterSolicitation(msg) => msg.validate_checksum(src, dst),
            ICMPv6Message::RouterAdvertisement(msg) => msg.validate_checksum(src, dst),
            ICMPv6Message::NeighborSolicitation(msg) => msg.validate_checksum(src, dst),
            ICMPv6Message::NeighborAdvertisement(msg) => msg.validate_checksum(src, dst),
            ICMPv6Message::Redirect(msg) => msg.validate_checksum(src, dst),
        }
    }

    /// メッセージタイプを取得
    pub fn message_type(&self) -> ICMPv6MessageType {
        match self {
            ICMPv6Message::DestinationUnreachable(_) => ICMPv6MessageType::DestinationUnreachable,
            ICMPv6Message::PacketTooBig(_) => ICMPv6MessageType::PacketTooBig,
            ICMPv6Message::TimeExceeded(_) => ICMPv6MessageType::TimeExceeded,
            ICMPv6Message::ParameterProblem(_) => ICMPv6MessageType::ParameterProblem,
            ICMPv6Message::EchoRequest(_) => ICMPv6MessageType::EchoRequest,
            ICMPv6Message::EchoReply(_) => ICMPv6MessageType::EchoReply,
            ICMPv6Message::RouterSolicitation(_) => ICMPv6MessageType::RouterSolicitation,
            ICMPv6Message::RouterAdvertisement(_) => ICMPv6MessageType::RouterAdvertisement,
            ICMPv6Message::NeighborSolicitation(_) => ICMPv6MessageType::NeighborSolicitation,
            ICMPv6Message::NeighborAdvertisement(_) => ICMPv6MessageType::NeighborAdvertisement,
            ICMPv6Message::Redirect(_) => ICMPv6MessageType::Redirect,
        }
    }
}

impl TryFromBytes for ICMPv6Message {
    type Error = ICMPv6Error;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();

        if bytes.len() < 4 {
            return Err(ICMPv6Error::InvalidPacketLength(bytes.len()));
        }

        let message_type = ICMPv6MessageType::try_from(bytes[0])?;
        let _code = bytes[1];
        let _checksum = u16::from_be_bytes([bytes[2], bytes[3]]);

        match message_type {
            ICMPv6MessageType::EchoRequest => EchoMessage::try_from_bytes(bytes)
                .map(ICMPv6Message::EchoRequest)
                .map_err(ICMPv6Error::from),
            ICMPv6MessageType::EchoReply => EchoMessage::try_from_bytes(bytes)
                .map(ICMPv6Message::EchoReply)
                .map_err(ICMPv6Error::from),
            ICMPv6MessageType::DestinationUnreachable => {
                DestinationUnreachableMessage::try_from_bytes(bytes)
                    .map(ICMPv6Message::DestinationUnreachable)
                    .map_err(ICMPv6Error::from)
            }
            ICMPv6MessageType::PacketTooBig => PacketTooBigMessage::try_from_bytes(bytes)
                .map(ICMPv6Message::PacketTooBig)
                .map_err(ICMPv6Error::from),
            ICMPv6MessageType::TimeExceeded => TimeExceededMessage::try_from_bytes(bytes)
                .map(ICMPv6Message::TimeExceeded)
                .map_err(ICMPv6Error::from),
            ICMPv6MessageType::ParameterProblem => ParameterProblemMessage::try_from_bytes(bytes)
                .map(ICMPv6Message::ParameterProblem)
                .map_err(ICMPv6Error::from),
            ICMPv6MessageType::RouterSolicitation => {
                RouterSolicitationMessage::try_from_bytes(bytes)
                    .map(ICMPv6Message::RouterSolicitation)
                    .map_err(ICMPv6Error::from)
            }
            ICMPv6MessageType::RouterAdvertisement => {
                RouterAdvertisementMessage::try_from_bytes(bytes)
                    .map(ICMPv6Message::RouterAdvertisement)
                    .map_err(ICMPv6Error::from)
            }
            ICMPv6MessageType::NeighborSolicitation => {
                NeighborSolicitationMessage::try_from_bytes(bytes)
                    .map(ICMPv6Message::NeighborSolicitation)
                    .map_err(ICMPv6Error::from)
            }
            ICMPv6MessageType::NeighborAdvertisement => {
                NeighborAdvertisementMessage::try_from_bytes(bytes)
                    .map(ICMPv6Message::NeighborAdvertisement)
                    .map_err(ICMPv6Error::from)
            }
            ICMPv6MessageType::Redirect => RedirectMessage::try_from_bytes(bytes)
                .map(ICMPv6Message::Redirect)
                .map_err(ICMPv6Error::from),
        }
    }
}

impl From<ICMPv6Message> for Bytes {
    fn from(message: ICMPv6Message) -> Self {
        match message {
            ICMPv6Message::EchoRequest(msg) | ICMPv6Message::EchoReply(msg) => msg.into(),
            ICMPv6Message::DestinationUnreachable(msg) => msg.into(),
            ICMPv6Message::PacketTooBig(msg) => msg.into(),
            ICMPv6Message::TimeExceeded(msg) => msg.into(),
            ICMPv6Message::ParameterProblem(msg) => msg.into(),
            ICMPv6Message::RouterSolicitation(msg) => msg.into(),
            ICMPv6Message::RouterAdvertisement(msg) => msg.into(),
            ICMPv6Message::NeighborSolicitation(msg) => msg.into(),
            ICMPv6Message::NeighborAdvertisement(msg) => msg.into(),
            ICMPv6Message::Redirect(msg) => msg.into(),
        }
    }
}

impl From<&ICMPv6Message> for Bytes {
    fn from(message: &ICMPv6Message) -> Self {
        message.clone().into()
    }
}

impl From<ICMPv6Message> for Vec<u8> {
    fn from(message: ICMPv6Message) -> Self {
        Bytes::from(message).to_vec()
    }
}

impl From<&ICMPv6Message> for Vec<u8> {
    fn from(message: &ICMPv6Message) -> Self {
        Bytes::from(message).to_vec()
    }
}

impl From<ICMPv6Message> for Box<[u8]> {
    fn from(message: ICMPv6Message) -> Self {
        Bytes::from(message).to_vec().into_boxed_slice()
    }
}

impl From<&ICMPv6Message> for Box<[u8]> {
    fn from(message: &ICMPv6Message) -> Self {
        Bytes::from(message).to_vec().into_boxed_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ICMPv6 Echo Request テストデータ
    const ICMPV6_ECHO_REQUEST_BYTES: [u8; 13] = [
        0x80, 0x00, // Type: Echo Request, Code: 0
        0x00, 0x00, // Checksum (placeholder)
        0x12, 0x34, // Identifier
        0x56, 0x78, // Sequence Number
        0x48, 0x65, 0x6C, 0x6C, 0x6F, // "Hello"
    ];

    #[test]
    fn test_icmpv6_echo_message_creation() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // [正常系] Echo Requestメッセージの作成
        let echo_request = ICMPv6Message::echo_request(0x1234, 0x5678, b"Hello", src, dst);
        assert_eq!(echo_request.message_type(), ICMPv6MessageType::EchoRequest);

        if let ICMPv6Message::EchoRequest(echo_msg) = echo_request {
            assert_eq!(echo_msg.identifier, 0x1234);
            assert_eq!(echo_msg.sequence_number, 0x5678);
            assert_eq!(echo_msg.data.as_ref(), b"Hello");
        } else {
            panic!("Expected EchoRequest message");
        }

        // [正常系] Echo Replyメッセージの作成
        let echo_reply = ICMPv6Message::echo_reply(0xABCD, 0xEF01, b"World", src, dst);
        assert_eq!(echo_reply.message_type(), ICMPv6MessageType::EchoReply);

        if let ICMPv6Message::EchoReply(echo_msg) = echo_reply {
            assert_eq!(echo_msg.identifier, 0xABCD);
            assert_eq!(echo_msg.sequence_number, 0xEF01);
            assert_eq!(echo_msg.data.as_ref(), b"World");
        } else {
            panic!("Expected EchoReply message");
        }
    }

    #[test]
    fn test_icmpv6_message_creation() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        // [正常系] ICMPv6Message Echo Request
        let message = ICMPv6Message::echo_request(0x1234, 0x5678, b"ping data", src, dst);
        assert_eq!(message.message_type(), ICMPv6MessageType::EchoRequest);

        // [正常系] Destination Unreachable
        let original_packet = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x04, 0x3A, 0x40, // IPv6 header
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // Destination address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
            0x00, // ICMPv6 header
        ];
        let message = ICMPv6Message::destination_unreachable(
            DestinationUnreachableCode::CommunicationProhibited,
            &original_packet,
            src,
            dst,
        );
        assert_eq!(
            message.message_type(),
            ICMPv6MessageType::DestinationUnreachable
        );

        // [正常系] Packet Too Big
        let message = ICMPv6Message::packet_too_big(1280, &original_packet, src, dst);
        assert_eq!(message.message_type(), ICMPv6MessageType::PacketTooBig);

        // [正常系] Router Solicitation
        let message = ICMPv6Message::router_solicitation(b"options", src, dst);
        assert_eq!(
            message.message_type(),
            ICMPv6MessageType::RouterSolicitation
        );

        // [正常系] Neighbor Solicitation
        let target = Ipv6Addr::LOCALHOST;
        let message = ICMPv6Message::neighbor_solicitation(target, b"options", src, dst);
        assert_eq!(
            message.message_type(),
            ICMPv6MessageType::NeighborSolicitation
        );
    }

    #[test]
    fn test_icmpv6_checksum_validation() {
        // [正常系] ICMPv6チェックサム検証
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let message = ICMPv6Message::echo_request(0x1234, 0x5678, b"test", src, dst);

        // チェックサムの検証を行う
        assert!(message.validate_checksum(src, dst));
    }

    #[test]
    fn test_icmpv6_message_into_bytes() {
        // [正常系] Echo Request
        let src = std::net::Ipv6Addr::LOCALHOST;
        let dst = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let message = ICMPv6Message::echo_request(0x1234, 0x5678, b"Hello", src, dst);
        let bytes: Vec<u8> = message.into();
        assert_eq!(bytes[0], 0x80); // Type: Echo Request
        assert_eq!(bytes[1], 0x00); // Code: 0

        // [正常系] Destination Unreachable
        let original_packet = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x04, 0x3A, 0x40, // IPv6 header
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // Destination address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
            0x00, // ICMPv6 header
        ];
        let message = ICMPv6Message::destination_unreachable(
            DestinationUnreachableCode::CommunicationProhibited,
            &original_packet,
            src,
            dst,
        );
        let bytes: Vec<u8> = message.into();
        assert_eq!(bytes[0], 1); // Type: Destination Unreachable
        assert_eq!(bytes[1], 1); // Code: 1

        // [正常系] Packet Too Big
        let message = ICMPv6Message::packet_too_big(1280, &original_packet, src, dst);
        let bytes: Vec<u8> = message.into();
        assert_eq!(bytes[0], 2); // Type: Packet Too Big
        assert_eq!(bytes[1], 0); // Code: 0
        assert_eq!(
            u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            1280
        );
    }

    #[test]
    fn test_icmpv6_message_from_bytes() {
        // [正常系] Echo Request
        let result = ICMPv6Message::try_from_bytes(&ICMPV6_ECHO_REQUEST_BYTES);
        assert!(result.is_ok());

        let message = result.unwrap();
        assert_eq!(message.message_type(), ICMPv6MessageType::EchoRequest);

        // [異常系] パケットサイズが不足
        let short_packet = [0x80, 0x00, 0x00]; // 3バイト
        let result = ICMPv6Message::try_from_bytes(&short_packet);
        assert!(result.is_err());
        assert!(matches!(
            result.err(),
            Some(ICMPv6Error::InvalidPacketLength(3))
        ));
    }

    #[test]
    fn test_icmpv6_neighbor_discovery_messages() {
        // [正常系] Router Solicitation
        let rs_bytes = [
            133, 0, 0, 0, // Type: 133, Code: 0, Checksum: 0, Reserved: 0
            0, 0, 0, 0, // Reserved
        ];
        let result = ICMPv6Message::try_from_bytes(&rs_bytes);
        assert!(result.is_ok());
        let message = result.unwrap();
        assert_eq!(
            message.message_type(),
            ICMPv6MessageType::RouterSolicitation
        );

        // [正常系] Neighbor Solicitation
        let ns_bytes = [
            135, 0, 0, 0, // Type: 135, Code: 0, Checksum: 0
            0, 0, 0, 0, // Reserved
            // Target Address (::1)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let result = ICMPv6Message::try_from_bytes(&ns_bytes);
        assert!(result.is_ok());
        let message = result.unwrap();
        assert_eq!(
            message.message_type(),
            ICMPv6MessageType::NeighborSolicitation
        );

        match message {
            ICMPv6Message::NeighborSolicitation(ns) => {
                assert_eq!(ns.target_address, Ipv6Addr::LOCALHOST);
            }
            _ => panic!("Expected NeighborSolicitation"),
        }
    }

    #[test]
    fn test_icmpv6_message_round_trip() {
        // [正常系] Echo Request ラウンドトリップ
        let src = std::net::Ipv6Addr::LOCALHOST;
        let dst = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let original = ICMPv6Message::echo_request(0x9999, 0xAAAA, b"Round Trip Test", src, dst);
        let bytes: Vec<u8> = original.clone().into();
        let parsed = ICMPv6Message::try_from_bytes(&bytes).unwrap();
        assert_eq!(original, parsed);

        // [正常系] Destination Unreachable ラウンドトリップ
        let original_packet = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x04, 0x3A, 0x40, // IPv6 header
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // Destination address
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
            0x00, // ICMPv6 header
        ];
        let original = ICMPv6Message::destination_unreachable(
            DestinationUnreachableCode::AddressUnreachable,
            &original_packet,
            src,
            dst,
        );
        let bytes: Vec<u8> = original.clone().into();
        let parsed = ICMPv6Message::try_from_bytes(&bytes).unwrap();
        assert_eq!(original, parsed);
    }
}
