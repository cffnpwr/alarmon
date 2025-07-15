pub mod destination_unreachable;
pub mod echo;
pub mod neighbor_advertisement;
pub mod neighbor_solicitation;
pub mod packet_too_big;
pub mod parameter_problem;
pub mod redirect;
pub mod router_advertisement;
pub mod router_solicitation;
pub mod time_exceeded;

use std::net::Ipv6Addr;

use bytes::{BufMut, Bytes, BytesMut};

pub use self::destination_unreachable::{
    DestinationUnreachableMessage, DestinationUnreachableMessageError,
};
pub use self::echo::{EchoMessage, EchoMessageError};
pub use self::neighbor_advertisement::{
    NeighborAdvertisementMessage, NeighborAdvertisementMessageError,
};
pub use self::neighbor_solicitation::{
    NeighborSolicitationMessage, NeighborSolicitationMessageError,
};
pub use self::packet_too_big::{PacketTooBigMessage, PacketTooBigMessageError};
pub use self::parameter_problem::{ParameterProblemMessage, ParameterProblemMessageError};
pub use self::redirect::{RedirectMessage, RedirectMessageError};
pub use self::router_advertisement::{RouterAdvertisementMessage, RouterAdvertisementMessageError};
pub use self::router_solicitation::{RouterSolicitationMessage, RouterSolicitationMessageError};
pub use self::time_exceeded::{TimeExceededMessage, TimeExceededMessageError};
use crate::checksum::calculate_internet_checksum;
use crate::icmpv6::ICMPv6MessageType;

/// ICMPv6メッセージの共通トレイト
pub trait Message
where
    Bytes: for<'a> From<&'a Self>,
{
    /// メッセージのタイプを取得
    fn message_type(&self) -> ICMPv6MessageType;

    /// メッセージのコードを取得
    fn code(&self) -> u8;

    /// メッセージの全長を取得
    fn total_length(&self) -> usize;

    /// チェックサムを計算
    fn calculate_checksum(&self, src: impl Into<Ipv6Addr>, dst: impl Into<Ipv6Addr>) -> u16 {
        let src: Ipv6Addr = src.into();
        let dst: Ipv6Addr = dst.into();

        let mut data = BytesMut::with_capacity(320 + self.total_length());
        // ICMPv6のチェックサム計算には、IPv6ヘッダーとICMPv6データが必要
        // 疑似IPv6ヘッダーを含める
        data.extend_from_slice(&src.octets());
        data.extend_from_slice(&dst.octets());
        data.put_u32(self.total_length() as u32);
        data.extend_from_slice(&[0; 3]); // ゼロフィールド(24bit)
        data.put_u8(58); // Next Header (ICMPv6は58)
        // ICMPv6メッセージのバイト列を追加
        data.extend_from_slice(&Bytes::from(self));

        calculate_internet_checksum(&data)
    }

    /// チェックサムを検証
    fn validate_checksum(&self, src: impl Into<Ipv6Addr>, dst: impl Into<Ipv6Addr>) -> bool {
        self.calculate_checksum(src, dst) == 0
    }
}
