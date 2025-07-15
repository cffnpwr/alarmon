pub mod destination_unreachable;
pub mod echo;
pub mod parameter_problem;
pub mod redirect;
pub mod time_exceeded;
pub mod timestamp;

use bytes::Bytes;

pub use self::destination_unreachable::{
    DestinationUnreachableMessage, DestinationUnreachableMessageError,
};
pub use self::echo::{EchoMessage, EchoMessageError};
pub use self::parameter_problem::{ParameterProblemMessage, ParameterProblemMessageError};
pub use self::redirect::{RedirectMessage, RedirectMessageError};
pub use self::time_exceeded::{TimeExceededMessage, TimeExceededMessageError};
pub use self::timestamp::{TimestampMessage, TimestampMessageError};
use crate::checksum::calculate_internet_checksum;

/// ICMPメッセージの共通インターフェース
///
/// 各ICMPメッセージタイプに共通するメッセージタイプとコード取得機能を提供
pub trait Message
where
    Bytes: for<'a> From<&'a Self>,
{
    /// メッセージタイプを取得
    fn msg_type(&self) -> u8;

    /// メッセージコードを取得
    fn code(&self) -> u8;

    /// メッセージの長さを取得
    fn total_length(&self) -> usize;

    /// チェックサムを計算
    fn calculate_checksum(&self) -> u16 {
        let data = Bytes::from(self);
        calculate_internet_checksum(&data)
    }

    /// チェックサムを検証
    fn validate_checksum(&self) -> bool {
        self.calculate_checksum() == 0
    }
}
