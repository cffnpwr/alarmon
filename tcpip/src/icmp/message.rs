pub mod destination_unreachable;
pub mod echo;
pub mod parameter_problem;
pub mod redirect;
pub mod time_exceeded;
pub mod timestamp;

pub use destination_unreachable::{
    DestinationUnreachableMessage, DestinationUnreachableMessageError,
};
pub use echo::{EchoMessage, EchoMessageError};
pub use parameter_problem::{ParameterProblemMessage, ParameterProblemMessageError};
pub use redirect::{RedirectMessage, RedirectMessageError};
pub use time_exceeded::{TimeExceededMessage, TimeExceededMessageError};
pub use timestamp::{TimestampMessage, TimestampMessageError};

/// ICMPメッセージの共通インターフェース
///
/// 各ICMPメッセージタイプに共通するメッセージタイプとコード取得機能を提供
pub trait Message
where
    Vec<u8>: for<'a> From<&'a Self>,
{
    /// メッセージタイプを取得
    fn msg_type(&self) -> u8;

    /// メッセージコードを取得
    fn code(&self) -> u8;

    /// チェックサムを計算
    fn calculate_checksum(&self) -> u16 {
        let data = Vec::<u8>::from(self);

        let mut sum: u32 = 0;
        let mut i = 0;

        // 16ビット単位で処理
        while i < data.len().saturating_sub(1) {
            let word = u16::from_be_bytes([data[i], data[i + 1]]);
            sum = sum.wrapping_add(word as u32);
            i += 2;
        }

        // 奇数バイトが残っている場合は最後のバイトを処理
        if i < data.len() {
            let word = u16::from_be_bytes([data[i], 0]);
            sum = sum.wrapping_add(word as u32);
        }

        // キャリーを畳み込む
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // 1の補数を取る
        !(sum as u16)
    }

    /// チェックサムを検証
    fn validate_checksum(&self) -> bool {
        self.calculate_checksum() == 0
    }
}
