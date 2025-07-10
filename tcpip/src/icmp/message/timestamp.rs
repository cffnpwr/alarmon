use bytes::{Bytes, BytesMut};
use chrono::NaiveTime;
use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;
use crate::icmp::MessageType;
use crate::icmp::message::Message;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TimestampMessageError {
    #[error("Invalid timestamp message type. Expected 13 or 14, but got {0}.")]
    InvalidMessageType(u8),
    #[error("Invalid timestamp message length. Expected 20 bytes, but got {0} bytes.")]
    InvalidMessageLength(usize),
    #[error("Invalid timestamp value. Expected less than 86_400_000, but got {0}.")]
    InvalidTimestamp(u32),
}

/// Timestamp メッセージ
///
/// RFC 792で定義されたTimestamp (Type 13) およびTimestamp Reply (Type 14) のメッセージ構造
/// ネットワーク時刻情報の要求と応答に使用
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = TimestampMessageError, types = [&[u8], Vec<u8>, Box<[u8]>])]
pub struct TimestampMessage {
    /// Is reply
    /// Timestamp RequestかTimestamp Replyかを示すフラグ
    pub is_reply: bool,

    /// Checksum
    pub checksum: u16,

    /// Identifier
    /// 識別子（Echoメッセージと同様）
    pub identifier: u16,

    /// Sequence Number
    /// シーケンス番号（Echoメッセージと同様）
    pub sequence_number: u16,

    /// Originate Timestamp
    /// 送信者がメッセージを送信した時刻（32bit、UTCの午前0時からのミリ秒）
    pub originate_timestamp: NaiveTime,

    /// Receive Timestamp
    /// 受信者がメッセージを受信した時刻（32bit、UTCの午前0時からのミリ秒）
    pub receive_timestamp: NaiveTime,

    /// Transmit Timestamp
    /// 受信者がReplyメッセージを送信した時刻（32bit、UTCの午前0時からのミリ秒）
    pub transmit_timestamp: NaiveTime,
}

impl TimestampMessage {
    /// 新しいTimestampメッセージを作成
    pub fn new(
        is_reply: bool,
        identifier: u16,
        sequence_number: u16,
        originate_timestamp: NaiveTime,
        receive_timestamp: NaiveTime,
        transmit_timestamp: NaiveTime,
    ) -> Self {
        let mut msg = TimestampMessage {
            is_reply,
            checksum: 0, // チェックサムは後で計算する
            identifier,
            sequence_number,
            originate_timestamp,
            receive_timestamp,
            transmit_timestamp,
        };

        // チェックサムを計算して設定
        msg.checksum = msg.calculate_checksum();
        msg
    }

    /// 新しいTimestamp Requestメッセージを作成
    pub fn new_request(
        identifier: u16,
        sequence_number: u16,
        originate_timestamp: NaiveTime,
    ) -> Self {
        Self::new(
            false,
            identifier,
            sequence_number,
            originate_timestamp,
            NaiveTime::MIN,
            NaiveTime::MIN,
        )
    }

    /// 新しいTimestamp Replyメッセージを作成
    pub fn new_reply(
        identifier: u16,
        sequence_number: u16,
        originate_timestamp: NaiveTime,
        receive_timestamp: NaiveTime,
        transmit_timestamp: NaiveTime,
    ) -> Self {
        Self::new(
            true,
            identifier,
            sequence_number,
            originate_timestamp,
            receive_timestamp,
            transmit_timestamp,
        )
    }

    /// RequestからReplyを作成
    pub fn create_reply(
        &self,
        receive_timestamp: NaiveTime,
        transmit_timestamp: NaiveTime,
    ) -> Self {
        Self::new_reply(
            self.identifier,
            self.sequence_number,
            self.originate_timestamp,
            receive_timestamp,
            transmit_timestamp,
        )
    }
}

impl Message for TimestampMessage {
    fn msg_type(&self) -> u8 {
        match self.is_reply {
            true => MessageType::TimestampReply.into(),
            false => MessageType::Timestamp.into(),
        }
    }

    fn code(&self) -> u8 {
        0
    }
}

impl TryFromBytes for TimestampMessage {
    type Error = TimestampMessageError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();
        if bytes.len() != 20 {
            return Err(TimestampMessageError::InvalidMessageLength(bytes.len()));
        }

        let is_reply = match bytes[0] {
            13 => false, // Timestamp Request
            14 => true,  // Timestamp Reply
            msg_type => return Err(TimestampMessageError::InvalidMessageType(msg_type)),
        };

        let checksum = u16::from_be_bytes([bytes[2], bytes[3]]);
        let identifier = u16::from_be_bytes([bytes[4], bytes[5]]);
        let sequence_number = u16::from_be_bytes([bytes[6], bytes[7]]);
        let originate_timestamp = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let receive_timestamp = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let transmit_timestamp = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);

        Ok(TimestampMessage {
            is_reply,
            checksum,
            identifier,
            sequence_number,
            originate_timestamp: naive_time_from_u32(originate_timestamp)?,
            receive_timestamp: naive_time_from_u32(receive_timestamp)?,
            transmit_timestamp: naive_time_from_u32(transmit_timestamp)?,
        })
    }
}

impl From<TimestampMessage> for Bytes {
    fn from(value: TimestampMessage) -> Self {
        let mut bytes = BytesMut::with_capacity(20);

        // Type (1 byte)
        bytes.extend_from_slice(&[value.msg_type()]);
        // Code (1 byte)
        bytes.extend_from_slice(&[value.code()]);
        // Checksum (2 bytes)
        bytes.extend_from_slice(&value.checksum.to_be_bytes());
        // Identifier (2 bytes)
        bytes.extend_from_slice(&value.identifier.to_be_bytes());
        // Sequence Number (2 bytes)
        bytes.extend_from_slice(&value.sequence_number.to_be_bytes());
        // Originate Timestamp (4 bytes)
        bytes.extend_from_slice(&u32_from_naive_time(value.originate_timestamp).to_be_bytes());
        // Receive Timestamp (4 bytes)
        bytes.extend_from_slice(&u32_from_naive_time(value.receive_timestamp).to_be_bytes());
        // Transmit Timestamp (4 bytes)
        bytes.extend_from_slice(&u32_from_naive_time(value.transmit_timestamp).to_be_bytes());

        bytes.freeze()
    }
}

impl From<&TimestampMessage> for Bytes {
    fn from(value: &TimestampMessage) -> Self {
        value.clone().into()
    }
}

impl From<TimestampMessage> for Vec<u8> {
    fn from(value: TimestampMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

impl From<&TimestampMessage> for Vec<u8> {
    fn from(value: &TimestampMessage) -> Self {
        Bytes::from(value).to_vec()
    }
}

/// 世界時の午前0時からのミリ秒をNaiveTimeに変換
fn naive_time_from_u32(value: u32) -> Result<NaiveTime, TimestampMessageError> {
    NaiveTime::from_num_seconds_from_midnight_opt(value / 1000, (value % 1000) * 1_000_000)
        .ok_or(TimestampMessageError::InvalidTimestamp(value))
}

/// NaiveTimeを世界時の午前0時からのミリ秒に変換
fn u32_from_naive_time(time: NaiveTime) -> u32 {
    let delta = time.signed_duration_since(NaiveTime::MIN);
    delta.num_milliseconds() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_naive_time_from_millis(millis: u32) -> NaiveTime {
        NaiveTime::from_num_seconds_from_midnight_opt(millis / 1000, (millis % 1000) * 1_000_000)
            .unwrap()
    }

    #[test]
    fn test_timestamp_message_new_request() {
        // [正常系] Timestamp Requestメッセージの生成
        let originate_time = create_naive_time_from_millis(1000000);
        let message = TimestampMessage::new_request(0x1234, 0x5678, originate_time);

        assert_eq!(message.identifier, 0x1234);
        assert_eq!(message.sequence_number, 0x5678);
        assert_eq!(message.originate_timestamp, originate_time);
        assert_eq!(message.receive_timestamp, NaiveTime::MIN);
        assert_eq!(message.transmit_timestamp, NaiveTime::MIN);
    }

    #[test]
    fn test_timestamp_message_new_reply() {
        // [正常系] Timestamp Replyメッセージの生成
        let originate_time = create_naive_time_from_millis(1000000);
        let receive_time = create_naive_time_from_millis(1000100);
        let transmit_time = create_naive_time_from_millis(1000200);
        let message = TimestampMessage::new_reply(
            0xABCD,
            0xEF01,
            originate_time,
            receive_time,
            transmit_time,
        );

        assert_eq!(message.identifier, 0xABCD);
        assert_eq!(message.sequence_number, 0xEF01);
        assert_eq!(message.originate_timestamp, originate_time);
        assert_eq!(message.receive_timestamp, receive_time);
        assert_eq!(message.transmit_timestamp, transmit_time);
    }

    #[test]
    fn test_timestamp_message_create_reply() {
        // [正常系] RequestからReplyの作成
        let originate_time = create_naive_time_from_millis(500000);
        let receive_time = create_naive_time_from_millis(500050);
        let transmit_time = create_naive_time_from_millis(500100);
        let request = TimestampMessage::new_request(0x1111, 0x2222, originate_time);
        let reply = request.create_reply(receive_time, transmit_time);

        assert_eq!(reply.identifier, 0x1111);
        assert_eq!(reply.sequence_number, 0x2222);
        assert_eq!(reply.originate_timestamp, originate_time);
        assert_eq!(reply.receive_timestamp, receive_time);
        assert_eq!(reply.transmit_timestamp, transmit_time);
    }

    #[test]
    fn test_timestamp_message_try_from_bytes_valid() {
        // [正常系] 有効なバイト列からの変換
        let bytes = [
            0x0D, // Type: Timestamp Request
            0x00, // Code: 0
            0x00, 0x00, // Checksum: 0
            0x12, 0x34, // identifier
            0x56, 0x78, // sequence_number
            0x00, 0x0F, 0x42, 0x40, // originate_timestamp (1000000)
            0x00, 0x0F, 0x42, 0xA4, // receive_timestamp (1000100)
            0x00, 0x0F, 0x43, 0x08, // transmit_timestamp (1000200)
        ];
        let message = TimestampMessage::try_from_bytes(&bytes).unwrap();

        assert_eq!(message.identifier, 0x1234);
        assert_eq!(message.sequence_number, 0x5678);
        assert_eq!(
            message.originate_timestamp,
            create_naive_time_from_millis(1000000)
        );
        assert_eq!(
            message.receive_timestamp,
            create_naive_time_from_millis(1000100)
        );
        assert_eq!(
            message.transmit_timestamp,
            create_naive_time_from_millis(1000200)
        );
    }

    #[test]
    fn test_timestamp_message_try_from_bytes_invalid_length() {
        // [異常系] 不正なメッセージ長
        let short_bytes = [0u8; 19]; // 19バイト（20バイト未満）
        assert!(matches!(
            TimestampMessage::try_from_bytes(&short_bytes).unwrap_err(),
            TimestampMessageError::InvalidMessageLength(19)
        ));

        let long_bytes = [0u8; 21]; // 21バイト（20バイト超過）
        assert!(matches!(
            TimestampMessage::try_from_bytes(&long_bytes).unwrap_err(),
            TimestampMessageError::InvalidMessageLength(21)
        ));

        // [異常系] 不正なメッセージタイプ
        let mut invalid_type_bytes = [0u8; 20];
        invalid_type_bytes[0] = 0x01; // Type: 無効な値（13と14以外）
        assert!(matches!(
            TimestampMessage::try_from_bytes(&invalid_type_bytes).unwrap_err(),
            TimestampMessageError::InvalidMessageType(1)
        ));
    }

    #[test]
    fn test_timestamp_message_round_trip() {
        // [正常系] バイト列変換のラウンドトリップテスト
        let originate_time = create_naive_time_from_millis(2000000);
        let receive_time = create_naive_time_from_millis(2000050);
        let transmit_time = create_naive_time_from_millis(2000100);
        let original = TimestampMessage::new_reply(
            0x9999,
            0xAAAA,
            originate_time,
            receive_time,
            transmit_time,
        );

        let bytes: Vec<u8> = original.clone().into();
        let parsed = TimestampMessage::try_from_bytes(&bytes).unwrap();

        assert_eq!(original, parsed);
    }

    #[test]
    fn test_timestamp_message_into_vec_u8() {
        // [正常系] Vec<u8>への変換
        let originate_time = create_naive_time_from_millis(1000);
        let message = TimestampMessage::new_request(0x1234, 0x5678, originate_time);

        let bytes: Vec<u8> = message.into();
        assert_eq!(bytes.len(), 20);
        assert_eq!(bytes[0], 0x0D); // Type: Timestamp Request
        assert_eq!(bytes[1], 0x00); // Code: 0
        assert_eq!(u16::from_be_bytes([bytes[4], bytes[5]]), 0x1234); // identifier
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 0x5678); // sequence_number
    }
}
