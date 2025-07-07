use bytes::{Bytes, BytesMut};
use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

use crate::TryFromBytes;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LoopbackFrameError {
    #[error("Invalid frame length. expected at least 4 bytes, but got {0} bytes")]
    InvalidFrameLength(usize),
}

/// Loopbackフレーム
///
/// BSD系のOSで独自に用いられるL2フレーム形式
///
/// 参照:
/// - [LINKTYPE_NULL | TCPDUMP & LIBPCAP](https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html)
/// - [freebsd-src/sys/net/if_loop.c at master · freebsd/freebsd-src](https://github.com/freebsd/freebsd-src/blob/master/sys/net/if_loop.c)
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = LoopbackFrameError, types = [&[u8], Vec<u8>, Box<[u8]>, bytes::Bytes])]
pub struct LoopbackFrame {
    /// 上位プロトコルの種類
    ///
    /// BSDのProtocol Familyの値が使用される。
    /// e.g. AF_INET=2
    ///
    /// MacOSの場合はLittle Endianで格納される。
    pub protocol: u32,

    /// フレームのデータ
    pub payload: Bytes,
}
impl LoopbackFrame {
    pub fn new(protocol: u32, payload: impl Into<Bytes>) -> Self {
        Self {
            protocol,
            payload: payload.into(),
        }
    }
}
impl TryFromBytes for LoopbackFrame {
    type Error = LoopbackFrameError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let value = value.as_ref();
        if value.len() < 4 {
            return Err(LoopbackFrameError::InvalidFrameLength(value.len()));
        }

        let protocol = u32::from_le_bytes(value[0..4].try_into().unwrap());
        let payload = Bytes::from(value[4..].to_vec());

        Ok(Self { protocol, payload })
    }
}
impl From<&LoopbackFrame> for Bytes {
    fn from(frame: &LoopbackFrame) -> Self {
        let mut bytes = BytesMut::with_capacity(4 + frame.payload.len());
        bytes.extend_from_slice(&frame.protocol.to_le_bytes());
        bytes.extend_from_slice(&frame.payload);
        bytes.freeze()
    }
}
impl From<LoopbackFrame> for Bytes {
    fn from(frame: LoopbackFrame) -> Self {
        Self::from(&frame)
    }
}
impl From<LoopbackFrame> for Vec<u8> {
    fn from(frame: LoopbackFrame) -> Self {
        Bytes::from(frame).to_vec()
    }
}
impl From<&LoopbackFrame> for Vec<u8> {
    fn from(frame: &LoopbackFrame) -> Self {
        Bytes::from(frame).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NORMAL_FRAME_BYTES: [u8; 8] = [
        0x02, 0x00, 0x00, 0x00, // protocol = AF_INET (2) in little endian
        0x01, 0x02, 0x03, 0x04, // payload
    ];

    #[test]
    fn test_new_loopback_frame() {
        // [正常系] Loopbackフレームの作成
        let protocol = 2; // AF_INET
        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let frame = LoopbackFrame::new(protocol, payload.clone());

        assert_eq!(frame.protocol, protocol);
        assert_eq!(frame.payload, Bytes::from(payload));
    }

    #[test]
    fn test_into_loopback_frame() {
        let expected_protocol = 2; // AF_INET
        let expected_payload = Bytes::from(vec![0x01, 0x02, 0x03, 0x04]);
        let expected = LoopbackFrame::new(expected_protocol, expected_payload.clone());

        // [正常系] &[u8]からの変換
        let frame_result = LoopbackFrame::try_from(&NORMAL_FRAME_BYTES[..]);
        assert!(frame_result.is_ok());
        assert_eq!(frame_result.unwrap(), expected);

        // [正常系] Vec<u8>からの変換
        let frame_result = LoopbackFrame::try_from(NORMAL_FRAME_BYTES.to_vec());
        assert!(frame_result.is_ok());
        assert_eq!(frame_result.unwrap(), expected);

        // [正常系] Bytesからの変換
        let frame_result = LoopbackFrame::try_from(Bytes::from(NORMAL_FRAME_BYTES.to_vec()));
        assert!(frame_result.is_ok());
        assert_eq!(frame_result.unwrap(), expected);

        // [異常系] 4バイト未満のデータからの変換
        let frame_result = LoopbackFrame::try_from(&[0x01, 0x02, 0x03][..]);
        assert!(frame_result.is_err());
        assert!(matches!(
            frame_result.unwrap_err(),
            LoopbackFrameError::InvalidFrameLength(3)
        ));
    }

    #[test]
    fn test_from_loopback_frame() {
        let protocol = 2; // AF_INET
        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let frame = LoopbackFrame::new(protocol, payload.clone());

        // [正常系] Bytesへの変換
        let frame_bytes: Bytes = frame.clone().into();
        assert_eq!(frame_bytes, Bytes::from(NORMAL_FRAME_BYTES.to_vec()));

        // [正常系] &LoopbackFrameからBytesへの変換
        let frame_bytes: Bytes = (&frame).into();
        assert_eq!(frame_bytes, Bytes::from(NORMAL_FRAME_BYTES.to_vec()));

        // [正常系] Vec<u8>への変換
        let frame_vec: Vec<u8> = frame.clone().into();
        assert_eq!(frame_vec, NORMAL_FRAME_BYTES.to_vec());

        // [正常系] &LoopbackFrameからVec<u8>への変換
        let frame_vec: Vec<u8> = (&frame).into();
        assert_eq!(frame_vec, NORMAL_FRAME_BYTES.to_vec());
    }
}
