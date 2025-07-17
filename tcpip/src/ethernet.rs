mod ether_type;
mod mac_address;
mod vlan;

use bytes::{Bytes, BytesMut};
use common_lib::auto_impl_macro::AutoTryFrom;
use thiserror::Error;

pub use self::ether_type::{EtherType, EtherTypeError};
pub use self::mac_address::{MacAddr, MacAddrError};
pub use self::vlan::{VLAN, VLANError};
use crate::TryFromBytes;

/// Ethernetフレーム処理に関するエラー
///
/// Ethernetフレームのパース・検証で発生する可能性のあるエラーを定義します。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EthernetFrameError {
    #[error("Invalid frame length. expected at less than 1514 bytes, but got {0} bytes")]
    InvalidFrameLength(usize),
    #[error(transparent)]
    InvalidMacAddr(#[from] MacAddrError),
    #[error(transparent)]
    InvalidEtherType(#[from] EtherTypeError),
    #[error(transparent)]
    InvalidVlan(#[from] VLANError),
}

/// Ethernetフレーム
///
/// IEEE 802.3標準に基づくEthernetフレーム構造を表現します。
/// VLANタグやQinQにも対応します。
///
/// 参照:
/// - [IEEE 802.3-2018 - Ethernet](https://standards.ieee.org/standard/802_3-2018.html)
/// - [IANA EtherType Numbers](https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml)
/// - [IEEE 802.1Q VLAN Tagging](https://standards.ieee.org/standard/802_1Q-2018.html)
#[derive(Debug, Clone, PartialEq, Eq, AutoTryFrom)]
#[auto_try_from(method = try_from_bytes, error = EthernetFrameError, types = [&[u8], Vec<u8>, Box<[u8]>, Bytes])]
pub struct EthernetFrame {
    pub src: MacAddr,
    pub dst: MacAddr,
    pub ether_type: EtherType,
    pub vlan: Option<VLAN>,
    pub payload: Bytes,
}

impl EthernetFrame {
    pub fn new(
        src: &MacAddr,
        dst: &MacAddr,
        ether_type: &EtherType,
        vlan: Option<&VLAN>,
        payload: impl Into<Bytes>,
    ) -> Self {
        EthernetFrame {
            src: *src,
            dst: *dst,
            ether_type: *ether_type,
            vlan: vlan.cloned(),
            payload: payload.into(),
        }
    }
}

impl TryFromBytes for EthernetFrame {
    type Error = EthernetFrameError;

    fn try_from_bytes(value: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let value = value.as_ref();
        let frame_length = value.len();
        // 本来は最小フレームサイズが６４Byteであるが、キャプチャ手段によってはパディングが削られるので最大サイズのみチェックする
        // Jumbo Frameはサポートしない
        if frame_length > 1514 {
            return Err(EthernetFrameError::InvalidFrameLength(frame_length));
        }

        // MACアドレスを取得
        let dst_mac = MacAddr::try_from(&value[0..6])?;
        let src_mac = MacAddr::try_from(&value[6..12])?;
        // EtherTypeを取得
        let ether_type = EtherType::try_from(&value[12..14])?;
        // VLANタグを取得
        let (ether_type, vlan, vlan_offset) = match ether_type {
            EtherType::VLAN => {
                let vlan = VLAN::try_from(&value[12..16])?;
                let ether_type = EtherType::try_from(&value[16..18])?;
                (ether_type, Some(vlan), 4)
            }
            EtherType::QinQ => {
                let vlan = VLAN::try_from(&value[12..20])?;
                let ether_type = EtherType::try_from(&value[20..22])?;
                (ether_type, Some(vlan), 8)
            }
            ether_type => (ether_type, None, 0),
        };
        // ペイロードを取得
        let payload = Bytes::copy_from_slice(&value[14 + vlan_offset..]);

        Ok(EthernetFrame {
            src: src_mac,
            dst: dst_mac,
            ether_type,
            vlan,
            payload,
        })
    }
}
impl TryFrom<&EthernetFrame> for Bytes {
    type Error = EthernetFrameError;

    fn try_from(value: &EthernetFrame) -> Result<Self, Self::Error> {
        let vlan_size = match value.vlan {
            Some(VLAN::Tag(_)) => 4,
            Some(VLAN::QinQ { .. }) => 8,
            None => 0,
        };
        let frame_size = value.payload.len() + 14 + vlan_size;
        if frame_size > 1514 {
            return Err(EthernetFrameError::InvalidFrameLength(frame_size));
        }

        let final_frame_size = if frame_size < 60 { 60 } else { frame_size };
        let mut bytes = BytesMut::with_capacity(final_frame_size);

        // MACアドレスとEtherType
        let dst: [u8; 6] = value.dst.into();
        let src: [u8; 6] = value.src.into();
        let ether_type: [u8; 2] = value.ether_type.into();

        bytes.extend_from_slice(&dst);
        bytes.extend_from_slice(&src);
        if let Some(vlan) = value.vlan {
            let vlan_bytes: Vec<u8> = vlan.into();
            bytes.extend_from_slice(&vlan_bytes);
        }
        bytes.extend_from_slice(&ether_type);
        bytes.extend_from_slice(&value.payload);

        // Ethernet Frameのサイズが６０Byte未満の場合、パディングを追加
        if frame_size < 60 {
            let padsize = 60 - frame_size;
            bytes.extend(std::iter::repeat_n(0u8, padsize));
        }

        Ok(bytes.freeze())
    }
}
impl TryFrom<EthernetFrame> for Bytes {
    type Error = EthernetFrameError;

    fn try_from(value: EthernetFrame) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}
impl TryFrom<EthernetFrame> for Vec<u8> {
    type Error = EthernetFrameError;

    fn try_from(value: EthernetFrame) -> Result<Self, Self::Error> {
        Bytes::try_from(value).map(|bytes| bytes.to_vec())
    }
}
impl TryFrom<&EthernetFrame> for Vec<u8> {
    type Error = EthernetFrameError;

    fn try_from(value: &EthernetFrame) -> Result<Self, Self::Error> {
        Bytes::try_from(value).map(|bytes| bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::{MacAddr, *};
    use crate::ethernet::vlan::{VLANTag, VLANTagPID};

    const NORMAL_FRAME_BYTES: [u8; 60] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xCD, // dst MAC
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, // src MAC
        0x08, 0x00, // EtherType = IPv4
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // payload
    ];
    const VLAN_FRAME_BYTES: [u8; 64] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xCD, // dst MAC
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, // src MAC
        0x81, 0x00, // VLAN Tag Protocol Identifier
        0x00, 0x01, // VLAN ID = 1
        0x08, 0x00, // EtherType = IPv4
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // payload
    ];
    const QINQ_FRAME_BYTES: [u8; 68] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xCD, // dst MAC
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, // src MAC
        0x88, 0xA8, // S Tag VLAN Tag Protocol Identifier
        0x00, 0x01, // S Tag VLAN ID = 1
        0x81, 0x00, // C Tag VLAN Tag Protocol Identifier
        0x00, 0x02, // C Tag VLAN ID = 2
        0x08, 0x00, // EtherType = IPv4
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // payload
    ];

    #[test]
    fn test_new_ethernet_frame() {
        let src_mac =
            MacAddr::try_from("01:23:45:67:89:AB").expect("Failed to parse src MAC address");
        let dst_mac =
            MacAddr::try_from("01:23:45:67:89:CD").expect("Failed to parse dst MAC address");
        let ether_type = EtherType::IPv4;
        let payload = Bytes::from(vec![0u8; 46]);

        let frame = EthernetFrame::new(&src_mac, &dst_mac, &ether_type, None, payload.clone());
        assert_eq!(frame.src, src_mac);
        assert_eq!(frame.dst, dst_mac);
        assert_eq!(frame.ether_type, ether_type);
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn test_into_ethernet_frame() {
        let src_mac =
            MacAddr::try_from("01:23:45:67:89:AB").expect("Failed to parse src MAC address");
        let dst_mac =
            MacAddr::try_from("01:23:45:67:89:CD").expect("Failed to parse dst MAC address");
        let ether_type = EtherType::IPv4;
        let payload = Bytes::from(vec![0u8; 46]);
        let expected = EthernetFrame::new(&src_mac, &dst_mac, &ether_type, None, payload.clone());

        // TryFrom &[u8]
        // 一般的なEthernet Frame (VLANなし)
        let frame_result = EthernetFrame::try_from(&NORMAL_FRAME_BYTES[..]);
        assert!(frame_result.is_ok());
        assert_eq!(frame_result.unwrap(), expected);

        let frame_result = EthernetFrame::try_from(vec![0u8; 1515].as_slice());
        assert!(frame_result.is_err());
        assert!(matches!(
            frame_result.unwrap_err(),
            EthernetFrameError::InvalidFrameLength(_)
        ));

        // VLANあり
        let vlan_tag =
            VLANTag::new(&VLANTagPID::VLAN, 0, false, 1).expect("Failed to create VLAN tag");
        let expected_vlan = EthernetFrame::new(
            &src_mac,
            &dst_mac,
            &ether_type,
            Some(&VLAN::Tag(vlan_tag)),
            payload.clone(),
        );
        let frame_result = EthernetFrame::try_from(&VLAN_FRAME_BYTES[..]);
        assert!(frame_result.is_ok());
        assert_eq!(frame_result.unwrap(), expected_vlan);

        // VLANあり (QinQ)
        let s_tag =
            VLANTag::new(&VLANTagPID::QinQ, 0, false, 1).expect("Failed to create VLAN tag");
        let c_tag =
            VLANTag::new(&VLANTagPID::VLAN, 0, false, 2).expect("Failed to create VLAN tag");
        let expected_qinq = EthernetFrame::new(
            &src_mac,
            &dst_mac,
            &ether_type,
            Some(&VLAN::QinQ {
                s_tag: s_tag,
                c_tag: c_tag,
            }),
            payload.clone(),
        );
        let frame_result = EthernetFrame::try_from(&QINQ_FRAME_BYTES[..]);
        assert!(frame_result.is_ok());
        assert_eq!(frame_result.unwrap(), expected_qinq);

        // TryFrom Vec<u8>
        let frame_result = EthernetFrame::try_from(NORMAL_FRAME_BYTES.to_vec());
        assert!(frame_result.is_ok());
        assert_eq!(frame_result.unwrap(), expected);
    }

    #[test]
    fn test_from_ethernet_frame() {
        let src_mac =
            MacAddr::try_from("01:23:45:67:89:AB").expect("Failed to parse src MAC address");
        let dst_mac =
            MacAddr::try_from("01:23:45:67:89:CD").expect("Failed to parse dst MAC address");
        let ether_type = EtherType::IPv4;
        let payload = Bytes::from(vec![0u8; 46]);

        // Into Vec<u8>
        let frame = EthernetFrame::new(&src_mac, &dst_mac, &ether_type, None, payload.clone());
        let frame_vec: Result<Vec<u8>, _> = frame.try_into();
        assert!(frame_vec.is_ok());
        assert_eq!(frame_vec.unwrap().as_slice(), NORMAL_FRAME_BYTES);

        // VLANあり
        let vlan_tag =
            VLANTag::new(&VLANTagPID::VLAN, 0, false, 1).expect("Failed to create VLAN tag");
        let vlan_frame = EthernetFrame::new(
            &src_mac,
            &dst_mac,
            &ether_type,
            Some(&VLAN::Tag(vlan_tag)),
            payload.clone(),
        );
        let vlan_frame_vec: Result<Vec<u8>, _> = vlan_frame.try_into();
        assert!(vlan_frame_vec.is_ok());
        assert_eq!(vlan_frame_vec.unwrap().as_slice(), VLAN_FRAME_BYTES);

        // VLANあり (QinQ)
        let s_tag =
            VLANTag::new(&VLANTagPID::QinQ, 0, false, 1).expect("Failed to create VLAN tag");
        let c_tag =
            VLANTag::new(&VLANTagPID::VLAN, 0, false, 2).expect("Failed to create VLAN tag");
        let qinq_frame = EthernetFrame::new(
            &src_mac,
            &dst_mac,
            &ether_type,
            Some(&VLAN::QinQ {
                s_tag: s_tag,
                c_tag: c_tag,
            }),
            payload.clone(),
        );
        let qinq_frame_vec: Result<Vec<u8>, _> = qinq_frame.try_into();
        assert!(qinq_frame_vec.is_ok());
        assert_eq!(qinq_frame_vec.unwrap().as_slice(), QINQ_FRAME_BYTES);

        // ペイロードが1500バイトを超える場合
        let payload = vec![0u8; 1501];
        let frame = EthernetFrame::new(&src_mac, &dst_mac, &ether_type, None, payload.clone());
        let frame_vec: Result<Vec<u8>, _> = frame.try_into();
        assert!(frame_vec.is_err());
        assert!(matches!(
            frame_vec.unwrap_err(),
            EthernetFrameError::InvalidFrameLength(_),
        ));
    }
}
