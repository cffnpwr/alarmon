use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Error)]
pub enum VLANTagPIDError {
    #[error("{0:X} is Invalid VLAN Tag PID")]
    InvalidVlanTagPID(u16),
    #[error("Invalid size of VLAN Tag PID")]
    InvalidVlanTagPIDSize,
}

/// VLAN Tag Protocol Identifier
#[derive(Debug, Clone, PartialEq)]
pub enum VLANTagPID {
    /// VLAN
    VLAN = 0x8100,

    /// QinQ
    /// 二重VLAN IEEE 802.1Q
    QinQ = 0x88A8,
}
impl TryFrom<u16> for VLANTagPID {
    type Error = VLANTagPIDError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x8100 => Ok(VLANTagPID::VLAN),
            0x88A8 => Ok(VLANTagPID::QinQ),
            _ => Err(VLANTagPIDError::InvalidVlanTagPID(value)),
        }
    }
}
impl TryFrom<[u8; 2]> for VLANTagPID {
    type Error = VLANTagPIDError;

    fn try_from(value: [u8; 2]) -> Result<Self, Self::Error> {
        let value = u16::from_be_bytes(value);
        VLANTagPID::try_from(value)
    }
}
impl TryFrom<&[u8; 2]> for VLANTagPID {
    type Error = VLANTagPIDError;

    fn try_from(value: &[u8; 2]) -> Result<Self, Self::Error> {
        let value = u16::from_be_bytes(*value);
        VLANTagPID::try_from(value)
    }
}
impl TryFrom<&[u8]> for VLANTagPID {
    type Error = VLANTagPIDError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 2 {
            return Err(VLANTagPIDError::InvalidVlanTagPIDSize);
        }
        let value = u16::from_be_bytes([value[0], value[1]]);
        VLANTagPID::try_from(value)
    }
}
impl TryFrom<Vec<u8>> for VLANTagPID {
    type Error = VLANTagPIDError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        VLANTagPID::try_from(value.as_slice())
    }
}
impl From<VLANTagPID> for u16 {
    fn from(val: VLANTagPID) -> Self {
        val as u16
    }
}
impl From<VLANTagPID> for [u8; 2] {
    fn from(value: VLANTagPID) -> Self {
        let value = value as u16;
        value.to_be_bytes()
    }
}
impl From<VLANTagPID> for Vec<u8> {
    fn from(value: VLANTagPID) -> Self {
        let bytes: [u8; 2] = value.into();
        bytes.to_vec()
    }
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum VLANTagError {
    #[error("Invalid VLAN Tag PID: {0}")]
    InvalidVlanTagPID(#[from] VLANTagPIDError),
    #[error("Invalid VLAN Tag")]
    InvalidVlanTag,
    #[error("Invalid size of VLAN Tag")]
    InvalidVlanTagSize,
    #[error("{0} is invalid VLAN Tag PCP")]
    InvalidVlanTagPCP(u8),
    #[error("{0} is invalid VLAN Tag VID")]
    InvalidVlanVID(u16),
}

#[derive(Debug, Clone, PartialEq)]
pub struct VLANTag {
    /// Tag Protocol Identifier
    pub tpid: VLANTagPID,

    /// Priority Code Point
    /// 優先度の値
    /// 0-7の範囲で7が最優先
    pub pcp: u8,

    /// Drop Eligible Indicator
    /// 輻輳が発生した場合に破棄してもいいかのフラグ
    pub dei: bool,

    /// VLAN Identifier
    /// 0-4094の範囲
    pub vid: u16,
}
impl VLANTag {
    pub fn new(tpid: &VLANTagPID, pcp: u8, dei: bool, vid: u16) -> Result<Self, VLANTagError> {
        if pcp > 7 {
            return Err(VLANTagError::InvalidVlanTagPCP(pcp));
        }
        if vid > 4094 {
            return Err(VLANTagError::InvalidVlanVID(vid));
        }
        Ok(VLANTag {
            tpid: tpid.clone(),
            pcp,
            dei,
            vid,
        })
    }
}
impl TryFrom<[u8; 4]> for VLANTag {
    type Error = VLANTagError;

    fn try_from(value: [u8; 4]) -> Result<Self, Self::Error> {
        let tpid = VLANTagPID::try_from(&value[0..2])?;
        let pcp = (value[2] & 0b11100000) >> 5;
        let dei = (value[2] & 0b00010000) != 0;
        let vid = u16::from_be_bytes([value[2] & 0b00001111, value[3]]);
        if vid > 4094 {
            return Err(VLANTagError::InvalidVlanVID(vid));
        }

        Ok(VLANTag {
            tpid,
            pcp,
            dei,
            vid,
        })
    }
}
impl TryFrom<&[u8; 4]> for VLANTag {
    type Error = VLANTagError;

    fn try_from(value: &[u8; 4]) -> Result<Self, Self::Error> {
        VLANTag::try_from(*value)
    }
}
impl TryFrom<&[u8]> for VLANTag {
    type Error = VLANTagError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 4 {
            return Err(VLANTagError::InvalidVlanTagSize);
        }
        let value = [value[0], value[1], value[2], value[3]];
        VLANTag::try_from(&value)
    }
}
impl TryFrom<Vec<u8>> for VLANTag {
    type Error = VLANTagError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        VLANTag::try_from(value.as_slice())
    }
}
impl From<VLANTag> for [u8; 4] {
    fn from(value: VLANTag) -> Self {
        let mut bytes = [0; 4];
        bytes[0..2].copy_from_slice(&Into::<[u8; 2]>::into(value.tpid));
        bytes[2] = (value.pcp << 5) | (value.dei as u8) << 4 | (value.vid >> 8) as u8;
        bytes[3] = value.vid as u8;
        bytes
    }
}
impl From<VLANTag> for Vec<u8> {
    fn from(value: VLANTag) -> Self {
        let bytes: [u8; 4] = value.into();
        bytes.to_vec()
    }
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum VLANError {
    #[error("Invalid VLAN Tag: {0}")]
    InvalidVlanTag(#[from] VLANTagError),
    #[error("Invalid size of VLAN")]
    InvalidVlanSize,
    #[error("{0:X} is invalid QinQ Tag")]
    InvalidQinQTag(u16),
}

#[derive(Debug, Clone, PartialEq)]
pub enum VLAN {
    /// VLAN Tag
    Tag(VLANTag),

    /// Double VLAN Tag
    /// 二重VLAN IEEE 802.1Q
    QinQ {
        /// Service VLAN Tag
        s_tag: VLANTag,
        /// Customer VLAN Tag
        c_tag: VLANTag,
    },
}
impl TryFrom<[u8; 4]> for VLAN {
    type Error = VLANError;

    fn try_from(value: [u8; 4]) -> Result<Self, Self::Error> {
        let tag = VLANTag::try_from(value)?;
        Ok(VLAN::Tag(tag))
    }
}
impl TryFrom<&[u8; 4]> for VLAN {
    type Error = VLANError;

    fn try_from(value: &[u8; 4]) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}
impl TryFrom<[u8; 8]> for VLAN {
    type Error = VLANError;

    fn try_from(value: [u8; 8]) -> Result<Self, Self::Error> {
        let s_tag = VLANTag::try_from(&value[0..4])?;
        if s_tag.tpid != VLANTagPID::QinQ {
            return Err(VLANError::InvalidQinQTag(s_tag.tpid.into()));
        }
        let c_tag = VLANTag::try_from(&value[4..8])?;
        Ok(VLAN::QinQ { c_tag, s_tag })
    }
}
impl TryFrom<&[u8; 8]> for VLAN {
    type Error = VLANError;

    fn try_from(value: &[u8; 8]) -> Result<Self, Self::Error> {
        (*value).try_into()
    }
}
impl TryFrom<&[u8]> for VLAN {
    type Error = VLANError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() == 4 {
            let value = [value[0], value[1], value[2], value[3]];
            return value.try_into();
        } else if value.len() == 8 {
            let value = [
                value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
            ];
            return value.try_into();
        }
        Err(VLANError::InvalidVlanSize)
    }
}
impl From<VLAN> for Vec<u8> {
    fn from(value: VLAN) -> Self {
        match value {
            VLAN::Tag(tag) => tag.into(),
            VLAN::QinQ { s_tag, c_tag } => {
                let mut bytes = Vec::with_capacity(8);
                bytes.extend_from_slice(&Into::<[u8; 4]>::into(s_tag));
                bytes.extend_from_slice(&Into::<[u8; 4]>::into(c_tag));
                bytes
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_into_vlan_tag_pid() {
        const VLAN_TAG_PID: u16 = 0x8100;
        const QINQ_TAG_PID: u16 = 0x88A8;
        const VLAN_TAG_PID_BYTES: [u8; 2] = [0x81, 0x00];
        const QINQ_TAG_PID_BYTES: [u8; 2] = [0x88, 0xA8];

        // From u16
        let pid = VLANTagPID::try_from(VLAN_TAG_PID);
        assert!(pid.is_ok());
        assert_eq!(pid.unwrap(), VLANTagPID::VLAN);

        let pid = VLANTagPID::try_from(QINQ_TAG_PID);
        assert!(pid.is_ok());
        assert_eq!(pid.unwrap(), VLANTagPID::QinQ);

        let err = VLANTagPID::try_from(0x1234);
        assert!(err.is_err());
        assert_eq!(err.unwrap_err(), VLANTagPIDError::InvalidVlanTagPID(0x1234));

        // From [u8; 2]
        let pid = VLANTagPID::try_from(VLAN_TAG_PID_BYTES);
        assert!(pid.is_ok());
        assert_eq!(pid.unwrap(), VLANTagPID::VLAN);

        let pid = VLANTagPID::try_from(QINQ_TAG_PID_BYTES);
        assert!(pid.is_ok());
        assert_eq!(pid.unwrap(), VLANTagPID::QinQ);

        // From &[u8; 2]
        let pid = VLANTagPID::try_from(&VLAN_TAG_PID_BYTES);
        assert!(pid.is_ok());
        assert_eq!(pid.unwrap(), VLANTagPID::VLAN);

        let pid = VLANTagPID::try_from(&QINQ_TAG_PID_BYTES);
        assert!(pid.is_ok());
        assert_eq!(pid.unwrap(), VLANTagPID::QinQ);

        // From &[u8]
        let pid = VLANTagPID::try_from(&VLAN_TAG_PID_BYTES[..]);
        assert!(pid.is_ok());
        assert_eq!(pid.unwrap(), VLANTagPID::VLAN);

        let pid = VLANTagPID::try_from(&QINQ_TAG_PID_BYTES[..]);
        assert!(pid.is_ok());
        assert_eq!(pid.unwrap(), VLANTagPID::QinQ);

        let err = VLANTagPID::try_from(&[0x12, 0x34, 0x56][..]);
        assert!(err.is_err());
        assert_eq!(err.unwrap_err(), VLANTagPIDError::InvalidVlanTagPIDSize);

        // From Vec<u8>
        let pid = VLANTagPID::try_from(VLAN_TAG_PID_BYTES.to_vec());
        assert!(pid.is_ok());
        assert_eq!(pid.unwrap(), VLANTagPID::VLAN);

        let pid = VLANTagPID::try_from(QINQ_TAG_PID_BYTES.to_vec());
        assert!(pid.is_ok());
        assert_eq!(pid.unwrap(), VLANTagPID::QinQ);
    }

    #[test]
    fn test_from_vlan_tag_pid() {
        // Into u16
        let pid_u16 = u16::from(VLANTagPID::VLAN);
        assert_eq!(pid_u16, 0x8100);

        let pid_u16 = u16::from(VLANTagPID::QinQ);
        assert_eq!(pid_u16, 0x88A8);

        // Into [u8; 2]
        let pid_bytes: [u8; 2] = VLANTagPID::VLAN.into();
        assert_eq!(pid_bytes, [0x81, 0x00]);

        let pid_bytes: [u8; 2] = VLANTagPID::QinQ.into();
        assert_eq!(pid_bytes, [0x88, 0xA8]);

        // Into Vec<u8>
        let pid_vec: Vec<u8> = VLANTagPID::VLAN.into();
        assert_eq!(pid_vec, vec![0x81, 0x00]);

        let pid_vec: Vec<u8> = VLANTagPID::QinQ.into();
        assert_eq!(pid_vec, vec![0x88, 0xA8]);
    }

    #[test]
    fn test_try_into_vlan_tag() {
        const VLAN_TAG: [u8; 4] = [0x81, 0x00, 0x00, 0x01];
        const VLAN_TAG_INVALID: [u8; 4] = [0x81, 0x00, 0x0F, 0xFF];

        // From [u8; 4]
        let tag = VLANTag::try_from(VLAN_TAG);
        let expected = VLANTag {
            tpid: VLANTagPID::VLAN,
            pcp: 0,
            dei: false,
            vid: 1,
        };
        assert!(tag.is_ok());
        assert_eq!(tag.unwrap(), expected);

        let err = VLANTag::try_from(VLAN_TAG_INVALID);
        assert!(err.is_err());
        assert_eq!(err.unwrap_err(), VLANTagError::InvalidVlanVID(4095));

        // From &[u8; 4]
        let tag = VLANTag::try_from(&VLAN_TAG);
        let expected = VLANTag {
            tpid: VLANTagPID::VLAN,
            pcp: 0,
            dei: false,
            vid: 1,
        };
        assert!(tag.is_ok());
        assert_eq!(tag.unwrap(), expected);

        // From &[u8]
        let tag = VLANTag::try_from(&VLAN_TAG[..]);
        let expected = VLANTag {
            tpid: VLANTagPID::VLAN,
            pcp: 0,
            dei: false,
            vid: 1,
        };
        assert!(tag.is_ok());
        assert_eq!(tag.unwrap(), expected);

        let tag = VLANTag::try_from(&[0x00][..]);
        assert!(tag.is_err());
        assert_eq!(tag.unwrap_err(), VLANTagError::InvalidVlanTagSize);

        // From Vec<u8>
        let tag = VLANTag::try_from(VLAN_TAG.to_vec());
        let expected = VLANTag {
            tpid: VLANTagPID::VLAN,
            pcp: 0,
            dei: false,
            vid: 1,
        };
        assert!(tag.is_ok());
        assert_eq!(tag.unwrap(), expected);
    }

    #[test]
    fn test_from_vlan_tag() {
        // Into [u8; 4]
        let tag = VLANTag {
            tpid: VLANTagPID::VLAN,
            pcp: 0,
            dei: false,
            vid: 1,
        };
        let bytes: [u8; 4] = tag.into();
        assert_eq!(bytes, [0x81, 0x00, 0x00, 0x01]);

        let tag = VLANTag {
            tpid: VLANTagPID::QinQ,
            pcp: 0,
            dei: false,
            vid: 1,
        };
        let bytes: [u8; 4] = tag.into();
        assert_eq!(bytes, [0x88, 0xA8, 0x00, 0x01]);

        // Into Vec<u8>
        let tag = VLANTag {
            tpid: VLANTagPID::VLAN,
            pcp: 0,
            dei: false,
            vid: 1,
        };
        let bytes: Vec<u8> = tag.into();
        assert_eq!(bytes, vec![0x81, 0x00, 0x00, 0x01]);

        let tag = VLANTag {
            tpid: VLANTagPID::QinQ,
            pcp: 0,
            dei: false,
            vid: 1,
        };
        let bytes: Vec<u8> = tag.into();
        assert_eq!(bytes, vec![0x88, 0xA8, 0x00, 0x01]);
    }

    #[test]
    fn test_try_into_vlan() {
        const VLAN_TAG: [u8; 4] = [0x81, 0x00, 0x00, 0x01];
        const QINQ_TAG: [u8; 8] = [0x88, 0xA8, 0x00, 0x01, 0x81, 0x00, 0x00, 0x02];
        const QINQ_TAG_INVALID: [u8; 8] = [0x81, 0x00, 0x00, 0x01, 0x81, 0x00, 0x00, 0x02];

        // From [u8; 4]
        let vlan = VLAN::try_from(VLAN_TAG);
        let expected = VLAN::Tag(VLANTag {
            tpid: VLANTagPID::VLAN,
            pcp: 0,
            dei: false,
            vid: 1,
        });
        assert!(vlan.is_ok());
        assert_eq!(vlan.unwrap(), expected);

        // From &[u8; 4]
        let vlan = VLAN::try_from(&VLAN_TAG);
        let expected = VLAN::Tag(VLANTag {
            tpid: VLANTagPID::VLAN,
            pcp: 0,
            dei: false,
            vid: 1,
        });
        assert!(vlan.is_ok());
        assert_eq!(vlan.unwrap(), expected);

        // From [u8; 8]
        let vlan = VLAN::try_from(QINQ_TAG);
        let expected = VLAN::QinQ {
            s_tag: VLANTag {
                tpid: VLANTagPID::QinQ,
                pcp: 0,
                dei: false,
                vid: 1,
            },
            c_tag: VLANTag {
                tpid: VLANTagPID::VLAN,
                pcp: 0,
                dei: false,
                vid: 2,
            },
        };
        assert!(vlan.is_ok());
        assert_eq!(vlan.unwrap(), expected);

        let err = VLAN::try_from(QINQ_TAG_INVALID);
        assert!(err.is_err());
        assert_eq!(err.unwrap_err(), VLANError::InvalidQinQTag(0x8100));

        // From &[u8; 8]
        let vlan = VLAN::try_from(&QINQ_TAG);
        assert!(vlan.is_ok());
        assert_eq!(vlan.unwrap(), expected);

        // From &[u8]
        let vlan = VLAN::try_from(&VLAN_TAG[..]);
        let expected = VLAN::Tag(VLANTag {
            tpid: VLANTagPID::VLAN,
            pcp: 0,
            dei: false,
            vid: 1,
        });
        assert!(vlan.is_ok());
        assert_eq!(vlan.unwrap(), expected);

        let vlan = VLAN::try_from(&QINQ_TAG[..]);
        let expected = VLAN::QinQ {
            s_tag: VLANTag {
                tpid: VLANTagPID::QinQ,
                pcp: 0,
                dei: false,
                vid: 1,
            },
            c_tag: VLANTag {
                tpid: VLANTagPID::VLAN,
                pcp: 0,
                dei: false,
                vid: 2,
            },
        };
        assert!(vlan.is_ok());
        assert_eq!(vlan.unwrap(), expected);

        let err = VLAN::try_from(&[0x00][..]);
        assert!(err.is_err());
        assert_eq!(err.unwrap_err(), VLANError::InvalidVlanSize);
    }

    #[test]
    fn test_from_vlan() {
        // Into Vec<u8>
        let vlan = VLAN::Tag(VLANTag {
            tpid: VLANTagPID::VLAN,
            pcp: 0,
            dei: false,
            vid: 1,
        });
        let bytes: Vec<u8> = vlan.into();
        assert_eq!(bytes, vec![0x81, 0x00, 0x00, 0x01]);

        let vlan = VLAN::QinQ {
            s_tag: VLANTag {
                tpid: VLANTagPID::QinQ,
                pcp: 0,
                dei: false,
                vid: 1,
            },
            c_tag: VLANTag {
                tpid: VLANTagPID::VLAN,
                pcp: 0,
                dei: false,
                vid: 2,
            },
        };
        let bytes: Vec<u8> = vlan.into();
        assert_eq!(bytes, vec![0x88, 0xA8, 0x00, 0x01, 0x81, 0x00, 0x00, 0x02]);
    }
}
