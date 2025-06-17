const DF_FLAG_MASK: u8 = 0b0100_0000;
const MF_FLAG_MASK: u8 = 0b0010_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags {
    /// Don't Fragment
    /// データグラムをフラグメントするかどうか
    pub df: bool,

    /// More Fragments
    /// 断片化されたデータグラムがまだあるかどうか
    pub mf: bool,
}
impl Default for Flags {
    fn default() -> Self {
        Flags {
            df: false,
            mf: false,
        }
    }
}
impl From<Flags> for u8 {
    fn from(value: Flags) -> Self {
        let mut flags = 0;
        if value.df {
            flags |= DF_FLAG_MASK; // DFフラグ
        }
        if value.mf {
            flags |= MF_FLAG_MASK; // MFフラグ
        }
        flags
    }
}
impl From<Flags> for u16 {
    fn from(value: Flags) -> Self {
        let upper_byte: u8 = value.into();
        u16::from(upper_byte) << 8 // 上位バイトに格納
    }
}
impl From<u8> for Flags {
    fn from(value: u8) -> Self {
        Flags {
            df: (value & DF_FLAG_MASK) != 0,
            mf: (value & MF_FLAG_MASK) != 0,
        }
    }
}
impl From<u16> for Flags {
    fn from(value: u16) -> Self {
        let upper_byte = (value >> 8) as u8;
        upper_byte.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_flags() {
        // Into u8
        let flags = Flags {
            df: false,
            mf: false,
        };
        let value: u8 = flags.into();
        assert_eq!(value, 0b0000_0000);

        let flags = Flags {
            df: true,
            mf: false,
        };
        let value: u8 = flags.into();
        assert_eq!(value, 0b0100_0000);

        let flags = Flags {
            df: false,
            mf: true,
        };
        let value: u8 = flags.into();
        assert_eq!(value, 0b0010_0000);

        let flags = Flags { df: true, mf: true };
        let value: u8 = flags.into();
        assert_eq!(value, 0b0110_0000);

        // Into u16
        let flags = Flags {
            df: false,
            mf: false,
        };
        let value: u16 = flags.into();
        assert_eq!(value, 0b0000_0000_0000_0000);

        let flags = Flags {
            df: true,
            mf: false,
        };
        let value: u16 = flags.into();
        assert_eq!(value, 0b0100_0000_0000_0000);

        let flags = Flags {
            df: false,
            mf: true,
        };
        let value: u16 = flags.into();
        assert_eq!(value, 0b0010_0000_0000_0000);

        let flags = Flags { df: true, mf: true };
        let value: u16 = flags.into();
        assert_eq!(value, 0b0110_0000_0000_0000);
    }

    #[test]
    fn test_into_flags() {
        // From u8
        let flags = Flags::from(0b0000_0000u8);
        assert_eq!(flags.df, false);
        assert_eq!(flags.mf, false);

        let flags = Flags::from(0b0100_0000u8);
        assert_eq!(flags.df, true);
        assert_eq!(flags.mf, false);

        let flags = Flags::from(0b0010_0000u8);
        assert_eq!(flags.df, false);
        assert_eq!(flags.mf, true);

        let flags = Flags::from(0b0110_0000u8);
        assert_eq!(flags.df, true);
        assert_eq!(flags.mf, true);

        // From u16
        let flags = Flags::from(0b0000_0000_0000_0000u16);
        assert_eq!(flags.df, false);
        assert_eq!(flags.mf, false);

        let flags = Flags::from(0b0100_0000_0000_0000u16);
        assert_eq!(flags.df, true);
        assert_eq!(flags.mf, false);

        let flags = Flags::from(0b0010_0000_0000_0000u16);
        assert_eq!(flags.df, false);
        assert_eq!(flags.mf, true);

        let flags = Flags::from(0b0110_0000_0000_0000u16);
        assert_eq!(flags.df, true);
        assert_eq!(flags.mf, true);
    }
}
