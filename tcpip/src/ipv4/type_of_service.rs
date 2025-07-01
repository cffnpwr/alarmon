const TOS_MASK_PRECEDENCE: u8 = 0b11100000;
const TOS_LOW_DELAY: u8 = 0b10000;
const TOS_HIGH_THROUGHPUT: u8 = 0b01000;
const TOS_HIGH_RELIABILITY: u8 = 0b00100;
const TOS_LOW_COST: u8 = 0b00010;
const TOS_UNUSED: u8 = 0b00001;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TypeOfService {
    /// 優先順位
    /// 0-7の値をとる
    pub precedence: u8,

    /// 低遅延フラグ
    pub low_delay: bool,

    /// 高スループットフラグ
    pub high_throughput: bool,

    /// 高信頼性フラグ
    pub high_reliability: bool,

    /// 低コストフラグ
    pub low_cost: bool,

    /// 未使用フィールド
    /// パケットの等価性のために必要
    /// 基本的に0
    pub unused: bool,
}
impl From<TypeOfService> for u8 {
    fn from(value: TypeOfService) -> Self {
        // 優先順位は上位3ビットに格納される
        let mut tos = (value.precedence << 5) & TOS_MASK_PRECEDENCE;
        if value.low_delay {
            tos |= TOS_LOW_DELAY;
        }
        if value.high_throughput {
            tos |= TOS_HIGH_THROUGHPUT;
        }
        if value.high_reliability {
            tos |= TOS_HIGH_RELIABILITY;
        }
        if value.low_cost {
            tos |= TOS_LOW_COST;
        }
        if value.unused {
            tos |= TOS_UNUSED;
        }
        tos
    }
}
impl From<u8> for TypeOfService {
    fn from(value: u8) -> Self {
        TypeOfService {
            precedence: (value & TOS_MASK_PRECEDENCE) >> 5,
            low_delay: (value & TOS_LOW_DELAY) != 0,
            high_throughput: (value & TOS_HIGH_THROUGHPUT) != 0,
            high_reliability: (value & TOS_HIGH_RELIABILITY) != 0,
            low_cost: (value & TOS_LOW_COST) != 0,
            unused: (value & TOS_UNUSED) != 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_type_of_service() {
        // Into u8
        let tos = TypeOfService {
            precedence: 5,
            low_delay: true,
            high_throughput: true,
            high_reliability: true,
            low_cost: true,
            unused: true,
        };
        let value: u8 = tos.into();
        assert_eq!(value, 0b10111111);
    }

    #[test]
    fn test_into_type_of_service() {
        // From u8
        let tos = TypeOfService::from(0b10111111u8);
        assert_eq!(tos.precedence, 5);
        assert_eq!(tos.low_delay, true);
        assert_eq!(tos.high_throughput, true);
        assert_eq!(tos.high_reliability, true);
        assert_eq!(tos.low_cost, true);
        assert_eq!(tos.unused, true);
    }
}
