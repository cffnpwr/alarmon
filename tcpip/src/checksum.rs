/// Internet Checksum 計算モジュール
/// 
/// RFC 1071に準拠したInternet Checksumの実装
/// IPv4ヘッダーチェックサムやICMPチェックサムで使用される

/// Internet Checksumを計算
/// 
/// # Arguments
/// * `data` - チェックサムを計算するデータ
/// 
/// # Returns
/// 16ビットのチェックサム値
/// 
/// # Example
/// ```
/// use tcpip::checksum::calculate_internet_checksum;
/// 
/// let data = vec![0x45, 0x00, 0x00, 0x3c];
/// let checksum = calculate_internet_checksum(&data);
/// ```
pub fn calculate_internet_checksum(data: &[u8]) -> u16 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_internet_checksum_even_bytes() {
        // [正常系] 偶数バイトのデータ
        let data = vec![0x45, 0x00, 0x00, 0x3c, 0x12, 0x34];
        let checksum = calculate_internet_checksum(&data);
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_calculate_internet_checksum_odd_bytes() {
        // [正常系] 奇数バイトのデータ
        let data = vec![0x45, 0x00, 0x00, 0x3c, 0x12];
        let checksum = calculate_internet_checksum(&data);
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_calculate_internet_checksum_empty() {
        // [正常系] 空データ
        let data = vec![];
        let checksum = calculate_internet_checksum(&data);
        assert_eq!(checksum, 0xFFFF);
    }

    #[test]
    fn test_calculate_internet_checksum_single_byte() {
        // [正常系] 1バイトのデータ
        let data = vec![0xFF];
        let checksum = calculate_internet_checksum(&data);
        assert_eq!(checksum, 0x00FF);
    }

    #[test]
    fn test_checksum_verification() {
        // [正常系] チェックサム検証テスト
        let mut data = vec![0x45, 0x00, 0x00, 0x3c];
        let original_checksum = calculate_internet_checksum(&data);
        
        // チェックサム値をデータに挿入
        data.extend_from_slice(&original_checksum.to_be_bytes());
        
        // チェックサムを含むデータのチェックサムは0になるべき
        let verification_checksum = calculate_internet_checksum(&data);
        assert_eq!(verification_checksum, 0);
    }
}