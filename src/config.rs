use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::{fmt, fs, io};

use chrono::Duration;
use rand::Rng;
use serde::{Deserialize, Deserializer};
use serde_with::{DurationSeconds, serde_as};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ConfigError {
    #[error("Failed to load {0}. error: {1}")]
    LoadFileError(PathBuf, io::ErrorKind),
    #[error(transparent)]
    TomlParseError(#[from] toml::de::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum TargetHost {
    IpAddress(IpAddr),
    Domain(String),
}

impl fmt::Display for TargetHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetHost::IpAddress(ip) => write!(f, "{ip}"),
            TargetHost::Domain(domain) => write!(f, "{domain}"),
        }
    }
}

impl From<IpAddr> for TargetHost {
    fn from(ip: IpAddr) -> Self {
        TargetHost::IpAddress(ip)
    }
}

impl<'de> Deserialize<'de> for TargetHost {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.parse::<IpAddr>() {
            Ok(ip) => Ok(TargetHost::IpAddress(ip)),
            Err(_) => Ok(TargetHost::Domain(s)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct Target {
    /// 監視対象のID
    #[serde(default)]
    pub(crate) id: u16,

    /// 対象の表示名
    pub(crate) name: String,

    /// 対象のホスト名またはIPアドレス
    pub(crate) host: TargetHost,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct ArpConfig {
    /// ARPテーブルのTTL(秒)
    #[serde(default = "ArpConfig::default_ttl")]
    #[serde_as(as = "DurationSeconds<i64>")]
    pub(crate) ttl: Duration,

    /// ARP応答のタイムアウト(秒)
    #[serde(default = "ArpConfig::default_timeout")]
    #[serde_as(as = "DurationSeconds<i64>")]
    pub(crate) timeout: Duration,
}

impl ArpConfig {
    const fn default_ttl() -> Duration {
        Duration::seconds(30)
    }

    const fn default_timeout() -> Duration {
        Duration::seconds(5)
    }
}

impl Default for ArpConfig {
    fn default() -> Self {
        Self {
            ttl: Self::default_ttl(),
            timeout: Self::default_timeout(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct TracerouteConfig {
    /// traceroute機能の有効/無効
    #[serde(default = "TracerouteConfig::default_enable")]
    pub(crate) enable: bool,

    /// 最大ホップ数
    #[serde(default = "TracerouteConfig::default_max_hops")]
    pub(crate) max_hops: u8,
}

impl TracerouteConfig {
    const fn default_enable() -> bool {
        true
    }

    const fn default_max_hops() -> u8 {
        30
    }
}

impl Default for TracerouteConfig {
    fn default() -> Self {
        Self {
            enable: Self::default_enable(),
            max_hops: Self::default_max_hops(),
        }
    }
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct Config {
    /// 監視対象のリスト
    pub(crate) targets: Vec<Target>,

    /// ICMP Echoの送信間隔(秒)
    /// デフォルトは1秒
    #[serde_as(as = "DurationSeconds<i64>")]
    #[serde(default = "Config::default_interval")]
    pub(crate) interval: Duration,

    /// ICMP Echoのタイムアウト(秒)
    /// デフォルトは5秒
    #[serde_as(as = "DurationSeconds<i64>")]
    #[serde(default = "Config::default_timeout")]
    pub(crate) timeout: Duration,

    /// ARP設定
    #[serde(default)]
    pub(crate) arp: ArpConfig,

    /// Traceroute設定
    #[serde(default)]
    pub(crate) traceroute: TracerouteConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            interval: Self::default_interval(),
            timeout: Self::default_timeout(),
            arp: ArpConfig::default(),
            traceroute: TracerouteConfig::default(),
        }
    }
}
impl Config {
    pub(crate) fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .map_err(|e| ConfigError::LoadFileError(path.to_path_buf(), e.kind()))?;
        let mut cfg: Self = toml::from_str(&content).map_err(ConfigError::TomlParseError)?;

        // IDを上書きする
        let mut rng = rand::rng();
        let start = rng.random::<u16>();
        for (i, target) in cfg.targets.iter_mut().enumerate() {
            if target.id == 0 {
                // IDが未設定の場合はランダムな値を設定
                target.id = start + i as u16;
            }
        }

        Ok(cfg)
    }

    /// デフォルトのICMP Echo送信間隔
    const fn default_interval() -> Duration {
        Duration::seconds(1)
    }

    /// デフォルトのICMP Echoタイムアウト
    const fn default_timeout() -> Duration {
        Duration::seconds(5)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn test_load() {
        // [正常系] 有効なTOMLファイルを読み込む
        let toml_content = r#"
interval = 60
timeout = 5

[[targets]]
name = "Router"
host = "192.168.1.1"

[[targets]]
name = "DNS"
host = "8.8.8.8"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(toml_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config = Config::load(temp_file.path()).unwrap();

        assert_eq!(config.targets.len(), 2);
        assert_eq!(config.targets[0].name, "Router");
        assert_eq!(
            config.targets[0].host,
            TargetHost::IpAddress("192.168.1.1".parse().unwrap())
        );
        assert_eq!(config.targets[1].name, "DNS");
        assert_eq!(
            config.targets[1].host,
            TargetHost::IpAddress("8.8.8.8".parse().unwrap())
        );
        assert_eq!(config.interval, Duration::seconds(60));
        assert_eq!(config.timeout, Duration::seconds(5));
        assert_eq!(config.arp.ttl, Duration::seconds(30)); // デフォルト値
        assert_eq!(config.arp.timeout, Duration::seconds(5)); // デフォルト値

        // [正常系] カスタムARP設定が指定されたTOMLファイルを読み込む
        let toml_with_arp = r#"
interval = 60
timeout = 5

[arp]
ttl = 60
timeout = 10

[traceroute]
enable = false
max_hops = 15

[[targets]]
name = "Router"
host = "192.168.1.1"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(toml_with_arp.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config = Config::load(temp_file.path()).unwrap();
        assert_eq!(config.arp.ttl, Duration::seconds(60)); // カスタム値
        assert_eq!(config.arp.timeout, Duration::seconds(10)); // カスタム値
        assert!(!config.traceroute.enable); // カスタム値
        assert_eq!(config.traceroute.max_hops, 15); // カスタム値

        // [異常系] 存在しないファイルを読み込む
        let non_existent_path = "/path/to/non/existent/file.toml";
        let result = Config::load(non_existent_path);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::LoadFileError(_, io::ErrorKind::NotFound)
        ));

        // [異常系] 無効なTOMLファイルを読み込む
        let invalid_toml = r#"
invalid toml content
[unclosed section
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(invalid_toml.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let result = Config::load(temp_file.path());

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::TomlParseError(_)
        ));

        // [正常系] timeoutフィールドがない場合はデフォルト値が使用される
        let incomplete_toml = r#"
interval = 60
# timeout is missing, should use default
[[targets]]
name = "Router"
host = "192.168.1.1"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(incomplete_toml.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let result = Config::load(temp_file.path());

        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.timeout, Duration::seconds(5)); // デフォルト値
    }

    #[test]
    fn test_target_host() {
        // [正常系] IPv4アドレスのパース
        let ipv4_host: TargetHost = "192.168.1.1".parse::<IpAddr>().unwrap().into();
        assert_eq!(
            ipv4_host,
            TargetHost::IpAddress("192.168.1.1".parse().unwrap())
        );
        assert_eq!(ipv4_host.to_string(), "192.168.1.1");

        // [正常系] IPv6アドレス（短縮形）のパース
        let ipv6_short_host: TargetHost = "2001:db8::1".parse::<IpAddr>().unwrap().into();
        assert_eq!(
            ipv6_short_host,
            TargetHost::IpAddress("2001:db8::1".parse().unwrap())
        );
        assert_eq!(ipv6_short_host.to_string(), "2001:db8::1");

        // [正常系] IPv6アドレス（完全形）のパース
        let ipv6_full_host: TargetHost = "2001:0db8:0000:0000:0000:0000:0000:0001"
            .parse::<IpAddr>()
            .unwrap()
            .into();
        assert_eq!(
            ipv6_full_host,
            TargetHost::IpAddress("2001:0db8:0000:0000:0000:0000:0000:0001".parse().unwrap())
        );
        assert_eq!(ipv6_full_host.to_string(), "2001:db8::1"); // 標準の短縮表示

        // [正常系] Domain名
        let domain_host = TargetHost::Domain("example.com".to_string());
        assert_eq!(domain_host.to_string(), "example.com");
    }

    #[test]
    fn test_target_host_serde() {
        // [正常系] IPv4アドレスのデシリアライズ
        let json_ipv4 = r#""192.168.1.1""#;
        let deserialized: TargetHost = serde_json::from_str(json_ipv4).unwrap();
        assert_eq!(
            deserialized,
            TargetHost::IpAddress("192.168.1.1".parse().unwrap())
        );

        // [正常系] IPv6アドレス（短縮形）のデシリアライズ
        let json_ipv6_short = r#""2001:db8::1""#;
        let deserialized: TargetHost = serde_json::from_str(json_ipv6_short).unwrap();
        assert_eq!(
            deserialized,
            TargetHost::IpAddress("2001:db8::1".parse().unwrap())
        );

        // [正常系] IPv6アドレス（完全形）のデシリアライズ
        let json_ipv6_full = r#""2001:0db8:0000:0000:0000:0000:0000:0001""#;
        let deserialized: TargetHost = serde_json::from_str(json_ipv6_full).unwrap();
        assert_eq!(
            deserialized,
            TargetHost::IpAddress("2001:0db8:0000:0000:0000:0000:0000:0001".parse().unwrap())
        );

        // [正常系] Domain名のデシリアライズ
        let json_domain = r#""example.com""#;
        let deserialized: TargetHost = serde_json::from_str(json_domain).unwrap();
        assert_eq!(deserialized, TargetHost::Domain("example.com".to_string()));

        // [正常系] 無効なIPアドレスはDomainとして扱われる
        let json_invalid = r#""invalid.ip.address""#;
        let deserialized: TargetHost = serde_json::from_str(json_invalid).unwrap();
        assert_eq!(
            deserialized,
            TargetHost::Domain("invalid.ip.address".to_string())
        );
    }
}
