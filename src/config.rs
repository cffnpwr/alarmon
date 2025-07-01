use std::path::{Path, PathBuf};
use std::{fs, io};

use chrono::Duration;
use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ConfigError {
    #[error("Failed to load {0}. error: {1}")]
    LoadFileError(PathBuf, io::ErrorKind),
    #[error(transparent)]
    TomlParseError(#[from] toml::de::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct Target {
    /// 対象の表示名
    pub(crate) name: String,

    /// 対象のホスト名またはIPアドレス
    pub(crate) host: String,
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct Config {
    /// 監視対象のリスト
    pub(crate) targets: Vec<Target>,

    /// ICMP Echoの送信間隔(秒)
    #[serde_as(as = "DurationSeconds<i64>")]
    pub(crate) interval: Duration,

    /// ICMP Echoのタイムアウト(秒)
    #[serde_as(as = "DurationSeconds<i64>")]
    pub(crate) timeout: Duration,
}
impl Config {
    pub(crate) fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .map_err(|e| ConfigError::LoadFileError(path.to_path_buf(), e.kind()))?;
        toml::from_str(&content).map_err(ConfigError::TomlParseError)
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
        assert_eq!(config.targets[0].host, "192.168.1.1");
        assert_eq!(config.targets[1].name, "DNS");
        assert_eq!(config.targets[1].host, "8.8.8.8");
        assert_eq!(config.interval, Duration::seconds(60));
        assert_eq!(config.timeout, Duration::seconds(5));

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

        // [異常系] 必須フィールドが不足しているTOMLファイルを読み込む
        let incomplete_toml = r#"
interval = 60
# timeout is missing
[[targets]]
name = "Router"
host = "192.168.1.1"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(incomplete_toml.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let result = Config::load(temp_file.path());

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConfigError::TomlParseError(_)
        ));
    }
}
