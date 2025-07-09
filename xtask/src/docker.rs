use std::path::Path;
use std::{env, fs};

use anyhow::Result;
use fxhash::FxHashMap;
use serde::Deserialize;

const DEFAULT_DOCKER_CONTEXT: &str = "default";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DockerConfig {
    current_context: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerMetadata {
    name: String,
    endpoints: DockerEndpoints,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerEndpoints {
    docker: DockerEndpoint,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerEndpoint {
    host: String,
    #[serde(rename = "SkipTLSVerify")]
    skip_tls_verify: bool,
}

#[derive(Debug)]
struct ContextInfo {
    host: String,
    skip_tls_verify: bool,
    tls_path: String,
}

/// Dockerの設定を取得する関数
///
/// 参照: https://docs.docker.com/reference/cli/docker/#configuration-files
pub(crate) fn get_docker_config(context: Option<String>) -> Result<FxHashMap<String, String>> {
    let home_dir = if cfg!(target_os = "windows") {
        format!("C:\\Users\\{}", env::var("USERNAME").unwrap())
    } else {
        env::var("HOME").unwrap()
    };
    let home_dir = Path::new(&home_dir);

    // 現在のDocker Contextを取得
    let context = if let Some(context) = env::var("DOCKER_CONTEXT").ok() {
        context
    } else if let Some(context) = context {
        context
    } else {
        let docker_config_path = env::var("DOCKER_CONFIG").unwrap_or_else(|_| {
            home_dir
                .join(".docker/config.json")
                .to_string_lossy()
                .into_owned()
        });
        let contents = fs::read_to_string(&docker_config_path)
            .map_err(|e| anyhow::anyhow!("Failed to read Docker config file: {}", e))?;
        let config: DockerConfig = serde_json::from_str(&contents)?;
        config.current_context
    };

    let mut socket = None;
    let mut is_tls_verify = None;
    let mut tls_path = None;
    if context != DEFAULT_DOCKER_CONTEXT {
        let contexts_dir = home_dir.join(".docker/contexts/meta/");
        if let Some(context_info) = find_docker_context(&contexts_dir, &context, home_dir)? {
            socket = Some(context_info.host);
            is_tls_verify = Some(context_info.skip_tls_verify);
            tls_path = Some(context_info.tls_path);
        }
    }

    let mut res = FxHashMap::default();
    if let Some(socket) = socket {
        res.insert("DOCKER_HOST".into(), socket);
    }
    if let Some(is_tls_verify) = is_tls_verify
        && is_tls_verify
    {
        res.insert("DOCKER_TLS_VERIFY".into(), is_tls_verify.to_string());
    }
    if let Some(tls_path) = tls_path {
        res.insert("DOCKER_CERT_PATH".into(), tls_path);
    }
    Ok(res)
}

fn find_docker_context(
    contexts_dir: &Path,
    context: &str,
    home_dir: &Path,
) -> Result<Option<ContextInfo>> {
    for entry in fs::read_dir(contexts_dir)? {
        let entry = entry?;
        let meta_path = entry.path().join("meta.json");

        let content = match fs::read_to_string(&meta_path) {
            Ok(content) => content,
            Err(_) => continue,
        };

        let metadata = match serde_json::from_str::<DockerMetadata>(&content) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };

        if metadata.name == context {
            let tls_path = home_dir
                .join(".docker/contexts/tls")
                .join(entry.file_name())
                .join("docker")
                .to_string_lossy()
                .into_owned();

            return Ok(Some(ContextInfo {
                host: metadata.endpoints.docker.host,
                skip_tls_verify: metadata.endpoints.docker.skip_tls_verify,
                tls_path,
            }));
        }
    }
    Ok(None)
}
