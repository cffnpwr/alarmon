use std::process::Stdio;

use anyhow::Result;
use tokio::process::Command;

use crate::docker::get_docker_config;

pub async fn test_workflows(
    workflow: &Option<String>,
    job: &Option<String>,
    dry_run: bool,
    os: &str,
    arch: &str,
) -> Result<()> {
    // Docker設定を取得
    let docker_env = get_docker_config(Some("remote".to_string()))?;

    let workflows = match workflow {
        Some(w) => vec![w.as_str()],
        None => vec!["release-pr", "release"],
    };

    for workflow_name in workflows {
        println!("=== Testing workflow: {} ===", workflow_name);

        let workflow_file = format!(".github/workflows/{}.yml", workflow_name);

        if let Some(specific_job) = job {
            run_act_job(&workflow_file, specific_job, dry_run, os, arch, &docker_env).await?;
        } else {
            test_workflow_jobs(
                &workflow_file,
                workflow_name,
                dry_run,
                os,
                arch,
                &docker_env,
            )
            .await?;
        }
    }

    Ok(())
}

async fn run_act_job(
    workflow_file: &str,
    job: &str,
    dry_run: bool,
    os: &str,
    arch: &str,
    docker_env: &fxhash::FxHashMap<String, String>,
) -> Result<()> {
    let mut cmd = Command::new("act");
    cmd.args([
        "-W",
        workflow_file,
        "-j",
        job,
        "--container-architecture",
        arch,
    ]);

    // OSに応じたプラットフォーム設定
    if os.starts_with("macos") || os.starts_with("windows") {
        cmd.args(["-P", &format!("{}=-self-hosted", os)]);
    } else {
        cmd.args(["-P", &format!("{}=catthehacker/ubuntu:act-latest", os)]);
    }

    if dry_run {
        cmd.arg("--dryrun");
    }

    // Docker環境変数を設定
    for (key, value) in docker_env {
        cmd.env(key, value);
    }

    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());

    let status = cmd.status().await?;

    if !status.success() {
        eprintln!("Job {} failed", job);
    }

    Ok(())
}

async fn test_workflow_jobs(
    workflow_file: &str,
    workflow_name: &str,
    dry_run: bool,
    os: &str,
    arch: &str,
    docker_env: &fxhash::FxHashMap<String, String>,
) -> Result<()> {
    let jobs = get_workflow_jobs(workflow_name);

    for (job_id, job_name) in jobs {
        println!("\n--- Testing job: {} ---", job_name);
        run_act_job(workflow_file, job_id, dry_run, os, arch, docker_env).await?;
    }

    Ok(())
}

fn get_workflow_jobs(workflow_name: &str) -> Vec<(&str, &str)> {
    match workflow_name {
        "release-pr" => vec![
            ("validate-pr", "Validate Release PR"),
            ("version-preview", "Version Preview"),
        ],
        "release" => vec![
            ("check-release", "Check Release Necessity"),
            ("prepare-release", "Prepare Release"),
        ],
        _ => {
            println!("Unknown workflow: {}", workflow_name);
            vec![]
        }
    }
}
