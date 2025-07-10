mod cli;
mod docker;
mod workflow;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use workflow::test_workflows;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::TestWorkflows {
            workflow,
            job,
            dry_run,
            os,
            arch,
        } => test_workflows(workflow, job, *dry_run, os, arch).await,
    }
}
