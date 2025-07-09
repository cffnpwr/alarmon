use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Development automation tasks for alarmon")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Test workflows with Act
    TestWorkflows {
        /// Specific workflow to test
        #[arg(short, long)]
        workflow: Option<String>,

        /// Specific job to test
        #[arg(short, long)]
        job: Option<String>,

        /// dry run mode
        #[arg(long)]
        dry_run: bool,

        /// Target OS for containers (ubuntu-latest, macos-latest, etc.)
        #[arg(short = 'o', long, default_value = "ubuntu-latest")]
        os: String,

        /// Container architecture (linux/amd64, linux/arm64, etc.)
        #[arg(short = 'a', long, default_value = "linux/amd64")]
        arch: String,
    },
}
