use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Clone, PartialEq, Eq, Parser)]
pub(crate) struct Cli {
    /// Path to the configuration file
    /// Defaults to "./config.toml"
    #[clap(long, short, default_value = "./config.toml")]
    pub(crate) config: PathBuf,

    /// Run in headless mode without TUI
    #[clap(long)]
    pub(crate) headless: bool,
}
impl Cli {
    pub(crate) fn parse() -> Self {
        <Self as Parser>::parse()
    }
}
