use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Clone, PartialEq, Eq, Parser)]
pub(crate) struct Cli {
    #[clap(long, short, default_value = "./config.toml")]
    pub(crate) config: PathBuf,
}
impl Cli {
    pub(crate) fn parse() -> Self {
        <Self as Parser>::parse()
    }
}
