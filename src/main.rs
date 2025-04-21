mod options;
mod listen;
mod call;
mod explorer;
mod search;
mod show;
mod util;

use anyhow::Context;
use clap::Parser;
use directories::ProjectDirs;
use explorer::Explorer;
use crate::util::Stdio;
use crate::options::{ Options, Commands };


fn main() -> anyhow::Result<()> {
    let options = Options::parse();
    let dir = ProjectDirs::from("", "", env!("CARGO_PKG_NAME"))
        .context("not found project dirs")?;

    match options.command {
        Commands::Listen(cmd) => cmd.exec(&dir),
        _ => call::call(&dir, Box::new(options))
    }
}

impl Commands {
    async fn exec(self, explorer: &Explorer, stdio: &mut Stdio)
        -> anyhow::Result<()>
    {
        match self {
            Commands::Listen(_) => Ok(()),
            Commands::Search(cmd) => cmd.exec(explorer, stdio).await,
            Commands::Show(cmd) => cmd.exec(explorer, stdio).await,
        }
    }
}
