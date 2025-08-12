#![allow(clippy::uninlined_format_args)]

mod listen;
mod call;
mod explorer;
mod search;
mod show;
mod complete;
mod disasm;
mod util;

use anyhow::Context;
use clap::Parser;
use directories::ProjectDirs;

use clap::Subcommand;
use serde::{ Serialize, Deserialize };

use explorer::Explorer;
use crate::util::Stdio;


/// Fi - binary analysis tools
#[derive(Serialize, Deserialize)]
#[derive(Debug, Parser)]
#[command(name = "fi")]
pub struct Options {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Serialize, Deserialize)]
#[derive(Debug, Subcommand)]
pub enum Commands {
    Complete(complete::Command),
    Listen(listen::Command),
    Search(search::Command),
    Show(show::Command),
}


fn main() -> anyhow::Result<()> {
    let options = Options::parse();
    let dir = ProjectDirs::from("", "", env!("CARGO_PKG_NAME"))
        .context("not found project dirs")?;

    match options.command {
        Commands::Complete(cmd) => cmd.exec(),
        Commands::Listen(cmd) => cmd.exec(&dir),
        _ => call::call(&dir, Box::new(options))
    }
}

impl Commands {
    async fn exec(self, explorer: &Explorer, stdio: &mut Stdio)
        -> anyhow::Result<()>
    {
        match self {
            Commands::Complete(_) | Commands::Listen(_) => Ok(()),
            Commands::Search(cmd) => cmd.exec(explorer, stdio).await,
            Commands::Show(cmd) => cmd.exec(explorer, stdio).await,
        }
    }
}
