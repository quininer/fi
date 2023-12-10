mod listen;
mod call;
mod explorer;
mod search;
mod util;

use anyhow::Context;
use clap::{ Parser, Subcommand };
use serde::{ Serialize, Deserialize };
use directories::ProjectDirs;
use tokio::net::UnixStream;
use explorer::Explorer;


/// Fi - binary analysis tools
#[derive(Serialize, Deserialize)]
#[derive(Debug, Parser)] // requires `derive` feature
#[command(name = "fi")]
struct Options {
    #[command(subcommand)]
    command: Commands,
}


#[derive(Serialize, Deserialize)]
#[derive(Debug, Subcommand)]
enum Commands {
    Listen(listen::Command),
    Search(search::Command)
}

fn main() -> anyhow::Result<()> {
    let options = Options::parse();
    let dir = ProjectDirs::from("", "", env!("CARGO_PKG_NAME"))
        .context("not found project dirs")?;

    match options.command {
        Commands::Listen(cmd) => cmd.exec(dir),
        _ => call::call(dir, &options)
    }
}

impl Commands {
    async fn exec(self, explorer: &Explorer, stream: UnixStream)
        -> anyhow::Result<()>
    {
        match self {
            Commands::Listen(_) => Ok(()),
            Commands::Search(cmd) => cmd.exec(explorer, stream).await
        }
    }
}
