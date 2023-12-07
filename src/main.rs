mod listen;
mod util;

use anyhow::Context;
use clap::{ Parser, Subcommand };
use directories::ProjectDirs;


/// Fi - binary analysis tools
#[derive(Debug, Parser)] // requires `derive` feature
#[command(name = "fi")]
struct Options {
    #[command(subcommand)]
    command: Commands,
}


#[derive(Debug, Subcommand)]
enum Commands {
    Listen(listen::Command)
}

fn main() -> anyhow::Result<()> {
    let options = Options::parse();
    let dir = ProjectDirs::from("", "", env!("CARGO_PKG_NAME"))
        .context("not found project dirs")?;

    match options.command {
        Commands::Listen(cmd) => cmd.exec(dir)
    }
}
