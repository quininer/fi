use clap::Subcommand;
use serde::{ Serialize, Deserialize };
use super::*;

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
    Listen(listen::Command),
    Search(search::Command),
    Show(show::Command),
}
