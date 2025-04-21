use clap::Args;
use serde::{ Serialize, Deserialize };
use std::path::PathBuf;

/// open file and listen ipc
#[derive(Serialize, Deserialize)]
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
#[command(flatten_help = true)]
pub struct Command {
    pub path: PathBuf
}
