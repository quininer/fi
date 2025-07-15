use std::path::PathBuf;
use clap::Args;
use serde::{ Serialize, Deserialize };

/// show text or data
#[derive(Serialize, Deserialize)]
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
#[command(flatten_help = true)]
pub struct Command {
    /// show address
    pub address: String,

    /// show length
    #[arg(short, long)]
    pub length: Option<u64>,

    /// no search symbol
    #[arg(long, default_value_t = false)]
    pub no_symbol: bool,

    /// dump raw data
    #[arg(long, default_value_t = false)]
    pub dump: bool,

    /// demangle symbol
    #[arg(short, long)]
    pub demangle: bool,

    /// address align
    #[arg(long)]
    pub align: Option<u64>,

    /// show source code by dwarf
    #[arg(long)]
    pub dwarf: bool,

    /// set dwarf path
    #[arg(long)]
    pub dwarf_path: Option<PathBuf>,

    /// show instr top usage by dwarf (bytes)
    #[arg(long)]
    pub dwarf_top: bool
}
