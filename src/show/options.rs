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

    /// address align
    #[arg(long)]
    pub align: Option<u64>,
}

