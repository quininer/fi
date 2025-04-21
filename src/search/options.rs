use clap::Args;
use serde::{ Serialize, Deserialize };

/// search symbol name and data
#[derive(Serialize, Deserialize)]
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
#[command(flatten_help = true)]
pub struct Command {
    /// search keywords
    pub keywords: Vec<String>,

    /// demangle symbol name
    #[arg(short, long, default_value_t = false)]
    pub demangle: bool,

    /// search by data instead of symbol name
    #[arg(long, default_value_t = false)]
    pub data: bool,

    /// filter section by regex
    #[arg(short, long)]
    pub filter_section: Option<String>,
}

