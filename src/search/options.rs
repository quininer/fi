use clap::Args;
use serde::{ Serialize, Deserialize };

/// search symbol name and data
#[derive(Serialize, Deserialize)]
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
#[command(flatten_help = true)]
pub struct Command {
    /// search keyword (regex, symbol address)
    pub keyword: String,

    /// demangle symbol name
    #[arg(short, long, default_value_t = false)]
    pub demangle: bool,

    /// search by data instead of symbol name
    #[arg(long)]
    pub data: bool,

    /// search for direct calls by symbol address
    #[arg(long)]
    pub callsite: bool,

    /// filter section by regex
    #[arg(short, long)]
    pub filter_section: Option<String>,

    /// print size (symbol)
    #[arg(short, long)]
    pub size: bool,

    /// sort by size (symbol)
    #[arg(long)]
    pub sort_size: bool,
    
    /// sort by name (symbol)
    #[arg(long)]
    pub sort_name: bool,

    /// only print duplicate (symbol)
    #[arg(long)]
    pub only_duplicate: bool,
}
