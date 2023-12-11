use std::io::Write;
use clap::Args;
use serde::{ Serialize, Deserialize };
use tokio::io::{ AsyncReadExt, AsyncWriteExt };
use tokio::net::UnixStream;
use aho_corasick::AhoCorasick;
use bstr::ByteSlice;
use object::{ Object, ObjectSymbol };
use symbolic_demangle::demangle;
use crate::explorer::Explorer;
use crate::util::Stdio;


/// search symbol name and data
#[derive(Serialize, Deserialize)]
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
#[command(flatten_help = true)]
pub struct Command {
    /// search keywords
    keywords: Vec<String>,

    /// demangle symbol name
    #[arg(short, long, default_value_t = false)]
    demangle: bool,

    /// search by data instead of symbol name
    #[arg(long, default_value_t = false)]
    data: bool
}

impl Command {
    pub async fn exec(self, explorer: &Explorer, mut stdio: Stdio) -> anyhow::Result<()> {
        let ac = AhoCorasick::new(&self.keywords)?;

        match (explorer.obj.has_debug_symbols(), self.data) {
            (true, false) => by_symbol(&self, &ac, explorer, &mut stdio).await,
            (false, false) => anyhow::bail!("no debug symbols"),
            (_, true) => by_data(&self, &ac, explorer, &mut stdio).await
        }
    }
}

async fn by_symbol(
    cmd: &Command,
    ac: &AhoCorasick,
    explorer: &Explorer,
    stdio: &mut Stdio
)
    -> anyhow::Result<()>
{
    let mut output = Vec::new();

    for (mangled_name, &idx) in explorer.cache.sym2idx(&explorer.obj) {
        let name = demangle(mangled_name);

        if ac.is_match(name.as_bytes())
            || cmd.keywords.iter().any(|w| mangled_name.ends_with(w))
        {
            let sym = explorer.obj.symbol_by_index(idx)?;
            let kind = explorer.symbol_kind(idx);

            let name = if !cmd.demangle {
                mangled_name
            } else {
                name.as_ref()
            };

            output.clear();
            writeln!(
                output,
                "{:016x} {} {}",
                sym.address(),
                kind,
                name,
            )?;
            stdio.stdout.write_all(&output)?;
        }
    }

    Ok(())
}

async fn by_data(
    cmd: &Command,
    ac: &AhoCorasick,
    explorer: &Explorer,
    stdio: &mut Stdio
)
    -> anyhow::Result<()>
{
    todo!()
}
