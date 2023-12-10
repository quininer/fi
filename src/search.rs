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


/// search symbol name and data
#[derive(Serialize, Deserialize)]
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
#[command(flatten_help = true)]
pub struct Command {
    keywords: Vec<String>,
}

impl Command {
    pub async fn exec(self, explorer: &Explorer, mut stream: UnixStream) -> anyhow::Result<()> {
        if let Err(err) = exec(self, explorer, &mut stream).await {
            let err = format!("search failed: {:?}", err);
            stream.write_all(err.as_bytes()).await?;
            stream.flush().await?;
        }

        Ok(())
    }
}

async fn exec(cmd: Command, explorer: &Explorer, stream: &mut UnixStream)
    -> anyhow::Result<()>
{
    let ac = AhoCorasick::new(&cmd.keywords)?;
    let mut output = Vec::new();

    for (mangled_name, &idx) in explorer.cache.sym2idx(&explorer.obj) {
        let name = demangle(mangled_name);

        if ac.is_match(name.as_bytes())
            || cmd.keywords.iter().any(|w| mangled_name.ends_with(w))
        {
            let sym = explorer.obj.symbol_by_index(idx)?;
            let kind = explorer.symbol_kind(idx);

            output.clear();
            writeln!(
                output,
                "{:016x} {} {}",
                sym.address(),
                kind,
                mangled_name,
            )?;
            stream.write_all(&output).await?;
        }
    }

    Ok(())
}
