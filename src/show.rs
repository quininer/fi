use anyhow::Context;
use clap::Args;
use object::{ Object, ObjectSection, ObjectSymbol, SymbolKind };
use serde::{ Serialize, Deserialize };
use crate::explorer::Explorer;
use crate::util::{ u64ptr, Stdio };

/// search symbol name and data
#[derive(Serialize, Deserialize)]
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
#[command(flatten_help = true)]
pub struct Command {
    /// show address
    address: String,

    /// show length
    #[arg(long)]
    length: Option<u64>,

    /// no search symbol
    #[arg(short, long, default_value_t = false)]
    no_symbol: bool,

    /// address align
    #[arg(long)]
    align: Option<u64>,
}

impl Command {
    pub async fn exec(self, explorer: &Explorer, stdio: &mut Stdio) -> anyhow::Result<()> {
        let addr = u64ptr(&self.address)?;

        if !self.no_symbol && explorer.obj.has_debug_symbols() {
            by_symbol(&self, explorer, addr, stdio).await
        } else {
            by_section(&self, explorer, addr, stdio).await
        }
    }
}

async fn by_symbol(
    cmd: &Command,
    explorer: &Explorer,
    addr: u64,
    stdio: &mut Stdio    
)
    -> anyhow::Result<()>
{
    let map = explorer.cache.addr2sym(&explorer.obj).await;
    let map = map.symbols();
    let (idx, sym_idx)= match map.binary_search_by_key(&addr, |sym| sym.address()) {
        Ok(idx) => (idx, None),
        Err(idx) => {
            let sym = map.get(idx).context("no available symbols found")?;
            let &sym_idx = explorer.cache.sym2idx(&explorer.obj).await
                .get(sym.name())
                .context("not found symbol")?;
            let sym = explorer.obj.symbol_by_index(sym_idx)?;
            let start = sym.address();
            let end = start + sym.size();

            if (start..end).contains(&addr) {
                (idx, Some(sym_idx))
            } else {
                anyhow::bail!("not found symbol by address")
            }
        },
    };

    let sym_idx = if let Some(sym_idx) = sym_idx {
        sym_idx
    } else {
        explorer.cache.sym2idx(&explorer.obj).await
            .get(map[idx].name())
            .copied()
            .context("not found symbol")?
    };
    let sym = explorer.obj.symbol_by_index(sym_idx)?;
    let section_idx = sym.section_index().context("not found section index")?;
    let section = explorer.obj.section_by_index(section_idx)?;

    let data = section.uncompressed_data()?;
    let offset = (sym.address() - section.address()) as usize;
    let size = sym.size() as usize;

    let data = &data[offset..][..size];

    if matches!(sym.kind(), SymbolKind::Text) {
        show_text(
            cmd,
            explorer,
            section.name().ok(),
            map[idx].name(),
            sym.address(),
            data,
            stdio
        );
    } else {
        show_data(
            cmd,
            explorer,
            section.name().ok(),
            Some(map[idx].name()),
            sym.address(),
            data,
            stdio
        );        
    }
    
    Ok(())
}

async fn by_section(
    cmd: &Command,
    explorer: &Explorer,
    addr: u64,
    stdio: &mut Stdio    
)
    -> anyhow::Result<()>
{
    let section = explorer.obj.sections()
        .find(|section| {
            let start = section.address();
            let end = start + section.size();
            (start..end).contains(&addr)
        })
        .context("not found section")?;

    let align = cmd.align.unwrap_or_else(|| section.align());
    let data = section.uncompressed_data()?;

    // TODO addr align

    let offset = (section.address() - addr) as usize;
    let len = cmd.length.unwrap_or(256) as usize;
    let len = std::cmp::min(len, data.len() - offset);
    let data = &data[offset..][..len];

    show_data(
        cmd,
        explorer,
        section.name().ok(),
        None,
        0, // align
        data,
        stdio
    );
             
    Ok(())
}

fn show_text(
    cmd: &Command,
    explorer: &Explorer,
    section_name: Option<&str>,
    symbol_name: &str,
    start: u64,
    data: &[u8],
    stdio: &mut Stdio    
) {
    //
}

fn show_data(
    cmd: &Command,
    explorer: &Explorer,
    section_name: Option<&str>,
    symbol_name: Option<&str>,
    start: u64,
    data: &[u8],
    stdio: &mut Stdio    
) {
    //
}
