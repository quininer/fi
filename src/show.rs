use std::io::Write;
use anyhow::Context;
use capstone::arch::BuildsCapstone;
use clap::Args;
use object::{ Object, ObjectSection, ObjectSymbol, SymbolKind, SymbolIndex, SectionIndex };
use serde::{ Serialize, Deserialize };
use crate::explorer::Explorer;
use crate::util::{ u64ptr, Stdio, HexPrinter, AsciiPrinter, YieldPoint };

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
    #[arg(long, default_value_t = false)]
    no_symbol: bool,

    /// dump raw data
    #[arg(long, default_value_t = false)]
    dump: bool,

    /// address align
    #[arg(long)]
    align: Option<u64>,
}

impl Command {
    pub async fn exec(self, explorer: &Explorer, stdio: &mut Stdio) -> anyhow::Result<()> {
        let addr = u64ptr(&self.address)?;

        if !self.no_symbol {
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
            let idx = idx.saturating_sub(1);
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

    let data = explorer.cache.data(&explorer.obj, section_idx).await?;
    let offset = (sym.address() - section.address()) as usize;
    let size = sym.size() as usize;

    let data = &data[offset..][..size];

    if cmd.dump {
        dump_data(data, stdio).await?;
    } else if matches!(sym.kind(), SymbolKind::Text) {
        show_text(
            cmd,
            explorer,
            section_idx,
            sym.index(),
            data,
            stdio
        ).await?;
    } else {
        show_data(
            section.name().ok(),
            Some(map[idx].name()),
            sym.address(),
            data,
            stdio
        ).await?;        
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
    let data = explorer.cache.data(&explorer.obj, section.index()).await?;

    let new_addr = (addr as *const u8).align_offset(align.try_into()?) as u64;
    let addr = if addr == new_addr || new_addr < align {
        addr
    } else {
        new_addr - align
    };

    let offset = (addr - section.address()) as usize;
    let len = cmd.length.unwrap_or(256) as usize;
    let len = std::cmp::min(len, data.len() - offset);
    let data = &data[offset..][..len];

    if cmd.dump {
        dump_data(data, stdio).await?;
    } else {
        show_data(
            section.name().ok(),
            None,
            addr,
            data,
            stdio
        ).await?;
    }
             
    Ok(())
}

async fn show_text(
    _cmd: &Command,
    explorer: &Explorer,
    section_idx: SectionIndex,
    symbol_idx: SymbolIndex,
    data: &[u8],
    stdio: &mut Stdio    
) -> anyhow::Result<()> {
    use std::fmt;
    use capstone::Capstone;

    struct InstPrinter<'a>(&'a capstone::Insn<'a>);

    impl fmt::Display for InstPrinter<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            if let Some(mnemonic) = self.0.mnemonic() {
                write!(f, "{} ", mnemonic)?;
                if let Some(op_str) = self.0.op_str() {
                    write!(f, "{}", op_str)?;
                }
            }

            Ok(())
        }
    }
    
    let section = explorer.obj.section_by_index(section_idx)?;
    let symbol = explorer.obj.symbol_by_index(symbol_idx)?;

    let disasm = match explorer.obj.architecture() {
        object::Architecture::X86_64 => Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .build()?,
        object::Architecture::Aarch64 => Capstone::new()
            .arm64()
            .build()?,
        object::Architecture::Riscv64 => Capstone::new()
            .riscv()
            .mode(capstone::arch::riscv::ArchMode::RiscV64)
            .build()?,
        arch => anyhow::bail!("unsupported arch: {:?}", arch)
    };

    if let Ok(name) = section.name() {
        writeln!(stdio.stdout, "section: {}", name)?;
    }

    if let Ok(name) = symbol.name() {
        writeln!(stdio.stdout, "symbol: {}", name)?;
    }

    let insts = disasm.disasm_all(data, symbol.address())?;

    for inst in insts.as_ref() {
        writeln!(
            stdio.stdout,
            "0x{:016p}  {}  {}",
            inst.address() as *const (),
            HexPrinter(inst.bytes(), 8),
            InstPrinter(&inst)
        )?;
    }

    // TODO
    
    Ok(())
}

async fn show_data(
    section_name: Option<&str>,
    symbol_name: Option<&str>,
    start: u64,
    data: &[u8],
    stdio: &mut Stdio    
) -> anyhow::Result<()> {
    if let Some(name) = section_name {
        writeln!(stdio.stdout, "section: {}", name)?;
    }

    if let Some(name) = symbol_name {
        writeln!(stdio.stdout, "symbol: {}", name)?;
    }

    let addr = start;
    let width = 16;
    let mut point = YieldPoint::default();

    for (offset, chunk) in data.chunks(width).enumerate() {
        let addr = addr.wrapping_add((offset * width) as u64);
        point.yield_now().await;
        
        writeln!(
            stdio.stdout,
            "0x{:016p}  {} {}",
            addr as *const u8,
            HexPrinter(chunk, width),
            AsciiPrinter(chunk)
        )?;
    }
    
    Ok(())
}

async fn dump_data(data: &[u8], stdio: &mut Stdio) -> anyhow::Result<()> {
    let mut point = YieldPoint::default();
    
    for chunk in data.chunks(4 * 1024) {
        stdio.stdout.write_all(chunk)?;
        point.yield_now().await;
    }

    Ok(())
}
