use std::fs;
use std::io::Write;
use std::ops::Range;
use std::path::Path;
use std::collections::hash_map;
use std::collections::HashMap;
use anyhow::Context;
use symbolic_demangle::demangle;
use object::{
    Object, ObjectSection, ObjectSymbol,
    SectionIndex, SectionKind,
    SymbolKind, SymbolIndex, SymbolMap, SymbolMapName
};
use indexmap::{ IndexSet, IndexMap };
use owo_colors::OwoColorize;

use clap::Args;
use serde::{ Serialize, Deserialize };

use crate::explorer::Explorer;
use crate::util::{
    u64ptr, Stdio, YieldPoint,
    HexPrinter, AsciiPrinter, MaybePrinter, EitherPrinter,
    IfSupported, Hyperlink
};
use crate::disasm::{ self, Disassembler };


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

    /// show instr top usage by dwarf (bytes)
    #[arg(long)]
    pub dwarf_top: bool
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
    let symlist = explorer.cache.symlist(&explorer.obj).await;
    let map = explorer.cache.addr2sym(&explorer.obj).await;
    let map = map.symbols();

    let (idx, sym_idx) = match map.binary_search_by_key(&addr, |sym| sym.address()) {
        Ok(idx) => (idx, None),
        Err(idx) => {
            let idx = idx.saturating_sub(1);
            let sym = map.get(idx).context("no available symbols found")?;
            let symlist_idx = symlist.binary_search_by_key(
                &sym.address(),
                |&symidx| explorer.obj.symbol_by_index(symidx).unwrap().address()
            )
                .ok()
                .context("not found symbol")?;
            let sym_idx = symlist[symlist_idx];
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
        let symlist_idx = symlist.binary_search_by_key(
            &map[idx].address(),
            |&symidx| explorer.obj.symbol_by_index(symidx).unwrap().address()
        )
            .ok()
            .context("not found symbol")?;
        symlist[symlist_idx]
    };
    let sym = explorer.obj.symbol_by_index(sym_idx)?;
    let section_idx = sym.section_index().context("not found section index")?;
    let section = explorer.obj.section_by_index(section_idx)?;

    let data = explorer.cache.data(&explorer.obj, section_idx).await?;
    let offset = (sym.address() - section.address()) as usize;
    let size = explorer.symbol_size(symlist, sym_idx)?;
    let size = size as usize;

    let data = if !matches!(section.kind(), SectionKind::UninitializedData | SectionKind::UninitializedTls) {
        &data[offset..][..size]
    } else {
        &[]
    };

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
            cmd,
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
            cmd,
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
    cmd: &Command,
    explorer: &Explorer,
    section_idx: SectionIndex,
    symbol_idx: SymbolIndex,
    data: &[u8],
    stdio: &mut Stdio    
) -> anyhow::Result<()> {
    use std::fmt;

    struct RelaPrinter<'a> {
        demangle: bool,
        explorer: &'a Explorer,
        disasm: &'a Disassembler,
        addr2sym: &'a SymbolMap<SymbolMapName<'static>>,
        dyn_rela: &'a [(u64, object::read::Relocation)],
        inst: &'a disasm::Inst<'a>,
    }

    impl fmt::Display for RelaPrinter<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            if let Ok(Some(addr)) = self.disasm.operand2addr(self.inst)
                && let Some((name, addr)) = query_symbol_by_addr(
                    self.explorer,
                    self.addr2sym,
                    self.dyn_rela,
                    addr
            ) {
                write!(
                    f,
                    "\t# {} @ {:018p}",
                    name.if_supported(self.demangle, |name| demangle(name)),
                    addr as *const ()
                )?;
            }

            Ok(())            
        }
    }

    #[derive(Debug)]
    struct Line {
        range: Range<u64>,
        file: Option<usize>,
        line: Option<u32>,
        column: Option<u32>
    }

    let addr2line = if cmd.dwarf {
        let path = &explorer.path;
        let addr2line = explorer.cache.addr2line.get_or_try_init(|| async {
            if let Some(dwarf_path) = explorer.dwarf_path.as_ref() {
                addr2line::Loader::new_with_sup(path, Some(dwarf_path)).map(Into::into)
            } else {
                addr2line::Loader::new(path).map(Into::into)
            }
        })
            .await
            .map_err(|err| anyhow::format_err!("addr2line: {:?}", err))?;
        Some(addr2line)
    } else {
        None
    };
    
    let section = explorer.obj.section_by_index(section_idx)?;
    let symbol = explorer.obj.symbol_by_index(symbol_idx)?;
    let addr2sym = explorer.cache.addr2sym(&explorer.obj).await;
    let dyn_rela = explorer.cache.dyn_rela(&explorer.obj).await;

    if let Ok(name) = section.name() {
        writeln!(
            stdio.stdout,
            "{} {}",
            "section:".if_supported(stdio.colored, |a| a.cyan()),
            name
        )?;        
    }

    if let Ok(name) = symbol.name() {
        writeln!(
            stdio.stdout,
            "{} {}",
            "symbol:".if_supported(stdio.colored, |a| a.cyan()),
            name.if_supported(cmd.demangle, |name| demangle(name))
        )?;        
    }    

    let mut files = IndexSet::new();
    let mut texts = HashMap::new();
    let lines = if let Some(addr2line) = addr2line.as_ref() {
        let addr2line = addr2line.lock().await;

        let mut lines = addr2line.find_location_range(
            symbol.address(),
            symbol.address() + symbol.size()
        )
            .map_err(|err| anyhow::format_err!("addr2line: {:?}", err))?
            .map(|(offset, len, location)| Line {
                range: offset..offset + len,
                file: location.file.map(|file| {
                    files.insert_full(file.to_owned()).0
                }),
                line: location.line,
                column: location.column
            })
            .collect::<Vec<_>>();
        lines.sort_by_key(|line| line.range.start);
        lines
    } else {
        Vec::new()
    };
    let mut last_fileid = None;
    let mut cursor = 0;

    // print top
    if cmd.dwarf_top {
        use addr2line::fallible_iterator::FallibleIterator;

        let addr2line = addr2line.as_ref().context("need --dward")?;
        let addr2line = addr2line.lock().await;
        let mut map: IndexMap<_, u64> = IndexMap::new();

        for line in &lines {
            let len = line.range.end - line.range.start;

            let mut iter = addr2line.find_frames(line.range.start)
                .map_err(|err| anyhow::format_err!("addr2line: {:?}", err))?
                .filter_map(|frame| Ok(frame.function))
                .filter_map(|name| Ok(name.raw_name().ok().map(|name| name.into_owned())))
                .peekable();
            let mut last = None;
            while let Some(next) = iter.next()? {
                if iter.peek()?.is_some() || last.is_none() {
                    last = Some(next);
                }
            }

            if let Some(frame) = last {
                *map.entry(frame).or_default() += len;
            } else {
                *map.entry("<unknown>".into()).or_default() += len;
            }
        }

        let mut map: Vec<_> = map.into_iter().collect();
        map.sort_by_key(|(_, count)| *count);

        for (symbol, count) in map {
            writeln!(
                stdio.stdout,
                "{:10 }\t{}",
                count,
                symbol.if_supported(cmd.demangle, |s| demangle(s)),
            )?;
        }

        return Ok(());
    }    

    // print asm
    {
        let disasm = Disassembler::new(&explorer.obj)?;
        let disasm = &disasm;

        let insts = disasm.disasm_all(data, symbol.address())?;
        for inst in insts.iter()? {
            let inst = inst?;
            let inst = &inst;

            if let Some(line) = lines.get(cursor)
                && line.range.contains(&inst.address())
            {
                cursor += 1;

                if let Some(fileid) = line.file {
                    let path = files.get_index(fileid).unwrap();
                    let text = match texts.entry(fileid) {
                        hash_map::Entry::Occupied(e) => Some(e.into_mut()),
                        hash_map::Entry::Vacant(e) => {
                            fs::read_to_string(path)
                                .ok()
                                .map(|text| e.insert(text))
                        },
                    };

                    if last_fileid.replace(fileid) != Some(fileid) {
                        let path_ref = Path::new(path);
                    
                        writeln!(
                            stdio.stdout,
                            "{} {}{}",
                            "file:".if_supported(stdio.colored, |a| a.cyan()),
                            if stdio.hyperlink {
                                EitherPrinter::Left(Hyperlink::new(
                                    MaybePrinter(path_ref.file_name().map(|name| name.display()), None),
                                    path
                                ))
                            } else {
                                EitherPrinter::Right(path)
                            }.if_supported(stdio.colored, |a| a.dimmed()),
                            format_args!(
                                ":{},{}",
                                MaybePrinter(line.line, Some('?')),
                                MaybePrinter(line.column, Some('?')),
                            ).if_supported(stdio.colored, |a| a.dimmed())
                        )?;
                    }                

                    if let Some(text) = text.as_ref()
                        && let Some(n) = line.line
                        && let Some(text) = text.lines().nth(n.saturating_sub(1) as usize)
                    {
                        let mid = text.len().min(line.column.unwrap_or_default().saturating_sub(1) as usize);
                        let (text0, text1) = text.split_at(mid);

                        writeln!(
                            stdio.stdout,
                            "{}{}",
                            text0.if_supported(stdio.colored, |a| a.dimmed()),
                            text1
                        )?;
                    }
                }
            }
        
            let rela = RelaPrinter {
                demangle: cmd.demangle,
                explorer, disasm, addr2sym, dyn_rela, inst
            };
        
            writeln!(
                stdio.stdout,
                "{:018p}  {}  {}{}",
                (inst.address() as *const ()),
                HexPrinter(inst.bytes(), 8).if_supported(stdio.colored, |a| a.dimmed()),
                inst,
                rela.if_supported(stdio.colored, |a| a.dimmed())
            )?;
        }
    }
    
    Ok(())
}

async fn show_data(
    cmd: &Command,
    section_name: Option<&str>,
    symbol_name: Option<&str>,
    start: u64,
    data: &[u8],
    stdio: &mut Stdio    
) -> anyhow::Result<()> {
    if let Some(name) = section_name {
        writeln!(
            stdio.stdout,
            "{} {}",
            "section:".if_supported(stdio.colored, |a| a.cyan()),
            name
        )?;
    }

    if let Some(name) = symbol_name {
        writeln!(
            stdio.stdout,
            "{} {}",
            "symbol:".if_supported(stdio.colored, |a| a.cyan()),
            name.if_supported(cmd.demangle, |name| demangle(name))
        )?;
    }

    let addr = start;
    let width = 16;
    let mut point = YieldPoint::default();

    for (offset, chunk) in data.chunks(width).enumerate() {
        let addr = addr.wrapping_add((offset * width) as u64);
        point.yield_now().await;
        
        writeln!(
            stdio.stdout,
            "{:018p}  {} {}",
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

pub(crate) fn query_symbol_by_addr(
    explorer: &Explorer,
    addr2sym: &SymbolMap<SymbolMapName<'static>>,
    dyn_rela: &[(u64, object::read::Relocation)],
    addr: u64,
) -> Option<(&'static str, u64)> {
    use object::read::RelocationTarget;

    let addr2sym = addr2sym.symbols();

    if let Ok(idx) = addr2sym.binary_search_by_key(&addr, |sym| sym.address()) {
        let sym = &addr2sym[idx];
        Some((sym.name(), sym.address()))
    } else {
        // section check
        {
            let got = match explorer.obj.format() {
                object::BinaryFormat::Elf => ".got",
                object::BinaryFormat::MachO => "__got",
                _ => return None,
            };
            let section = explorer.obj.section_by_name(got)?;

            let start = section.address();
            let end = start + section.size();

            if !(start..end).contains(&addr) {
                return None;
            }
        }

        let idx = match dyn_rela.binary_search_by_key(&addr, |(addr, _)| *addr) {
            Ok(idx) => idx,
            Err(idx) if dyn_rela.len() > idx => idx,
            Err(_) => return None
        };
        let (rela_addr, rela) = &dyn_rela[idx];

        if !(addr..addr.saturating_add(8)).contains(rela_addr) {
            return None;
        }

        match rela.target() {
            RelocationTarget::Symbol(symidx) => {
                let sym = explorer.obj.symbol_by_index(symidx).ok()?;
                let name = sym.name().ok()?;
                Some((name, sym.address()))
            },
            RelocationTarget::Absolute => {
                let addr = rela.addend().try_into().ok()?;
                let idx = addr2sym.binary_search_by_key(&addr, |sym| sym.address()).ok()?;
                let sym = &addr2sym[idx];
                Some((sym.name(), sym.address()))
            },
            _ => None
        }
    }
}
