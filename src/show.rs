mod options;

use std::fs;
use std::io::Write;
use std::ops::Range;
use std::path::Path;
use std::collections::hash_map;
use std::collections::HashMap;
use anyhow::Context;
use symbolic_demangle::demangle;
use capstone::arch::{ BuildsCapstone, DetailsArchInsn };
use object::{ Object, ObjectSection, ObjectSymbol, SymbolKind, SymbolIndex, SectionIndex, SymbolMap, SymbolMapName };
use indexmap::IndexSet;
use owo_colors::OwoColorize;
use crate::explorer::Explorer;
use crate::util::{ u64ptr, Stdio, HexPrinter, AsciiPrinter, MaybePrinter, YieldPoint, IfSupported, Hyperlink, EitherPrinter };
pub use options::Command;

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
    let size = explorer.symbol_size(sym_idx).await?;
    let size = size as usize;

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
    use capstone::Capstone;

    struct InstPrinter<'a>(&'a capstone::Insn<'a>);

    impl fmt::Display for InstPrinter<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0.mnemonic().unwrap_or("???"))?;

            if let Some(op_str) = self.0.op_str() {
                write!(f, " {}", op_str)?;
            }

            Ok(())
        }
    }

    struct RelaPrinter<'a> {
        demangle: bool,
        explorer: &'a Explorer,
        disasm: &'a Capstone,
        addr2sym: &'a SymbolMap<SymbolMapName<'static>>,
        dyn_rela: &'a [(u64, object::read::Relocation)],
        inst: &'a capstone::Insn<'a>,
    }

    impl fmt::Display for RelaPrinter<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            if let Some(addr) = operand2addr(self.disasm, self.addr2sym, self.inst) {
                if let Ok(Some(name)) = query_symbol_by_addr(
                    self.explorer,
                    self.addr2sym,
                    self.dyn_rela,
                    addr
                ) {
                    write!(
                        f,
                        "\t# {}",
                        name.if_supported(self.demangle, |name| demangle(name))
                    )?;
                }
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
        let path = cmd.dwarf_path.as_deref().unwrap_or(&explorer.path);
        let addr2line = explorer.cache.addr2line.get_or_try_init(|| async {
            addr2line::Loader::new(path).map(Into::into)
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

    let disasm = match explorer.obj.architecture() {
        object::Architecture::X86_64 => Capstone::new()
            .x86()
            .mode(capstone::arch::x86::ArchMode::Mode64)
            .detail(true)
            .build()?,
        object::Architecture::Aarch64 => Capstone::new()
            .arm64()
            .mode(capstone::arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()?,
        object::Architecture::Riscv64 => Capstone::new()
            .riscv()
            .mode(capstone::arch::riscv::ArchMode::RiscV64)
            .detail(true)
            .build()?,
        arch => anyhow::bail!("unsupported arch: {:?}", arch)
    };
    let disasm = &disasm;

    let insts = disasm.disasm_all(data, symbol.address())?;
    for inst in insts.as_ref() {
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
            InstPrinter(inst),
            rela.if_supported(stdio.colored, |a| a.dimmed())
        )?;
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

fn operand2addr(
    disasm: &capstone::Capstone,
    addr2sym: &SymbolMap<SymbolMapName<'_>>,
    inst: &capstone::Insn<'_>,
)
    -> Option<u64>
{
    use capstone::arch::ArchDetail;
    use capstone::arch::x86::X86OperandType;
    use capstone::arch::x86::X86Reg::{ Type as X86RegType, X86_REG_RIP };
    use capstone::InsnGroupType::{ Type as InsnGroupType, CS_GRP_CALL, CS_GRP_JUMP };

    let detail = disasm.insn_detail(inst).ok()?;
    let _group_id = detail.groups()
        .iter()
        .map(|id| InsnGroupType::from(id.0))
        .find(|&id| matches!(id, CS_GRP_CALL | CS_GRP_JUMP))?;

    match detail.arch_detail() {
        ArchDetail::X86Detail(inst_detail) => {
            let operand = inst_detail.operands().next()?;

            match operand.op_type {
                X86OperandType::Imm(imm) => {
                    let addr = imm.try_into().ok()?;
                    addr2sym.get(addr).map(|_| addr)
                },
                X86OperandType::Mem(mem) if X86RegType::from(mem.base().0) == X86_REG_RIP => {
                    let disp: u64 = mem.disp().try_into().ok()?;
                    Some(inst.address() + disp)
                },
                _ => None
            }
        },
        _ => None
    }
}

fn query_symbol_by_addr(
    explorer: &Explorer,
    addr2sym: &SymbolMap<SymbolMapName<'static>>,
    dyn_rela: &[(u64, object::read::Relocation)],
    addr: u64,
) -> anyhow::Result<Option<&'static str>> {
    use object::read::RelocationTarget;

    let addr2sym = addr2sym.symbols();

    if let Ok(idx) = addr2sym.binary_search_by_key(&addr, |sym| sym.address()) {
        Ok(Some(addr2sym[idx].name()))
    } else {
        // section check
        {
            let Some(section) = explorer.obj.section_by_name(".got")
                else { return Ok(None) };            

            let start = section.address();
            let end = start + section.size();

            if !(start..end).contains(&addr) {
                return Ok(None);
            }
        }

        let idx = match dyn_rela.binary_search_by_key(&addr, |(addr, _)| *addr) {
            Ok(idx) => idx,
            Err(idx) if dyn_rela.len() > idx => idx,
            Err(_) => return Ok(None)
        };
        let (rela_addr, rela) = &dyn_rela[idx];

        if !(addr..addr.saturating_add(8)).contains(rela_addr) {
            return Ok(None);
        }

        let name = match rela.target() {
            RelocationTarget::Symbol(symidx) => explorer.obj.symbol_by_index(symidx)
                .ok()
                .and_then(|sym| sym.name().ok()),
            RelocationTarget::Absolute => {
                let addr = rela.addend().try_into()?;
                addr2sym.binary_search_by_key(&addr, |sym| sym.address())
                    .ok()
                    .map(|idx| addr2sym[idx].name())
            },
            _ => None
        };        

        Ok(name)
    }
}
