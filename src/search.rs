use std::{ fs, cmp };
use std::collections::HashSet;
use std::io::Write;
use anyhow::Context;
use bstr::ByteSlice;
use object::{ Object, ObjectSection, ObjectSymbol };
use symbolic_demangle::demangle;

use clap::Args;
use serde::{ Serialize, Deserialize };

use crate::explorer::Explorer;
use crate::util::{ Stdio, YieldPoint, MaybePrinter, is_data_section, u64ptr };
use crate::disasm::Disassembler;


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

impl Command {
    pub async fn exec(self, explorer: &Explorer, stdio: &mut Stdio) -> anyhow::Result<()> {
        match (self.callsite, self.data) {
            (false, false) => by_symbol(&self, explorer, stdio).await,
            (true, false) => by_call(&self, explorer, stdio).await,
            (false, true) => by_data(&self, explorer, stdio).await,
            (true, true) => anyhow::bail!("cannot use `--callsite` and `--data` at the same time")
        }
    }
}

async fn by_symbol(cmd: &Command, explorer: &Explorer, stdio: &mut Stdio)
    -> anyhow::Result<()>
{
    let re = regex::Regex::new(&cmd.keyword)?;
    let filter = cmd.filter_section
        .as_ref()
        .map(|rule| regex::Regex::new(rule))
        .transpose()?;
    let symlist = explorer.cache.symlist(&explorer.obj).await;
    
    let mut outbuf = Vec::new();
    let mut point = YieldPoint::default();
    let mut output = Vec::new();
    let mut sum = 0;

    for &idx in symlist {
        point.yield_now().await;

        let sym = explorer.obj.symbol_by_index(idx).unwrap();
        let mangled_name = match sym.name() {
            Ok(name) => name,
            Err(err) => {
                eprintln!("bad symbol name: {:?}", err);
                continue
            }
        };
        
        // filter section by regex
        if let Some(rule) = filter.as_ref() {
            let sym = explorer.obj.symbol_by_index(idx)?;
            let Some(section_idx) = sym.section_index()
                else { continue };
            let section = explorer.obj.section_by_index(section_idx)?;

            if let Ok(section_name) = section.name()
                && !rule.is_match(section_name)
            {
                continue
            }
        }
        
        let name = if cmd.demangle {
            demangle(mangled_name)
        } else {
            (*mangled_name).into()
        };

        if re.is_match(&name) {
            let mut sym_size = 0;

            if cmd.size || cmd.sort_size {
                sym_size = explorer.symbol_size(symlist, idx)?;
            }

            if !cmd.sort_size && !cmd.sort_name && !cmd.only_duplicate {
                sum += sym_size;
                print_symbol(
                    explorer,
                    idx, &name, sym_size,
                    cmd.size,
                    &mut outbuf,
                    &mut stdio.stdout
                )?;
            } else {
                output.push((idx, name, sym_size));
            }
        }
    }

    output.sort_unstable_by(|(_, name0, size0), (_, name1, size1)| match (cmd.sort_size, cmd.sort_name) {
        (false, false) => cmp::Ordering::Equal,
        (true, false) => size0.cmp(size1),
        (false, true) => name0.cmp(name1),
        (true, true) => (name0, size0).cmp(&(name1, size1))
    });

    let mut dup = HashSet::new();

    for (idx, name, size) in &output {
        if cmd.only_duplicate {
            let dupname = name.split('.').next().unwrap_or(name);
            if dup.insert(dupname) {
                continue;
            }
        }

        sum += size;
        print_symbol(
            explorer,
            *idx, name, *size,
            cmd.size,
            &mut outbuf,
            &mut stdio.stdout
        )?;
    }

    if cmd.size {
        writeln!(stdio.stdout, "sum: {}", sum)?;
    }

    Ok(())
}

async fn by_data(cmd: &Command, explorer: &Explorer, stdio: &mut Stdio)
    -> anyhow::Result<()>
{
    let re = regex::bytes::Regex::new(&cmd.keyword)?;
    let filter = cmd.filter_section
        .as_ref()
        .map(|rule| regex::Regex::new(rule))
        .transpose()?;
    let mut point = YieldPoint::default();
    
    for section in explorer.obj.sections()
        .filter(|section| is_data_section(section.kind()))
    {
        // filter section by regex
        if let Some(rule) = filter.as_ref()
            && let Ok(section_name) = section.name()
            && !rule.is_match(section_name)
        {
            continue
        }

        if let Ok(data) = explorer.cache.data(&explorer.obj, section.index()).await {
            let base = section.address();
            
            for mat in re.find_iter(&data) {
                let addr = base + mat.start() as u64;
                point.yield_now().await;

                writeln!(
                    &mut stdio.stdout,
                    "{:018p}\t{:?}\t{}",
                    addr as *const (),
                    section.name(),
                    data[mat.range()].as_bstr()
                )?;
            }
        }
    }

    Ok(())    
}

async fn by_call(cmd: &Command, explorer: &Explorer, stdio: &mut Stdio)
    -> anyhow::Result<()>
{
    use std::rc::Rc;
    use std::cell::RefCell;
    use rayon::prelude::*;
    use super::show;

    thread_local! {
        static DISASM_CACHE: RefCell<Option<Rc<Disassembler>>> =
            const { RefCell::new(None) };
    }
    
    let address = u64ptr(&cmd.keyword)?;
    let symlist = explorer.cache.symlist(&explorer.obj).await;
    let addr2sym = explorer.cache.addr2sym(&explorer.obj).await;
    let dyn_rela = explorer.cache.dyn_rela(&explorer.obj).await;

    let symidx = symlist
        .binary_search_by_key(&address, |&idx| explorer.obj.symbol_by_index(idx).unwrap().address())
        .ok()
        .context("not found symbol by address")?;
    let symidx = symlist[symidx];
    let sym = explorer.obj.symbol_by_index(symidx).unwrap();

    if !matches!(sym.kind(), object::SymbolKind::Text) {
        anyhow::bail!("symbol kind is not text");
    }

    let section_idx = sym.section_index().unwrap();
    let section = explorer.obj.section_by_index(section_idx)?;
    let section_data = explorer.cache.data(&explorer.obj, section_idx).await?;

    let mut output = symlist
        .par_iter()
        .filter_map(|&symidx| {
            let sym = explorer.obj.symbol_by_index(symidx).unwrap();

            if sym.section_index() != Some(section_idx) {
                return None;
            }

            let mangled_name = sym.name().unwrap();
            let name = if cmd.demangle {
                demangle(mangled_name)
            } else {
                (*mangled_name).into()
            };

            let offset = (sym.address() - section.address()) as usize;
            let size = match explorer.symbol_size(symlist, symidx) {
                Ok(size) => size,
                Err(err) => return Some(Err(err))
            };
            let data = &section_data[offset..][..size as usize];

            let disasm = DISASM_CACHE.with_borrow_mut(|disasm| {
                if let Some(disasm) = disasm.as_ref() {
                    Ok(disasm.clone())
                } else {
                    let disasm2 = Disassembler::new(&explorer.obj)?;
                    Ok(disasm.insert(Rc::new(disasm2)).clone())
                }
            });
            let disasm = match disasm {
                Ok(disasm) => disasm,
                Err(err) => return Some(Err(err))
            };
            let disasm = &*disasm;

            let insts = match disasm.disasm_all(data, sym.address()) {
                Ok(insts) => insts,
                Err(err) => return Some(Err(err))
            };
            for inst in insts.iter()
                .ok()?
                .filter_map(|inst| inst.ok())
            {
                let addr = match disasm.operand2addr(&inst) {
                    Ok(Some(addr)) => addr,
                    Ok(None) => return None,
                    Err(err) => return Some(Err(err))
                };
                
                if let Some((_name, addr)) = show::query_symbol_by_addr(explorer, addr2sym, dyn_rela, addr)
                    && addr == address
                {
                    return Some(Ok((symidx, name, size)));
                }
            }

            None
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    output.sort_unstable_by(|(idx0, name0, size0), (idx1, name1, size1)| match (cmd.sort_size, cmd.sort_name) {
        (false, false) => idx0.0.cmp(&idx1.0),
        (true, false) => size0.cmp(size1),
        (false, true) => name0.cmp(name1),
        (true, true) => (name0, size0).cmp(&(name1, size1))
    });

    let mut outbuf = Vec::new();

    for (idx, name, size) in &output {
        print_symbol(
            explorer,
            *idx, name, *size,
            cmd.size,
            &mut outbuf,
            &mut stdio.stdout
        )?;
    }

    Ok(())    
}

fn print_symbol(
    explorer: &Explorer,
    idx: object::SymbolIndex,
    name: &str,
    size: u64,
    show_size: bool,
    outbuf: &mut Vec<u8>,
    stdout: &mut fs::File,
) -> anyhow::Result<()> {
    let sym = explorer.obj.symbol_by_index(idx)?;
    let kind = explorer.symbol_kind(idx);
    
    outbuf.clear();
    writeln!(
        outbuf,
        "{:018p}{} {} {}",
        sym.address() as *const (),
        MaybePrinter(show_size.then_some(format_args!(" {:10}", size)), None),
        kind,
        name,
    )?;
    stdout.write_all(outbuf)?;
    
    Ok(())
}
