mod options;

use std::cmp;
use std::collections::HashSet;
use std::io::Write;
use bstr::ByteSlice;
use object::{ Object, ObjectSection, ObjectSymbol };
use symbolic_demangle::demangle;
use crate::explorer::Explorer;
use crate::util::{ Stdio, YieldPoint, MaybePrinter, is_data_section };
pub use options::Command;


impl Command {
    pub async fn exec(self, explorer: &Explorer, stdio: &mut Stdio) -> anyhow::Result<()> {
        match self.data {
            false => by_symbol(&self, explorer, stdio).await,
            true => by_data(&self, explorer, stdio).await
        }
    }
}

async fn by_symbol(
    cmd: &Command,
    explorer: &Explorer,
    stdio: &mut Stdio
)
    -> anyhow::Result<()>
{
    let re = regex::Regex::new(&cmd.keyword)?;
    let filter = cmd.filter_section
        .as_ref()
        .map(|rule| regex::Regex::new(rule))
        .transpose()?;
    let mut outbuf = Vec::new();
    let mut point = YieldPoint::default();
    let mut output = Vec::new();

    let mut print = |idx, size, name: &str| {
        let sym = explorer.obj.symbol_by_index(idx)?;
        let kind = explorer.symbol_kind(idx);
        
        outbuf.clear();
        writeln!(
            outbuf,
            "{:018p}{} {} {}",
            sym.address() as *const (),
            MaybePrinter(cmd.size.then_some(format_args!(" {:10}", size)), None),
            kind,
            name,
        )?;
        stdio.stdout.write_all(&outbuf)?;
        Ok(()) as anyhow::Result<()>
    };
    let mut sum = 0;

    for &idx in explorer.cache.symlist(&explorer.obj).await {
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

            if let Ok(section_name) = section.name() {
                if !rule.is_match(section_name) {
                    continue
                }
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
                sym_size = explorer.symbol_size(idx).await?;
            }

            if !cmd.sort_size && !cmd.sort_name && !cmd.only_duplicate {
                sum += sym_size;
                print(idx, sym_size, &name)?;
            } else {
                output.push((idx, name, sym_size));
            }
        }
    }

    output.sort_unstable_by(|(_, name0, size0), (_, name1, size1)| match (cmd.sort_size, cmd.sort_name) {
        (false, false) => cmp::Ordering::Equal,
        (true, false) => size0.cmp(&size1),
        (false, true) => name0.cmp(&name1),
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
        print(*idx, *size, name)?;
    }

    if cmd.size {
        writeln!(stdio.stdout, "sum: {}", sum)?;
    }

    Ok(())
}

async fn by_data(
    cmd: &Command,
    explorer: &Explorer,
    stdio: &mut Stdio
)
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
        if let Some(rule) = filter.as_ref() {
            if let Ok(section_name) = section.name() {
                if !rule.is_match(section_name) {
                    continue
                }
            }
        }

        if let Ok(data) = explorer.cache.data(&explorer.obj, section.index()).await {
            let base = section.address();
            
            for mat in re.find_iter(&*data) {
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
