use std::io::Write;
use clap::Args;
use serde::{ Serialize, Deserialize };
use aho_corasick::AhoCorasick;
use bstr::ByteSlice;
use object::{ Object, ObjectSection, ObjectSymbol };
use symbolic_demangle::demangle;
use crate::explorer::Explorer;
use crate::util::{ Stdio, YieldPoint, is_data_section };


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
    data: bool,

    /// filter section by regex
    #[arg(short, long)]
    filter_section: Option<String>,
}

impl Command {
    pub async fn exec(self, explorer: &Explorer, stdio: &mut Stdio) -> anyhow::Result<()> {
        let ac = AhoCorasick::new(&self.keywords)?;

        match self.data {
            false => by_symbol(&self, &ac, explorer, stdio).await,
            true => by_data(&self, &ac, explorer, stdio).await
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
    let filter = cmd.filter_section
        .as_ref()
        .map(|rule| regex::Regex::new(rule))
        .transpose()?;
    let mut outbuf = Vec::new();
    let mut point = YieldPoint::default();

    for (mangled_name, &idx) in explorer.cache.sym2idx(&explorer.obj).await {
        point.yield_now().await;
        
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

            outbuf.clear();
            writeln!(
                outbuf,
                "{:018p} {} {}",
                sym.address() as *const (),
                kind,
                name,
            )?;
            stdio.stdout.write_all(&outbuf)?;
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

        // TODO less alloc
        if let Ok(data) = explorer.cache.data(&explorer.obj, section.index()).await {
            let base = section.address();
            
            for mat in ac.find_iter(&*data) {
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
