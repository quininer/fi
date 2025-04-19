use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use tokio::sync::OnceCell;
use memmap2::{ MmapOptions, Mmap };
use object::{ Object, ObjectSymbol, ObjectSection };
use indexmap::IndexMap;


pub struct Explorer {
    pub obj: object::File<'static>,
    pub cache: Cache,
}

#[derive(Default)]
pub struct Cache {
    pub addr2sym: OnceCell<object::read::SymbolMap<object::read::SymbolMapName<'static>>>,
    pub sym2idx: OnceCell<IndexMap<&'static str, object::read::SymbolIndex>>,
}

static TARGET: OnceLock<(fs::File, Mmap)> = OnceLock::new();

impl Explorer {
    pub fn open(path: &Path) -> anyhow::Result<Explorer> {
        let fd = fs::File::open(path)?;
        let mmap = unsafe {
            MmapOptions::new().map_copy_read_only(&fd)?
        };
        let (_, mmap) = TARGET.get_or_init(move || (fd, mmap));
        let obj = object::File::parse(mmap.as_ref())?;

        Ok(Explorer {
            obj,
            cache: Cache::default(),
        })
    }

    pub fn symbol_kind(&self, idx: object::read::SymbolIndex) -> char {
        use object::{ SymbolSection, SectionKind };

        let sym = self.obj.symbol_by_index(idx).unwrap();

        let mut kind = match sym.section() {
            SymbolSection::Undefined => 'U',
            SymbolSection::Absolute => 'A',
            SymbolSection::Common => 'C',
            SymbolSection::Section(idx) => match self.obj.section_by_index(idx).map(|section| section.kind()) {
                Ok(SectionKind::Text) => 't',
                Ok(SectionKind::Data) | Ok(SectionKind::Tls) | Ok(SectionKind::TlsVariables) => {
                    'd'
                }
                Ok(SectionKind::ReadOnlyData) | Ok(SectionKind::ReadOnlyString) => 'r',
                Ok(SectionKind::UninitializedData) | Ok(SectionKind::UninitializedTls) => 'b',
                Ok(SectionKind::Common) => 'C',
                _ => '?',
            },
            _ => '?',
        };

        if sym.is_global() {
            kind = kind.to_ascii_uppercase();
        }

        kind
    }
}

impl Cache {
    pub async fn addr2sym<'a>(&'a self, obj: &object::File<'static>)
        -> &'a object::read::SymbolMap<object::read::SymbolMapName<'static>>
    {
        self.addr2sym.get_or_init(async || obj.symbol_map()).await
    }

    pub async fn sym2idx<'a>(&'a self, obj: &object::File<'static>)
        -> &'a IndexMap<&'static str, object::read::SymbolIndex>
    {
        self.sym2idx.get_or_init(async || {
            let mut map = IndexMap::new();
            for sym in obj.symbols() {
                let sym_name = match sym.name() {
                    Ok(name) => name,
                    Err(err) => {
                        eprintln!("bad symbol name: {:?}", err);
                        continue
                    }
                };
                map.insert(sym_name, sym.index());
            }
            map.shrink_to_fit();
            map
        }).await
    }
}
