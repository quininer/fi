use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use tokio::sync::{ OnceCell, RwLock };
use memmap2::{ MmapOptions, Mmap };
use object::{ Object, ObjectSymbol, ObjectSection };
use indexmap::IndexMap;


pub struct Explorer {
    pub obj: object::File<'static>,
    pub cache: Cache,
    pub config: RwLock<Config>
}

#[derive(Default)]
pub struct Cache {
    pub addr2sym: OnceLock<object::read::SymbolMap<object::read::SymbolMapName<'static>>>,
    pub sym2idx: OnceLock<IndexMap<&'static str, object::read::SymbolIndex>>,
}

#[derive(Default)]
pub struct Config {
    demangle: bool
}

static TARGET: OnceLock<Mmap> = OnceLock::new();

impl Explorer {
    pub fn open(path: &Path) -> anyhow::Result<Explorer> {
        let fd = fs::File::open(path)?;
        let mmap = unsafe {
            MmapOptions::new().map_copy_read_only(&fd)?
        };
        let mmap = TARGET.get_or_init(move || mmap);
        let obj = object::File::parse(mmap.as_ref())?;

        Ok(Explorer {
            obj,
            cache: Cache::default(),
            config: RwLock::new(Config::default())
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
    pub fn addr2sym<'a>(&'a self, obj: &object::File<'static>)
        -> &'a object::read::SymbolMap<object::read::SymbolMapName<'static>>
    {
        self.addr2sym.get_or_init(|| obj.symbol_map())
    }

    pub fn sym2idx<'a>(&'a self, obj: &object::File<'static>)
        -> &'a IndexMap<&'static str, object::read::SymbolIndex>
    {
        self.sym2idx.get_or_init(|| {
            let mut map = IndexMap::new();
            for sym in obj.symbols() {
                let sym_name = match sym.name() {
                    Ok(name) => name,
                    Err(_err) => {
                        // TODO warn
                        continue
                    }
                };
                map.insert(sym_name, sym.index());
            }
            map.shrink_to_fit();
            map
        })
    }
}
