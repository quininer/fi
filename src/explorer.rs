use std::fs;
use std::path::PathBuf;
use std::borrow::Cow;
use std::sync::{ Arc, OnceLock };
use std::collections::HashMap;
use tokio::sync::{ OnceCell, RwLock, Mutex };
use memmap2::{ MmapOptions, Mmap };
use object::{ Object, ObjectSection, ObjectSymbol, ObjectSymbolTable };
use object::read::{ SectionIndex, SymbolIndex };
use addr2line::Loader;


pub struct Explorer {
    pub path: PathBuf,
    pub obj: object::File<'static>,
    pub cache: Cache,
}

#[derive(Default)]
pub struct Cache {
    pub addr2sym: OnceCell<object::read::SymbolMap<object::read::SymbolMapName<'static>>>,
    pub symlist: OnceCell<Box<[SymbolIndex]>>,
    pub dyn_rela: OnceCell<Box<[(u64, object::read::Relocation)]>>,
    pub addr2line: OnceCell<Mutex<Loader>>,
    pub data: DataCache
}

#[derive(Default)]
pub struct DataCache {
    data: RwLock<Vec<Arc<Cow<'static, [u8]>>>>,
    map: RwLock<HashMap<SectionIndex, usize>>,
}

static TARGET: OnceLock<(fs::File, Mmap)> = OnceLock::new();

impl Explorer {
    pub fn open(path: PathBuf) -> anyhow::Result<Explorer> {
        let fd = fs::File::open(&path)?;
        let mmap = unsafe {
            MmapOptions::new().map_copy_read_only(&fd)?
        };
        let (_, mmap) = TARGET.get_or_init(move || (fd, mmap));
        let obj = object::File::parse(mmap.as_ref())?;

        Ok(Explorer {
            path, obj,
            cache: Cache::default(),
        })
    }

    pub fn symbol_kind(&self, idx: SymbolIndex) -> char {
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

    pub async fn symbol_size(&self, idx: SymbolIndex) -> anyhow::Result<u64> {
        let sym = self.obj.symbol_by_index(idx)?;

        let size = if self.obj.format() != object::BinaryFormat::MachO {
            sym.size()
        } else {
            let symlist = self.cache.symlist(&self.obj).await;

            let idx = match symlist.binary_search_by(|&idx0| {
                let sym0 = self.obj.symbol_by_index(idx0).unwrap();
                sym0.address().cmp(&sym.address())
            }) {
                Ok(idx) => idx,
                Err(_) => anyhow::bail!("not found symbol address")
            };
            match symlist.get(idx + 1) {
                Some(&sym1) => {
                    let sym1 = self.obj.symbol_by_index(sym1).unwrap();
                    sym1.address() - sym.address()
                },
                None => match sym.section() {
                    object::read::SymbolSection::Section(section_idx) => {
                        let section = self.obj.section_by_index(section_idx)?;
                        section.address() + section.size() - sym.address()
                    },
                    _ => sym.size(),
                }
            }
        };

        Ok(size)        
    }
}

impl Cache {
    pub async fn addr2sym<'a>(&'a self, obj: &object::File<'static>)
        -> &'a object::read::SymbolMap<object::read::SymbolMapName<'static>>
    {
        self.addr2sym.get_or_init(async || obj.symbol_map()).await
    }

    pub async fn symlist<'a>(&'a self, obj: &object::File<'static>)
        -> &'a [SymbolIndex]
    {
        self.symlist.get_or_init(async || {
            let mut list = obj.symbol_table()
                .into_iter()
                .map(|symtab| symtab.symbols())
                .flatten()
                .map(|sym| sym.index())
                .collect::<Vec<_>>();
            list.sort_by_key(|&symidx| obj.symbol_by_index(symidx).unwrap().address());
            list.into_boxed_slice()
        }).await
    }

    pub async fn dyn_rela<'a>(&'a self, obj: &object::File<'static>)
        -> &'a [(u64, object::read::Relocation)]
    {
        self.dyn_rela.get_or_init(async || {
            let mut list = obj.dynamic_relocations()
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            list.sort_by_key(|(addr, _)| *addr);
            list.into_boxed_slice()
        })
            .await
    }

    pub async fn data<'a>(&'a self, obj: &object::File<'static>, idx: SectionIndex)
        -> anyhow::Result<Arc<Cow<'static, [u8]>>>
    {
        // fast check
        {
            let map = self.data.map.read().await;
            if let Some(id) = map.get(&idx).copied() {
                let list = self.data.data.read().await;
                return Ok(list[id].clone());
            }
        }

        // insert
        let id = {
            let mut map = self.data.map.write().await;

            // double check
            if map.get(&idx).is_none() {
                let section = obj.section_by_index(idx)?;
                let data = section.uncompressed_data()?;
                
                let mut list = self.data.data.write().await;
                let id = list.len();
                list.push(Arc::new(data));
                map.insert(idx, id);

                Some(id)
            } else {
                None
            }
        };

        let id = if let Some(id) = id {
            id
        } else {
            let map = self.data.map.read().await;
            map.get(&idx).copied().unwrap()
        };

        let list = self.data.data.read().await;
        Ok(list[id].clone())
    }
}
