mod server;

use std::{ io, fs };
use std::path::PathBuf;
use std::sync::OnceLock;
use clap::Args;
use directories::ProjectDirs;
use memmap2::{ MmapOptions, Mmap };
use object::Object;
use crate::util::hashname;
use server::Server;


#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
#[command(flatten_help = true)]
pub struct Command {
    path: PathBuf
}

static TARGET: OnceLock<Mmap> = OnceLock::new();

impl Command {
    pub fn exec(self, dir: ProjectDirs) -> anyhow::Result<()> {
        let ipc_path = {
            let dir = dir.runtime_dir()
                .unwrap_or_else(|| dir.cache_dir());

            fs::create_dir_all(dir)
                .or_else(|err| match err.kind() {
                    io::ErrorKind::AlreadyExists => Ok(()),
                    _ => Err(err)
                })?;

            dir.join(hashname(&self.path))
        };

        let fd = fs::File::open(&self.path)?;
        let mmap = unsafe {
            MmapOptions::new().map_copy_read_only(&fd)?
        };
        let mmap = TARGET.get_or_init(move || mmap);
        let obj = object::File::parse(mmap.as_ref())?;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        rt.block_on(async move {
            let server = Server::new(&ipc_path, obj).await?;

            scopeguard::defer!{
                fs::remove_file(&ipc_path).unwrap();
            }

            println!("set -x FI_SESSION {}", ipc_path.display());

            tokio::select!{
                ret = tokio::signal::ctrl_c() => ret?,
                ret = server.listen() => ret?
            }

            Ok(())
        })
    }
}
