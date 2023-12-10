mod server;

use std::{ io, fs, env };
use std::path::PathBuf;
use clap::Args;
use serde::{ Serialize, Deserialize };
use directories::ProjectDirs;
use crate::util::hashname;
use crate::call::SESSION_ENVNAME;
use crate::explorer::Explorer;
use server::Server;


#[derive(Serialize, Deserialize)]
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
#[command(flatten_help = true)]
pub struct Command {
    path: PathBuf
}

impl Command {
    pub fn exec(self, dir: ProjectDirs) -> anyhow::Result<()> {
        let ipc_path = if let Some(ipc_path) = env::var_os(SESSION_ENVNAME) {
            PathBuf::from(ipc_path)
        } else {
            let dir = dir.runtime_dir()
                .unwrap_or_else(|| dir.cache_dir());

            fs::create_dir_all(dir)
                .or_else(|err| match err.kind() {
                    io::ErrorKind::AlreadyExists => Ok(()),
                    _ => Err(err)
                })?;

            dir.join(hashname(&self.path))
        };

        let explorer = Explorer::open(&self.path)?;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        rt.block_on(async move {
            let server = Server::new(&ipc_path, explorer).await?;

            scopeguard::defer!{
                fs::remove_file(&ipc_path).unwrap();
            }

            println!("set -x {} {}", SESSION_ENVNAME, ipc_path.display());

            tokio::select!{
                ret = tokio::signal::ctrl_c() => ret?,
                ret = server.listen() => ret?
            }

            Ok(())
        })
    }
}
