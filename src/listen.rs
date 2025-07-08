mod options;
mod server;

use std::{ io, fs, env };
use std::path::PathBuf;
use directories::ProjectDirs;
use crate::util::{ hashpath, hashname };
use crate::call::SESSION_ENVNAME;
use crate::explorer::Explorer;
use server::Server;
pub use options::Command;


impl Command {
    pub fn exec(self, dir: &ProjectDirs) -> anyhow::Result<()> {
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
            let cwd = env::current_dir()?;

            let path = format!(
                "{}-{}",
                hashpath(&cwd),
                hashname(&self.path)
            );

            dir.join(path)
        };

        let explorer = Explorer::open(self.path)?;

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
