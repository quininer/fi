use std::env;
use std::path::PathBuf;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::io::{ self, Read, Write };
use anyhow::Context as AnyhowContext;
use serde::{ Serialize, Deserialize };
use directories::ProjectDirs;
use passfd::FdPassingExt;
use crate::util::hashpath;
use crate::Options;


pub const SESSION_ENVNAME: &str = "FI_SESSION";

#[derive(Serialize, Deserialize)]
pub struct Start {
    pub options: Box<Options>
}

#[derive(Serialize, Deserialize)]
pub struct Exit {
    pub code: ExitCode
}

#[derive(Serialize, Deserialize)]
pub enum ExitCode {
    Ok,
    Failure
}

pub fn call(dir: &ProjectDirs, options: Box<Options>) -> anyhow::Result<()> {
    let ipc_path = if let Some(ipc_path) = env::var_os(SESSION_ENVNAME) {
        PathBuf::from(ipc_path)
    } else {
        use std::os::unix::fs::FileTypeExt;

        let dir = dir.runtime_dir()
            .unwrap_or_else(|| dir.cache_dir());
        let mut found = Vec::new();

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;

            if entry.file_type()?.is_socket() {
                found.push(entry.path());
            }
        }

        let prefix = hashpath(&env::current_dir()?);

        found.sort_by_key(|path| path.file_name()
            .and_then(|name| name.to_str())
            .filter(|name| name.starts_with(&prefix))
            .is_none()
        );

        found
            .into_iter()
            .next()
            .context("not found any ipc path")?
    };

    exec(ipc_path, options)
}

fn exec(ipc_path: PathBuf, options: Box<Options>) -> anyhow::Result<()> {
    let mut stream = UnixStream::connect(ipc_path).context("session connect failed")?;

    {
        let options = Start { options };
        let buf = cbor4ii::serde::to_vec(Vec::new(), &options)?;
        let len: u16 = buf.len().try_into().context("command too long")?;

        stream.write_all(&len.to_le_bytes())?;
        stream.write_all(&buf)?;
        stream.flush()?;

        stream.send_fd(io::stdin().as_raw_fd())?;
        stream.send_fd(io::stdout().as_raw_fd())?;
        stream.send_fd(io::stderr().as_raw_fd())?;
        stream.flush()?;
    }

    let mut buf = [0; 2];
    stream.read_exact(&mut buf)?;
    let len = u16::from_le_bytes(buf);
    let mut buf = vec![0; len.into()];
    stream.read_exact(&mut buf)?;

    let exit: Exit = cbor4ii::serde::from_slice(&buf)?;

    match exit.code {
        ExitCode::Ok => Ok(()),
        ExitCode::Failure => anyhow::bail!("exec failed")
    }
}
