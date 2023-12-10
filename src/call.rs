use std::{ io, env, future };
use std::path::PathBuf;
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use anyhow::Context;
use directories::ProjectDirs;
use tokio::io::unix::AsyncFd;
use tokio_linux_zio as zio;
use crate::Options;


pub const SESSION_ENVNAME: &str = "FI_SESSION";

pub fn call(dir: ProjectDirs, options: &Options) -> anyhow::Result<()> {
    let ipc_path = if let Some(ipc_path) = env::var_os(SESSION_ENVNAME) {
        PathBuf::from(ipc_path)
    } else {
        use std::os::unix::fs::FileTypeExt;

        let dir = dir.runtime_dir()
            .unwrap_or_else(|| dir.cache_dir());
        let mut found = None;

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;

            if entry.file_type()?.is_socket() {
                found = Some(entry.path());
            }
        }

        found.context("not found any ipc path")?
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(exec(ipc_path, options))
}

async fn exec(ipc_path: PathBuf, options: &Options) -> anyhow::Result<()> {
    let mut stream = UnixStream::connect(ipc_path).context("session connect failed")?;

    {
        use std::io::Write;

        let buf = cbor4ii::serde::to_vec(Vec::new(), options)?;
        let len: u16 = buf.len().try_into().context("command too long")?;

        stream.write_all(&len.to_le_bytes())?;
        stream.write_all(&buf)?;
        stream.flush()?;
    }

    stream.set_nonblocking(true)?;
    let stream = AsyncFd::new(stream)?;

    let stdin = io::stdin();
    let stdout = io::stdout();
    zio::set_nonblocking(&stdin, true)?;
    zio::set_nonblocking(&stdout, true)?;
    let stdin = AsyncFd::new(stdin)?;
    let stdout = AsyncFd::new(stdout)?;

    let (pr, pw) = zio::pipe()?;
    let (pr2, pw2) = zio::pipe()?;
    let mut pw = Some(pw);
    let mut pw2 = Some(pw2);
    let mut sw = Some(&stream);

    loop {
        tokio::select!{
            ret = maybe_splice(&stdin, pw.as_ref().map(AsRef::as_ref)) => {
                ret?;
                pw.take();
            },
            ret = maybe_splice(pr.as_ref(), sw) => {
                ret?;
                sw.take();
                stream.get_ref().shutdown(Shutdown::Write)?;
            },
            ret = maybe_splice(&stream, pw2.as_ref().map(AsRef::as_ref)) => {
                ret?;
                pw2.take();
            },
            ret = zio::splice(pr2.as_ref(), &stdout, None) => {
                ret?;
                break
            },
        };
    }

    Ok(())
}

async fn maybe_splice<R, W>(reader: &AsyncFd<R>, writer: Option<&AsyncFd<W>>)
    -> io::Result<usize>
where
    R: AsRawFd,
    W: AsRawFd
{
    if let Some(writer) = writer {
        zio::splice(reader, writer, None).await
    } else {
        future::pending::<()>().await;
        Ok(0)
    }
}
