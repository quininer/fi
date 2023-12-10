use std::{ io, env, future };
use std::pin::Pin;
use std::net::Shutdown;
use std::path::PathBuf;
use std::marker::Unpin;
use std::task::{ ready, Context, Poll };
use std::os::fd::AsRawFd;
use anyhow::Context as AnyhowContext;
use directories::ProjectDirs;
use tokio::net::UnixStream;
use tokio::io::unix::AsyncFd;
use tokio::io::{ ReadBuf, AsyncRead, AsyncWrite };
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
    let mut stream = UnixStream::connect(ipc_path).await
        .context("session connect failed")?;

    {
        use tokio::io::AsyncWriteExt;

        let buf = cbor4ii::serde::to_vec(Vec::new(), options)?;
        let len: u16 = buf.len().try_into().context("command too long")?;

        stream.write_all(&len.to_le_bytes()).await?;
        stream.write_all(&buf).await?;
        stream.flush().await?;
    }

    let stdin = io::stdin();
    let stdout = io::stdout();
    set_nonblocking(&stdin, true)?;
    set_nonblocking(&stdout, true)?;
    let mut stdin = UnixFile(AsyncFd::new(stdin)?);
    let mut stdout = UnixFile(AsyncFd::new(stdout)?);

    let (mut reader, mut writer) = stream.split();

    // If use splice here, there will be error when use stdout redirect.
    //
    // > EINVAL The target file is opened in append mode.
    tokio::select!{
        ret = tokio::io::copy(&mut reader, &mut stdout) => ret?,
        ret = tokio::io::copy(&mut stdin, &mut writer) => ret?,
    };

    tokio::io::copy(&mut reader, &mut stdout).await?;

    Ok(())
}

pub struct UnixFile<T: AsRawFd>(AsyncFd<T>);

impl<T> AsyncRead for UnixFile<T>
where
    T: AsRawFd + io::Read + Unpin,
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>)
        -> Poll<io::Result<()>>
    {
        loop {
            let mut guard = ready!(self.as_mut().get_mut().0.poll_read_ready_mut(cx))?;

            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|inner| inner.get_mut().read(unfilled)) {
                Ok(Ok(len)) => {
                    buf.advance(len);
                    return Poll::Ready(Ok(()));
                },
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl<T> AsyncWrite for UnixFile<T>
where
    T: AsRawFd + io::Write + Unpin
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8])
        -> Poll<io::Result<usize>>
    {
        loop {
            let mut guard = ready!(self.as_mut().get_mut().0.poll_write_ready_mut(cx))?;

            match guard.try_io(|inner| inner.get_mut().write(buf)) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>)
        -> Poll<io::Result<()>>
    {
        loop {
            let mut guard = ready!(self.as_mut().get_mut().0.poll_write_ready_mut(cx))?;

            match guard.try_io(|inner| inner.get_mut().flush()) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }

    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>)
        -> Poll<io::Result<()>>
    {
        Poll::Ready(Ok(()))
    }
}

#[cfg(target_os = "linux")]
pub fn set_nonblocking<T: AsRawFd>(fd: &T, nb: bool) -> io::Result<()> {
    unsafe {
        let v = nb as libc::c_int;
        match libc::ioctl(fd.as_raw_fd(), libc::FIONBIO, &v) {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(())
        }
    }
}
