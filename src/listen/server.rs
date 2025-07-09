use std::fs::File;
use std::io::Write;
use std::sync::Arc;
use std::path::Path;
use std::os::fd::FromRawFd;
use tokio::io::{ self, AsyncReadExt, AsyncWriteExt };
use tokio::net::{ UnixListener, UnixStream };
use crate::call::{ Start, Exit, ExitCode };
use crate::explorer::Explorer;
use crate::util::{ Stdio, recv_fd };


pub struct Server {
    explorer: Arc<Explorer>,
    listener: UnixListener
}

impl Server {
    pub async fn new(ipc_path: &Path, explorer: Explorer)
        -> anyhow::Result<Self>
    {
        let explorer = Arc::new(explorer);
        let listener = UnixListener::bind(ipc_path)?;
        Ok(Server { explorer, listener })
    }

    pub async fn listen(&self) -> anyhow::Result<()> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            let explorer = Arc::clone(&self.explorer);
            tokio::spawn(async move {
                if let Err(err) = exec(&explorer, stream).await {
                    eprintln!("ipc error: {:?}", err);
                }
            });
        }
    }
}

async fn exec(
    explorer: &Explorer,
    mut stream: UnixStream,
) -> anyhow::Result<()> {
    let len = stream.read_u16_le().await?;
    let mut buf = vec![0; len.into()];
    stream.read_exact(&mut buf).await?;

    let start: Start = cbor4ii::serde::from_slice(&buf)?;
    let pid = stream.peer_cred()?.pid();

    println!("{:?} {:?}", pid, &start.options);

    let stdin = recv_fd(&stream).await?;
    let stdout = recv_fd(&stream).await?;
    let stderr = recv_fd(&stream).await?;
    let mut stdio = unsafe {
        Stdio {
            colored: start.colored,
            hyperlink: start.hyperlink,
            stdin: File::from_raw_fd(stdin),
            stdout: File::from_raw_fd(stdout),
            stderr: File::from_raw_fd(stderr)
        }
    };
    let mut sink = io::sink();

    let code = tokio::select! {
        result = start.options.command.exec(explorer, &mut stdio) => match result {
            Ok(()) => ExitCode::Ok,
            Err(err) => {
                writeln!(stdio.stderr, "exec failed: {:?}", err)?;
                ExitCode::Failure
            }
        },
        _ = io::copy(&mut stream, &mut sink) => {
            eprintln!("{:?} command cancel", pid);
            return Ok(())
        }
    };

    let exit = Exit { code };
    let buf = cbor4ii::serde::to_vec(Vec::new(), &exit)?;
    let len: u16 = buf.len().try_into()?;

    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&buf).await?;
    stream.flush().await?;

    Ok(())
}
