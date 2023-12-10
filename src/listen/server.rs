use std::path::Path;
use std::sync::Arc;
use tokio::net::{ UnixListener, UnixStream };
use crate::Options;
use crate::explorer::Explorer;


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
    use tokio::io::AsyncReadExt;

    let len = stream.read_u16_le().await?;
    let mut buf = vec![0; len.into()];
    stream.read_exact(&mut buf).await?;

    let cmd: Options = cbor4ii::serde::from_slice(&buf)?;

    println!("{:?} {:?}", stream.peer_cred()?.pid(), cmd);

    cmd.command.exec(explorer, stream).await?;

    Ok(())
}
