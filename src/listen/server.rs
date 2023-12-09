use std::path::Path;
use std::sync::Arc;
use tokio::net::{ UnixListener, UnixStream };
use tokio::net::unix::SocketAddr;
use crate::Options;


pub struct Server {
    obj: Arc<object::File<'static>>,
    listener: UnixListener
}

impl Server {
    pub async fn new(ipc_path: &Path, obj: object::File<'static>)
        -> anyhow::Result<Self>
    {
        let obj = Arc::new(obj);
        let listener = UnixListener::bind(ipc_path)?;
        Ok(Server { obj, listener })
    }

    pub async fn listen(&self) -> anyhow::Result<()> {
        loop {
            let (stream, addr) = self.listener.accept().await?;
            let obj = Arc::clone(&self.obj);
            tokio::spawn(async move {
                if let Err(err) = exec(obj, stream, addr).await {
                    eprintln!("ipc error: {:?}", err);
                }
            });
        }
    }
}

async fn exec(
    obj: Arc<object::File<'static>>,
    mut stream: UnixStream,
    addr: SocketAddr
) -> anyhow::Result<()> {
    use tokio::io::{ AsyncReadExt, AsyncWriteExt };

    let len = stream.read_u16_le().await?;
    let mut buf = vec![0; len.into()];
    stream.read_exact(&mut buf).await?;

    let cmd: Options = cbor4ii::serde::from_slice(&buf)?;
    cmd.command.exec(&mut stream).await?;

    Ok(())
}
