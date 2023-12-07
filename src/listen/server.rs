use std::path::Path;
use std::sync::Arc;
use tokio::net::{ UnixListener, UnixStream };
use tokio::net::unix::SocketAddr;


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
            tokio::spawn(async move {
                if let Err(err) = exec(stream, addr).await {
                    eprintln!("ipc error: {:?}", err);
                }
            });
        }
    }
}

async fn exec(mut stream: UnixStream, addr: SocketAddr) -> anyhow::Result<()> {
    use tokio::io::{ AsyncReadExt, AsyncWriteExt };

    let mut buf = Vec::new();

    loop {
        let stream = &mut stream;

        let len = stream.read_u32().await?;
        buf.clear();
        stream.take(len.into()).read_to_end(&mut buf).await?;

        //
    }
}
