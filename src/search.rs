use clap::Args;
use serde::{ Serialize, Deserialize };
use tokio::io::{ AsyncReadExt, AsyncWriteExt };
use tokio::net::unix::SocketAddr;
use tokio::net::UnixStream;


#[derive(Serialize, Deserialize)]
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
#[command(flatten_help = true)]
pub struct Command {
    //
}

impl Command {
    pub async fn exec(self, stream: &mut UnixStream) -> anyhow::Result<()> {
        stream.write_all(b"hello world").await?;
        stream.flush().await?;
        stream.shutdown().await?;
        Ok(())
    }
}
