use std::io;
use std::fs::File;
use std::path::Path;
use std::os::fd::RawFd;
use tokio::net::UnixStream;


pub fn hashname(path: &Path) -> String {
    use std::hash::{ Hash, Hasher };
    use std::collections::hash_map::DefaultHasher;

    let mut hasher = DefaultHasher::new();
    std::process::id().hash(&mut hasher);
    std::time::SystemTime::now().hash(&mut hasher);
    path.as_os_str().len().hash(&mut hasher);
    path.hash(&mut hasher);
    let out = hasher.finish();

    data_encoding::HEXLOWER.encode(&out.to_le_bytes())
}

pub struct Stdio {
    pub stdin: File,
    pub stdout: File,
    pub stderr: File
}

pub async fn recv_fd(mut stream: &UnixStream)
    -> io::Result<RawFd>
{
    use std::os::fd::AsRawFd;
    use passfd::FdPassingExt;

    loop {
        stream.readable().await?;

        match stream.as_raw_fd().recv_fd() {
            Ok(fd) => return Ok(fd),
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => (),
            Err(err) => return Err(err)
        }
    }
}
