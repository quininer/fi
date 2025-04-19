use std::io;
use std::fs::File;
use std::path::Path;
use std::os::fd::RawFd;
use std::hash::{ Hash, Hasher };
use std::collections::hash_map::DefaultHasher;
use tokio::net::UnixStream;


pub fn hashpath(path: &Path) -> String {
    let mut hasher = DefaultHasher::new();
    path.as_os_str().hash(&mut hasher);
    let out = hasher.finish();

    data_encoding::HEXLOWER.encode(&out.to_le_bytes())
}

pub fn hashname(path: &Path) -> String {
    let mut hasher = DefaultHasher::new();
    std::process::id().hash(&mut hasher);
    std::time::SystemTime::now().hash(&mut hasher);
    path.as_os_str().len().hash(&mut hasher);
    path.hash(&mut hasher);
    let out = hasher.finish();

    data_encoding::HEXLOWER.encode(&out.to_le_bytes())
}

pub struct Stdio {
    #[allow(dead_code)]
    pub stdin: File,
    pub stdout: File,
    pub stderr: File
}

pub async fn recv_fd(stream: &UnixStream) -> io::Result<RawFd> {
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

pub fn u64ptr(value: &str) -> anyhow::Result<u64> {
    use anyhow::Context;

    let value = if let Some(value) = value.strip_prefix("0x") {
        let mut buf = [0; 8];
        let n = data_encoding::HEXLOWER_PERMISSIVE.decode_len(value.len())?;
        let n = buf.len().checked_sub(n).context("hex value is greater than 64bit")?;
        data_encoding::HEXLOWER_PERMISSIVE
            .decode_mut(value.as_bytes(), &mut buf[n..])
            .map_err(|err| anyhow::format_err!("hex decode failed: {:?}", err))?;
        u64::from_be_bytes(buf)
    } else {
        value.parse::<u64>().context("number parse failed")?
    };

    Ok(value)
}

pub fn is_data_section(kind: object::read::SectionKind) -> bool {
    use object::read::SectionKind;
    
    matches!(
        kind,
        SectionKind::Data
            | SectionKind::ReadOnlyData
            | SectionKind::ReadOnlyDataWithRel
            | SectionKind::ReadOnlyString
            | SectionKind::Tls
            | SectionKind::TlsVariables
            | SectionKind::OtherString
            | SectionKind::DebugString
            | SectionKind::Note
    )    
}

#[derive(Default)]
pub struct YieldPoint(u8);

impl YieldPoint {
    pub async fn yield_now(&mut self) {
        if self.0 == u8::MAX {
            self.0 = 0;
            tokio::task::yield_now().await
        } else {
            self.0 += 1;
        }
    }
}
