use std::{ io, fmt };
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
    pub colored: bool,
    pub hyperlink: bool,
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

/// Parse an address, either decimal or hexadecimal with a `0x` / `0X` prefix.
///
/// Hexadecimal digits need no zero padding, so both `0x141a781` and
/// `0x000000000141a781` are accepted.
pub fn u64ptr(value: &str) -> anyhow::Result<u64> {
    use anyhow::Context;
    use std::num::IntErrorKind;

    let value = match value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        Some(hex) => {
            anyhow::ensure!(!hex.is_empty(), "hex value is empty");
            anyhow::ensure!(
                !hex.as_bytes().first().is_some_and(|c| matches!(c, b'+' | b'-')),
                "hex value must not have a sign"
            );

            u64::from_str_radix(hex, 16).map_err(|err| match err.kind() {
                IntErrorKind::PosOverflow =>
                    anyhow::format_err!("hex value is greater than 64bit"),
                _ => anyhow::format_err!("hex parse failed: {value:?}"),
            })?
        }
        None => value.parse::<u64>().context("number parse failed")?
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

pub struct HexPrinter<'a>(pub &'a [u8], pub usize);
pub struct AsciiPrinter<'a>(pub &'a [u8]);
pub struct MaybePrinter<T>(pub Option<T>, pub Option<char>);
pub enum EitherPrinter<A, B> {
    Left(A),
    Right(B)
}

impl fmt::Display for HexPrinter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        debug_assert!(self.0.len() <= self.1);
        
        for &b in self.0.iter().take(self.1) {
            write!(f, "{:02x} ", b)?;
        }

        for _ in self.0.len()..self.1 {
            write!(f, "   ")?;
        }

        Ok(())
    }
}

impl fmt::Display for AsciiPrinter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::fmt::Write;

        for &b in self.0.iter() {
            let c = b as char;
            let c = if c.is_ascii_graphic() {
                c
            } else {
                '.'
            };
            f.write_char(c)?;
        }

        Ok(())
    }
}

impl<T: fmt::Display> fmt::Display for MaybePrinter<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(t) = self.0.as_ref() {
            fmt::Display::fmt(t, f)?;
        } else if let Some(t) = self.1.as_ref() {
            fmt::Display::fmt(t, f)?;
        }

        Ok(())
    }
}

impl<A: fmt::Display, B: fmt::Display> fmt::Display for EitherPrinter<A, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EitherPrinter::Left(a) => fmt::Display::fmt(a, f),
            EitherPrinter::Right(b) => fmt::Display::fmt(b, f),
        }
    }
}

pub trait IfSupported {
    fn if_supported<'a, F, O>(&'a self, flag: bool, f: F)
        -> EitherPrinter<O, &'a Self>
    where
        F: FnOnce(&'a Self) -> O,
        O: 'a
    ;
}

impl<T> IfSupported for T {
    fn if_supported<'a, F, O>(&'a self, flag: bool, f: F)
        -> EitherPrinter<O, &'a Self>
    where
        F: FnOnce(&'a Self) -> O,
        O: 'a
    {
        if flag {
            EitherPrinter::Left(f(self))
        } else {
            EitherPrinter::Right(self)
        }
    }
}

pub struct Hyperlink<T, L> {
    text: T,
    link: L
}

impl<T: fmt::Display, L: AsRef<str>> Hyperlink<T, L> {
    pub fn new(text: T, link: L) -> Self {
        Hyperlink { text, link }
    }
}

impl<T: fmt::Display, L: AsRef<str>> fmt::Display for Hyperlink<T, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\x1B]8;;{}\x1B\\", self.link.as_ref())?;
        fmt::Display::fmt(&self.text, f)?;
        write!(f, "\x1B]8;;\x1B\\")
    }
}

#[cfg(test)]
mod tests {
    use super::u64ptr;

    #[test]
    fn parse_address() {
        // decimal
        assert_eq!(u64ptr("0").unwrap(), 0);
        assert_eq!(u64ptr("4718433").unwrap(), 0x47ff61);
        assert_eq!(u64ptr("1000").unwrap(), 1000);

        // padded hex
        assert_eq!(u64ptr("0x000000000141a781").unwrap(), 0x141a781);
        assert_eq!(u64ptr("0xffffffffffffffff").unwrap(), u64::MAX);

        // unpadded hex, odd number of digits
        assert_eq!(u64ptr("0x0").unwrap(), 0);
        assert_eq!(u64ptr("0x1").unwrap(), 1);
        assert_eq!(u64ptr("0x141a781").unwrap(), 0x141a781);
        assert_eq!(u64ptr("0XFFFF").unwrap(), 0xffff);
        assert_eq!(u64ptr("0x1000000000000000").unwrap(), 1 << 60);
    }

    #[test]
    fn reject_bad_address() {
        assert!(u64ptr("").is_err());
        assert!(u64ptr("0x").is_err());
        assert!(u64ptr("0x1_0").is_err());
        assert!(u64ptr("0xg").is_err());
        assert!(u64ptr("0x-1").is_err());
        assert!(u64ptr("0x+1").is_err());
        assert!(u64ptr("0x10000000000000000").is_err());
        assert!(u64ptr("-1").is_err());
        assert!(u64ptr("18446744073709551616").is_err());
    }
}
