//! ShadowCrypt core: file encryption and decryption.
//!
//! * New files are written in the **SCR3** format (scrypt + chunked AES-256-GCM),
//!   see [`scr3`].
//! * Legacy **SCR2** files (single-shot AES-256-GCM, ShadowCrypt 1.x) can still be
//!   decrypted, see [`scr2`].
//! * **AES Crypt** files of every stream version (0, 1, 2 and 3) can be decrypted,
//!   see [`aescrypt`].
//!
//! Stream-level functions work on any `Read + Seek` / `Write` pair; [`files`]
//! wraps them with safe file handling (temp file + atomic no-clobber rename).

pub mod aescrypt;
pub mod error;
pub mod files;
pub mod progress;
pub mod scr2;
pub mod scr3;

use std::io::{Read, Seek, SeekFrom, Write};

pub use error::{Error, Result};
pub use progress::{Ctx, Phase, Progress};

/// Read buffer size used while streaming (must be a multiple of 16).
pub(crate) const IO_CHUNK: usize = 1 << 20;

/// An encrypted container format that ShadowCrypt understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// ShadowCrypt v3 (current, written by this version).
    Scr3,
    /// ShadowCrypt v2 (ShadowCrypt 1.x, decrypt only).
    Scr2,
    /// AES Crypt stream format with the given version (0-3, decrypt only).
    AesCrypt(u8),
}

impl Format {
    pub fn label(&self) -> String {
        match self {
            Format::Scr3 => "ShadowCrypt v3".into(),
            Format::Scr2 => "ShadowCrypt v2".into(),
            Format::AesCrypt(v) => format!("AES Crypt v{v}"),
        }
    }
}

/// Number of leading bytes [`sniff`] needs.
pub const SNIFF_LEN: usize = 5;

/// Identify an encrypted file from its first bytes. Returns `None` for anything
/// that is not a recognised encrypted container (i.e. a file to be encrypted).
pub fn sniff(head: &[u8]) -> Option<Format> {
    if head.len() >= 4 && &head[..4] == b"SCR3" {
        return Some(Format::Scr3);
    }
    if head.len() >= 4 && &head[..4] == b"SCR2" {
        return Some(Format::Scr2);
    }
    if head.len() >= 5 && &head[..3] == b"AES" {
        let version = head[3];
        let fifth = head[4];
        return match version {
            // v0 stores "size modulo 16" in the fifth octet
            0 if fifth < 16 => Some(Format::AesCrypt(0)),
            // v1-v3 have a reserved zero octet there
            1..=3 if fifth == 0 => Some(Format::AesCrypt(version)),
            _ => None,
        };
    }
    None
}

/// Sniff the format of a seekable stream, restoring its position afterwards.
pub fn sniff_stream<R: Read + Seek>(r: &mut R) -> Result<Option<Format>> {
    let pos = r.stream_position()?;
    let mut head = [0u8; SNIFF_LEN];
    let n = read_up_to(r, &mut head)?;
    r.seek(SeekFrom::Start(pos))?;
    Ok(sniff(&head[..n]))
}

/// Encrypt `input` into `output` using the current format (SCR3).
/// `total` is the plaintext length if known (used only for progress reporting).
pub fn encrypt<R: Read, W: Write>(
    input: R,
    output: W,
    password: &str,
    total: u64,
    ctx: &mut Ctx,
) -> Result<()> {
    scr3::encrypt(input, output, password.as_bytes(), &scr3::Params::default(), total, ctx)
}

/// Decrypt any supported format, auto-detecting it from the header.
pub fn decrypt<R: Read + Seek, W: Write>(
    mut input: R,
    output: W,
    password: &str,
    ctx: &mut Ctx,
) -> Result<Format> {
    let format = sniff_stream(&mut input)?.ok_or(Error::NotEncrypted)?;
    match format {
        Format::Scr3 => scr3::decrypt(input, output, password.as_bytes(), ctx)?,
        Format::Scr2 => scr2::decrypt(input, output, password.as_bytes(), ctx)?,
        Format::AesCrypt(_) => aescrypt::decrypt(input, output, password, ctx)?,
    }
    Ok(format)
}

/// Read until `buf` is full or EOF; returns the number of bytes read.
pub(crate) fn read_up_to<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Read exactly `buf.len()` bytes, mapping a short read to [`Error::Truncated`].
pub(crate) fn read_exact_or_truncated<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    if read_up_to(r, buf)? != buf.len() {
        return Err(Error::Truncated);
    }
    Ok(())
}

/// Length of the stream from the current position to the end, restoring the position.
pub(crate) fn remaining_len<R: Seek>(r: &mut R) -> Result<u64> {
    let pos = r.stream_position()?;
    let end = r.seek(SeekFrom::End(0))?;
    r.seek(SeekFrom::Start(pos))?;
    Ok(end.saturating_sub(pos))
}

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    Ok(b)
}
