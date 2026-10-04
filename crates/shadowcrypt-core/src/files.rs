//! File-level encrypt/decrypt with safe output handling.
//!
//! * Output is written to a hidden temp file in the destination folder and only
//!   renamed to its final name once it is complete (and, for decryption, fully
//!   authenticated). A crash or error never leaves a partial or unverified file
//!   under the real name; the temp file is removed on failure.
//! * Existing files are never overwritten: `report.pdf` becomes
//!   `report (1).pdf`, `report (2).pdf`, … and the final rename itself refuses
//!   to clobber, so a file created in the meantime is not overwritten either.

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};

use crate::{scr3, sniff, Ctx, Error, Format, Phase, Result, SNIFF_LEN};

const BUF_SIZE: usize = 1 << 20;
const MAX_NAME_ATTEMPTS: u32 = 10_000;
/// Free space kept in reserve beyond the expected output size.
const SPACE_MARGIN: u64 = 1 << 20;

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    /// `Some` if the file is a recognised encrypted container.
    pub format: Option<Format>,
}

#[derive(Debug, Clone)]
pub struct Outcome {
    pub output: PathBuf,
    pub format: Format,
}

/// Stat a file and detect whether it is encrypted (by content, not extension).
pub fn inspect(path: &Path) -> Result<FileInfo> {
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Err(Error::Io(io::Error::new(io::ErrorKind::InvalidInput, "Not a file")));
    }
    let mut head = [0u8; SNIFF_LEN];
    let n = crate::read_up_to(&mut File::open(path)?, &mut head)?;
    Ok(FileInfo {
        path: path.to_path_buf(),
        name: file_name(path),
        size: meta.len(),
        format: sniff(&head[..n]),
    })
}

/// Encrypt `input` to `<name>.aes` in `out_dir` (default: next to the input).
pub fn encrypt_file(input: &Path, out_dir: Option<&Path>, password: &str, ctx: &mut Ctx) -> Result<Outcome> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    let src = File::open(input)?;
    let size = src.metadata()?.len();
    let dir = output_dir(input, out_dir);
    let name = file_name(input);

    let params = scr3::Params::default();
    let chunks = size / (1u64 << params.chunk_log2) + 1;
    check_space(&dir, size + scr3::HEADER_LEN as u64 + chunks * scr3::TAG_LEN as u64)?;

    let (stem, ext) = split_name(&name);
    let output = write_atomically(&dir, &stem, &format!("{ext}.aes"), ctx, |w, ctx| {
        scr3::encrypt(BufReader::with_capacity(BUF_SIZE, src), w, password.as_bytes(), &params, size, ctx)
    })?;
    Ok(Outcome { output, format: Format::Scr3 })
}

/// Decrypt `input` into `out_dir` (default: next to the input). The output name
/// drops a trailing `.aes`/`.enc`; otherwise `.decrypted` is appended.
pub fn decrypt_file(input: &Path, out_dir: Option<&Path>, password: &str, ctx: &mut Ctx) -> Result<Outcome> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    let mut src = BufReader::with_capacity(BUF_SIZE, File::open(input)?);
    let size = src.get_ref().metadata()?.len();
    let format = crate::sniff_stream(&mut src)?.ok_or(Error::NotEncrypted)?;
    let dir = output_dir(input, out_dir);
    check_space(&dir, size)?;

    let (stem, ext) = decrypted_name(&file_name(input));
    let output = write_atomically(&dir, &stem, &ext, ctx, |w, ctx| {
        crate::decrypt(src, w, password, ctx).map(|_| ())
    })?;
    Ok(Outcome { output, format })
}

/// Run `body` against a temp file in `dir`, then move it to a free
/// `stem[ (n)]ext` name without overwriting anything.
fn write_atomically(
    dir: &Path,
    stem: &str,
    ext: &str,
    ctx: &mut Ctx,
    body: impl FnOnce(&mut BufWriter<&File>, &mut Ctx) -> Result<()>,
) -> Result<PathBuf> {
    let tmp = tempfile::Builder::new()
        .prefix(".shadowcrypt-")
        .suffix(".partial")
        .tempfile_in(dir)?;
    {
        let mut w = BufWriter::with_capacity(BUF_SIZE, tmp.as_file());
        body(&mut w, ctx)?;
        w.flush()?;
    }
    ctx.report(Phase::Finalizing, 0, 0);
    tmp.as_file().sync_all()?;

    let mut tmp = tmp;
    for i in 0..MAX_NAME_ATTEMPTS {
        let candidate = dir.join(candidate_name(stem, ext, i));
        if candidate.exists() {
            continue;
        }
        match tmp.persist_noclobber(&candidate) {
            Ok(_) => return Ok(candidate),
            Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => tmp = e.file,
            // Some filesystems (FAT/exFAT, some network shares on Unix) can't do
            // an exclusive rename; fall back to a plain rename of a name we just
            // checked is free.
            Err(e) => {
                let tmp = e.file;
                if candidate.exists() {
                    return Err(Error::Io(e.error));
                }
                tmp.persist(&candidate).map_err(|e| Error::Io(e.error))?;
                return Ok(candidate);
            }
        }
    }
    Err(Error::Io(io::Error::new(io::ErrorKind::AlreadyExists, "No free output file name")))
}

fn output_dir(input: &Path, out_dir: Option<&Path>) -> PathBuf {
    match out_dir {
        Some(d) => d.to_path_buf(),
        None => match input.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        },
    }
}

fn file_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into())
}

/// Split `name` into (stem, extension-with-dot); dotfiles have no extension.
pub fn split_name(name: &str) -> (String, String) {
    match name.rfind('.') {
        Some(i) if i > 0 => (name[..i].to_string(), name[i..].to_string()),
        _ => (name.to_string(), String::new()),
    }
}

/// `photo.jpg.aes` → (`photo`, `.jpg`); `notes.aes` → (`notes`, ``);
/// `blob` → (`blob`, `.decrypted`).
pub fn decrypted_name(name: &str) -> (String, String) {
    let lower = name.to_ascii_lowercase();
    for suffix in [".aes", ".enc"] {
        if lower.ends_with(suffix) && name.len() > suffix.len() {
            return split_name(&name[..name.len() - suffix.len()]);
        }
    }
    (name.to_string(), ".decrypted".into())
}

fn candidate_name(stem: &str, ext: &str, i: u32) -> String {
    if i == 0 {
        format!("{stem}{ext}")
    } else {
        format!("{stem} ({i}){ext}")
    }
}

fn check_space(dir: &Path, needed: u64) -> Result<()> {
    // Best effort: if free space can't be determined, let the write itself fail.
    if let Ok(available) = fs4::available_space(dir) {
        if available < needed.saturating_add(SPACE_MARGIN) {
            return Err(Error::InsufficientSpace { needed, available });
        }
    }
    Ok(())
}

/// Convenience for tests and tools: decrypt from any reader into memory.
pub fn decrypt_to_vec<R: Read + Seek>(r: R, password: &str) -> Result<(Vec<u8>, Format)> {
    let mut out = Vec::new();
    let f = crate::decrypt(r, &mut out, password, &mut Ctx::silent())?;
    Ok((out, f))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(split_name("a.txt"), ("a".into(), ".txt".into()));
        assert_eq!(split_name(".bashrc"), (".bashrc".into(), "".into()));
        assert_eq!(split_name("archive.tar.gz"), ("archive.tar".into(), ".gz".into()));
        assert_eq!(decrypted_name("photo.jpg.aes"), ("photo".into(), ".jpg".into()));
        assert_eq!(decrypted_name("PHOTO.JPG.AES"), ("PHOTO".into(), ".JPG".into()));
        assert_eq!(decrypted_name("notes.aes"), ("notes".into(), "".into()));
        assert_eq!(decrypted_name(".aes"), (".aes".into(), ".decrypted".into()));
        assert_eq!(decrypted_name("blob"), ("blob".into(), ".decrypted".into()));
        assert_eq!(candidate_name("photo", ".jpg", 2), "photo (2).jpg");
        assert_eq!(candidate_name("photo", ".jpg.aes", 1), "photo (1).jpg.aes");
    }
}
