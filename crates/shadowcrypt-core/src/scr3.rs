//! ShadowCrypt v3 format.
//!
//! ```text
//! offset size
//!  0      4   magic "SCR3"
//!  4      1   KDF id (1 = scrypt)
//!  5      1   scrypt log2(N)
//!  6      1   scrypt r
//!  7      1   scrypt p
//!  8     32   salt
//! 40      7   nonce prefix
//! 47      1   log2(chunk size)
//! 48     32   HMAC-SHA256(header_key, bytes 0..48)
//! 80      …   chunks: AES-256-GCM(payload_key, nonce_i, plaintext_i) || tag(16)
//! ```
//!
//! * `master = scrypt(password, salt, N, r, p)`; `header_key` and `payload_key`
//!   are derived from it with HKDF-SHA256 under distinct labels.
//! * The header MAC doubles as a password check, so a wrong password is
//!   rejected immediately without touching the payload.
//! * Chunks use the STREAM construction (as in `age` / libsodium secretstream):
//!   `nonce_i = prefix(7) || i as u32 BE || last_flag(1)`. Each chunk is
//!   authenticated before it is released; reordering, truncation and appended
//!   data are all detected. The final chunk may be short (or empty for an empty
//!   file); every other chunk is exactly the chunk size.

use std::io::{Read, Seek, Write};

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{random_bytes, read_exact_or_truncated, read_up_to, remaining_len, Ctx, Error, Phase, Result};

pub const MAGIC: &[u8; 4] = b"SCR3";
pub const HEADER_LEN: usize = 80;
pub const TAG_LEN: usize = 16;
const KDF_SCRYPT: u8 = 1;
const INFO_HEADER: &[u8] = b"ShadowCrypt v3 header key";
const INFO_PAYLOAD: &[u8] = b"ShadowCrypt v3 payload key";

/// Bounds accepted when reading a file, so a hostile header can't demand
/// absurd amounts of memory or time.
const MAX_LOG_N: u8 = 22;
const MAX_KDF_MEMORY: u64 = 1 << 30; // 1 GiB
const MIN_CHUNK_LOG2: u8 = 10;
const MAX_CHUNK_LOG2: u8 = 24;

#[derive(Debug, Clone, Copy)]
pub struct Params {
    pub log_n: u8,
    pub r: u8,
    pub p: u8,
    pub chunk_log2: u8,
}

impl Default for Params {
    /// scrypt N=2^18, r=8, p=1 (256 MiB, roughly half a second), 64 KiB chunks.
    fn default() -> Self {
        Self { log_n: 18, r: 8, p: 1, chunk_log2: 16 }
    }
}

impl Params {
    fn validate(&self) -> Result<()> {
        let mem = 128u64 * self.r as u64 * (1u64 << self.log_n.min(63));
        if self.log_n == 0
            || self.log_n > MAX_LOG_N
            || self.r == 0
            || self.p == 0
            || self.p > 16
            || mem > MAX_KDF_MEMORY
        {
            return Err(Error::Corrupt("unsupported key-derivation parameters"));
        }
        if !(MIN_CHUNK_LOG2..=MAX_CHUNK_LOG2).contains(&self.chunk_log2) {
            return Err(Error::Corrupt("unsupported chunk size"));
        }
        Ok(())
    }

    fn chunk_size(&self) -> usize {
        1usize << self.chunk_log2
    }
}

struct Keys {
    header: Zeroizing<[u8; 32]>,
    payload: Zeroizing<[u8; 32]>,
}

fn derive_keys(password: &[u8], salt: &[u8], params: &Params) -> Result<Keys> {
    let sp = scrypt::Params::new(params.log_n, params.r as u32, params.p as u32, 32)
        .map_err(|_| Error::Corrupt("unsupported key-derivation parameters"))?;
    let mut master = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(password, salt, &sp, master.as_mut()).expect("valid output length");
    let hk = Hkdf::<Sha256>::new(None, master.as_ref());
    let mut keys = Keys { header: Zeroizing::new([0u8; 32]), payload: Zeroizing::new([0u8; 32]) };
    hk.expand(INFO_HEADER, keys.header.as_mut()).expect("valid length");
    hk.expand(INFO_PAYLOAD, keys.payload.as_mut()).expect("valid length");
    Ok(keys)
}

fn header_mac(key: &[u8; 32], header: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    mac.update(header);
    mac.finalize().into_bytes().into()
}

fn nonce(prefix: &[u8], counter: u32, last: bool) -> Nonce<aes_gcm::aes::cipher::consts::U12> {
    let mut n = [0u8; 12];
    n[..7].copy_from_slice(prefix);
    n[7..11].copy_from_slice(&counter.to_be_bytes());
    n[11] = last as u8;
    Nonce::clone_from_slice(&n)
}

pub fn encrypt<R: Read, W: Write>(
    mut r: R,
    mut w: W,
    password: &[u8],
    params: &Params,
    total: u64,
    ctx: &mut Ctx,
) -> Result<()> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    params.validate()?;

    let salt: [u8; 32] = random_bytes()?;
    let prefix: [u8; 7] = random_bytes()?;

    let mut header = [0u8; HEADER_LEN];
    header[..4].copy_from_slice(MAGIC);
    header[4] = KDF_SCRYPT;
    header[5] = params.log_n;
    header[6] = params.r;
    header[7] = params.p;
    header[8..40].copy_from_slice(&salt);
    header[40..47].copy_from_slice(&prefix);
    header[47] = params.chunk_log2;

    ctx.report(Phase::DerivingKey, 0, 0);
    let keys = derive_keys(password, &salt, params)?;
    ctx.check_cancel()?;
    let mac = header_mac(&keys.header, &header[..48]);
    header[48..].copy_from_slice(&mac);
    w.write_all(&header)?;

    let aead = Aes256Gcm::new(keys.payload.as_ref().into());
    let cs = params.chunk_size();
    // Two buffers: the chunk being encrypted and one chunk of look-ahead, so we
    // know whether the current chunk is the last one.
    let mut cur = Zeroizing::new(vec![0u8; cs]);
    let mut next = Zeroizing::new(vec![0u8; cs]);
    let mut cur_len = read_up_to(&mut r, &mut cur)?;
    let mut counter: u32 = 0;
    let mut done: u64 = 0;

    loop {
        ctx.check_cancel()?;
        let next_len = if cur_len == cs { read_up_to(&mut r, &mut next)? } else { 0 };
        let last = next_len == 0;
        let tag = aead
            .encrypt_in_place_detached(&nonce(&prefix, counter, last), b"", &mut cur[..cur_len])
            .map_err(|_| Error::TooLarge)?;
        w.write_all(&cur[..cur_len])?;
        w.write_all(&tag)?;
        done += cur_len as u64;
        ctx.report(Phase::Encrypting, done, total);
        if last {
            break;
        }
        counter = counter.checked_add(1).ok_or(Error::TooLarge)?;
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
    }
    w.flush()?;
    Ok(())
}

pub fn decrypt<R: Read + Seek, W: Write>(
    mut r: R,
    mut w: W,
    password: &[u8],
    ctx: &mut Ctx,
) -> Result<()> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    let mut header = [0u8; HEADER_LEN];
    read_exact_or_truncated(&mut r, &mut header)?;
    if &header[..4] != MAGIC {
        return Err(Error::NotEncrypted);
    }
    if header[4] != KDF_SCRYPT {
        return Err(Error::Corrupt("unknown key-derivation function"));
    }
    let params = Params { log_n: header[5], r: header[6], p: header[7], chunk_log2: header[47] };
    params.validate()?;

    ctx.report(Phase::DerivingKey, 0, 0);
    let keys = derive_keys(password, &header[8..40], &params)?;
    ctx.check_cancel()?;
    let expected = header_mac(&keys.header, &header[..48]);
    if !bool::from(expected.ct_eq(&header[48..80])) {
        return Err(Error::WrongPassword);
    }

    let prefix = &header[40..47];
    let cs = params.chunk_size();
    let full = (cs + TAG_LEN) as u64;
    let payload_len = remaining_len(&mut r)?;
    if payload_len < TAG_LEN as u64 {
        return Err(Error::Truncated);
    }
    // The encryptor never emits an empty trailing chunk after a full one, so the
    // final chunk is whatever is left after the full-size chunks.
    let chunks = payload_len.div_ceil(full);
    let last_len = payload_len - (chunks - 1) * full;
    if last_len < TAG_LEN as u64 {
        return Err(Error::Truncated);
    }
    if chunks > u32::MAX as u64 + 1 {
        return Err(Error::TooLarge);
    }
    let plain_total = payload_len - chunks * TAG_LEN as u64;

    let aead = Aes256Gcm::new(keys.payload.as_ref().into());
    let mut buf = Zeroizing::new(vec![0u8; cs + TAG_LEN]);
    let mut done: u64 = 0;
    for i in 0..chunks {
        ctx.check_cancel()?;
        let last = i == chunks - 1;
        let n = if last { last_len as usize } else { full as usize };
        let chunk = &mut buf[..n];
        read_exact_or_truncated(&mut r, chunk)?;
        let (data, tag) = chunk.split_at_mut(n - TAG_LEN);
        aead.decrypt_in_place_detached(&nonce(prefix, i as u32, last), b"", data, Tag::from_slice(tag))
            .map_err(|_| Error::Tampered)?;
        w.write_all(data)?;
        done += data.len() as u64;
        ctx.report(Phase::Decrypting, done, plain_total);
    }
    w.flush()?;
    Ok(())
}
