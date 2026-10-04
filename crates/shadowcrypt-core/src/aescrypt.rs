//! AES Crypt decryption, stream format versions 0, 1, 2 and 3.
//!
//! Follows the reference implementation (terrapane/aescrypt_engine) and
//! <https://www.aescrypt.com/aes_stream_format.html>:
//!
//! ```text
//! v0: "AES" 0x00 modulo  IV(16)                                   C  HMAC(32)
//! v1: "AES" 0x01 0x00    IV(16) Enc(IV2+K2)(48) HMAC1(32)         C  modulo HMAC2(32)
//! v2: "AES" 0x02 0x00 ext* IV(16) Enc(IV2+K2)(48) HMAC1(32)       C  modulo HMAC2(32)
//! v3: "AES" 0x03 0x00 ext* iter(4) IV(16) Enc(IV2+K2)(48) HMAC1(32) C(PKCS#7) HMAC2(32)
//! ```
//!
//! * v0-v2: key = SHA-256 iterated 8192x over (digest || UTF-16LE password),
//!   digest seeded with IV zero-padded to 32 bytes.
//! * v3: key = PBKDF2-HMAC-SHA512(UTF-8 password, salt = IV, iter).
//! * HMAC1 = HMAC-SHA256(key, Enc(IV2+K2) [|| 0x03 for v3]).
//! * HMAC2 = HMAC-SHA256(K2, C). C is AES-256-CBC under (K2, IV2); v0 uses (key, IV).
//! * The final block is trimmed by `modulo & 0x0F` (0 = full block), or by
//!   PKCS#7 padding in v3.

use std::io::{Read, Seek, SeekFrom, Write};

use aes::cipher::{generic_array::GenericArray, BlockDecryptMut, KeyIvInit};
use aes::Aes256;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{read_exact_or_truncated, remaining_len, Ctx, Error, Phase, Result, IO_CHUNK};

type HmacSha256 = Hmac<Sha256>;
type CbcDec = cbc::Decryptor<Aes256>;

/// Upper bound on PBKDF2 iterations accepted from a file (same as the reference).
pub const MAX_ITERATIONS: u32 = 5_000_000;
/// AES Crypt's legacy key-derivation round count (v0-v2).
const ACKDF_ROUNDS: usize = 8192;
/// Sanity limit on the total size of v2/v3 extensions.
const MAX_EXTENSIONS_LEN: u64 = 1 << 20;

pub fn decrypt<R: Read + Seek, W: Write>(
    mut r: R,
    mut w: W,
    password: &str,
    ctx: &mut Ctx,
) -> Result<()> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }

    // ── Header ──
    let mut head = [0u8; 5];
    read_exact_or_truncated(&mut r, &mut head)?;
    if &head[..3] != b"AES" {
        return Err(Error::NotEncrypted);
    }
    let version = head[3];
    if version > 3 {
        return Err(Error::UnsupportedVersion(version));
    }
    // v0: "size modulo 16"; v1+: reserved (the v1/v2 modulo lives in the trailer)
    let header_modulo = head[4] & 0x0F;

    if version >= 2 {
        skip_extensions(&mut r)?;
    }

    let iterations = if version >= 3 {
        let mut b = [0u8; 4];
        read_exact_or_truncated(&mut r, &mut b)?;
        let it = u32::from_be_bytes(b);
        if it == 0 || it > MAX_ITERATIONS {
            return Err(Error::Corrupt("invalid KDF iteration count"));
        }
        it
    } else {
        0
    };

    let mut iv = [0u8; 16];
    read_exact_or_truncated(&mut r, &mut iv)?;

    // ── Key derivation ──
    ctx.report(Phase::DerivingKey, 0, 0);
    let key = if version <= 2 {
        ackdf(password, &iv)
    } else {
        let mut k = Zeroizing::new([0u8; 32]);
        pbkdf2::pbkdf2_hmac::<Sha512>(password.as_bytes(), &iv, iterations, k.as_mut());
        k
    };
    ctx.check_cancel()?;

    // ── Session key (v1+) ──
    let (data_iv, data_key) = if version == 0 {
        (iv, key)
    } else {
        let mut enc = [0u8; 48];
        read_exact_or_truncated(&mut r, &mut enc)?;
        let mut stored = [0u8; 32];
        read_exact_or_truncated(&mut r, &mut stored)?;

        let mut mac = <HmacSha256 as Mac>::new_from_slice(key.as_ref()).expect("any key length");
        mac.update(&enc);
        if version >= 3 {
            mac.update(&[version]);
        }
        if !bool::from(mac.finalize().into_bytes().ct_eq(&stored)) {
            return Err(Error::WrongPassword);
        }

        let mut dec = CbcDec::new(key.as_ref().into(), (&iv).into());
        for block in enc.as_chunks_mut::<16>().0 {
            dec.decrypt_block_mut(GenericArray::from_mut_slice(block));
        }
        let mut session_iv = [0u8; 16];
        session_iv.copy_from_slice(&enc[..16]);
        let mut session_key = Zeroizing::new([0u8; 32]);
        session_key.copy_from_slice(&enc[16..48]);
        zeroize::Zeroize::zeroize(&mut enc);
        (session_iv, session_key)
    };

    // ── Layout of the remainder: ciphertext + trailer ──
    let trailer_len: u64 = if version == 1 || version == 2 { 33 } else { 32 };
    let remaining = remaining_len(&mut r)?;
    if remaining < trailer_len {
        return Err(Error::Truncated);
    }
    let ct_len = remaining - trailer_len;
    if !ct_len.is_multiple_of(16) {
        return Err(Error::Corrupt("ciphertext is not a whole number of blocks"));
    }
    if version >= 3 && ct_len == 0 {
        return Err(Error::Corrupt("missing padding block"));
    }

    let data_start = r.stream_position()?;
    r.seek(SeekFrom::Start(data_start + ct_len))?;
    let mut trailer = [0u8; 33];
    read_exact_or_truncated(&mut r, &mut trailer[..trailer_len as usize])?;
    let (modulo, stored_hmac): (u8, &[u8]) = match version {
        0 => (header_modulo, &trailer[..32]),
        1 | 2 => (trailer[0] & 0x0F, &trailer[1..33]),
        _ => (0, &trailer[..32]),
    };
    r.seek(SeekFrom::Start(data_start))?;

    // ── Stream: HMAC over ciphertext, CBC-decrypt, hold back the final block ──
    let mut mac = <HmacSha256 as Mac>::new_from_slice(data_key.as_ref()).expect("any key length");
    let mut dec = CbcDec::new(data_key.as_ref().into(), (&data_iv).into());
    let mut buf = Zeroizing::new(vec![0u8; IO_CHUNK]);
    let mut last_block = Zeroizing::new([0u8; 16]);
    let mut have_last = false;
    let mut done: u64 = 0;

    while done < ct_len {
        ctx.check_cancel()?;
        let n = ((ct_len - done) as usize).min(IO_CHUNK);
        let chunk = &mut buf[..n];
        read_exact_or_truncated(&mut r, chunk)?;
        mac.update(chunk);
        for block in chunk.as_chunks_mut::<16>().0 {
            dec.decrypt_block_mut(GenericArray::from_mut_slice(block));
        }
        // Everything except the very last block of the whole stream can be written now.
        if have_last {
            w.write_all(last_block.as_ref())?;
        }
        w.write_all(&chunk[..n - 16])?;
        last_block.copy_from_slice(&chunk[n - 16..]);
        have_last = true;
        done += n as u64;
        ctx.report(Phase::Decrypting, done, ct_len);
    }

    ctx.report(Phase::Finalizing, ct_len, ct_len);
    if !bool::from(mac.finalize().into_bytes().ct_eq(stored_hmac)) {
        // v0 has no key-check value, so a wrong password only shows up here.
        return Err(if version == 0 { Error::WrongPasswordOrCorrupt } else { Error::Tampered });
    }

    if have_last {
        let keep = if version >= 3 {
            let pad = last_block[15] as usize;
            if pad == 0 || pad > 16 {
                return Err(Error::Corrupt("invalid padding"));
            }
            16 - pad
        } else if modulo == 0 {
            16
        } else {
            modulo as usize
        };
        w.write_all(&last_block[..keep])?;
    }
    w.flush()?;
    Ok(())
}

/// Skip the v2+ extension blocks: repeated (u16 BE length, data), ending at length 0.
fn skip_extensions<R: Read + Seek>(r: &mut R) -> Result<()> {
    let mut total: u64 = 0;
    loop {
        let mut len = [0u8; 2];
        read_exact_or_truncated(r, &mut len)?;
        let len = u16::from_be_bytes(len) as u64;
        if len == 0 {
            return Ok(());
        }
        total += len;
        if total > MAX_EXTENSIONS_LEN || remaining_len(r)? < len {
            return Err(Error::Corrupt("invalid header extensions"));
        }
        r.seek(SeekFrom::Current(len as i64))?;
    }
}

/// AES Crypt's original KDF (stream versions 0-2).
fn ackdf(password: &str, iv: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let pw: Zeroizing<Vec<u8>> =
        Zeroizing::new(password.encode_utf16().flat_map(|u| u.to_le_bytes()).collect());
    let mut digest = Zeroizing::new([0u8; 32]);
    digest[..16].copy_from_slice(iv);
    for _ in 0..ACKDF_ROUNDS {
        let mut h = Sha256::new();
        h.update(digest.as_ref());
        h.update(pw.as_slice());
        digest.copy_from_slice(&h.finalize());
    }
    digest
}
