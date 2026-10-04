//! Legacy ShadowCrypt v2 format (ShadowCrypt 1.x), decrypt only.
//!
//! ```text
//! "SCR2" | 0x02 | salt(16) | iv(12) | tag(16) | ciphertext
//! key = scrypt(password, salt, N=2^17, r=8, p=1, 32)
//! ciphertext = AES-256-GCM(key, iv), no AAD
//! ```
//!
//! The whole file is one GCM message, so it is decrypted as a stream here
//! (CTR keystream + GHASH) and the tag is checked at the end. Callers must
//! discard the output on error, which [`crate::files`] does.

use std::io::{Read, Seek, Write};

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use aes::Aes256;
use ghash::{universal_hash::UniversalHash, GHash};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{read_exact_or_truncated, remaining_len, Ctx, Error, Phase, Result, IO_CHUNK};

const HEADER_LEN: usize = 49;
const SCRYPT_LOG_N: u8 = 17;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

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
    if &header[..4] != b"SCR2" {
        return Err(Error::NotEncrypted);
    }
    if header[4] != 0x02 {
        return Err(Error::UnsupportedVersion(header[4]));
    }
    let salt = &header[5..21];
    let iv = &header[21..33];
    let stored_tag = &header[33..49];

    ctx.report(Phase::DerivingKey, 0, 0);
    let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 32).expect("valid params");
    let mut key = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(password, salt, &params, key.as_mut()).expect("valid output length");
    ctx.check_cancel()?;

    let cipher = Aes256::new(key.as_ref().into());
    // H = E_K(0^128)
    let mut h = GenericArray::default();
    cipher.encrypt_block(&mut h);
    let mut ghash = GHash::new(&h);
    // J0 = IV || 0^31 || 1 ; tag mask = E_K(J0); payload counter starts at inc32(J0)
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;
    let mut tag_mask = GenericArray::clone_from_slice(&j0);
    cipher.encrypt_block(&mut tag_mask);
    let mut ctr_iv = j0;
    ctr_iv[15] = 2;
    let mut ctr = ctr::Ctr32BE::<Aes256>::new(key.as_ref().into(), (&ctr_iv).into());

    let ct_len = remaining_len(&mut r)?;
    // GCM's 32-bit block counter limits one message to 2^32 - 2 blocks.
    if ct_len > ((1u64 << 32) - 2) * 16 {
        return Err(Error::TooLarge);
    }
    let mut buf = Zeroizing::new(vec![0u8; IO_CHUNK]);
    let mut done: u64 = 0;
    while done < ct_len {
        ctx.check_cancel()?;
        let n = ((ct_len - done) as usize).min(IO_CHUNK);
        let chunk = &mut buf[..n];
        read_exact_or_truncated(&mut r, chunk)?;
        // IO_CHUNK is a multiple of 16, so only the final call can be a partial block.
        ghash.update_padded(chunk);
        ctr.apply_keystream(chunk);
        w.write_all(chunk)?;
        done += n as u64;
        ctx.report(Phase::Decrypting, done, ct_len);
    }

    ctx.report(Phase::Finalizing, ct_len, ct_len);
    let mut lengths = GenericArray::default();
    lengths[8..].copy_from_slice(&(ct_len * 8).to_be_bytes()); // AAD length (first 8 bytes) is 0
    ghash.update(&[lengths]);
    let mut tag = ghash.finalize();
    for (t, m) in tag.iter_mut().zip(tag_mask.iter()) {
        *t ^= m;
    }
    if !bool::from(tag.as_slice().ct_eq(stored_tag)) {
        return Err(Error::WrongPasswordOrCorrupt);
    }
    w.flush()?;
    Ok(())
}
