//! SCR3 round-trip, robustness and file-handling tests.

use std::io::Cursor;
use std::sync::atomic::AtomicBool;

use shadowcrypt_core::files::{self, decrypt_to_vec};
use shadowcrypt_core::scr3::{self, Params, HEADER_LEN, TAG_LEN};
use shadowcrypt_core::{sniff, Ctx, Error, Format};

/// Cheap KDF and tiny chunks so tests exercise many chunks quickly.
const FAST: Params = Params { log_n: 10, r: 8, p: 1, chunk_log2: 10 };
const CS: usize = 1 << 10;

fn encrypt(data: &[u8], pw: &str, params: &Params) -> Vec<u8> {
    let mut out = Vec::new();
    scr3::encrypt(data, &mut out, pw.as_bytes(), params, data.len() as u64, &mut Ctx::silent()).unwrap();
    out
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

#[test]
fn roundtrip_boundary_sizes() {
    for len in [0, 1, 15, 16, 17, CS - 1, CS, CS + 1, 2 * CS, 3 * CS + 7] {
        let data = pattern(len);
        let ct = encrypt(&data, "pw", &FAST);
        let chunks = if len == 0 { 1 } else { len.div_ceil(CS) };
        assert_eq!(ct.len(), HEADER_LEN + len + chunks * TAG_LEN, "len {len}");
        assert_eq!(sniff(&ct), Some(Format::Scr3));
        let (pt, fmt) = decrypt_to_vec(Cursor::new(&ct), "pw").unwrap();
        assert_eq!(fmt, Format::Scr3);
        assert_eq!(pt, data, "len {len}");
    }
}

#[test]
fn default_params_roundtrip_and_unicode_password() {
    let data = b"hello world".to_vec();
    let pw = "pässwörd 🔑 ключ";
    let ct = encrypt(&data, pw, &Params::default());
    assert_eq!(decrypt_to_vec(Cursor::new(&ct), pw).unwrap().0, data);
}

#[test]
fn wrong_password_is_detected_before_payload() {
    let ct = encrypt(&pattern(5000), "right", &FAST);
    assert!(matches!(decrypt_to_vec(Cursor::new(&ct), "wrong").unwrap_err(), Error::WrongPassword));
    // even with the payload missing entirely, the header check says "wrong password"
    assert!(matches!(
        decrypt_to_vec(Cursor::new(&ct[..HEADER_LEN + 16]), "wrong").unwrap_err(),
        Error::WrongPassword
    ));
}

#[test]
fn header_tampering_detected() {
    let ct = encrypt(&pattern(100), "pw", &FAST);
    for idx in [8, 39, 40, 46, 79] {
        let mut bad = ct.clone();
        bad[idx] ^= 1;
        let err = decrypt_to_vec(Cursor::new(&bad), "pw").unwrap_err();
        assert!(matches!(err, Error::WrongPassword), "byte {idx}: {err:?}");
    }
    // KDF parameters out of bounds are refused without running the KDF
    let mut bad = ct.clone();
    bad[5] = 40;
    assert!(matches!(decrypt_to_vec(Cursor::new(&bad), "pw").unwrap_err(), Error::Corrupt(_)));
}

#[test]
fn payload_tampering_truncation_and_extension_detected() {
    let data = pattern(3 * CS + 100);
    let ct = encrypt(&data, "pw", &FAST);

    // flip a bit in each chunk
    for chunk in 0..4 {
        let mut bad = ct.clone();
        bad[HEADER_LEN + chunk * (CS + TAG_LEN) + 3] ^= 1;
        assert!(matches!(decrypt_to_vec(Cursor::new(&bad), "pw").unwrap_err(), Error::Tampered));
    }
    // drop the final chunk exactly at a chunk boundary
    let cut = HEADER_LEN + 3 * (CS + TAG_LEN);
    assert!(decrypt_to_vec(Cursor::new(&ct[..cut]), "pw").is_err());
    // truncate by a byte
    assert!(decrypt_to_vec(Cursor::new(&ct[..ct.len() - 1]), "pw").is_err());
    // append garbage
    let mut ext = ct.clone();
    ext.extend_from_slice(&[0u8; 40]);
    assert!(decrypt_to_vec(Cursor::new(&ext), "pw").is_err());
    // swap two chunks
    let mut swapped = ct.clone();
    let a = HEADER_LEN..HEADER_LEN + CS + TAG_LEN;
    let b = a.end..a.end + CS + TAG_LEN;
    let (ca, cb) = (ct[a.clone()].to_vec(), ct[b.clone()].to_vec());
    swapped[a].copy_from_slice(&cb);
    swapped[b].copy_from_slice(&ca);
    assert!(decrypt_to_vec(Cursor::new(&swapped), "pw").is_err());
}

#[test]
fn same_input_encrypts_differently() {
    let a = encrypt(b"same", "pw", &FAST);
    let b = encrypt(b"same", "pw", &FAST);
    assert_ne!(a, b);
}

#[test]
fn empty_password_rejected() {
    let mut out = Vec::new();
    let r = scr3::encrypt(&b"x"[..], &mut out, b"", &FAST, 1, &mut Ctx::silent());
    assert!(matches!(r.unwrap_err(), Error::EmptyPassword));
}

#[test]
fn cancellation_stops_work() {
    let cancel = AtomicBool::new(true);
    let mut ctx = Ctx::new(|_| {}, &cancel);
    let data = pattern(10_000);
    let r = scr3::encrypt(&data[..], Vec::new(), b"pw", &FAST, 0, &mut ctx);
    assert!(matches!(r.unwrap_err(), Error::Cancelled));
}

#[test]
fn not_encrypted_input() {
    assert!(sniff(b"hello world").is_none());
    assert!(sniff(b"AES\x07\x00").is_none());
    assert!(sniff(b"AES\x02\x05").is_none());
    assert_eq!(sniff(b"AES\x00\x05"), Some(Format::AesCrypt(0)));
    assert!(matches!(decrypt_to_vec(Cursor::new(b"plain text"), "pw").unwrap_err(), Error::NotEncrypted));
}

// ── File-level behaviour ──

#[test]
fn file_roundtrip_naming_and_no_clobber() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("photo.jpg");
    std::fs::write(&src, pattern(70_000)).unwrap();

    let info = files::inspect(&src).unwrap();
    assert_eq!(info.format, None);

    let enc = files::encrypt_file(&src, None, "pw", &mut Ctx::silent()).unwrap();
    assert_eq!(enc.output, dir.path().join("photo.jpg.aes"));
    assert_eq!(files::inspect(&enc.output).unwrap().format, Some(Format::Scr3));

    // Encrypting again must not overwrite: photo (1).jpg.aes
    let enc2 = files::encrypt_file(&src, None, "pw", &mut Ctx::silent()).unwrap();
    assert_eq!(enc2.output, dir.path().join("photo (1).jpg.aes"));

    // Decrypt while the original still exists → photo (1).jpg, original untouched
    let dec = files::decrypt_file(&enc.output, None, "pw", &mut Ctx::silent()).unwrap();
    assert_eq!(dec.output, dir.path().join("photo (1).jpg"));
    assert_eq!(std::fs::read(&dec.output).unwrap(), pattern(70_000));
    assert_eq!(std::fs::read(&src).unwrap(), pattern(70_000));

    // No temp files left behind
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".partial"))
        .collect();
    assert!(leftovers.is_empty());
}

#[test]
fn failed_decrypt_leaves_nothing_behind() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("secret.txt");
    std::fs::write(&src, b"top secret").unwrap();
    let enc = files::encrypt_file(&src, None, "pw", &mut Ctx::silent()).unwrap();
    std::fs::remove_file(&src).unwrap();

    let err = files::decrypt_file(&enc.output, None, "bad", &mut Ctx::silent()).unwrap_err();
    assert!(matches!(err, Error::WrongPassword));
    let names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["secret.txt.aes".to_string()]);
}

#[test]
fn legacy_scr2_file_level_decrypt() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/scr2/short.scr2.aes");
    let copy = dir.path().join("note.txt.aes");
    std::fs::copy(fixture, &copy).unwrap();
    let out = files::decrypt_file(&copy, None, "Hello", &mut Ctx::silent()).unwrap();
    assert_eq!(out.format, Format::Scr2);
    assert_eq!(out.output, dir.path().join("note.txt"));
    assert_eq!(std::fs::read(out.output).unwrap(), b"ShadowCrypt SCR2 fixture");
}

#[test]
fn file_named_aes_but_plain_is_offered_for_encryption() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("looks-encrypted.aes");
    std::fs::write(&p, b"just text").unwrap();
    assert_eq!(files::inspect(&p).unwrap().format, None);
}
