//! Compatibility tests against files produced by other implementations.

use std::io::Cursor;
use std::path::PathBuf;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use shadowcrypt_core::{files::decrypt_to_vec, Error, Format};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[derive(Deserialize)]
struct Vector {
    plaintext: String,
    ciphertext_hex: String,
}

#[derive(Deserialize)]
struct FileFixture {
    file: String,
    password: String,
    plain_sha256: String,
}

fn load_vectors(version: u8) -> Vec<Vector> {
    let p = fixtures().join(format!("aescrypt/test_vectors_v{version}.json"));
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

#[test]
fn aescrypt_known_answer_vectors_all_versions() {
    let mut total = 0;
    for version in 0..=3u8 {
        let vectors = load_vectors(version);
        assert_eq!(vectors.len(), 21, "v{version} vector count");
        for (i, v) in vectors.iter().enumerate() {
            let ct = hex::decode(&v.ciphertext_hex).unwrap();
            let (pt, fmt) = decrypt_to_vec(Cursor::new(&ct), "Hello")
                .unwrap_or_else(|e| panic!("v{version} vector {i}: {e}"));
            assert_eq!(fmt, Format::AesCrypt(version));
            assert_eq!(pt, v.plaintext.as_bytes(), "v{version} vector {i}");
            total += 1;
        }
    }
    assert_eq!(total, 84);
}

#[test]
fn aescrypt_wrong_password_per_version() {
    for version in 0..=3u8 {
        let v = &load_vectors(version)[5];
        let ct = hex::decode(&v.ciphertext_hex).unwrap();
        let err = decrypt_to_vec(Cursor::new(&ct), "hello").unwrap_err();
        match version {
            // v0 has no key check: only detectable at the end
            0 => assert!(matches!(err, Error::WrongPasswordOrCorrupt), "v0: {err:?}"),
            _ => assert!(matches!(err, Error::WrongPassword), "v{version}: {err:?}"),
        }
    }
}

#[test]
fn aescrypt_tampering_detected_per_version() {
    for version in 0..=3u8 {
        let v = load_vectors(version).into_iter().max_by_key(|v| v.plaintext.len()).unwrap();
        let mut ct = hex::decode(&v.ciphertext_hex).unwrap();
        let trailer = if version == 1 || version == 2 { 33 } else { 32 };
        let idx = ct.len() - trailer - 20; // inside the ciphertext body
        ct[idx] ^= 0x01;
        let err = decrypt_to_vec(Cursor::new(&ct), "Hello").unwrap_err();
        assert!(
            matches!(err, Error::Tampered | Error::WrongPasswordOrCorrupt),
            "v{version}: {err:?}"
        );
    }
}

#[test]
fn aescrypt_truncation_detected_per_version() {
    for version in 0..=3u8 {
        let v = load_vectors(version).into_iter().max_by_key(|v| v.plaintext.len()).unwrap();
        let ct = hex::decode(&v.ciphertext_hex).unwrap();
        for cut in [1usize, 16, 33, ct.len() / 2] {
            let r = decrypt_to_vec(Cursor::new(&ct[..ct.len() - cut]), "Hello");
            assert!(r.is_err(), "v{version} truncated by {cut} must fail");
        }
    }
}

#[test]
fn pyaescrypt_files() {
    let dir = fixtures().join("pyaescrypt");
    let list: Vec<FileFixture> =
        serde_json::from_slice(&std::fs::read(dir.join("pyaes_fixtures.json")).unwrap()).unwrap();
    assert_eq!(list.len(), 3);
    for f in list {
        let data = std::fs::read(dir.join(&f.file)).unwrap();
        let (pt, fmt) = decrypt_to_vec(Cursor::new(&data), &f.password)
            .unwrap_or_else(|e| panic!("{}: {e}", f.file));
        assert_eq!(fmt, Format::AesCrypt(2));
        assert_eq!(sha256_hex(&pt), f.plain_sha256, "{}", f.file);
    }
}

#[test]
fn shadowcrypt_v2_files_from_1_x() {
    let dir = fixtures().join("scr2");
    let list: Vec<FileFixture> =
        serde_json::from_slice(&std::fs::read(dir.join("scr2_fixtures.json")).unwrap()).unwrap();
    assert_eq!(list.len(), 4);
    for f in &list {
        let data = std::fs::read(dir.join(&f.file)).unwrap();
        let (pt, fmt) = decrypt_to_vec(Cursor::new(&data), &f.password)
            .unwrap_or_else(|e| panic!("{}: {e}", f.file));
        assert_eq!(fmt, Format::Scr2);
        assert_eq!(sha256_hex(&pt), f.plain_sha256, "{}", f.file);
    }
    // wrong password / tampering
    let data = std::fs::read(dir.join("short.scr2.aes")).unwrap();
    assert!(matches!(
        decrypt_to_vec(Cursor::new(&data), "nope").unwrap_err(),
        Error::WrongPasswordOrCorrupt
    ));
    let mut bad = data.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(decrypt_to_vec(Cursor::new(&bad), "Hello").is_err());
}
