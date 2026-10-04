# ShadowCrypt

A free, open-source desktop app for encrypting and decrypting files with a password. Runs on Windows, macOS and Linux.

![Drop screen](screenshots/Screen1.png)
![Encrypt screen](screenshots/Screen2.png)

## Why it exists

[AES Crypt](https://www.aescrypt.com) became paywalled, leaving people unable to open their own encrypted `.aes` files without paying. ShadowCrypt is a free replacement: it decrypts `.aes` files made by **every version of AES Crypt** (stream formats 0, 1, 2 and 3), and encrypts new files with a stronger, modern format.

## Features

- **Opens all AES Crypt files** - stream formats 0-3, i.e. files from the earliest AES Crypt releases up to the current paid 4.x versions
- **Strong encryption** - scrypt key derivation + chunked AES-256-GCM authenticated encryption
- **Instant wrong-password detection** - no waiting for a large file to finish before learning the password was wrong
- **Never writes unverified data** - output goes to a temporary file and only gets its real name once it is complete and authenticated
- **Never overwrites** - existing files are kept; new ones are named `photo (1).jpg`, `photo (2).jpg`, ...
- **No size limit** - files of any size are streamed, never loaded into memory
- **Explorer / Finder integration** - double-click `.aes` files; on Windows, right-click any file and choose *Open With ShadowCrypt*
- **Offline** - no network access, no telemetry, no accounts
- **No admin required** - per-user install on Windows

## Supported formats

| Format | Encrypt | Decrypt | Notes |
|---|:-:|:-:|---|
| ShadowCrypt v3 (`SCR3`) | Yes | Yes | Current format |
| ShadowCrypt v2 (`SCR2`) | - | Yes | Files from ShadowCrypt 1.x |
| AES Crypt stream format 3 | - | Yes | AES Crypt 4.x (PBKDF2-SHA512) |
| AES Crypt stream format 2 | - | Yes | AES Crypt 3.x |
| AES Crypt stream format 1 | - | Yes | Early AES Crypt |
| AES Crypt stream format 0 | - | Yes | Earliest AES Crypt |

The format is detected from the file contents, not its name, so renamed files work too.

AES Crypt compatibility is verified against the 84 known-answer vectors from the official AES Crypt test suite (all four stream formats), files produced by the independent [pyAesCrypt](https://github.com/marcobellaccini/pyAesCrypt) implementation (including non-ASCII passwords), and tests for wrong passwords, tampering and truncation in every format.

## Encryption format (SCR3)

| Property | Value |
|---|---|
| Key derivation | scrypt, N=2^18, r=8, p=1 (256 MB, ~0.5 s); parameters stored per file |
| Key separation | HKDF-SHA256 into a header key and a payload key |
| Password check | HMAC-SHA256 over the header (wrong password detected instantly) |
| Cipher | AES-256-GCM in 64 KB chunks, STREAM construction |
| Integrity | Every chunk authenticated; reordering, truncation and appended data are detected |
| Salt / nonce | 32-byte random salt, 7-byte random nonce prefix per file |

```
"SCR3" | kdf=1 | log2(N) | r | p | salt(32) | nonce prefix(7) | log2(chunk) | header MAC(32)
chunk i: AES-256-GCM(payload key, prefix || i (u32 BE) || last flag, plaintext_i) || tag(16)
```

The previous SCR2 format encrypted the whole file as a single GCM message, which meant a wrong password was only detected after processing the entire file, and was limited to about 64 GB. SCR2 files remain fully readable.

## Building from source

**Requirements:** [Rust](https://rustup.rs) (stable), Node.js 20+, and the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) for your OS (WebView2 is built into Windows 10/11; Linux needs `libwebkit2gtk-4.1-dev`).

```bash
git clone https://github.com/vnatco/shadowcrypt.git
cd shadowcrypt
npm install
```

Run in development (hot reload):

```bash
npm run dev
```

Build installers for the current OS (output in `target/release/bundle/`):

```bash
npm run build
```

Run the test suite:

```bash
npm test
```

## Releases and code signing

Pushing a tag like `v2.0.0` runs `.github/workflows/release.yml`, which builds Windows (NSIS), macOS (universal `.dmg`) and Linux (AppImage, `.deb`, `.rpm`) packages and attaches them to a draft GitHub release.

- **macOS:** signed and notarized automatically when the `APPLE_*` repository secrets are set.
- **Windows:** not signed yet. Signing needs a code signing certificate plus `bundle.windows.signCommand` in `src-tauri/tauri.conf.json`. Until then, SmartScreen shows a warning on first run.

## Project layout

```
crates/shadowcrypt-core/   Encryption library (all formats) + tests and fixtures
src-tauri/                 Desktop app shell (Tauri): commands, OS integration, installer hooks
src/                       User interface (React)
```

## Upgrading from ShadowCrypt 1.x

2.0 is a rewrite on Tauri (much smaller installer, native Rust crypto). Uninstall 1.x from *Settings > Apps* before installing 2.0. Files encrypted with 1.x open normally in 2.0.

## License

MIT - see [LICENSE](LICENSE).
