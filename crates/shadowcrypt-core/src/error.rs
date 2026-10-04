use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The password is definitely wrong (a key-check value failed before any
    /// plaintext was produced).
    #[error("Incorrect password")]
    WrongPassword,

    /// The format can only detect this at the very end of the file, so a wrong
    /// password and a damaged file are indistinguishable (AES Crypt v0, SCR2).
    #[error("Incorrect password, or the file is damaged")]
    WrongPasswordOrCorrupt,

    /// The password was accepted but the data failed authentication.
    #[error("The file is damaged or has been tampered with")]
    Tampered,

    #[error("The file is truncated or incomplete")]
    Truncated,

    #[error("The file is corrupt: {0}")]
    Corrupt(&'static str),

    #[error("This file isn't encrypted with a supported format")]
    NotEncrypted,

    #[error("Unsupported file version ({0})")]
    UnsupportedVersion(u8),

    #[error("Password must not be empty")]
    EmptyPassword,

    #[error("The file is too large for this format")]
    TooLarge,

    #[error("Cancelled")]
    Cancelled,

    #[error("Not enough disk space: need {needed} bytes, only {available} free")]
    InsufficientSpace { needed: u64, available: u64 },

    #[error("{0}")]
    Io(#[from] io::Error),
}

impl Error {
    /// Stable machine-readable code for the UI.
    pub fn code(&self) -> &'static str {
        match self {
            Error::WrongPassword => "wrong_password",
            Error::WrongPasswordOrCorrupt => "wrong_password_or_corrupt",
            Error::Tampered => "tampered",
            Error::Truncated => "truncated",
            Error::Corrupt(_) => "corrupt",
            Error::NotEncrypted => "not_encrypted",
            Error::UnsupportedVersion(_) => "unsupported_version",
            Error::EmptyPassword => "empty_password",
            Error::TooLarge => "too_large",
            Error::Cancelled => "cancelled",
            Error::InsufficientSpace { .. } => "insufficient_space",
            Error::Io(e) if e.kind() == io::ErrorKind::PermissionDenied => "permission_denied",
            Error::Io(_) => "io",
        }
    }
}
