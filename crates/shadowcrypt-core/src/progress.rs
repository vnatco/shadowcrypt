use std::sync::atomic::{AtomicBool, Ordering};

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    DerivingKey,
    Encrypting,
    Decrypting,
    Finalizing,
}

#[derive(Debug, Clone, Copy)]
pub struct Progress {
    pub phase: Phase,
    /// Bytes processed so far in this phase.
    pub done: u64,
    /// Total bytes for this phase (0 when unknown).
    pub total: u64,
}

/// Per-operation context: progress reporting and cooperative cancellation.
pub struct Ctx<'a> {
    on_progress: Box<dyn FnMut(Progress) + Send + 'a>,
    cancel: Option<&'a AtomicBool>,
}

impl<'a> Ctx<'a> {
    pub fn new(on_progress: impl FnMut(Progress) + Send + 'a, cancel: &'a AtomicBool) -> Self {
        Self { on_progress: Box::new(on_progress), cancel: Some(cancel) }
    }

    /// A context that ignores progress and can't be cancelled.
    pub fn silent() -> Ctx<'static> {
        Ctx { on_progress: Box::new(|_| {}), cancel: None }
    }

    pub fn report(&mut self, phase: Phase, done: u64, total: u64) {
        (self.on_progress)(Progress { phase, done, total });
    }

    pub fn check_cancel(&self) -> Result<()> {
        match self.cancel {
            Some(c) if c.load(Ordering::Relaxed) => Err(Error::Cancelled),
            _ => Ok(()),
        }
    }
}
