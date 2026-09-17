//! A process-wide queue of diagnostic lines a library-crate module produced
//! but cannot write anywhere itself — `crate::diag` lives in `main.rs`'s
//! binary crate, not this one (see `crate::plugin::auth`'s own docs for why
//! this crate does not reach into it directly). [`super::auth`],
//! [`super::engine_http`], [`super::engine_logfile`] and [`super::time`] each
//! kept an independent `Mutex<Vec<String>>` plus a `take_pending_diagnostics`
//! draining it, with the doc comment on every one of the four pointing at the
//! others as "the identical split" — one [`Queue`] type now, one static of it
//! per module, each still drained by its own `take_pending_diagnostics` (kept
//! local to each module rather than folded into this one, since a caller
//! asking `main.rs`'s fetch loop for "the auth diagnostics" wants exactly
//! that module's queue, not all four merged).

use std::collections::HashSet;
use std::sync::Mutex;

/// A queue of diagnostic lines. `push`/`take` alone are enough for a module
/// with its own dedup rule ([`super::auth`]'s `queue_diag_once` keys by an
/// arbitrary discovery-config hash; [`super::time`] queues at most one fixed
/// message per process); [`queue_diag_once`] below is for the shared
/// `(plugin_id, reason)` shape the rest of this crate needs.
pub(crate) struct Queue(Mutex<Vec<String>>);

impl Default for Queue {
    fn default() -> Self {
        Self::new()
    }
}

impl Queue {
    pub(crate) const fn new() -> Self {
        Queue(Mutex::new(Vec::new()))
    }

    /// Push `message` unconditionally.
    pub(crate) fn push(&self, message: String) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(message);
    }

    /// Every line queued since the last call, removing them. Harmless to
    /// call more or less often — a queue not drained this tick is drained
    /// the next one, and an empty queue costs a lock.
    pub(crate) fn take(&self) -> Vec<String> {
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *guard)
    }
}

/// Queue `build_message()`'s result on `queue`, under `(plugin_id, reason)`
/// in `logged`, the first time only — `engine_logfile`'s own once-per-
/// `(plugin, reason)` diagnostic dedup, shared here rather than kept as its
/// one caller's private copy, since [`super::engine_http`]'s `for_each`
/// truncation diagnostic needs the identical rule: a manifest's own overflow
/// must not silence a *different* plugin's, the way a single process-wide
/// flag did before this existed. `build_message` is a closure rather than a
/// plain `String` so the (trivial) formatting cost is paid only when this is
/// actually the first time, not on every refresh a cap keeps tripping on.
/// `reason` is a fixed label the caller chooses (`"matched-files"`,
/// `"for-each-truncated"`, …), never text that varies per call — two
/// different reasons for the same plugin are two different lines, the same
/// one repeated is one.
pub(crate) fn queue_diag_once(
    queue: &Queue,
    logged: &Mutex<Option<HashSet<String>>>,
    plugin_id: &str,
    reason: &str,
    build_message: impl FnOnce() -> String,
) {
    let should_log = logged
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashSet::new)
        .insert(format!("{plugin_id}\u{1}{reason}"));
    if should_log {
        queue.push(build_message());
    }
}
