//! Local usage-history collection.
//!
//! Providers that keep a local record of token usage declare a `[history]`
//! section in their manifest (`docs/PLUGIN-ARCHITECTURE.md`): a `format`
//! selecting one of the extractors in [`formats`], plus the root/glob the
//! [`scanner`] walks. Records are folded into append-only per-hour buckets
//! persisted by [`store`] under the app's own config directory — provider
//! files are only ever read, and only complete lines are consumed, so a
//! writer mid-append never produces a partial record.
//!
//! Nothing here stores prompts, responses, or any transcript content —
//! only token counts, model names, session ids and project basenames.

pub mod formats;
pub mod scanner;
pub mod store;

use chrono::{DateTime, Utc};

/// One provider request's token usage, normalised across formats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageRecord {
    /// When the request completed (provider-reported timestamp).
    pub ts: DateTime<Utc>,
    /// Owning manifest id (`claude`, `codex`, …).
    pub provider: String,
    /// Project basename (`cwd`'s last component), or `"unknown"`.
    pub project: String,
    /// Provider session/conversation id — for per-session views, not a key.
    pub session_id: String,
    /// Model identifier as the provider wrote it, or `"unknown"`.
    pub model: String,
    pub input: u64,
    pub output: u64,
    /// Tokens served from the provider's cache (billed cheap or free).
    pub cache_read: u64,
    /// Tokens written into the provider's cache (billed at a premium).
    pub cache_write: u64,
    /// Reasoning tokens where a provider reports them separately
    /// (Antigravity); Codex folds them into `output`.
    pub thinking: u64,
    /// Stable id used to drop re-scanned duplicates (message id, turn id,
    /// or a synthetic `path:offset` key for formats without one).
    pub dedup_key: String,
}

impl UsageRecord {
    /// Total tokens across every class.
    pub fn total(&self) -> u64 {
        self.input + self.output + self.cache_read + self.cache_write + self.thinking
    }
}
