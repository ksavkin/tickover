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

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

use chrono::{DateTime, Utc};

use crate::plugin::manifest::PluginManifest;

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

/// Where the history store lives: `<config>/tickover/history/` —
/// the app's own namespace, never a provider's. `None` when the platform
/// reports no config dir (a pathological environment — the caller treats
/// it as "history unavailable", not a crash).
pub fn default_dir() -> Option<PathBuf> {
    crate::plugin::app_config_dir().map(|d| d.join("history"))
}

/// What one scan tick did per provider — surfaced by `stats` so format
/// drift (`skipped_unparsed`) and budget exhaustion (`partial`) are
/// visible rather than silent.
#[derive(Debug)]
pub struct ProviderScan {
    pub provider: String,
    /// `true` when the manifest's root resolved to nothing readable —
    /// provider installed-but-no-history, not an error.
    pub root_missing: bool,
    pub outcome: scanner::ScanOutcome,
}

/// One scan tick across every loaded manifest that declares `[history]`.
/// Each provider gets its own slice of the shared wall-clock budget; the
/// tick ends early (providers after the cutoff simply report `partial`)
/// rather than overrun it.
pub fn scan_tick(
    store: &mut store::HistoryStore,
    manifests: &[PluginManifest],
    options: &BTreeMap<String, bool>,
) -> Vec<ProviderScan> {
    let deadline = Instant::now() + scanner::SCAN_WALL_BUDGET;
    let mut scans = Vec::new();
    for m in manifests {
        let Some(h) = &m.history else { continue };
        let root = crate::plugin::engine_logfile::resolve_root_fields(
            &h.root,
            &h.root_env,
            &h.root_env_join,
            options,
        );
        if !root.is_dir() {
            scans.push(ProviderScan {
                provider: m.id.clone(),
                root_missing: true,
                outcome: scanner::ScanOutcome::default(),
            });
            continue;
        }
        let extractor = formats::extractor_for(h.format);
        let outcome =
            scanner::scan_root(store, &m.id, &root, &h.glob, extractor.as_ref(), deadline);
        scans.push(ProviderScan {
            provider: m.id.clone(),
            root_missing: false,
            outcome,
        });
    }
    scans
}
