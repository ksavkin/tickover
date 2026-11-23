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
pub mod pricing;
pub mod projects;
pub mod query;
pub mod report;
pub mod report_data;
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

/// All configured history roots (`root` plus any `extra_roots`) for footer
/// attribution in the generated report.
pub fn declared_sources(manifests: &[PluginManifest]) -> Vec<String> {
    let mut sources = Vec::new();
    for m in manifests {
        let Some(h) = &m.history else { continue };
        sources.push(h.root.clone());
        for extra in &h.extra_roots {
            if !sources.contains(extra) {
                sources.push(extra.clone());
            }
        }
    }
    sources
}

/// One scan tick across every loaded manifest that declares `[history]`.
/// The wall-clock budget is divided evenly across them up front — a shared
/// deadline would let the first provider's cold corpus starve the rest for
/// tick after tick, which is exactly what happened to every manifest that
/// sorted after Codex's several-thousand rollouts.
///
/// `options_for` resolves a manifest's declared `[[option]]`s — per plugin,
/// not global, since two manifests can reuse a key name for different
/// values. `manifests` is only the enabled ones with a `[history]` section
/// — both callers already filter to that before calling this — but `known`
/// must be every id the registry has, enabled or not: `scan_root` checks a
/// claimed path's stored owner against it to tell a provider merely
/// disabled for this run (still a live claim) from one actually removed or
/// renamed (a stale one, safe to hand to whoever asks).
pub fn scan_tick(
    store: &mut store::HistoryStore,
    manifests: &[PluginManifest],
    known: &std::collections::HashSet<&str>,
    options_for: &dyn Fn(&PluginManifest) -> BTreeMap<String, bool>,
) -> Vec<ProviderScan> {
    let with_history = manifests.iter().filter(|m| m.history.is_some()).count();
    let slice = if with_history == 0 {
        scanner::SCAN_WALL_BUDGET
    } else {
        scanner::SCAN_WALL_BUDGET / with_history as u32
    };
    let mut scans = Vec::new();
    for m in manifests {
        let Some(h) = &m.history else { continue };
        // A fresh deadline per provider: one that finishes early simply
        // leaves its slice unused — the next provider starts its own.
        let deadline = Instant::now() + slice;
        let options = options_for(m);
        let primary = crate::plugin::engine_logfile::resolve_root_fields(
            &h.root,
            &h.root_env,
            &h.root_env_join,
            &options,
        );
        let mut roots = vec![primary];
        for extra in &h.extra_roots {
            let resolved =
                crate::plugin::expand_home(&crate::plugin::substitute_options(extra, &options));
            if !roots.contains(&resolved) {
                roots.push(resolved);
            }
        }
        let extractor = formats::extractor_for(h.format);
        // `glob` gets the same `{option.<key>}` substitution `root` just
        // got above (both go through `resolve_root_fields`/`substitute_options`
        // for `root`, and this call for `glob`) — the manifest layer sweeps
        // it for exactly that placeholder (`PluginManifest::validate`'s
        // `templates` list treats the three the same), so leaving it raw
        // here would mean a declared, validated placeholder that never
        // actually resolves: the glob would search for its own literal
        // `{option.…}` text and match nothing, ever.
        let glob = crate::plugin::substitute_options(&h.glob, &options);
        let mut any_dir = false;
        let mut combined = scanner::ScanOutcome::default();
        for root in &roots {
            if !root.is_dir() {
                continue;
            }
            if any_dir && (combined.partial || Instant::now() >= deadline) {
                // Earlier root already spent this tick's slice; carry `partial`
                // so the caller schedules a follow-up pass for remaining roots.
                combined.partial = true;
                break;
            }
            any_dir = true;
            let outcome = scanner::scan_root(
                store,
                &m.id,
                root,
                &glob,
                extractor.as_ref(),
                deadline,
                known,
            );
            combined.files_seen += outcome.files_seen;
            combined.files_scanned += outcome.files_scanned;
            combined.bytes_read += outcome.bytes_read;
            combined.records += outcome.records;
            combined.skipped_unparsed += outcome.skipped_unparsed;
            combined.claimed_by_another += outcome.claimed_by_another;
            combined.partial |= outcome.partial;
        }
        scans.push(ProviderScan {
            provider: m.id.clone(),
            root_missing: !any_dir,
            outcome: combined,
        });
    }
    // Confirmed against the filesystem itself, not against whichever roots
    // this process resolved — the panel and `tickover stats` can resolve
    // a provider's root differently (a different `CODEX_HOME` or
    // `CLAUDE_CONFIG_DIR` in one environment), and keying the prune to
    // this process's own resolution let each one drop state the other
    // still needed. Their day lines stay counted regardless; if a path is
    // recreated later, a fresh scan's overlapping ranges supersede the old
    // ones at load rather than double-counting. A provider narrowing its
    // own search (`~/.grok` → `~/.grok/logs`) no longer prunes the file it
    // stopped walking this way — only the file's own deletion does.
    store.prune_missing_files();
    scans
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn scan_tick_scans_primary_and_extra_roots_together() {
        let base = std::env::temp_dir().join(format!("tickover-multiroot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root_a = base.join("cli");
        let root_b = base.join("ide");
        let store_dir = base.join("store");
        std::fs::create_dir_all(&root_a).unwrap();
        std::fs::create_dir_all(&root_b).unwrap();

        let line = |id: &str, tok: u64| {
            serde_json::json!({
                "timestamp": "2026-11-23T10:00:00Z",
                "type": "assistant",
                "message": {
                    "id": id,
                    "model": "claude-sonnet-4-6",
                    "usage": {
                        "input_tokens": tok,
                        "output_tokens": 50,
                        "cache_read_input_tokens": 0,
                        "cache_creation_input_tokens": 0
                    }
                }
            })
            .to_string()
        };
        std::fs::write(root_a.join("a.jsonl"), format!("{}\n", line("m1", 100))).unwrap();
        std::fs::write(root_b.join("b.jsonl"), format!("{}\n", line("m2", 200))).unwrap();

        let toml = format!(
            r#"
id = "sample"
name = "Sample"
menu_label = "Sa"
order = 1
engine = "http-api"
requires_reader = ["reading-history", "history-extra-roots"]
[[windows]]
label = "5H"
role = "primary"
[windows.period]
mode = "assumed"
assumed = 300
[windows.source]
used_percent_path = "p"
resets_at_path = "r"
[http]
[[http.request]]
url = "https://example.com/u"
[history]
format = "claude-transcripts"
root = "{root_a}"
extra_roots = ["{root_b}"]
glob = "*.jsonl"
"#,
            root_a = root_a.display(),
            root_b = root_b.display()
        );
        let manifest = PluginManifest::from_str(&toml).unwrap();
        let known: HashSet<&str> = ["sample"].into_iter().collect();
        let mut store = store::HistoryStore::open(&store_dir).unwrap();
        let manifests = vec![manifest];

        let scans = scan_tick(&mut store, &manifests, &known, &|_| BTreeMap::new());
        assert_eq!(scans.len(), 1);
        assert!(!scans[0].root_missing);
        assert_eq!(scans[0].outcome.files_seen, 2);
        assert_eq!(scans[0].outcome.files_scanned, 2);
        assert_eq!(scans[0].outcome.records, 2);
        store.commit().unwrap();

        let enabled: HashSet<String> = ["sample".to_string()].into_iter().collect();
        let stats = query::compute(&store, query::ALL_DAYS, &enabled);
        assert_eq!(stats.total.input, 300);
        assert_eq!(stats.total.output, 100);

        // Removing root_a still scans root_b cleanly without setting root_missing.
        std::fs::remove_dir_all(&root_a).unwrap();
        let scans2 = scan_tick(&mut store, &manifests, &known, &|_| BTreeMap::new());
        assert!(!scans2[0].root_missing);
        assert_eq!(scans2[0].outcome.files_seen, 1);
        assert_eq!(scans2[0].outcome.records, 0);

        let _ = std::fs::remove_dir_all(&base);
    }
}
