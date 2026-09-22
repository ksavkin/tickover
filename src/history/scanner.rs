//! Resumable incremental scanning of provider history trees.
//!
//! Separate machinery from the quota walk (`engine_logfile`) on purpose:
//! quota reads the newest handful of matching files under a hard byte
//! budget, while history needs *everything, eventually* — so this scanner
//! is resumable instead of bounded. Each file's [`FileState`] remembers
//! how far it was consumed (`cursor`), and a scan only ever reads forward
//! of it. The wall-clock budget stops a pass partway (`partial`), and the
//! next pass resumes where the last one stopped rather than starting over.
//!
//! Two correctness rules hold for every format:
//!
//! * **Provider files are read-only.** Nothing here writes, truncates,
//!   renames or quarantines anything under a provider's root — all state
//!   lives in [`HistoryStore`]'s own directory.
//! * **Symlinks are not followed.** `walkdir` does not descend through
//!   them by default and files are re-checked as regular files before any
//!   byte is read.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::history::formats::HistoryExtractor;
use crate::history::store::{DayLine, HistoryStore};

/// How long one scan pass may run before it yields with `partial` set.
/// Generous enough that a warm pass (all files unchanged) always finishes;
/// only cold scans of large corpora ever slice.
pub const SCAN_WALL_BUDGET: Duration = Duration::from_millis(2000);

/// One file's read is capped per pass, so a multi-GB transcript cannot
/// hold a scan hostage; the remainder is picked up by later passes.
pub const PER_FILE_BYTE_CAP: u64 = 32 * 1024 * 1024;

/// A file larger than this is still scanned, but in slices of
/// [`PER_FILE_BYTE_CAP`] per pass.
pub const MAX_TRACKED_FILES: usize = 50_000;

/// What a scan pass did — the observability `stats` reports.
#[derive(Debug, Default)]
pub struct ScanOutcome {
    /// Matching files found under the root.
    pub files_seen: usize,
    /// Files actually read this pass.
    pub files_scanned: usize,
    /// New bytes consumed across all files.
    pub bytes_read: u64,
    /// Records accepted after dedup.
    pub records: usize,
    /// Lines that looked like usage but failed to parse.
    pub skipped_unparsed: u64,
    /// `true` when the wall-clock budget stopped the pass early — the
    /// caller should schedule another pass soon, not treat this as done.
    pub partial: bool,
}

/// A candidate file's `stat` identity, refreshed each pass.
struct FileSig {
    path: PathBuf,
    size: u64,
    mtime: i64,
}

/// Walk `root` for files matching `glob` (basename, `*` wildcards — the
/// same matcher `engine_logfile` uses) and extract new usage into `store`.
///
/// `provider` is the manifest id stamped onto every record's bucket.
/// Returns early with `partial` once `deadline` passes.
pub fn scan_root(
    store: &mut HistoryStore,
    provider: &str,
    root: &Path,
    glob: &str,
    extractor: &dyn HistoryExtractor,
    deadline: Instant,
) -> ScanOutcome {
    let mut outcome = ScanOutcome::default();
    let files = collect(root, glob);
    outcome.files_seen = files.len();

    // Cross-file dedup within a single pass (Grok's unified log and its
    // per-session updates can carry the same turn).
    let mut pass_seen: HashSet<String> = HashSet::new();
    // Buckets accumulate per file and flush once the file's extraction
    // succeeds — a failed append leaves the cursor unmoved so the bytes
    // are retried next pass rather than silently lost.
    let mut buckets: Vec<DayLine> = Vec::new();

    for sig in files {
        if Instant::now() >= deadline {
            outcome.partial = true;
            break;
        }
        let key = sig.path.to_string_lossy().into_owned();

        // Decide what this file needs. Three answers: nothing (unchanged),
        // rescan (rewritten — gen bumps, its old buckets stop counting),
        // or resume (appended — read from cursor).
        match store.file_state(&sig.path) {
            Some(st) if st.mtime == sig.mtime && st.size == sig.size && st.cursor >= sig.size => {
                continue; // unchanged since last pass — one stat was the whole cost
            }
            Some(_) => {
                // Changed. A smaller size, or a different prefix digest,
                // means rewrite rather than append.
                let shrunk = sig.size < store.file_state(&sig.path).map_or(0, |s| s.cursor);
                let digest = HistoryStore::prefix_digest(&sig.path);
                let rewritten = match (shrunk, store.file_state(&sig.path)) {
                    (true, _) => true,
                    (_, Some(st)) => digest.as_deref() != Some(st.digest.as_str()),
                    (_, None) => false,
                };
                match store.file_state_mut(&sig.path) {
                    Some(st) if rewritten => {
                        st.reset(digest.unwrap_or_default(), sig.size, sig.mtime)
                    }
                    Some(st) => {
                        st.size = sig.size;
                        st.mtime = sig.mtime;
                        if let Some(d) = digest {
                            st.digest = d;
                        }
                    }
                    None => {}
                }
            }
            None => {
                let digest = HistoryStore::prefix_digest(&sig.path).unwrap_or_default();
                store.begin_file(&sig.path, digest, sig.size, sig.mtime);
            }
        }

        let resume_from = store.file_state(&sig.path).map_or(0, |s| s.cursor);
        let gen = store.file_state(&sig.path).map_or(0, |s| s.gen);
        let extraction = {
            let Some(st) = store.file_state_mut(&sig.path) else {
                continue;
            };
            match extractor.extract(&sig.path, st, PER_FILE_BYTE_CAP, deadline) {
                Ok(e) => e,
                Err(_) => continue, // read failure: retry next pass, cursor unmoved
            }
        };
        outcome.files_scanned += 1;
        outcome.bytes_read += extraction.cursor.saturating_sub(resume_from);
        outcome.skipped_unparsed += extraction.skipped_unparsed;

        // Fold records into (hour, provider, project, model, session)
        // buckets. Dedup order: this pass's cross-file set first, then the
        // file's own ring — the ring persists across passes, the set does
        // not need to.
        let mut grouped: BTreeMap<(String, String, String, String), DayLine> = BTreeMap::new();
        let mut seen_keys: Vec<String> = Vec::new();
        for mut rec in extraction.records {
            if rec.provider.is_empty() {
                rec.provider = provider.to_string();
            }
            // Dedup keys are globally meaningful (message ids, turn ids) —
            // a bare-key pass set therefore also catches a record that
            // shows up in a second file (Grok's unified log + session
            // updates overlap exactly that way).
            if !rec.dedup_key.is_empty() {
                if pass_seen.contains(&rec.dedup_key) {
                    continue;
                }
                if store
                    .file_state(&sig.path)
                    .is_some_and(|st| st.seen(&rec.dedup_key))
                {
                    pass_seen.insert(rec.dedup_key.clone());
                    continue;
                }
                pass_seen.insert(rec.dedup_key.clone());
                seen_keys.push(rec.dedup_key.clone());
            }
            let hour = rec.ts.format("%Y-%m-%dT%H").to_string();
            let gkey = (
                hour.clone(),
                rec.project.clone(),
                rec.model.clone(),
                rec.session_id.clone(),
            );
            let bucket = grouped.entry(gkey).or_insert_with(|| DayLine {
                v: crate::history::store::SCHEMA_VERSION,
                hour,
                provider: provider.to_string(),
                project: rec.project.clone(),
                model: rec.model.clone(),
                session: rec.session_id.clone(),
                file: key.clone(),
                gen,
                input: 0,
                output: 0,
                cache_read: 0,
                cache_write: 0,
                thinking: 0,
                messages: 0,
            });
            bucket.input += rec.input;
            bucket.output += rec.output;
            bucket.cache_read += rec.cache_read;
            bucket.cache_write += rec.cache_write;
            bucket.thinking += rec.thinking;
            bucket.messages += 1;
            outcome.records += 1;
        }
        buckets.extend(grouped.into_values());
        // Persist buckets *before* moving the cursor: crash between append
        // and commit leaves the old cursor, and the next pass's identical
        // re-append is dropped by `days.jsonl`'s exact-line dedup at load.
        if store.append_days(&buckets).is_err() {
            buckets.clear();
            continue; // cursor stays — bytes are retried next pass
        }
        buckets.clear();
        if let Some(st) = store.file_state_mut(&sig.path) {
            st.cursor = extraction.cursor;
            st.size = sig.size;
            st.mtime = sig.mtime;
            st.skipped_unparsed += extraction.skipped_unparsed;
            for k in &seen_keys {
                st.mark_seen(k.clone());
            }
        }
    }
    outcome
}

/// Matching files under `root`, newest first — so a budgeted pass always
/// covers the files still being written before it reaches cold history.
fn collect(root: &Path, glob: &str) -> Vec<FileSig> {
    let mut files: Vec<FileSig> = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if files.len() >= MAX_TRACKED_FILES {
            break;
        }
        let ft = entry.file_type();
        if !ft.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy();
        if !crate::plugin::engine_logfile::glob_matches(glob, &name) {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        files.push(FileSig {
            path: entry.path().to_path_buf(),
            size: meta.len(),
            mtime: meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs() as i64),
        });
    }
    files.sort_by_key(|f| std::cmp::Reverse(f.mtime));
    files
}
