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
use std::fs;
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
        // WAL-mode SQLite writes land in `<path>-wal` while the `.db`'s
        // own signature stays frozen until a checkpoint — a live
        // conversation would look "unchanged" forever without it.
        let wal_now = if extractor.watches_wal() {
            wal_sig(&sig.path)
        } else {
            (0, 0, 0)
        };

        // Stamp the owning provider before the unchanged check can skip —
        // the query layer attributes drift counts (and any future
        // per-file figure) to a provider through it.
        if let Some(st) = store.file_state_mut(&sig.path) {
            st.provider = provider.to_string();
        }

        // Decide what this file needs. Three answers: nothing (unchanged),
        // rescan (rewritten — gen bumps, its old buckets stop counting),
        // or resume (appended — read from cursor).
        match store.file_state(&sig.path) {
            Some(st)
                if st.mtime == sig.mtime
                    && st.size == sig.size
                    && st.cursor >= sig.size
                    && wal_now == stored_wal_sig(st) =>
            {
                continue; // unchanged since last pass — one stat was the whole cost
            }
            Some(_) => {
                // Changed. A smaller size, or a different prefix digest,
                // means rewrite rather than append. The digest covers the
                // span it was computed over (`digest_len`), so an append to
                // a small file verifies against the old span rather than
                // re-digesting the grown tail.
                let st_cursor = store.file_state(&sig.path).map_or(0, |s| s.cursor);
                let span = store
                    .file_state(&sig.path)
                    .map_or(0, |s| s.digest_len.min(s.size));
                let shrunk = sig.size < st_cursor || sig.size < span;
                let digest = HistoryStore::prefix_digest(&sig.path, span);
                let rewritten = match (shrunk, store.file_state(&sig.path)) {
                    (true, _) => true,
                    (_, Some(st)) => digest.as_deref() != Some(st.digest.as_str()),
                    (_, None) => false,
                };
                match store.file_state_mut(&sig.path) {
                    Some(st) if rewritten => {
                        // The digest stored with the reset must cover the
                        // *new* span — the one just compared was over the
                        // old file's prefix.
                        let new_span = sig.size.min(crate::history::store::PREFIX_BYTES as u64);
                        let fresh_digest =
                            HistoryStore::prefix_digest(&sig.path, new_span).unwrap_or_default();
                        st.reset(fresh_digest, sig.size, sig.mtime)
                    }
                    Some(st) => {
                        st.size = sig.size;
                        st.mtime = sig.mtime;
                    }
                    None => {}
                }
            }
            None => {
                let span = (sig.size).min(crate::history::store::PREFIX_BYTES as u64);
                let digest = HistoryStore::prefix_digest(&sig.path, span).unwrap_or_default();
                store.begin_file(&sig.path, digest, sig.size, sig.mtime);
            }
        }

        let resume_from = store.file_state(&sig.path).map_or(0, |s| s.cursor);
        let gen = store.file_state(&sig.path).map_or(0, |s| s.gen);
        // Extractors mutate `st.aux` while they read (Codex's cumulative
        // baseline, Grok's session map, Antigravity's row watermark). If the
        // append below fails, those advances must roll back too — otherwise
        // the retry diffs against an already-advanced baseline and the
        // records between are lost silently.
        let aux_backup = store.file_state(&sig.path).map(|s| s.aux.clone());
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
        let mut global_keys: Vec<String> = Vec::new();
        // Byte range for JSONL; a row-watermark span for SQLite — whatever
        // the extractor reports is what supersession compares.
        let (range_lo, range_hi) = extraction.range.unwrap_or((resume_from, extraction.cursor));
        for mut rec in extraction.records {
            if rec.provider.is_empty() {
                rec.provider = provider.to_string();
            }
            // Dedup keys are globally meaningful (message ids, turn ids) —
            // so they are checked against the pass set, this file's ring,
            // *and* the store-wide ring: the same record surfacing in a
            // second file on a later pass (Grok's unified log + session
            // updates overlap exactly that way) is still caught.
            if !rec.dedup_key.is_empty() {
                if pass_seen.contains(&rec.dedup_key)
                    || store
                        .file_state(&sig.path)
                        .is_some_and(|st| st.seen(&rec.dedup_key))
                    || store.seen_globally(&key, &rec.dedup_key)
                {
                    pass_seen.insert(rec.dedup_key.clone());
                    continue;
                }
                pass_seen.insert(rec.dedup_key.clone());
                global_keys.push(rec.dedup_key.clone());
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
                lo: range_lo,
                hi: range_hi,
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
            if let (Some(st), Some(aux)) = (store.file_state_mut(&sig.path), aux_backup) {
                st.aux = aux;
            }
            continue; // cursor stays — bytes are retried next pass
        }
        buckets.clear();
        if let Some(st) = store.file_state_mut(&sig.path) {
            st.cursor = extraction.cursor;
            st.size = sig.size;
            st.mtime = sig.mtime;
            st.skipped_unparsed += extraction.skipped_unparsed;
            if extractor.watches_wal() {
                st.aux.insert(
                    "wal".into(),
                    serde_json::json!([wal_now.0, wal_now.1, wal_now.2]),
                );
            }
            for k in &seen_keys {
                st.mark_seen(k.clone());
            }
        }
        for k in global_keys {
            store.mark_seen_globally(&key, k);
        }
    }
    outcome
}

/// `(size, mtime-nanos, header-mix)` of a SQLite `<file>-wal` sibling —
/// `(0, 0, 0)` when no WAL exists, which is also the signature an
/// extractor stores for one. Nanosecond resolution matters: a passive
/// checkpoint can leave the WAL the same size and let the next write land
/// within the same second — a seconds-granular sig would call that
/// "unchanged" and skip live rows. The header mix covers the residual
/// hole (same size *and* same mtime, e.g. an in-place frame overwrite):
/// the 32-byte WAL header's salts/checksums change on every checkpoint
/// reset, so mixing it catches what stat cannot.
fn wal_sig(path: &Path) -> (u64, u64, u64) {
    let wal = PathBuf::from(format!("{}-wal", path.display()));
    fs::metadata(&wal)
        .ok()
        .map(|m| {
            let mut header = [0u8; 32];
            let header_mix = fs::File::open(&wal)
                .ok()
                .and_then(|mut f| {
                    use std::io::Read as _;
                    f.read(&mut header).ok()
                })
                .map(|n| {
                    // Mix the bytes actually read; a shorter file just
                    // mixes fewer — still a valid change signal.
                    use blake2::Digest as _;
                    let h = blake2::Blake2b512::digest(&header[..n]);
                    u64::from_le_bytes(h[..8].try_into().unwrap())
                })
                .unwrap_or(0);
            (
                m.len(),
                m.modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_nanos() as u64),
                header_mix,
            )
        })
        .unwrap_or((0, 0, 0))
}

/// The WAL signature a `watches_wal` extractor recorded last scan.
fn stored_wal_sig(st: &crate::history::store::FileState) -> (u64, u64, u64) {
    st.aux
        .get("wal")
        .and_then(|v| serde_json::from_value::<(u64, u64, u64)>(v.clone()).ok())
        .unwrap_or((0, 0, 0))
}

/// Matching files under `root`, newest first — so a budgeted pass always
/// covers the files still being written before it reaches cold history.
/// The [`MAX_TRACKED_FILES`] cap applies *after* the sort: cutting the walk
/// early would bound memory but could leave the newest file outside the
/// tracked set entirely.
fn collect(root: &Path, glob: &str) -> Vec<FileSig> {
    let mut files: Vec<FileSig> = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
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
    files.truncate(MAX_TRACKED_FILES);
    files
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::formats::Extraction;
    use crate::history::store::{FileState, HistoryStore};
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A SQLite-shaped stub: consumes the file in one pass and watches
    /// the `-wal` sibling for writes the `.db` signature misses.
    struct WalStub {
        calls: AtomicUsize,
    }
    impl HistoryExtractor for WalStub {
        fn extract(
            &self,
            _path: &Path,
            st: &mut FileState,
            _byte_cap: u64,
            _deadline: Instant,
        ) -> io::Result<Extraction> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Extraction {
                cursor: st.size,
                ..Default::default()
            })
        }
        fn watches_wal(&self) -> bool {
            true
        }
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tickover-scan-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_growing_wal_reopens_an_unchanged_db() {
        let root = tmpdir("wal-root");
        let dir = tmpdir("wal-store");
        fs::write(root.join("conv.db"), b"db-bytes").unwrap();
        let mut store = HistoryStore::open(&dir).unwrap();
        let ex = WalStub {
            calls: AtomicUsize::new(0),
        };
        let far = Instant::now() + Duration::from_secs(30);

        scan_root(&mut store, "agy", &root, "*.db", &ex, far);
        assert_eq!(ex.calls.load(Ordering::SeqCst), 1);
        // Same signatures, no WAL yet: the second pass is a stat-only skip.
        scan_root(&mut store, "agy", &root, "*.db", &ex, far);
        assert_eq!(ex.calls.load(Ordering::SeqCst), 1);
        // Writes landing in the WAL alone must still reopen the db.
        fs::write(root.join("conv.db-wal"), b"new rows").unwrap();
        scan_root(&mut store, "agy", &root, "*.db", &ex, far);
        assert_eq!(ex.calls.load(Ordering::SeqCst), 2);
        // Checkpointed away: WAL gone — one reopen to record (0,0), then skip.
        fs::remove_file(root.join("conv.db-wal")).unwrap();
        scan_root(&mut store, "agy", &root, "*.db", &ex, far);
        scan_root(&mut store, "agy", &root, "*.db", &ex, far);
        assert_eq!(ex.calls.load(Ordering::SeqCst), 3);
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_same_size_wal_rewrite_reopens_the_db() {
        // A checkpoint resets the WAL header salts and later writes can
        // land at the same length inside one mtime tick — stat alone calls
        // that "unchanged"; the header mix must not.
        let root = tmpdir("wal-mix-root");
        let dir = tmpdir("wal-mix-store");
        fs::write(root.join("conv.db"), b"db-bytes").unwrap();
        let mut store = HistoryStore::open(&dir).unwrap();
        let ex = WalStub {
            calls: AtomicUsize::new(0),
        };
        let far = Instant::now() + Duration::from_secs(30);

        scan_root(&mut store, "agy", &root, "*.db", &ex, far);
        fs::write(
            root.join("conv.db-wal"),
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        scan_root(&mut store, "agy", &root, "*.db", &ex, far);
        assert_eq!(ex.calls.load(Ordering::SeqCst), 2);
        // Same length, different bytes — the sig must still move.
        fs::write(
            root.join("conv.db-wal"),
            b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();
        scan_root(&mut store, "agy", &root, "*.db", &ex, far);
        assert_eq!(ex.calls.load(Ordering::SeqCst), 3);
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&dir);
    }
}
