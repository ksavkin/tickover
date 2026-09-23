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

use std::collections::BTreeMap;
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
                if rewritten {
                    // The digest stored with the reset must cover the
                    // *new* span — the one just compared was over the
                    // old file's prefix.
                    let new_span = sig.size.min(crate::history::store::PREFIX_BYTES as u64);
                    let fresh_digest =
                        HistoryStore::prefix_digest(&sig.path, new_span).unwrap_or_default();
                    // The file's global-ring ownership dies with the old
                    // generation — otherwise pass 2+ of a large rescan
                    // (resume_from > 0) would skip every re-derived record
                    // as a "ring-evicted repeat".
                    store.release_owned(&key);
                    if let Some(st) = store.file_state_mut(&sig.path) {
                        st.reset(fresh_digest, sig.size, sig.mtime);
                    }
                } else if let Some(st) = store.file_state_mut(&sig.path) {
                    st.size = sig.size;
                    st.mtime = sig.mtime;
                }
            }
            None => {
                let span = (sig.size).min(crate::history::store::PREFIX_BYTES as u64);
                let digest = HistoryStore::prefix_digest(&sig.path, span).unwrap_or_default();
                store.begin_file(&sig.path, provider, digest, sig.size, sig.mtime);
            }
        }

        // `min(sig.size)`: a cursor past EOF means the file shrank without
        // tripping the rewrite detector — clamping keeps the pass honest
        // (the seal must never claim bytes that aren't there).
        let resume_from = store
            .file_state(&sig.path)
            .map_or(0, |s| s.cursor.min(sig.size));
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
        let mut seen_keys: Vec<(String, [u64; 5])> = Vec::new();
        let mut global_keys: Vec<String> = Vec::new();
        // Skipped repeats that still prove an id is live — applied as LRU
        // touches after the append succeeds, so an actively re-emitted id
        // can't be evicted while the provider is still writing it.
        let mut touches: Vec<String> = Vec::new();
        // Last usage per dedup key this pass — a repeat inside the same
        // pass diffs against the newest observation, not the first.
        let mut pass_usage: std::collections::HashMap<String, [u64; 5]> =
            std::collections::HashMap::new();
        // Byte range for JSONL; a row-watermark span for SQLite — whatever
        // the extractor reports is what supersession compares.
        let (range_lo, range_hi) = extraction.range.unwrap_or((resume_from, extraction.cursor));
        // A pass that reached the end of its source seals coverage: the
        // cursor/watermark only ever advances past bytes that were
        // appended, so `complete` means every line of this file's bucket —
        // this one plus the live prefix chain — re-derives the whole
        // file. A cap- or deadline-truncated pass re-derived a prefix and
        // must not claim coverage it hasn't emitted.
        let full = extraction.complete;
        // Whether the source carried any records at all — an empty
        // *extraction* can seal stale coverage via a tombstone, but an
        // extraction whose records were all deduped must not: their
        // tokens already live in the lines the seal would kill.
        let source_empty = extraction.records.is_empty();
        for mut rec in extraction.records {
            if rec.provider.is_empty() {
                rec.provider = provider.to_string();
            }
            let usage = [
                rec.input,
                rec.output,
                rec.cache_read,
                rec.cache_write,
                rec.thinking,
            ];
            // Whether this record is a re-emission of an already-counted
            // event: its tokens still fold, but it must not add a second
            // message to the bucket.
            let mut is_update = false;
            // Dedup keys are globally meaningful (message ids, turn ids) —
            // checked against this pass's map, the file's persisted ring,
            // *and* the store-wide ring: the same record surfacing in a
            // second file on a later pass (Grok's unified log + session
            // updates overlap exactly that way) is still caught.
            if !rec.dedup_key.is_empty() {
                let prior = pass_usage.get(&rec.dedup_key).copied().or_else(|| {
                    store
                        .file_state(&sig.path)
                        .and_then(|st| st.last_usage(&rec.dedup_key))
                });
                if let Some(old) = prior {
                    // Re-emission of an already-counted event (Claude
                    // streams a message's usage as it grows): count only
                    // the growth. The baseline is the componentwise
                    // high-water mark, not the newest observation — a
                    // regressed reading must not lower it, or the next
                    // partial recovery would emit phantom growth.
                    let delta = [
                        rec.input.saturating_sub(old[0]),
                        rec.output.saturating_sub(old[1]),
                        rec.cache_read.saturating_sub(old[2]),
                        rec.cache_write.saturating_sub(old[3]),
                        rec.thinking.saturating_sub(old[4]),
                    ];
                    let high_water = [
                        old[0].max(rec.input),
                        old[1].max(rec.output),
                        old[2].max(rec.cache_read),
                        old[3].max(rec.cache_write),
                        old[4].max(rec.thinking),
                    ];
                    pass_usage.insert(rec.dedup_key.clone(), high_water);
                    if delta.iter().all(|&d| d == 0) {
                        touches.push(rec.dedup_key.clone());
                        continue;
                    }
                    rec.input = delta[0];
                    rec.output = delta[1];
                    rec.cache_read = delta[2];
                    rec.cache_write = delta[3];
                    rec.thinking = delta[4];
                    is_update = true;
                    seen_keys.push((rec.dedup_key.clone(), high_water));
                } else {
                    // Seen before but the ring holds no usage for it
                    // (pre-field entry or an evicted baseline), or first
                    // seen by a *different* file — a true duplicate either
                    // way. No `pass_usage` insert: the baseline is
                    // unknown, so a later repeat in this pass must skip
                    // again rather than emit a delta priced off this
                    // record. The self-owned exception: a key this file
                    // owns globally but whose ring entry aged out reads as
                    // "re-emission mid-stream" only when the pass resumed
                    // mid-file — a from-origin pass is a rewrite/state-loss
                    // rescan, where the same keys must count again.
                    let ring_evicted_self =
                        resume_from > 0 && store.owns_globally(&key, &rec.dedup_key);
                    if store
                        .file_state(&sig.path)
                        .is_some_and(|st| st.seen(&rec.dedup_key))
                        || store.seen_globally(&key, &rec.dedup_key)
                        || ring_evicted_self
                    {
                        touches.push(rec.dedup_key.clone());
                        continue;
                    }
                    pass_usage.insert(rec.dedup_key.clone(), usage);
                    global_keys.push(rec.dedup_key.clone());
                    seen_keys.push((rec.dedup_key.clone(), usage));
                }
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
                full,
                b: 0, // `append_days` stamps the real batch id
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
            if !is_update {
                bucket.messages += 1;
            }
            outcome.records += 1;
        }
        buckets.extend(grouped.into_values());
        if source_empty && full {
            // A complete pass over a source with *no records* still owns
            // the coverage claim — without a carrier line the seal never
            // fires and stale lines of this (file, gen) sum forever.
            // The tombstone's own range tiles the prefix chain the same
            // way a bucket line would, so live coverage survives it.
            buckets.push(DayLine {
                v: crate::history::store::SCHEMA_VERSION,
                hour: chrono::Utc::now().format("%Y-%m-%dT%H").to_string(),
                provider: provider.to_string(),
                project: String::new(),
                model: String::new(),
                session: String::new(),
                file: key.clone(),
                gen,
                lo: range_lo,
                hi: range_hi,
                full: true,
                b: 0,
                input: 0,
                output: 0,
                cache_read: 0,
                cache_write: 0,
                thinking: 0,
                messages: 0,
            });
        }
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
            for (k, usage) in &seen_keys {
                st.mark_seen(k.clone(), *usage);
            }
            for k in &touches {
                st.touch(k);
            }
        }
        for k in global_keys {
            store.mark_seen_globally(&key, k);
        }
        for k in &touches {
            store.touch_globally(k);
        }
    }
    outcome
}

/// `(size, mtime-nanos, edge-mix)` of a SQLite `<file>-wal` sibling —
/// `(0, 0, 0)` when no WAL exists, which is also the signature an
/// extractor stores for one. Nanosecond resolution matters: a passive
/// checkpoint can leave the WAL the same size and let the next write land
/// within the same second — a seconds-granular sig would call that
/// "unchanged" and skip live rows. The edge mix covers the residual hole
/// (same size *and* same mtime): the 32-byte header's salts change on
/// every checkpoint reset, and the trailing bytes move with any appended
/// or rewritten frame, so mixing both edges catches what stat cannot.
fn wal_sig(path: &Path) -> (u64, u64, u64) {
    // OsString append — `path.display()` would corrupt non-UTF8 names.
    let mut wal_os = path.as_os_str().to_os_string();
    wal_os.push("-wal");
    let wal = PathBuf::from(wal_os);
    fs::metadata(&wal)
        .ok()
        .map(|m| {
            let edge_mix = fs::File::open(&wal)
                .ok()
                .map(|mut f| {
                    use std::io::{Read as _, Seek as _, SeekFrom};
                    let mut edges = Vec::with_capacity(64);
                    let mut head = [0u8; 32];
                    let n = f.read(&mut head).unwrap_or(0);
                    edges.extend_from_slice(&head[..n]);
                    let len = m.len();
                    if len > 32 {
                        let mut tail = [0u8; 32];
                        let start = len.saturating_sub(32);
                        if f.seek(SeekFrom::Start(start)).is_ok() {
                            let n = f.read(&mut tail).unwrap_or(0);
                            edges.extend_from_slice(&tail[..n]);
                        }
                    }
                    use blake2::Digest as _;
                    let h = blake2::Blake2b512::digest(&edges);
                    u64::from_le_bytes(h[..8].try_into().unwrap())
                })
                .unwrap_or(0);
            (
                m.len(),
                m.modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_nanos() as u64),
                edge_mix,
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
    use crate::history::UsageRecord;
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

    /// A Claude transcript line: `id`, `input`, `output` are the knobs
    /// the delta tests turn.
    fn claude_line(id: &str, input: u64, output: u64) -> String {
        format!(
            r#"{{"type":"assistant","isSidechain":false,"sessionId":"s1","cwd":"/u/proj","timestamp":"2026-09-22T14:30:00.000Z","message":{{"id":"{id}","model":"m","usage":{{"input_tokens":{input},"output_tokens":{output}}}}}}}"#
        )
    }

    #[test]
    fn a_reemitted_id_reports_only_its_growth() {
        // Claude streams a message's usage under one message.id: the
        // persisted ring must emit the *delta* of the later re-emission,
        // not drop it (first-wins) and not re-count it (naive).
        let root = tmpdir("delta-root");
        let dir = tmpdir("delta-store");
        fs::write(root.join("t.jsonl"), claude_line("m1", 100, 10) + "\n").unwrap();
        let mut store = HistoryStore::open(&dir).unwrap();
        let ex = crate::history::formats::claude::ClaudeExtractor;
        let far = Instant::now() + Duration::from_secs(30);

        scan_root(&mut store, "claude", &root, "*.jsonl", &ex, far);
        store.commit().unwrap();
        // The stream continues: same id, output grew 10 -> 25.
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(root.join("t.jsonl"))
            .unwrap();
        use std::io::Write as _;
        writeln!(f, "{}", claude_line("m1", 100, 25)).unwrap();
        drop(f);
        scan_root(&mut store, "claude", &root, "*.jsonl", &ex, far);
        store.commit().unwrap();

        let live: Vec<_> = store.live_days().cloned().collect();
        let total_out: u64 = live.iter().map(|d| d.output).sum();
        let total_in: u64 = live.iter().map(|d| d.input).sum();
        let total_msgs: u32 = live.iter().map(|d| d.messages).sum();
        assert_eq!(total_out, 25, "the final observation wins");
        assert_eq!(total_in, 100, "input did not grow — no delta");
        assert_eq!(total_msgs, 1, "a re-emission is not a second message");
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

    #[test]
    fn a_regressed_reemission_does_not_lower_the_baseline() {
        // Claude re-emits usage as it streams; a provider hiccup can send
        // a *smaller* snapshot. If that lowered the baseline, the next
        // partial recovery would emit phantom growth — so the baseline
        // must track the componentwise high-water mark.
        let root = tmpdir("regress-root");
        let dir = tmpdir("regress-store");
        fs::write(root.join("t.jsonl"), claude_line("m1", 100, 30) + "\n").unwrap();
        let mut store = HistoryStore::open(&dir).unwrap();
        let ex = crate::history::formats::claude::ClaudeExtractor;
        let far = Instant::now() + Duration::from_secs(30);
        scan_root(&mut store, "claude", &root, "*.jsonl", &ex, far);
        store.commit().unwrap();

        // The stream regresses to (100,20) then partially recovers to
        // (100,25): both are below the high-water output of 30, so
        // neither may emit.
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(root.join("t.jsonl"))
            .unwrap();
        use std::io::Write as _;
        writeln!(f, "{}", claude_line("m1", 100, 20)).unwrap();
        writeln!(f, "{}", claude_line("m1", 100, 25)).unwrap();
        drop(f);
        scan_root(&mut store, "claude", &root, "*.jsonl", &ex, far);
        store.commit().unwrap();
        let total_out: u64 = store.live_days().map(|d| d.output).sum();
        assert_eq!(total_out, 30, "regressed snapshots emit no growth");

        // Genuine growth past the high-water mark still counts.
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(root.join("t.jsonl"))
            .unwrap();
        writeln!(f, "{}", claude_line("m1", 100, 40)).unwrap();
        drop(f);
        scan_root(&mut store, "claude", &root, "*.jsonl", &ex, far);
        store.commit().unwrap();
        let total_out: u64 = store.live_days().map(|d| d.output).sum();
        assert_eq!(total_out, 40, "growth past the high-water mark counts");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_key_shared_across_files_counts_once_and_stays_owned() {
        // Grok's unified log and the session file carry the same turn;
        // whichever file emits first owns the key globally. The second
        // file's sightings — including grown ones — are duplicates of the
        // owner's event, not new usage: they must skip outright and never
        // acquire a baseline to delta from.
        let root = tmpdir("xfile-root");
        let dir = tmpdir("xfile-store");
        fs::write(root.join("a.jsonl"), claude_line("m1", 100, 10) + "\n").unwrap();
        fs::write(root.join("b.jsonl"), claude_line("m1", 100, 10) + "\n").unwrap();
        let mut store = HistoryStore::open(&dir).unwrap();
        let ex = crate::history::formats::claude::ClaudeExtractor;
        let far = Instant::now() + Duration::from_secs(30);
        scan_root(&mut store, "claude", &root, "*.jsonl", &ex, far);
        store.commit().unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            100,
            "one event, one count"
        );

        // The stream keeps updating under the same id in *both* files:
        // only the owner's delta may land.
        for name in ["a.jsonl", "b.jsonl"] {
            let mut f = fs::OpenOptions::new()
                .append(true)
                .open(root.join(name))
                .unwrap();
            use std::io::Write as _;
            writeln!(f, "{}", claude_line("m1", 100, 40)).unwrap();
        }
        scan_root(&mut store, "claude", &root, "*.jsonl", &ex, far);
        store.commit().unwrap();
        let live: Vec<_> = store.live_days().cloned().collect();
        assert_eq!(
            live.iter().map(|d| d.output).sum::<u64>(),
            40,
            "the growth is counted once, by the owner"
        );
        assert_eq!(live.iter().map(|d| d.messages).sum::<u32>(), 1);
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_append_retries_the_file_in_full() {
        // If `days.jsonl` can't be written, nothing may move: cursor,
        // dedup rings and the global ring all gate the retry — a mark
        // that survived a failed append would eat the re-emission.
        let root = tmpdir("fail-root");
        let dir = tmpdir("fail-store");
        fs::write(root.join("t.jsonl"), claude_line("m1", 100, 10) + "\n").unwrap();
        let mut store = HistoryStore::open(&dir).unwrap();
        let ex = crate::history::formats::claude::ClaudeExtractor;
        let far = Instant::now() + Duration::from_secs(30);

        // Poison the sink: a directory where the file must be.
        fs::create_dir(dir.join("days.jsonl")).unwrap();
        scan_root(&mut store, "claude", &root, "*.jsonl", &ex, far);
        let key = root.join("t.jsonl").to_string_lossy().into_owned();
        let st = store.file_state(Path::new(&key)).unwrap();
        assert_eq!(st.cursor, 0, "a failed append must not move the cursor");
        assert!(!st.seen("m1"), "the ring must not mark a lost record");

        fs::remove_dir(dir.join("days.jsonl")).unwrap();
        scan_root(&mut store, "claude", &root, "*.jsonl", &ex, far);
        store.commit().unwrap();
        let live: Vec<_> = store.live_days().cloned().collect();
        assert_eq!(live.iter().map(|d| d.input).sum::<u64>(), 100);
        assert_eq!(live.iter().map(|d| d.messages).sum::<u32>(), 1);
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A scripted extractor that plays the multi-pass rewrite rescan:
    /// gen 0 emits `shared` and completes; after the rewrite the new
    /// generation's first pass stops mid-file and its finishing pass
    /// re-derives `shared` — a key the *old* generation still owned
    /// globally until `release_owned` ran.
    struct RescanStub {
        calls: AtomicUsize,
    }
    impl HistoryExtractor for RescanStub {
        fn extract(
            &self,
            _path: &Path,
            st: &mut FileState,
            _byte_cap: u64,
            _deadline: Instant,
        ) -> io::Result<Extraction> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            let rec = |key: &str, input: u64| UsageRecord {
                ts: chrono::Utc::now(),
                provider: String::new(),
                project: "p".into(),
                session_id: "s".into(),
                model: "m".into(),
                input,
                output: 0,
                cache_read: 0,
                cache_write: 0,
                thinking: 0,
                dedup_key: key.into(),
            };
            let mid = st.size / 2;
            Ok(match n {
                0 => Extraction {
                    records: vec![rec("shared", 10)],
                    cursor: st.size,
                    complete: true,
                    ..Default::default()
                },
                1 => Extraction {
                    records: vec![rec("fresh", 5)],
                    cursor: mid,
                    range: Some((0, mid)),
                    complete: false,
                    ..Default::default()
                },
                _ => Extraction {
                    records: vec![rec("shared", 20)],
                    cursor: st.size,
                    range: Some((mid, st.size)),
                    complete: true,
                    ..Default::default()
                },
            })
        }
    }

    #[test]
    fn a_rewrites_later_passes_are_not_ring_evicted_self() {
        // A rewritten file rescans from origin, but a large rescan spans
        // passes: pass 2+ resumes with `resume_from > 0`, where a key the
        // *old* generation still owned globally would read as a
        // ring-evicted repeat and be eaten. `release_owned` on reset must
        // let the rescan re-own its keys.
        let root = tmpdir("rescan-root");
        let dir = tmpdir("rescan-store");
        fs::write(root.join("t.jsonl"), "first generation bytes").unwrap();
        let mut store = HistoryStore::open(&dir).unwrap();
        let ex = RescanStub {
            calls: AtomicUsize::new(0),
        };
        let far = Instant::now() + Duration::from_secs(30);

        scan_root(&mut store, "p", &root, "*.jsonl", &ex, far);
        store.commit().unwrap();
        assert_eq!(store.live_days().map(|d| d.input).sum::<u64>(), 10);

        // Rewrite: new bytes, new generation.
        fs::write(root.join("t.jsonl"), "second generation bytes, different").unwrap();
        scan_root(&mut store, "p", &root, "*.jsonl", &ex, far); // truncated pass 1
        scan_root(&mut store, "p", &root, "*.jsonl", &ex, far); // completing pass 2
        store.commit().unwrap();
        let live: Vec<_> = store.live_days().cloned().collect();
        assert_eq!(
            live.iter().map(|d| d.input).sum::<u64>(),
            25,
            "gen 1 = 5 (fresh) + 20 (re-derived shared); gen 0 filtered"
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_torn_tail_at_eof_does_not_seal() {
        // A writer mid-line at EOF leaves bytes past the last newline:
        // the pass didn't consume the file's content, so its line must
        // not carry `full` — the seal would kill coverage the pass never
        // produced.
        let root = tmpdir("torn-root");
        let dir = tmpdir("torn-store");
        let first = claude_line("m1", 100, 10);
        let second = claude_line("m2", 200, 20);
        // `second` is deliberately missing its newline — a torn tail.
        fs::write(root.join("t.jsonl"), format!("{first}\n{second}")).unwrap();
        let mut store = HistoryStore::open(&dir).unwrap();
        let ex = crate::history::formats::claude::ClaudeExtractor;
        let far = Instant::now() + Duration::from_secs(30);

        scan_root(&mut store, "claude", &root, "*.jsonl", &ex, far);
        store.commit().unwrap();
        let live: Vec<_> = store.live_days().cloned().collect();
        assert_eq!(live.iter().map(|d| d.input).sum::<u64>(), 100);
        assert!(
            live.iter().all(|d| !d.full),
            "a torn tail must not seal coverage"
        );

        // The writer finishes the line: the next pass reads it and seals.
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(root.join("t.jsonl"))
            .unwrap();
        use std::io::Write as _;
        writeln!(f).unwrap();
        drop(f);
        scan_root(&mut store, "claude", &root, "*.jsonl", &ex, far);
        store.commit().unwrap();
        let live: Vec<_> = store.live_days().cloned().collect();
        assert_eq!(live.iter().map(|d| d.input).sum::<u64>(), 300);
        assert!(live.iter().any(|d| d.full));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&dir);
    }
}
