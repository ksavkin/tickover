//! Persistent history state: per-file scan cursors plus the append-only
//! bucket log everything aggregates from.
//!
//! Two files under `<config>/tickover/history/`, both owned by this app —
//! the provider's own directories are never written to:
//!
//! * `state.json` — [`ScannerState`]: a map of scanned file → [`FileState`]
//!   (size, mtime, cursor, prefix digest, generation, dedup ring). Rewritten
//!   atomically (tmp + rename) like `config.rs` does; a corrupt one is
//!   quarantined aside and rebuilt from a full rescan rather than trusted.
//! * `days.jsonl` — append-only [`DayLine`] records, one per
//!   (hour, provider, project, model, session, file generation). Never
//!   edited in place: a file that was rewritten gets a new `gen`, and its
//!   older lines stop counting at query time instead of being deleted.
//!   When stale lines outweigh live ones the log is compacted once.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Current on-disk schema. Bump when a field's meaning changes; an older
/// `state.json` that fails to parse is quarantined and rebuilt — a rescan
/// is always the correct recovery because day lines are only ever additive.
pub const SCHEMA_VERSION: u32 = 1;

/// How many dedup keys one file remembers between scans. The ring exists
/// for the tail-overlap case (a file rewritten since its last scan, or the
/// same record re-read after a reset), not for whole-history dedup —
/// extractors dedup *within* a pass themselves.
const RECENT_IDS_PER_FILE: usize = 512;

/// First bytes of a file hashed into [`FileState::digest`] — enough to
/// catch a rewrite that keeps size/mtime plausible (Claude transcripts and
/// Codex rollouts both start with a header line naming their own ids).
const PREFIX_BYTES: usize = 4096;

/// Rewrite `days.jsonl` once it passes this size — a lazy bound so a
/// provider that rewrites its history constantly cannot grow the log
/// without limit. Live lines are kept; stale-generation lines drop out.
const DAYS_COMPACT_BYTES: u64 = 16 * 1024 * 1024;

/// One file's scan progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileState {
    /// Byte size at last scan, from `stat`.
    pub size: u64,
    /// Modification time at last scan, seconds since the epoch.
    pub mtime: i64,
    /// How far this file has been consumed. The meaning belongs to the
    /// format: a byte offset past the last complete line for JSONL, a
    /// timestamp watermark (ms) for SQLite — either way it only ever moves
    /// forward within one `gen`.
    pub cursor: u64,
    /// blake2b hex of the first [`PREFIX_BYTES`], recomputed when `mtime`
    /// moves — a changed prefix means the file was rewritten, not appended.
    pub digest: String,
    /// Incremented on every reset; [`DayLine::gen`] lines from an older
    /// generation stop counting the moment this bumps.
    pub gen: u32,
    /// Bounded ring of recently seen dedup keys, oldest first.
    pub recent_ids: VecDeque<String>,
    /// Lines that looked like usage but did not parse, cumulative for this
    /// file's current generation — the format-drift signal `stats` shows.
    #[serde(default)]
    pub skipped_unparsed: u64,
    /// Format-specific extractor state that must survive between passes —
    /// e.g. Codex's cumulative `total_token_usage` baseline when a file's
    /// events lack `last_token_usage` and deltas have to be diffed. Opaque
    /// to the store; owned entirely by the extractor.
    #[serde(default)]
    pub aux: BTreeMap<String, u64>,
}

impl FileState {
    /// A file seen for the first time — nothing consumed, generation 0.
    pub fn fresh(digest: String, size: u64, mtime: i64) -> Self {
        FileState {
            size,
            mtime,
            cursor: 0,
            digest,
            gen: 0,
            recent_ids: VecDeque::new(),
            skipped_unparsed: 0,
            aux: BTreeMap::new(),
        }
    }

    /// Start a new generation: the file was rewritten, so everything
    /// extracted under the old cursor is suspect — older day lines stop
    /// counting (their `gen` no longer matches) and dedup starts empty.
    pub fn reset(&mut self, digest: String, size: u64, mtime: i64) {
        self.size = size;
        self.mtime = mtime;
        self.cursor = 0;
        self.digest = digest;
        self.gen += 1;
        self.recent_ids.clear();
        self.skipped_unparsed = 0;
        self.aux.clear();
    }

    /// Whether `id` is still in the ring.
    pub fn seen(&self, id: &str) -> bool {
        self.recent_ids.iter().any(|k| k == id)
    }

    /// Record `id`, evicting the oldest once the ring is full.
    pub fn mark_seen(&mut self, id: String) {
        if self.recent_ids.len() >= RECENT_IDS_PER_FILE {
            self.recent_ids.pop_front();
        }
        self.recent_ids.push_back(id);
    }
}

/// All remembered file positions. `BTreeMap` so `state.json` diffs read in
/// path order and two runs write byte-identical files for identical input.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ScannerState {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub files: BTreeMap<String, FileState>,
}

/// One aggregate line in `days.jsonl`. This is the *only* thing history
/// persists from a transcript: counts and names, never content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DayLine {
    /// Schema marker, same value as [`SCHEMA_VERSION`].
    pub v: u32,
    /// UTC hour this bucket covers, `"YYYY-MM-DDTHH"` — local-day grouping
    /// is a query-time concern (`chrono::Local`), so DST needs nothing here.
    pub hour: String,
    pub provider: String,
    /// Project basename only — never a full path.
    pub project: String,
    pub model: String,
    /// Session/conversation id — for per-session views and streaks.
    pub session: String,
    /// Which file produced this bucket, paired with `gen` so a rewritten
    /// file's older contributions are identifiable as stale.
    pub file: String,
    pub gen: u32,
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub thinking: u64,
    /// Records folded into this bucket (request/turn count).
    pub messages: u32,
}

impl DayLine {
    /// Total tokens across every class in this bucket.
    pub fn sum(&self) -> u64 {
        self.input + self.output + self.cache_read + self.cache_write + self.thinking
    }
}

/// The pair of files plus the in-memory state between them.
pub struct HistoryStore {
    dir: PathBuf,
    pub state: ScannerState,
    /// Lines read from `days.jsonl` at open — kept so a compacting rewrite
    /// doesn't have to re-parse what was already validated once.
    days: Vec<DayLine>,
}

impl HistoryStore {
    pub fn state_path(dir: &Path) -> PathBuf {
        dir.join("state.json")
    }
    pub fn days_path(dir: &Path) -> PathBuf {
        dir.join("days.jsonl")
    }

    /// Open (or create) the store under `dir`. A missing directory is made;
    /// a corrupt `state.json` is moved aside to `state.corrupt-<secs>.json`
    /// and rebuilt empty — the next scan repopulates it from scratch.
    /// `days.jsonl` lines that fail to parse are dropped on the floor of
    /// the load loop rather than failing the store: they are our own cache,
    /// and a torn append is survivable.
    pub fn open(dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let state = match fs::read_to_string(Self::state_path(dir)) {
            Ok(text) => match serde_json::from_str::<ScannerState>(&text) {
                Ok(s) if s.version == SCHEMA_VERSION => s,
                _ => {
                    let aside = dir.join(format!(
                        "state.corrupt-{}.json",
                        chrono::Utc::now().timestamp()
                    ));
                    let _ = fs::rename(Self::state_path(dir), aside);
                    ScannerState::default()
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => ScannerState::default(),
            Err(e) => return Err(e),
        };
        let mut days = Vec::new();
        let mut seen_lines: std::collections::HashSet<String> = std::collections::HashSet::new();
        match fs::read_to_string(Self::days_path(dir)) {
            Ok(text) => {
                for line in text.lines() {
                    // Exact-duplicate lines are the rescan artifact a crash
                    // between `append_days` and `commit` leaves behind: the
                    // bytes were appended, the cursor never moved, and the
                    // next scan re-produces the same aggregate. Two *real*
                    // events cannot land in the same bucket with identical
                    // counts across every class without being the same
                    // parse twice — so dropping the duplicate line is the
                    // crash-consistency rule, not a data-losing shortcut.
                    if !seen_lines.insert(line.to_string()) {
                        continue;
                    }
                    if let Ok(d) = serde_json::from_str::<DayLine>(line) {
                        if d.v == SCHEMA_VERSION {
                            days.push(d);
                        }
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(HistoryStore {
            dir: dir.to_path_buf(),
            state,
            days,
        })
    }

    /// This file's remembered progress, if it was ever scanned.
    pub fn file_state(&self, path: &Path) -> Option<&FileState> {
        self.state.files.get(&path.to_string_lossy().into_owned())
    }

    /// This file's remembered progress, mutably — for cursor and ring
    /// updates after a successful extract.
    pub fn file_state_mut(&mut self, path: &Path) -> Option<&mut FileState> {
        self.state
            .files
            .get_mut(&path.to_string_lossy().into_owned())
    }

    /// Register `path` at generation 0 (or return the existing entry).
    pub fn begin_file(&mut self, path: &Path, digest: String, size: u64, mtime: i64) {
        self.state
            .files
            .entry(path.to_string_lossy().into_owned())
            .or_insert_with(|| FileState::fresh(digest, size, mtime));
    }

    /// Append finished buckets to `days.jsonl` — the only write the log
    /// ever takes between compactions.
    pub fn append_days(&mut self, new: &[DayLine]) -> io::Result<()> {
        if new.is_empty() {
            return Ok(());
        }
        let path = Self::days_path(&self.dir);
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let mut buf = Vec::new();
        for d in new {
            serde_json::to_writer(&mut buf, d).map_err(io::Error::other)?;
            buf.push(b'\n');
        }
        f.write_all(&buf)?;
        f.sync_data().ok();
        self.days.extend(new.iter().cloned());
        Ok(())
    }

    /// Persist `state.json` atomically (tmp + rename), then compact
    /// `days.jsonl` if it has grown past [`DAYS_COMPACT_BYTES`].
    pub fn commit(&mut self) -> io::Result<()> {
        self.state.version = SCHEMA_VERSION;
        let tmp = self.dir.join("state.json.tmp");
        let target = Self::state_path(&self.dir);
        {
            let mut f = fs::File::create(&tmp)?;
            serde_json::to_writer(&mut f, &self.state).map_err(io::Error::other)?;
            f.write_all(b"\n")?;
            f.sync_data().ok();
        }
        fs::rename(&tmp, &target)?;
        self.maybe_compact_days()
    }

    /// Day lines that still count: a line is stale only when its file is
    /// still tracked at a *newer* generation. Lines from a file that has
    /// since been deleted keep counting — the usage happened; the provider
    /// removing its log does not un-spend the tokens.
    pub fn live_days(&self) -> impl Iterator<Item = &DayLine> {
        let current: HashMap<&str, u32> = self
            .state
            .files
            .iter()
            .map(|(p, s)| (p.as_str(), s.gen))
            .collect();
        self.days
            .iter()
            .filter(move |d| current.get(d.file.as_str()).is_none_or(|&gen| gen == d.gen))
    }

    /// Rewrite `days.jsonl` dropping stale-generation lines, when it is big
    /// enough for the dropped share to be worth one rewrite.
    fn maybe_compact_days(&mut self) -> io::Result<()> {
        let path = Self::days_path(&self.dir);
        let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if size < DAYS_COMPACT_BYTES {
            return Ok(());
        }
        let live: Vec<&DayLine> = self.live_days().collect();
        if live.len() == self.days.len() {
            return Ok(());
        }
        let tmp = self.dir.join("days.jsonl.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            let mut buf = Vec::new();
            for d in &live {
                serde_json::to_writer(&mut buf, *d).map_err(io::Error::other)?;
                buf.push(b'\n');
            }
            f.write_all(&buf)?;
            f.sync_data().ok();
        }
        fs::rename(&tmp, &path)?;
        self.days = live.into_iter().cloned().collect();
        Ok(())
    }

    /// blake2b hex of a file's first [`PREFIX_BYTES`] — the rewrite signal
    /// `mtime`/`size` alone can miss when a provider rewrites in place.
    pub fn prefix_digest(path: &Path) -> Option<String> {
        use blake2::Digest as _;
        use std::io::Read;
        let mut f = fs::File::open(path).ok()?;
        let mut buf = vec![0u8; PREFIX_BYTES];
        let n = f.read(&mut buf).ok()?;
        buf.truncate(n);
        Some(hex_prefix(&blake2::Blake2b512::digest(&buf)))
    }
}

/// First 16 hex chars of a blake2b-512 digest — collision room is absurd
/// for a file-identity check, and a short string keeps `state.json` small.
fn hex_prefix(digest: &[u8]) -> String {
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tickover-history-test-{}-{}",
            tag,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn day(file: &str, gen: u32, input: u64) -> DayLine {
        DayLine {
            v: SCHEMA_VERSION,
            hour: "2026-09-22T14".to_string(),
            provider: "claude".to_string(),
            project: "proj".to_string(),
            model: "m".to_string(),
            session: "s".to_string(),
            file: file.to_string(),
            gen,
            input,
            output: 0,
            cache_read: 0,
            cache_write: 0,
            thinking: 0,
            messages: 1,
        }
    }

    #[test]
    fn corrupt_state_is_quarantined_and_rebuilt() {
        let dir = tmpdir("corrupt");
        fs::write(dir.join("state.json"), "{not json").unwrap();
        let store = HistoryStore::open(&dir).unwrap();
        assert!(store.state.files.is_empty());
        let quarantined = fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).any(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("state.corrupt-")
        });
        assert!(quarantined, "corrupt state.json must be set aside");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn days_round_trip_and_stale_gens_drop_out() {
        let dir = tmpdir("days");
        let mut store = HistoryStore::open(&dir).unwrap();
        store
            .append_days(&[day("/f", 0, 10), day("/f", 0, 20)])
            .unwrap();
        store
            .state
            .files
            .insert("/f".to_string(), FileState::fresh("d".into(), 1, 1));
        store.commit().unwrap();

        let mut store = HistoryStore::open(&dir).unwrap();
        assert_eq!(store.live_days().count(), 2);
        // Rewrite: gen bumps, older contributions stop counting.
        store
            .file_state_mut(Path::new("/f"))
            .unwrap()
            .reset("d2".into(), 2, 2);
        assert_eq!(store.live_days().map(|d| d.input).sum::<u64>(), 0);
        store.append_days(&[day("/f", 1, 7)]).unwrap();
        assert_eq!(store.live_days().map(|d| d.input).sum::<u64>(), 7);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn lines_from_a_deleted_file_keep_counting() {
        let dir = tmpdir("deleted");
        let mut store = HistoryStore::open(&dir).unwrap();
        store.append_days(&[day("/gone", 0, 5)]).unwrap();
        // Provider removed its history file; nothing re-registers it.
        assert_eq!(store.live_days().map(|d| d.input).sum::<u64>(), 5);
        let _ = fs::remove_dir_all(&dir);
    }
}
