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
//!   Known narrow gap: a crash between an append and the commit *plus* a
//!   file-order change on retry can leave one cross-file duplicate counted
//!   twice — the committed day line carries no dedup key to recognize its
//!   twin by. Day lines stay aggregates; the residual is one event, not a
//!   class of them.
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
pub const SCHEMA_VERSION: u32 = 2;

/// How many dedup keys one file remembers between scans. The ring exists
/// for the tail-overlap case (a file rewritten since its last scan, or the
/// same record re-read after a reset), not for whole-history dedup —
/// extractors dedup *within* a pass themselves.
const RECENT_IDS_PER_FILE: usize = 512;

/// How many dedup keys the store remembers across files — larger than the
/// per-file ring because it is the only guard against a record arriving
/// via a second file on a later pass.
const GLOBAL_RECENT_IDS: usize = 8192;

/// `serde` default for `digest_len` on state written before the field
/// existed — those digests covered `min(PREFIX_BYTES, size)`, and the
/// `.min(st.size)` at compare time restores the same span.
fn default_digest_len() -> u64 {
    PREFIX_BYTES as u64
}

/// First bytes of a file hashed into [`FileState::digest`] — enough to
/// catch a rewrite that keeps size/mtime plausible (Claude transcripts and
/// Codex rollouts both start with a header line naming their own ids).
pub(crate) const PREFIX_BYTES: usize = 4096;

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
    /// blake2b hex of the file's first [`Self::digest_len`] bytes,
    /// recomputed when `mtime` moves — a changed prefix means the file was
    /// rewritten, not appended.
    pub digest: String,
    /// How many bytes `digest` covers: `min(PREFIX_BYTES, size)` at the
    /// time the digest was taken. For a file smaller than [`PREFIX_BYTES`]
    /// this is the whole file, and it is what lets an *append* to such a
    /// file still verify as append — comparing a fixed 4 KiB prefix would
    /// re-digest the newly grown tail and look like a rewrite every pass.
    #[serde(default = "default_digest_len")]
    pub digest_len: u64,
    /// Incremented on every reset; [`DayLine::gen`] lines from an older
    /// generation stop counting the moment this bumps.
    pub gen: u32,
    /// Bounded ring of recently seen dedup keys, oldest first — persisted
    /// across commits: providers legitimately re-log an id at a later
    /// offset (Claude rewrites an assistant message as it streams), and
    /// the ring is what tells that repeat from a new event next pass.
    pub recent_ids: VecDeque<String>,
    /// Membership mirror of `recent_ids` — checked per record, so O(1).
    /// Rebuilt from `recent_ids` at store open.
    #[serde(skip)]
    recent_set: std::collections::HashSet<String>,
    /// Lines that looked like usage but did not parse, cumulative for this
    /// file's current generation — the format-drift signal `stats` shows.
    #[serde(default)]
    pub skipped_unparsed: u64,
    /// The provider manifest that owns this file's root — lets queries
    /// attribute drift counts (and any per-file figure) to a provider so a
    /// disabled one drops out of every total.
    #[serde(default)]
    pub provider: String,
    /// Format-specific extractor state that must survive between passes —
    /// e.g. Codex's cumulative `total_token_usage` baseline when a file's
    /// events lack `last_token_usage`, or the session-attribution map Grok
    /// needs once the `session created` lines are behind the cursor.
    /// `serde_json::Value` rather than a narrower shape: what a format
    /// needs remembered is the format's business. Opaque to the store;
    /// owned entirely by the extractor.
    #[serde(default)]
    pub aux: BTreeMap<String, serde_json::Value>,
}

impl FileState {
    /// A file seen for the first time — nothing consumed, generation 0.
    /// `digest` must cover the first `min(PREFIX_BYTES, size)` bytes.
    pub fn fresh(digest: String, size: u64, mtime: i64) -> Self {
        FileState {
            size,
            mtime,
            cursor: 0,
            digest_len: PREFIX_BYTES.min(size as usize) as u64,
            digest,
            gen: 0,
            recent_ids: VecDeque::new(),
            recent_set: std::collections::HashSet::new(),
            skipped_unparsed: 0,
            provider: String::new(),
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
        self.digest_len = PREFIX_BYTES.min(size as usize) as u64;
        self.digest = digest;
        self.gen += 1;
        self.recent_ids.clear();
        self.recent_set.clear();
        self.skipped_unparsed = 0;
        self.aux.clear();
    }

    /// Whether `id` is still in the ring.
    pub fn seen(&self, id: &str) -> bool {
        self.recent_set.contains(id)
    }

    /// Record `id`, evicting the oldest once the ring is full.
    pub fn mark_seen(&mut self, id: String) {
        if self.recent_ids.len() >= RECENT_IDS_PER_FILE {
            if let Some(old) = self.recent_ids.pop_front() {
                self.recent_set.remove(&old);
            }
        }
        if self.recent_set.insert(id.clone()) {
            self.recent_ids.push_back(id);
        }
    }
}

/// One entry of the cross-file dedup ring: which path first emitted this
/// key. The path is what makes a rewrite rescan safe — a key re-emitted
/// by its own file must count again (its old lines died with the gen
/// bump), while the same key from a *different* file is the duplicate.
/// `V1` accepts ring entries written before paths were tracked; they
/// carry no owner so they never enter the lookup map — they only occupy
/// ring slots until they age out.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GlobalKey {
    V1(String),
    V2 { k: String, p: String },
}

/// All remembered file positions. `BTreeMap` so `state.json` diffs read in
/// path order and two runs write byte-identical files for identical input.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ScannerState {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub files: BTreeMap<String, FileState>,
    /// Cross-file dedup ring, oldest first. Per-file `recent_ids` covers a
    /// record re-read from its own file; this one covers the same record
    /// surfacing in a *second* file on a later pass (Grok's unified log and
    /// a session's `updates.jsonl` carry the same turn, and the wall-clock
    /// budget can put those files in different passes).
    #[serde(default)]
    pub global_ids: VecDeque<GlobalKey>,
    /// `key → first path` mirror of `global_ids` — the ring is scanned at
    /// every record, so membership has to be O(1), not O(8192).
    #[serde(skip)]
    global_map: std::collections::HashMap<String, String>,
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
    /// Byte range of the file this bucket was extracted from:
    /// `[cursor at pass start, cursor at pass end)`. Two lines with the
    /// same bucket key and overlapping ranges are the same bytes parsed
    /// twice — the crash-rescan artifact the load path supersedes.
    #[serde(default)]
    pub lo: u64,
    #[serde(default)]
    pub hi: u64,
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub thinking: u64,
    /// Records folded into this bucket (request/turn count).
    pub messages: u32,
}

/// Advisory exclusive lock on the store directory — held for a whole
/// open→scan→commit cycle. The tray app and `tickover stats` share this
/// store, and without it a lost-update race on `state.json` re-reads bytes
/// the other process already committed. `File::lock` releases on drop and
/// on process death, so a crashed scanner never leaves it held.
pub struct StoreLock(#[allow(dead_code)] fs::File);

/// Take the store lock for `dir`, blocking until a concurrent scan
/// finishes. The returned guard keeps the lock; dropping releases it.
pub fn lock_store(dir: &Path) -> io::Result<StoreLock> {
    fs::create_dir_all(dir)?;
    let f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(dir.join("lock"))?;
    f.lock()?;
    repair_days_tail(dir)?;
    Ok(StoreLock(f))
}

/// A crash mid-append can leave `days.jsonl` ending without a newline.
/// Left in place, the fragment merges with the next append's first line
/// and *both* fail to parse — the retried buckets are lost for good.
/// Only ever called with the lock held, so a torn tail is always a crash
/// leftover, never a write in flight: cut it back to the last newline.
fn repair_days_tail(dir: &Path) -> io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let path = HistoryStore::days_path(dir);
    let mut f = match fs::OpenOptions::new().read(true).write(true).open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let len = f.metadata()?.len();
    if len == 0 {
        return Ok(());
    }
    f.seek(SeekFrom::End(-1))?;
    let mut last = [0u8; 1];
    f.read_exact(&mut last)?;
    if last[0] == b'\n' {
        return Ok(());
    }
    // Walk backwards for the last newline — a torn tail is short (one
    // line), but bound the scan anyway.
    let mut pos = len;
    let mut buf = [0u8; 4096];
    while pos > 0 {
        let n = (pos.min(buf.len() as u64)) as usize;
        pos -= n as u64;
        f.seek(SeekFrom::Start(pos))?;
        f.read_exact(&mut buf[..n])?;
        if let Some(i) = buf[..n].iter().rposition(|&b| b == b'\n') {
            f.set_len(pos + i as u64 + 1)?;
            return Ok(());
        }
    }
    // No newline at all — the whole file is one torn write.
    f.set_len(0)
}

/// `File::create` with 0600 on unix — the store's files hold project
/// basenames and session ids; world-readable is not acceptable.
#[cfg(unix)]
fn enforce_private(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let world_readable = fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o077 != 0)
        .unwrap_or(false);
    if world_readable {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
}

#[cfg(not(unix))]
fn enforce_private(_path: &Path) {}

/// `File::create` with 0600 on unix — the store's files hold project
/// basenames and session ids; world-readable is not acceptable.
fn create_private(path: &Path) -> io::Result<fs::File> {
    let mut oo = fs::OpenOptions::new();
    oo.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        oo.mode(0o600);
    }
    oo.open(path)
}

impl DayLine {
    /// Total tokens across every class in this bucket.
    pub fn sum(&self) -> u64 {
        self.input + self.output + self.cache_read + self.cache_write + self.thinking
    }

    /// Tokens that had to be generated — everything except cache reads.
    /// The "burn" figure; a resent context must not count as fresh spend.
    pub fn active(&self) -> u64 {
        self.input + self.output + self.cache_write + self.thinking
    }
}

/// Bucket identity for range supersession: same file, generation, hour
/// and attribution. Two lines sharing it with overlapping byte ranges
/// are the same bytes parsed twice — the newer one wins.
type BucketKey = (String, u32, String, String, String, String, String);

fn bucket_key(d: &DayLine) -> BucketKey {
    (
        d.file.clone(),
        d.gen,
        d.hour.clone(),
        d.provider.clone(),
        d.project.clone(),
        d.model.clone(),
        d.session.clone(),
    )
}

/// The pair of files plus the in-memory state between them.
pub struct HistoryStore {
    dir: PathBuf,
    pub state: ScannerState,
    /// Lines read from `days.jsonl`, including superseded ones — they
    /// leave through `dead` until the next compacting rewrite.
    days: Vec<DayLine>,
    /// Indices into `days` that a later overlapping line replaced.
    dead: std::collections::HashSet<usize>,
    /// `bucket key → live line indices`, maintained at open and append so
    /// in-memory `live_days` reflects supersession, not just the next load.
    by_key: std::collections::HashMap<BucketKey, Vec<usize>>,
    /// Exact serialized lines — the crash-rescan artifact is a byte-
    /// identical re-append, cheaper to catch as a string than by key.
    seen_lines: std::collections::HashSet<String>,
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
        // Files written by an older version may sit at the umask default —
        // tighten them now rather than only at the next create.
        enforce_private(&Self::state_path(dir));
        enforce_private(&Self::days_path(dir));
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
        let mut store = HistoryStore {
            dir: dir.to_path_buf(),
            state,
            days: Vec::new(),
            dead: std::collections::HashSet::new(),
            by_key: std::collections::HashMap::new(),
            seen_lines: std::collections::HashSet::new(),
        };
        match fs::read_to_string(Self::days_path(dir)) {
            Ok(text) => {
                for line in text.lines() {
                    // A byte-identical line is the same parse twice — the
                    // crash-rescan artifact; two genuinely identical
                    // aggregates carry different `lo`/`hi` and serialize
                    // differently, so real events survive this check.
                    if !store.seen_lines.insert(line.to_string()) {
                        continue;
                    }
                    let Ok(d) = serde_json::from_str::<DayLine>(line) else {
                        continue;
                    };
                    // Lines from *older* schemas still count — a rescan
                    // supersedes what it can re-derive, and lines whose
                    // files no longer exist are the only record of that
                    // usage. Only a line written by a *newer* app version
                    // is dropped: its fields could mean something else.
                    if d.v > SCHEMA_VERSION {
                        continue;
                    }
                    store.fold_line(d);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        if !store.dead.is_empty() {
            store.physically_drop_dead();
        }
        // Rebuild the O(1) mirrors serde skipped: per-file recent sets and
        // the key→first-path map behind the global ring. V1 ring entries
        // carry no path — they are left out of the map rather than treated
        // as "another path" for everyone (the old bug), and they age out
        // of the ring on their own.
        for st in store.state.files.values_mut() {
            st.recent_set = st.recent_ids.iter().cloned().collect();
        }
        let mut map = std::collections::HashMap::new();
        for g in &store.state.global_ids {
            if let GlobalKey::V2 { k, p } = g {
                map.entry(k.clone()).or_insert_with(|| p.clone());
            }
        }
        store.state.global_map = map;
        Ok(store)
    }

    /// Fold one validated line into `days`/`by_key`: a later line whose
    /// byte range overlaps an earlier same-bucket line re-parsed those
    /// bytes — the earlier aggregate is superseded, not summed. This is
    /// what makes append-then-commit crash-safe both at load *and* inside
    /// a session (a state-loss rebuild rescans into the same ranges).
    fn fold_line(&mut self, d: DayLine) {
        // A line with `hi <= lo` never carried a real range: pre-range
        // writes deserialize to `lo = hi = 0`, and a buggy extractor can
        // persist an empty span. The rule is asymmetric: such a line
        // never supersedes (it cannot say what it covered — two rangeless
        // lines of one bucket must still sum), but counts as covering its
        // bucket's whole span *as the old line*, so any re-emitted real
        // range replaces it.
        let idxs = self.by_key.entry(bucket_key(&d)).or_default();
        if d.hi > d.lo {
            idxs.retain(|&i| {
                let old = &self.days[i];
                let (olo, ohi) = if old.hi <= old.lo {
                    (0, u64::MAX)
                } else {
                    (old.lo, old.hi)
                };
                !(d.lo < ohi && olo < d.hi) || {
                    self.dead.insert(i);
                    false
                }
            });
        }
        idxs.push(self.days.len());
        self.days.push(d);
    }

    /// Drop `dead` indices from `days` and reindex — called after a load
    /// that superseded lines, and after a compacting rewrite.
    fn physically_drop_dead(&mut self) {
        let mut days = Vec::with_capacity(self.days.len() - self.dead.len());
        let mut by_key: std::collections::HashMap<BucketKey, Vec<usize>> =
            std::collections::HashMap::new();
        for (i, d) in std::mem::take(&mut self.days).into_iter().enumerate() {
            if self.dead.contains(&i) {
                continue;
            }
            by_key.entry(bucket_key(&d)).or_default().push(days.len());
            days.push(d);
        }
        self.days = days;
        self.by_key = by_key;
        self.dead.clear();
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

    /// Whether `id` was already emitted by a *different* file. The path
    /// check is what keeps a rewrite rescan correct: the file's own keys
    /// re-emitted under a bumped generation must count again — their old
    /// lines are already dead — while a second file carrying the same
    /// event is still the duplicate.
    pub fn seen_globally(&self, path: &str, id: &str) -> bool {
        self.state.global_map.get(id).is_some_and(|p| p != path)
    }

    /// Record `id` in the cross-file ring, evicting the oldest once full.
    /// The first path to emit a key owns it for the ring's lifetime.
    pub fn mark_seen_globally(&mut self, path: &str, id: String) {
        if self.state.global_map.contains_key(&id) {
            return;
        }
        self.state.global_map.insert(id.clone(), path.to_string());
        self.state.global_ids.push_back(GlobalKey::V2 {
            k: id,
            p: path.to_string(),
        });
        if self.state.global_ids.len() > GLOBAL_RECENT_IDS {
            if let Some(old) = self.state.global_ids.pop_front() {
                let (k, p) = match old {
                    GlobalKey::V1(k) => (k, String::new()),
                    GlobalKey::V2 { k, p } => (k, p),
                };
                // Only the map entry that still points at this occurrence
                // is removed — a V1 placeholder never owned a map slot.
                if self.state.global_map.get(&k).is_some_and(|mp| *mp == p) {
                    self.state.global_map.remove(&k);
                }
            }
        }
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
    /// Append finished buckets to `days.jsonl` — the only write the log
    /// ever takes between compactions. Each line is folded through the
    /// same dedup/supersession the load path applies, so the in-memory
    /// view never double-counts a re-append even before the next open.
    pub fn append_days(&mut self, new: &[DayLine]) -> io::Result<()> {
        if new.is_empty() {
            return Ok(());
        }
        let mut accepted: Vec<(String, DayLine)> = Vec::with_capacity(new.len());
        for d in new {
            let line = serde_json::to_string(d).map_err(io::Error::other)?;
            // Byte-identical = the crash-rescan artifact, already on disk.
            if !self.seen_lines.contains(&line) {
                accepted.push((line, d.clone()));
            }
        }
        if accepted.is_empty() {
            return Ok(());
        }
        let path = Self::days_path(&self.dir);
        let mut oo = fs::OpenOptions::new();
        oo.create(true).append(true);
        // Same 0600 as the report — these files carry project basenames
        // and session ids, sensitive in exactly the same way.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            oo.mode(0o600);
        }
        let mut f = oo.open(&path)?;
        let mut buf = Vec::new();
        for (line, _) in &accepted {
            buf.extend_from_slice(line.as_bytes());
            buf.push(b'\n');
        }
        f.write_all(&buf)?;
        f.sync_data().ok();
        // Only after the bytes are on disk do the lines count in memory —
        // a failed append leaves both views untouched, so the retry's
        // identical re-append is caught by `seen_lines` on the next open.
        for (line, d) in accepted {
            self.seen_lines.insert(line);
            self.fold_line(d);
        }
        Ok(())
    }

    /// Persist `state.json` atomically (tmp + rename), then compact
    /// `days.jsonl` if it has grown past [`DAYS_COMPACT_BYTES`].
    pub fn commit(&mut self) -> io::Result<()> {
        self.state.version = SCHEMA_VERSION;
        let tmp = self.dir.join("state.json.tmp");
        let target = Self::state_path(&self.dir);
        {
            let mut f = create_private(&tmp)?;
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
            .enumerate()
            .filter(move |(i, d)| {
                !self.dead.contains(i)
                    && current.get(d.file.as_str()).is_none_or(|&gen| gen == d.gen)
            })
            .map(|(_, d)| d)
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
            let mut f = create_private(&tmp)?;
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
        self.dead.clear();
        self.by_key.clear();
        for (i, d) in self.days.iter().enumerate() {
            self.by_key.entry(bucket_key(d)).or_default().push(i);
        }
        Ok(())
    }

    /// Drop state for paths under none of `roots` — a manifest edit that
    /// narrowed the search leaves entries the walk can never reach again.
    /// Their day lines keep counting (history once recorded stays); if a
    /// path re-enters a root, the rescan's ranges supersede them at load.
    pub fn prune_files_outside(&mut self, roots: &[PathBuf]) -> usize {
        let before = self.state.files.len();
        self.state
            .files
            .retain(|p, _| roots.iter().any(|r| Path::new(p).starts_with(r)));
        before - self.state.files.len()
    }

    /// blake2b hex of a file's first [`PREFIX_BYTES`] — the rewrite signal
    /// `mtime`/`size` alone can miss when a provider rewrites in place.
    pub fn prefix_digest(path: &Path, len: u64) -> Option<String> {
        use blake2::Digest as _;
        use std::io::Read;
        let f = fs::File::open(path).ok()?;
        let mut buf = Vec::new();
        f.take(len).read_to_end(&mut buf).ok()?;
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
            lo: 0,
            hi: 0,
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
    fn overlapping_byte_ranges_supersede_but_disjoint_ranges_sum() {
        // Crash-rescan: a line covering [0,100) is superseded by a later
        // re-parse of [0,150) — the stale aggregate is replaced, not added.
        // Disjoint ranges in the same bucket are different bytes and both
        // count; identical counts at different ranges are different events.
        let dir = tmpdir("ranges");
        let mut store = HistoryStore::open(&dir).unwrap();
        let mut a = day("/f", 0, 100);
        a.lo = 0;
        a.hi = 100;
        let mut b = day("/f", 0, 150);
        b.lo = 0;
        b.hi = 150;
        let mut c = day("/f", 0, 60);
        c.lo = 150;
        c.hi = 200;
        store.append_days(&[a, b, c]).unwrap();
        // In-memory all three exist; the supersession happens at load.
        drop(store);
        let store = HistoryStore::open(&dir).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            210,
            "[0,150) replaced [0,100); [150,200) summed: 150 + 60"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn identical_aggregates_at_disjoint_ranges_both_survive() {
        // The old exact-line dedup dropped a second identical aggregate;
        // with lo/hi the lines serialize differently and both count.
        let dir = tmpdir("identical");
        let mut store = HistoryStore::open(&dir).unwrap();
        let mut a = day("/f", 0, 42);
        a.lo = 0;
        a.hi = 100;
        let mut b = day("/f", 0, 42);
        b.lo = 100;
        b.hi = 200;
        store.append_days(&[a, b]).unwrap();
        drop(store);
        let store = HistoryStore::open(&dir).unwrap();
        assert_eq!(store.live_days().map(|d| d.input).sum::<u64>(), 84);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_drops_only_paths_outside_the_active_roots() {
        let dir = tmpdir("prune");
        let mut store = HistoryStore::open(&dir).unwrap();
        store.state.files.insert(
            "/grok/memtrace/a.jsonl".into(),
            FileState::fresh("d".into(), 1, 1),
        );
        store.state.files.insert(
            "/grok/logs/unified.jsonl".into(),
            FileState::fresh("d".into(), 1, 1),
        );
        store.state.files.insert(
            "/codex/sessions/x.jsonl".into(),
            FileState::fresh("d".into(), 1, 1),
        );
        let roots = vec![PathBuf::from("/grok/logs"), PathBuf::from("/codex")];
        assert_eq!(store.prune_files_outside(&roots), 1);
        assert!(store
            .file_state(Path::new("/grok/logs/unified.jsonl"))
            .is_some());
        assert!(store
            .file_state(Path::new("/codex/sessions/x.jsonl"))
            .is_some());
        assert!(store
            .file_state(Path::new("/grok/memtrace/a.jsonl"))
            .is_none());
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

    #[test]
    fn torn_tail_is_cut_back_to_the_last_newline() {
        // A crash mid-append leaves a fragment with no newline; left in
        // place it would merge with the next append's first line and
        // poison both forever.
        let dir = tmpdir("torn");
        let mut store = HistoryStore::open(&dir).unwrap();
        let mut first = day("/f", 0, 10);
        first.lo = 0;
        first.hi = 50;
        store.append_days(&[first]).unwrap();
        store.commit().unwrap();
        drop(store);
        // Simulate the torn write: append half a serialized line.
        let mut a = day("/f", 0, 99);
        a.lo = 100;
        a.hi = 200;
        let fragment = serde_json::to_string(&a).unwrap();
        use std::io::Write;
        fs::OpenOptions::new()
            .append(true)
            .open(dir.join("days.jsonl"))
            .unwrap()
            .write_all(&fragment.as_bytes()[..fragment.len() / 2])
            .unwrap();

        let lock = lock_store(&dir).unwrap();
        let mut store = HistoryStore::open(&dir).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            10,
            "the fragment was never acknowledged — only the complete line survives"
        );
        // The next append must land on a clean boundary, not glue itself
        // to the fragment.
        let mut b = day("/f", 0, 7);
        b.lo = 200;
        b.hi = 300;
        store.append_days(&[b]).unwrap();
        store.commit().unwrap();
        drop(store);
        drop(lock);
        let _lock = lock_store(&dir).unwrap();
        let store = HistoryStore::open(&dir).unwrap();
        assert_eq!(store.live_days().map(|d| d.input).sum::<u64>(), 17);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_zero_range_lines_are_superseded_but_never_supersede() {
        // A `hi == 0` line never carried a real range (the pre-watermark
        // Antigravity deadline bug wrote them). It cannot say what it
        // covered, so it never supersedes a sibling — but any re-emitted
        // real range replaces it.
        let dir = tmpdir("legacy");
        let mut store = HistoryStore::open(&dir).unwrap();
        store
            .append_days(&[day("/f", 0, 10), day("/f", 0, 20)])
            .unwrap();
        store.commit().unwrap();
        drop(store);
        let mut store = HistoryStore::open(&dir).unwrap();
        // Both legacy lines survived (summing preserved).
        assert_eq!(store.live_days().map(|d| d.input).sum::<u64>(), 30);
        // A real-range re-parse of the same bucket supersedes them.
        let mut r = day("/f", 0, 42);
        r.lo = 0;
        r.hi = 500;
        store.append_days(&[r]).unwrap();
        assert_eq!(store.live_days().map(|d| d.input).sum::<u64>(), 42);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn per_file_dedup_rings_survive_commit_and_reopen() {
        // A provider can re-log an id at a later offset (Claude streams
        // usage updates under one message id); the ring must still say
        // "seen" on the next pass — across commits and across restarts.
        let dir = tmpdir("rings");
        let mut store = HistoryStore::open(&dir).unwrap();
        store
            .state
            .files
            .insert("/f".to_string(), FileState::fresh("d".into(), 1, 1));
        store
            .file_state_mut(Path::new("/f"))
            .unwrap()
            .mark_seen("k1".into());
        store.commit().unwrap();
        assert!(store.file_state(Path::new("/f")).unwrap().seen("k1"));
        drop(store);
        let store = HistoryStore::open(&dir).unwrap();
        assert!(store.file_state(Path::new("/f")).unwrap().seen("k1"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn lines_from_an_older_schema_still_count() {
        // A v1 day line is data the current schema can still read — and
        // for a file that no longer exists it is the only record left.
        // Only lines from a *newer* schema are refused.
        let dir = tmpdir("oldschema");
        let mut store = HistoryStore::open(&dir).unwrap();
        let mut old = day("/gone", 0, 33);
        old.v = SCHEMA_VERSION - 1;
        store.append_days(&[old]).unwrap();
        store.commit().unwrap();
        drop(store);
        let store = HistoryStore::open(&dir).unwrap();
        assert_eq!(store.live_days().map(|d| d.input).sum::<u64>(), 33);
        let _ = fs::remove_dir_all(&dir);
    }
}
