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

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
    /// The usage each ring id last carried. A re-emission is not a new
    /// event, but it is not always identical either — Claude streams a
    /// growing `output_tokens` under one `message.id`. The scanner emits
    /// only the delta against the componentwise high-water mark, so a
    /// regressed snapshot never lowers the baseline. Membership without
    /// a usage row (entries persisted before this field existed) still
    /// dedups outright — a repeat of unknown growth can't be priced.
    #[serde(default)]
    pub recent_usage: std::collections::HashMap<String, [u64; 5]>,
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
            recent_usage: std::collections::HashMap::new(),
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
        self.recent_usage.clear();
        self.recent_set.clear();
        self.skipped_unparsed = 0;
        self.aux.clear();
    }

    /// Whether `id` is still in the ring.
    pub fn seen(&self, id: &str) -> bool {
        self.recent_set.contains(id)
    }

    /// The usage `id` last reported, if the ring remembers it.
    pub fn last_usage(&self, id: &str) -> Option<[u64; 5]> {
        self.recent_usage.get(id).copied()
    }

    /// Refresh `id`'s recency without touching its usage — for repeats
    /// that emit nothing (zero-delta, membership-only skip) but prove the
    /// id is still live and shouldn't age out of the ring.
    pub fn touch(&mut self, id: &str) {
        if self.recent_set.contains(id) {
            self.recent_ids.retain(|k| k != id);
            self.recent_ids.push_back(id.to_string());
        }
    }

    /// Record `id` with the usage it carried, evicting the oldest once
    /// the ring is full. A repeat stores the componentwise high-water
    /// mark — the next re-emission diffs against it — and moves `id` to
    /// the back: a plain FIFO would evict an actively re-emitted id while
    /// the ring is full, and the next repeat would then read as brand-new
    /// usage and count twice.
    pub fn mark_seen(&mut self, id: String, usage: [u64; 5]) {
        if self.recent_set.contains(&id) {
            self.recent_ids.retain(|k| k != &id);
        } else if self.recent_ids.len() >= RECENT_IDS_PER_FILE {
            if let Some(old) = self.recent_ids.pop_front() {
                self.recent_set.remove(&old);
                self.recent_usage.remove(&old);
            }
        }
        self.recent_set.insert(id.clone());
        self.recent_ids.push_back(id.clone());
        // Keep the componentwise high-water mark, not the raw snapshot:
        // a regressed re-emission must not lower the baseline the next
        // repeat diffs against.
        let merged = match self.recent_usage.get(&id) {
            Some(old) => [
                old[0].max(usage[0]),
                old[1].max(usage[1]),
                old[2].max(usage[2]),
                old[3].max(usage[3]),
                old[4].max(usage[4]),
            ],
            None => usage,
        };
        self.recent_usage.insert(id, merged);
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
    /// Id the next `append_days` batch stamps on its lines — persisted so
    /// a restart can't reissue a batch id older lines already carry.
    #[serde(default)]
    pub next_batch: u64,
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
    /// The pass that wrote this line read its file to the end — only such
    /// a line may supersede every older line of its `(file, gen)` (a
    /// truncated prefix must not claim coverage it didn't re-derive).
    /// Persisted because supersession replays at load.
    #[serde(default)]
    pub full: bool,
    /// Append-batch id — one per `append_days` call, persisted so that at
    /// load the lines of one scan batch still recognise each other: a
    /// seal kills stale coverage, never its own batch-mates (a file whose
    /// records span several hours emits one `full` line per bucket).
    #[serde(default)]
    pub b: u64,
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
    /// Private rather than `pub`: every write has to pass through
    /// [`Self::state_mut`] (or one of the narrower methods below) so
    /// [`Self::live_cache`] never outlives a change to `files` that would
    /// make it wrong — a public field would let a caller edit `files`
    /// straight past that and read a liveness answer for the store as it
    /// was before the edit.
    state: ScannerState,
    /// Lines read from `days.jsonl`, including superseded ones — they
    /// leave through `dead` until the next compacting rewrite.
    days: Vec<DayLine>,
    /// Indices into `days` that a later overlapping line replaced.
    dead: std::collections::HashSet<usize>,
    /// `bucket key → live line indices`, maintained at open and append so
    /// in-memory `live_days` reflects supersession, not just the next load.
    by_key: std::collections::HashMap<BucketKey, Vec<usize>>,
    /// `(file, gen) → line indices` — the seal's reach: a complete pass
    /// re-derived the file's whole contribution, so its scope is every
    /// bucket of this generation, not only the one the line landed in.
    by_file: std::collections::HashMap<(String, u32), Vec<usize>>,
    /// Exact serialized lines — the crash-rescan artifact is a byte-
    /// identical re-append, cheaper to catch as a string than by key.
    seen_lines: std::collections::HashSet<String>,
    /// [`Self::live_days`]'s answer, memoized as indices into `days` — one
    /// walk of `files` and `days` per change instead of one per call, since
    /// a tick asks every window of every provider the same question against
    /// the same snapshot. `Arc` rather than a plain `Vec` so the accessor
    /// can clone the handle out and drop the `RefCell` borrow before
    /// building the returned iterator — a borrow held for the iterator's
    /// whole life would panic the moment any caller tried to compact or
    /// append while still consuming it. `None` means "unknown", not "empty";
    /// every `&mut self` path that can change what counts as live clears it
    /// back to `None` rather than trying to patch it in place.
    live_cache: RefCell<Option<Arc<Vec<usize>>>>,
    /// Whether `state` has changed since the last successful [`Self::commit`]
    /// (or, on the very first commit, since `open` loaded — or failed to
    /// load — it). `commit` skips the `state.json` rewrite entirely when
    /// this is `false`: the file can be several megabytes, and a scan pass
    /// that touched no file at all still called it once per manifest.
    /// `days.jsonl`'s own append path has no equivalent — it is already
    /// only ever written when there is something new to append.
    state_dirty: bool,
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
        // `state_dirty` starts `false` only when what's now in memory is
        // byte-for-byte what a fresh `open` would read straight back — a
        // quarantined-and-rebuilt or altogether missing `state.json` needs a
        // real file in its place even if nothing mutates `state` before the
        // next `commit`, the same as an unconditional write always gave it.
        let (state, state_dirty) = match fs::read_to_string(Self::state_path(dir)) {
            Ok(text) => match serde_json::from_str::<ScannerState>(&text) {
                Ok(s) if s.version == SCHEMA_VERSION => (s, false),
                _ => {
                    let aside = dir.join(format!(
                        "state.corrupt-{}.json",
                        chrono::Utc::now().timestamp()
                    ));
                    let _ = fs::rename(Self::state_path(dir), aside);
                    (ScannerState::default(), true)
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => (ScannerState::default(), true),
            Err(e) => return Err(e),
        };
        let mut store = HistoryStore {
            dir: dir.to_path_buf(),
            state,
            days: Vec::new(),
            dead: std::collections::HashSet::new(),
            by_key: std::collections::HashMap::new(),
            by_file: std::collections::HashMap::new(),
            seen_lines: std::collections::HashSet::new(),
            live_cache: RefCell::new(None),
            state_dirty,
        };
        match fs::read_to_string(Self::days_path(dir)) {
            Ok(text) => {
                for line in text.lines() {
                    // A byte-identical line is the same parse twice — the
                    // crash-rescan artifact; two genuinely identical
                    // aggregates carry different `lo`/`hi` and serialize
                    // differently, so real events survive this check.
                    // Parse first: a torn fragment that fails serde must
                    // not occupy a `seen_lines` slot it can't defend.
                    let Ok(d) = serde_json::from_str::<DayLine>(line) else {
                        continue;
                    };
                    if !store.seen_lines.insert(line.to_string()) {
                        continue;
                    }
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
        // Batch ids must stay ahead of anything already on disk — a state
        // rebuild resets the counter, and a reused id would let a stale
        // line pose as a seal's batch-mate. Not a `state_dirty` site: this
        // is deterministic from `days.jsonl`, which is already on disk —
        // the identical value falls back out of the same computation on
        // every future `open`, so there is nothing to lose by leaving its
        // persistence to whatever next legitimately dirties `state`.
        store.state.next_batch = store
            .days
            .iter()
            .map(|d| d.b)
            .max()
            .unwrap_or(0)
            .max(store.state.next_batch)
            + 1;
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

    /// Fold one validated line into `days`/the indexes: a later line whose
    /// range overlaps an earlier same-bucket line re-parsed those bytes —
    /// the earlier aggregate is superseded, not summed. Batch-mates
    /// (`old.b == d.b`, one append — e.g. a multi-hour extraction emitting
    /// several buckets) are fresh coverage, never stale. Invalidates the
    /// liveness cache unconditionally: this runs once per line during
    /// `open`'s load loop (the cache is already empty then) and once per
    /// appended line from `append_days`, where it always changes `days`.
    fn fold_line(&mut self, d: DayLine) {
        self.invalidate_live_cache();
        // A line with `hi <= lo` never carried a real range: pre-range
        // writes deserialize to `lo = hi = 0`, and a buggy extractor can
        // persist an empty span. The rule is asymmetric: such a line
        // never supersedes (it cannot say what it covered — two rangeless
        // lines of one bucket must still sum), but counts as covering its
        // bucket's whole span *as the old line*, so any re-emitted real
        // range replaces it.
        //
        // A `full` line seals coverage: its pass reached the end of the
        // source, and because cursors/watermarks only advance past ranges
        // that were appended, the live lines of this file+generation now
        // re-derive its whole contribution. The seal therefore reaches
        // *every* older line of the generation — even lines in drifted
        // buckets or alien coordinate spaces (v1 byte ranges vs. v2 row
        // ranges can neither overlap numerically nor share a bucket key,
        // but the rescan covers the same events) — except two kinds:
        //
        //   * batch-mates — lines the same append produced for other
        //     buckets; they ARE the new coverage. One append is one pass
        //     and emits one shared range, so "same append" is exactly
        //     `(b, lo, hi)` equality. Bare `b == d.b` would be wrong for
        //     legacy lines, which all deserialize with `b = 0`: a legacy
        //     seal would call every older line of the generation a mate
        //     and kill nothing. Under the shape rule a legacy seal keeps
        //     only same-range fan-out lines — indistinguishable from its
        //     own append, which is the best available for them.
        //   * the prefix chain — the earlier passes' lines inside
        //     `[0, lo)`; their bytes were already counted and this line
        //     only completes them. Honest passes never overlap: each
        //     emits one shared range per batch and resumes where the
        //     last cursor stopped, though spans that produced no records
        //     leave gaps. So a candidate range that overlaps an
        //     already-kept range is stale — an artifact of a pass that
        //     appended but never committed, always *older* than the
        //     re-derivation that replaced it. Candidates are tried
        //     freshest-batch-first, and a kept step keeps every line of
        //     its `(range, batch)` — one pass emits a line per bucket,
        //     all sharing the pass's range and batch id.
        //
        // A `lo == hi == 0` tombstone — a complete pass that had nothing
        // to emit — seals the same way: nothing covers `[0, 0)`, so
        // every older line of the generation dies. A truncated pass's
        // line must not seal at all: it re-derived a prefix, nothing
        // more.
        if d.full {
            if let Some(idxs) = self.by_file.get_mut(&(d.file.clone(), d.gen)) {
                let keep: std::collections::HashSet<usize> = idxs
                    .iter()
                    .copied()
                    .filter(|&i| {
                        let o = &self.days[i];
                        o.b == d.b && o.lo == d.lo && o.hi == d.hi
                    })
                    .collect();
                // Candidate steps: one per (batch, range) — a batch's
                // lines all share the pass's range. Freshest first: the
                // latest re-derivation owns contested bytes. Freshness is
                // `(b, position)` — the batch id, then the line's append
                // order — because legacy lines all share `b = 0` and only
                // their position in the file still says which came last.
                let mut steps: std::collections::BTreeMap<(u64, u64), (u64, usize)> =
                    std::collections::BTreeMap::new();
                for &i in idxs.iter() {
                    let o = &self.days[i];
                    if keep.contains(&i) || self.dead.contains(&i) || o.hi <= o.lo || o.hi > d.lo {
                        continue;
                    }
                    steps
                        .entry((o.lo, o.hi))
                        .and_modify(|e| *e = (*e).max((o.b, i)))
                        .or_insert((o.b, i));
                }
                let mut ordered: Vec<(u64, u64, u64, usize)> = steps
                    .iter()
                    .map(|(&(lo, hi), &(b, i))| (lo, hi, b, i))
                    .collect();
                ordered.sort_by_key(|&(_, _, b, i)| std::cmp::Reverse((b, i)));
                let mut taken: Vec<(u64, u64)> = Vec::new();
                let mut selected: std::collections::HashSet<(u64, u64, u64)> =
                    std::collections::HashSet::new();
                for (lo, hi, b, _) in ordered {
                    if taken.iter().any(|&(tlo, thi)| lo < thi && tlo < hi) {
                        continue; // overlaps a fresher chain step — stale
                    }
                    taken.push((lo, hi));
                    selected.insert((lo, hi, b));
                }
                idxs.retain(|&i| {
                    if keep.contains(&i) {
                        return true;
                    }
                    if !self.dead.contains(&i)
                        && selected.contains(&(self.days[i].lo, self.days[i].hi, self.days[i].b))
                    {
                        return true;
                    }
                    self.dead.insert(i);
                    false
                });
            }
        } else if d.hi > d.lo {
            let idxs = self.by_key.entry(bucket_key(&d)).or_default();
            idxs.retain(|&i| {
                if self.dead.contains(&i) {
                    return false;
                }
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
        let i = self.days.len();
        self.by_key.entry(bucket_key(&d)).or_default().push(i);
        self.by_file
            .entry((d.file.clone(), d.gen))
            .or_default()
            .push(i);
        self.days.push(d);
    }

    /// Drop `dead` indices from `days` and reindex — called after a load
    /// that superseded lines, and after a compacting rewrite. Every cached
    /// live index would point at the wrong line once positions shift, so
    /// this invalidates even though its one call site (inside `open`) never
    /// finds a cache to drop.
    fn physically_drop_dead(&mut self) {
        self.invalidate_live_cache();
        let mut days = Vec::with_capacity(self.days.len() - self.dead.len());
        let mut by_key: std::collections::HashMap<BucketKey, Vec<usize>> =
            std::collections::HashMap::new();
        let mut by_file: std::collections::HashMap<(String, u32), Vec<usize>> =
            std::collections::HashMap::new();
        for (i, d) in std::mem::take(&mut self.days).into_iter().enumerate() {
            if self.dead.contains(&i) {
                continue;
            }
            by_key.entry(bucket_key(&d)).or_default().push(days.len());
            by_file
                .entry((d.file.clone(), d.gen))
                .or_default()
                .push(days.len());
            days.push(d);
        }
        self.days = days;
        self.by_file = by_file;
        self.by_key = by_key;
        self.dead.clear();
    }

    /// Read-only view of the scanner's persisted position — file cursors,
    /// generations, dedup rings. A read never needs to invalidate anything.
    pub fn state(&self) -> &ScannerState {
        &self.state
    }

    /// Mutable access to the scanner's persisted position, for a caller that
    /// needs to reach past the narrower methods below (test setup, mainly).
    /// Invalidates [`Self::live_cache`] and marks `state` dirty
    /// unconditionally on the handout, not on some later inspection of what
    /// changed — there is no way to see after the fact whether a
    /// `&mut ScannerState` touched `files`.
    pub fn state_mut(&mut self) -> &mut ScannerState {
        self.invalidate_live_cache();
        self.mark_state_dirty();
        &mut self.state
    }

    /// Drop the memoized [`Self::live_days`] answer — called from every
    /// path that can change which lines count as live: a fold (append or
    /// load), a compaction, a dead-line sweep, a new file entry, or any
    /// mutable reach into `state` that might bump a generation.
    fn invalidate_live_cache(&mut self) {
        *self.live_cache.get_mut() = None;
    }

    /// Mark that `state` no longer matches what `commit` last wrote (or what
    /// `open` read) — called from every path that changes anything
    /// `state.json` serializes: `files`, `global_ids`, `next_batch`. Distinct
    /// from [`Self::invalidate_live_cache`] because the two caches answer
    /// different questions — the global dedup ring is persisted but never
    /// read by `live_days`, so a path that only touches it dirties `state`
    /// without needing to invalidate the liveness cache at all.
    fn mark_state_dirty(&mut self) {
        self.state_dirty = true;
    }

    /// This file's remembered progress, if it was ever scanned.
    pub fn file_state(&self, path: &Path) -> Option<&FileState> {
        self.state.files.get(&path.to_string_lossy().into_owned())
    }

    /// This file's remembered progress, mutably — for cursor and ring
    /// updates after a successful extract. Invalidates on the handout: a
    /// generation bump ([`FileState::reset`]) is invisible to the store
    /// otherwise, and every other mutation through this handle is cheap
    /// enough to over-invalidate for.
    pub fn file_state_mut(&mut self, path: &Path) -> Option<&mut FileState> {
        self.invalidate_live_cache();
        self.mark_state_dirty();
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

    /// Whether this very file owns `id` in the global ring — true on a
    /// mid-stream re-emission whose ring entry aged out (must not count
    /// twice). A rewrite rescan clears the file's ownership first, so a
    /// resumed pass can't mistake re-derived records for evicted repeats.
    pub fn owns_globally(&self, path: &str, id: &str) -> bool {
        self.state.global_map.get(id).is_some_and(|p| p == path)
    }

    /// Drop every global-ring entry `path` owns — part of a rewrite reset:
    /// the file's contribution is about to be re-derived under a bumped
    /// generation, so its old ownership claims die with the old one.
    /// `global_ids` is what `state.json` persists, so `state` is dirtied
    /// only once that retain actually removes something — `global_map` is
    /// the `#[serde(skip)]` mirror and never needs to dirty anything on its
    /// own, and a path that owned nothing here (the ordinary case: most
    /// rewrites touch a file that never emitted a ring-eligible id) must
    /// not force a `state.json` rewrite for having been asked.
    pub fn release_owned(&mut self, path: &str) {
        self.state.global_map.retain(|_, p| p != path);
        let before = self.state.global_ids.len();
        self.state
            .global_ids
            .retain(|g| !matches!(g, GlobalKey::V2 { p, .. } if p == path));
        if self.state.global_ids.len() != before {
            self.mark_state_dirty();
        }
    }

    /// Refresh `id`'s recency in the global ring — a duplicate sighting
    /// proves the key is still live, and a still-live owner shouldn't age
    /// out while repeats keep arriving.
    pub fn touch_globally(&mut self, id: &str) {
        if !self.state.global_map.contains_key(id) {
            return;
        }
        if let Some(pos) = self
            .state
            .global_ids
            .iter()
            .position(|g| matches!(g, GlobalKey::V2 { k, .. } if k == id))
        {
            if let Some(g) = self.state.global_ids.remove(pos) {
                // Only reached once the reposition below is guaranteed —
                // the `contains_key` guard above can pass while this
                // `position` still comes up empty (a V1 leftover), which
                // must not mark `state` dirty for a no-op.
                self.mark_state_dirty();
                self.state.global_ids.push_back(g);
            }
        }
    }

    /// Record `id` in the cross-file ring, evicting the oldest once full.
    /// The first path to emit a key owns it for the ring's lifetime.
    pub fn mark_seen_globally(&mut self, path: &str, id: String) {
        if self.state.global_map.contains_key(&id) {
            return;
        }
        self.mark_state_dirty();
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

    /// Register `path` at generation 0 (or return the existing entry). A
    /// path new to `state.files` can flip day lines of the same file out of
    /// the deleted-file fallback [`Self::live_days`] otherwise uses, so this
    /// invalidates unconditionally rather than only on the fresh-entry case.
    pub fn begin_file(
        &mut self,
        path: &Path,
        provider: &str,
        digest: String,
        size: u64,
        mtime: i64,
    ) {
        self.invalidate_live_cache();
        self.mark_state_dirty();
        self.state
            .files
            .entry(path.to_string_lossy().into_owned())
            .or_insert_with(|| {
                let mut st = FileState::fresh(digest, size, mtime);
                st.provider = provider.to_string();
                st
            });
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
        let batch = self.state.next_batch;
        let mut accepted: Vec<(String, DayLine)> = Vec::with_capacity(new.len());
        for d in new {
            let mut d = d.clone();
            d.b = batch;
            let line = serde_json::to_string(&d).map_err(io::Error::other)?;
            // Byte-identical = the crash-rescan artifact, already on disk.
            // A post-crash retry carries a fresh `b`, so it serializes
            // differently — but its identical range still supersedes the
            // copy that made it to disk, so the duplicate can't count.
            if !self.seen_lines.contains(&line) {
                accepted.push((line, d));
            }
        }
        if accepted.is_empty() {
            return Ok(());
        }
        // Claimed only now that a line is actually going to carry it — a
        // pass that re-offers nothing but duplicates advances neither the
        // counter nor `state`, so `commit` below finds nothing to write.
        self.state.next_batch = self.state.next_batch.saturating_add(1);
        self.mark_state_dirty();
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
        // The whole batch shares one id: a seal line may kill anything
        // older, but never its own batch-mates.
        for (line, d) in accepted {
            self.seen_lines.insert(line);
            self.fold_line(d);
        }
        Ok(())
    }

    /// Persist `state.json` atomically (tmp + rename) — but only when
    /// [`Self::state_dirty`] says `state` actually differs from what's on
    /// disk — then compact `days.jsonl` if it has grown past
    /// [`DAYS_COMPACT_BYTES`] (that trigger is unconditional; a
    /// `days.jsonl`-only pass with an untouched `state` still needs to
    /// compact). A scan pass that touched no file still called this once
    /// per manifest, and `tickover stats` calls it dozens of times a run —
    /// serializing every one of `state.files`'s entries into a multi-
    /// megabyte file when nothing about them changed was the real cost;
    /// routing the write through a `BufWriter` (flushed before `sync_data`,
    /// same tmp+rename shape and private-file creation as before) is what
    /// makes the writes that do still happen cheap too. `days.jsonl`'s own
    /// append path needed neither change — it only ever writes new lines.
    pub fn commit(&mut self) -> io::Result<()> {
        if self.state_dirty {
            self.state.version = SCHEMA_VERSION;
            let tmp = self.dir.join("state.json.tmp");
            let target = Self::state_path(&self.dir);
            {
                let f = create_private(&tmp)?;
                let mut w = io::BufWriter::new(f);
                serde_json::to_writer(&mut w, &self.state).map_err(io::Error::other)?;
                w.write_all(b"\n")?;
                w.flush()?;
                w.get_ref().sync_data().ok();
            }
            fs::rename(&tmp, &target)?;
            self.state_dirty = false;
        }
        self.maybe_compact_days()
    }

    /// Day lines that still count: a line is stale only when its file is
    /// still tracked at a *newer* generation. Lines from a file that has
    /// since been deleted keep counting — the usage happened; the provider
    /// removing its log does not un-spend the tokens — but only the
    /// newest generation's: without the state entry nothing suppresses
    /// superseded generations, so the file's latest *live* gen stands in
    /// as its remembered watermark.
    ///
    /// Amortised O(live lines) per call: the answer is memoized in
    /// [`Self::live_cache`], so only the first call after a change any
    /// `&mut self` path here might have made pays to rebuild it — an
    /// O(files + days) walk over `state.files` and `days` — and every call
    /// after that, until the next such change, is just an iterator over the
    /// indices that walk already found. A tick asks this same question once
    /// per (provider, window) — 5-6 times a second against an unchanged
    /// snapshot — so it is that rebuild, not the read, that must not repeat
    /// for every one of them.
    pub fn live_days(&self) -> impl Iterator<Item = &DayLine> {
        let idx = {
            let mut cache = self.live_cache.borrow_mut();
            if cache.is_none() {
                *cache = Some(Arc::new(self.compute_live_indices()));
            }
            // Cloning the `Arc` out and dropping `cache` here (its scope
            // ends with this block) is what lets the returned iterator
            // outlive this call without holding the `RefCell` borrowed —
            // a live iterator across a later `&mut self` call would
            // otherwise panic on the second borrow instead of just being
            // stale, which nothing here promises to avoid on its own.
            Arc::clone(cache.as_ref().unwrap())
        };
        (0..idx.len()).map(move |k| &self.days[idx[k]])
    }

    /// [`Self::live_days`]'s answer, computed fresh: every non-dead index
    /// whose file is at the state's current generation, or — for a file no
    /// longer in `state.files` — at that file's own newest surviving
    /// generation. Split out so [`Self::live_days`] only ever calls it
    /// through the cache.
    fn compute_live_indices(&self) -> Vec<usize> {
        let current: HashMap<&str, u32> = self
            .state
            .files
            .iter()
            .map(|(p, s)| (p.as_str(), s.gen))
            .collect();
        let mut last_live: HashMap<&str, u32> = HashMap::new();
        for (i, d) in self.days.iter().enumerate() {
            if self.dead.contains(&i) {
                continue;
            }
            let e = last_live.entry(d.file.as_str()).or_insert(d.gen);
            if d.gen > *e {
                *e = d.gen;
            }
        }
        self.days
            .iter()
            .enumerate()
            .filter(|(i, d)| {
                !self.dead.contains(i)
                    && match current.get(d.file.as_str()) {
                        Some(&gen) => gen == d.gen,
                        None => last_live.get(d.file.as_str()) == Some(&d.gen),
                    }
            })
            .map(|(i, _)| i)
            .collect()
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
        // Reindex in place — compaction changes every index, so both
        // maps must be rebuilt, not just `by_key`: a stale `by_file`
        // index either points past the shortened `days` (panic) or at
        // an unrelated line (a seal then kills coverage it never read).
        self.days = live.into_iter().cloned().collect();
        self.dead.clear();
        self.by_key.clear();
        self.by_file.clear();
        for (i, d) in self.days.iter().enumerate() {
            self.by_key.entry(bucket_key(d)).or_default().push(i);
            self.by_file
                .entry((d.file.clone(), d.gen))
                .or_default()
                .push(i);
        }
        // The indices the pre-compaction `live_days()` call above cached
        // point at positions in the old `days` — every one of them is
        // wrong now that the array has been rewritten shorter.
        self.invalidate_live_cache();
        Ok(())
    }

    /// Drop state for paths under none of `roots` — a manifest edit that
    /// narrowed the search leaves entries the walk can never reach again.
    /// Their day lines keep counting (history once recorded stays); if a
    /// path re-enters a root, the rescan's ranges supersede them at load.
    /// A file leaving `state.files` can flip its day lines onto the
    /// deleted-file fallback [`Self::live_days`] uses, so the liveness
    /// cache invalidates even when nothing actually matched `roots` — but
    /// `state` itself is only dirtied when something was actually removed:
    /// this runs on every scan tick regardless of whether the root set
    /// narrowed, and a dirty mark on every no-op call would leave `commit`
    /// rewriting `state.json` on every tick again, the very rewrite the
    /// dirty flag exists to skip.
    pub fn prune_files_outside(&mut self, roots: &[PathBuf]) -> usize {
        self.invalidate_live_cache();
        let before = self.state.files.len();
        self.state
            .files
            .retain(|p, _| roots.iter().any(|r| Path::new(p).starts_with(r)));
        let removed = before - self.state.files.len();
        if removed > 0 {
            self.mark_state_dirty();
        }
        removed
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
            full: false,
            b: 0,
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
    fn a_pass_that_only_reoffers_duplicate_lines_leaves_state_untouched() {
        // `next_batch` wound back to the value the first call used stands in
        // for a crash-rescan retry: the re-derived line serializes to the
        // exact bytes `seen_lines` already holds, so every line this second
        // call offers is a duplicate and none of it should move `state` —
        // not the counter, not the dirty flag `commit` below would
        // otherwise pay to clear.
        let dir = tmpdir("dup-noop");
        let mut store = HistoryStore::open(&dir).unwrap();
        // `open` already claims a batch id one past the highest it finds on
        // disk (nothing, here, so 1) before this call ever raises it further
        // — captured so the rewind below lands on the exact id the accepted
        // line was stamped with, not a guessed constant.
        let batch = store.state.next_batch;
        store.append_days(&[day("/f", 0, 10)]).unwrap();
        store.state_mut().next_batch = batch;
        store.commit().unwrap();
        assert!(!store.state_dirty, "commit must have cleared it");
        let before = fs::read(dir.join("state.json")).unwrap();

        store.append_days(&[day("/f", 0, 10)]).unwrap();
        assert!(
            !store.state_dirty,
            "an all-duplicate append must not dirty state"
        );
        store.commit().unwrap();
        let after = fs::read(dir.join("state.json")).unwrap();
        assert_eq!(
            before, after,
            "state.json must be byte-identical after an all-duplicate append"
        );
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
            .mark_seen("k1".into(), [1, 2, 3, 4, 5]);
        store.commit().unwrap();
        assert!(store.file_state(Path::new("/f")).unwrap().seen("k1"));
        drop(store);
        let store = HistoryStore::open(&dir).unwrap();
        assert!(store.file_state(Path::new("/f")).unwrap().seen("k1"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_re_emitted_id_is_not_evicted_by_ring_pressure() {
        // With a plain FIFO, an actively streaming id gets pushed out by
        // newer ids while the ring is full; the next re-emission then
        // reads as brand-new usage and double-counts. Refreshing recency
        // on repeat (LRU) keeps it alive.
        let mut st = FileState::fresh("d".into(), 1, 1);
        st.mark_seen("hot".into(), [1, 0, 0, 0, 0]);
        for i in 0..crate::history::store::RECENT_IDS_PER_FILE {
            st.mark_seen(format!("cold-{i}"), [9, 9, 9, 9, 9]);
            if i == 3 {
                // Re-emit "hot" while the ring still has cold ids queued
                // ahead of it — the repeat must move it to the back.
                st.mark_seen("hot".into(), [2, 0, 0, 0, 0]);
            }
        }
        assert!(st.seen("hot"), "the active id outlived the filler");
        assert_eq!(st.last_usage("hot"), Some([2, 0, 0, 0, 0]));
        // And the ring still evicts genuinely-old entries.
        assert!(!st.seen("cold-0"), "the oldest filler was evicted");
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

    #[test]
    fn a_full_from_origin_line_supersedes_across_range_spaces() {
        // v1 Antigravity lines carry *byte* ranges; v2 lines carry row
        // indices. They can never overlap numerically, yet a complete
        // rescan re-derives the same events — `full` is what lets the
        // row-range line kill the alien byte-range line.
        let dir = tmpdir("spaces");
        let mut store = HistoryStore::open(&dir).unwrap();
        let mut byte_line = day("/f", 0, 100);
        byte_line.lo = 5000;
        byte_line.hi = 9000;
        store.append_days(&[byte_line]).unwrap();
        let mut row_line = day("/f", 0, 100);
        row_line.lo = 0;
        row_line.hi = 10;
        row_line.full = true;
        store.append_days(&[row_line]).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            100,
            "the full rescan replaced the byte-range aggregate"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_truncated_from_origin_line_supersedes_only_what_it_read() {
        // A deadline-truncated first scan emits [0,k) with `full=false`:
        // it must kill the overlapping part of the old coverage but leave
        // ranges beyond what it re-read untouched — the completing pass
        // will supersede the rest later.
        let dir = tmpdir("trunc");
        let mut store = HistoryStore::open(&dir).unwrap();
        let mut old = day("/f", 0, 100);
        old.lo = 100;
        old.hi = 200;
        store.append_days(&[old]).unwrap();
        let mut partial = day("/f", 0, 50);
        partial.lo = 0;
        partial.hi = 50;
        // `full` left false: [0,50) doesn't overlap [100,200), so the old
        // line must survive the truncated pass.
        store.append_days(&[partial]).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            150,
            "100 (unread tail) + 50 (re-derived prefix)"
        );
        // The completing pass covers the whole file and claims it.
        let mut complete = day("/f", 0, 150);
        complete.lo = 0;
        complete.hi = 200;
        complete.full = true;
        store.append_days(&[complete]).unwrap();
        assert_eq!(store.live_days().map(|d| d.input).sum::<u64>(), 150);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn seal_batch_mates_survive_a_reload() {
        // A file whose records span two hours emits one `full` line per
        // bucket in a single append. On reload each line folds in file
        // order — without the batch id the second seal would mistake the
        // first for stale coverage and kill it.
        let dir = tmpdir("batchmates");
        let mut store = HistoryStore::open(&dir).unwrap();
        let mut h10 = day("/f", 0, 100);
        h10.hour = "2026-09-22T10".into();
        h10.lo = 0;
        h10.hi = 500;
        h10.full = true;
        let mut h11 = day("/f", 0, 60);
        h11.hour = "2026-09-22T11".into();
        h11.lo = 500;
        h11.hi = 1000;
        h11.full = true;
        store.append_days(&[h10, h11]).unwrap();
        store.commit().unwrap();
        drop(store);
        let store = HistoryStore::open(&dir).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            160,
            "both hour buckets survive the reload fold"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_seal_still_kills_older_batches() {
        // Batch-mates are protected; an earlier batch's lines are not —
        // even when a line sits in a different bucket of the same file.
        let dir = tmpdir("batchkill");
        let mut store = HistoryStore::open(&dir).unwrap();
        let mut stale = day("/f", 0, 70);
        stale.hour = "2026-09-22T09".into();
        stale.lo = 5000;
        stale.hi = 9000;
        store.append_days(&[stale]).unwrap();
        let mut cur = day("/f", 0, 120);
        cur.lo = 0;
        cur.hi = 1000;
        cur.full = true;
        store.append_days(&[cur]).unwrap();
        store.commit().unwrap();
        drop(store);
        let store = HistoryStore::open(&dir).unwrap();
        assert_eq!(store.live_days().map(|d| d.input).sum::<u64>(), 120);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_full_seal_reaches_stale_lines_in_other_buckets_of_the_file() {
        // Attribution can drift between schema versions: the same file's
        // v1 line can sit in a different hour/model bucket than the v2
        // rescan emits. A seal is file-scoped — it re-derived the whole
        // contribution, so the drifted bucket dies with the rest.
        let dir = tmpdir("xseal");
        let mut store = HistoryStore::open(&dir).unwrap();
        let mut drifted = day("/f", 0, 60);
        drifted.hour = "2026-09-22T10".into();
        drifted.lo = 5000;
        drifted.hi = 9000;
        let mut prefix = day("/f", 0, 50);
        prefix.lo = 0;
        prefix.hi = 50;
        store.append_days(&[drifted, prefix]).unwrap();
        let mut tail = day("/f", 0, 150);
        tail.lo = 50;
        tail.hi = 200;
        tail.full = true;
        store.append_days(&[tail]).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            200,
            "50 (prefix) + 150 (tail); the drifted-bucket line died too"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_completing_resume_seals_coverage_and_keeps_its_prefix_chain() {
        // The truncated-first-scan split: pass 1 emitted [0,50), pass 2
        // resumed and reached the end with [50,200). Together they
        // re-derive the file — the seal must keep the chain segment
        // [0,50) (its tokens are not re-emitted) while killing stale
        // lines in any coordinate space, like a v1 byte-range leftover.
        let dir = tmpdir("seal");
        let mut store = HistoryStore::open(&dir).unwrap();
        let mut alien = day("/f", 0, 70);
        alien.lo = 5000;
        alien.hi = 9000; // a v1 byte range — never overlaps row ranges
        let mut prefix = day("/f", 0, 50);
        prefix.lo = 0;
        prefix.hi = 50;
        store.append_days(&[alien, prefix]).unwrap();
        let mut tail = day("/f", 0, 150);
        tail.lo = 50;
        tail.hi = 200;
        tail.full = true;
        store.append_days(&[tail]).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            200,
            "50 (prefix chain) + 150 (completing tail); the alien line died"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_tombstone_seals_a_source_that_now_has_no_records() {
        // A complete pass that found zero records emits no bucket — but
        // still owns the coverage claim. The tombstone carries the seal,
        // so stale lines of the same (file, gen) die instead of summing
        // forever.
        let dir = tmpdir("tombstone");
        let mut store = HistoryStore::open(&dir).unwrap();
        let mut stale = day("/f", 0, 80);
        stale.lo = 0;
        stale.hi = 100;
        store.append_days(&[stale]).unwrap();
        let mut tomb = day("/f", 0, 0);
        tomb.messages = 0;
        tomb.lo = 0;
        tomb.hi = 0;
        tomb.full = true;
        store.append_days(&[tomb]).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            0,
            "the stale line dies under the empty-source seal"
        );
        store.commit().unwrap();
        drop(store);
        let store = HistoryStore::open(&dir).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            0,
            "and stays dead across a reload"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stale_line_inside_the_prefix_span_cannot_steal_the_chain() {
        // Sort order must not decide which `[0, hi)` line is the "real"
        // chain head: the greedy cover takes the farthest-reaching tile,
        // so a stale short prefix dies and the true chain survives whole.
        let dir = tmpdir("chaincover");
        let mut store = HistoryStore::open(&dir).unwrap();
        // Stale drifted-bucket line that sorts *before* the real chain.
        let mut stale = day("/f", 0, 30);
        stale.hour = "2026-09-22T09".into();
        stale.lo = 0;
        stale.hi = 30;
        store.append_days(&[stale]).unwrap();
        // The real prefix chain: [0,50) + [50,100).
        let mut c1 = day("/f", 0, 50);
        c1.lo = 0;
        c1.hi = 50;
        store.append_days(&[c1]).unwrap();
        let mut c2 = day("/f", 0, 60);
        c2.lo = 50;
        c2.hi = 100;
        store.append_days(&[c2]).unwrap();
        // The completing pass seals at [100, 200).
        let mut seal = day("/f", 0, 150);
        seal.lo = 100;
        seal.hi = 200;
        seal.full = true;
        store.append_days(&[seal]).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            260,
            "50 + 60 (real chain) + 150 (seal); the stale 30-token prefix died"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stale_overlapping_step_loses_to_the_fresher_chain() {
        // Crash-artifact shape: a pass appended S [0,60) but died before
        // commit, so the retry re-derived the span as [0,50)+[50,100).
        // The seal must keep the fresh disjoint chain and kill the stale
        // overlapping step — keeping both would double-count [50,60).
        let dir = tmpdir("stalestep");
        let mut store = HistoryStore::open(&dir).unwrap();
        let mut s = day("/f", 0, 60);
        s.hour = "2026-09-22T09".into();
        s.lo = 0;
        s.hi = 60;
        store.append_days(&[s]).unwrap(); // batch 1 — crashed pass
        let mut l1 = day("/f", 0, 50);
        l1.hour = "2026-09-22T10".into();
        l1.lo = 0;
        l1.hi = 50;
        store.append_days(&[l1]).unwrap(); // batch 2
        let mut l2 = day("/f", 0, 50);
        l2.hour = "2026-09-22T11".into();
        l2.lo = 50;
        l2.hi = 100;
        store.append_days(&[l2]).unwrap(); // batch 3
        let mut seal = day("/f", 0, 100);
        seal.lo = 100;
        seal.hi = 200;
        seal.full = true;
        store.append_days(&[seal]).unwrap(); // batch 4
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            200,
            "50 + 50 + 100; the stale overlapping [0,60) step died"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_legacy_seal_kills_stale_ranges_and_keeps_shape_mates() {
        // Pre-batch-id lines all deserialize with `b = 0`. If mates were
        // matched on `b` alone, a legacy seal would call every older line
        // of the generation a batch-mate and never kill stale coverage.
        // The mate test is the full `(b, lo, hi)` shape: one append emits
        // one range, so equal shape is the best legacy proxy for
        // "same append".
        let dir = tmpdir("legacyseal");
        fs::create_dir_all(&dir).unwrap();
        let line = |hour: &str, lo: u64, hi: u64, full: bool, input: u64| {
            format!(
                r#"{{"v":{SCHEMA_VERSION},"hour":"{hour}","provider":"claude","project":"p","model":"m","session":"s","file":"/f","gen":0,"lo":{lo},"hi":{hi},"full":{full},"input":{input},"output":0,"cache_read":0,"cache_write":0,"thinking":0,"messages":1}}"#
            )
        };
        fs::write(
            dir.join("days.jsonl"),
            [
                line("2026-09-22T09", 0, 60, false, 60), // stale overlapping step
                line("2026-09-22T10", 0, 50, false, 50), // the real chain
                line("2026-09-22T11", 50, 100, false, 50),
                line("2026-09-22T12", 100, 200, true, 100), // seal, bucket 1
                line("2026-09-22T13", 100, 200, true, 100), // seal, bucket 2
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();
        let store = HistoryStore::open(&dir).unwrap();
        let live: Vec<_> = store.live_days().cloned().collect();
        assert_eq!(
            live.iter().map(|d| d.input).sum::<u64>(),
            300,
            "50 + 50 + 100 + 100: stale [0,60) dies, both seal shape-mates live"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn compaction_reindexes_by_file_before_the_next_seal() {
        // `maybe_compact_days` shortens `days`; a `by_file` index left
        // pointing at pre-compaction positions either indexes out of
        // bounds or folds a seal against unrelated lines. Pad the file
        // past the 16 MB threshold, kill a line in-session so the
        // compaction actually drops rows, then seal — the fold must see
        // the compacted layout, not the old one.
        let dir = tmpdir("compact");
        let mut store = HistoryStore::open(&dir).unwrap();
        let mut a = day("/f", 0, 100);
        a.lo = 0;
        a.hi = 100;
        let mut b = day("/f", 0, 150);
        b.lo = 0;
        b.hi = 150;
        store.append_days(&[a, b]).unwrap(); // b supersedes a → dead
                                             // Padding: a single unparseable line past the compact threshold.
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(dir.join("days.jsonl"))
            .unwrap();
        use std::io::Write as _;
        writeln!(f, "{}", "x".repeat(17 * 1024 * 1024)).unwrap();
        drop(f);
        store.commit().unwrap(); // compacts
        assert_eq!(store.days.len(), 1, "dead line + junk compacted away");
        // The seal's fold touches by_file — stale indexes panic or
        // corrupt here.
        let mut seal = day("/f", 0, 1000);
        seal.lo = 150;
        seal.hi = 1000;
        seal.full = true;
        store.append_days(&[seal]).unwrap();
        assert_eq!(store.live_days().map(|d| d.input).sum::<u64>(), 1150);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_counts_only_its_latest_live_generation() {
        // If a file leaves `state.files` (state rebuilt, roots narrowed),
        // nothing suppresses its superseded generations anymore — counting
        // them would double-spend rewritten history. The file's latest
        // *live* generation stands in as its watermark; a same-gen file
        // that was deleted still counts in full.
        let dir = tmpdir("missinggen");
        let mut store = HistoryStore::open(&dir).unwrap();
        store.append_days(&[day("/f", 0, 10)]).unwrap();
        store
            .state
            .files
            .insert("/f".to_string(), FileState::fresh("d".into(), 1, 1));
        store
            .file_state_mut(Path::new("/f"))
            .unwrap()
            .reset("d2".into(), 2, 2);
        store.append_days(&[day("/f", 1, 7)]).unwrap();
        assert_eq!(store.live_days().map(|d| d.input).sum::<u64>(), 7);

        store.state.files.remove("/f"); // the state entry is gone
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            7,
            "the superseded gen-0 line must not revive without state"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_mid_file_seal_still_keeps_its_chain() {
        // A complete pass resumed mid-file seals with `lo > 0`: the chain
        // tiling `[0, lo)` survives, anything else of the generation dies.
        let dir = tmpdir("midseal");
        let mut store = HistoryStore::open(&dir).unwrap();
        let mut c1 = day("/f", 0, 40);
        c1.lo = 0;
        c1.hi = 40;
        store.append_days(&[c1]).unwrap();
        let mut seal = day("/f", 0, 160);
        seal.lo = 40;
        seal.hi = 200;
        seal.full = true;
        store.append_days(&[seal]).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            200,
            "40 (chain) + 160 (seal)"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_store_stays_send_for_the_scan_worker_to_hand_across_threads() {
        // The scan worker builds its own `HistoryStore` off the UI thread
        // and sends the finished one back over a channel — a type that
        // stopped being `Send` (an `Rc` slipped into the liveness cache,
        // say) would only fail at that one call site, far from here.
        fn assert_send<T: Send>() {}
        assert_send::<HistoryStore>();
    }

    #[test]
    fn live_days_cache_reflects_every_kind_of_mutation_on_the_next_call() {
        // The liveness answer is memoized. Each of these mutations — a
        // superseding generation, a tombstone, and a compaction — must be
        // visible on the very next `live_days()` call, not eventually.
        let dir = tmpdir("cache-reflects");
        let mut store = HistoryStore::open(&dir).unwrap();
        store.append_days(&[day("/f", 0, 10)]).unwrap();
        store
            .state_mut()
            .files
            .insert("/f".to_string(), FileState::fresh("d".into(), 1, 1));
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            10,
            "cache populated at gen 0"
        );

        // A superseding generation: the cached gen-0 answer must not stick.
        store
            .file_state_mut(Path::new("/f"))
            .unwrap()
            .reset("d2".into(), 2, 2);
        store.append_days(&[day("/f", 1, 7)]).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            7,
            "the next call must see the bumped generation, not the cached one"
        );

        // A tombstone seals the generation on top of the same cached call.
        let mut tomb = day("/f", 1, 0);
        tomb.lo = 0;
        tomb.hi = 0;
        tomb.full = true;
        store.append_days(&[tomb]).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            0,
            "the tombstone's seal must be visible on the very next call"
        );

        // Compaction rewrites `days` and reindexes every position the
        // cache's indices pointed at; pad the file past the threshold
        // (unparseable junk the store never folds in) so `commit` runs it.
        store.append_days(&[day("/g", 0, 3)]).unwrap();
        assert_eq!(store.live_days().count(), 2, "cache populated once more");
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(dir.join("days.jsonl"))
            .unwrap();
        use std::io::Write as _;
        writeln!(f, "{}", "x".repeat(17 * 1024 * 1024)).unwrap();
        drop(f);
        store.commit().unwrap(); // compacts, reindexing every live position
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            3,
            "compaction must not leave the cache pointing at stale positions"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_commit_with_no_mutation_since_the_last_one_leaves_the_state_file_untouched() {
        let dir = tmpdir("commit-clean");
        let mut store = HistoryStore::open(&dir).unwrap();
        store
            .state_mut()
            .files
            .insert("/f".to_string(), FileState::fresh("d".into(), 1, 1));
        store.commit().unwrap();
        let path = dir.join("state.json");
        let before_meta = fs::metadata(&path).unwrap();
        let before_bytes = fs::read(&path).unwrap();

        // Nothing touches `state` between these — both must be no-ops.
        store.commit().unwrap();
        store.commit().unwrap();

        let after_meta = fs::metadata(&path).unwrap();
        let after_bytes = fs::read(&path).unwrap();
        assert_eq!(before_bytes, after_bytes, "the bytes must not change");
        assert_eq!(
            before_meta.modified().unwrap(),
            after_meta.modified().unwrap(),
            "an unmodified state must not be rewritten at all, not just rewritten identically"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_commit_after_file_state_mut_changes_rewrites_the_state_file() {
        let dir = tmpdir("commit-dirty");
        let mut store = HistoryStore::open(&dir).unwrap();
        store
            .state_mut()
            .files
            .insert("/f".to_string(), FileState::fresh("d".into(), 1, 1));
        store.commit().unwrap();
        let path = dir.join("state.json");
        let before_bytes = fs::read(&path).unwrap();

        store
            .file_state_mut(Path::new("/f"))
            .unwrap()
            .reset("d2".into(), 2, 2);
        store.commit().unwrap();

        let after_bytes = fs::read(&path).unwrap();
        assert_ne!(
            before_bytes, after_bytes,
            "the bumped generation must have reached disk"
        );
        // The rewrite through `BufWriter` must round-trip exactly like the
        // unbuffered write it replaced — `open` reading the new bytes back
        // and finding gen 1 is the proof.
        let reopened = HistoryStore::open(&dir).unwrap();
        assert_eq!(reopened.file_state(Path::new("/f")).unwrap().gen, 1);
        let _ = fs::remove_dir_all(&dir);
    }
}
