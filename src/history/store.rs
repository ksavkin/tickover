//! Persistent history state: per-file scan cursors plus the append-only
//! bucket log everything aggregates from.
//!
//! Two files under `<config>/tickover/history/`, both owned by this app —
//! the provider's own directories are never written to:
//!
//! * `state.json` — [`ScannerState`]: a map of scanned file → [`FileState`]
//!   (size, mtime, cursor, prefix digest, generation, dedup ring). Rewritten
//!   atomically (tmp + rename) like `config.rs` does; an older or unreadable
//!   file is quarantined aside and rebuilt from a full rescan rather than
//!   trusted, while a *newer* one — a downgrade — is left in place and this
//!   run starts empty instead. Known narrow gap: a crash between an append
//!   and the commit *plus* a file-order change on retry can leave one
//!   cross-file duplicate counted twice — the committed day line carries no
//!   dedup key to recognize its twin by. Day lines stay aggregates; the
//!   residual is one event, not a class of them.
//! * `days.jsonl` — append-only [`DayLine`] records, one per
//!   (hour, provider, project, model, session, file generation). Never
//!   edited in place: a file that was rewritten gets a new `gen`, and its
//!   older lines stop counting at query time instead of being deleted. Once
//!   the log passes a size threshold a compaction rewrite drops whatever has
//!   become genuinely dead — a provider whose log only ever grows, or whose
//!   rewrites never complete a pass long enough to seal a newer generation,
//!   never produces anything genuinely dead and keeps growing past it.

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
/// per-file ring because this is what stands between a record and being
/// recounted when it arrives via a second file on a later pass. Bounded,
/// not absolute: a live re-sighting keeps an id touched indefinitely, but
/// one that goes quiet for longer than this ring holds ages out, and a
/// second file emitting it afterward is indistinguishable from a
/// genuinely new record.
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

/// [`HistoryStore::commit`] considers rewriting `days.jsonl` from this size
/// up, and again each time it has grown half as much as the last rewrite
/// left it ([`ScannerState::compacted_size`]). A scanner pass writes one line
/// per bucket, so a session polled every few minutes spends most of the file
/// on lines that differ only in their byte range;
/// [`HistoryStore::checkpointed_days`] folds those together. What is left
/// grows with real activity (one line per hour, session, model and file), not
/// with the number of passes, and nothing here caps that: every line is the
/// only record of usage, often from a transcript the provider has deleted.
const DAYS_COMPACT_BYTES: u64 = 4 * 1024 * 1024;

/// How many `state.corrupt-*.json` snapshots [`HistoryStore::open`] keeps —
/// enough to look back past more than one incident without letting a
/// standing corruption (or a downgrade that repeatedly meets an unreadable
/// file) accumulate one more file on every run forever.
const MAX_CORRUPT_BACKUPS: usize = 3;

/// One file's scan progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileState {
    /// Byte size at last scan, from `stat`.
    pub size: u64,
    /// Modification time at last scan, seconds since the epoch.
    pub mtime: i64,
    /// How far this file has been consumed. The meaning belongs to the
    /// format: a byte offset past the last complete line for JSONL. SQLite
    /// does not resume from here at all — Antigravity keeps its own row
    /// watermark in `aux["max_idx"]` and only ever writes `0` (pass
    /// incomplete) or `size` (pass reached the end) here, so the
    /// scanner's unchanged check still has a byte-shaped answer to
    /// compare. Either way it only ever moves forward within one `gen`.
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
    /// Set once, at [`Self::fresh`] or [`Self::reset`], and never widened
    /// on the append path that follows: a file first seen at 600 bytes
    /// keeps a 600-byte rewrite-detection span for as long as it is
    /// tracked, even long after it has grown past [`PREFIX_BYTES`] — only
    /// a genuine rewrite (which calls [`Self::reset`]) re-measures it
    /// against the file's current size.
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
    /// needs remembered is the format's business, and the store never
    /// reads or interprets a key here. Not exclusively the extractor's,
    /// though: the scanner keeps its own `"wal"` key alongside them, for
    /// the signature a `watches_wal` format's unchanged check needs.
    #[serde(default)]
    pub aux: BTreeMap<String, serde_json::Value>,
    /// The highest generation of this file that a `full` line has ever
    /// sealed, `None` for an entry that predates this field or has never
    /// sealed anything. [`Self::gen`] deriving sealed-ness fresh from
    /// `days.jsonl` on every call cannot survive a reopen: a seal's own
    /// line can be superseded by a later same-bucket line (an ordinary,
    /// correct supersession — a crash-then-deadline retry re-reading the
    /// same bytes), and the moment that happens to coincide with a reopen,
    /// `open`'s own load-time cleanup physically drops the now-dead row
    /// before anything gets a chance to notice it was ever `full` —
    /// there is no line left to read `full` from at all. This field is
    /// the fact surviving in a *second* place on purpose: it is written
    /// monotonically, the moment a `full` line is folded in, capped at
    /// [`Self::gen`] so a relic day line from an unrelated earlier life
    /// (delete-and-recreate, a schema rebuild, a downgrade) can never
    /// raise it — `open` parses `state.json`, and so this file's current
    /// `gen`, before it ever folds a single line of `days.jsonl`, so that
    /// cap is live on every reopen, not only the pass that first wrote
    /// the value. [`Self::reset`] does not clear it — a rewrite bumping
    /// the generation is exactly when the older generation's sealed-ness
    /// still matters.
    #[serde(default)]
    pub sealed_through: Option<u32>,
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
            sealed_through: None,
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
    /// [`HistoryStore::open`] advances this in memory on every open, a
    /// read-only session that never calls `append_days` included — a
    /// harmless waste rather than a leak, since the value is a pure
    /// function of `days.jsonl`'s own recorded ids and is never persisted
    /// unless something else already dirties `state`.
    #[serde(default)]
    pub next_batch: u64,
    /// The generation a path had already *resolved to*
    /// ([`HistoryStore::target_gen`]) the moment
    /// [`HistoryStore::prune_missing_files`] removed its `files` entry —
    /// not the raw tracked `gen`, which on its own would silently discard
    /// whatever [`FileState::sealed_through`] was holding the figure back
    /// to (a rewrite whose rescan had not produced anything yet, held at
    /// its last sealed generation). `days.jsonl` alone cannot tell a file
    /// recreated at a lower generation from one whose higher-numbered
    /// history simply predates it — both look like "the biggest
    /// generation this path has ever recorded" to a reader with no other
    /// information — so the one moment that does know which generation
    /// was truly current writes the already-resolved answer down here
    /// before the entry, and the fact it depended on, disappears. A path
    /// that no longer exists can never move again, so this number is
    /// permanent for as long as the entry is. Cleared the moment the path
    /// is tracked again (`begin_file`): a live `files` entry is always
    /// the more accurate source once one exists.
    #[serde(default)]
    pub pruned_generations: BTreeMap<String, u32>,
    /// `days.jsonl`'s size after the last compaction check that ran, whether
    /// or not it found anything to do — the second half of the trigger in
    /// [`HistoryStore::maybe_compact_days`]. Without it, a file past
    /// [`DAYS_COMPACT_BYTES`] would pay for that search on every commit.
    #[serde(default)]
    pub compacted_size: u64,
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

    /// Whether this bucket records anything happening at all — some
    /// tokens or some request. A coverage tombstone always reads `false`
    /// here (it carries none of either, by construction), but so does any
    /// other line that happens to sum to nothing: the question is what the
    /// line records, not why it was written, so the query layer can treat
    /// both alike without knowing tombstones exist.
    pub fn has_activity(&self) -> bool {
        self.sum() > 0 || self.messages > 0
    }

    /// Fold `other`'s counters into this line. Only ever called with lines of
    /// one [`BucketKey`], so attribution needs no merging.
    fn absorb(&mut self, other: &DayLine) {
        self.v = self.v.max(other.v);
        self.input += other.input;
        self.output += other.output;
        self.cache_read += other.cache_read;
        self.cache_write += other.cache_write;
        self.thinking += other.thinking;
        self.messages = self.messages.saturating_add(other.messages);
    }
}

/// Bucket identity for range supersession: same file, generation, hour
/// and attribution. Two lines sharing it with overlapping byte ranges
/// are the same bytes parsed twice — the newer one wins.
type BucketKey = (String, u32, String, String, String, String, String);

/// [`HistoryStore::generation_maps`]'s answer: per-file current generation
/// (from `state.files`), newest generation any non-dead line has reached,
/// and newest generation a `full` line has actually sealed.
type GenerationMaps<'a> = (
    HashMap<&'a str, u32>,
    HashMap<&'a str, u32>,
    HashMap<&'a str, u32>,
);

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
    /// `true` when `open` found a `state.json` from a *newer* schema — a
    /// downgrade, not corruption. The file was left exactly where it was
    /// rather than quarantined, so nothing here may ever write over it:
    /// `commit` checks this before every `state.json` rewrite, for the
    /// life of this store, however many scans run in between — and skips
    /// compacting `days.jsonl` too, since a compacting rewrite would write
    /// it from this run's in-memory `days`, which `open` already built
    /// with every newer-schema line dropped. The cost is that a downgraded
    /// run remembers nothing across restarts — every process start
    /// rebuilds `state` from scratch and re-derives whatever it touches —
    /// and `days.jsonl` cannot shrink no matter how large it grows, until
    /// the machine is upgraded back to the version that owns the file, at
    /// which point both are exactly as that version left them.
    foreign_newer_state: bool,
    /// Whether [`Self::prune_missing_files`] has already run once for this
    /// store instance. A `stat` per tracked entry adds up on a machine
    /// with ten thousand of them, and the caller that matters
    /// (`spawn_history_scan`) opens the store once and runs up to eight
    /// scan ticks inside the same lock — paying the whole sweep again on
    /// every one of them would buy no new information, since a file
    /// confirmed gone on tick one is still gone on tick eight. Limiting
    /// the sweep to one call per store instance reduces the syscall count
    /// for one run; it does not remove the risk, since no `stat` here
    /// carries a timeout, so one unresponsive network volume still blocks
    /// whichever tick's turn it is to run the (now singular) sweep.
    missing_files_pruned: bool,
}

impl HistoryStore {
    pub fn state_path(dir: &Path) -> PathBuf {
        dir.join("state.json")
    }
    pub fn days_path(dir: &Path) -> PathBuf {
        dir.join("days.jsonl")
    }

    /// Open (or create) the store under `dir`. A missing directory is made;
    /// an unreadable or *older*-schema `state.json` is moved aside to
    /// `state.corrupt-<secs>.json` and rebuilt empty — the next scan
    /// repopulates it from scratch. A *newer*-schema file is a downgrade,
    /// not corruption: it is left exactly where it is (see
    /// [`Self::foreign_newer_state`]) and this run starts empty instead.
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
        let (state, state_dirty, foreign_newer_state) =
            match fs::read_to_string(Self::state_path(dir)) {
                Ok(text) => match serde_json::from_str::<ScannerState>(&text) {
                    Ok(s) if s.version == SCHEMA_VERSION => (s, false, false),
                    Ok(s) if s.version > SCHEMA_VERSION => {
                        // A build newer than this one wrote it — the data is
                        // intact and belongs to a version that will come back.
                        // Renaming it aside would be indistinguishable from
                        // discarding it the moment that version runs again.
                        (ScannerState::default(), true, true)
                    }
                    _ => {
                        let aside = dir.join(format!(
                            "state.corrupt-{}.json",
                            chrono::Utc::now().timestamp()
                        ));
                        let _ = fs::rename(Self::state_path(dir), aside);
                        (ScannerState::default(), true, false)
                    }
                },
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    (ScannerState::default(), true, false)
                }
                Err(e) => return Err(e),
            };
        // One corruption or downgrade-then-corruption incident leaves one
        // more `state.corrupt-*.json` behind, and nothing else ever cleans
        // them up — prune every time `open` runs, not only the run that
        // just made one, so backups already sitting here from before this
        // check existed get swept too.
        prune_corrupt_backups(dir);
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
            foreign_newer_state,
            missing_files_pruned: false,
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
            // Recorded on the tracked `FileState` itself, monotonically —
            // see [`FileState::sealed_through`] for why a fact derived
            // fresh from `days.jsonl` on every call is not enough to
            // survive a reopen on its own. Capped at the file's own
            // current generation, `st.gen`: `open` parses `state.json`
            // before it folds `days.jsonl`, so a file is already tracked
            // by the time this runs on the load loop, and a line whose
            // `gen` exceeds `st.gen` can only be a relic of an earlier,
            // unrelated life (delete-and-recreate, a schema rebuild, a
            // downgrade) — the same relic [`Self::generation_maps`]'s own
            // walk excludes. Without this cap here, that relic would be
            // absorbed into the persisted high-water mark on every single
            // reopen, permanently, since this path runs on every load —
            // not merely once, the way appending the relic live would.
            // Only marked dirty when the value actually moves — this runs
            // on every `full` line folded, including every unchanged
            // reload of an already-sealed file.
            let sealed_grew = self.state.files.get_mut(&d.file).is_some_and(|st| {
                if d.gen > st.gen {
                    return false;
                }
                let merged = st.sealed_through.map_or(d.gen, |s| s.max(d.gen));
                let grew = st.sealed_through != Some(merged);
                st.sealed_through = Some(merged);
                grew
            });
            if sealed_grew {
                self.mark_state_dirty();
            }
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
    /// Also clears any [`ScannerState::pruned_generations`] entry for
    /// `path`: a live `FileState` is always the more accurate source once
    /// one exists again, and the recorded generation has done its job the
    /// moment tracking resumes.
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
        let key = path.to_string_lossy().into_owned();
        self.state.pruned_generations.remove(&key);
        self.state.files.entry(key).or_insert_with(|| {
            let mut st = FileState::fresh(digest, size, mtime);
            st.provider = provider.to_string();
            st
        });
    }

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
        // Lines already queued earlier in this same call: a caller
        // offering the same line twice in one batch must not slip past
        // `seen_lines` just because neither copy has reached disk yet —
        // both would otherwise carry the same fresh `b` and be accepted
        // as each other's batch-mate rather than caught as a repeat.
        let mut batch_lines: std::collections::HashSet<String> = std::collections::HashSet::new();
        for d in new {
            let mut d = d.clone();
            d.b = batch;
            let line = serde_json::to_string(&d).map_err(io::Error::other)?;
            // Byte-identical = the crash-rescan artifact, already on disk.
            // A post-crash retry carries a fresh `b`, so it serializes
            // differently — but its identical range still supersedes the
            // copy that made it to disk, so the duplicate can't count.
            if self.seen_lines.contains(&line) || !batch_lines.insert(line.clone()) {
                continue;
            }
            accepted.push((line, d));
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
    /// disk, and never when [`Self::foreign_newer_state`] is set — then
    /// compact `days.jsonl` if [`Self::maybe_compact_days`]'s size trigger
    /// says so (that trigger is unconditional; a `days.jsonl`-only pass with
    /// an untouched `state` still needs to compact) — *unless*
    /// `foreign_newer_state` is set, in which case compaction is skipped
    /// too: `open` already dropped every line a newer schema wrote from
    /// this run's in-memory `days` (any `v` greater than
    /// [`SCHEMA_VERSION`]), and a compacting rewrite writes `days.jsonl`
    /// from that same memory — running it here would erase the newer
    /// build's own lines from disk, exactly what leaving `state.json`
    /// alone is meant to prevent. The cost is the same as leaving
    /// `state.json` unwritten: no reclamation while downgraded, however
    /// large `days.jsonl` grows in the meantime. The dirty guard earns its
    /// keep at this call's frequency: a scan pass that touched no file
    /// still calls it once per manifest, `tickover stats` calls it dozens
    /// of times a run, and `state.files` serialises to several megabytes on
    /// a machine with ten thousand tracked files. The write that does
    /// happen goes through a `BufWriter` into the private tmp file
    /// [`create_private`] makes, flushed before `sync_data` and renamed
    /// over the target, so a reader never sees a half-written state.
    /// `days.jsonl` needs none of this — it only ever appends new lines.
    pub fn commit(&mut self) -> io::Result<()> {
        self.write_state()?;
        if self.foreign_newer_state {
            return Ok(());
        }
        self.maybe_compact_days()?;
        // A second write, after the compaction, only when it recorded a new
        // `compacted_size`. The cursors a checkpoint trusted were already on
        // disk from the write above; a crash between the two costs one
        // repeated check.
        self.write_state()
    }

    /// The `state.json` half of [`Self::commit`].
    fn write_state(&mut self) -> io::Result<()> {
        if !self.state_dirty || self.foreign_newer_state {
            return Ok(());
        }
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
        Ok(())
    }

    /// Day lines that still count: a line is stale only when its file is
    /// still tracked at a *newer, sealed* generation — see
    /// [`Self::target_gen`] for exactly which generation that is. Lines
    /// from a file that has since been deleted keep counting — the usage
    /// happened; the provider removing its log does not un-spend the
    /// tokens — but only the newest generation's: without the state entry
    /// nothing suppresses superseded generations, so the file's latest
    /// *live* gen stands in as its remembered watermark.
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
    /// whose generation matches [`Self::target_gen`] for its file — or,
    /// for a file [`Self::target_gen`] returns `None` for (neither tracked
    /// nor in [`ScannerState::pruned_generations`]), one at that file's
    /// own newest surviving
    /// generation. Split out so [`Self::live_days`] only ever calls it
    /// through the cache.
    fn compute_live_indices(&self) -> Vec<usize> {
        let maps = self.generation_maps();
        let (_, last_live, _) = &maps;
        self.days
            .iter()
            .enumerate()
            .filter(|(i, d)| {
                !self.dead.contains(i)
                    && match Self::target_gen(&maps, d.file.as_str()) {
                        Some(target) => d.gen == target,
                        None => last_live.get(d.file.as_str()) == Some(&d.gen),
                    }
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// The three per-file generation facts [`Self::target_gen`] needs: the
    /// state's current generation, the newest generation any non-dead
    /// line has reached, and the newest generation a `full` line has
    /// actually sealed (absent for a file still on its first, still-
    /// partial scan — there is nothing yet to fall back to for one).
    fn generation_maps(&self) -> GenerationMaps<'_> {
        let mut current: HashMap<&str, u32> = self
            .state
            .files
            .iter()
            .map(|(p, s)| (p.as_str(), s.gen))
            .collect();
        // A path recorded in `pruned_generations` is treated exactly like
        // a tracked one for `target_gen`'s purposes — its generation just
        // came from the moment it stopped being tracked instead of from a
        // live `FileState`. A path cannot be both tracked and recorded
        // here (`begin_file` clears the entry the moment it retracks a
        // path), so `files` and `pruned_generations` never really compete;
        // `or_insert` is only defensive.
        for (p, &g) in &self.state.pruned_generations {
            current.entry(p.as_str()).or_insert(g);
        }
        let mut last_live: HashMap<&str, u32> = HashMap::new();
        // Seeded from each tracked file's own persisted high-water mark
        // before the `days` walk below ever raises it — see
        // [`FileState::sealed_through`] for why deriving this fresh from
        // `days.jsonl` alone, every call, cannot survive a reopen: the
        // seal's own line can die to an ordinary supersession, and if that
        // coincides with a reopen, `open`'s load-time cleanup drops the
        // now-dead row before any fresh derivation would ever see it was
        // `full`. The seeded value needs no cap against `current` here the
        // way the walk's own contributions do below: `fold_line` already
        // refuses to raise `sealed_through` past the file's own tracked
        // `gen` at the point it is written (a relic day line above it is
        // exactly the case that cap exists for), so by the time it lands
        // in `state.files` it is already `<= current[file]`.
        let mut sealed_gen: HashMap<&str, u32> = self
            .state
            .files
            .iter()
            .filter_map(|(p, s)| s.sealed_through.map(|g| (p.as_str(), g)))
            .collect();
        // A pruned path's recorded generation is already the resolved
        // target — `prune_missing_files` computed it by calling
        // `target_gen` itself, at the moment the `FileState` (and its
        // `sealed_through`) was still there to read. Once that entry is
        // gone, nothing seeds `sealed_gen` for the path any more, so the
        // walk below would start it from scratch and could rebuild it
        // from whatever `full` line it finds — including one at a lower
        // generation the file had already moved past before it was ever
        // swept, which reads as "sealed" only because sealing never un-
        // happens, not because it is still the file's newest one. Seeding
        // here pins the entry at the recorded number before that walk
        // runs: `current[file]` for a pruned path is exactly that same
        // number, so the walk's own cap keeps it from ever being raised
        // any further, and the plain-max fold it performs can never lower
        // it either. `or_insert` only matters for a path recorded here
        // while still tracked — normally impossible (`begin_file` clears
        // the entry the moment it retracks a path) — so an existing
        // `state.files`-seeded value always wins.
        for (p, &g) in &self.state.pruned_generations {
            sealed_gen.entry(p.as_str()).or_insert(g);
        }
        for (i, d) in self.days.iter().enumerate() {
            // A generation that once reached the end of its source has
            // reached it, permanently — sealing is a fact about the
            // generation, not about the one line that happened to record
            // it. A later same-bucket line can still supersede *that
            // line* (a crash-then-deadline retry re-reads the same bytes
            // and legitimately wins the ordinary overlap rule), but it
            // does not un-finish the pass that sealed the generation, so
            // `sealed_gen` reads every `full` line regardless of whether
            // it is still live. `sealed_gen` only ever increases for a
            // file this way: nothing here, and no supersession elsewhere,
            // can un-seal a generation once one of its lines has been
            // `full` — which is what makes it safe for
            // `compute_droppable_indices` to delete a generation the
            // moment a higher one seals: no future call can walk that
            // deletion back by falling to a lower target than the seal
            // already promised.
            //
            // Capped at the file's current generation (tracked, or
            // recorded in `pruned_generations`): a `full` line *above*
            // that number is not a candidate a
            // rewrite could ever have produced — cursors only move
            // forward within a generation and a new one only ever starts
            // at the file's own next number — so it can only be a relic
            // of an earlier, unrelated life (the same recreate/rebuild/
            // downgrade case `target_gen` already treats as a dead end).
            // Taking the plain maximum over every `full` line regardless
            // of that would let one such relic hide a *real*, lower
            // sealed generation this file's current lineage actually
            // produced — the newest sealed generation would silently stop
            // being the newest one under this cap's number and start
            // being the newest one under an unrelated life's, which is
            // never the intended fallback.
            if d.full && current.get(d.file.as_str()).is_none_or(|&cap| d.gen <= cap) {
                let e = sealed_gen.entry(d.file.as_str()).or_insert(d.gen);
                if d.gen > *e {
                    *e = d.gen;
                }
            }
            if self.dead.contains(&i) {
                continue;
            }
            let e = last_live.entry(d.file.as_str()).or_insert(d.gen);
            if d.gen > *e {
                *e = d.gen;
            }
        }
        (current, last_live, sealed_gen)
    }

    /// The one generation a file's lines must carry to count as live —
    /// the single source [`Self::compute_live_indices`] and
    /// [`Self::compute_droppable_indices`] both read, so the two can never
    /// disagree about which generation currently speaks for a file.
    ///
    /// `None` for a file with neither a `state.files` entry nor a
    /// [`ScannerState::pruned_generations`] one: there is no current
    /// generation to target at all, and both callers fall back to the
    /// file's newest surviving (non-dead) generation instead — the only
    /// case this residual fallback still needs to cover is data from
    /// before `pruned_generations` existed. For a tracked file, or one
    /// recorded there, the target is its generation *if that generation
    /// is sealed*, or otherwise the
    /// newest generation this file *has* sealed at or below it — a
    /// rewrite bumps the tracked generation the instant it is detected,
    /// before the rescan it triggers has re-derived anything, so a
    /// not-yet-sealed current generation defers to the last complete
    /// figure rather than the unsealed slice produced so far.
    ///
    /// "At or below it" is load-bearing: [`Self::generation_maps`] caps
    /// what counts as sealed for this purpose at the file's own
    /// generation, so a `full` line above it — always a relic of an
    /// unrelated earlier life, since a generation only ever advances by
    /// one and cursors only move forward within it — cannot masquerade as
    /// "the newest sealed generation" and hide a real, lower one this
    /// file's actual lineage produced.
    ///
    /// A file with no sealed generation at or below its own has nothing to
    /// defer to, so the target is simply the current generation itself,
    /// tracked or recorded — whatever that generation's own lines say, live
    /// or not yet begun. Two shapes reach this: a file still on its
    /// first-ever, still-partial scan (no sealed generation exists at
    /// all), and a file whose state was dropped and recreated (deletion,
    /// a `prune_missing_files` sweep, a `SCHEMA_VERSION` reset, a
    /// downgrade) while a sealed generation from its previous life is
    /// still sitting in `days.jsonl` at a number *higher* than the fresh
    /// one — capped out of consideration by the same rule above, so it
    /// never lends its figure to the file's new life.
    fn target_gen(maps: &GenerationMaps<'_>, file: &str) -> Option<u32> {
        let (current, _, sealed_gen) = maps;
        let gen = *current.get(file)?;
        Some(match sealed_gen.get(file) {
            Some(&sealed) if sealed < gen => sealed,
            _ => gen,
        })
    }

    /// Indices compaction may physically drop: [`Self::dead`] lines —
    /// already superseded within their own generation — plus lines whose
    /// generation misses [`Self::target_gen`] *and* whose file has since
    /// sealed a strictly *later* generation than the line's own — the
    /// only thing that actually makes an earlier generation obsolete. The
    /// second test is load-bearing on its own, not merely a mirror of
    /// "not live": a mid-rescan file with an unsealed current generation
    /// misses the target too (the target is the last sealed generation,
    /// not the in-progress one), but nothing has sealed *past* it yet, so
    /// its lines are not droppable — dropping them here would be
    /// permanent, and the seal that finishes the rescan still needs them
    /// to complete its prefix chain. The same test is what keeps a file
    /// back at a lower generation than one it had already sealed (see
    /// [`Self::target_gen`]'s last case) from losing that older sealed
    /// line to compaction: nothing has sealed past *that* generation
    /// either, so it is retained — permanently, until this file's fresh
    /// life reaches and seals past it in turn. A file no longer in
    /// `state.files` drops everything but its own newest surviving
    /// generation, same as [`Self::live_days`]'s deleted-file fallback.
    fn compute_droppable_indices(&self) -> std::collections::HashSet<usize> {
        let maps = self.generation_maps();
        let (_, last_live, sealed_gen) = &maps;
        self.days
            .iter()
            .enumerate()
            .filter(|(i, d)| {
                self.dead.contains(i)
                    || match Self::target_gen(&maps, d.file.as_str()) {
                        Some(target) => {
                            d.gen != target
                                && sealed_gen
                                    .get(d.file.as_str())
                                    .is_some_and(|&sealed| sealed > d.gen)
                        }
                        None => last_live.get(d.file.as_str()) != Some(&d.gen),
                    }
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// Compact `days.jsonl` once it has reached [`DAYS_COMPACT_BYTES`] and
    /// grown half again past the size the last check left it at — a file that
    /// sits just over the threshold must not be rewritten on every commit
    /// that turns up one dead line.
    fn maybe_compact_days(&mut self) -> io::Result<()> {
        let path = Self::days_path(&self.dir);
        let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if size < DAYS_COMPACT_BYTES.max(self.state.compacted_size.saturating_mul(3) / 2) {
            return Ok(());
        }
        self.compact_days()
    }

    /// Rewrite `days.jsonl` dropping genuinely dead lines
    /// ([`Self::compute_droppable_indices`]) and folding pass-by-pass lines
    /// together ([`Self::checkpointed_days`]). Not the same set
    /// [`Self::live_days`] shows: a line mid-rescan and not yet sealed is
    /// hidden from the live figure but kept on disk, because the seal that
    /// will complete it still needs it.
    ///
    /// Runs under [`lock_store`], on a store `open` read fresh: the rewrite
    /// comes from this process's memory, so a stale one would lose lines.
    fn compact_days(&mut self) -> io::Result<()> {
        let path = Self::days_path(&self.dir);
        let droppable = self.compute_droppable_indices();
        let Some(keep) = self.checkpointed_days(&droppable) else {
            let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            self.record_compacted_size(size);
            return Ok(());
        };
        let tmp = self.dir.join("days.jsonl.tmp");
        let mut seen_lines = std::collections::HashSet::with_capacity(keep.len());
        let written;
        {
            let mut f = create_private(&tmp)?;
            let mut buf = Vec::new();
            for d in &keep {
                let line = serde_json::to_string(d).map_err(io::Error::other)?;
                buf.extend_from_slice(line.as_bytes());
                buf.push(b'\n');
                seen_lines.insert(line);
            }
            f.write_all(&buf)?;
            // Not `.ok()`: this rewrite replaces lines that may be the only
            // record of a deleted transcript, so it must not take the place
            // of the old file before its bytes are known to be on disk.
            f.sync_data()?;
            written = buf.len() as u64;
        }
        fs::rename(&tmp, &path)?;
        #[cfg(unix)]
        if let Ok(d) = fs::File::open(&self.dir) {
            d.sync_all().ok();
        }
        // Reindex in place — compaction changes every index, so both
        // maps must be rebuilt, not just `by_key`: a stale `by_file`
        // index either points past the shortened `days` (panic) or at
        // an unrelated line (a seal then kills coverage it never read).
        self.days = keep;
        self.seen_lines = seen_lines;
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
        // The indices `compute_droppable_indices` returned above point at
        // positions in the old `days` — every one of them is wrong now
        // that the array has been rewritten shorter, and so is anything
        // `live_days` had cached before this call.
        self.invalidate_live_cache();
        self.record_compacted_size(written);
        Ok(())
    }

    fn record_compacted_size(&mut self, size: u64) {
        self.state.compacted_size = size;
        self.mark_state_dirty();
    }

    /// The lines a compaction should write: everything outside `droppable`,
    /// with each file [`Self::checkpoint_of`] accepts reduced to its
    /// checkpoint. `None` when that would change nothing.
    fn checkpointed_days(
        &self,
        droppable: &std::collections::HashSet<usize>,
    ) -> Option<Vec<DayLine>> {
        let maps = self.generation_maps();
        let mut by_file: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, d) in self.days.iter().enumerate() {
            if !droppable.contains(&i) {
                by_file.entry(d.file.as_str()).or_default().push(i);
            }
        }
        let mut replaced: HashMap<usize, DayLine> = HashMap::new();
        let mut absorbed: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for (file, idxs) in &by_file {
            let Some(lines) = self.checkpoint_of(file, idxs, &maps) else {
                continue;
            };
            for &i in idxs {
                absorbed.insert(i);
            }
            for (i, line) in lines {
                absorbed.remove(&i);
                replaced.insert(i, line);
            }
        }
        if droppable.is_empty() && absorbed.is_empty() {
            return None;
        }
        Some(
            self.days
                .iter()
                .enumerate()
                .filter(|(i, _)| !droppable.contains(i) && !absorbed.contains(i))
                .map(|(i, d)| replaced.remove(&i).unwrap_or_else(|| d.clone()))
                .collect(),
        )
    }

    /// One file's lines folded into one line per bucket, each paired with the
    /// index of the line it takes the place of (the bucket's first, so a
    /// session's first project stays first) — or `None` when the file must be
    /// left alone, or folding it would save nothing.
    ///
    /// Every line of a checkpoint carries the same `(b, 0, H)`, and that is
    /// the point: to [`Self::fold_line`] they are then one step of the prefix
    /// chain, whose seal keeps them all and whose successor starts at `H`.
    /// Giving each bucket its own merged range instead would leave steps that
    /// overlap, and the next seal kills the older of two overlapping steps.
    ///
    /// Each refusal below is a way `[0, H)` could claim more than is settled:
    ///
    /// * more than one generation, or not the one the live figure reads: a
    ///   rescan is under way and its seal still needs the old lines;
    /// * the freshest step is not a seal reaching `H`: the pass that would
    ///   vouch for the whole range never finished;
    /// * activity without a range: a line from before ranges existed, which
    ///   the seal logic treats differently and this must not relabel;
    /// * `H` past the committed cursor: a pass wrote these lines and died
    ///   before `commit`. Its retry starts below `H`, and would overlap every
    ///   checkpoint line of its buckets instead of the one pass's bytes;
    /// * row coordinates (`aux["max_idx"]`, Antigravity): `lo`/`hi` count rows
    ///   while `cursor` is `0` or the file's size, so the cursor test above
    ///   would pass without meaning anything.
    ///
    /// A file no longer tracked has no pass to retry, so the last two do not
    /// apply to it. [`DayLine::full`] on the merged lines is not a new claim:
    /// the freshest step already sealed the generation.
    fn checkpoint_of(
        &self,
        file: &str,
        idxs: &[usize],
        maps: &GenerationMaps<'_>,
    ) -> Option<Vec<(usize, DayLine)>> {
        if idxs.len() < 2 {
            return None;
        }
        let gen = self.days[idxs[0]].gen;
        if idxs.iter().any(|&i| self.days[i].gen != gen)
            || Self::target_gen(maps, file).is_some_and(|target| target != gen)
        {
            return None;
        }
        let h = idxs.iter().map(|&i| self.days[i].hi).max()?;
        // Same freshness `fold_line` orders candidate steps by.
        let freshest = *idxs.iter().max_by_key(|&&i| (self.days[i].b, i))?;
        if !self.days[freshest].full || self.days[freshest].hi != h {
            return None;
        }
        if idxs.iter().any(|&i| {
            let d = &self.days[i];
            d.has_activity() && d.hi <= d.lo
        }) {
            return None;
        }
        if let Some(st) = self.state.files.get(file) {
            if st.gen != gen || h > st.cursor || st.aux.contains_key("max_idx") {
                return None;
            }
        }
        let mut buckets: HashMap<BucketKey, usize> = HashMap::new();
        let mut lines: Vec<(usize, DayLine)> = Vec::new();
        for &i in idxs {
            let d = &self.days[i];
            if !d.has_activity() {
                continue;
            }
            match buckets.entry(bucket_key(d)) {
                std::collections::hash_map::Entry::Occupied(e) => {
                    lines[*e.get()].1.absorb(d);
                }
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(lines.len());
                    lines.push((i, d.clone()));
                }
            }
        }
        if lines.is_empty() {
            // Nothing but coverage: the seal alone has to survive a reload.
            return Some(vec![(freshest, self.days[freshest].clone())]);
        }
        if lines.len() == idxs.len() {
            return None;
        }
        let b = self.days[freshest].b;
        for (_, line) in &mut lines {
            line.b = b;
            line.lo = 0;
            line.hi = h;
            line.full = true;
        }
        Some(lines)
    }

    /// Drop state for a path once its file is confirmed gone or replaced
    /// by something the scanner's walk will never offer again: a bare
    /// `NotFound` from `stat`ing the exact path, or a successful `stat`
    /// reporting something other than a regular file. The root a
    /// manifest resolves can differ between the
    /// tray process and `tickover stats` (a different `CODEX_HOME` or
    /// `CLAUDE_CONFIG_DIR` in one of the two environments), and pruning by
    /// "no active root reaches this path any more" let each process's
    /// tick prune the *other's* still-live files out from under it —
    /// confirming against the filesystem itself needs no notion of roots
    /// at all, and both processes agree on what it says. An unreadable
    /// root, an unmounted volume, or a permission failure surface as some
    /// other `io::Error`, never `NotFound` — so they keep the entry
    /// rather than costing a cursor, same as a successful stat of a
    /// regular file does. `symlink_metadata` rather than `metadata`: a
    /// dangling symlink standing in a tracked file's place resolves to
    /// nothing through `metadata` (misread as some other I/O error, not
    /// `NotFound`), while `symlink_metadata` sees the link itself and
    /// reports it as the non-regular-file case — `collect`'s walk never
    /// follows symlinks and its own `is_file()` check excludes them, so
    /// without this a path that has been replaced by a symlink, dangling
    /// or not, would never be re-offered *and* never be pruned, stuck
    /// exactly like an entry for a file that was deleted with nothing
    /// left in its place.
    ///
    /// Their day lines keep counting regardless (history once recorded
    /// stays) — at whichever generation the path was tracked at just
    /// before this call, recorded into
    /// [`ScannerState::pruned_generations`] before the `files` entry
    /// disappears. `days.jsonl` alone cannot tell that generation apart
    /// from a higher one sitting in the same file from a still-earlier
    /// life (delete-and-recreate, a `SCHEMA_VERSION` rebuild, a
    /// downgrade): both look like "the biggest generation ever recorded
    /// for this path" to a reader with nothing else to go on, and the
    /// higher one is not always the more recent — this is the only moment
    /// that knows which one actually was, and this record is what lets
    /// [`Self::generation_maps`] answer correctly for however long the
    /// path stays untracked. If a path is recreated later, a fresh scan's
    /// overlapping ranges supersede the old lines at load, and
    /// [`Self::begin_file`] clears the record the same moment. A file
    /// leaving `state.files` can flip its day lines onto this fallback, so
    /// the liveness cache invalidates even when nothing was actually
    /// confirmed gone — but `state` itself is only dirtied when something
    /// was actually removed: this runs on every scan tick regardless, and
    /// a dirty mark on every no-op call would leave `commit` rewriting
    /// `state.json` on every tick again, the very rewrite the dirty flag
    /// exists to skip.
    ///
    /// Cost: a file that still exists but has fallen outside every
    /// enabled manifest's root — the root itself narrowed, not the file —
    /// is no longer pruned here; it sits in `state.files` unreachable
    /// until the file itself is actually deleted.
    ///
    /// The global ring is deliberately left untouched here. A dropped
    /// path's day lines are still live (just above), so the ids they
    /// represent are still live too, and must keep blocking a *different*
    /// path from claiming them — releasing them the way a rewrite does
    /// would open exactly that double count. The ownership only goes stale
    /// once the path's *own* state is gone, and staleness only matters the
    /// moment a fresh scan resurrects it: that is `scan_root`'s job (the
    /// `None` arm of its match, where `begin_file` registers a path with no
    /// prior state), not this one's — see the release call planted there.
    /// Runs at most once per store instance — see
    /// [`Self::missing_files_pruned`]. A caller that wants a fresh sweep
    /// (a long-lived process holding one store across many hours) has to
    /// open a new [`HistoryStore`] for it; nothing here re-arms the guard.
    pub fn prune_missing_files(&mut self) -> usize {
        if self.missing_files_pruned {
            return 0;
        }
        self.missing_files_pruned = true;
        self.invalidate_live_cache();
        let gone: Vec<String> = self
            .state
            .files
            .keys()
            .filter(|p| match fs::symlink_metadata(Path::new(p.as_str())) {
                Err(e) => e.kind() == io::ErrorKind::NotFound,
                Ok(meta) => !meta.file_type().is_file(),
            })
            .cloned()
            .collect();
        if gone.is_empty() {
            return 0;
        }
        // Each swept path's resolved *target*, not its raw tracked `gen`
        // — computed now, while the path is still tracked, because this
        // is the last moment anything can compute it: `sealed_through`
        // disappears the instant its `FileState` does. A file that no
        // longer exists can never move again, so recording where it had
        // already resolved to is exactly what stays true forever; the
        // raw `gen` alone would silently discard whatever `sealed_through`
        // was holding it back to. `generation_maps` borrows `&self`, so
        // every target is read into an owned `Vec` before the removal
        // loop below takes `&mut self.state.files`.
        let maps = self.generation_maps();
        let targets: Vec<(String, u32)> = gone
            .iter()
            .filter_map(|p| Self::target_gen(&maps, p).map(|g| (p.clone(), g)))
            .collect();
        drop(maps);
        for p in &gone {
            self.state.files.remove(p);
        }
        for (p, g) in targets {
            self.state.pruned_generations.insert(p, g);
        }
        self.mark_state_dirty();
        gone.len()
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

/// Delete every `state.corrupt-*.json` in `dir` beyond the
/// [`MAX_CORRUPT_BACKUPS`] most recent, oldest epoch first. The epoch is
/// parsed back out of the name and compared as the integer it is, not as
/// a string: lexical order lets a stray file whose suffix happens to sort
/// last (`state.corrupt-zzz.json`, or simply a wider number of digits)
/// outrank every real backup and evict the one `open` just made. A name
/// whose suffix doesn't parse as one is left alone entirely — neither
/// counted against the cap nor deleted — rather than guessed at.
///
/// The epoch is whole seconds (`chrono::Utc::now().timestamp()` at the
/// write site in [`HistoryStore::open`]), so two quarantines within the
/// same second produce the same name; the `rename` that creates the
/// second one then silently overwrites the first rather than erroring —
/// accepted here as the cost of a scheme that names files after nothing
/// but a wall-clock reading, since two corruption events one second apart
/// are not a case this store expects to need forensics for.
///
/// Runs from every [`HistoryStore::open`], with no distinction for a
/// caller that only ever reads the result — the read-only store handle
/// the panel keeps for itself, and `tickover stats`, both prune here too.
/// The alternative would be threading a "will this open write?" flag
/// through every call site for the sake of a handful of quarantine files
/// that are not the store's live data in the first place.
///
/// Best-effort throughout: a listing, parse, or delete failure here must
/// not fail `open` over files that are not the store's live data.
fn prune_corrupt_backups(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut backups: Vec<(u64, PathBuf)> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let epoch: u64 = name
                .strip_prefix("state.corrupt-")?
                .strip_suffix(".json")?
                .parse()
                .ok()?;
            Some((epoch, e.path()))
        })
        .collect();
    if backups.len() <= MAX_CORRUPT_BACKUPS {
        return;
    }
    backups.sort_by_key(|&(epoch, _)| epoch);
    for (_, path) in &backups[..backups.len() - MAX_CORRUPT_BACKUPS] {
        let _ = fs::remove_file(path);
    }
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

    /// One scanner pass: a line per `(hour, input)` over one shared range,
    /// the way `scan_root` emits them.
    fn pass(
        store: &mut HistoryStore,
        file: &str,
        range: (u64, u64),
        full: bool,
        buckets: &[(&str, u64)],
    ) {
        let lines: Vec<DayLine> = buckets
            .iter()
            .map(|&(hour, input)| {
                let mut d = day(file, 0, input);
                d.hour = hour.to_string();
                d.lo = range.0;
                d.hi = range.1;
                d.full = full;
                d
            })
            .collect();
        store.append_days(&lines).unwrap();
    }

    fn tombstone(store: &mut HistoryStore, file: &str, lo: u64, hi: u64) {
        let mut d = day(file, 0, 0);
        d.messages = 0;
        d.project = String::new();
        d.model = String::new();
        d.session = String::new();
        d.lo = lo;
        d.hi = hi;
        d.full = true;
        store.append_days(&[d]).unwrap();
    }

    fn track(store: &mut HistoryStore, file: &str, cursor: u64) {
        let mut st = FileState::fresh("d".into(), cursor, 1);
        st.cursor = cursor;
        store.state.files.insert(file.to_string(), st);
    }

    /// Live input per hour, sorted — what a checkpoint must leave unchanged.
    fn live_by_hour(store: &HistoryStore) -> BTreeMap<String, u64> {
        let mut out = BTreeMap::new();
        for d in store.live_days() {
            if d.has_activity() {
                *out.entry(d.hour.clone()).or_default() += d.input;
            }
        }
        out
    }

    fn line_count(dir: &Path) -> usize {
        fs::read_to_string(dir.join("days.jsonl"))
            .unwrap()
            .lines()
            .count()
    }

    #[test]
    fn a_checkpoint_folds_passes_into_one_line_per_bucket_and_keeps_every_token() {
        let dir = tmpdir("checkpoint-folds");
        let mut store = HistoryStore::open(&dir).unwrap();
        track(&mut store, "/f", 300);
        pass(&mut store, "/f", (0, 100), true, &[("h1", 1), ("h2", 2)]);
        pass(&mut store, "/f", (100, 200), true, &[("h2", 4)]);
        pass(&mut store, "/f", (200, 300), true, &[("h2", 8)]);
        let before = live_by_hour(&store);
        assert_eq!(line_count(&dir), 4);

        store.compact_days().unwrap();

        assert_eq!(line_count(&dir), 2);
        assert_eq!(live_by_hour(&store), before);
        assert_eq!(store.seen_lines.len(), 2, "seen_lines must shrink with it");
        let reopened = HistoryStore::open(&dir).unwrap();
        assert_eq!(live_by_hour(&reopened), before, "and survive a reload");
        assert!(reopened
            .days
            .iter()
            .all(|d| d.full && d.lo == 0 && d.hi == 300));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_seal_after_a_checkpoint_keeps_the_whole_checkpoint() {
        let dir = tmpdir("checkpoint-next-seal");
        let mut store = HistoryStore::open(&dir).unwrap();
        track(&mut store, "/f", 200);
        pass(&mut store, "/f", (0, 100), true, &[("h1", 1)]);
        pass(&mut store, "/f", (100, 200), true, &[("h1", 2), ("h2", 4)]);
        store.compact_days().unwrap();

        // A bucket the next pass touches and one it does not: only a shared
        // step keeps both alive under this seal.
        pass(&mut store, "/f", (200, 300), true, &[("h1", 8)]);
        let want = BTreeMap::from([("h1".to_string(), 11), ("h2".to_string(), 4)]);
        assert_eq!(live_by_hour(&store), want);
        let reopened = HistoryStore::open(&dir).unwrap();
        assert_eq!(live_by_hour(&reopened), want);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_truncated_pass_after_a_checkpoint_leaves_it_alone() {
        let dir = tmpdir("checkpoint-truncated");
        let mut store = HistoryStore::open(&dir).unwrap();
        track(&mut store, "/f", 200);
        pass(&mut store, "/f", (0, 100), true, &[("h1", 1)]);
        pass(&mut store, "/f", (100, 200), true, &[("h1", 2)]);
        store.compact_days().unwrap();
        pass(&mut store, "/f", (200, 250), false, &[("h1", 4)]);
        let want = BTreeMap::from([("h1".to_string(), 7)]);
        assert_eq!(live_by_hour(&store), want);
        let reopened = HistoryStore::open(&dir).unwrap();
        assert_eq!(live_by_hour(&reopened), want);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_checkpoint_folds_the_first_one_in() {
        let dir = tmpdir("checkpoint-twice");
        let mut store = HistoryStore::open(&dir).unwrap();
        track(&mut store, "/f", 300);
        pass(&mut store, "/f", (0, 100), true, &[("h1", 1), ("h2", 2)]);
        pass(&mut store, "/f", (100, 200), true, &[("h1", 4)]);
        store.compact_days().unwrap();
        pass(&mut store, "/f", (200, 300), true, &[("h1", 8)]);
        let before = live_by_hour(&store);
        store.compact_days().unwrap();
        assert_eq!(line_count(&dir), 2);
        assert_eq!(live_by_hour(&store), before);
        assert_eq!(live_by_hour(&HistoryStore::open(&dir).unwrap()), before);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_checkpoint_refuses_a_pass_the_cursor_has_not_committed() {
        // The crash window: lines on disk past the committed cursor. The
        // retry starts at the cursor and overlaps them; a checkpoint would
        // have stretched that overlap over the whole file.
        let dir = tmpdir("checkpoint-crash");
        let mut store = HistoryStore::open(&dir).unwrap();
        track(&mut store, "/f", 100);
        pass(&mut store, "/f", (0, 100), true, &[("h1", 1)]);
        pass(&mut store, "/f", (100, 200), true, &[("h1", 2)]);
        store.compact_days().unwrap();
        assert_eq!(line_count(&dir), 2, "the file must be left alone");

        pass(&mut store, "/f", (100, 200), true, &[("h1", 4)]);
        assert_eq!(
            live_by_hour(&store),
            BTreeMap::from([("h1".to_string(), 5)])
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_checkpoint_refuses_a_chain_no_seal_vouches_for() {
        let dir = tmpdir("checkpoint-unsealed");
        let mut store = HistoryStore::open(&dir).unwrap();
        track(&mut store, "/open", 200);
        pass(&mut store, "/open", (0, 100), true, &[("h1", 1)]);
        pass(&mut store, "/open", (100, 200), false, &[("h1", 2)]);
        // `fold_line` kills any line past a seal's `lo`, so a freshest seal
        // short of `H` takes editing memory to reach; refused all the same.
        track(&mut store, "/short", 300);
        pass(&mut store, "/short", (0, 100), true, &[("h1", 4)]);
        pass(&mut store, "/short", (100, 200), true, &[("h1", 8)]);
        let first = store.days.iter().position(|d| d.file == "/short").unwrap();
        store.days[first].hi = 300;
        store.compact_days().unwrap();
        assert_eq!(line_count(&dir), 4);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_checkpoint_refuses_row_coordinates_until_the_file_is_gone() {
        let dir = tmpdir("checkpoint-rows");
        let mut store = HistoryStore::open(&dir).unwrap();
        track(&mut store, "/db", 1_000_000);
        store
            .state
            .files
            .get_mut("/db")
            .unwrap()
            .aux
            .insert("max_idx".to_string(), serde_json::json!(7));
        pass(&mut store, "/db", (0, 5), true, &[("h1", 1)]);
        pass(&mut store, "/db", (5, 7), true, &[("h1", 2)]);
        store.compact_days().unwrap();
        assert_eq!(line_count(&dir), 2);

        store.state.files.remove("/db");
        store.state.pruned_generations.insert("/db".to_string(), 0);
        store.compact_days().unwrap();
        assert_eq!(line_count(&dir), 1);
        assert_eq!(
            live_by_hour(&store),
            BTreeMap::from([("h1".to_string(), 3)])
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_checkpoint_refuses_activity_with_no_range() {
        // A seal kills a rangeless line behind it, so only one that sorts
        // older than the seal yet sits after it survives to reach this check:
        // legacy lines all carry `b = 0`.
        let dir = tmpdir("checkpoint-legacy");
        let mut store = HistoryStore::open(&dir).unwrap();
        track(&mut store, "/f", 200);
        pass(&mut store, "/f", (0, 100), true, &[("h1", 1)]);
        pass(&mut store, "/f", (100, 200), true, &[("h1", 2)]);
        store.append_days(&[day("/f", 0, 4)]).unwrap();
        store.days[2].b = 0;
        store.compact_days().unwrap();
        assert_eq!(line_count(&dir), 3, "the file must be left alone");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_checkpoint_refuses_a_file_held_at_an_older_generation() {
        // A rewrite bumped the generation and its rescan has not sealed: the
        // figure still reads the old one, and that rescan needs it intact.
        let dir = tmpdir("checkpoint-rewrite");
        let mut store = HistoryStore::open(&dir).unwrap();
        track(&mut store, "/f", 200);
        pass(&mut store, "/f", (0, 100), true, &[("h1", 1)]);
        pass(&mut store, "/f", (100, 200), true, &[("h1", 2)]);
        store.state.files.get_mut("/f").unwrap().gen = 1;
        let before = live_by_hour(&store);
        store.compact_days().unwrap();
        assert_eq!(line_count(&dir), 2);
        assert_eq!(live_by_hour(&store), before);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tombstones_fold_away_and_an_idle_file_keeps_its_seal() {
        let dir = tmpdir("checkpoint-tombstones");
        let mut store = HistoryStore::open(&dir).unwrap();
        track(&mut store, "/busy", 300);
        pass(&mut store, "/busy", (0, 100), true, &[("h1", 1)]);
        tombstone(&mut store, "/busy", 100, 200);
        tombstone(&mut store, "/busy", 300, 300);
        track(&mut store, "/idle", 300);
        tombstone(&mut store, "/idle", 0, 100);
        tombstone(&mut store, "/idle", 100, 300);
        let before = live_by_hour(&store);

        store.compact_days().unwrap();

        assert_eq!(line_count(&dir), 2);
        assert_eq!(live_by_hour(&store), before);
        let reopened = HistoryStore::open(&dir).unwrap();
        let idle: Vec<_> = reopened.days.iter().filter(|d| d.file == "/idle").collect();
        assert_eq!(idle.len(), 1);
        assert!(idle[0].full, "the seal has to survive the reload");
        assert_eq!((idle[0].lo, idle[0].hi), (100, 300), "and stay as written");
        let busy: Vec<_> = reopened.days.iter().filter(|d| d.file == "/busy").collect();
        assert_eq!(busy.len(), 1);
        assert_eq!((busy[0].lo, busy[0].hi), (0, 300));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_checkpoint_keeps_two_files_of_one_bucket_apart() {
        let dir = tmpdir("checkpoint-two-files");
        let mut store = HistoryStore::open(&dir).unwrap();
        for f in ["/a", "/b"] {
            track(&mut store, f, 200);
            pass(&mut store, f, (0, 100), true, &[("h1", 1)]);
            pass(&mut store, f, (100, 200), true, &[("h1", 2)]);
        }
        store.compact_days().unwrap();
        assert_eq!(line_count(&dir), 2);
        assert_eq!(
            live_by_hour(&store),
            BTreeMap::from([("h1".to_string(), 6)])
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_checkpoint_cannot_change_what_counts_as_sealed() {
        // Compared on a deleted file too: `generation_maps` rebuilds these
        // from the very lines a checkpoint rewrites.
        let dir = tmpdir("checkpoint-maps");
        let mut store = HistoryStore::open(&dir).unwrap();
        track(&mut store, "/live", 200);
        pass(&mut store, "/live", (0, 100), true, &[("h1", 1)]);
        pass(&mut store, "/live", (100, 200), true, &[("h2", 2)]);
        pass(&mut store, "/gone", (0, 100), true, &[("h1", 4)]);
        pass(&mut store, "/gone", (100, 200), true, &[("h1", 8)]);
        store
            .state
            .pruned_generations
            .insert("/gone".to_string(), 0);
        let owned = |s: &HistoryStore| {
            let (current, last_live, sealed) = s.generation_maps();
            let own = |m: HashMap<&str, u32>| -> BTreeMap<String, u32> {
                m.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
            };
            (own(current), own(last_live), own(sealed))
        };
        let before = owned(&store);
        store.compact_days().unwrap();
        assert_eq!(line_count(&dir), 3);
        assert_eq!(owned(&store), before);
        store.commit().unwrap();
        assert_eq!(owned(&HistoryStore::open(&dir).unwrap()), before);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Random honest histories, checkpointed at random moments, against the
    /// same history never checkpointed: the two must read the same at every
    /// step and after a reload. Passes resume at the cursor, sometimes stop
    /// short, sometimes write and crash before their cursor moves, and
    /// sometimes find nothing to emit.
    #[test]
    fn checkpoints_at_random_moments_never_change_the_live_figure() {
        struct Rng(u64);
        impl Rng {
            fn next(&mut self, n: u64) -> u64 {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                self.0 % n
            }
        }
        for seed in 1..=40u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let plain_dir = tmpdir(&format!("checkpoint-sim-plain-{seed}"));
            let folded_dir = tmpdir(&format!("checkpoint-sim-folded-{seed}"));
            let mut plain = HistoryStore::open(&plain_dir).unwrap();
            let mut folded = HistoryStore::open(&folded_dir).unwrap();
            let mut cursors = [0u64; 3];
            let files = ["/a", "/b", "/c"];
            for f in files {
                track(&mut plain, f, 0);
                track(&mut folded, f, 0);
            }
            let mut folded_any = false;
            for step in 0..60u64 {
                let which = rng.next(3) as usize;
                let lo = cursors[which];
                let hi = lo + 1 + rng.next(50);
                let complete = rng.next(4) > 0;
                let crashes = rng.next(6) == 0;
                let empty = rng.next(5) == 0;
                let hours = ["h1", "h2", "h3", "h4"];
                let buckets = [
                    (hours[rng.next(4) as usize], 1 + rng.next(9)),
                    (hours[rng.next(4) as usize], 1 + rng.next(9)),
                ];
                for store in [&mut plain, &mut folded] {
                    if empty && complete {
                        tombstone(store, files[which], lo, hi);
                    } else if buckets[0].0 == buckets[1].0 {
                        let merged = [(buckets[0].0, buckets[0].1 + buckets[1].1)];
                        pass(store, files[which], (lo, hi), complete, &merged);
                    } else {
                        pass(store, files[which], (lo, hi), complete, &buckets);
                    }
                }
                if !crashes {
                    cursors[which] = hi;
                    for store in [&mut plain, &mut folded] {
                        store.state.files.get_mut(files[which]).unwrap().cursor = hi;
                    }
                }
                if rng.next(5) == 0 {
                    let lines = folded.days.len();
                    folded.compact_days().unwrap();
                    folded_any |= folded.days.len() < lines;
                }
                assert_eq!(
                    live_by_hour(&folded),
                    live_by_hour(&plain),
                    "seed {seed} step {step}"
                );
                if rng.next(7) == 0 {
                    plain.commit().unwrap();
                    folded.commit().unwrap();
                    plain = HistoryStore::open(&plain_dir).unwrap();
                    folded = HistoryStore::open(&folded_dir).unwrap();
                    assert_eq!(
                        live_by_hour(&folded),
                        live_by_hour(&plain),
                        "seed {seed} step {step}, after reload"
                    );
                }
            }
            assert!(folded_any, "seed {seed} never exercised a checkpoint");
            let _ = fs::remove_dir_all(&plain_dir);
            let _ = fs::remove_dir_all(&folded_dir);
        }
    }

    #[test]
    fn the_size_trigger_waits_for_half_again_the_last_compaction() {
        let dir = tmpdir("compact-trigger");
        let mut store = HistoryStore::open(&dir).unwrap();
        pass(&mut store, "/f", (0, 100), true, &[("h1", 1)]);
        let pad = |dir: &Path, bytes: u64| {
            let path = dir.join("days.jsonl");
            let f = fs::OpenOptions::new().append(true).open(path).unwrap();
            let len = f.metadata().unwrap().len();
            f.set_len(len + bytes).unwrap();
        };
        let size = |dir: &Path| fs::metadata(dir.join("days.jsonl")).unwrap().len();

        pad(&dir, DAYS_COMPACT_BYTES);
        store.state.compacted_size = 8 * 1024 * 1024;
        store.maybe_compact_days().unwrap();
        assert_eq!(
            store.state.compacted_size,
            8 * 1024 * 1024,
            "under 12 MiB nothing runs, however far past the threshold"
        );

        pad(&dir, 8 * 1024 * 1024 + 1);
        store.maybe_compact_days().unwrap();
        assert!(store.state.compacted_size >= size(&dir));
        assert!(store.state_dirty, "the new size has to reach state.json");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn compacted_size_survives_a_commit_and_an_old_state_file_reads_as_zero() {
        let dir = tmpdir("compacted-size");
        let mut store = HistoryStore::open(&dir).unwrap();
        pass(&mut store, "/f", (0, 100), true, &[("h1", 1)]);
        store.record_compacted_size(123);
        store.commit().unwrap();
        assert!(!store.state_dirty);
        assert_eq!(HistoryStore::open(&dir).unwrap().state.compacted_size, 123);
        let old: ScannerState = serde_json::from_str("{}").unwrap();
        assert_eq!(old.compacted_size, 0);
        let _ = fs::remove_dir_all(&dir);
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
    fn a_newer_schema_state_file_is_left_in_place_not_overwritten() {
        // A downgrade meets a `state.json` a later build wrote. Its data
        // is intact and belongs to the version that will come back — it
        // must not be quarantined, and this run must not write over it
        // even after scanning something of its own.
        let dir = tmpdir("newer-schema");
        let mut newer = ScannerState {
            version: SCHEMA_VERSION + 1,
            ..Default::default()
        };
        newer
            .files
            .insert("/f".to_string(), FileState::fresh("d".into(), 1, 1));
        fs::write(
            HistoryStore::state_path(&dir),
            serde_json::to_string(&newer).unwrap(),
        )
        .unwrap();
        let before = fs::read(HistoryStore::state_path(&dir)).unwrap();

        let mut store = HistoryStore::open(&dir).unwrap();
        assert!(
            store.state.files.is_empty(),
            "a schema this build doesn't understand starts empty rather than misread"
        );
        let quarantined = fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).any(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("state.corrupt-")
        });
        assert!(
            !quarantined,
            "a newer schema is a downgrade, not corruption"
        );

        store.begin_file(Path::new("/g"), "claude", "d".into(), 1, 1);
        store.commit().unwrap();
        let after = fs::read(HistoryStore::state_path(&dir)).unwrap();
        assert_eq!(
            before, after,
            "the newer build's state.json must survive a downgraded run untouched"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_downgraded_run_never_compacts_days_jsonl() {
        // `commit` skips `maybe_compact_days` whenever `foreign_newer_state`
        // is set. A compacting rewrite always writes `days.jsonl` from this
        // run's in-memory `days`, which never holds a newer schema's own
        // lines (`open`'s load loop cannot parse them and drops them on the
        // floor) — running it here would erase those lines from disk
        // instead of merely leaving `state.json` alone, the same data loss
        // the newer-schema guard exists to prevent for the other file.
        let dir = tmpdir("downgrade-skips-compaction");
        let newer = ScannerState {
            version: SCHEMA_VERSION + 1,
            ..Default::default()
        };
        fs::write(
            HistoryStore::state_path(&dir),
            serde_json::to_string(&newer).unwrap(),
        )
        .unwrap();
        // A genuinely droppable line: with `state.files` trusted as empty
        // (the whole point of the newer-schema guard), "/f" is untracked,
        // so gen 0 — superseded by the later, also-untracked gen 1 — is
        // droppable via `compute_droppable_indices`'s untracked-fallback
        // rule without ever touching `self.dead`. That matters here: a
        // range-overlap kill would be resolved in memory by `open`'s own
        // `physically_drop_dead` before `commit` ever ran, leaving nothing
        // for a later compaction to find either way and making this test
        // pass whether or not the guard exists. This one stays droppable
        // at `commit` time regardless.
        let mut gen0 = day("/f", 0, 5);
        gen0.full = true;
        gen0.lo = 0;
        gen0.hi = 100;
        let mut gen1 = day("/f", 1, 7);
        gen1.full = true;
        gen1.lo = 0;
        gen1.hi = 100;
        let mut buf = Vec::new();
        for d in [&gen0, &gen1] {
            serde_json::to_writer(&mut buf, d).unwrap();
            buf.push(b'\n');
        }
        // Past the compaction threshold, and unparseable to this build —
        // exactly what a newer schema's own lines look like here.
        buf.push(b'\n');
        buf.extend_from_slice("x".repeat(17 * 1024 * 1024).as_bytes());
        fs::write(HistoryStore::days_path(&dir), &buf).unwrap();
        let before = fs::read(HistoryStore::days_path(&dir)).unwrap();

        let mut store = HistoryStore::open(&dir).unwrap();
        store.begin_file(Path::new("/g"), "claude", "d".into(), 1, 1);
        store.commit().unwrap();

        let after = fs::read(HistoryStore::days_path(&dir)).unwrap();
        assert_eq!(
            before, after,
            "a downgraded run must never rewrite days.jsonl"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_corrupt_backups_are_pruned_by_parsed_epoch_not_lexical_order() {
        // Real epochs are ten digits today; a lexical string sort gets a
        // shorter or differently-led number wrong — `"1000000000"` sorts
        // *before* `"999999999"` as strings (the first byte '1' loses to
        // '9'), even though it is the larger, newer value. Parsed as the
        // integer it names, order comes out right. An unparseable suffix
        // is left alone entirely: neither evicted nor counted toward the
        // cap.
        let dir = tmpdir("corrupt-backups-numeric");
        fs::create_dir_all(&dir).unwrap();
        for epoch in [
            999_999_999u64,
            1_000_000_000,
            1_000_000_001,
            1_000_000_002,
            1_000_000_003,
        ] {
            fs::write(dir.join(format!("state.corrupt-{epoch}.json")), "{}").unwrap();
        }
        fs::write(dir.join("state.corrupt-not-a-number.json"), "{}").unwrap();
        let _store = HistoryStore::open(&dir).unwrap();
        let mut kept: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("state.corrupt-"))
            .collect();
        kept.sort();
        assert_eq!(
            kept,
            vec![
                "state.corrupt-1000000001.json".to_string(),
                "state.corrupt-1000000002.json".to_string(),
                "state.corrupt-1000000003.json".to_string(),
                "state.corrupt-not-a-number.json".to_string(),
            ],
            "the three newest by parsed epoch survive; the unparseable name is untouched"
        );
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
    fn an_unsealed_rescan_holds_the_last_sealed_generations_figure() {
        // Gen 0 was sealed at 10 by a complete pass. A rewrite bumps the
        // generation and the rescan's first pass lands a partial, unsealed
        // bucket — the file must not read as zero, or as that partial
        // slice, until a `full` line actually seals the new generation.
        let dir = tmpdir("held-gen");
        let mut store = HistoryStore::open(&dir).unwrap();
        let mut sealed0 = day("/f", 0, 10);
        sealed0.full = true;
        store.append_days(&[sealed0]).unwrap();
        store
            .state
            .files
            .insert("/f".to_string(), FileState::fresh("d".into(), 1, 1));
        store.commit().unwrap();
        assert_eq!(store.live_days().map(|d| d.input).sum::<u64>(), 10);

        store
            .file_state_mut(Path::new("/f"))
            .unwrap()
            .reset("d2".into(), 2, 2);
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            10,
            "nothing re-derived yet — the last sealed generation still stands"
        );

        let mut partial = day("/f", 1, 5);
        partial.lo = 0;
        partial.hi = 50;
        store.append_days(&[partial]).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            10,
            "an unsealed partial bucket must not replace the held figure"
        );

        let mut tail = day("/f", 1, 7);
        tail.lo = 50;
        tail.hi = 200;
        tail.full = true;
        store.append_days(&[tail]).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            12,
            "sealed — the new generation's own figures now stand on their own"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn compaction_never_deletes_the_only_live_generation_of_a_file() {
        // A file can land back at a generation *lower* than one it has
        // already sealed: delete-and-recreate (its state entry drops
        // while `days.jsonl` keeps the old sealed lines, then
        // `begin_file` restarts it at gen 0), the next `SCHEMA_VERSION`
        // bump (every older schema is quarantined, so a rewritten log's
        // owner is rediscovered from gen 0 with its sealed history still
        // sitting at a higher gen), or a downgrade. `state.files` says
        // gen 0; `days.jsonl` still has a `full` line at gen 1 from the
        // file's previous life. Liveness then targets gen 0 — the file's
        // only live generation — and compaction must never read the
        // stale sealed gen-1 line as "cover" for it and delete it.
        let dir = tmpdir("recreate-lower-gen");
        let mut store = HistoryStore::open(&dir).unwrap();
        let mut sealed1 = day("/f", 1, 999);
        sealed1.full = true;
        store.append_days(&[sealed1]).unwrap();
        // The file's fresh life: `state.files` says gen 0, same as
        // `FileState::fresh` always starts — whatever dropped the old
        // entry (deletion, a schema rebuild, a downgrade) is already
        // behind this point.
        store
            .state
            .files
            .insert("/f".to_string(), FileState::fresh("d".into(), 1, 1));
        store.append_days(&[day("/f", 0, 7)]).unwrap();
        assert_eq!(store.live_days().map(|d| d.input).sum::<u64>(), 7);

        // Pad past the compaction threshold with raw junk so a real
        // compaction fires.
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(dir.join("days.jsonl"))
            .unwrap();
        use std::io::Write as _;
        writeln!(f, "{}", "x".repeat(17 * 1024 * 1024)).unwrap();
        drop(f);
        store.commit().unwrap(); // compacts

        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            7,
            "gen 0 is the file's only live generation — compaction must not eat it"
        );
        drop(store);
        let store = HistoryStore::open(&dir).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            7,
            "the figure must survive a reopen too"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_revoked_seal_does_not_resurrect_an_already_compacted_generation() {
        // Sealing is a fact about a generation reaching the end of its
        // source, not about the one line that happened to record it. Gen
        // 1 seals at 7; a crash-then-deadline retry (a non-full line
        // whose range overlaps the seal's own) supersedes that specific
        // line by the ordinary same-bucket rule — the retry re-read
        // bytes the seal already accounted for and simply ran out of
        // budget, so its own count (3) is what survives. What must not
        // happen is gen 1 reading as "never sealed" the moment its line
        // dies: that would send `target_gen` looking for the newest
        // *other* sealed generation, which is gen 0 — a generation
        // compaction already trusted the gen-1 seal to justify deleting.
        // Falling back to it here would be inconsistent at best (a
        // number from a rewrite the file has since moved past) and, once
        // compaction has actually removed it, unrecoverable at worst.
        let dir = tmpdir("seal-survives-revocation");
        let mut store = HistoryStore::open(&dir).unwrap();

        let mut sealed0 = day("/f", 0, 10);
        sealed0.full = true;
        store.append_days(&[sealed0]).unwrap();
        store
            .state
            .files
            .insert("/f".to_string(), FileState::fresh("d".into(), 1, 1));
        store
            .file_state_mut(Path::new("/f"))
            .unwrap()
            .reset("d2".into(), 2, 2);

        let mut sealed1 = day("/f", 1, 7);
        sealed1.full = true;
        sealed1.lo = 0;
        sealed1.hi = 20;
        store.append_days(&[sealed1]).unwrap();
        assert_eq!(store.live_days().map(|d| d.input).sum::<u64>(), 7);

        // The crash-then-deadline retry: a non-full re-read of an
        // overlapping span. It legitimately supersedes the seal's own
        // line through the ordinary same-bucket overlap rule — that part
        // of the machinery is untouched and correct.
        let mut retry = day("/f", 1, 3);
        retry.lo = 0;
        retry.hi = 15;
        store.append_days(&[retry]).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            3,
            "gen 1 is still the sealed generation — its own superseded \
             line does not send the target back to gen 0"
        );

        // The log crosses the compaction threshold only now. Gen 0 is
        // droppable exactly because gen 1 sealed at some point — a fact
        // that stands regardless of what later happened to the line
        // that recorded it.
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(dir.join("days.jsonl"))
            .unwrap();
        use std::io::Write as _;
        writeln!(f, "{}", "x".repeat(17 * 1024 * 1024)).unwrap();
        drop(f);
        store.commit().unwrap(); // compacts

        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            3,
            "compaction must not have resurrected gen 0"
        );
        drop(store);
        let store = HistoryStore::open(&dir).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            3,
            "the figure must survive a reopen too"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_seal_below_the_tracked_generation_survives_a_reopen_after_its_line_dies() {
        // The shape that actually exercises the persisted
        // `FileState::sealed_through` field: the sealed generation stays
        // *below* the tracked one across the reopen, so whether the
        // target still resolves to it is the whole question. Deriving
        // "was gen 0 ever sealed" fresh from `days.jsonl` alone cannot
        // answer that once the seal's own line is superseded, because
        // `open`'s load-time cleanup physically drops a dead row before
        // anything gets a chance to read `full` off it — the previous
        // test in this file (the revoked-seal one) never actually
        // exercises this: there, the sealed generation *is* the tracked
        // one, so `target_gen`'s fallback branch lands on the same
        // number whether or not the seal is remembered.
        let dir = tmpdir("seal-below-tracked-survives-reopen");
        let mut store = HistoryStore::open(&dir).unwrap();

        let mut sealed0 = day("/f", 0, 10);
        sealed0.full = true;
        sealed0.lo = 0;
        sealed0.hi = 20;
        store.append_days(&[sealed0]).unwrap();
        store
            .state
            .files
            .insert("/f".to_string(), FileState::fresh("d".into(), 1, 1));

        // A crash-then-deadline retry at the same generation, overlapping
        // the seal's own range — the ordinary same-bucket rule supersedes
        // it, same as always.
        let mut retry = day("/f", 0, 3);
        retry.lo = 0;
        retry.hi = 15;
        store.append_days(&[retry]).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            3,
            "gen 0's own superseded line does not stop gen 0 from still being live"
        );

        // The rewrite that closes gen 0 for good — nothing can ever change
        // whether gen 0 was sealed again after this.
        store
            .file_state_mut(Path::new("/f"))
            .unwrap()
            .reset("d2".into(), 2, 2);
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            3,
            "gen 1 hasn't produced anything yet — gen 0's held figure stands"
        );
        store.commit().unwrap();

        drop(store);
        let store = HistoryStore::open(&dir).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            3,
            "the target must still resolve to gen 0 after a reopen, not \
             fall through to gen 1's still-empty generation just because \
             gen 0's seal's own line did not survive the reload"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pruned_files_stale_generation_does_not_outlive_its_recorded_prune_gen() {
        // A file's old life sealed at gen 1 (999 tokens); it was deleted
        // and rediscovered at gen 0 with its own, unrelated total (7).
        // Both generations' lines still sit in `days.jsonl` — gen 1's
        // because nothing physically removes a merely-not-live line on
        // its own, gen 0's because it is the file's current, correct
        // life. Deleting the file *again*, this time out of its gen-0
        // life, must not let its day lines fall back to whichever
        // generation number happens to be numerically largest.
        let root = tmpdir("prune-gen-root");
        let dir = tmpdir("prune-gen-store");
        let f = root.join("f.jsonl");
        fs::write(&f, b"x").unwrap();
        let key = f.to_string_lossy().into_owned();
        let mut store = HistoryStore::open(&dir).unwrap();

        let mut old_life = day(&key, 1, 999);
        old_life.full = true;
        store.append_days(&[old_life]).unwrap();
        store
            .state
            .files
            .insert(key.clone(), FileState::fresh("d".into(), 1, 1));
        let mut new_life = day(&key, 0, 7);
        new_life.full = true;
        store.append_days(&[new_life]).unwrap();
        assert_eq!(store.live_days().map(|d| d.input).sum::<u64>(), 7);

        fs::remove_file(&f).unwrap();
        assert_eq!(store.prune_missing_files(), 1);
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            7,
            "the file's true last life (gen 0, 7) must survive its \
             deletion, not the numerically larger but unrelated gen 1 (999)"
        );
        store.commit().unwrap();

        drop(store);
        let store = HistoryStore::open(&dir).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            7,
            "the recorded prune generation must survive a reopen too"
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_swept_files_held_figure_survives_the_sweep_that_drops_it() {
        // Gen 0 seals at 10; a crash-then-deadline retry supersedes the
        // seal's own line, so the honest figure is 3. A rewrite moves the
        // file to gen 1, whose rescan has not produced anything yet, so
        // the figure holds at 3 via `sealed_through = Some(0)` while the
        // file stays tracked. The file is then deleted. Recording the raw
        // tracked `gen` (1) at prune time would throw the held figure
        // away — gen 1 has nothing in it — so `prune_missing_files` must
        // record the *resolved target* (0), not the tracked generation.
        let root = tmpdir("swept-held-root");
        let dir = tmpdir("swept-held-store");
        let f = root.join("f.jsonl");
        fs::write(&f, b"x").unwrap();
        let key = f.to_string_lossy().into_owned();
        let mut store = HistoryStore::open(&dir).unwrap();

        let mut sealed0 = day(&key, 0, 10);
        sealed0.full = true;
        sealed0.lo = 0;
        sealed0.hi = 20;
        store.append_days(&[sealed0]).unwrap();
        store
            .state
            .files
            .insert(key.clone(), FileState::fresh("d".into(), 1, 1));

        let mut retry = day(&key, 0, 3);
        retry.lo = 0;
        retry.hi = 15;
        store.append_days(&[retry]).unwrap();
        assert_eq!(store.live_days().map(|d| d.input).sum::<u64>(), 3);

        store.file_state_mut(&f).unwrap().reset("d2".into(), 2, 2);
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            3,
            "held at gen 0's figure while gen 1 has not sealed anything"
        );

        // The file vanishes while still tracked at the unsealed gen 1.
        fs::remove_file(&f).unwrap();
        assert_eq!(store.prune_missing_files(), 1);
        let swept = store.live_days().map(|d| d.input).sum::<u64>();
        assert_eq!(
            swept, 3,
            "the file's held figure must survive the sweep, not fall to \
             gen 1's empty generation just because that was the raw \
             tracked value"
        );
        store.commit().unwrap();

        drop(store);
        let store = HistoryStore::open(&dir).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            3,
            "the recorded target must survive a reopen too"
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_swept_files_recorded_target_is_not_pulled_down_by_a_lower_relic_seal() {
        // Gen 0 seals at 10, and nothing ever marks that line dead — dead-
        // marking only ever competes lines within the same (file, gen)
        // bucket, and gen 0's bucket never sees another line. A rewrite
        // moves the file to gen 1, which also seals, this time at 7; a
        // crash-then-deadline retry then supersedes gen 1's own seal line,
        // settling the figure at 3. `prune_missing_files` must record 1 —
        // the generation the file actually settled at — as the swept
        // path's target, not 0.
        //
        // The reopen before the sweep is load-bearing: it is what
        // physically drops gen 1's now-dead seal line, leaving gen 0's
        // already-superseded seal as the only `full` line still present
        // once the `FileState` is gone. A `sealed_gen` built from scratch
        // by the day-log walk at that point would find only that relic
        // and settle on 0 — a generation the file had already moved past,
        // long before it was ever swept — and drag the recorded target
        // back down to it.
        let root = tmpdir("swept-relic-seal-root");
        let dir = tmpdir("swept-relic-seal-store");
        let f = root.join("f.jsonl");
        fs::write(&f, b"x").unwrap();
        let key = f.to_string_lossy().into_owned();
        let mut store = HistoryStore::open(&dir).unwrap();
        store
            .state
            .files
            .insert(key.clone(), FileState::fresh("d".into(), 1, 1));

        let mut sealed0 = day(&key, 0, 10);
        sealed0.full = true;
        sealed0.lo = 0;
        sealed0.hi = 20;
        store.append_days(&[sealed0]).unwrap();

        store.file_state_mut(&f).unwrap().reset("d2".into(), 2, 2);
        let mut sealed1 = day(&key, 1, 7);
        sealed1.full = true;
        sealed1.lo = 0;
        sealed1.hi = 20;
        store.append_days(&[sealed1]).unwrap();
        assert_eq!(store.live_days().map(|d| d.input).sum::<u64>(), 7);

        let mut retry = day(&key, 1, 3);
        retry.lo = 0;
        retry.hi = 15;
        store.append_days(&[retry]).unwrap();
        assert_eq!(store.live_days().map(|d| d.input).sum::<u64>(), 3);

        store.commit().unwrap();
        drop(store);
        let mut store = HistoryStore::open(&dir).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            3,
            "the tracked figure survives the reopen that drops gen 1's now-dead seal line"
        );

        fs::remove_file(&f).unwrap();
        assert_eq!(store.prune_missing_files(), 1);
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            3,
            "gen 0's relic seal must not pull the recorded target down to itself"
        );
        store.commit().unwrap();

        drop(store);
        let store = HistoryStore::open(&dir).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            3,
            "the recorded target must hold at 1, not the relic's 0, after a further reopen"
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stale_sealed_generation_above_current_does_not_hide_a_real_one_below() {
        // Current gen 2, still mid-rescan (no seal yet). Gen 1
        // legitimately sealed at 10 before the rewrite to gen 2. An
        // ancient, unrelated life also left a sealed gen 5 sitting in
        // `days.jsonl` (from some earlier delete-and-recreate). Its mere
        // presence must not hide gen 1's seal: taking the plain maximum
        // sealed generation over all of history would let gen 5 —
        // irrelevant, above the file's current lineage — stand in for
        // "the newest sealed generation" instead of gen 1, the real one.
        //
        // The reopen is load-bearing, not decoration: `open` parses
        // `state.json` (gen 2) before it ever folds a single line of
        // `days.jsonl`, so the file is already tracked by the time the
        // ancient gen-5 line folds. Without a cap where `sealed_through`
        // is written, that fold would absorb gen 5 into the persisted
        // high-water mark on this very reopen — this test caught exactly
        // that with only the walk capped and the write path left open.
        let dir = tmpdir("stale-above-hides-real-below");
        let mut store = HistoryStore::open(&dir).unwrap();

        let mut ancient = day("/f", 5, 2);
        ancient.full = true;
        store.append_days(&[ancient]).unwrap();

        let mut real_seal = day("/f", 1, 10);
        real_seal.full = true;
        store.append_days(&[real_seal]).unwrap();

        let mut current = FileState::fresh("d".into(), 1, 1);
        current.gen = 2;
        store.state.files.insert("/f".to_string(), current);

        let in_mem = store.live_days().map(|d| d.input).sum::<u64>();
        assert_eq!(
            in_mem, 10,
            "gen 1's real seal must stand in while gen 2 is still \
             mid-rescan, not be hidden by the ancient, irrelevant gen 5"
        );

        store.commit().unwrap();
        drop(store);
        let store = HistoryStore::open(&dir).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            10,
            "the reload folds the ancient gen-5 line while the file is \
             already tracked at gen 2 — it must not be absorbed into \
             sealed_through and hide gen 1's real seal on this pass"
        );
        assert_eq!(
            store.file_state(Path::new("/f")).unwrap().sealed_through,
            Some(1),
            "sealed_through must record gen 1, not the relic gen 5"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn live_and_droppable_never_overlap_across_every_generation_shape() {
        // The shapes a file's (current, sealed) generations can take:
        // steady state, a rescan in progress, a rescan just sealed, and a
        // file back at a generation lower than one it already sealed
        // (delete-and-recreate, a schema rebuild, a downgrade). No line
        // may ever be both live and droppable in any of them — the two
        // sets are read from the same `target_gen` so they cannot
        // disagree, but a shared shortcut computing the same wrong answer
        // twice would still pass this test only by accident, so every
        // shape is checked by hand.
        //
        // This is a structural guard on the two sets agreeing with each
        // other, not a guarantee that what they agree on is correct: a
        // `target_gen` that is shared and wrong would still pass here.
        // `a_revoked_seal_does_not_resurrect_an_already_compacted_generation`
        // is what pins the target's correctness across time — a
        // generation's sealed status must not change once compaction has
        // relied on it, which no single-call snapshot of these two sets
        // can show.
        let dir = tmpdir("live-droppable-invariant");
        let mut store = HistoryStore::open(&dir).unwrap();

        // Steady: current 0, sealed 0.
        let mut steady = day("/steady", 0, 1);
        steady.full = true;
        store.append_days(&[steady]).unwrap();
        store
            .state
            .files
            .insert("/steady".to_string(), FileState::fresh("d".into(), 1, 1));

        // Mid-rescan: current 1, sealed 0.
        let mut mid_sealed = day("/mid", 0, 1);
        mid_sealed.full = true;
        let mut mid_partial = day("/mid", 1, 1);
        mid_partial.lo = 0;
        mid_partial.hi = 10;
        store.append_days(&[mid_sealed, mid_partial]).unwrap();
        let mut mid_state = FileState::fresh("d".into(), 1, 1);
        mid_state.gen = 1;
        store.state.files.insert("/mid".to_string(), mid_state);

        // Rescan just sealed: current 1, sealed 1.
        let mut done_old = day("/done", 0, 1);
        done_old.full = true;
        let mut done_new = day("/done", 1, 1);
        done_new.full = true;
        store.append_days(&[done_old, done_new]).unwrap();
        let mut done_state = FileState::fresh("d".into(), 1, 1);
        done_state.gen = 1;
        store.state.files.insert("/done".to_string(), done_state);

        // Recreate: current 0, sealed 1 — a file back at a lower generation
        // than one it already sealed.
        let mut recreate_sealed = day("/recreate", 1, 1);
        recreate_sealed.full = true;
        let recreate_new = day("/recreate", 0, 1);
        store.append_days(&[recreate_sealed, recreate_new]).unwrap();
        store
            .state
            .files
            .insert("/recreate".to_string(), FileState::fresh("d".into(), 1, 1));

        let live: std::collections::HashSet<usize> =
            store.compute_live_indices().into_iter().collect();
        let droppable = store.compute_droppable_indices();
        let overlap: Vec<usize> = live.intersection(&droppable).copied().collect();
        assert!(
            overlap.is_empty(),
            "live and droppable overlap at indices {overlap:?}"
        );
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
    fn two_identical_lines_offered_in_one_call_fold_only_once() {
        // `seen_lines` guards a repeat across calls (see the test above);
        // a caller offering the very same line twice inside one call must
        // not slip past that guard just because neither copy is on disk
        // yet — both would otherwise carry the same fresh `b` and count
        // as each other's batch-mate.
        let dir = tmpdir("dup-same-batch");
        let mut store = HistoryStore::open(&dir).unwrap();
        store
            .append_days(&[day("/f", 0, 10), day("/f", 0, 10)])
            .unwrap();
        store.commit().unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            10,
            "two identical lines in one batch must fold once, not twice"
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
    fn prune_missing_files_drops_only_a_confirmed_deletion() {
        let root = tmpdir("prune-root");
        let dir = tmpdir("prune-store");
        fs::write(root.join("a.jsonl"), b"x").unwrap();
        let a_key = root.join("a.jsonl").to_string_lossy().into_owned();
        let gone_key = root.join("gone.jsonl").to_string_lossy().into_owned();
        let mut store = HistoryStore::open(&dir).unwrap();
        store
            .state
            .files
            .insert(a_key.clone(), FileState::fresh("d".into(), 1, 1));
        store
            .state
            .files
            .insert(gone_key.clone(), FileState::fresh("d".into(), 1, 1));
        assert_eq!(store.prune_missing_files(), 1);
        assert!(
            store.file_state(Path::new(&a_key)).is_some(),
            "the file still exists"
        );
        assert!(
            store.file_state(Path::new(&gone_key)).is_none(),
            "stat confirmed this one gone"
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn prune_missing_files_keeps_an_entry_it_cannot_confirm() {
        // A directory with no search permission turns `stat` on anything
        // beneath it into `PermissionDenied`, never `NotFound` — the same
        // shape an unmounted volume or an unreadable root would produce.
        // Neither may cost a cursor.
        use std::os::unix::fs::PermissionsExt;
        let root = tmpdir("prune-locked-root");
        let dir = tmpdir("prune-locked-store");
        let locked = root.join("locked");
        fs::create_dir_all(&locked).unwrap();
        fs::write(locked.join("a.jsonl"), b"x").unwrap();
        let key = locked.join("a.jsonl").to_string_lossy().into_owned();
        let mut store = HistoryStore::open(&dir).unwrap();
        store
            .state
            .files
            .insert(key.clone(), FileState::fresh("d".into(), 1, 1));

        let mode = fs::metadata(&locked).unwrap().permissions().mode();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let removed = store.prune_missing_files();
        fs::set_permissions(&locked, fs::Permissions::from_mode(mode)).unwrap();

        assert_eq!(removed, 0, "a path stat can't confirm must not be pruned");
        assert!(store.file_state(Path::new(&key)).is_some());
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_missing_files_runs_at_most_once_per_store_instance() {
        // A `stat` per tracked entry adds up across the up-to-eight scan
        // ticks one process runs inside a single store's lifetime; the
        // sweep sees everything it will ever see on the first call, so a
        // file that becomes confirmably gone only *after* that call stays
        // tracked until the next store is opened rather than costing a
        // second full sweep to notice it.
        let root = tmpdir("prune-once-root");
        let dir = tmpdir("prune-once-store");
        fs::write(root.join("a.jsonl"), b"x").unwrap();
        let a_key = root.join("a.jsonl").to_string_lossy().into_owned();
        let mut store = HistoryStore::open(&dir).unwrap();
        store
            .state
            .files
            .insert(a_key.clone(), FileState::fresh("d".into(), 1, 1));
        assert_eq!(
            store.prune_missing_files(),
            0,
            "the file exists on the store's one sweep"
        );

        fs::remove_file(root.join("a.jsonl")).unwrap();
        assert_eq!(
            store.prune_missing_files(),
            0,
            "a second call on the same store must not look again"
        );
        assert!(
            store.file_state(Path::new(&a_key)).is_some(),
            "the now-deleted file's entry is left for the next store's sweep"
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn prune_missing_files_treats_a_dangling_symlink_as_gone() {
        // `symlink_metadata` succeeds on a symlink even once its target
        // is missing — a bare `NotFound` check never catches this, and
        // the scanner's walk (`follow_links(false)`, `is_file()`) never
        // offers a symlink either way, so without the non-regular-file
        // test the entry would be stuck forever: never rescanned, never
        // pruned.
        let root = tmpdir("prune-dangling-root");
        let dir = tmpdir("prune-dangling-store");
        let target = root.join("gone-target.jsonl");
        fs::write(&target, b"x").unwrap();
        let link = root.join("a.jsonl");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        fs::remove_file(&target).unwrap(); // the symlink now dangles
        let key = link.to_string_lossy().into_owned();
        let mut store = HistoryStore::open(&dir).unwrap();
        store
            .state
            .files
            .insert(key.clone(), FileState::fresh("d".into(), 1, 1));

        assert_eq!(store.prune_missing_files(), 1);
        assert!(store.file_state(Path::new(&key)).is_none());
        let _ = fs::remove_dir_all(&root);
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
    fn compaction_keeps_an_unsealed_line_but_drops_a_truly_superseded_one() {
        // A rescan's first pass on `/f` lands a partial, unsealed bucket;
        // before the completing pass ever runs, `days.jsonl` crosses the
        // compaction threshold. The partial line is invisible to
        // `live_days` right now — its generation isn't sealed yet — but
        // it is not dead: the completing pass still needs it in its
        // prefix chain. A *different* file, `/other`, has already
        // completed its own rewrite — its old generation is sealed over
        // and genuinely dead. Without `/other` in the fixture this test
        // would pass even with compaction's rewrite skipped entirely
        // (nothing droppable, `maybe_compact_days` returns before
        // touching the file), proving nothing about the chain it claims
        // to protect.
        let dir = tmpdir("compact-hold");
        let mut store = HistoryStore::open(&dir).unwrap();

        let mut sealed0 = day("/f", 0, 10);
        sealed0.full = true;
        store.append_days(&[sealed0]).unwrap();
        store
            .state
            .files
            .insert("/f".to_string(), FileState::fresh("d".into(), 1, 1));
        store
            .file_state_mut(Path::new("/f"))
            .unwrap()
            .reset("d2".into(), 2, 2);
        let mut partial = day("/f", 1, 5);
        partial.lo = 0;
        partial.hi = 50;
        store.append_days(&[partial]).unwrap();

        // `/other`: already rewritten once — gen 0 is sealed and now
        // genuinely superseded by the sealed gen 1 that replaced it.
        let mut other_old = day("/other", 0, 999);
        other_old.full = true;
        let mut other_new = day("/other", 1, 3);
        other_new.full = true;
        store.append_days(&[other_old, other_new]).unwrap();
        store
            .state
            .files
            .insert("/other".to_string(), FileState::fresh("d".into(), 1, 1));
        store
            .file_state_mut(Path::new("/other"))
            .unwrap()
            .reset("d2".into(), 2, 2); // bumps to gen 1, matching other_new

        // Pad past the compaction threshold with raw junk — never loaded
        // into memory, so it is dropped on rewrite regardless; only its
        // size matters here.
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(dir.join("days.jsonl"))
            .unwrap();
        use std::io::Write as _;
        writeln!(f, "{}", "x".repeat(17 * 1024 * 1024)).unwrap();
        drop(f);
        let before_size = fs::metadata(dir.join("days.jsonl")).unwrap().len();
        store.commit().unwrap(); // compacts
        let after_size = fs::metadata(dir.join("days.jsonl")).unwrap().len();
        assert!(
            after_size < before_size,
            "a genuinely dead line was in the fixture — compaction must have rewritten the file smaller"
        );
        assert_eq!(
            store.days.len(),
            3,
            "/f's sealed(0) and partial(1), plus /other's sealed gen 1 — /other's dead gen 0 is gone"
        );

        // The completing pass seals /f's new generation, chaining onto the
        // prefix compaction must have preserved.
        let mut tail = day("/f", 1, 7);
        tail.lo = 50;
        tail.hi = 200;
        tail.full = true;
        store.append_days(&[tail]).unwrap();
        assert_eq!(
            store.live_days().map(|d| d.input).sum::<u64>(),
            15,
            "5 (preserved partial) + 7 (tail) + 3 (/other) — compaction must not have eaten the chain"
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
