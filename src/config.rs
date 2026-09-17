//! Tiny persisted preferences (JSON under the OS config dir). Best-effort.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{json, Value};

// Tests must never read or write the real `~/Library/.../config.json` — that
// file is shared with whatever real app instance may be running on this
// machine (see the module docs on `plugin_option`/the bridge keys below), and
// a test run stomping on it would silently corrupt a user's live settings.
// `path()` consults this thread-local override first; `#[cfg(test)]`-only, so
// it costs nothing and can't be set in a release build — production `path()`
// always resolves the real OS config dir, unchanged. Each `#[test]` fn runs
// on its own thread (the default `libtest` behaviour), so a thread-local is
// enough isolation under `cargo test`'s default parallelism — no env var, no
// global mutex.
//
// `--test-threads=1` does not make the fallback one file for the whole
// suite — measured: libtest gives each test its own thread in every mode
// reachable here (default, `--test-threads=1`, and `--test-threads=1
// --nocapture` — all three leave one scratch file per config-writing test,
// not one in total), so the fallback is per test in practice.
//
// In practice, and not by contract: that is libtest's behaviour, not its
// promise, and a runner that pooled threads would hand two tests one file.
// So the promise below is only that a write lands somewhere **disposable** —
// never that it lands somewhere **empty**. A test that needs a config nothing
// else has touched still says so, with `with_test_config_path`, or states the
// keys it depends on. (Before any of this, every test shared one config — the
// real one — so either way this is strictly less sharing.)
//
// The override alone was not enough, and the way it failed is worth keeping:
// **it protected only the tests that remembered to ask for it**, which is the
// ones written by somebody already thinking about this file. The leak came in
// sideways instead. `main`'s `a_delivered_built_in_is_not_delivered_again…`
// hands `upgrade_builtin_manifests` a temp directory — the manifests it writes
// really do land there — but that function also records its decision in the
// *config*, once per built-in, through `set_builtin_migrated`. So a run under
// the developer's own `HOME` wrote five `plugin.<id>.builtin_migrated` markers
// into the live install (and `forget_remembered_accounts` deleted a key beside
// them) while every file went to `/tmp`. That state — a marker saying "this
// version's decision was already made" with no manifest on disk — is exactly
// what stops a built-in from ever arriving, and it is indistinguishable from
// the legitimate one a user creates by deleting a manifest we delivered. It
// cost the 2026-08-22 install its `copilot.toml`, silently: `diag::line`
// writes to stderr only under `cargo test` (the same class, fixed there
// first — see `crate::diag::line`), so nothing was logged.
//
// So the fallback is a scratch file rather than the real one. A test that asks
// for a specific path still gets it; a test that never heard of this override
// gets a disposable file of its own thread instead of the user's settings.
// Production is untouched: `path()` has two `#[cfg]`-selected definitions, and
// the release one is the single line it always was.
//
// Two things this deliberately does *not* cover, so nobody reads more into it
// than it says:
//
// * **`dir()` still resolves the real directory under test** — and has to, or
//   the test that checks this sandbox would have nothing to name as the place
//   it must not reach. What lives beside `config.json` there is the plugins
//   folder (reached through `seed::plugins_dir`, which never consults this
//   module) and `platform`'s instance lock and show-panel file. No test writes
//   to either today — a full run creates nothing at all under `HOME` — but
//   that is a measurement, not a guarantee, and rule "tests only under a
//   substituted `HOME`" stays in force for exactly that reason.
// * **`#[cfg(test)]` here is the binary's own unit tests.** That is all of
//   them for this module: `config` is `mod config;` in `src/main.rs`, and the
//   integration tests under `tests/` link the library (`menubar`, `model`,
//   `plugin`), which has no way to reach this file.
#[cfg(test)]
thread_local! {
    static TEST_PATH_OVERRIDE: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    /// Where a test that set no override writes instead of the real file.
    ///
    /// Resolved once per thread and then kept, because the state under test is
    /// often persistence itself: `upgrade_builtin_manifests` records a marker
    /// and the next call must read it back, and a path recomputed per call
    /// would answer that with an empty config every time — turning a suite
    /// that guards a real behaviour into one that cannot see it.
    static TEST_SCRATCH_PATH: PathBuf = test_scratch_path();
}

/// A disposable `config.json` for the calling thread: a *name* in the temp
/// directory, and nothing on disk until something writes.
///
/// All three parts earn their place, and the reasoning is
/// `with_test_config_path`'s below, one step further out:
///
/// * **pid** — two `cargo test` processes at once must not share a file;
/// * **nanoseconds** — a pid alone repeats (macOS recycles within about 32k)
///   and nothing here removes these files, so a later run would open an
///   earlier one's and read state nobody in that process wrote. That is a
///   test going red once in a while for no reason a reader can find;
/// * **counter** — the clock is not the tiebreaker it looks like: two threads
///   resolving this at once can read the same `as_nanos`. It is *not* a thread
///   identity, which is why it is a counter and not a `ThreadId` (whose only
///   stable rendering is its `Debug` one anyway).
///
/// No directory of our own, deliberately. An earlier version made one per
/// thread — and made it *eagerly*, on the first `path()` call, so a run left
/// ten of them behind for two files: eight came from tests that only ever
/// *read* the config. A bare filename creates nothing at all until a setter
/// runs, and takes `create_dir_all`'s swallowed error with it.
#[cfg(test)]
fn test_scratch_path() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "tickover-test-config-{}-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is after the epoch")
            .as_nanos(),
        SEQ.fetch_add(1, Ordering::Relaxed),
    ))
}

#[cfg(test)]
fn path() -> Option<PathBuf> {
    if let Some(p) = TEST_PATH_OVERRIDE.with(|o| o.borrow().clone()) {
        return Some(p);
    }
    Some(TEST_SCRATCH_PATH.with(|p| p.clone()))
}

#[cfg(not(test))]
fn path() -> Option<PathBuf> {
    dir().map(|d| d.join("config.json"))
}

/// This app's own directory under the OS config dir — where `config.json`,
/// the plugins folder and the single-instance lock all live.
///
/// Delegates to [`tickover::plugin::app_config_dir`] rather than re-deriving
/// `dirs::config_dir().join("tickover")` here too: that library function is
/// the one true definition callable from every crate this binary links
/// (`plugin::seed::plugins_dir` already uses it). `registry::lockfile_path`
/// still spells the same join out for itself rather than calling it — a
/// duplicate this file can name but not remove, since fixing it means editing
/// `src/plugin/registry.rs`, not this one.
pub fn dir() -> Option<PathBuf> {
    tickover::plugin::app_config_dir()
}

/// One-time move of an install made before the rename to Tickover:
/// `<config>/codex-limits` becomes `<config>/tickover`, and the log file
/// inside it (`crate::diag`'s) is best-effort-renamed to match. Returns
/// whether a migration happened, so `main` can gate
/// `autostart::retire_legacy_entry` on it — a fresh install never held the
/// old login item that function retires, and must not risk the permission
/// prompt macOS can raise for touching one.
///
/// Must run before anything else touches the config directory.
/// `platform::claim_single_instance`, `diag::line` and `seed::seed_if_empty`
/// all create `<config>/tickover` the moment they run — an instance lock, a
/// log file, a seeded manifest — and once that empty directory exists this
/// finds a destination already there and does nothing, silently orphaning a
/// still-full `<config>/codex-limits`. So `main` calls this first, before any
/// of them, before there is even a log to record what it did in.
///
/// Unguarded by the single-instance lock, deliberately: it runs before that
/// lock is claimed. Two copies launched at once can both reach it — the
/// loser finds the old directory already gone (`Ok(false)`) or hits a rename
/// error it goes on to log — and neither leaves anything half-moved, since
/// `fs::rename` is atomic on every filesystem this app ships for.
///
/// Best-effort like the rest of this module, with one difference: the error
/// is returned rather than swallowed here, because at the point this runs
/// there is nothing yet to swallow it into — `diag` writes beside
/// `config.json`, which is what may still need moving. `main` logs it once
/// this returns.
pub fn migrate_legacy_dir() -> Result<bool, std::io::Error> {
    let Some(config_root) = dirs::config_dir() else {
        return Ok(false);
    };
    migrate_legacy_dir_at(
        &config_root.join("codex-limits"),
        &config_root.join("tickover"),
    )
}

/// The rename [`migrate_legacy_dir`] performs, with both paths taken
/// explicitly so it can be tested against a temp directory instead of the
/// real config dir. `dir()` has no test override and must not gain one just
/// for this (see the module docs above `path()`): `migrate_legacy_dir`
/// itself is never called from a test, only this half of it, which never
/// resolves `dirs::config_dir()` at all.
fn migrate_legacy_dir_at(old: &Path, new: &Path) -> Result<bool, std::io::Error> {
    if new.exists() || !old.exists() {
        return Ok(false);
    }
    std::fs::rename(old, new)?;
    // Best-effort: the directory itself has already moved, which is the part
    // that matters, and a log left under its old name inside the new
    // directory is not worth reporting the migration as failed over.
    let _ = std::fs::rename(new.join("codex-limits.log"), new.join("tickover.log"));
    Ok(true)
}

/// How many `.corrupt-<unix secs>[-<n>]` names [`backup_if_corrupt`] tries
/// before giving up on saving a backup at all. The name is only
/// second-resolution, so two corrupt files backed up inside the same second
/// would otherwise fight over one name — implausible for one `config.json`
/// (fixing the first backup's corruption is what the write right after it
/// does), but not worth assuming can never happen when the cost of being
/// wrong is silently skipping a backup instead of trying the next name.
const CORRUPT_BACKUP_MAX_ATTEMPTS: u32 = 100;

/// Save whatever is at `path` right now aside as `<name>.corrupt-<unix
/// secs>` (or a `-<n>`-suffixed sibling, see [`CORRUPT_BACKUP_MAX_ATTEMPTS`]),
/// unless it already parses as a JSON **object**. [`load`] treats anything
/// else — unparsable, or valid JSON that isn't an object (`[]`, `"x"`,
/// `42`, `null`) — the same as "nothing here", and every setter builds its
/// new value from an empty object and then overwrites the file. Without this
/// check naming both failure shapes, a `config.json` that was somehow made
/// into a bare JSON array would parse *fine* by `from_str::<Value>`'s own
/// measure, so the corrupt-detection above it used to wave it through: every
/// setter's `as_object_mut()` would then find nothing to insert into, silently
/// discard the change, and re-save the same non-object right back — a setting
/// that can never be written again, with nothing on screen or in the log to
/// say so. Backing it up and starting fresh (an empty object) is what
/// [`load`] does too, so the two agree on what "not a usable config" means.
///
/// A copy of the content (never a rename) either way — the normal write
/// below still has to land at `path` regardless of which shape was wrong,
/// and leaving the original in place is one less way for a failed backup to
/// turn a bad file into a missing one.
///
/// Written via `create_new`, never `std::fs::copy`/a plain write into
/// the backup name — that name is predictable (this second, this pid's
/// process is not part of it, unlike `write_atomically`'s temp path), and
/// `copy` opens its destination with truncate, following a symlink planted
/// there and overwriting whatever it points to rather than the intended
/// backup. `create_new` refuses any directory entry already at that path,
/// symlink included, rather than opening through it — the same guarantee
/// `write_atomically`'s own temp file relies on, here without the
/// remove-first step that only works because that path's suffix is unique to
/// this process.
///
/// Best-effort like the rest of this module: a backup that can't be written
/// is logged and given up on, not allowed to block the write it was meant to
/// precede.
fn backup_if_corrupt(path: &std::path::Path) {
    let Some(existing) =
        tickover::plugin::read_regular_file(path, tickover::plugin::SMALL_FILE_MAX_BYTES)
    else {
        return; // absent, not a regular file, or unreadable for some other reason: nothing to save
    };
    // Named apart so the line below can say which is true: `[]` did
    // parse, and saying it "did not parse" beside a copy that plainly does
    // would be this app's own diagnostic contradicting the file it just
    // wrote out.
    let reason = match serde_json::from_str::<Value>(tickover::plugin::strip_bom(&existing)) {
        Ok(v) if v.is_object() => return, // a usable config — an ordinary overwrite, nothing at risk
        Ok(_) => "parsed, but wasn't a JSON object",
        Err(_) => "did not parse as JSON",
    };
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let stem = path.file_name().unwrap_or_default().to_os_string();
    for attempt in 1..=CORRUPT_BACKUP_MAX_ATTEMPTS {
        let mut backup_name = stem.clone();
        if attempt == 1 {
            backup_name.push(format!(".corrupt-{secs}"));
        } else {
            backup_name.push(format!(".corrupt-{secs}-{attempt}"));
        }
        let backup = path.with_file_name(backup_name);
        let result = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&backup)
            .and_then(|mut f| std::io::Write::write_all(&mut f, existing.as_bytes()));
        match result {
            Ok(()) => {
                crate::diag::line(format!(
                    "{} {reason} — the previous copy was saved as {} before it was overwritten",
                    path.display(),
                    backup.display()
                ));
                return;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                crate::diag::line(format!(
                    "{} {reason}, and the previous copy could not be backed up to {}: {e}",
                    path.display(),
                    backup.display()
                ));
                return;
            }
        }
    }
    crate::diag::line(format!(
        "{} {reason}, and no unused backup name was found after {CORRUPT_BACKUP_MAX_ATTEMPTS} tries",
        path.display()
    ));
}

#[cfg(test)]
thread_local! {
    /// How many times [`write_atomically`] has actually landed a write on
    /// this thread, since the last [`take_write_count`]. Test-only
    /// instrumentation: a "does not rewrite the file for an unchanged value"
    /// test used to check this through the file's mtime, which is
    /// indistinguishable from "wrote nothing" on any filesystem with
    /// one-second resolution even when the file actually was rewritten twice
    /// inside that second — exactly the case a fast, in-memory temp directory
    /// produces on every run. Counting the write itself makes the claim
    /// direct instead of hoping the clock ticked in between.
    static WRITE_COUNT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Take (and reset) the number [`WRITE_COUNT`] has reached on this thread.
#[cfg(test)]
fn take_write_count() -> u64 {
    WRITE_COUNT.with(|c| c.replace(0))
}

/// Serializes the load → mutate → write cycle every setter in this module
/// performs — `set_bool`, `set_u64`, `set_plugin_seen_window_for`,
/// `forget_remembered_accounts`, `set_builtin_migrated`,
/// `remove_plugin_keys`, each acquiring this for its whole body, before its
/// own `load()`.
///
/// **Invariant this stands in for:** every setter is called from the main
/// thread, so nothing races another today, and the cross-process version of
/// the same race is already closed by the single-instance file lock
/// ([`crate::platform::claim_single_instance`]). Held here anyway, as
/// insurance for the day a setter call moves onto a background thread — the
/// fetch worker is the obvious future candidate. Without it, two overlapping
/// load → mutate → write cycles could each read the same starting `Value`,
/// mutate their own key, and have whichever writes second silently discard
/// the first one's change; the predictable-temp-path pair inside
/// [`tickover::plugin::write_via_temp`] (`remove_file` then
/// `create_new(true)`) guards against a hostile symlink planted at that
/// path, not against two honest writers racing each other.
///
/// A plain `Mutex`, not a `RwLock`: every caller through here writes, so
/// there is no reader-heavy case to give a second lock kind a reason to
/// exist. Poisoning is recovered (`unwrap_or_else(|e| e.into_inner())`) the
/// same way `plugin::throttle::STATES`'s lock is — a panic mid-write on some
/// future background thread must not turn every later config write into a
/// permanent failure for a process this crate's own `panic = "abort"`
/// decision (see `Cargo.toml`) never unwinds out of anyway.
static CONFIG_WRITE_LOCK: Mutex<()> = Mutex::new(());

/// Write `text` to `path` without ever leaving a half-written file behind —
/// through [`tickover::plugin::write_via_temp`], the same temp-neighbour-
/// then-rename sequence `main.rs`'s `install_write`/`update_write` use for a
/// plugin manifest, atomic on every filesystem this app runs on. A plain
/// write truncates first, so an app quit (or a crash, or a full disk) in the
/// middle of one leaves settings that no longer parse — and this file's
/// reader treats unparsable as empty, which is every preference in it,
/// silently gone. No check before the rename (a no-op `pre_rename`): unlike
/// `install_write`'s new-file case, every setter here means to overwrite
/// whatever is already at `path`.
///
/// Backs up a corrupt `path` (see [`backup_if_corrupt`]) before ever touching
/// it — every setter routes through here, so this is the one place that can
/// catch a corrupt file the moment before it would be overwritten with a
/// fresh, mostly-empty one.
fn write_atomically(path: &std::path::Path, text: &str) {
    let Some(dir) = path.parent() else { return };
    let _ = std::fs::create_dir_all(dir);
    backup_if_corrupt(path);
    // Dropped before the write is even attempted, not only once it lands: a
    // failed write still leaves the file's stat in a state `with_config`
    // hasn't seen (the temp file below may have been created and removed, or
    // `backup_if_corrupt` may have just replaced `path`'s corrupt bytes with
    // nothing this call wrote), so treating the cache as trustworthy on every
    // failure branch costs more reasoning than one avoidable reparse the next
    // time something reads it.
    invalidate_config_cache();
    if tickover::plugin::write_via_temp(path, text.as_bytes(), |_| Ok(())).is_ok() {
        #[cfg(test)]
        WRITE_COUNT.with(|c| c.set(c.get() + 1));
    }
}

/// Drop this thread's cached config unconditionally — called from
/// [`write_atomically`] before it creates the temp file or renames it over
/// `path`, so every write it goes on to attempt, landed or not, is covered by
/// the same call. See the comment at that call site for why "not only on
/// success" is deliberate.
fn invalidate_config_cache() {
    CONFIG_CACHE.with(|c| *c.borrow_mut() = None);
}

struct CachedConfig {
    path: PathBuf,
    // `None` when `path` had no metadata the moment this was cached: the file
    // does not exist yet, or `mtime` is unavailable on this filesystem. A
    // later stat that again comes back with no metadata reads as the same
    // absence, not a reason to reload.
    stamp: Option<(std::time::SystemTime, u64)>,
    value: Value,
}

thread_local! {
    /// One thread's most recently parsed `config.json`, invalidated by
    /// [`with_config`] itself (on a moved `mtime`/size) and by every
    /// [`write_atomically`] call (unconditionally, win or lose — see the
    /// comment there). Per-thread for the same reason `TEST_PATH_OVERRIDE`
    /// and `TEST_SCRATCH_PATH` above are: production code only ever touches
    /// config from the main thread, and keying by path as well means two
    /// tests sharing a reused libtest thread can never serve one another's
    /// cached value.
    static CONFIG_CACHE: std::cell::RefCell<Option<CachedConfig>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// How many times [`read_uncached`] has actually opened and parsed the
    /// file on this thread, since the last [`take_read_count`]. The
    /// `WRITE_COUNT` idiom above, for the read side: a "the cache serves the
    /// second lookup without touching disk" test needs to see the parse
    /// itself skipped, not infer it from timing.
    static READ_COUNT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Take (and reset) the number [`READ_COUNT`] has reached on this thread.
#[cfg(test)]
fn take_read_count() -> u64 {
    READ_COUNT.with(|c| c.replace(0))
}

fn stamp_of(p: &Path) -> Option<(std::time::SystemTime, u64)> {
    let m = std::fs::metadata(p).ok()?;
    Some((m.modified().ok()?, m.len()))
}

/// Parse `config.json` off disk — no memoisation. Called only from
/// [`with_config`], once it has already decided the cached value is stale;
/// this is where the `open` + read + `serde_json::from_str` actually happens.
fn read_uncached(p: &Path) -> Value {
    #[cfg(test)]
    READ_COUNT.with(|c| c.set(c.get() + 1));
    let text = tickover::plugin::read_regular_file(p, tickover::plugin::SMALL_FILE_MAX_BYTES);
    // `read_regular_file` also returns `None` for a plain missing file — the
    // ordinary first-run case, silent by design — so this only fires when
    // something is actually sitting at `p` and got refused for its kind
    // (a FIFO, a device, a directory) or its size (over
    // `SMALL_FILE_MAX_BYTES`): loud rather than the same silent
    // "no config" a genuinely absent file gets, since this is a file this
    // app is about to overwrite on the next setting change without whoever
    // put it there ever finding out why nothing they wrote through it back
    // was ever read.
    if text.is_none() && p.exists() {
        crate::diag::line(format!(
            "{} exists but is not a regular file under {} MiB (or a symlink to one) — reading as no config",
            p.display(),
            tickover::plugin::SMALL_FILE_MAX_BYTES / (1024 * 1024)
        ));
    }
    text
        // A byte-order mark makes `from_str` fail, which this treats as an
        // empty config — and the next write then persists that emptiness
        // over every setting the file held. One editor that saves a BOM is
        // enough to silently reset the lot; see `plugin::strip_bom`.
        .and_then(|s| serde_json::from_str::<Value>(tickover::plugin::strip_bom(&s)).ok())
        // Valid JSON that isn't an object (`[]`, a bare string, `null`…)
        // is exactly as unusable as unparsable text — every setter below
        // reads and writes through `as_object_mut()`, which finds nothing on
        // anything else and silently no-ops. Filtered here so this and
        // `backup_if_corrupt` (which runs first, on the raw text, and backs
        // up precisely this shape) agree on what counts as "nothing here".
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

/// Borrow the parsed config, reading it off disk only when [`stamp_of`] shows
/// `mtime`/size have moved since the last borrow on this thread — a hand
/// edit to `config.json` is still picked up, at the cost of one `stat` per
/// call in place of the `open` + read + parse the uncached form paid every
/// time. The lookups this app makes on the one-second tick (`get_bool_opt`,
/// `get_u64`, `plugin_seen_window_for`, …) go through here rather than
/// [`load`], so a read never pays for an owned copy it only reads one field
/// out of.
fn with_config<T>(f: impl FnOnce(&Value) -> T) -> T {
    let Some(p) = path() else {
        return f(&json!({}));
    };
    let stamp = stamp_of(&p);
    CONFIG_CACHE.with(|cell| {
        let stale =
            !matches!(&*cell.borrow(), Some(cached) if cached.path == p && cached.stamp == stamp);
        if stale {
            let value = read_uncached(&p);
            *cell.borrow_mut() = Some(CachedConfig {
                path: p,
                stamp,
                value,
            });
        }
        let cached = cell.borrow();
        f(&cached
            .as_ref()
            .expect("populated on the stale branch just above, or already held a match")
            .value)
    })
}

/// An owned copy of the whole persisted config — for the setters below, each
/// of which builds a new [`Value`] from it, and for the handful of tests that
/// assert on it whole. A clone of a config with a couple dozen scalar
/// entries is the cheap kind, nothing like the file read [`with_config`]
/// exists to skip.
fn load() -> Value {
    with_config(Value::clone)
}

fn get_bool(key: &str) -> bool {
    get_bool_opt(key).unwrap_or(false)
}

/// Like [`get_bool`] but distinguishes "key absent" (`None`) from a stored
/// `false` — needed by [`plugin_enabled`], whose default is the manifest's own
/// `enabled`, not a blanket `false`.
fn get_bool_opt(key: &str) -> Option<bool> {
    with_config(|cfg| cfg.get(key).and_then(Value::as_bool))
}

fn set_bool(key: &str, v: bool) {
    let _write_guard = CONFIG_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(p) = path() else { return };
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let mut cfg = load();
    if let Some(obj) = cfg.as_object_mut() {
        obj.insert(key.to_string(), Value::Bool(v));
    }
    write_atomically(&p, &cfg.to_string());
}

/// Render compact stats as the tray title (menu-bar text).
pub fn menu_bar_text() -> bool {
    get_bool("menu_bar_text")
}
pub fn set_menu_bar_text(v: bool) {
    set_bool("menu_bar_text", v);
}

/// Run from the Dock with an ordinary window instead of the menu bar.
///
/// A full menu bar makes macOS drop the status item with no warning and no
/// overflow affordance, which leaves a tray-only app with no reachable UI at
/// all — including no way to switch this very setting back on. So it persists
/// here and `TICKOVER_DOCK=1` writes it, giving a recovery path that needs
/// nothing from the menu bar.
pub fn dock_mode() -> bool {
    get_bool("dock_mode")
}
pub fn set_dock_mode(v: bool) {
    set_bool("dock_mode", v);
}

/// Also monitor the Claude *desktop* account (needs a one-time macOS Keychain
/// grant; off by default so no surprise prompt appears).
// Reachable only from the bridge match arms just below — `plugin_ping` /
// `set_plugin_ping` / `plugin_surface_enabled` / `set_plugin_surface_enabled`
// are what `main.rs` actually calls, across the crate boundary that makes
// `pub` a real signal there. Nothing outside this file ever names one of
// these six directly, so they stay file-private — `config` is itself a
// module of the binary crate, not the library, so this is a readability
// choice rather than a reachability one either way.
fn monitor_desktop() -> bool {
    get_bool("monitor_desktop")
}
fn set_monitor_desktop(v: bool) {
    set_bool("monitor_desktop", v);
}

/// Auto-send `codex exec hello` while the Codex 5-hour window sits empty (to
/// start a fresh one). Consumes a little quota, so it's a toggle. One ping per
/// window — see `main.rs::ping_due`/`window_start` and the two keys below.
fn auto_ping_codex() -> bool {
    get_bool("auto_ping_codex")
}
fn set_auto_ping_codex(v: bool) {
    set_bool("auto_ping_codex", v);
}

/// Same, for Claude (`claude -p hello`), keyed on the CLI account's 5h window.
fn auto_ping_claude() -> bool {
    get_bool("auto_ping_claude")
}
fn set_auto_ping_claude(v: bool) {
    set_bool("auto_ping_claude", v);
}

// ── Generic per-plugin state (the plugin manager) ──────────────────────────
//
// The plugin manager persists each plugin's enable / ping / opt-in-surface
// state here, keyed by the plugin's manifest id — so the rest of the app can
// stay generic over plugin ids. Three legacy keys predate the manager and are
// **bridged** so existing users' settings survive untouched: the well-known
// "codex" / "claude" ping toggles keep reading and writing
// `auto_ping_codex` / `auto_ping_claude`, and the Claude "desktop" opt-in
// surface keeps `monitor_desktop`. Every other id/surface uses a generic key:
//   * `plugin.<id>.enabled`
//   * `plugin.<id>.ping`
//   * `plugin.<id>.surface.<surface-id>`
// The bridge is the *only* place plugin ids are hard-coded — see the module
// docs on `src/main.rs`.

/// Master enable for a plugin. No legacy key existed, so `manifest_default`
/// (the manifest's own `enabled`, default true) is used until the user
/// overrides it; config stores only the override (precedence config > manifest).
pub fn plugin_enabled(id: &str, manifest_default: bool) -> bool {
    get_bool_opt(&format!("plugin.{id}.enabled")).unwrap_or(manifest_default)
}
pub fn set_plugin_enabled(id: &str, v: bool) {
    set_bool(&format!("plugin.{id}.enabled"), v);
}

/// Auto-ping "hello" on 5h reset for a plugin. Bridged to the legacy
/// `auto_ping_codex` / `auto_ping_claude` keys for those two ids.
pub fn plugin_ping(id: &str) -> bool {
    match id {
        "codex" => auto_ping_codex(),
        "claude" => auto_ping_claude(),
        _ => get_bool(&format!("plugin.{id}.ping")),
    }
}
pub fn set_plugin_ping(id: &str, v: bool) {
    match id {
        "codex" => set_auto_ping_codex(v),
        "claude" => set_auto_ping_claude(v),
        _ => set_bool(&format!("plugin.{id}.ping"), v),
    }
}

/// Whether an opt-in surface of a plugin is enabled. Bridged to the legacy
/// `monitor_desktop` key for the Claude "desktop" surface.
pub fn plugin_surface_enabled(plugin_id: &str, surface_id: &str) -> bool {
    match (plugin_id, surface_id) {
        ("claude", "desktop") => monitor_desktop(),
        _ => get_bool(&format!("plugin.{plugin_id}.surface.{surface_id}")),
    }
}
pub fn set_plugin_surface_enabled(plugin_id: &str, surface_id: &str, v: bool) {
    match (plugin_id, surface_id) {
        ("claude", "desktop") => set_monitor_desktop(v),
        _ => set_bool(&format!("plugin.{plugin_id}.surface.{surface_id}"), v),
    }
}

/// Value of a declarative `[[option]]` a plugin manifest exposes
/// (`plugin::manifest::OptionConfig`) — read by the engines as the
/// `{option.<key>}` substitution. No legacy key exists
/// for these (introduced after the plugin manager), so `manifest_default`
/// (the manifest's own `default`) is used until the user overrides it;
/// config stores only the override (precedence config > manifest), mirroring
/// [`plugin_enabled`]. Generic over both plugin id and option key — no
/// well-known-id bridge needed here.
pub fn plugin_option(id: &str, key: &str, manifest_default: bool) -> bool {
    get_bool_opt(&format!("plugin.{id}.option.{key}")).unwrap_or(manifest_default)
}
pub fn set_plugin_option(id: &str, key: &str, v: bool) {
    set_bool(&format!("plugin.{id}.option.{key}"), v);
}

// ── Seen-window registry and auto-ping bookkeeping ────────────────────────
//
// What this plugin's provider has told us about its quota windows, and what we
// did about it:
//
//   * `plugin.<id>.seen.<reading id>.<role>.at` / `.period_minutes` — the
//     newest reset the provider has *stated* for one window, and how long it
//     said that window was. Only ever moved forward. A provider that stops
//     reporting a window at all once it is empty (Codex does exactly this)
//     leaves nothing to recognise the passed boundary by; this is that
//     boundary, remembered from while it was still being stated. Written
//     whatever the ping toggle says — and for every plugin, not only ones with
//     a `[ping]` section — because both readers below need it to already be
//     there by the time the window vanishes.
//   * `plugin.<id>.seen_window` — what the above was before it had a reading id
//     and a role: one value per plugin, the plugin's primary window on its
//     first surface. Still on users' disks, still read (see
//     `main.rs::seen_window_of`), never written again.
//   * `plugin.<id>.pinged_at` — when the last auto-ping was fired. Compared
//     against the *start* of the window on screen: a ping older than the
//     current window means this window has not been pinged. A timestamp rather
//     than a window id because the same window is named differently before and
//     after a provider starts reporting it (see `main.rs::ping_due`).
//
// On disk rather than in memory so a restart cannot ping the same window
// twice, and — the reason they exist — so a boundary the machine slept through
// is still recognisable afterwards as one that was never pinged.
//
// All of them are read on the one-second tick, so every setter here writes only
// when the value actually moves; none of them moves more often than once per
// window.

fn get_u64(key: &str) -> u64 {
    with_config(|cfg| cfg.get(key).and_then(Value::as_u64)).unwrap_or(0)
}

fn set_u64(key: &str, v: u64) {
    let _write_guard = CONFIG_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // One `load()` for both the comparison and the mutation below, not one
    // each — the value it returns is the owned copy this function goes on to
    // insert into and write back regardless, so there is nothing a second
    // call would see that this one hasn't already.
    let mut cfg = load();
    if cfg.get(key).and_then(Value::as_u64).unwrap_or(0) == v {
        return;
    }
    let Some(p) = path() else { return };
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Some(obj) = cfg.as_object_mut() {
        obj.insert(key.to_string(), Value::from(v));
    }
    write_atomically(&p, &cfg.to_string());
}

/// One quota window as this app last saw the provider state it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeenWindow {
    /// The newest reset the provider stated for this window (Unix seconds).
    pub at: u64,
    /// How long the provider said the window was, when it said anything at
    /// all. `None` is a real answer and not a default: a window whose length
    /// was never stated is one whose next boundary cannot be worked out.
    ///
    /// Remembered rather than looked up in the manifest, because for the
    /// provider this whole registry exists for there is nothing to look up:
    /// both of Codex's windows declare `period.mode = "from_field"`, so their
    /// length lives in the very response that stops arriving.
    pub period_minutes: Option<u64>,
}

fn seen_key(plugin_id: &str, reading_id: &str, role: &str, field: &str) -> String {
    format!("plugin.{plugin_id}.seen.{reading_id}.{role}.{field}")
}

/// What this plugin's provider last stated about one window of one reading, or
/// `None` if it never stated anything about it.
///
/// Keyed by *reading* id and role rather than by plugin: a plugin can report
/// several accounts (Claude's CLI and desktop surfaces, a log-file engine's
/// sub-accounts), and their windows empty independently. Nested under
/// `plugin.<id>.` all the same, so [`remove_plugin_keys`] still takes the whole
/// registry with the plugin.
pub fn plugin_seen_window_for(plugin_id: &str, reading_id: &str, role: &str) -> Option<SeenWindow> {
    with_config(|cfg| seen_window_from(cfg, plugin_id, reading_id, role))
}

/// The read [`plugin_seen_window_for`] and [`set_plugin_seen_window_for`]'s
/// comparison guard both need, factored out so the setter can run it against
/// its own already-loaded `cfg` instead of paying a second [`load`] for the
/// same lookup the getter would make.
fn seen_window_from(
    cfg: &Value,
    plugin_id: &str,
    reading_id: &str,
    role: &str,
) -> Option<SeenWindow> {
    let at = cfg
        .get(seen_key(plugin_id, reading_id, role, "at"))
        .and_then(Value::as_u64)
        .filter(|at| *at > 0)?;
    Some(SeenWindow {
        at,
        // Stored as 0 for "never stated" so the two keys are always written
        // together — a period left over from the previous window would be read
        // as this one's.
        period_minutes: cfg
            .get(seen_key(plugin_id, reading_id, role, "period_minutes"))
            .and_then(Value::as_u64)
            .filter(|m| *m > 0),
    })
}

/// Record what the provider states about one window — both fields in a single
/// write, so no reader can ever see the new reset beside the old length.
pub fn set_plugin_seen_window_for(plugin_id: &str, reading_id: &str, role: &str, seen: SeenWindow) {
    let _write_guard = CONFIG_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Normalised the same way the read above normalises what it returns: an
    // `at` of `0` never reads back as anything but `None`, so writing one here
    // would compare unequal to that `None` forever and rewrite the file every
    // call. The caller is expected to have filtered this already — this is
    // only the backstop.
    if seen.at == 0 {
        return;
    }
    let seen = SeenWindow {
        at: seen.at,
        period_minutes: seen.period_minutes.filter(|m| *m > 0),
    };
    // One `load()` for both the comparison and the mutation below — `cfg` is
    // the same owned copy either way, so a second call here would only ask
    // the disk the identical question this one already has the answer to.
    let mut cfg = load();
    if seen_window_from(&cfg, plugin_id, reading_id, role) == Some(seen) {
        return;
    }
    let Some(p) = path() else { return };
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Some(obj) = cfg.as_object_mut() {
        obj.insert(
            seen_key(plugin_id, reading_id, role, "at"),
            Value::from(seen.at),
        );
        obj.insert(
            seen_key(plugin_id, reading_id, role, "period_minutes"),
            Value::from(seen.period_minutes.unwrap_or(0)),
        );
    }
    write_atomically(&p, &cfg.to_string());
}

/// The pre-registry key: newest reset this plugin's provider stated for its
/// primary window on its first surface, or `0` if it never did. Read as a
/// fallback for exactly that one window (`main.rs::seen_window_of`) and never
/// written — an install upgrading into the registry above must not lose the
/// boundary its auto-ping is working from.
pub fn plugin_seen_window(id: &str) -> u64 {
    get_u64(&format!("plugin.{id}.seen_window"))
}

/// Only an install made before the registry existed has this key, so nothing
/// in the app writes it — the tests that stand in for such an install do.
#[cfg(test)]
fn set_plugin_seen_window(id: &str, reset: u64) {
    set_u64(&format!("plugin.{id}.seen_window"), reset);
}

/// When this plugin's auto-ping last fired — `0` if it never has. See the
/// section comment above.
pub fn plugin_pinged_at(id: &str) -> u64 {
    get_u64(&format!("plugin.{id}.pinged_at"))
}
pub fn set_plugin_pinged_at(id: &str, when: u64) {
    set_u64(&format!("plugin.{id}.pinged_at"), when);
}

// ── Built-in manifest upgrades ────────────────────────────────────────────
//
// Which shipped version of a built-in manifest this install has already been
// offered (`crate::plugin::seed::upgrade_builtin`). Written whatever the
// outcome — replaced, kept because the user edited it — so the decision is
// made once per shipped version rather than re-litigated on every launch.
// That is also what lets a deliberate rollback stand: the copy the user put
// back is not mistaken for an install that never migrated.

/// The built-in version this plugin's manifest was last migrated to, if any.
pub fn builtin_migrated(id: &str) -> Option<String> {
    with_config(|cfg| {
        cfg.get(format!("plugin.{id}.builtin_migrated"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    })
}

/// Drop the `plugin.<id>.accounts` map an older build kept: a remembered
/// "plan tier -> address" cache, used to guess which account a log-derived row
/// belonged to. Nothing reads it any more — the address comes from the
/// provider now — and what is left behind is an email address sitting in a
/// config file for no reason at all.
pub fn forget_remembered_accounts(id: &str) {
    let _write_guard = CONFIG_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(p) = path() else { return };
    let mut cfg = load();
    let Some(obj) = cfg.as_object_mut() else {
        return;
    };
    if obj.remove(&format!("plugin.{id}.accounts")).is_none() {
        return; // nothing stored — don't rewrite the file for nothing
    }
    write_atomically(&p, &cfg.to_string());
}

/// Record that this install has settled the built-in upgrade to `version`.
pub fn set_builtin_migrated(id: &str, version: &str) {
    let _write_guard = CONFIG_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(p) = path() else { return };
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let mut cfg = load();
    if let Some(obj) = cfg.as_object_mut() {
        obj.insert(
            format!("plugin.{id}.builtin_migrated"),
            Value::String(version.to_string()),
        );
    }
    write_atomically(&p, &cfg.to_string());
}

/// Drop every stored override for a removed plugin — enabled/disabled state,
/// surface toggles, options, seen-window bookkeeping — everything nested under
/// `plugin.<id>.`, so a later reinstall starts from the manifest's defaults
/// rather than whatever this install session had accumulated. The codex/claude
/// bridge keys (`auto_ping_codex`, `monitor_desktop`, …) survive by
/// construction rather than by any carve-out here: they are top-level keys,
/// never nested under `plugin.<id>.` at all, so this never sees them.
///
/// `builtin_migrated` is the one key that *is* under that prefix and this
/// deliberately leaves alone anyway: it is not user state, it is the record
/// that a built-in's on-disk manifest has already been carried forward to a
/// given version. If Remove wiped it, the very next launch's
/// `seed::upgrade_builtin` would find the plugin `Absent` and rewrite the
/// shipped file the user just chose to delete — the seed step then treats
/// "gone" the same as "never migrated".
pub fn remove_plugin_keys(id: &str) {
    let _write_guard = CONFIG_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(p) = path() else { return };
    let prefix = format!("plugin.{id}.");
    let keep = format!("plugin.{id}.builtin_migrated");
    let mut cfg = load();
    let Some(obj) = cfg.as_object_mut() else {
        return;
    };
    let stale: Vec<String> = obj
        .keys()
        .filter(|k| k.starts_with(&prefix) && k.as_str() != keep)
        .cloned()
        .collect();
    if stale.is_empty() {
        return;
    }
    for key in stale {
        obj.remove(&key);
    }
    write_atomically(&p, &cfg.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Point `path()` at a fresh temp file for the duration of `f`, so no test
    /// in this module ever touches the real `config.json` — see the
    /// `TEST_PATH_OVERRIDE` doc comment above `path()`. The temp directory is
    /// removed again once `f` returns, whether or not it panics is not
    /// guaranteed (no `catch_unwind`), matching the best-effort cleanup style
    /// used elsewhere in this codebase's own temp-dir tests.
    fn with_test_config_path<T>(f: impl FnOnce() -> T) -> T {
        // A process-wide counter (not just pid+nanos) guarantees a distinct dir
        // per call: these tests carry no per-test `tag`, and the OS clock's
        // resolution is coarse enough that two tests starting in the same tick
        // would otherwise share one `config.json` and clobber each other.
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tickover-config-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SEQ.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("config.json");
        TEST_PATH_OVERRIDE.with(|o| *o.borrow_mut() = Some(path));
        let result = f();
        TEST_PATH_OVERRIDE.with(|o| *o.borrow_mut() = None);
        std::fs::remove_dir_all(&dir).ok();
        result
    }

    /// The half `with_test_config_path` cannot cover: a test that never calls
    /// it. Both tests below deliberately set **no** override — that is the
    /// state being checked.
    ///
    /// This is the one that would have caught the 2026-08-22 incident. The
    /// leaking test was not in this module and was not about config at all; it
    /// reached `set_builtin_migrated` through the production function it was
    /// exercising, and wrote five markers into the developer's live install.
    #[test]
    fn a_test_that_asked_for_nothing_still_writes_somewhere_disposable() {
        let resolved = path().expect("a test always resolves a config path");
        // Not "is not `<dir>/config.json`" but "is not under `<dir>` at all":
        // the narrower assertion passes for a sandbox writing
        // `<dir>/config-test.json`, which is still the user's directory.
        // `expect` rather than `if let`: a `None` would make the check
        // vacuously true, which is the shape of a guard that guards nothing.
        let real = dir().expect("the OS config dir resolves on every platform this runs on");
        assert!(
            !resolved.starts_with(&real),
            "an unsandboxed test must not write anywhere inside {}",
            real.display()
        );
        // And the other side of it. "Not in the config dir" alone is satisfied
        // by a home directory, or by `/`, which would be the same mistake one
        // class wider — the very generalisation this test exists to have
        // learned.
        assert!(
            resolved.starts_with(std::env::temp_dir()),
            "the scratch config belongs in the temp directory, not at {}",
            resolved.display()
        );

        // And the scratch file is a working config, not a hole: the incident
        // was a *write* that landed in the wrong place, so a fallback that
        // quietly dropped writes would trade one silent failure for another —
        // `a_delivered_built_in_is_not_delivered_again…` asserts on a marker
        // written by one call and read back by the next.
        let id = "tickover-scratch-probe";
        set_builtin_migrated(id, "9.9.9");
        assert_eq!(builtin_migrated(id).as_deref(), Some("9.9.9"));
    }

    /// Two reads with no write between them must parse the file only once —
    /// `get_bool_opt`/`get_u64`/`plugin_seen_window_for` sit on the
    /// one-second tick, and a reparse on every lookup is exactly the cost
    /// [`with_config`]'s cache exists to remove.
    #[test]
    fn two_reads_with_no_write_between_them_reparse_the_file_once() {
        with_test_config_path(|| {
            set_plugin_enabled("acme", true);
            take_read_count(); // drop whatever the write above already caused

            assert!(plugin_enabled("acme", false));
            assert!(plugin_enabled("acme", false));
            assert!(!plugin_ping("acme"));

            assert_eq!(
                take_read_count(),
                1,
                "the file is parsed once; the next two lookups are served from the cache"
            );
        });
    }

    /// A `config.json` edited by something other than this module — a user's
    /// text editor, another process — between two reads is picked up on the
    /// very next one: the cache [`with_config`] keeps is invalidated by a
    /// moved `mtime`/size, not only by this module's own writes.
    #[test]
    fn a_hand_edit_between_two_reads_is_picked_up() {
        with_test_config_path(|| {
            set_plugin_enabled("acme", true);
            assert!(plugin_enabled("acme", false), "the write above is visible");

            let p = path().expect("test config path resolves");
            let before = r#"{"plugin.acme.enabled":false}"#;
            std::fs::write(&p, before).expect("a hand edit outside this module");

            assert!(
                !plugin_enabled("acme", true),
                "the hand edit is visible on the next read, not a value cached from before it"
            );

            // A same-length edit moves nothing `stamp_of` could tell apart
            // through `len` alone — only `mtime` changes — so this is the
            // half of the stamp a length-only comparison would miss. The
            // mtime is set explicitly, ahead of `now`, rather than trusted to
            // land on a different value than `before`'s on its own: a
            // filesystem with second-resolution mtimes could otherwise stamp
            // both writes identically within the same test.
            let after = r#"{"plugin.acme.enabled":"aaa"}"#;
            assert_eq!(
                before.len(),
                after.len(),
                "this fixture only proves anything if the byte length does not move"
            );
            std::fs::write(&p, after).expect("a same-length hand edit");
            let touched = std::time::SystemTime::now() + std::time::Duration::from_secs(2);
            std::fs::OpenOptions::new()
                .write(true)
                .open(&p)
                .expect("open for mtime")
                .set_modified(touched)
                .expect("advance mtime explicitly");

            assert_eq!(
                with_config(|v| v["plugin.acme.enabled"].clone()),
                json!("aaa"),
                "a same-length hand edit is still picked up once its mtime has moved"
            );
        });
    }

    /// One scratch file per thread, resolved once — not one per call to
    /// `path()`. A fresh path each time reads back as an empty config, which
    /// every test about remembering something would fail on, and the marker
    /// tests would fail *loudly* rather than being sandboxed quietly.
    #[test]
    fn the_scratch_config_is_one_file_for_the_whole_test_not_a_new_one_per_call() {
        assert_eq!(path(), path());
    }

    /// A corrupt `config.json` used to be one preference change away from
    /// vanishing outright: `load` reads unparsable as empty, every setter
    /// builds its new value from that empty object, and `write_atomically`
    /// then overwrote the only copy with it — the corrupt bytes gone, and
    /// nothing on disk to even show what had been lost. `backup_if_corrupt`
    /// runs first now, so a copy survives under `config.json.corrupt-<unix
    /// secs>` and the log says so, before the setter's own change lands as
    /// usual.
    #[test]
    fn a_corrupt_config_is_backed_up_before_the_next_write_overwrites_it() {
        with_test_config_path(|| {
            let p = path().expect("test config path resolves");
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            let corrupt = "{not valid json";
            std::fs::write(&p, corrupt).expect("seed a corrupt file");
            let _ = crate::diag::take_recorded(); // drain anything left on this thread

            set_plugin_enabled("acme", true);

            let backups: Vec<_> = std::fs::read_dir(p.parent().unwrap())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .starts_with("config.json.corrupt-")
                })
                .collect();
            assert_eq!(
                backups.len(),
                1,
                "exactly one backup, named after the file it came from"
            );
            assert_eq!(
                std::fs::read_to_string(backups[0].path()).unwrap(),
                corrupt,
                "the corrupt bytes are preserved verbatim, not re-serialized"
            );

            assert!(
                plugin_enabled("acme", false),
                "the write that triggered the backup still landed"
            );

            let lines = crate::diag::take_recorded();
            assert!(
                lines
                    .iter()
                    .any(|l| l.contains("did not parse") && l.contains("corrupt-")),
                "expected a diagnostic naming the backup: {lines:?}"
            );
        });
    }

    /// The backup name is predictable — this second, not this
    /// process, unlike `write_atomically`'s own temp path — so anything
    /// running as this user can plant a symlink on it ahead of time.
    /// `std::fs::copy`'s destination-truncate would have followed that link
    /// and overwritten whatever it pointed to; `create_new` instead refuses
    /// the occupied name outright and falls through to the next
    /// counter-suffixed one, so the backup still lands somewhere.
    #[test]
    #[cfg(unix)]
    fn a_corrupt_backup_will_not_follow_a_symlink_planted_on_its_predictable_name() {
        with_test_config_path(|| {
            let p = path().expect("test config path resolves");
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            let corrupt = "{not valid json";
            std::fs::write(&p, corrupt).expect("seed a corrupt file");

            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let stem = p.file_name().unwrap().to_os_string();
            let name_for = |suffix: &str| {
                let mut n = stem.clone();
                n.push(suffix);
                p.with_file_name(n)
            };
            let predicted = name_for(&format!(".corrupt-{secs}"));
            let suffixed = name_for(&format!(".corrupt-{secs}-2"));

            let outside = p.with_file_name("precious-config-backup-victim.txt");
            std::fs::write(&outside, b"do not touch").unwrap();
            std::os::unix::fs::symlink(&outside, &predicted).expect("plant the link");

            set_plugin_enabled("acme", true);

            assert_eq!(
                std::fs::read(&outside).unwrap(),
                b"do not touch",
                "the link's target must be untouched"
            );
            assert!(
                std::fs::symlink_metadata(&predicted)
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false),
                "the link itself is left exactly as it was — refused, not cleared to make room"
            );
            assert_eq!(
                std::fs::read_to_string(&suffixed).unwrap(),
                corrupt,
                "the backup still lands, under the next name"
            );

            let _ = std::fs::remove_file(&outside);
            let _ = std::fs::remove_file(&predicted);
            let _ = std::fs::remove_file(&suffixed);
        });
    }

    /// A `config.json` holding valid JSON that isn't an object (here,
    /// `[]`) used to parse *fine* by `from_str::<Value>`'s own measure — so
    /// `backup_if_corrupt` waved it through, and every setter's
    /// `as_object_mut()` found nothing to insert into and silently discarded
    /// the change, then re-saved the same bare array right back. A setting
    /// could never be written again, with nothing on screen or in the log to
    /// say why.
    #[test]
    fn a_valid_but_non_object_config_is_treated_as_corrupt() {
        with_test_config_path(|| {
            let p = path().expect("test config path resolves");
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, "[]").expect("seed a non-object config");
            let _ = crate::diag::take_recorded();

            set_plugin_enabled("acme", true);

            assert!(
                plugin_enabled("acme", false),
                "the write must actually take, not silently no-op against the bare array"
            );

            let backups: Vec<_> = std::fs::read_dir(p.parent().unwrap())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .starts_with("config.json.corrupt-")
                })
                .collect();
            assert_eq!(
                backups.len(),
                1,
                "the bare array is backed up exactly like unparsable text"
            );
            assert_eq!(std::fs::read_to_string(backups[0].path()).unwrap(), "[]");

            let lines = crate::diag::take_recorded();
            assert!(
                lines
                    .iter()
                    .any(|l| l.contains("wasn't a JSON object") && l.contains("corrupt-")),
                "expected a diagnostic naming the backup, and not claiming the array \
                 \"did not parse\" when it plainly did: {lines:?}"
            );
        });
    }

    /// Reading `config.json` through a plain `std::fs::read_to_string` used
    /// to mean a FIFO planted at that path (deliberately, or a leftover from
    /// something else entirely) blocked `load` forever — every read of a
    /// preference, on every startup, hangs waiting for a writer that will
    /// never come. `read_regular_file` refuses anything that is not a
    /// regular file (or a symlink to one) before ever opening it in a way
    /// that could block, so this must come back with "no config" — the same
    /// as a missing file — not hang the test (and not the app) waiting on
    /// it. Unlike a missing file, though, something really is sitting at
    /// that path, refused for its kind rather than its absence, so `load`
    /// says so once rather than reading as indistinguishable from a fresh
    /// install.
    #[test]
    #[cfg(unix)]
    fn load_of_a_fifo_reads_as_no_config_instead_of_hanging() {
        with_test_config_path(|| {
            let p = path().expect("test config path resolves");
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            let made = std::process::Command::new("mkfifo").arg(&p).status();
            if !matches!(made, Ok(s) if s.success()) {
                // `mkfifo` isn't guaranteed present everywhere this test runs —
                // silently asserting nothing here used to look identical to the
                // FIFO case actually having been exercised. Print rather than
                // skip outright: a CI log that never shows this line is the one
                // place this gap would otherwise go unnoticed.
                eprintln!(
                    "SKIP: load_of_a_fifo_reads_as_no_config_instead_of_hanging — mkfifo unavailable"
                );
                return;
            }
            let _ = crate::diag::take_recorded(); // drain anything left on this thread

            assert_eq!(
                load(),
                json!({}),
                "a FIFO at config.json must read as no config, not hang"
            );

            let lines = crate::diag::take_recorded();
            assert!(
                lines
                    .iter()
                    .any(|l| l.contains("not a regular file")
                        && l.contains(&p.display().to_string())),
                "expected a diagnostic naming the FIFO, not silence: {lines:?}"
            );

            std::fs::remove_file(&p).ok();
        });
    }

    /// `plugin_option` follows the same config > manifest-default precedence
    /// as `plugin_enabled`/`plugin_ping`, with no well-known-id bridge to
    /// worry about. Runs against a disposable temp file (`with_test_config_path`)
    /// — never the real `config.json` a running app instance may hold open.
    #[test]
    fn plugin_option_defaults_then_reads_back_the_override() {
        with_test_config_path(|| {
            let id = "tickover-test-plugin-option-xyz";
            let key = "beta_mode";

            assert!(
                !plugin_option(id, key, false),
                "no override yet -> manifest default (false) wins"
            );
            assert!(
                plugin_option(id, key, true),
                "no override yet -> manifest default (true) wins"
            );

            set_plugin_option(id, key, true);
            assert!(
                plugin_option(id, key, false),
                "config override (true) wins over the manifest default"
            );

            set_plugin_option(id, key, false);
            assert!(
                !plugin_option(id, key, true),
                "an explicit false override also wins"
            );
        });
    }

    #[test]
    fn remove_plugin_keys_drops_only_that_plugins_generic_keys() {
        with_test_config_path(|| {
            set_plugin_enabled("gone", false);
            set_plugin_ping("gone", true);
            set_plugin_surface_enabled("gone", "cli", true);
            set_plugin_option("gone", "beta", true);
            // A different plugin's keys, and the well-known bridge keys, must
            // survive removing "gone".
            set_plugin_enabled("staying", true);
            set_auto_ping_codex(true);
            set_monitor_desktop(true);

            remove_plugin_keys("gone");

            assert!(
                plugin_enabled("gone", true),
                "override gone -> manifest default (true) wins again"
            );
            assert!(
                !plugin_ping("gone"),
                "ping override cleared -> generic key default (false)"
            );
            assert!(
                !plugin_surface_enabled("gone", "cli"),
                "surface override cleared"
            );
            assert!(
                !plugin_option("gone", "beta", false),
                "option override cleared"
            );

            assert!(
                plugin_enabled("staying", false),
                "a different plugin's keys are untouched"
            );
            assert!(
                auto_ping_codex(),
                "the codex/claude bridge keys are never touched by remove_plugin_keys"
            );
            assert!(
                monitor_desktop(),
                "the claude-desktop bridge key is never touched by remove_plugin_keys"
            );
        });
    }

    #[test]
    fn remove_plugin_keys_leaves_the_builtin_migrated_marker_in_place() {
        // A removed built-in must not look "never migrated" to the next
        // launch: seed::upgrade_builtin treats a plugin with no marker as
        // Absent and re-delivers the shipped manifest, undoing the very
        // Remove the user asked for. Everything else under `plugin.<id>.`
        // still goes, same as the generic-keys test above.
        // "antigravity", not "codex": `plugin_ping`/`set_plugin_ping` bridge
        // codex (and claude) straight to the legacy `auto_ping_codex` key,
        // which `remove_plugin_keys` never touches either — by design, same
        // as the bridge keys in the test above. A removable built-in with no
        // bridge is what actually exercises the generic-key sweep here.
        with_test_config_path(|| {
            set_builtin_migrated("antigravity", "1.2.0");
            set_plugin_enabled("antigravity", false);
            set_plugin_ping("antigravity", true);

            remove_plugin_keys("antigravity");

            assert_eq!(
                builtin_migrated("antigravity").as_deref(),
                Some("1.2.0"),
                "builtin_migrated must survive remove_plugin_keys"
            );
            assert!(
                plugin_enabled("antigravity", true),
                "every other override for the plugin is still cleared"
            );
            assert!(!plugin_ping("antigravity"), "ping override cleared");
        });
    }

    #[test]
    fn remove_plugin_keys_is_a_no_op_when_the_plugin_has_no_stored_state() {
        with_test_config_path(|| {
            // Must not create a config.json (or panic) for a plugin id that
            // was never given a config override.
            remove_plugin_keys("never-configured");
            assert!(path().map(|p| !p.exists()).unwrap_or(true));
        });
    }

    /// The seen-window registry: absent reads as `None` (never seen), a stored
    /// entry reads back whole, entries for other readings and other roles of
    /// the same plugin are separate, and the lot goes with the plugin when it
    /// is removed — a reinstalled plugin must not inherit the window history of
    /// the one it replaced.
    #[test]
    fn the_seen_window_registry_round_trips_per_reading_and_role() {
        with_test_config_path(|| {
            assert_eq!(
                plugin_seen_window_for("acme", "acme", "primary"),
                None,
                "absent reads as never seen"
            );

            let five_h = SeenWindow {
                at: 1_700_000_000,
                period_minutes: Some(300),
            };
            let weekly = SeenWindow {
                at: 1_700_500_000,
                period_minutes: Some(10_080),
            };
            set_plugin_seen_window_for("acme", "acme", "primary", five_h);
            set_plugin_seen_window_for("acme", "acme", "secondary", weekly);
            set_plugin_seen_window_for("acme", "acme-desktop", "primary", weekly);
            set_plugin_seen_window_for("other", "other", "primary", weekly);

            assert_eq!(
                plugin_seen_window_for("acme", "acme", "primary"),
                Some(five_h)
            );
            assert_eq!(
                plugin_seen_window_for("acme", "acme", "secondary"),
                Some(weekly),
                "the other role of the same reading is its own entry"
            );
            assert_eq!(
                plugin_seen_window_for("acme", "acme-desktop", "primary"),
                Some(weekly),
                "a second surface of the same plugin is its own entry"
            );

            remove_plugin_keys("acme");
            assert_eq!(
                plugin_seen_window_for("acme", "acme", "primary"),
                None,
                "removed with the plugin"
            );
            assert_eq!(
                plugin_seen_window_for("acme", "acme", "secondary"),
                None,
                "removed with the plugin"
            );
            assert_eq!(
                plugin_seen_window_for("acme", "acme-desktop", "primary"),
                None,
                "every surface's entry goes with the plugin"
            );
            assert_eq!(
                plugin_seen_window_for("other", "other", "primary"),
                Some(weekly),
                "another plugin is untouched"
            );
        });
    }

    /// A window whose length the provider never stated is stored as such, and
    /// reads back as `None` rather than as a zero-length window — the reader
    /// that projects the next boundary has to be able to tell that it can't.
    #[test]
    fn a_seen_window_without_a_stated_length_reads_back_as_unknown_not_as_zero() {
        with_test_config_path(|| {
            let no_length = SeenWindow {
                at: 1_700_000_000,
                period_minutes: None,
            };
            set_plugin_seen_window_for("acme", "acme", "primary", no_length);
            assert_eq!(
                plugin_seen_window_for("acme", "acme", "primary"),
                Some(no_length)
            );

            // And a length arriving later replaces it rather than sitting
            // beside the old value.
            let with_length = SeenWindow {
                at: 1_700_000_000,
                period_minutes: Some(300),
            };
            set_plugin_seen_window_for("acme", "acme", "primary", with_length);
            assert_eq!(
                plugin_seen_window_for("acme", "acme", "primary"),
                Some(with_length)
            );
        });
    }

    /// Like `set_u64`, the registry's setter runs on the one-second UI tick, so
    /// an unchanged entry must not cost a file write per second.
    #[test]
    fn the_registry_setter_does_not_rewrite_the_file_for_an_unchanged_entry() {
        with_test_config_path(|| {
            let seen = SeenWindow {
                at: 1_700_000_000,
                period_minutes: Some(300),
            };
            set_plugin_seen_window_for("acme", "acme", "primary", seen);
            take_write_count(); // drop the write above; only the second call is under test
            set_plugin_seen_window_for("acme", "acme", "primary", seen);
            assert_eq!(
                take_write_count(),
                0,
                "an unchanged entry must not touch the file"
            );
        });
    }

    /// A `0` boundary reads back as `None` (see `plugin_seen_window_for`
    /// above), so writing one would never compare equal to what the next read
    /// returns — before this guard the setter rewrote `config.json` on every
    /// single call it was given one, forever, and never once remembered it.
    #[test]
    fn the_registry_setter_refuses_a_zero_boundary_instead_of_rewriting_forever() {
        with_test_config_path(|| {
            let zero = SeenWindow {
                at: 0,
                period_minutes: Some(300),
            };
            set_plugin_seen_window_for("acme", "acme", "primary", zero);
            assert_eq!(
                take_write_count(),
                0,
                "a zero boundary is never worth a write"
            );
            assert_eq!(
                plugin_seen_window_for("acme", "acme", "primary"),
                None,
                "and nothing was remembered"
            );

            set_plugin_seen_window_for("acme", "acme", "primary", zero);
            assert_eq!(
                take_write_count(),
                0,
                "repeating it costs no write either — not a rewrite every call"
            );
        });
    }

    /// The auto-ping's timestamps: absent reads as `0` (never seen, never
    /// pinged), a stored value reads back, and both go with the plugin when it
    /// is removed — a reinstalled plugin must not inherit the ping history of
    /// the one it replaced. `seen_window` is the pre-registry key, still read
    /// as a fallback (`main.rs::seen_window_of`) and never written any more.
    #[test]
    fn auto_ping_timestamps_round_trip_and_are_removed_with_the_plugin() {
        with_test_config_path(|| {
            assert_eq!(plugin_seen_window("acme"), 0, "absent reads as never");
            assert_eq!(plugin_pinged_at("acme"), 0, "absent reads as never");

            set_plugin_seen_window("acme", 1_700_000_000);
            set_plugin_pinged_at("acme", 1_700_000_005);
            set_plugin_seen_window("other", 1_700_000_111);
            assert_eq!(plugin_seen_window("acme"), 1_700_000_000);
            assert_eq!(plugin_pinged_at("acme"), 1_700_000_005);

            remove_plugin_keys("acme");
            assert_eq!(plugin_seen_window("acme"), 0, "removed with the plugin");
            assert_eq!(plugin_pinged_at("acme"), 0, "removed with the plugin");
            assert_eq!(
                plugin_seen_window("other"),
                1_700_000_111,
                "another plugin is untouched"
            );
        });
    }

    /// `set_u64` writes only when the value moves — it runs on the one-second
    /// UI tick, and a rewrite per tick would be a file write per second.
    #[test]
    fn set_u64_does_not_rewrite_the_file_for_an_unchanged_value() {
        with_test_config_path(|| {
            set_plugin_pinged_at("acme", 1_700_000_005);
            take_write_count(); // drop the write above; only the second call is under test
            set_plugin_pinged_at("acme", 1_700_000_005);
            assert_eq!(
                take_write_count(),
                0,
                "an unchanged value must not touch the file"
            );
        });
    }

    // ── legacy config-dir migration ────────────────────────────────────────
    //
    // `migrate_legacy_dir` itself is never called from these tests — it
    // resolves the real `dirs::config_dir()`, and running it unguarded would
    // rename part of the developer's actual config directory the moment a
    // test happened to run without a substituted `HOME`. `migrate_legacy_dir_at`
    // is the same rename against paths a test supplies instead, so everything
    // below exercises the whole rest of the logic without going anywhere near
    // the real one.

    /// A fresh `(old, new)` pair under a disposable temp directory, mirroring
    /// `test_scratch_path`'s pid + nanos + counter (two tests starting in the
    /// same clock tick must not share a directory).
    fn temp_legacy_pair(tag: &str) -> (PathBuf, PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "tickover-migrate-test-{tag}-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SEQ.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&base).expect("create temp base");
        (base.join("codex-limits"), base.join("tickover"))
    }

    #[test]
    fn migrate_legacy_dir_moves_the_old_directory_and_its_log() {
        let (old, new) = temp_legacy_pair("happy");
        std::fs::create_dir_all(&old).expect("seed old dir");
        std::fs::write(old.join("config.json"), "{}").expect("seed config");
        std::fs::write(old.join("codex-limits.log"), "a line\n").expect("seed log");

        let migrated = migrate_legacy_dir_at(&old, &new).expect("migration succeeds");
        assert!(
            migrated,
            "an existing old directory with no new one is a migration"
        );
        assert!(!old.exists(), "the old directory is gone, not copied");
        assert_eq!(
            std::fs::read_to_string(new.join("config.json")).unwrap(),
            "{}"
        );
        assert_eq!(
            std::fs::read_to_string(new.join("tickover.log")).unwrap(),
            "a line\n"
        );
        assert!(
            !new.join("codex-limits.log").exists(),
            "the log moved under its new name"
        );

        std::fs::remove_dir_all(new.parent().unwrap()).ok();
    }

    #[test]
    fn migrate_legacy_dir_leaves_both_alone_when_the_new_directory_already_exists() {
        let (old, new) = temp_legacy_pair("both-exist");
        std::fs::create_dir_all(&old).expect("seed old dir");
        std::fs::write(old.join("config.json"), "{\"stale\":true}").expect("seed old config");
        std::fs::create_dir_all(&new).expect("seed new dir");
        std::fs::write(new.join("config.json"), "{\"live\":true}").expect("seed new config");

        let migrated = migrate_legacy_dir_at(&old, &new).expect("no error");
        assert!(
            !migrated,
            "a new directory already there means nothing to migrate"
        );
        assert!(old.exists(), "the old directory is untouched");
        assert_eq!(
            std::fs::read_to_string(old.join("config.json")).unwrap(),
            "{\"stale\":true}",
            "not overwritten, not moved"
        );
        assert_eq!(
            std::fs::read_to_string(new.join("config.json")).unwrap(),
            "{\"live\":true}",
            "the live directory is untouched too"
        );

        std::fs::remove_dir_all(new.parent().unwrap()).ok();
    }
}
