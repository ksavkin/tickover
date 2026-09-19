//! Generic log-file usage engine (`engine = "log-file"`).
//!
//! It walks a provider's local rollout/log files (Codex's
//! `~/.codex/sessions/**/rollout-*.jsonl` is the shape it was built for,
//! though Codex itself now reads its usage API through the `http-api` engine
//! instead — no shipped manifest currently declares `engine = "log-file"`; a
//! Codex-like fixture in `tests/reader.rs` and this module's own `tests`
//! below both keep it covered) looking for a JSON container that carries a
//! `primary` and/or a `secondary` named window — a container missing one of
//! the two is read as reporting only the other, not discarded — each with a
//! `used_percent` (0–100) and (usually) a `resets_at` and `window_minutes`.
//!
//! Everything a manifest's `[[windows]]` list can vary — labels, UI role,
//! nominal-period source (`assumed` vs `from_field`), and the min/max period
//! bounds used to classify an ambiguous slot — is read from
//! [`crate::plugin::manifest::WindowConfig`]. What can **not** be configured
//! is:
//!
//! * the container's own shape: a `primary`/`secondary` pair of objects,
//!   found either under the manifest's `container_key` or, failing that, by
//!   an inline shape match anywhere in the JSON line ([`find_container`]);
//! * the field-spelling tolerance inside each slot (`used_percent` /
//!   `usedPercent` / `percent_used`, `resets_at` / `resetsAt` / `reset_at`,
//!   `window_minutes` / `windowMinutes`) — a provider's own log format may
//!   drift between releases, so this engine bakes in a fixed set of
//!   defensive aliases rather than exposing them as manifest knobs;
//! * mtime-based freshness with cross-file fallback: files are walked
//!   newest-first by mtime (not filename), and the newest file with *no*
//!   `container_key` reading falls through to the next one.
//!
//! When no reading is found at all, this engine distinguishes "not
//! installed" from "installed, no data yet" through manifest knobs rather
//! than a hardcoded binary name: `[logfile] detect_bin` names the executable
//! to look up on `PATH`, and `not_installed_message` / `no_data_message` are
//! the two messages ([`no_reading_message`]). A manifest that sets neither
//! falls back to the single generic message this engine has always shown.
//!
//! [`fetch`] is the engine's public entry point; [`fetch_from_root`] is the
//! same logic with the root directory injected, so tests never touch
//! `$HOME` or real env vars.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value;

use crate::model::{ProviderReading, TokenRenewal, Window};
use crate::plugin::manifest::{
    AccountMatchConfig, AccountType, LogFileConfig, LogFileFormat, LogFileSelect, PeriodMode,
    PluginManifest, ResetsAtFormat, Role as ManifestRole, WindowConfig,
};
use crate::plugin::time::parse_iso8601;

// ── Public entry point ───────────────────────────────────────────────────

/// Read one provider's log-file usage. Always returns exactly one reading —
/// this engine has no notion of multiple surfaces (unlike `engine_http`'s
/// per-account CLI/desktop split), so `active_surface_ids` is unused.
///
/// `options` is the plugin's declared `[[option]]` set resolved to its
/// current value (`crate::config::plugin_option`, read by the caller —
/// this engine is hermetic and never reads config itself); it drives the
/// `{option.<key>}` substitution in `root`/`root_env_join`/`glob` (see
/// [`resolve_root`], [`fetch_from_root`]).
pub fn fetch(
    m: &PluginManifest,
    _active_surface_ids: &[String],
    options: &BTreeMap<String, bool>,
) -> Vec<ProviderReading> {
    match m.logfile.as_ref() {
        Some(lf) => {
            let root = resolve_root(lf, options);
            // One walk per fetch, shared by both readers below. These trees
            // are somebody else's and they are not small — 3975 files on the
            // author's machine — so walking them twice to answer one question
            // is a cost with nothing to show for it. Sorted once here too —
            // `fetch_from_root` and `secondary_accounts` both trust the order
            // they are handed rather than each re-sorting their own copy.
            let glob = crate::plugin::substitute_options(&lf.glob, options);
            let mut files = collect_log_files(&root, &glob);
            newest_first(&mut files);
            let files = cap_to_newest_files(files, &m.id);
            // The primary row: the current login's account, `id = <plugin id>`.
            // Its `account_match` filter keeps a shared session tree from
            // showing another account's usage under this login (see
            // `resolve_account_match`) — resolved once here (a file read, a
            // base64 decode, and a JSON parse) rather than separately by each
            // of the two callers below.
            let account_match = resolve_account_match(m, lf);
            let mut out = vec![fetch_from_root(
                m,
                lf,
                &root,
                &files,
                account_match.as_ref(),
            )];
            // Additional rows, one per *other* account whose readings share the
            // same log tree (Codex Desktop signed into a different ChatGPT
            // account than the CLI). Empty unless `[logfile.account_match]` is
            // configured and the current login's identity is readable — so a
            // plain single-account plugin is completely unaffected.
            out.extend(secondary_accounts(m, lf, &files, account_match.as_ref()));
            out
        }
        // Built and then failed, rather than assembled with `error` set by
        // hand. The invariant "an error claims nothing about the provider"
        // lives in `ProviderReading::fail`, and a second path that sets `error`
        // itself is a second place for it to live — which is how it would come
        // to be true in one place and not the other. The gate is stated as
        // "no path constructs a reading with an error and a non-empty
        // windows/status/balances", and a path that never sets them by hand
        // satisfies it by construction.
        None => {
            let mut reading = ProviderReading {
                id: m.id.clone(),
                name: m.name.clone(),
                short: m.menu_label.clone(),
                tag: None,
                account: None,
                windows: Vec::new(),
                quota_status: None,
                balances: Vec::new(),
                error: None,
                token_renewal: TokenRenewal::No,
                in_menu_bar: default_surface_in_menu_bar(m),
                bare_when_sole: false,
            };
            reading.fail("log-file engine invoked without a [logfile] section");
            vec![reading]
        }
    }
}

fn default_surface_in_menu_bar(m: &PluginManifest) -> bool {
    m.surface.first().map(|s| s.in_menu_bar).unwrap_or(true)
}

/// Root that holds the log files: `root_env` (if set and the env var exists)
/// takes it verbatim as the root — joined with `root_env_join`, if the
/// manifest sets one — else `root` (`~`/`{config_dir}`-expanded — see
/// [`crate::plugin::expand_home`]). Both `root` and `root_env_join` get
/// `{option.<key>}` substitution first (see
/// [`crate::plugin::substitute_options`]).
///
/// `root_env_join` exists for a layout like Codex's: `$CODEX_HOME/sessions`
/// rather than `$CODEX_HOME` itself, so a `$CODEX_HOME` override does not
/// widen a recursive `glob` to rollout files outside `sessions/` (e.g.
/// archived ones), which could make mtime-based freshness pick the wrong
/// one.
fn resolve_root(lf: &LogFileConfig, options: &BTreeMap<String, bool>) -> PathBuf {
    if let Some(env_name) = &lf.root_env {
        if let Some(v) = std::env::var_os(env_name) {
            let base = PathBuf::from(v);
            return match &lf.root_env_join {
                Some(sub) => base.join(crate::plugin::substitute_options(sub, options)),
                None => base,
            };
        }
    }
    crate::plugin::expand_home(&crate::plugin::substitute_options(&lf.root, options))
}

/// The root-injectable core of the engine — everything [`fetch`] does except
/// resolving `root` from the manifest/env, so tests can point it at a
/// fixture directory without touching `$HOME` or real env vars.
///
/// Takes no `options`: every `{option.<key>}` substitution this engine makes
/// (`root`, `root_env_join`, `glob`) happens in [`fetch`] before `files` is
/// ever walked, so by the time a caller reaches this function the option set
/// has already done its only job. `account_match` is likewise resolved by
/// the caller, once, rather than asked for again here — see
/// [`resolve_account_match`].
fn fetch_from_root(
    m: &PluginManifest,
    lf: &LogFileConfig,
    root: &Path,
    files: &[LogFile],
    account_match: Option<&(String, String)>,
) -> ProviderReading {
    let mut reading = ProviderReading {
        id: m.id.clone(),
        name: m.name.clone(),
        short: m.menu_label.clone(),
        tag: None,
        account: resolve_account(m),
        windows: Vec::new(),
        quota_status: None,
        // This engine reads log lines: a line records a window, never a
        // balance, so nothing here can fill one.
        balances: Vec::new(),
        error: None,
        token_renewal: TokenRenewal::No,
        in_menu_bar: default_surface_in_menu_bar(m),
        bare_when_sole: false,
    };

    match latest_reading(
        files,
        &m.id,
        &lf.container_key,
        account_match,
        lf.format,
        lf.select,
    ) {
        Some(raw) => {
            reading.tag = resolve_tag(m, Some(&raw.container));
            match windows_from_raw(m, lf, &raw) {
                Ok(windows) => reading.windows = windows,
                Err(message) => reading.fail(message),
            }
        }
        None => {
            reading.fail(no_reading_message(m, lf, root));
        }
    }
    reading
}

/// Build the manifest's configured windows from one raw container reading —
/// the shared body of both the primary reading ([`fetch_from_root`]) and each
/// secondary account row ([`build_secondary_reading`]).
///
/// A window the reading does not carry is left out rather than emitted blank,
/// the same rule the HTTP engine follows (`engine_http::build_window`) and for
/// the same reason: a row with no figure in it is the reading saying there is
/// no such window, not saying it knows nothing about one.
fn windows_from_raw(
    m: &PluginManifest,
    lf: &LogFileConfig,
    raw: &RawReading,
) -> Result<Vec<Window>, String> {
    crate::plugin::collect_windows(m, "reading", |i, w| {
        let slot = classify_slot(
            w,
            lf.classify_threshold_minutes,
            &raw.primary,
            &raw.secondary,
        );
        // Zero or one, never more: a log record carries a window's fields
        // directly, with no array to expand over, which is why `validate`
        // refuses `for_each` on this engine rather than leaving it to be
        // ignored here.
        build_window(i, w, slot.as_ref()).into_iter().collect()
    })
}

/// How stale an account's freshest reading may be and still earn its own row:
/// one weekly window (10080 min). A reading older than that describes a quota
/// window that has since reset, so the account is treated as gone rather than
/// shown with a number from a bygone window. Bounds recency by the reading's
/// own `timestamp`, not file mtime — Codex rewrites/compacts session files, so
/// mtime can be far newer than the newest line inside (a real anomaly observed
/// on disk), which would otherwise resurrect a long-abandoned account.
const SECONDARY_RECENCY_SECS: u64 = 10_080 * 60;

/// One account's freshest usable reading, discovered while grouping a shared
/// session tree by `account_match.container_field`.
struct PlanGroup {
    /// The reading line's own `timestamp`, Unix seconds — used for recency.
    ts: u64,
    raw: RawReading,
}

/// The extra rows beyond the primary: one per *other* account (a distinct
/// `container_field` value) whose readings live in the same session tree. Only
/// meaningful when `[logfile.account_match]` is set — otherwise there's no
/// notion of "this login" to contrast against, so this is empty and the engine
/// behaves as a plain single-account reader.
///
/// Each row gets a distinct reading id `"<plugin id>#<value>"` (e.g.
/// `"codex#plus"`), so the popup's per-row window model doesn't collide with
/// the primary's (they'd share a key otherwise). Rows are popup-only
/// (`in_menu_bar = false`) — the menu-bar pill stays pinned to the current
/// login — and carry no email (a rollout log holds no account identity beyond
/// its plan tier, so the *other* account can only be labelled by plan).
///
/// `account_match` is resolved once by [`fetch`] and handed to both this and
/// [`fetch_from_root`], rather than asked for again here.
fn secondary_accounts(
    m: &PluginManifest,
    lf: &LogFileConfig,
    files: &[LogFile],
    account_match: Option<&(String, String)>,
) -> Vec<ProviderReading> {
    // No account_match (or an unreadable current login) → no "other accounts"
    // to contrast against. The primary row already stands alone.
    let Some((field, expected)) = account_match else {
        return Vec::new();
    };
    let groups = collect_plan_groups(files, &m.id, &lf.container_key, field);

    // Recency is measured against the freshest reading of *any* account, so a
    // quiet-but-current login still anchors "recent" for its busier siblings.
    let Some(reference) = groups.values().map(|g| g.ts).max() else {
        return Vec::new();
    };
    // `reference` is a reading line's own `timestamp` — content a provider's
    // log wrote, not a clock this app controls. A corrupted line or a clock
    // running fast could claim a timestamp past "now"; letting that push the
    // cutoff into the future would silently exclude every genuinely current
    // account, which is the opposite of what a recency cutoff is for.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(reference);
    let cutoff = reference.min(now).saturating_sub(SECONDARY_RECENCY_SECS);

    // BTreeMap iteration is key-sorted → a deterministic row order without any
    // clock/RNG (both unavailable to the engine).
    groups
        .iter()
        .filter(|(value, _)| value.as_str() != expected.as_str()) // the primary already covers this login
        .filter(|(_, g)| g.ts >= cutoff) // drop accounts whose window has since reset
        .map(|(value, g)| build_secondary_reading(m, lf, value, &g.raw))
        .collect()
}

/// A secondary account's popup row. Distinct id, plan-only label, no email,
/// popup-only — see [`secondary_accounts`].
fn build_secondary_reading(
    m: &PluginManifest,
    lf: &LogFileConfig,
    value: &str,
    raw: &RawReading,
) -> ProviderReading {
    // A secondary account row carries the same verdict as the primary one: a
    // reading nothing could be got out of is an error here too, rather than an
    // account whose section is silently blank.
    //
    // `value` is `account_match.container_field`'s raw text out of a log
    // line a provider wrote — control characters, bidi overrides, up to
    // `MAX_LINE_BYTES` of it — and this id becomes a config key and the
    // popup's per-row model key, the same two things a window's key becomes
    // (`crate::plugin::window_key`). Sanitised for the same reason
    // `sanitize_provider_text` exists (this text is not merely displayed —
    // this exact string is what this id is built from) and capped by it
    // before `encode_key_part` ever sees it, so a provider filling this
    // field with a megabyte cannot inflate the id to three times that in
    // `%XX` escapes.
    let id = format!(
        "{}#{}",
        m.id,
        crate::plugin::encode_key_part(&crate::plugin::sanitize_provider_text(value))
    );
    let mut reading = ProviderReading {
        id,
        name: m.name.clone(),
        short: m.menu_label.clone(),
        tag: resolve_tag(m, Some(&raw.container)),
        account: None,
        windows: Vec::new(),
        balances: Vec::new(),
        error: None,
        token_renewal: TokenRenewal::No,
        // This engine reads log lines, which carry no statement about the
        // quota as a whole — only the windows a session happened to record.
        // A manifest that declares `[status]` here is refused at validation
        // rather than quietly ignored (`PluginManifest::validate`).
        quota_status: None,
        in_menu_bar: false,
        bare_when_sole: false,
    };
    // Through `fail()` rather than by assembling the failed shape by hand, so
    // the "an error carries no claims" rule has one implementation. Assembled
    // here, it was a second one that happened to agree — and a rule living in
    // two places is the shape this project's last latent hole had.
    match windows_from_raw(m, lf, raw) {
        Ok(windows) => reading.windows = windows,
        Err(message) => reading.fail(message),
    }
    reading
}

/// Group a session tree by `field` (e.g. `plan_type`): for each distinct value,
/// the reading with the newest `timestamp` that actually carries window data.
/// Containers with no slots (Codex emits bare `rate_limits` lines) and those
/// whose `field` is absent/non-string are skipped, so a plan-less or empty
/// line can't spawn a phantom row. `files` is expected to already be sorted
/// newest-first ([`newest_first`]) — the walk stops once mtime falls a couple
/// of weekly windows behind the newest entry, `files[0]` — a cost bound only
/// (selection is by the line's own `timestamp`), generous enough that the
/// file-mtime anomaly can't hide a genuinely recent line.
///
/// Bounded by its own [`FETCH_BYTE_BUDGET`], separate from
/// [`latest_reading`]'s own — the two run one after the other in [`fetch`]
/// and a shared budget would let whichever ran first spend all of it.
/// `plugin_id` is for the one diagnostic this can produce.
fn collect_plan_groups(
    files: &[LogFile],
    plugin_id: &str,
    container_key: &str,
    field: &str,
) -> BTreeMap<String, PlanGroup> {
    let mtime_secs = |t: SystemTime| {
        t.duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    };
    let newest_mtime = files.first().map(|(_, mt, _)| mtime_secs(*mt)).unwrap_or(0);
    let mtime_floor = newest_mtime.saturating_sub(SECONDARY_RECENCY_SECS.saturating_mul(2));

    let mut groups: BTreeMap<String, PlanGroup> = BTreeMap::new();
    let mut budget = FETCH_BYTE_BUDGET;
    for (path, mtime, len) in files {
        if mtime_secs(*mtime) < mtime_floor {
            break;
        }
        let cost = tail_cost(*len);
        if cost > budget {
            queue_diag_once(plugin_id, "secondary-byte-budget", || {
                format!(
                    "{plugin_id}: the secondary-accounts log scan hit its \
                     {FETCH_BYTE_BUDGET}-byte-per-fetch limit before finishing every matched file"
                )
            });
            break;
        }
        budget -= cost;
        for (value, (ts, raw)) in parse_file_groups(path, container_key, field) {
            let newer = groups.get(&value).is_none_or(|g| ts > g.ts);
            if newer {
                groups.insert(value, PlanGroup { ts, raw });
            }
        }
    }
    groups
}

/// Longest single log line this engine will hold in memory.
///
/// `BufRead::lines` is unbounded: one line is one allocation, however long the
/// line is. These files are written by somebody else's tool, they are already
/// gigabytes in aggregate on a working machine, and a truncated or binary file
/// can easily contain no newline at all — at which point "read a line" means
/// "read the whole file into memory", on a thread the panel is waiting for.
/// 4 MiB is far above any real rate-limit line and far below anything that
/// hurts.
const MAX_LINE_BYTES: u64 = 4 * 1024 * 1024;

/// How much of a log file's tail is read.
///
/// Both readers here want the *last* reading in a file, and both used to scan
/// the whole file to find it — every refresh, forever. That is fine for a log
/// of a few megabytes and absurd for what these directories actually grow to:
/// measured on the author's machine, 3975 rollout files totalling 4.9 GB, with
/// single sessions large enough that one pass took minutes. Reading only the
/// tail bounds the work per refresh at a fixed cost no matter how large the
/// file gets. What it gives up is readings older than the last 8 MiB of a
/// file, which neither caller wants: one keeps only the newest reading, the
/// other only the newest per account.
const TAIL_BYTES: u64 = 8 * 1024 * 1024;

/// A reader positioned over the last [`TAIL_BYTES`] of `file`, with any
/// partial first line discarded so the caller always starts on a line
/// boundary. A file shorter than the window is read from the beginning.
fn tail_reader(mut file: File) -> std::io::Result<BufReader<File>> {
    let len = file.metadata()?.len();
    if len <= TAIL_BYTES {
        return Ok(BufReader::new(file));
    }
    file.seek(std::io::SeekFrom::Start(len - TAIL_BYTES))?;
    let mut reader = BufReader::new(file);
    // Whatever line the seek landed inside of is half a line; skip it.
    let mut partial = Vec::new();
    let _ = read_line_capped(&mut reader, &mut partial)?;
    Ok(reader)
}

/// What [`read_line_capped`] found.
enum CappedLine {
    /// End of file.
    Eof,
    /// A complete line, in `buf`.
    Read,
    /// A line longer than [`MAX_LINE_BYTES`]; `buf` is meaningless and the
    /// reader has been advanced past it. Skipped rather than truncated: half
    /// a JSON object is not a reading, and pretending otherwise would parse
    /// garbage.
    TooLong,
}

fn read_line_capped(reader: &mut impl BufRead, buf: &mut Vec<u8>) -> std::io::Result<CappedLine> {
    buf.clear();
    let read = reader
        .by_ref()
        .take(MAX_LINE_BYTES)
        .read_until(b'\n', buf)?;
    if read == 0 {
        return Ok(CappedLine::Eof);
    }
    if !buf.ends_with(b"\n") && read as u64 == MAX_LINE_BYTES {
        // Drain the rest of the oversized line without keeping any of it.
        let mut skip = Vec::new();
        loop {
            skip.clear();
            let n = reader
                .by_ref()
                .take(MAX_LINE_BYTES)
                .read_until(b'\n', &mut skip)?;
            if n == 0 || skip.ends_with(b"\n") {
                break;
            }
        }
        return Ok(CappedLine::TooLong);
    }
    Ok(CappedLine::Read)
}

/// One file's readings, folded down to at most one per `field` value as the
/// scan goes rather than materialised line by line and folded afterwards: a
/// value's kept entry is only replaced by a line with a strictly newer
/// `timestamp`, so a tie keeps whichever line came first in file-read order,
/// and a line that cannot beat what is already kept never pays for
/// [`parse_container`]'s clone of the whole container at all. A line missing
/// a window-bearing container, a string `field`, or a parseable top-level
/// `timestamp` is skipped.
fn parse_file_groups(
    path: &Path,
    container_key: &str,
    field: &str,
) -> BTreeMap<String, (u64, RawReading)> {
    let mut out: BTreeMap<String, (u64, RawReading)> = BTreeMap::new();
    let Ok(file) = File::open(path) else {
        return out;
    };
    let Ok(mut reader) = tail_reader(file) else {
        return out;
    };
    let needle = format!("\"{container_key}\"");
    let mut buf = Vec::new();
    loop {
        match read_line_capped(&mut reader, &mut buf) {
            Ok(CappedLine::Eof) | Err(_) => break,
            Ok(CappedLine::TooLong) => continue,
            Ok(CappedLine::Read) => {}
        }
        let Ok(line) = std::str::from_utf8(&buf) else {
            continue;
        };
        if !line.contains(&needle) {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(container) = find_container(&value, container_key) else {
            continue;
        };
        let Some(field_value) = json_path(container, field).and_then(Value::as_str) else {
            continue; // no plan tier → not attributable to an account
        };
        let Some(ts) = value
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(parse_iso8601)
        else {
            continue; // no timestamp → can't place it on the recency line
        };
        if out
            .get(field_value)
            .is_some_and(|(kept_ts, _)| ts <= *kept_ts)
        {
            continue; // this file already kept a line for `field_value` at least as new
        }
        let Some(raw) = parse_container(container) else {
            continue; // a slot-less container carries no usage
        };
        out.insert(field_value.to_string(), (ts, raw));
    }
    out
}

/// The error message shown when no reading was found at all — distinguishes
/// "not installed" from "installed but no data yet". Both messages fall back
/// to the pre-existing generic wording when a manifest doesn't set them, so
/// a log-file plugin without `detect_bin` behaves exactly as one always did
/// before these two messages existed.
fn no_reading_message(m: &PluginManifest, lf: &LogFileConfig, root: &Path) -> String {
    let generic = format!("No {} usage data found yet.", m.name);
    let not_installed = lf
        .detect_bin
        .as_deref()
        .is_some_and(|bin| !bin_in_path(bin) && !root.is_dir());
    if not_installed {
        lf.not_installed_message.clone().unwrap_or(generic)
    } else {
        lf.no_data_message.clone().unwrap_or(generic)
    }
}

/// Whether an executable named `name` is resolvable on `PATH`, including
/// the Windows executable-extension search.
fn bin_in_path(name: &str) -> bool {
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".cmd", ".bat"]
    } else {
        &[""]
    };
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| {
        exts.iter().any(|ext| {
            // Appended, not `set_extension`: a `detect_bin` is free text out
            // of a manifest, and a name that already contains a dot —
            // `claude.js`, `node.exe` — would have that suffix *replaced*
            // rather than extended, so the file actually on disk is the one
            // name this would never look for.
            let mut file = dir.join(name).into_os_string();
            file.push(ext);
            std::path::Path::new(&file).is_file()
        })
    })
}

// ── Slot classification ──────────────────────────────────────────────────

/// One raw quota slot as read out of the container's `primary`/`secondary`
/// object. `resets_at` is kept as the raw JSON value (rather than
/// pre-converted to Unix seconds) because its interpretation depends on the
/// *matched window's* `source.resets_at_format`, which isn't known until
/// after classification.
#[derive(Debug, Clone, PartialEq)]
struct RawSlot {
    used_percent: f64,
    resets_at_raw: Option<Value>,
    window_minutes: Option<u64>,
}

/// A parsed container reading: up to two raw slots plus the container value
/// itself (for `[tag] from = "field"` lookups, e.g. Codex's `plan_type`).
#[derive(Debug, Clone)]
struct RawReading {
    primary: Option<RawSlot>,
    secondary: Option<RawSlot>,
    container: Value,
}

/// Effective `[min, max]` period-length bounds (minutes) a raw slot must
/// fall in to classify as this window. Defaults from `classify_threshold_minutes`
/// (short = primary, long = secondary), narrowed by an explicit
/// `source.min_period_minutes`/`max_period_minutes` when the manifest sets one.
fn effective_bounds(w: &WindowConfig, threshold: u64) -> (u64, u64) {
    match w.role {
        ManifestRole::Primary => (
            w.source.min_period_minutes.unwrap_or(0),
            w.source.max_period_minutes.unwrap_or(threshold),
        ),
        ManifestRole::Secondary => (
            w.source
                .min_period_minutes
                .unwrap_or(threshold.saturating_add(1)),
            w.source.max_period_minutes.unwrap_or(u64::MAX),
        ),
        // A quota that is not the subscription has no default length to be
        // short or long *relative to*: a log line's two slots are the
        // subscription's own pair. It classifies only on bounds the manifest
        // states outright, and falls back to nothing.
        ManifestRole::Extra => (
            w.source.min_period_minutes.unwrap_or(0),
            w.source.max_period_minutes.unwrap_or(u64::MAX),
        ),
    }
}

/// Pick which raw slot (if either) fills `w`:
///
/// 1. **Classified**: the first of `primary`, `secondary` (always scanned in
///    that order, regardless of `w`'s own role) whose `window_minutes` falls
///    inside `w`'s bounds.
/// 2. **Positional fallback** (only when step 1 finds nothing): a `primary`-
///    role window falls back to the raw `primary` slot unless it declares a
///    length that overshoots the bound; a `secondary`-role window falls back
///    to the raw `secondary` slot only when it declares no length at all —
///    deliberately stricter, and deliberately asymmetric with the `primary`
///    case above.
fn classify_slot(
    w: &WindowConfig,
    threshold: u64,
    primary: &Option<RawSlot>,
    secondary: &Option<RawSlot>,
) -> Option<RawSlot> {
    // A log line's two slots are the subscription's pair. A quota that is not
    // the subscription has to say exactly which length it is, or it takes
    // neither — bounds of "anything" would match the first slot and print the
    // subscription's own numbers under a second name.
    if w.role == ManifestRole::Extra
        && w.source.min_period_minutes.is_none()
        && w.source.max_period_minutes.is_none()
    {
        return None;
    }
    let (min_bound, max_bound) = effective_bounds(w, threshold);
    for s in [primary, secondary].into_iter().flatten() {
        if matches!(s.window_minutes, Some(m) if m >= min_bound && m <= max_bound) {
            return Some(s.clone());
        }
    }
    match w.role {
        ManifestRole::Primary => primary
            .clone()
            .filter(|s| !matches!(s.window_minutes, Some(m) if m > max_bound)),
        ManifestRole::Secondary => secondary.clone().filter(|s| s.window_minutes.is_none()),
        // No positional fallback: the two slots of a log line are the
        // subscription's, and handing one to an extra quota is exactly the
        // confusion this role exists to prevent.
        ManifestRole::Extra => None,
    }
}

/// This window as the reading reports it, or `None` when no slot in the
/// reading is this window — a weekly-only reading yields a weekly window and
/// nothing else, rather than a blank 5H row beside it.
fn build_window(index: usize, w: &WindowConfig, slot: Option<&RawSlot>) -> Option<Window> {
    let slot = slot?;
    Some(Window {
        // Same key for the same declared window whichever engine read it: a
        // provider that migrates from logs to an API keeps its registry entry.
        key: crate::plugin::window_key(w, index),
        label: w.label.clone(),
        role: crate::plugin::map_role(w.role),
        used_percent: Some(slot.used_percent),
        resets_at: resets_at_for(slot, w.source.resets_at_format),
        period_minutes: match w.period.mode {
            PeriodMode::Assumed => w.period.assumed,
            PeriodMode::FromField => slot.window_minutes,
            // Refused at load (`manifest::validate_window_period_mode`): a
            // `RawSlot` carries only an already-classified `window_minutes`,
            // with no raw start/end pair behind it to read a length from, so
            // no manifest that parses ever reaches this arm on this engine.
            // Kept exhaustive rather than a catch-all `_`, so a third mode
            // added later fails this match rather than silently falling
            // through to it.
            PeriodMode::FromBounds => None,
        },
    })
}

/// This slot's `resets_at`, in whichever format the manifest declares —
/// [`crate::plugin::time::resets_at`] does the actual parsing (both the
/// number-or-quoted-number reading and the RFC3339 one) and the one thing
/// this engine and `engine_http` both need after it: a value more than ten
/// years from now is treated as absent (see that function's own doc).
fn resets_at_for(slot: &RawSlot, format: ResetsAtFormat) -> Option<u64> {
    let raw = slot.resets_at_raw.as_ref()?;
    crate::plugin::time::resets_at(raw, format)
}

// ── File discovery ───────────────────────────────────────────────────────

/// One matched file: its path, mtime, and length — the length carried along
/// from [`collect_log_files`]'s own walk rather than asked for again by
/// [`tail_cost`].
type LogFile = (PathBuf, SystemTime, u64);

/// Find the freshest container reading under `root`: walk every file whose
/// basename matches `glob`, newest-first by mtime, and return the last
/// reading in the first file that has one — a file with zero matching
/// readings (a session that just started) falls through to the next. `files`
/// is expected to already be sorted newest-first ([`newest_first`]) — the
/// caller sorts once for both this and [`collect_plan_groups`] rather than
/// each doing its own pass over the same list.
///
/// `account_match` (`Some((field, expected))`) additionally requires the
/// container's `field` to equal `expected` — so a session tree that
/// interleaves several accounts' readings only ever yields the current
/// login's. A file with no *matching* container falls through to the next,
/// exactly as an empty file does.
///
/// Bounded by its own [`FETCH_BYTE_BUDGET`], separate from
/// [`collect_plan_groups`]'s own — see that constant's doc. A file whose read
/// would exceed the remaining budget is never opened; the ones already found
/// stand, and whatever reading a file past the cut might have carried is
/// simply not looked for this fetch. `plugin_id` is for the one diagnostic
/// this can produce, nothing else — the search itself does not change.
fn latest_reading(
    files: &[LogFile],
    plugin_id: &str,
    container_key: &str,
    account_match: Option<&(String, String)>,
    format: LogFileFormat,
    select: LogFileSelect,
) -> Option<RawReading> {
    let mut budget = FETCH_BYTE_BUDGET;
    for (path, _mtime, len) in files {
        let cost = tail_cost(*len);
        if cost > budget {
            queue_diag_once(plugin_id, "primary-byte-budget", || {
                format!(
                    "{plugin_id}: the primary log scan hit its {FETCH_BYTE_BUDGET}-byte-per-fetch \
                     limit before finishing every matched file"
                )
            });
            break;
        }
        budget -= cost;
        if let Some(found) = parse_file(path, container_key, account_match, format, select) {
            return Some(found);
        }
    }
    None
}

/// A recursive walk under `root` has no natural size limit of its own: a
/// manifest's `root`/`root_env`/`glob` is data this app trusts to be honest
/// about the provider's own data directory, not data it trusts to be small,
/// and a mistyped one (or an env var pointed at something far wider) could
/// hand this walk a home directory instead of a session tree. `LOG_WALK_MAX_ENTRIES`
/// caps how many directory entries a single collection visits before it stops
/// and reports whatever it already found; a session tree this engine has ever
/// been measured against (`fetch`'s doc: 3975 files) is nowhere near the cap,
/// so this only ever bites a manifest that got its root wrong.
const LOG_WALK_MAX_ENTRIES: usize = 200_000;

/// All files under `root` whose basename matches `glob` — including a
/// symlink to one, so a provider's log directory laid out through a symlink
/// (a relocated `$HOME`, a bind-mount stand-in) is not silently invisible to
/// this engine — paired with their mtime (full resolution — truncating to
/// whole seconds before the freshness sort is what let two files written a
/// fraction of a second apart tie and fall back to whatever order the
/// filesystem happened to hand them in) and their length, so [`tail_cost`]
/// never has to ask the filesystem for it a second time.
fn collect_log_files(root: &Path, glob: &str) -> Vec<LogFile> {
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .take(LOG_WALK_MAX_ENTRIES)
    {
        let ty = entry.file_type();
        if !ty.is_file() && !ty.is_symlink() {
            continue;
        }
        let name = entry.file_name().to_string_lossy();
        if !glob_matches(glob, &name) {
            continue;
        }
        // A followed `stat`, not `entry.metadata()`'s own: this walk never
        // follows links (`follow_links(false)`, so a symlinked *directory*
        // cannot recurse into a cycle), which makes `entry.metadata()` an
        // `lstat` — a symlink's own mtime and length, not the file
        // `tail_reader` will actually open and read. Following it here, once
        // an entry has already passed the glob, both charges the length
        // `tail_cost` needs correctly and turns away a symlink that resolves
        // to a directory or to nothing (`metadata.is_file()` is false for
        // both) — the two cases `entry.file_type()` alone could not tell
        // apart from a symlink to a real log file.
        let Ok(metadata) = std::fs::metadata(entry.path()) else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        let mtime = metadata.modified().unwrap_or(UNIX_EPOCH);
        let len = metadata.len();
        out.push((entry.into_path(), mtime, len));
    }
    out
}

/// Sort `files` newest-mtime-first, in place — the one comparator every
/// caller that cares about freshness shares, rather than each sorting its own
/// copy: [`fetch`] runs this once per fetch, and [`latest_reading`]/
/// [`collect_plan_groups`] trust the order they are handed instead of
/// re-deriving it. Files without a readable mtime sort last (they carry
/// [`UNIX_EPOCH`], the earliest possible value). Two files stamped the same
/// instant — not impossible on a filesystem some other tool writes to in a
/// batch — break the tie on path rather than on `walkdir`'s visit order,
/// which is an accident of the filesystem, not a decision anyone made.
fn newest_first(files: &mut [LogFile]) {
    files.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
}

/// How many *matched* files ([`collect_log_files`]'s own output, not the
/// directory entries `LOG_WALK_MAX_ENTRIES` bounds) one fetch will actually
/// hand to [`latest_reading`]/[`secondary_accounts`] to open and read.
///
/// A session tree well inside the entry-walk cap can still match far more
/// files than either reader could ever need: both already read newest-first
/// and only care about the freshest handful, so a plugin whose glob has
/// matched a few hundred files for years would otherwise have every one of
/// them opened and tail-read again on every refresh, for a question only the
/// newest ones can ever answer.
const LOG_WALK_MAX_FILES: usize = 200;

/// Keep only the newest [`LOG_WALK_MAX_FILES`] of `files`, logging once per
/// plugin when anything is actually dropped. `files` is expected to already
/// be sorted ([`newest_first`]) — this only truncates, so a caller that
/// skipped that step silently keeps the wrong end of its own list rather than
/// having this quietly re-sort for it.
fn cap_to_newest_files(mut files: Vec<LogFile>, plugin_id: &str) -> Vec<LogFile> {
    if files.len() <= LOG_WALK_MAX_FILES {
        return files;
    }
    let matched = files.len();
    files.truncate(LOG_WALK_MAX_FILES);
    queue_diag_once(plugin_id, "matched-files", || {
        format!(
            "{plugin_id}: {matched} files matched the log glob; only the newest \
             {LOG_WALK_MAX_FILES} were read"
        )
    });
    files
}

/// Total bytes either [`latest_reading`] or [`collect_plan_groups`] will pull
/// out of files in one call, its own budget rather than one shared between
/// the two: a session tree of a couple hundred files near the
/// [`TAIL_BYTES`] window each would otherwise cost hundreds of megabytes of
/// reads on every refresh, the primary lookup and the secondary-accounts
/// lookup each paying it separately today regardless of this cap.
const FETCH_BYTE_BUDGET: u64 = 64 * 1024 * 1024;

/// A file's charge against [`FETCH_BYTE_BUDGET`]: `len`, the length
/// [`collect_log_files`] read off its own `stat` during the walk, capped at
/// [`TAIL_BYTES`]. An estimate charged ahead of the read, not a bound on it —
/// the file can grow or shrink between that walk and whichever read this
/// pass gets to, and [`tail_reader`] answers to its own (freshly read) length
/// and [`TAIL_BYTES`] regardless of what was charged here. Good enough for a
/// *budget*: this only has to stay in the right neighbourhood across a
/// fetch's worth of files, not account for each one exactly.
fn tail_cost(len: u64) -> u64 {
    len.min(TAIL_BYTES)
}

/// Diagnostics only the binary can write — `crate::diag` lives in `main.rs`'s
/// binary crate, not this library one (see `crate::plugin::auth`'s own
/// `PENDING_DIAGNOSTICS` for the identical split, and its own doc for why
/// this crate does not reach into either directly). Queued here, meant to be
/// drained once per fetch pass by `main.rs` via
/// [`take_pending_diagnostics`].
static PENDING_DIAGNOSTICS: crate::plugin::diag_queue::Queue =
    crate::plugin::diag_queue::Queue::new();

/// Every `(plugin id, reason)` pair this process has already logged once —
/// shared by both diagnostics this module queues, so a session tree that
/// keeps tripping the same cap on every refresh gets one line for it, not
/// one per refresh.
static ALREADY_LOGGED: Mutex<Option<std::collections::HashSet<String>>> = Mutex::new(None);

/// Queue `build_message()`'s result under `(plugin_id, reason)`, the first
/// time only — [`crate::plugin::diag_queue::queue_diag_once`], the same
/// `(plugin, reason)` dedup `engine_http`'s own `for_each`-truncation
/// diagnostic now shares.
fn queue_diag_once(plugin_id: &str, reason: &str, build_message: impl FnOnce() -> String) {
    crate::plugin::diag_queue::queue_diag_once(
        &PENDING_DIAGNOSTICS,
        &ALREADY_LOGGED,
        plugin_id,
        reason,
        build_message,
    );
}

/// Every diagnostic line queued since the last call, removing them.
pub fn take_pending_diagnostics() -> Vec<String> {
    PENDING_DIAGNOSTICS.take()
}

/// Whether `name` (a bare file name, no directories) matches `glob`. Only the
/// part of `glob` after its final path separator is meaningful — directories
/// are always walked recursively regardless of a leading `**/`, so
/// `"**/rollout-*.jsonl"` and `"rollout-*.jsonl"` behave identically.
///
/// `\` is a path separator on Windows and an ordinary filename character
/// everywhere else — a manifest's `glob` is one string shared by every
/// platform, so splitting on `\` off Windows would treat a literal backslash
/// in a Unix basename pattern as a directory boundary and quietly discard
/// everything before it. `rsplit` on a non-empty pattern list always yields
/// at least the whole string back, so the `unwrap_or` below never actually
/// falls through — kept because the type still asks for it, not because the
/// `None` arm is reachable.
fn glob_matches(glob: &str, name: &str) -> bool {
    let separators: &[char] = if cfg!(windows) { &['/', '\\'] } else { &['/'] };
    let name_pattern = glob.rsplit(separators).next().unwrap_or(glob);
    match_wildcard(name_pattern, name)
}

/// Minimal `*`-only glob matcher (no external glob dependency, `Cargo.toml`
/// is out of scope for this unit): true if every literal segment between the
/// pattern's `*`s appears in `text` in order, with the first/last segment
/// anchored to the start/end unless the pattern itself starts/ends with `*`.
fn match_wildcard(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let mut text = text;
    if let Some(first) = parts.first() {
        if !first.is_empty() {
            match text.strip_prefix(*first) {
                Some(rest) => text = rest,
                None => return false,
            }
        }
    }
    let last = parts[parts.len() - 1];
    if !last.is_empty() {
        match text.strip_suffix(last) {
            Some(rest) => text = rest,
            None => return false,
        }
    }
    let mut pos = 0usize;
    for part in &parts[1..parts.len() - 1] {
        if part.is_empty() {
            continue;
        }
        match text[pos..].find(part) {
            Some(idx) => pos += idx + part.len(),
            None => return false,
        }
    }
    true
}

/// Parse one log file, returning a container reading in it that satisfies
/// `account_match` (every reading, when `account_match` is `None`) —
/// `select` decides which one when more than one qualifies.
fn parse_file(
    path: &Path,
    container_key: &str,
    account_match: Option<&(String, String)>,
    format: LogFileFormat,
    select: LogFileSelect,
) -> Option<RawReading> {
    let file = File::open(path).ok()?;
    let mut reader = tail_reader(file).ok()?;
    // Cheap pre-filter: skip lines that can't possibly contain the container.
    let needle = format!("\"{container_key}\"");
    let mut latest: Option<RawReading> = None;
    let mut buf = Vec::new();
    loop {
        match read_line_capped(&mut reader, &mut buf) {
            Ok(CappedLine::Eof) | Err(_) => break,
            Ok(CappedLine::TooLong) => continue,
            Ok(CappedLine::Read) => {}
        }
        let Ok(line) = std::str::from_utf8(&buf) else {
            continue;
        };
        if !line.contains(&needle) {
            continue;
        }
        let value = match format {
            // The one shape this engine's parser understands: one JSON
            // object per line. A manifest naming any other `[logfile]
            // format` is refused before this function is ever reached (see
            // `LogFileFormat`'s own doc).
            LogFileFormat::Jsonl => match serde_json::from_str::<Value>(line) {
                Ok(v) => v,
                Err(_) => continue,
            },
        };
        if let Some(container) = find_container(&value, container_key) {
            if !container_matches(container, account_match) {
                continue;
            }
            if let Some(raw) = parse_container(container) {
                match select {
                    // The one policy this engine's scan implements: each
                    // qualifying line replaces the one kept before it, so the
                    // scan's own forward order over the file decides — see
                    // `LogFileSelect`'s own doc.
                    LogFileSelect::Last => latest = Some(raw),
                }
            }
        }
    }
    latest
}

/// Whether `container` passes the `account_match` guard: its `field` (a dotted
/// JSON path, like `[tag] path`) equals `expected`. Always true when there is
/// no guard.
fn container_matches(container: &Value, account_match: Option<&(String, String)>) -> bool {
    match account_match {
        None => true,
        Some((field, expected)) => {
            json_path(container, field).and_then(Value::as_str) == Some(expected.as_str())
        }
    }
}

/// Depth-first search for the container inside an arbitrary JSON value.
/// Prefers a value stored under the literal `container_key`, but also
/// recognises an inlined object that simply carries `primary`/`secondary` —
/// this shape check is hardcoded (see module docs), not manifest-configurable.
fn find_container<'a>(value: &'a Value, container_key: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => {
            if let Some(c) = map.get(container_key) {
                // Same rule as the shape fallback below: a container that
                // carries no usable slot is not the reading, even when it is
                // sitting under the very key this engine looks for. A line
                // whose outer level has an empty `rate_limits` and the real
                // one nested deeper must resolve to the real one.
                if looks_like_container(c) && parse_container(c).is_some() {
                    return Some(c);
                }
            }
            // The shape fallback must not swallow the line. An object with an
            // object-valued `primary` of its own — a connection record, a
            // payload envelope — looks exactly like a container from here, and
            // accepting it means the real one nested below is never reached
            // and the whole line reads as "no usage". So the root only counts
            // when it carries a slot that actually parses.
            if looks_like_container(value) && parse_container(value).is_some() {
                return Some(value);
            }
            for child in map.values() {
                if let Some(found) = find_container(child, container_key) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(items) => items.iter().find_map(|v| find_container(v, container_key)),
        _ => None,
    }
}

/// Heuristic: does this value look like a container payload?
fn looks_like_container(value: &Value) -> bool {
    let Some(map) = value.as_object() else {
        return false;
    };
    let has_window = |k: &str| map.get(k).map(Value::is_object).unwrap_or(false);
    has_window("primary") || has_window("secondary")
}

fn parse_container(value: &Value) -> Option<RawReading> {
    let map = value.as_object()?;
    let primary = map.get("primary").and_then(parse_raw_slot);
    let secondary = map.get("secondary").and_then(parse_raw_slot);
    if primary.is_none() && secondary.is_none() {
        return None;
    }
    Some(RawReading {
        primary,
        secondary,
        container: value.clone(),
    })
}

fn parse_raw_slot(value: &Value) -> Option<RawSlot> {
    let map = value.as_object()?;
    // `used_percent` is required for a slot to be meaningful; tolerate a few
    // spellings in case a future release renames the field.
    let used_percent = first_f64(map, &["used_percent", "usedPercent", "percent_used"])?;
    let resets_at_raw = ["resets_at", "resetsAt", "reset_at"]
        .iter()
        .find_map(|k| map.get(*k))
        .cloned();
    // A saturating `as u64` on an absurd float, or a field a provider fills
    // in a different unit than declared, is a length nothing here should
    // classify a window against — the same ten-year rule
    // `crate::plugin::time::resets_at` applies to a point in time, restated
    // for a duration.
    let window_minutes = first_u64(map, &["window_minutes", "windowMinutes"])
        .filter(|&m| crate::plugin::time::plausible_period_minutes(m));
    Some(RawSlot {
        used_percent: used_percent.clamp(0.0, 100.0),
        resets_at_raw,
        window_minutes,
    })
}

/// First key that yields a float (accepts ints too).
fn first_f64(map: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<f64> {
    keys.iter()
        .find_map(|k| map.get(*k).and_then(Value::as_f64))
}

/// First key that yields a non-negative integer — `window_minutes`, the one
/// caller, is a whole number of minutes, but tolerates a provider that
/// serialises it as a JSON float (`300.0`) rather than an int.
fn first_u64(map: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|k| {
        map.get(*k).and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64))
        })
    })
}

// ── Tag / account (manifest-driven, not engine-hardcoded) ───────────────

/// Resolve a dotted JSON path (`"a.b.c"`) against an arbitrary value —
/// forwards to `crate::plugin::json_path_get`, the same walker
/// `crate::plugin::auth::json_path_value` also forwards to, so a
/// `container_key`/`tag.path` written with an array selector (`[0]`,
/// `[field=value]`) resolves here too rather than silently missing.
fn json_path<'v>(root: &'v Value, path: &str) -> Option<&'v Value> {
    crate::plugin::json_path_get(root, path)
}

/// `[tag]` resolution. `from = "field"` reads `tag.path` out of the
/// container that produced this reading (e.g. Codex's `plan_type`, which
/// lives alongside `primary`/`secondary` in the same object) — this engine
/// has no surfaces of its own, so it calls straight through to
/// [`crate::plugin::resolve_tag_from`], unlike `engine_http::resolve_tag`,
/// which layers an explicit `[[surface]]` label on top of the same call.
fn resolve_tag(m: &PluginManifest, container: Option<&Value>) -> Option<String> {
    crate::plugin::resolve_tag_from(&m.tag, container)
}

/// `[account]` resolution. Only `type = "jwt-file"` is wired here: read
/// `path` as JSON, pull the JWT string at `token_path`, base64url-decode its
/// unsigned payload, and read `claim` out of the decoded claims. `type =
/// "http"` shares the provider's own `[http]`/surface auth chain, which this
/// engine has no use for, so it (and `"none"`) resolve to no account.
fn resolve_account(m: &PluginManifest) -> Option<String> {
    let claim = m.account.claim.as_deref()?;
    let claims = jwt_claims(m)?;
    let raw = json_path(&claims, claim)?.as_str()?;
    // The claim's *name* is the manifest's; the value decoded out of it is
    // the token's own payload — sanitised like any other provider-supplied
    // text before it reaches the panel, and rejected outright if that leaves
    // nothing.
    let account = crate::plugin::sanitize_provider_text(raw);
    (!account.is_empty()).then_some(account)
}

/// Decode the `[account]` jwt-file's claims to a JSON value — the shared step
/// behind [`resolve_account`] (the email) and [`resolve_account_match`] (the
/// shared-tree guard value). `None` unless the account is a readable jwt-file:
/// `type = "http"`/`"none"` share the provider's own auth chain, which this
/// engine has no use for.
fn jwt_claims(m: &PluginManifest) -> Option<Value> {
    if m.account.kind != AccountType::JwtFile {
        return None;
    }
    let path = m.account.path.as_deref()?;
    let token_path = m.account.token_path.as_deref()?;
    let text = crate::plugin::read_regular_file(
        &crate::plugin::expand_home(path),
        crate::plugin::SMALL_FILE_MAX_BYTES,
    )?;
    let value: Value = serde_json::from_str(&text).ok()?;
    let jwt = json_path(&value, token_path)?.as_str()?;
    let payload = jwt.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The `[logfile] account_match` guard resolved to a concrete
/// `(container_field, expected_value)` pair: only a container whose
/// `container_field` equals `expected_value` may produce this reading. `None`
/// — meaning *no* filtering — when there's no `account_match`, the `[account]`
/// isn't a readable jwt-file, or the `auth_claim` path doesn't resolve to a
/// string. A shared-session-tree guard must never *hide* data it cannot
/// positively disqualify: if we can't read the current login's identity, we
/// fall back to the pre-existing "newest reading wins" behaviour rather than
/// blanking the panel.
fn resolve_account_match(m: &PluginManifest, lf: &LogFileConfig) -> Option<(String, String)> {
    let am: &AccountMatchConfig = lf.account_match.as_ref()?;
    let claims = jwt_claims(m)?;
    let mut cur = &claims;
    for seg in &am.auth_claim {
        cur = cur.get(seg)?;
    }
    let expected = cur.as_str()?.to_string();
    Some((am.container_field.clone(), expected))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::plugin::manifest::{PeriodConfig, PeriodUnit, SourceConfig};

    /// Guards every test below that calls `std::env::set_var`/`remove_var`:
    /// real process environment is process-wide state `cargo test`'s default
    /// parallelism does not otherwise serialize, and each test's own
    /// uniquely-named variable stops it from *reading* another test's value
    /// but not from *racing* the underlying set/remove calls themselves —
    /// the same discipline as `engine_http`'s own, distinct `ENV_TEST_LOCK`.
    /// `.unwrap_or_else(|e| e.into_inner())`, not `.unwrap()`: one test
    /// panicking while holding this lock must not poison it for every test
    /// queued behind it.
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The invariant is stated as a property of **every path that builds a
    /// reading**, not of `ProviderReading::fail`: a test that calls `fail` and
    /// checks it emptied three fields proves the method works and says nothing
    /// about a path that sets `error` by hand. This engine had exactly such a
    /// path — the `[logfile]`-less branch, which assembled the literal itself —
    /// so the branch is exercised here rather than trusted.
    #[test]
    fn the_logfile_less_path_claims_nothing_about_the_provider() {
        let m = PluginManifest {
            logfile: None,
            ..codex_like_manifest("null", "null", "null")
        };
        let readings = fetch(&m, &[], &BTreeMap::new());

        assert_eq!(readings.len(), 1);
        let r = &readings[0];
        assert!(
            r.error.is_some(),
            "a manifest this engine cannot run is an error"
        );
        assert!(r.windows.is_empty());
        assert_eq!(r.quota_status, None);
        assert!(
            r.balances.is_empty(),
            "an errored reading must not carry balances"
        );
    }

    // ── fixtures / helpers ─────────────────────────────────────────────

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tickover-logfile-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn write_file(dir: &Path, name: &str, lines: &[String]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, lines.join("\n")).expect("write fixture file");
        path
    }

    /// The same file-discovery + `account_match` resolution [`fetch`] does
    /// once per fetch, so a `fetch_from_root`/`secondary_accounts` test below
    /// exercises the exact preparation those two run behind, without
    /// repeating it at every call site.
    fn discover(
        dir: &Path,
        glob: &str,
        m: &PluginManifest,
        lf: &LogFileConfig,
    ) -> (Vec<LogFile>, Option<(String, String)>) {
        let mut files = collect_log_files(dir, glob);
        newest_first(&mut files);
        (files, resolve_account_match(m, lf))
    }

    fn set_mtime(path: &Path, when: std::time::SystemTime) {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("open for mtime");
        file.set_modified(when).expect("set mtime");
    }

    fn no_options() -> BTreeMap<String, bool> {
        BTreeMap::new()
    }

    fn make_jwt(claims_json: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims_json);
        format!("{header}.{payload}.sig")
    }

    /// One string as TOML writes it, quotes included. The manifests below
    /// interpolate real temporary paths, and a Windows one is
    /// `C:\Users\RUNNER~1\AppData\Local\Temp\…` — where TOML reads a
    /// backslash as the start of an escape sequence, so `\U` opens an
    /// eight-digit unicode escape and `\a` is no escape at all. Either way
    /// the manifest does not parse and every test built on it fails for a
    /// reason unrelated to what it tests.
    ///
    /// The escaping is the TOML crate's own rather than a pair of
    /// `replace` calls: quoting a string is exactly the job it already does,
    /// and a hand-rolled version covers the backslash it was written for and
    /// not the next character that needs it.
    fn toml_value(value: &str) -> String {
        toml::Value::from(value).to_string()
    }

    /// A Codex-like manifest: `engine = "log-file"`, one primary window
    /// classified `from_field`, one secondary window classified `assumed`,
    /// `jwt-file` account, uppercase `plan_type` tag — mirrors the
    /// `CODEX_LIKE` fixture in `manifest.rs`. `root`/`root_env` only matter
    /// for the handful of tests that exercise `fetch`/`resolve_root`
    /// directly; everything else calls `fetch_from_root` with an injected
    /// root and ignores them.
    fn codex_like_manifest(root_env: &str, root: &str, account_path: &str) -> PluginManifest {
        let (root_env, root, account_path) = (
            toml_value(root_env),
            toml_value(root),
            toml_value(account_path),
        );
        let toml = format!(
            r#"
            id           = "codex"
            name         = "Codex"
            menu_label   = "Cx"
            order        = 10
            engine       = "log-file"

            [tag]
            from = "field"
            path = "plan_type"
            transform = "uppercase"

            [account]
            type       = "jwt-file"
            path       = {account_path}
            token_path = "tokens.id_token"
            claim      = "email"

            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode  = "from_field"
            field = "window_minutes"
            [windows.source]
            used_percent_path = "used_percent"
            resets_at_path    = "resets_at"

            [[windows]]
            label = "WK"
            role  = "secondary"
            [windows.period]
            mode  = "assumed"
            assumed = 10080
            [windows.source]
            used_percent_path = "used_percent"
            resets_at_path    = "resets_at"

            [logfile]
            root_env      = {root_env}
            root          = {root}
            glob          = "rollout-*.jsonl"
            container_key = "rate_limits"
            "#
        );
        PluginManifest::from_str(&toml).expect("valid test manifest")
    }

    fn win(label: &str, role: ManifestRole) -> WindowConfig {
        WindowConfig {
            id: String::new(),
            required: false,
            label: label.to_string(),
            role,
            period: PeriodConfig {
                mode: PeriodMode::Assumed,
                field: None,
                assumed: Some(0),
                unit: PeriodUnit::Minutes,
                start_path: None,
                end_path: None,
            },
            source: SourceConfig {
                containers: Vec::new(),
                used_percent_path: Some("used_percent".to_string()),
                remaining_fraction_path: None,
                resets_at_path: "resets_at".to_string(),
                resets_at_format: ResetsAtFormat::Unix,
                max_period_minutes: None,
                min_period_minutes: None,
            },
            for_each: None,
            for_each_where: None,
            element_id_path: None,
        }
    }

    fn win_with_bounds(
        label: &str,
        role: ManifestRole,
        min: Option<u64>,
        max: Option<u64>,
    ) -> WindowConfig {
        let mut w = win(label, role);
        w.source.min_period_minutes = min;
        w.source.max_period_minutes = max;
        w
    }

    fn slot(used: f64, minutes: Option<u64>) -> RawSlot {
        RawSlot {
            used_percent: used,
            resets_at_raw: Some(json!(1_800_000_000)),
            window_minutes: minutes,
        }
    }

    // ── classification ───────────────────────────────────────────────────

    #[test]
    fn only_the_tail_of_a_large_file_is_read() {
        // A file bigger than the window: the reading buried near its start is
        // never even *seen* — not merely outrun by a newer one, which the
        // ordinary newest-line-wins rule would do on its own, `tail_reader`
        // or not, since a later line in the file always wins over an earlier
        // one. Proving the read is bounded needs the buried reading to be the
        // *only* one — no later line to have won regardless.
        let dir = temp_dir("tail");
        let path = dir.join("rollout-big.jsonl");
        let buried = r#"{"rate_limits":{"primary":{"used_percent":1.0,"window_minutes":300,"resets_at":100}}}"#;
        let filler = format!("{{\"noise\":\"{}\"}}\n", "x".repeat(64 * 1024));
        let mut text = String::with_capacity(TAIL_BYTES as usize + 1024 * 1024);
        text.push_str(buried);
        text.push('\n');
        while text.len() < TAIL_BYTES as usize + 512 * 1024 {
            text.push_str(&filler);
        }
        std::fs::write(&path, &text).unwrap();

        assert!(
            parse_file(
                &path,
                "rate_limits",
                None,
                LogFileFormat::Jsonl,
                LogFileSelect::Last
            )
            .is_none(),
            "the only reading in the file sits before the tail window and must never be read"
        );

        // The same file, with a second reading appended inside the window:
        // now it is found, proving the window itself is not simply empty.
        let new = r#"{"rate_limits":{"primary":{"used_percent":42.0,"window_minutes":300,"resets_at":200}}}"#;
        text.push_str(new);
        text.push('\n');
        std::fs::write(&path, &text).unwrap();

        let reading = parse_file(
            &path,
            "rate_limits",
            None,
            LogFileFormat::Jsonl,
            LogFileSelect::Last,
        )
        .expect("the tail's reading is found");
        assert_eq!(reading.primary.as_ref().map(|s| s.used_percent), Some(42.0));
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── per-fetch caps: matched files, bytes scanned ─────────────────────

    #[test]
    fn cap_to_newest_files_keeps_the_newest_and_reports_the_drop_once() {
        let base = std::time::SystemTime::now();
        // Already newest-first by construction (index 0 is `base` itself,
        // increasing index moves further into the past) — `cap_to_newest_files`
        // trusts that rather than sorting it again, matching what `fetch`
        // itself hands it after its own `newest_first` call.
        let mut files: Vec<LogFile> = (0..(LOG_WALK_MAX_FILES + 10))
            .map(|i| {
                (
                    PathBuf::from(format!("rollout-{i}.jsonl")),
                    base - std::time::Duration::from_secs(i as u64),
                    0,
                )
            })
            .collect();
        newest_first(&mut files);
        // Index 0 is the newest (smallest offset from `base`); the newest
        // `LOG_WALK_MAX_FILES` of them are indices 0..LOG_WALK_MAX_FILES.
        let capped = cap_to_newest_files(files, "cap-test-plugin");
        assert_eq!(capped.len(), LOG_WALK_MAX_FILES);
        let index_of = |p: &Path| -> usize {
            p.to_string_lossy()
                .trim_start_matches("rollout-")
                .trim_end_matches(".jsonl")
                .parse()
                .expect("test fixture names are always `rollout-{i}.jsonl`")
        };
        assert!(
            capped
                .iter()
                .all(|(p, ..)| index_of(p) < LOG_WALK_MAX_FILES),
            "only the newest files (the lowest indices) survive the cap"
        );

        let diag = take_pending_diagnostics();
        assert!(
            diag.iter().any(|l| l.contains("cap-test-plugin")),
            "the truncation is reported once: {diag:?}"
        );
    }

    #[test]
    fn cap_to_newest_files_is_a_no_op_under_the_cap() {
        let files = vec![(PathBuf::from("a"), std::time::SystemTime::now(), 0u64)];
        let capped = cap_to_newest_files(files.clone(), "under-cap-plugin");
        assert_eq!(capped, files);
        assert!(take_pending_diagnostics().is_empty());
    }

    #[test]
    fn latest_reading_stops_once_its_byte_budget_is_spent() {
        // Filler files sized just over `TAIL_BYTES`, so each costs exactly
        // `TAIL_BYTES` against the budget regardless of the (sparse, near-
        // free to create) size actually claimed on disk. Enough of them to
        // exhaust `FETCH_BYTE_BUDGET` exactly.
        let dir = temp_dir("byte-budget");
        let filler_size = TAIL_BYTES + 1024;
        let filler_count = (FETCH_BYTE_BUDGET / TAIL_BYTES) as usize;
        let base = std::time::SystemTime::now();
        for i in 0..filler_count {
            let path = dir.join(format!("rollout-filler-{i}.jsonl"));
            let file = std::fs::File::create(&path).unwrap();
            file.set_len(filler_size).unwrap();
            // Newest first, so the walk spends the whole budget on these
            // before it would ever reach the real one below.
            set_mtime(&path, base - std::time::Duration::from_secs(i as u64));
        }
        let real = write_file(
            &dir,
            "rollout-real.jsonl",
            &[json!({ "rate_limits": { "primary": { "used_percent": 77.0 } } }).to_string()],
        );
        set_mtime(
            &real,
            base - std::time::Duration::from_secs(filler_count as u64 + 10),
        );

        let mut files = collect_log_files(&dir, "rollout-*.jsonl");
        newest_first(&mut files);
        assert!(
            latest_reading(
                &files,
                "byte-budget-plugin",
                "rate_limits",
                None,
                LogFileFormat::Jsonl,
                LogFileSelect::Last,
            )
            .is_none(),
            "the real reading sits past the byte budget and must never be opened"
        );

        let diag = take_pending_diagnostics();
        assert!(
            diag.iter().any(|l| l.contains("byte-budget-plugin")),
            "the cutoff is reported once: {diag:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_absurdly_long_line_is_skipped_without_reading_it_into_memory() {
        // A truncated or binary file can hold no newline at all, in which
        // case "read a line" used to mean "read the whole file" — on the
        // thread the panel is waiting for.
        let dir = temp_dir("long-line");
        let path = dir.join("rollout-huge.jsonl");
        let mut text = String::with_capacity(MAX_LINE_BYTES as usize + 4096);
        text.push_str(&format!(
            "{{\"junk\":\"{}\"}}\n",
            "x".repeat(MAX_LINE_BYTES as usize + 16)
        ));
        text.push_str(
            r#"{"rate_limits":{"primary":{"used_percent":11.0,"window_minutes":300,"resets_at":1783216497}}}"#,
        );
        text.push('\n');
        std::fs::write(&path, &text).unwrap();

        let reading = parse_file(
            &path,
            "rate_limits",
            None,
            LogFileFormat::Jsonl,
            LogFileSelect::Last,
        )
        .expect("the line after the huge one is read");
        assert_eq!(reading.primary.as_ref().map(|s| s.used_percent), Some(11.0));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn window_slots_are_classified_by_length_not_position() {
        let five_h = win("5H", ManifestRole::Primary);
        let weekly = win("WK", ManifestRole::Secondary);
        let threshold = 720;

        // Normal reading: primary = 5h, secondary = weekly.
        let primary = Some(slot(11.0, Some(300)));
        let secondary = Some(slot(72.0, Some(10080)));
        assert_eq!(
            classify_slot(&five_h, threshold, &primary, &secondary)
                .unwrap()
                .used_percent,
            11.0
        );
        assert_eq!(
            classify_slot(&weekly, threshold, &primary, &secondary)
                .unwrap()
                .used_percent,
            72.0
        );

        // Live-seen degenerate reading: weekly alone in `primary`.
        let primary = Some(slot(3.0, Some(10080)));
        let secondary = None;
        assert!(
            classify_slot(&five_h, threshold, &primary, &secondary).is_none(),
            "weekly data must not pose as the 5h limit"
        );
        assert_eq!(
            classify_slot(&weekly, threshold, &primary, &secondary)
                .unwrap()
                .used_percent,
            3.0
        );

        // Swapped order entirely.
        let primary = Some(slot(72.0, Some(10080)));
        let secondary = Some(slot(11.0, Some(300)));
        assert_eq!(
            classify_slot(&five_h, threshold, &primary, &secondary)
                .unwrap()
                .used_percent,
            11.0
        );
        assert_eq!(
            classify_slot(&weekly, threshold, &primary, &secondary)
                .unwrap()
                .used_percent,
            72.0
        );

        // No lengths declared → positional fallback.
        let primary = Some(slot(11.0, None));
        let secondary = Some(slot(72.0, None));
        assert_eq!(
            classify_slot(&five_h, threshold, &primary, &secondary)
                .unwrap()
                .used_percent,
            11.0
        );
        assert_eq!(
            classify_slot(&weekly, threshold, &primary, &secondary)
                .unwrap()
                .used_percent,
            72.0
        );
    }

    #[test]
    fn classify_threshold_minutes_from_manifest_drives_the_boundary() {
        let short = win("SHORT", ManifestRole::Primary);
        let long = win("LONG", ManifestRole::Secondary);
        let threshold = 60; // custom — not the codex default of 720

        let primary = Some(slot(1.0, Some(90))); // > 60 → long-class, not short
        let secondary = None;
        assert!(classify_slot(&short, threshold, &primary, &secondary).is_none());
        assert_eq!(
            classify_slot(&long, threshold, &primary, &secondary)
                .unwrap()
                .used_percent,
            1.0
        );
    }

    #[test]
    fn explicit_min_max_period_minutes_override_the_default_threshold() {
        let tight_primary = win_with_bounds("5H", ManifestRole::Primary, None, Some(100));
        let threshold = 720; // irrelevant once source.max_period_minutes is set

        let primary = Some(slot(1.0, Some(300))); // within the default 720 but not the tighter 100
        let secondary = None;
        assert!(
            classify_slot(&tight_primary, threshold, &primary, &secondary).is_none(),
            "a declared length outside the configured bound must not fall back positionally either"
        );
    }

    // ── container discovery ─────────────────────────────────────────────

    #[test]
    fn finds_nested_rate_limits() {
        let line = json!({
            "timestamp": "2026-07-04T21:08:04.268Z",
            "type": "event_msg",
            "payload": {
                "type": "token_count",
                "info": { "model_context_window": 258400 },
                "rate_limits": {
                    "limit_id": "codex",
                    "primary":   { "used_percent": 11.0, "window_minutes": 300,   "resets_at": 1783216497 },
                    "secondary": { "used_percent": 72.0, "window_minutes": 10080, "resets_at": 1783614509 },
                    "plan_type": "prolite"
                }
            }
        });
        let container = find_container(&line, "rate_limits").expect("should locate rate_limits");
        let raw = parse_container(container).expect("should parse");
        let p = raw.primary.unwrap();
        let s = raw.secondary.unwrap();
        assert_eq!(p.used_percent, 11.0);
        assert_eq!(resets_at_for(&p, ResetsAtFormat::Unix), Some(1783216497));
        assert_eq!(p.window_minutes, Some(300));
        assert_eq!(s.used_percent, 72.0);
        assert_eq!(resets_at_for(&s, ResetsAtFormat::Unix), Some(1783614509));
        assert_eq!(
            json_path(&raw.container, "plan_type").and_then(Value::as_str),
            Some("prolite")
        );
    }

    #[test]
    fn inlined_rate_limits_object_is_recognised() {
        let inline = json!({
            "primary":   { "used_percent": 5.0, "resets_at": 111 },
            "secondary": { "used_percent": 6.0, "resets_at": 222 }
        });
        let found = find_container(&inline, "rate_limits").expect("inline object recognised");
        let raw = parse_container(found).unwrap();
        assert_eq!(raw.primary.unwrap().used_percent, 5.0);
    }

    #[test]
    fn malformed_json_is_ignored() {
        let dir = temp_dir("malformed");
        let path = write_file(
            &dir,
            "rollout-a.jsonl",
            &[
                "garbage \"rate_limits\" trailing".to_string(),
                "{ this is not json".to_string(),
                json!({ "rate_limits": { "primary": { "used_percent": 40.0 } } }).to_string(),
            ],
        );
        let raw = parse_file(
            &path,
            "rate_limits",
            None,
            LogFileFormat::Jsonl,
            LogFileSelect::Last,
        )
        .expect("must skip the broken lines and parse the good one");
        assert_eq!(raw.primary.unwrap().used_percent, 40.0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tolerates_missing_resets_at() {
        let s = parse_raw_slot(&json!({ "used_percent": 40.0 })).unwrap();
        assert_eq!(s.used_percent, 40.0);
        assert_eq!(s.resets_at_raw, None);
        assert_eq!(resets_at_for(&s, ResetsAtFormat::Unix), None);
    }

    /// The window contract is 0..100 whichever engine produced it — a
    /// negative figure clamps to 0 the same way `engine_http::build_window`
    /// clamps a remaining-fraction complement out of range.
    #[test]
    fn a_negative_used_percent_clamps_to_zero() {
        let s = parse_raw_slot(&json!({ "used_percent": -4.0 })).unwrap();
        assert_eq!(s.used_percent, 0.0);
    }

    /// The same saturating-cast defence `crate::plugin::time::resets_at`
    /// applies to a point in time, restated for a duration: a `window_minutes`
    /// far beyond any real quota window is treated as absent rather than fed
    /// to classification.
    #[test]
    fn an_implausible_window_minutes_is_treated_as_absent() {
        let ordinary =
            parse_raw_slot(&json!({ "used_percent": 1.0, "window_minutes": 10_080 })).unwrap();
        assert_eq!(ordinary.window_minutes, Some(10_080));

        let absurd =
            parse_raw_slot(&json!({ "used_percent": 1.0, "window_minutes": 999_999_999_999u64 }))
                .unwrap();
        assert_eq!(absurd.window_minutes, None);
    }

    #[test]
    fn a_quoted_unix_timestamp_resolves_the_same_as_a_bare_one() {
        let s = RawSlot {
            used_percent: 1.0,
            resets_at_raw: Some(json!("1787207494")),
            window_minutes: None,
        };
        assert_eq!(
            resets_at_for(&s, ResetsAtFormat::Unix),
            Some(1_787_207_494),
            "a provider that quotes its numbers must not lose the reset time"
        );
    }

    /// `resets_at_for` delegates to `crate::plugin::time::resets_at`, so a
    /// ms-vs-s confusion (or any value more than ten years out) is treated as
    /// absent here exactly as it is in `engine_http` — one rule, one place.
    #[test]
    fn an_implausible_resets_at_is_treated_as_absent() {
        let s = RawSlot {
            used_percent: 1.0,
            resets_at_raw: Some(json!(9_999_999_999_999u64)),
            window_minutes: None,
        };
        assert_eq!(resets_at_for(&s, ResetsAtFormat::Unix), None);
    }

    #[test]
    fn tolerates_alternate_field_spellings() {
        let s =
            parse_raw_slot(&json!({ "usedPercent": 33.0, "resetsAt": 555, "windowMinutes": 300 }))
                .unwrap();
        assert_eq!(s.used_percent, 33.0);
        assert_eq!(resets_at_for(&s, ResetsAtFormat::Unix), Some(555));
        assert_eq!(s.window_minutes, Some(300));
    }

    #[test]
    fn resets_at_format_iso8601_is_parsed() {
        let s = RawSlot {
            used_percent: 1.0,
            resets_at_raw: Some(json!("2026-01-01T00:00:00Z")),
            window_minutes: None,
        };
        assert_eq!(
            resets_at_for(&s, ResetsAtFormat::Iso8601),
            Some(1_767_225_600)
        );
    }

    #[test]
    fn glob_matches_rollout_pattern_by_basename() {
        assert!(glob_matches(
            "**/rollout-*.jsonl",
            "rollout-2026-01-01-abc.jsonl"
        ));
        assert!(glob_matches("rollout-*.jsonl", "rollout-x.jsonl"));
        assert!(!glob_matches("rollout-*.jsonl", "notes.txt"));
        assert!(!glob_matches("rollout-*.jsonl", "rollout-x.log"));
    }

    #[test]
    #[cfg(not(windows))]
    fn a_literal_backslash_is_part_of_the_basename_off_windows() {
        // `\` is an ordinary filename character on every platform but
        // Windows — treating it as a path separator here would drop
        // everything before it and turn a pattern that should match exactly
        // into one that matches something looser (or nothing at all).
        assert!(glob_matches("weird\\name-*.jsonl", "weird\\name-1.jsonl"));
        assert!(!glob_matches("weird\\name-*.jsonl", "name-1.jsonl"));
    }

    // ── cross-file fallback ──────────────────────────────────────────────

    #[test]
    fn falls_back_to_an_older_file_when_the_newest_has_no_reading() {
        let dir = temp_dir("fallback");
        let has_no_data = write_file(
            &dir,
            "rollout-fresh.jsonl",
            &["{\"type\":\"other\"}".to_string()],
        );
        let has_data = write_file(
            &dir,
            "rollout-stale.jsonl",
            &[json!({ "rate_limits": { "primary": { "used_percent": 11.0 } } }).to_string()],
        );
        // mtime, not filename, decides freshness: the file *without* data is
        // touched last so a naive filename-order walk would pick it first.
        let base = std::time::SystemTime::now();
        set_mtime(&has_data, base - std::time::Duration::from_secs(120));
        set_mtime(&has_no_data, base);

        let mut files = collect_log_files(&dir, "rollout-*.jsonl");
        newest_first(&mut files);
        let raw = latest_reading(
            &files,
            "test-plugin",
            "rate_limits",
            None,
            LogFileFormat::Jsonl,
            LogFileSelect::Last,
        )
        .expect("must fall back to the file that actually has a reading");
        assert_eq!(raw.primary.unwrap().used_percent, 11.0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn two_files_stamped_the_same_instant_break_the_tie_on_path() {
        // Two files an mtime truncated to whole seconds would have called
        // simultaneous even before this fix — same `SystemTime`, no filename
        // order to fall back on other than the one the sort itself imposes.
        let dir = temp_dir("mtime-tie");
        let a = write_file(
            &dir,
            "rollout-a.jsonl",
            &[json!({ "rate_limits": { "primary": { "used_percent": 5.0 } } }).to_string()],
        );
        let b = write_file(
            &dir,
            "rollout-b.jsonl",
            &[json!({ "rate_limits": { "primary": { "used_percent": 99.0 } } }).to_string()],
        );
        let same_instant = std::time::SystemTime::now();
        set_mtime(&a, same_instant);
        set_mtime(&b, same_instant);

        let mut files = collect_log_files(&dir, "rollout-*.jsonl");
        newest_first(&mut files);
        let raw = latest_reading(
            &files,
            "test-plugin",
            "rate_limits",
            None,
            LogFileFormat::Jsonl,
            LogFileSelect::Last,
        )
        .expect("either file resolves a reading");
        assert_eq!(
            raw.primary.unwrap().used_percent,
            5.0,
            "an exact mtime tie must resolve deterministically by path, not by \
             whatever order the filesystem happened to hand the walk"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `entry.metadata()` under `follow_links(false)` is an `lstat` — the
    /// symlink's own length, the byte length of the target path string it
    /// stores, not the file this engine will actually open and tail-read.
    /// `collect_log_files` must follow the link for its `stat`, matching
    /// `tail_reader`'s own open, so a session tree reached through a symlink
    /// is charged (and freshness-sorted, and byte-budgeted) by what is
    /// actually inside it.
    #[test]
    #[cfg(unix)]
    fn a_symlinked_log_is_charged_the_targets_length_not_the_links() {
        let dir = temp_dir("symlink-length");
        let real = write_file(
            &dir,
            "rollout-real.jsonl",
            &[json!({ "rate_limits": { "primary": { "used_percent": 33.0 } } }).to_string()],
        );
        let real_len = std::fs::metadata(&real).unwrap().len();

        let link = dir.join("rollout-link.jsonl");
        std::os::unix::fs::symlink(&real, &link).expect("create symlink fixture");
        // The link's own (lstat) length is the byte length of the target
        // path string it stores, not the file it points at — different from
        // `real_len` on any real fixture path, which is what makes this
        // prove the followed stat is actually in use rather than
        // coincidentally agreeing with it.
        let link_lstat_len = std::fs::symlink_metadata(&link).unwrap().len();
        assert_ne!(
            link_lstat_len, real_len,
            "the fixture only proves anything if the link's own length differs from the target's"
        );

        let files = collect_log_files(&dir, "rollout-*.jsonl");
        let (_, _, charged_len) = files
            .iter()
            .find(|(p, ..)| p == &link)
            .expect("the symlink is discovered, not silently skipped");
        assert_eq!(
            *charged_len, real_len,
            "the symlink must be charged the target file's length, not the link's own"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── tag / account ────────────────────────────────────────────────────

    #[test]
    fn tag_from_field_uppercases_plan_type() {
        let m = codex_like_manifest(
            "TICKOVER_TEST_LOGFILE_NEVER_SET_1",
            "/nonexistent",
            "/nonexistent",
        );
        let container = json!({ "primary": { "used_percent": 1.0 }, "plan_type": "prolite" });
        assert_eq!(
            resolve_tag(&m, Some(&container)).as_deref(),
            Some("PROLITE")
        );
        assert_eq!(resolve_tag(&m, None), None, "no container, no tag");
    }

    #[test]
    fn tag_from_field_sanitises_plan_type_before_the_chip_sees_it() {
        let m = codex_like_manifest(
            "TICKOVER_TEST_LOGFILE_NEVER_SET_1B",
            "/nonexistent",
            "/nonexistent",
        );
        let container =
            json!({ "primary": { "used_percent": 1.0 }, "plan_type": "pro\u{200B}\nlite" });
        assert_eq!(
            resolve_tag(&m, Some(&container)).as_deref(),
            Some("PROLITE"),
            "plan_type is response-supplied text like any other in this app"
        );
    }

    #[test]
    fn account_email_is_read_from_jwt_file() {
        let dir = temp_dir("account");
        let auth_path = dir.join("auth.json");
        let jwt = make_jwt(r#"{"email":"user@example.com"}"#);
        std::fs::write(
            &auth_path,
            json!({ "tokens": { "id_token": jwt } }).to_string(),
        )
        .unwrap();

        let m = codex_like_manifest(
            "TICKOVER_TEST_LOGFILE_NEVER_SET_2",
            "/nonexistent",
            &auth_path.to_string_lossy(),
        );
        assert_eq!(resolve_account(&m).as_deref(), Some("user@example.com"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn account_email_is_sanitised_the_same_as_any_other_decoded_claim() {
        let dir = temp_dir("account-sanitise");
        let auth_path = dir.join("auth.json");
        let jwt = make_jwt("{\"email\":\"user@example.com\u{200B}\\r\"}");
        std::fs::write(
            &auth_path,
            json!({ "tokens": { "id_token": jwt } }).to_string(),
        )
        .unwrap();

        let m = codex_like_manifest(
            "TICKOVER_TEST_LOGFILE_NEVER_SET_2B",
            "/nonexistent",
            &auth_path.to_string_lossy(),
        );
        assert_eq!(resolve_account(&m).as_deref(), Some("user@example.com"));
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── end-to-end (fetch_from_root) ────────────────────────────────────

    #[test]
    fn fetch_from_root_builds_the_equivalent_provider_reading() {
        let dir = temp_dir("happy-path");
        let auth_path = dir.join("auth.json");
        let jwt = make_jwt(r#"{"email":"user@example.com"}"#);
        std::fs::write(
            &auth_path,
            json!({ "tokens": { "id_token": jwt } }).to_string(),
        )
        .unwrap();

        write_file(
            &dir,
            "rollout-a.jsonl",
            &[json!({
                "rate_limits": {
                    "primary":   { "used_percent": 11.0, "window_minutes": 300,   "resets_at": 1783216497 },
                    "secondary": { "used_percent": 72.0, "window_minutes": 10080, "resets_at": 1783614509 },
                    "plan_type": "prolite"
                }
            })
            .to_string()],
        );

        let m = codex_like_manifest(
            "TICKOVER_TEST_LOGFILE_NEVER_SET_3",
            "/nonexistent",
            &auth_path.to_string_lossy(),
        );
        let lf = m.logfile.as_ref().unwrap();
        let (files, account_match) = discover(&dir, &lf.glob, &m, lf);
        let reading = fetch_from_root(&m, lf, &dir, &files, account_match.as_ref());

        assert_eq!(reading.id, "codex");
        assert_eq!(reading.name, "Codex");
        assert_eq!(reading.short, "Cx");
        assert_eq!(reading.tag.as_deref(), Some("PROLITE"));
        assert_eq!(reading.account.as_deref(), Some("user@example.com"));
        assert!(reading.error.is_none());
        assert!(reading.in_menu_bar);
        assert!(
            !reading.bare_when_sole,
            "the engine never sets bare_when_sole; the scheduler does"
        );

        let five = reading.primary_window().unwrap();
        assert_eq!(five.label, "5H");
        assert_eq!(five.used_percent, Some(11.0));
        assert_eq!(five.resets_at, Some(1783216497));
        assert_eq!(
            five.period_minutes,
            Some(300),
            "mode = from_field reads window_minutes from the data"
        );

        let week = reading.secondary_window().unwrap();
        assert_eq!(week.label, "WK");
        assert_eq!(week.used_percent, Some(72.0));
        assert_eq!(week.resets_at, Some(1783614509));
        assert_eq!(
            week.period_minutes,
            Some(10080),
            "mode = assumed uses the manifest constant"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_already_substituted_glob_decides_which_files_are_found() {
        let dir = temp_dir("option-glob");
        // The file only matches the glob once `{option.enabled}` resolves to
        // "true" — proving that whatever substituted `lf.glob` (`fetch`'s
        // job, not `fetch_from_root`'s: this function takes no `options` at
        // all) is what `collect_log_files` actually walks with, not just
        // `resolve_root`'s path fields.
        write_file(
            &dir,
            "rollout-true-a.jsonl",
            &[json!({ "rate_limits": { "primary": { "used_percent": 9.0 } } }).to_string()],
        );
        let m = codex_like_manifest(
            "TICKOVER_TEST_LOGFILE_NEVER_SET_GLOB",
            "/nonexistent",
            "/nonexistent",
        );
        let mut lf = m.logfile.as_ref().unwrap().clone();
        lf.glob = "rollout-{option.enabled}-*.jsonl".to_string();
        let mut opts = BTreeMap::new();
        opts.insert("enabled".to_string(), true);

        let glob = crate::plugin::substitute_options(&lf.glob, &opts);
        let (files, account_match) = discover(&dir, &glob, &m, &lf);
        let reading = fetch_from_root(&m, &lf, &dir, &files, account_match.as_ref());
        assert!(
            reading.error.is_none(),
            "the substituted glob must match the fixture file"
        );
        assert_eq!(reading.primary_window().unwrap().used_percent, Some(9.0));

        // With the option off, the same glob no longer matches the fixture.
        opts.insert("enabled".to_string(), false);
        let glob = crate::plugin::substitute_options(&lf.glob, &opts);
        let (files, account_match) = discover(&dir, &glob, &m, &lf);
        let reading = fetch_from_root(&m, &lf, &dir, &files, account_match.as_ref());
        assert!(
            reading.error.is_some(),
            "a mismatched substituted glob must find nothing"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_required_window_missing_from_the_reading_is_an_error_here_too() {
        // `required` is a promise the manifest makes, and for a while this
        // engine did not keep it: it dropped windows the reading did not carry
        // and never looked at the flag, so a manifest could state a guarantee
        // the app quietly ignored — and a manifest can come from a third-party
        // registry. The rule now lives in one place for both engines
        // (`crate::plugin::collect_windows`), which is what stops the two
        // drifting apart again.
        let dir = temp_dir("required-missing");
        write_file(
            &dir,
            "rollout-a.jsonl",
            &[json!({
                "rate_limits": {
                    "primary": { "used_percent": 3.0, "window_minutes": 300, "resets_at": 999 }
                }
            })
            .to_string()],
        );
        let mut m = codex_like_manifest(
            "TICKOVER_TEST_LOGFILE_NEVER_SET_REQ",
            "/nonexistent",
            "/nonexistent",
        );
        let weekly = m
            .windows
            .iter_mut()
            .find(|w| w.role == crate::plugin::manifest::Role::Secondary)
            .expect("the codex-like manifest has a weekly window");
        weekly.required = true;
        let label = weekly.label.clone();

        let lf = m.logfile.as_ref().unwrap();
        let (files, account_match) = discover(&dir, &lf.glob, &m, lf);
        let reading = fetch_from_root(&m, lf, &dir, &files, account_match.as_ref());

        assert_eq!(
            reading.error.as_deref(),
            Some(format!("no \"{label}\" window in the reading").as_str()),
            "the 5-hour slot parsed, but the window the manifest guarantees did not"
        );
        assert!(
            reading.windows.is_empty(),
            "a refused reading carries no rows"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_reading_carrying_no_usable_slot_reads_as_no_data_not_a_broken_window() {
        // The counterpart of the HTTP case: this manifest marks nothing
        // required, so a reading nothing could be got out of is reported as
        // no windows rather than as a broken provider. "Nothing resolved
        // means broken" was tried and removed — see
        // `crate::plugin::collect_windows` for the provider it is false for.
        let dir = temp_dir("nothing-usable");
        write_file(
            &dir,
            "rollout-a.jsonl",
            &[json!({ "rate_limits": { "primary": { "resets_at": 999 } } }).to_string()],
        );
        let m = codex_like_manifest(
            "TICKOVER_TEST_LOGFILE_NEVER_SET_EMPTY",
            "/nonexistent",
            "/nonexistent",
        );
        let lf = m.logfile.as_ref().unwrap();
        let (files, account_match) = discover(&dir, &lf.glob, &m, lf);
        let reading = fetch_from_root(&m, lf, &dir, &files, account_match.as_ref());

        // This engine never reaches the window rule for such a line: a
        // container carrying no usable slot is discarded while parsing, so
        // the file reads as holding no reading at all and the provider says
        // its "no usage data" sentence. Worth pinning — it is why the floor
        // that was removed from the shared rule was never doing anything here
        // in the first place.
        assert!(
            reading.error.is_some(),
            "no usable line means no reading at all"
        );
        assert!(
            !reading
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("window"),
            "and the reason is that nothing was found, not that a window went missing — got: {:?}",
            reading.error
        );
        assert!(reading.windows.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn found_reading_with_one_slot_missing_emits_only_the_slot_it_has() {
        let dir = temp_dir("weekly-only");
        write_file(
            &dir,
            "rollout-a.jsonl",
            &[json!({
                "rate_limits": {
                    "primary": { "used_percent": 3.0, "window_minutes": 10080, "resets_at": 999 }
                }
            })
            .to_string()],
        );
        let m = codex_like_manifest(
            "TICKOVER_TEST_LOGFILE_NEVER_SET_4",
            "/nonexistent",
            "/nonexistent",
        );
        let lf = m.logfile.as_ref().unwrap();
        let (files, account_match) = discover(&dir, &lf.glob, &m, lf);
        let reading = fetch_from_root(&m, lf, &dir, &files, account_match.as_ref());

        assert!(
            reading.error.is_none(),
            "a reading was found; this is not the error state"
        );
        assert_eq!(
            reading.windows.len(),
            1,
            "only the slot the reading actually carried"
        );
        assert!(
            reading.primary_window().is_none(),
            "the weekly data must not pose as the 5h window, and an empty 5h row is not a 5h window either"
        );
        let week = reading.secondary_window().unwrap();
        assert_eq!(week.used_percent, Some(3.0));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_matching_files_produces_an_error_reading_with_empty_windows() {
        let dir = temp_dir("no-data");
        let m = codex_like_manifest(
            "TICKOVER_TEST_LOGFILE_NEVER_SET_5",
            "/nonexistent",
            "/nonexistent",
        );
        let lf = m.logfile.as_ref().unwrap();
        let (files, account_match) = discover(&dir, &lf.glob, &m, lf);
        let reading = fetch_from_root(&m, lf, &dir, &files, account_match.as_ref());

        assert!(reading.error.is_some());
        assert!(reading.windows.is_empty());
        assert_eq!(reading.id, "codex");
        assert!(!reading.bare_when_sole);
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── account_match (shared session-tree guard) ───────────────────────

    /// A Codex-like manifest with a `[logfile.account_match]` guard. The
    /// `auth_claim` deliberately routes through a claim key that *contains a
    /// dot* (`"acme.auth"`), proving the segment-list form navigates it — a
    /// dotted-string path would mis-split it (the real Codex claim is
    /// `https://api.openai.com/auth`).
    fn codex_like_manifest_with_match(root: &str, account_path: &str) -> PluginManifest {
        let (root, account_path) = (toml_value(root), toml_value(account_path));
        let toml = format!(
            r#"
            id           = "codex"
            name         = "Codex"
            menu_label   = "Cx"
            order        = 10
            engine       = "log-file"

            [tag]
            from = "field"
            path = "plan_type"
            transform = "uppercase"

            [account]
            type       = "jwt-file"
            path       = {account_path}
            token_path = "tokens.id_token"
            claim      = "email"

            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode  = "from_field"
            field = "window_minutes"
            [windows.source]
            used_percent_path = "used_percent"
            resets_at_path    = "resets_at"
            max_period_minutes = 720

            [[windows]]
            label = "WK"
            role  = "secondary"
            [windows.period]
            mode  = "from_field"
            field = "window_minutes"
            [windows.source]
            used_percent_path = "used_percent"
            resets_at_path    = "resets_at"
            min_period_minutes = 721

            [logfile]
            root          = {root}
            glob          = "rollout-*.jsonl"
            container_key = "rate_limits"
            [logfile.account_match]
            container_field = "plan_type"
            auth_claim      = ["acme.auth", "plan"]
            "#
        );
        PluginManifest::from_str(&toml).expect("valid account_match manifest")
    }

    #[test]
    fn a_manifest_reads_a_windows_path_as_a_path() {
        // Every helper above interpolates a real directory into a manifest,
        // and on Windows a real directory is `C:\Users\RUNNER~1\AppData\…`.
        // Written into a TOML basic string unescaped, `\U` opens an
        // eight-digit unicode escape and `\a` opens nothing at all: the
        // manifest fails to parse and six tests fail for a reason none of
        // them is about. It took a Windows runner to find that, so this
        // states it where any machine can.
        let m = codex_like_manifest(
            "TICKOVER_TEST_LOGFILE_NEVER_SET_WIN",
            r"C:\Users\RUNNER~1\AppData\Local\Temp\sessions",
            r"C:\a\auth.json",
        );
        let lf = m.logfile.as_ref().expect("[logfile]");
        assert_eq!(lf.root, r"C:\Users\RUNNER~1\AppData\Local\Temp\sessions");
        assert_eq!(
            m.account.path.as_deref(),
            Some(r"C:\a\auth.json"),
            "a backslash is a path separator here, not the start of an escape"
        );
    }

    /// A rollout line whose `rate_limits` carries one weekly slot and a plan.
    fn weekly_line(plan: &str, used: f64) -> String {
        json!({
            "rate_limits": {
                "plan_type": plan,
                "secondary": { "used_percent": used, "window_minutes": 10080, "resets_at": 1_800_000_000u64 }
            }
        })
        .to_string()
    }

    #[test]
    fn account_match_pins_the_reading_to_the_current_login_plan() {
        let dir = temp_dir("account-match");
        let auth_path = dir.join("auth.json");
        // Current login: plan = "prolite", nested under a dotted claim key.
        let jwt = make_jwt(r#"{"email":"me@example.com","acme.auth":{"plan":"prolite"}}"#);
        std::fs::write(
            &auth_path,
            json!({ "tokens": { "id_token": jwt } }).to_string(),
        )
        .unwrap();

        // A single file interleaving both accounts, with a maxed-out `plus`
        // line *last* — exactly the shape that makes the un-guarded "newest
        // line wins" rule show the wrong account. The guard must select the
        // `prolite` line regardless of position.
        write_file(
            &dir,
            "rollout-a.jsonl",
            &[
                weekly_line("plus", 100.0),
                weekly_line("prolite", 5.0),
                weekly_line("plus", 100.0),
            ],
        );

        let m = codex_like_manifest_with_match("/nonexistent", &auth_path.to_string_lossy());
        let lf = m.logfile.as_ref().unwrap();
        let (files, account_match) = discover(&dir, &lf.glob, &m, lf);
        let reading = fetch_from_root(&m, lf, &dir, &files, account_match.as_ref());

        assert!(
            reading.error.is_none(),
            "the prolite line is a valid reading"
        );
        assert_eq!(
            reading.secondary_window().unwrap().used_percent,
            Some(5.0),
            "must surface the current (prolite) account's 5%, not the plus account's 100%"
        );
        assert_eq!(
            reading.tag.as_deref(),
            Some("PROLITE"),
            "the plan chip must match the selected account"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn account_match_shows_no_data_when_the_current_account_has_no_reading() {
        let dir = temp_dir("account-match-nodata");
        let auth_path = dir.join("auth.json");
        let jwt = make_jwt(r#"{"email":"me@example.com","acme.auth":{"plan":"prolite"}}"#);
        std::fs::write(
            &auth_path,
            json!({ "tokens": { "id_token": jwt } }).to_string(),
        )
        .unwrap();

        // Only the *other* account (plus) has any usage logged.
        write_file(&dir, "rollout-a.jsonl", &[weekly_line("plus", 100.0)]);

        let m = codex_like_manifest_with_match("/nonexistent", &auth_path.to_string_lossy());
        let lf = m.logfile.as_ref().unwrap();
        let (files, account_match) = discover(&dir, &lf.glob, &m, lf);
        let reading = fetch_from_root(&m, lf, &dir, &files, account_match.as_ref());

        assert!(
            reading.error.is_some(),
            "no prolite reading exists — honest 'no data', not the plus account's number"
        );
        assert!(reading.windows.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn account_match_falls_back_to_newest_when_the_plan_cannot_be_read() {
        let dir = temp_dir("account-match-noauth");
        // account.path points nowhere → the current plan is unknowable, so the
        // guard must NOT hide data; the pre-existing "newest line wins" applies.
        write_file(
            &dir,
            "rollout-a.jsonl",
            &[weekly_line("prolite", 5.0), weekly_line("plus", 100.0)],
        );

        let m = codex_like_manifest_with_match("/nonexistent", "/nonexistent/auth.json");
        let lf = m.logfile.as_ref().unwrap();
        let (files, account_match) = discover(&dir, &lf.glob, &m, lf);
        let reading = fetch_from_root(&m, lf, &dir, &files, account_match.as_ref());

        assert!(
            reading.error.is_none(),
            "with the plan unknown, a reading must still show"
        );
        assert_eq!(
            reading.secondary_window().unwrap().used_percent,
            Some(100.0),
            "unreadable auth → no filtering → the last line (plus 100%) wins, as before"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn container_matches_compares_the_field_against_expected() {
        let container = json!({ "plan_type": "prolite", "primary": { "used_percent": 1.0 } });
        let field = "plan_type".to_string();
        assert!(
            container_matches(&container, None),
            "no guard accepts anything"
        );
        assert!(container_matches(
            &container,
            Some(&(field.clone(), "prolite".to_string()))
        ));
        assert!(!container_matches(
            &container,
            Some(&(field, "plus".to_string()))
        ));
        // A field the container doesn't carry never matches a demanded value.
        let missing = "nonexistent".to_string();
        assert!(!container_matches(
            &container,
            Some(&(missing, "x".to_string()))
        ));
    }

    // ── secondary account rows (multi-account session tree) ─────────────

    /// A rollout line stamped with `ts`, carrying one weekly slot and a plan.
    fn ts_weekly_line(ts: &str, plan: &str, weekly_used: f64) -> String {
        json!({
            "timestamp": ts,
            "rate_limits": {
                "plan_type": plan,
                "secondary": { "used_percent": weekly_used, "window_minutes": 10080, "resets_at": 1_800_000_000u64 }
            }
        })
        .to_string()
    }

    #[test]
    fn collect_plan_groups_takes_newest_with_slots_and_skips_null_and_slotless() {
        let dir = temp_dir("groups");
        write_file(
            &dir,
            "rollout-a.jsonl",
            &[
                ts_weekly_line("2026-07-20T00:00:00Z", "plus", 50.0), // older plus
                ts_weekly_line("2026-07-21T00:00:00Z", "plus", 100.0), // newer plus → wins
                // A container with no plan_type must not spawn a phantom group.
                json!({ "timestamp": "2026-07-22T00:00:00Z", "rate_limits": { "secondary": { "used_percent": 3.0, "window_minutes": 10080 } } }).to_string(),
                // A slot-less container carries no usage and is ignored.
                json!({ "timestamp": "2026-07-22T01:00:00Z", "rate_limits": { "plan_type": "plus" } }).to_string(),
            ],
        );

        let mut files = collect_log_files(&dir, "rollout-*.jsonl");
        newest_first(&mut files);
        let groups = collect_plan_groups(&files, "test-plugin", "rate_limits", "plan_type");
        assert_eq!(
            groups.keys().collect::<Vec<_>>(),
            vec!["plus"],
            "only the real, plan-tagged account"
        );
        assert_eq!(
            groups["plus"].raw.secondary.as_ref().unwrap().used_percent,
            100.0,
            "the newest slotted plus reading wins, not the slot-less newest line"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn two_records_tied_on_timestamp_keep_the_one_earlier_in_the_file() {
        let dir = temp_dir("groups-tie");
        write_file(
            &dir,
            "rollout-a.jsonl",
            &[
                ts_weekly_line("2026-07-20T00:00:00Z", "plus", 11.0), // earlier in the file
                ts_weekly_line("2026-07-20T00:00:00Z", "plus", 42.0), // same instant, later line
            ],
        );

        let mut files = collect_log_files(&dir, "rollout-*.jsonl");
        newest_first(&mut files);
        let groups = collect_plan_groups(&files, "tie-test-plugin", "rate_limits", "plan_type");
        assert_eq!(
            groups["plus"].raw.secondary.as_ref().unwrap().used_percent,
            11.0,
            "two records tied on timestamp: the one earlier in the file wins"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn secondary_accounts_appends_only_other_recent_plan_labelled_accounts() {
        let dir = temp_dir("secondary");
        let auth_path = dir.join("auth.json");
        let jwt = make_jwt(r#"{"email":"me@example.com","acme.auth":{"plan":"prolite"}}"#);
        std::fs::write(
            &auth_path,
            json!({ "tokens": { "id_token": jwt } }).to_string(),
        )
        .unwrap();

        write_file(
            &dir,
            "rollout-a.jsonl",
            &[
                ts_weekly_line("2026-07-22T07:00:00Z", "prolite", 9.0), // current login → NOT a secondary
                ts_weekly_line("2026-07-21T12:00:00Z", "plus", 100.0), // other account, recent → included
                ts_weekly_line("2026-07-10T00:00:00Z", "free", 76.0), // other account, >7d stale → excluded
            ],
        );

        let m = codex_like_manifest_with_match("/nonexistent", &auth_path.to_string_lossy());
        let lf = m.logfile.as_ref().unwrap();
        let (files, account_match) = discover(&dir, &lf.glob, &m, lf);
        let secondaries = secondary_accounts(&m, lf, &files, account_match.as_ref());

        assert_eq!(
            secondaries.len(),
            1,
            "only the recent, non-current account earns a row"
        );
        let plus = &secondaries[0];
        assert_eq!(
            plus.id, "codex#plus",
            "distinct id keeps its window model off the primary's"
        );
        assert_eq!(
            plus.account, None,
            "a rollout log holds no email for the other account"
        );
        assert_eq!(plus.tag.as_deref(), Some("PLUS"), "labelled by plan tier");
        assert!(
            !plus.in_menu_bar,
            "secondary rows are popup-only; the pill stays on the current login"
        );
        assert_eq!(plus.secondary_window().unwrap().used_percent, Some(100.0));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `value` is a plan-tier string straight out of a log line a provider
    /// wrote, not a manifest author's — control characters, a newline, any
    /// length up to `MAX_LINE_BYTES`. It becomes this row's id, which is a
    /// config key and the popup's per-row model key, so it goes through the
    /// same sanitise-then-encode `sanitized_account`/`fill_label` already
    /// use for other response-supplied text, capped before it is encoded so
    /// a hostile value cannot inflate threefold in `%XX` escapes.
    #[test]
    fn a_secondary_reading_id_is_sanitised_and_encoded_before_becoming_a_config_key() {
        let m = codex_like_manifest("/nonexistent", "/nonexistent", "/nonexistent");
        let lf = m.logfile.as_ref().unwrap();
        let raw = RawReading {
            primary: Some(slot(10.0, Some(300))),
            secondary: None,
            container: json!({}),
        };
        let hostile = format!("pro\u{202E}\nteam{}", "x".repeat(200));
        let reading = build_secondary_reading(&m, lf, &hostile, &raw);

        assert!(
            reading.id.starts_with("codex#"),
            "keeps the plugin id prefix: {}",
            reading.id
        );
        assert!(
            !reading.id.contains('\n'),
            "a raw newline must never reach a config key: {:?}",
            reading.id
        );
        assert!(
            reading.id.len() < 250,
            "sanitising to PROVIDER_TEXT_MAX_CHARS before encoding bounds the id, {} bytes",
            reading.id.len()
        );

        // An ordinary plan value still becomes exactly the id it always did —
        // the fix must not change the case every shipped manifest relies on.
        let plain = build_secondary_reading(&m, lf, "plus", &raw);
        assert_eq!(plain.id, "codex#plus");
    }

    #[test]
    fn secondary_accounts_is_empty_when_the_current_login_is_unreadable() {
        let dir = temp_dir("secondary-noauth");
        write_file(
            &dir,
            "rollout-a.jsonl",
            &[ts_weekly_line("2026-07-22T00:00:00Z", "plus", 100.0)],
        );

        // account.path points nowhere → no "current login" to contrast against.
        let m = codex_like_manifest_with_match("/nonexistent", "/nonexistent/auth.json");
        let lf = m.logfile.as_ref().unwrap();
        let (files, account_match) = discover(&dir, &lf.glob, &m, lf);
        assert!(
            secondary_accounts(&m, lf, &files, account_match.as_ref()).is_empty(),
            "without a known current account there is no notion of an 'other' account"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_bogus_future_timestamp_on_one_account_cannot_hide_another_that_is_genuinely_current() {
        // `reference` is `max(ts)` across every account, including the
        // current login's own line — content this app reads but does not
        // control. A corrupted or clock-skewed line claiming a year 2099
        // timestamp must not push the recency cutoff seven days past 2099
        // and quietly drop a secondary account whose own line is genuinely
        // from today.
        let dir = temp_dir("secondary-future");
        let auth_path = dir.join("auth.json");
        let jwt = make_jwt(r#"{"email":"me@example.com","acme.auth":{"plan":"prolite"}}"#);
        std::fs::write(
            &auth_path,
            json!({ "tokens": { "id_token": jwt } }).to_string(),
        )
        .unwrap();

        let now = chrono::Utc::now().to_rfc3339();
        write_file(
            &dir,
            "rollout-a.jsonl",
            &[
                ts_weekly_line("2099-01-01T00:00:00Z", "prolite", 9.0), // current login, bogus line
                ts_weekly_line(&now, "plus", 100.0), // other account, actually current
            ],
        );

        let m = codex_like_manifest_with_match("/nonexistent", &auth_path.to_string_lossy());
        let lf = m.logfile.as_ref().unwrap();
        let (files, account_match) = discover(&dir, &lf.glob, &m, lf);
        let secondaries = secondary_accounts(&m, lf, &files, account_match.as_ref());

        assert_eq!(
            secondaries.len(),
            1,
            "a bogus future reference must not push the cutoff past now and \
             exclude a genuinely recent account"
        );
        assert_eq!(secondaries[0].id, "codex#plus");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fetch_emits_the_primary_and_a_secondary_account_row() {
        let dir = temp_dir("fetch-multi");
        let auth_path = dir.join("auth.json");
        let jwt = make_jwt(r#"{"email":"me@example.com","acme.auth":{"plan":"prolite"}}"#);
        std::fs::write(
            &auth_path,
            json!({ "tokens": { "id_token": jwt } }).to_string(),
        )
        .unwrap();

        write_file(
            &dir,
            "rollout-a.jsonl",
            &[
                ts_weekly_line("2026-07-22T07:00:00Z", "prolite", 9.0),
                ts_weekly_line("2026-07-21T12:00:00Z", "plus", 100.0),
            ],
        );

        // `root` points straight at the fixture dir (absolute → no `~`/env needed).
        let m =
            codex_like_manifest_with_match(&dir.to_string_lossy(), &auth_path.to_string_lossy());
        let readings = fetch(&m, &[], &no_options());

        assert_eq!(
            readings.len(),
            2,
            "primary (current login) + one secondary account"
        );
        assert_eq!(readings[0].id, "codex");
        assert_eq!(readings[0].account.as_deref(), Some("me@example.com"));
        assert_eq!(readings[0].tag.as_deref(), Some("PROLITE"));
        assert_eq!(
            readings[0].secondary_window().unwrap().used_percent,
            Some(9.0)
        );
        assert_eq!(readings[1].id, "codex#plus");
        assert_eq!(readings[1].account, None);
        assert_eq!(
            readings[1].secondary_window().unwrap().used_percent,
            Some(100.0)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── public fetch() / root resolution ────────────────────────────────

    #[test]
    fn fetch_uses_root_env_override_when_set() {
        let dir = temp_dir("fetch-root-env");
        write_file(
            &dir,
            "rollout-a.jsonl",
            &[json!({ "rate_limits": { "primary": { "used_percent": 5.0 } } }).to_string()],
        );

        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let env_name = "TICKOVER_TEST_ENGINE_LOGFILE_ROOT";
        std::env::set_var(env_name, &dir);
        let m = codex_like_manifest(env_name, "/nonexistent-should-not-be-used", "/nonexistent");
        let readings = fetch(&m, &[], &no_options());
        std::env::remove_var(env_name);

        assert_eq!(readings.len(), 1);
        assert!(
            readings[0].error.is_none(),
            "must have found the fixture via the env-overridden root"
        );
        assert_eq!(
            readings[0].primary_window().unwrap().used_percent,
            Some(5.0)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_root_falls_back_to_configured_root_when_env_unset() {
        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let unset_env = "TICKOVER_TEST_ENGINE_LOGFILE_ROOT_UNSET";
        std::env::remove_var(unset_env);
        let lf = LogFileConfig {
            root_env: Some(unset_env.to_string()),
            root_env_join: None,
            root: "~/.codex/sessions".to_string(),
            glob: "rollout-*.jsonl".to_string(),
            format: LogFileFormat::Jsonl,
            select: LogFileSelect::Last,
            container_key: "rate_limits".to_string(),
            classify_threshold_minutes: 720,
            detect_bin: None,
            not_installed_message: None,
            no_data_message: None,
            account_match: None,
        };
        let expected = dirs::home_dir().unwrap().join(".codex").join("sessions");
        assert_eq!(resolve_root(&lf, &no_options()), expected);
    }

    #[test]
    fn resolve_root_joins_root_env_join_onto_the_env_override() {
        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let env_name = "TICKOVER_TEST_ENGINE_LOGFILE_ROOT_JOIN";
        std::env::set_var(env_name, "/tmp/x");
        let lf = LogFileConfig {
            root_env: Some(env_name.to_string()),
            root_env_join: Some("sessions".to_string()),
            root: "~/.codex/sessions".to_string(),
            glob: "rollout-*.jsonl".to_string(),
            format: LogFileFormat::Jsonl,
            select: LogFileSelect::Last,
            container_key: "rate_limits".to_string(),
            classify_threshold_minutes: 720,
            detect_bin: None,
            not_installed_message: None,
            no_data_message: None,
            account_match: None,
        };
        assert_eq!(
            resolve_root(&lf, &no_options()),
            PathBuf::from("/tmp/x/sessions")
        );
        std::env::remove_var(env_name);
    }

    #[test]
    fn resolve_root_substitutes_option_placeholders_in_root_env_join() {
        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let env_name = "TICKOVER_TEST_ENGINE_LOGFILE_ROOT_OPTION_JOIN";
        std::env::set_var(env_name, "/tmp/x");
        let lf = LogFileConfig {
            root_env: Some(env_name.to_string()),
            root_env_join: Some("{option.subdir}".to_string()),
            root: "~/.codex/sessions".to_string(),
            glob: "rollout-*.jsonl".to_string(),
            format: LogFileFormat::Jsonl,
            select: LogFileSelect::Last,
            container_key: "rate_limits".to_string(),
            classify_threshold_minutes: 720,
            detect_bin: None,
            not_installed_message: None,
            no_data_message: None,
            account_match: None,
        };
        let mut opts = BTreeMap::new();
        opts.insert("subdir".to_string(), true);
        assert_eq!(resolve_root(&lf, &opts), PathBuf::from("/tmp/x/true"));

        opts.insert("subdir".to_string(), false);
        assert_eq!(resolve_root(&lf, &opts), PathBuf::from("/tmp/x/false"));
        std::env::remove_var(env_name);
    }

    #[test]
    fn resolve_root_substitutes_option_placeholders_in_the_plain_root_fallback() {
        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let unset_env = "TICKOVER_TEST_ENGINE_LOGFILE_ROOT_OPTION_PLAIN_UNSET";
        std::env::remove_var(unset_env);
        let lf = LogFileConfig {
            root_env: Some(unset_env.to_string()),
            root_env_join: None,
            root: "~/.codex-{option.variant}".to_string(),
            glob: "rollout-*.jsonl".to_string(),
            format: LogFileFormat::Jsonl,
            select: LogFileSelect::Last,
            container_key: "rate_limits".to_string(),
            classify_threshold_minutes: 720,
            detect_bin: None,
            not_installed_message: None,
            no_data_message: None,
            account_match: None,
        };
        let mut opts = BTreeMap::new();
        opts.insert("variant".to_string(), true);
        let expected = dirs::home_dir().unwrap().join(".codex-true");
        assert_eq!(resolve_root(&lf, &opts), expected);
    }

    #[test]
    fn resolve_root_ignores_root_env_join_when_env_unset() {
        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let unset_env = "TICKOVER_TEST_ENGINE_LOGFILE_ROOT_JOIN_UNSET";
        std::env::remove_var(unset_env);
        let lf = LogFileConfig {
            root_env: Some(unset_env.to_string()),
            root_env_join: Some("sessions".to_string()),
            root: "~/.codex/sessions".to_string(),
            glob: "rollout-*.jsonl".to_string(),
            format: LogFileFormat::Jsonl,
            select: LogFileSelect::Last,
            container_key: "rate_limits".to_string(),
            classify_threshold_minutes: 720,
            detect_bin: None,
            not_installed_message: None,
            no_data_message: None,
            account_match: None,
        };
        // No suffix appended onto the plain `root` fallback.
        let expected = dirs::home_dir().unwrap().join(".codex").join("sessions");
        assert_eq!(resolve_root(&lf, &no_options()), expected);
    }

    // ── installed vs no-data messaging ───────────────────────────────────

    /// A binary that is genuinely on `PATH` wherever this test suite runs:
    /// the platform's own shell. `sh` on Unix; on Windows `cmd`, which is
    /// also the more interesting case, since it only resolves through the
    /// executable-extension search — the file on disk is `cmd.exe`.
    fn shell_on_path() -> &'static str {
        if cfg!(windows) {
            "cmd"
        } else {
            "sh"
        }
    }

    #[test]
    fn bin_in_path_finds_a_real_shell_builtin_and_rejects_nonsense_names() {
        let shell = shell_on_path();
        assert!(bin_in_path(shell), "{shell} must be found on PATH");
        assert!(
            !bin_in_path("tickover-tray-definitely-not-a-real-binary-xyz"),
            "a nonsense name must not resolve"
        );
    }

    #[test]
    #[cfg(windows)]
    fn a_name_that_already_has_an_extension_keeps_it() {
        // `cmd.exe` names a real file, so the empty-suffix candidate finds
        // it. Replacing the extension instead of appending to it would turn
        // this into a search for `cmd.exe.exe`... and, worse, `cmd.js` into a
        // search for `cmd.exe`, which resolves to something else entirely.
        assert!(
            bin_in_path("cmd.exe"),
            "an explicit .exe must still resolve"
        );
        assert!(
            !bin_in_path("cmd.definitely-not-an-extension"),
            "and a name whose real suffix names nothing must not resolve via a substituted one"
        );
    }

    #[test]
    fn no_reading_message_is_generic_when_manifest_sets_no_detect_bin_or_messages() {
        let dir = temp_dir("generic-message");
        let m = codex_like_manifest(
            "TICKOVER_TEST_LOGFILE_NEVER_SET_6",
            "/nonexistent",
            "/nonexistent",
        );
        let mut lf = m.logfile.as_ref().unwrap().clone();
        lf.detect_bin = None;
        lf.not_installed_message = None;
        lf.no_data_message = None;

        let msg = no_reading_message(&m, &lf, &dir);
        assert_eq!(msg, "No Codex usage data found yet.");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_reading_message_is_not_installed_when_detect_bin_missing_and_root_absent() {
        let m = codex_like_manifest(
            "TICKOVER_TEST_LOGFILE_NEVER_SET_7",
            "/nonexistent",
            "/nonexistent",
        );
        let mut lf = m.logfile.as_ref().unwrap().clone();
        lf.detect_bin = Some("tickover-tray-definitely-not-a-real-binary-xyz".to_string());
        lf.not_installed_message =
            Some("Codex CLI not found.\nInstall: npm i -g @openai/codex".to_string());
        lf.no_data_message = Some("No usage yet — run a Codex session.".to_string());

        let missing_root = Path::new("/definitely/does/not/exist/anywhere");
        let msg = no_reading_message(&m, &lf, missing_root);
        assert_eq!(msg, "Codex CLI not found.\nInstall: npm i -g @openai/codex");
    }

    #[test]
    fn no_reading_message_is_no_data_when_root_exists_even_without_the_binary() {
        let dir = temp_dir("root-exists");
        let m = codex_like_manifest(
            "TICKOVER_TEST_LOGFILE_NEVER_SET_8",
            "/nonexistent",
            "/nonexistent",
        );
        let mut lf = m.logfile.as_ref().unwrap().clone();
        lf.detect_bin = Some("tickover-tray-definitely-not-a-real-binary-xyz".to_string());
        lf.not_installed_message =
            Some("Codex CLI not found.\nInstall: npm i -g @openai/codex".to_string());
        lf.no_data_message = Some("No usage yet — run a Codex session.".to_string());

        // The root directory existing is enough to count as "installed",
        // even though the binary itself isn't on PATH.
        let msg = no_reading_message(&m, &lf, &dir);
        assert_eq!(msg, "No usage yet — run a Codex session.");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_reading_message_is_no_data_when_detect_bin_is_on_path() {
        let dir = temp_dir("bin-on-path");
        let m = codex_like_manifest(
            "TICKOVER_TEST_LOGFILE_NEVER_SET_9",
            "/nonexistent",
            "/nonexistent",
        );
        let mut lf = m.logfile.as_ref().unwrap().clone();
        lf.detect_bin = Some(shell_on_path().to_string()); // resolvable on PATH
        lf.not_installed_message =
            Some("Codex CLI not found.\nInstall: npm i -g @openai/codex".to_string());
        lf.no_data_message = Some("No usage yet — run a Codex session.".to_string());

        let missing_root = Path::new("/definitely/does/not/exist/anywhere");
        let msg = no_reading_message(&m, &lf, missing_root);
        assert_eq!(msg, "No usage yet — run a Codex session.");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fetch_from_root_reports_not_installed_message_end_to_end() {
        let dir = temp_dir("not-installed-e2e");
        let m = codex_like_manifest(
            "TICKOVER_TEST_LOGFILE_NEVER_SET_10",
            "/nonexistent",
            "/nonexistent",
        );
        let mut lf = m.logfile.as_ref().unwrap().clone();
        lf.detect_bin = Some("tickover-tray-definitely-not-a-real-binary-xyz".to_string());
        lf.not_installed_message =
            Some("Codex CLI not found.\nInstall: npm i -g @openai/codex".to_string());
        lf.no_data_message = Some("No usage yet — run a Codex session.".to_string());

        // `dir` itself is created by `temp_dir`, so remove it first to exercise
        // the "root does not exist" branch of the installed check.
        std::fs::remove_dir_all(&dir).ok();

        let (files, account_match) = discover(&dir, &lf.glob, &m, &lf);
        let reading = fetch_from_root(&m, &lf, &dir, &files, account_match.as_ref());
        assert_eq!(
            reading.error.as_deref(),
            Some("Codex CLI not found.\nInstall: npm i -g @openai/codex")
        );
    }
}
