//! Provider plugin system.
//!
//! Every provider reading has a neutral shape (`crate::model`), and each
//! provider is described by a declarative TOML manifest rather than a
//! per-provider Rust module, read by a small set of generic engines:
//!
//! * [`manifest`] — the manifest schema (`PluginManifest`), parsing and
//!   validation. This is the stable contract the other modules build on.
//! * [`capability`] — `requires_reader`: what a manifest may ask this build of
//!   the reader to do, checked in both directions so neither an old app nor an
//!   undeclared new field ends in a confidently wrong number.
//! * [`auth`] — the ordered credential-lookup chain (`[[surface.auth]]`).
//! * [`engine_logfile`] — the `engine = "log-file"` reader (Codex-style).
//! * [`engine_http`] — the `engine = "http-api"` reader (Claude-style).
//! * [`time`] — timestamp parsing shared by [`engine_logfile`] and
//!   [`engine_http`]: an RFC3339 parser, a Unix-seconds reader tolerant of a
//!   provider that quotes its numbers, and the ten-year plausibility check
//!   neither engine used to enforce on its own.
//! * [`seed`] — the manifests shipped built-in with the app.
//! * [`scheduler`] — generic engine dispatch + refresh-cadence check, used by
//!   `src/main.rs`'s per-plugin fetch loop.
//! * [`throttle`] — the floor under how often [`engine_http`] may ask one
//!   provider, plus the backoff and the stop-on-dead-token that keep a
//!   failing endpoint from being hammered. The cadence in a manifest paces
//!   the timer; this paces everything else that fetches (panel open, Refresh,
//!   startup).
//! * [`registry`] — downloading/verifying manifests published under
//!   `plugins/` of this repository (`index.toml`), installed-vs-registry
//!   state and trust disclosure. Everything in it is pure and hermetic
//!   except its two network calls (`fetch_text`, `fetch_bytes`) — see its
//!   own module docs.
//! * [`signature`] — who published the registry index, as opposed to whether
//!   it arrived intact: ed25519 (minisign) verification of `index.toml`,
//!   checked ahead of [`registry`]'s own sha256/parsing once a key is pinned
//!   — see its own module docs for what a signature does and does not prove.

pub mod auth;
pub mod capability;
pub mod engine_http;
pub mod engine_logfile;
pub mod manifest;
pub mod registry;
pub mod scheduler;
pub mod seed;
pub mod signature;
pub mod throttle;
pub mod time;

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::model::Window;
use manifest::{PluginManifest, WindowConfig};

/// The UI slot a manifest's declared role names. One definition, so every
/// caller agrees: both engines convert a window's declared role into this UI
/// slot while building a `Window` (`engine_http`/`engine_logfile`), and
/// `src/main.rs` converts it the same way to look up a declared window's
/// remembered seen-state by role. A role mapped differently by any of them
/// would file the same window under the wrong slot — the failure
/// `crate::model::Role` exists to prevent.
pub fn map_role(r: manifest::Role) -> crate::model::Role {
    match r {
        manifest::Role::Primary => crate::model::Role::Primary,
        manifest::Role::Secondary => crate::model::Role::Secondary,
        manifest::Role::Extra => crate::model::Role::Extra,
    }
}

/// Assemble a reading's windows from whatever each declared window resolved
/// to, and decide whether what came back is usable at all.
///
/// Both engines call this with their own `build`, because the rule is about
/// the *manifest* rather than about JSON or log lines, and an engine that
/// implemented it differently would make `required` mean two things. It once
/// meant nothing at all in one of them: the log-file engine dropped
/// unresolved windows and never looked at `required`, so a manifest could
/// state a guarantee this app did not keep.
///
/// One refusal, and only one: a `required` window the reading does not carry.
/// That is the provider being wrong about its own shape, and the message names
/// the window so the manifest's author can see which one went missing (see
/// [`WindowConfig::required`]).
///
/// **A reading with no windows at all is not refused**, and that is a decision
/// rather than an omission. The obvious rule — "nothing resolved, so the
/// response must be broken" — was tried here and had to come out again,
/// because it is false for the provider this app was written for. Codex stops
/// reporting a window while that window is empty, and an account can have both
/// of its windows empty at once: in the hours after a weekly reset, with
/// nothing spent since. The body then holds two nulls and nothing else, which
/// is byte-for-byte what a broken endpoint would send, so no rule can tell
/// them apart. Refusing it costs the whole provider — the panel shows an error
/// instead of the account, the menu bar drops it, and the auto-ping stops in
/// precisely the state it exists to end. Reporting no windows costs a panel
/// section that says "no usage reported yet", which is true.
///
/// So a provider with a genuine invariant states it with `required` and gets a
/// hard error; one whose windows can all legitimately vanish states nothing
/// and gets an honest empty section. Only the manifest can tell those apart,
/// which is the whole reason the field exists.
///
/// `noun` names where the data was supposed to be ("response", "reading"), so
/// the message says something an author can act on.
pub fn collect_windows<F>(
    m: &PluginManifest,
    noun: &str,
    mut build: F,
) -> Result<Vec<Window>, String>
where
    F: FnMut(usize, &WindowConfig) -> Vec<Window>,
{
    let mut windows = Vec::new();
    let mut missing_required: Option<&str> = None;
    for (index, w) in m.windows.iter().enumerate() {
        // A `Vec` rather than an `Option` because an enumerating entry
        // (`windows.for_each`) draws a row per element of an array, so "what
        // this entry produced" is zero, one or many. `required` reads the
        // same either way — nothing produced is nothing reported.
        let produced = build(index, w);
        match produced.is_empty() {
            false => windows.extend(produced),
            // First one wins: the message names a window rather than counting
            // them, and a reading that lost one has usually lost the lot.
            true if w.required && missing_required.is_none() => {
                missing_required = Some(w.label.as_str());
            }
            true => {}
        }
    }
    if let Some(label) = missing_required {
        // Naming one window claims the others arrived. When none did, say
        // that instead — an author reading `no "5H" window` goes looking for
        // what happened to the 5-hour window, and the answer is that nothing
        // came back at all.
        return Err(match windows.is_empty() {
            true => format!("no limit data in {noun}"),
            false => format!("no \"{label}\" window in the {noun}"),
        });
    }
    Ok(windows)
}

/// Drop a UTF-8 byte-order mark, if the text starts with one.
///
/// A BOM is legal UTF-8 and `read_to_string` keeps it, so it arrives as a
/// zero-width character sitting in front of the first key — where a TOML or
/// JSON parser sees a syntax error on line 1 and the file reads as corrupt.
///
/// Which is not hypothetical on Windows, and not the user's fault when it
/// happens: "Edit" in the plugin manager opens the manifest in Notepad
/// (`open_in_text_editor`), whose Save has historically written UTF-8 *with*
/// a BOM. So the app can hand someone a file to edit and then refuse to read
/// what they saved. PowerShell's `Set-Content -Encoding utf8` does the same
/// thing to a config file edited by hand.
///
/// Stripping is safe in both directions: a BOM carries no meaning in either
/// format, and nothing here writes one.
pub fn strip_bom(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

/// The host `url` will actually be sent to — `None` for anything that is not
/// `https`, including a string that does not parse as a URL at all. Every
/// caller of this function is deciding whether a credential may leave the
/// machine, and no answer is safer than a wrong one.
///
/// Parsed with the `url` crate — the same WHATWG parser `ureq` builds a
/// request through — rather than by splitting the string on `/`, `?`, `#`
/// and `@` by hand. The two do not agree on where a URL's authority ends:
/// `https` is a WHATWG *special* scheme, and a special scheme's authority
/// ends at a `\` exactly as it does at a `/` — a byte a hand-rolled split
/// never looked for. `https://evil.example\@api.anthropic.com/x` reads, to
/// a human and to a naive parser, as userinfo `evil.example` at host
/// `api.anthropic.com`; `url` — and therefore `ureq`, which sends the
/// request — reads it as host `evil.example`, path
/// `/@api.anthropic.com/x`. An `allowed_hosts` check that used the naive
/// reading would wave through a URL whose request goes somewhere else
/// entirely, which is the whole point of the check failing quietly.
///
/// `Url::host_str` already returns the host normalised — lowercase, an
/// IPv6 literal bracketed with its hex digits lowered, a Unicode label
/// turned to its punycode form — so nothing further is done to what it
/// returns here; callers still compare case-insensitively regardless, as a
/// second, cheaper safeguard rather than a substitute for this one.
pub fn https_host(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    parsed.host_str().map(str::to_string)
}

/// Expand a manifest path spec.
///
/// Two prefixes are recognised, checked only at the very start of the
/// string, and only when what follows is either nothing or a path
/// separator (see [`strip_prefix_at_boundary`]):
/// * `~` — the user's home directory ([`dirs::home_dir`]).
/// * `{config_dir}` — the OS config directory ([`dirs::config_dir`]; e.g.
///   `~/Library/Application Support` on macOS, `%APPDATA%` on Windows).
///
/// Anything else is returned as a literal path. If the corresponding
/// directory can't be resolved, the original spec is returned unchanged as a
/// path (better a confusing path than a panic) — callers should still treat
/// the result as best-effort.
pub fn expand_home(spec: &str) -> PathBuf {
    if let Some(rest) = strip_prefix_at_boundary(spec, "{config_dir}") {
        return match dirs::config_dir() {
            Some(dir) => join_rest(dir, rest),
            None => PathBuf::from(spec),
        };
    }
    if let Some(rest) = strip_prefix_at_boundary(spec, "~") {
        return match dirs::home_dir() {
            Some(home) => join_rest(home, rest),
            None => PathBuf::from(spec),
        };
    }
    PathBuf::from(spec)
}

/// `spec` with `prefix` removed, but only when what follows is either
/// nothing or a path separator — never when it merely looks like more of
/// the same word. Without this boundary, `~otheruser/x` would strip to
/// `otheruser/x` and join it onto *this* user's home directory rather than
/// `otheruser`'s (`~` names a user's home only when it stands alone or is
/// immediately followed by `/`; `~otheruser` is a different, POSIX-defined
/// shell expansion this app has never implemented and must not silently
/// mimic half of), and `{config_dir}rc` — a literal string that merely
/// starts with the placeholder's own text — would resolve as `<config
/// dir>/rc` rather than being left as the literal path it actually is.
fn strip_prefix_at_boundary<'a>(spec: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = spec.strip_prefix(prefix)?;
    if rest.is_empty() || rest.starts_with('/') || rest.starts_with('\\') {
        Some(rest)
    } else {
        None
    }
}

/// Join whatever followed a recognised prefix onto `base`, stripping a
/// leading separator so `base.join(rest)` doesn't mistake it for absolute.
fn join_rest(base: PathBuf, rest: &str) -> PathBuf {
    let rest = rest.trim_start_matches(['/', '\\']);
    if rest.is_empty() {
        base
    } else {
        base.join(rest)
    }
}

/// Read a file that must resolve to a *regular* file, bounded in size.
///
/// Every path this app reads is either configured in a manifest or sits in a
/// directory the user's other programs can write to, so "open the path and
/// read to the end" is not a safe instruction: a FIFO blocks until somebody
/// writes to it, which for a startup read is forever, and a character device
/// never ends at all. A symlink *to a regular file* is read exactly as if it
/// had been written directly — refusing it (as `symlink_metadata` used to,
/// here) reads as "this manifest/credentials file is absent" for no better
/// reason than the extra hop, which is not what somebody who symlinked a
/// shared dotfile into place would expect. What still has to be refused is a
/// path — direct or through a symlink — that resolves to anything other than
/// a plain file, a FIFO or device most of all, and the path can change kind
/// between a check and an open (a classic TOCTOU), so the `is_file()`
/// criterion below is applied twice: once by path, once more against the
/// open handle — the same two-stat technique `auth::scan_candidate` uses for
/// the identical race. The cap keeps an unexpectedly enormous file from being
/// pulled into memory whole.
///
/// The non-blocking open below that actually closes the race for a FIFO
/// swapped in between the two stats — `O_NONBLOCK` — is `cfg(unix)`; on a
/// platform without it, the first `metadata` call is still a cheap early
/// exit for the *ordinary* case (a FIFO already sitting there when this is
/// called), but a path that changes kind at exactly the wrong moment could
/// still block the open on that platform. Same qualification
/// `auth::scan_candidate`'s own doc gives its identical guard.
pub fn read_regular_file(path: &std::path::Path, max_bytes: u64) -> Option<String> {
    use std::io::Read;
    // Follows a symlink (unlike `symlink_metadata`) — a cheap early exit for
    // the common case (missing, a directory, a FIFO) that never opens a
    // handle at all.
    match std::fs::metadata(path) {
        Ok(meta) if meta.file_type().is_file() => {
            if meta.len() > max_bytes {
                return None;
            }
        }
        _ => return None,
    }
    let mut open_options = std::fs::OpenOptions::new();
    open_options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // This stat and the open below are two different syscalls: the path
        // can change kind between them, so a symlink swapped in for a FIFO
        // right after the check above would otherwise block an open with no
        // reason to expect anyone to ever write to it. `O_NONBLOCK` makes the
        // open itself return at once no matter what is there now (POSIX: a
        // FIFO opened this way still succeeds); the handle-level `is_file()`
        // check just below is what turns that success into a refusal instead
        // of a read — the same technique `auth::scan_candidate` uses for the
        // identical race.
        open_options.custom_flags(libc::O_NONBLOCK);
    }
    let file = open_options.open(path).ok()?;
    match file.metadata() {
        Ok(meta) if meta.file_type().is_file() => {}
        _ => return None,
    }
    let mut text = String::new();
    file.take(max_bytes).read_to_string(&mut text).ok()?;
    Some(text)
}

/// This app's own directory under the OS config dir
/// (`<OS config dir>/tickover`) — the library side's one definition.
/// `seed::plugins_dir` and `registry::lockfile_path` used to each redo
/// `dirs::config_dir()...join("tickover")` by hand, with their own text and
/// their own fallback, which is exactly the two-places-to-look
/// `config::dir()`'s own doc comment (in the binary crate) already warns
/// against — for its two callers there, not these. The binary and this
/// library are two separate compilation units (`src/lib.rs` does not declare
/// a `config` module), so `config::dir()` cannot reuse this function and
/// this cannot reuse it either; this is the one definition available to
/// callers that live in the library.
///
/// `None` when the OS config dir itself can't be resolved — callers decide
/// their own fallback, the same way `config::dir()`'s callers do.
pub fn app_config_dir() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("tickover"))
}

/// The directories a provider CLI is looked for in, and the ones it is
/// handed as `PATH` when one runs — the canonical list. Two callers, in two
/// crates that don't share code otherwise: `main.rs`'s `cli_dirs` (a thin
/// wrapper kept only so `find_bin`/`cli_path_env`/the auto-ping's own tests
/// don't move) and `auth::bin_candidates`, resolving an `oauth-refresh`
/// step's `[surface.auth.client] bins` names the same way. One list, moved
/// here rather than duplicated, because "where we are willing to find a CLI"
/// and "where a client's own binary lives" are the same question asked twice.
///
/// A bundled app inherits launchd's minimal `/usr/bin:/bin:/usr/sbin:/sbin`.
/// That is not only too little to *find* a CLI installed by npm or Homebrew;
/// it is also too little to *start* one that was found, because several of
/// these CLIs are wrapper scripts rather than binaries — `~/.npm-global/bin/
/// codex` is a symlink to `codex.js`, whose `#!/usr/bin/env node` finds no
/// `node` on that PATH. The run then dies before it begins, and since the
/// ping discards its output, it dies without a trace. So one list serves both
/// purposes: where we are willing to find a CLI is where that CLI may look for
/// its own interpreter.
pub fn cli_install_dirs() -> Vec<PathBuf> {
    let mut dirs_to_check: Vec<PathBuf> = Vec::new();
    if let Some(h) = dirs::home_dir() {
        dirs_to_check.push(h.join(".npm-global").join("bin"));
        dirs_to_check.push(h.join(".local").join("bin"));
        dirs_to_check.push(h.join(".bun").join("bin"));
        dirs_to_check.push(h.join(".volta").join("bin"));
        dirs_to_check.push(h.join(".cargo").join("bin"));
        dirs_to_check.push(h.join(".asdf").join("shims"));
        dirs_to_check.push(h.join(".local").join("share").join("mise").join("shims"));
        dirs_to_check.push(h.join("AppData").join("Roaming").join("npm"));
        // nvm keeps one directory per installed version and puts none of them
        // anywhere fixed, so the only way to name them is to look. Sorted so
        // the choice is stable rather than whatever order the filesystem hands
        // back; missing directory, unreadable directory and no versions
        // installed all simply contribute nothing.
        let mut nvm: Vec<PathBuf> = std::fs::read_dir(h.join(".nvm").join("versions").join("node"))
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path().join("bin"))
            .filter(|bin| bin.is_dir())
            .collect();
        nvm.sort();
        dirs_to_check.extend(nvm);
    }
    dirs_to_check.push("/usr/local/bin".into());
    dirs_to_check.push("/opt/homebrew/bin".into());
    dirs_to_check
}

/// A declared window's key: `<entry>:<element>`.
///
/// One function, called by both engines, because a key spelled differently in
/// one of them would file the same window under two registry entries — the
/// failure `map_role` exists to prevent, one field over.
///
/// The `<element>` half is empty here on purpose: this is the *entry's* own
/// key, and an enumerating entry (`windows.for_each`) has no single element
/// to name at this point — [`window_element_key`] is the one that fills that
/// half, once per element. The separator is written anyway rather than added
/// later: a key whose shape changes between releases is a key every install
/// has to migrate, and the empty tail costs one byte.
///
/// Separators are outside the byte set a part may contain (`[A-Za-z0-9_-]`), so
/// a value carrying one cannot be mistaken for a boundary. That is not
/// housekeeping: with `-` doing both jobs, `kind = "a-b"` with scope `c` and
/// `kind = "a"` with scope `b-c` would build the same key, and two quotas would
/// share one registry entry.
pub fn window_key(w: &WindowConfig, index: usize) -> String {
    format!(
        "{}{KEY_ENTRY_SEPARATOR}",
        encode_key_part(&w.entry_key(index))
    )
}

/// The same key, for a `[[balances]]` entry.
///
/// Same shape, same encoding, same empty `<element>` tail — a balance bound to
/// one quota rather than to the account was not observed live, so nothing
/// fills that half yet, and a key with no room for it would have to be
/// re-cut the day a provider does. The entry halves cannot collide with a
/// window's: an entry without an id falls back to `bN` where a window falls
/// back to `wN`, and a declared id is unique within its own section.
pub fn balance_key(b: &manifest::BalanceConfig, index: usize) -> String {
    format!(
        "{}{KEY_ENTRY_SEPARATOR}",
        encode_key_part(&b.entry_key(index))
    )
}

/// The same key for one row of an **enumerating** entry: the declared entry,
/// then the identity the element carries (`windows.for_each`).
///
/// The element half is percent-encoded like the entry half, so a model name
/// with a dot or a space in it cannot split the config path this key becomes a
/// segment of.
pub fn window_element_key(w: &WindowConfig, index: usize, element_id: &str) -> String {
    format!("{}{}", window_key(w, index), encode_key_part(element_id))
}

/// Between `<entry>` and `<element>`.
pub const KEY_ENTRY_SEPARATOR: char = ':';

/// Percent-encode everything outside the unreserved set, so a key part can
/// never contain a separator or a `.`.
///
/// `.` matters most: the key becomes a segment of a dotted config path
/// (`plugin.<id>.seen.<reading>.<key>`), and one inside it would split the path
/// and grow a neighbouring table in the user's `config.json`.
pub fn encode_key_part(part: &str) -> String {
    let mut out = String::with_capacity(part.len());
    for byte in part.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' => out.push(byte as char),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Longest a provider-supplied string may be once it reaches the screen.
///
/// Counted in Unicode scalar values rather than bytes, because truncating
/// bytes cuts a code point in half; "characters" would be a third thing again
/// (a grapheme cluster), and naming the unit is the point.
pub const PROVIDER_TEXT_MAX_CHARS: usize = 64;

/// Make a string from a provider's response safe to put on screen and in the
/// log.
///
/// The manifest is trusted — installing one is trusting it, and it can already
/// name its own credential source and command. **The response is not.** It
/// arrives over the network, it changes without notice, and an enumerating
/// entry (`windows.for_each`) supplies row captions straight from it.
///
/// Called at every sink a response-fed string reaches the screen through:
/// `reached_type`, the currency and text an amount can carry, an enumerating
/// entry's row caption (`fill_label`), the plan chip (`[tag] from =
/// "field"`), and the account address (`sanitized_account` in each engine) —
/// nothing a provider's response supplies reaches the panel unfiltered.
///
/// Not covered, deliberately: combining marks. A run of them stacks glyphs
/// vertically, and the cap below bounds how far that can go, but stripping
/// them would mangle ordinary text in half the world's scripts.
///
/// Stripped, not escaped: C0/C1 controls (a newline turns one row into two, and
/// a `\r` rewrites the log line before it), the bidi overrides
/// (U+202A–U+202E, U+2066–U+2069) that can visually reorder the text around
/// them, and the zero-width characters (U+200B–U+200D, U+FEFF) that hide
/// differences between two strings that look identical. Trimmed before the
/// length cap is applied, not after: capping first would let leading padding
/// spend the budget that should go to content, then trim away only what's
/// left exposed at the far edge — a caption padded with ten leading spaces
/// would lose ten characters of its own text to them instead of losing
/// nothing. Trimmed once more at the end for whatever the cut itself exposes
/// (a run of internal whitespace landing right at the cap). Then capped,
/// because a provider deciding to answer with a megabyte is a provider
/// deciding how tall the panel is.
pub fn sanitize_provider_text(text: &str) -> String {
    text.trim()
        .chars()
        .filter(|c| !c.is_control() && !is_invisible_or_directional(*c))
        .take(PROVIDER_TEXT_MAX_CHARS)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Characters that take up no space of their own but change how the text
/// around them reads — or ends.
///
/// Listed as classes rather than as the two or three that come to mind: the
/// directional marks (`U+200E`/`U+200F`), the word joiner and, worst of the
/// set, the Unicode line and paragraph separators. `char::is_control` does
/// not cover `U+2028`/`U+2029`, so a provider could still end a line in the
/// middle of one. The tag characters (`U+E0000`–`U+E007F`) and variation
/// selectors supplement (`U+E0100`–`U+E01EF`) round the set out: both ranges
/// render as nothing at all in a normal font, and a run of tag characters
/// used to be able to smuggle arbitrary text invisibly inside what looked
/// like an ordinary short caption.
fn is_invisible_or_directional(c: char) -> bool {
    matches!(
        c,
        // Directional marks and overrides: reorder what is printed after them.
        '\u{061C}'                  // Arabic letter mark
            | '\u{200E}' | '\u{200F}' // left-to-right / right-to-left mark
            | '\u{202A}'..='\u{202E}' // embeddings and overrides
            | '\u{2066}'..='\u{2069}' // isolates
            // Zero-width: hide a difference between two strings that look the same.
            | '\u{200B}'..='\u{200D}' // zero-width space, non-joiner, joiner
            | '\u{2060}'..='\u{2064}' // word joiner and invisible operators
            | '\u{FEFF}'              // zero-width no-break space
            | '\u{FFF9}'..='\u{FFFB}' // interlinear annotation
            | '\u{00AD}'              // soft hyphen
            // Line and paragraph separators, which `is_control` does not catch.
            | '\u{2028}' | '\u{2029}'
            // Tag characters and the variation selectors supplement: render
            // as nothing, and can carry a whole hidden string of their own.
            | '\u{E0000}'..='\u{E007F}'
            | '\u{E0100}'..='\u{E01EF}'
    )
}

/// Enough for any manifest, credentials file or version file this app reads —
/// all of them are hand-sized JSON or TOML.
pub const SMALL_FILE_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// [`manifest::AuthClientDiscovery`]'s `id_pattern`/`secret_pattern`: the
/// most bytes either may ever match, checked at manifest load
/// (`manifest::validate`, via `regex_syntax`'s parsed `maximum_len`) and
/// enforced again defensively at scan time (`auth::scan_candidate`). A
/// client id or secret is never remotely this long — the shipped
/// Antigravity ones measure 73 and 35 bytes — so the bound exists to stop a
/// pattern from turning "scan a file for a short id" into "read an
/// unbounded slice of it and call the slice the client".
pub const CLIENT_PATTERN_MAX_MATCH_BYTES: usize = 256;

/// [`manifest::AuthClientDiscovery`]'s `id_pattern`/`secret_pattern`: the
/// most bytes the pattern's own *source text* may be, checked at manifest
/// load (`manifest::validate`). A different bound from
/// [`CLIENT_PATTERN_MAX_MATCH_BYTES`], and for a different reason: that one
/// bounds what the pattern can *match*, this one bounds what the pattern
/// *is* — a compact pattern can still match a short, bounded string while
/// its own source is enormous (thousands of fixed-length alternatives, say),
/// and it is the source text `registry::analyze_trust` renders in the
/// install-time trust dialog, not the match. A real `id_pattern`/
/// `secret_pattern` is a few dozen characters (the shipped Antigravity ones
/// measure well under 100); 512 is generous headroom above that, not a
/// figure tuned to any one pattern.
pub const CLIENT_PATTERN_MAX_TEXT_BYTES: usize = 512;

/// Substitute every `{option.<key>}` placeholder in `template` with the
/// current value of that plugin option, `"true"`/`"false"` — shared by
/// [`crate::plugin::engine_http`] (headers, URL) and
/// [`crate::plugin::engine_logfile`] (`root`, `root_env_join`, `glob`).
///
/// `options` is the plugin's declared `[[option]]` set resolved to its
/// current value (config override, else the manifest's own `default`) —
/// engines are hermetic and never read config themselves (see their module
/// docs); the caller (`src/main.rs`) resolves this map once per fetch and
/// passes it in.
///
/// A `{option.<key>}` whose `key` isn't in `options` (a manifest typo, or a
/// manifest written for a newer engine version than declares the option) is
/// left untouched rather than replaced with an empty string — this keeps the
/// mistake visible in whatever field it lands in, instead of silently
/// producing an empty/malformed URL, header or path.
pub fn substitute_options(template: &str, options: &BTreeMap<String, bool>) -> String {
    let mut out = template.to_string();
    for (key, value) in options {
        let placeholder = format!("{{option.{key}}}");
        out = out.replace(&placeholder, if *value { "true" } else { "false" });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_byte_order_mark_is_dropped_and_nothing_else_is() {
        assert_eq!(strip_bom("\u{feff}id = \"codex\""), "id = \"codex\"");
        assert_eq!(
            strip_bom("id = \"codex\""),
            "id = \"codex\"",
            "text without one is untouched"
        );
        // Only at the very start, and only once: a BOM anywhere else is a
        // real (if odd) character in the document, not framing to remove.
        assert_eq!(strip_bom("\u{feff}\u{feff}x"), "\u{feff}x");
        assert_eq!(strip_bom("x\u{feff}"), "x\u{feff}");
        assert_eq!(strip_bom(""), "");
    }

    // ── https_host ───────────────────────────────────────────────────────

    #[test]
    fn https_host_reads_the_host_the_way_the_request_will_reach_it() {
        assert_eq!(
            https_host("https://api.anthropic.com/api/oauth/usage").as_deref(),
            Some("api.anthropic.com")
        );
        // Userinfo and port are not the host.
        assert_eq!(
            https_host("https://user:pass@api.anthropic.com/x").as_deref(),
            Some("api.anthropic.com")
        );
        assert_eq!(
            https_host("https://api.anthropic.com:443/x").as_deref(),
            Some("api.anthropic.com")
        );
        // `Url::host_str` already lowercases.
        assert_eq!(
            https_host("https://API.ANTHROPIC.COM/x").as_deref(),
            Some("api.anthropic.com")
        );
    }

    #[test]
    fn https_host_sees_the_backslash_authority_terminator_ureq_sees() {
        // `https` is a WHATWG "special" scheme, so its authority ends at a
        // `\` exactly as it does at a `/` — the byte a hand-rolled split on
        // `/`, `?`, `#` and `@` never looked for, and the reason this
        // function exists rather than one written by hand. The host here is
        // `evil.example`, not `api.anthropic.com`: `ureq` would send the
        // request there, so an `allowed_hosts` check must see it there too.
        assert_eq!(
            https_host("https://evil.example\\@api.anthropic.com/api/oauth/usage").as_deref(),
            Some("evil.example")
        );
    }

    #[test]
    fn https_host_rejects_non_https_and_unparsable_urls() {
        assert_eq!(https_host("http://api.anthropic.com/x"), None);
        assert_eq!(https_host("ftp://api.anthropic.com/x"), None);
        assert_eq!(https_host("not a url at all"), None);
        assert_eq!(https_host(""), None);
    }

    #[test]
    fn https_host_handles_a_bracketed_ipv6_literal_without_panicking() {
        assert_eq!(https_host("https://[::1]/x").as_deref(), Some("[::1]"));
    }

    #[test]
    fn expands_tilde_to_home_dir() {
        let home = dirs::home_dir().expect("home dir resolvable in test env");
        assert_eq!(
            expand_home("~/.codex/auth.json"),
            home.join(".codex/auth.json")
        );
        assert_eq!(expand_home("~"), home);
    }

    #[test]
    fn expands_config_dir_placeholder() {
        let cfg = dirs::config_dir().expect("config dir resolvable in test env");
        assert_eq!(
            expand_home("{config_dir}/Claude/config.json"),
            cfg.join("Claude/config.json")
        );
        assert_eq!(expand_home("{config_dir}"), cfg);
    }

    #[test]
    fn leaves_literal_paths_unchanged() {
        assert_eq!(expand_home("/etc/hosts"), PathBuf::from("/etc/hosts"));
        assert_eq!(expand_home("relative/path"), PathBuf::from("relative/path"));
    }

    #[test]
    fn a_tilde_immediately_followed_by_more_letters_is_not_this_users_home() {
        // `~otheruser/x` names *otheruser's* home directory in a real shell,
        // a POSIX expansion this app has never implemented — stripping the
        // bare `~` and joining the rest onto *this* user's home directory
        // instead would silently mimic half of that expansion and land on a
        // path nobody asked for.
        assert_eq!(
            expand_home("~otheruser/x"),
            PathBuf::from("~otheruser/x"),
            "left as a literal path, not resolved against this user's home"
        );
    }

    #[test]
    fn a_config_dir_placeholder_immediately_followed_by_more_letters_is_left_literal() {
        // `{config_dir}rc` merely starts with the placeholder's own text —
        // without a separator right after it, it isn't the placeholder at
        // all, and must not resolve as `<config dir>/rc`.
        assert_eq!(
            expand_home("{config_dir}rc"),
            PathBuf::from("{config_dir}rc")
        );
    }

    // ── substitute_options ───────────────────────────────────────────────

    #[test]
    fn substitute_options_replaces_known_keys_with_true_or_false() {
        let mut options = BTreeMap::new();
        options.insert("include_beta".to_string(), true);
        options.insert("verbose".to_string(), false);

        assert_eq!(
            substitute_options(
                "beta={option.include_beta}&verbose={option.verbose}",
                &options
            ),
            "beta=true&verbose=false"
        );
    }

    #[test]
    fn substitute_options_leaves_unknown_placeholders_untouched() {
        let options = BTreeMap::new();
        assert_eq!(
            substitute_options("mode={option.typo_key}", &options),
            "mode={option.typo_key}",
            "an undeclared option key must stay visible, not vanish into an empty string"
        );
    }

    #[test]
    fn substitute_options_is_a_no_op_on_templates_without_placeholders() {
        let mut options = BTreeMap::new();
        options.insert("include_beta".to_string(), true);
        assert_eq!(
            substitute_options("no placeholders here", &options),
            "no placeholders here"
        );
    }

    #[test]
    #[cfg(unix)]
    fn read_regular_file_refuses_anything_that_is_not_one() {
        let dir =
            std::env::temp_dir().join(format!("tickover-read-regular-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let real = dir.join("real.json");
        std::fs::write(&real, "{}").unwrap();
        assert_eq!(
            read_regular_file(&real, SMALL_FILE_MAX_BYTES).as_deref(),
            Some("{}")
        );

        // A directory, a missing path, and a file past the cap.
        assert_eq!(read_regular_file(&dir, SMALL_FILE_MAX_BYTES), None);
        assert_eq!(
            read_regular_file(&dir.join("nope.json"), SMALL_FILE_MAX_BYTES),
            None
        );
        assert_eq!(
            read_regular_file(&real, 1),
            None,
            "a file over the cap is refused, not truncated"
        );

        // A FIFO: reading one blocks until somebody writes, which for a
        // startup read means forever. `metadata` sees it for what it is
        // without opening it — there is no symlink here for it to follow.
        let fifo = dir.join("blocks.json");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        if matches!(made, Ok(s) if s.success()) {
            assert_eq!(read_regular_file(&fifo, SMALL_FILE_MAX_BYTES), None);
        } else {
            // `mkfifo` isn't guaranteed present everywhere this test runs —
            // silently asserting nothing here used to look identical to the
            // FIFO case actually having been exercised. Print rather than
            // skip outright: a CI log that never shows this line is the one
            // place this gap would otherwise go unnoticed.
            eprintln!(
                "SKIP: read_regular_file_refuses_anything_that_is_not_one — mkfifo unavailable"
            );
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg(unix)]
    fn read_regular_file_follows_a_symlink_to_a_regular_file() {
        // The gap this closes: a symlinked credentials file or manifest used
        // to read as absent for no reason but the extra hop — "not signed
        // in" for an account that plainly is.
        let dir = std::env::temp_dir().join(format!(
            "tickover-read-regular-symlink-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let real = dir.join("real.json");
        std::fs::write(&real, "{\"token\":\"abc\"}").unwrap();
        let link = dir.join("via-symlink.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert_eq!(
            read_regular_file(&link, SMALL_FILE_MAX_BYTES).as_deref(),
            Some("{\"token\":\"abc\"}"),
            "a symlinked credentials file/manifest must read exactly like one written directly"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sanitize_provider_text_trims_before_capping_so_leading_padding_never_eats_the_budget() {
        let padded = format!("{}{}", " ".repeat(10), "x".repeat(PROVIDER_TEXT_MAX_CHARS));
        let sanitized = sanitize_provider_text(&padded);
        assert_eq!(
            sanitized.chars().count(),
            PROVIDER_TEXT_MAX_CHARS,
            "capping before trimming would have spent ten characters of the budget on the \
             leading padding instead of on content: {sanitized:?}"
        );
    }

    #[test]
    fn sanitize_provider_text_strips_tag_characters_and_the_variation_selectors_supplement() {
        // Both ranges render as nothing in a normal font — a caption could
        // otherwise carry a whole hidden string of its own, invisibly, past
        // whatever the person approving the install actually reads on screen.
        let hidden = format!("visible{}{}", '\u{E0041}', '\u{E01EF}');
        assert_eq!(sanitize_provider_text(&hidden), "visible");
    }
}
