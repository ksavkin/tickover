//! The plugin registry: discovering, verifying and comparing manifests
//! published under `plugins/` of this repository (`index.toml` at its root —
//! see `docs/PLUGIN-ARCHITECTURE.md`'s "Registry" section, whose schema this
//! module implements verbatim) and fetched over HTTPS.
//!
//! Everything here is pure and hermetic **except** [`fetch_text`] and
//! [`fetch_bytes`] — the two network calls, isolated so the rest (index
//! parsing/validation, URL resolution, semver compare, sha256, the lockfile,
//! the installed-vs-registry diff, and trust disclosure) is unit-testable on
//! fixtures with zero network access. `src/main.rs`'s registry UI is the only
//! caller of either: [`fetch_bytes`] for anything a later step checks byte
//! for byte — `index.toml` itself (its ed25519 signature is over the exact
//! bytes the server sent, not a UTF-8 round-trip of them) and a manifest file
//! (see [`verify_and_prepare`]'s byte-exact contract) — and [`fetch_text`]
//! for the index's `.minisig` signature file, whose own bytes are never
//! hashed or compared against anything, so decoding them on the way in costs
//! nothing. It wires this module's pure functions together with the actual
//! filesystem writes (this module never writes a plugin manifest to disk
//! itself — see [`verify_and_prepare`]'s doc comment for the byte-exact
//! contract that implies).
//!
//! ```text
//! schema_version = 1                       # optional, default 1
//! [[plugin]]
//! id          = "some-provider"            # ^[A-Za-z0-9_-]+$
//! name        = "Some Provider"
//! version     = "1.0.0"                    # non-empty
//! description = "Some Provider usage indicator"  # optional
//! manifest    = "manifests/some-provider.toml"   # relative, no scheme, no ..
//! sha256      = "…"                        # 64 lowercase hex chars
//! ```
//!
//! Trust model: verifying `sha256` against the index only proves the
//! downloaded bytes weren't altered in transit — it says nothing about
//! whether the manifest itself is trustworthy. [`analyze_trust`] surfaces
//! what a manifest declares (not a verdict) so the installer can show a
//! meaningful warning before writing it to disk; see
//! `docs/PLUGIN-ARCHITECTURE.md`'s "Trust model" section for the full
//! picture this only summarizes.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::plugin::https_host;
use crate::plugin::manifest::{AuthStep, AuthType, EngineKind, LogFileConfig, PluginManifest};

// ── index.toml schema ────────────────────────────────────────────────────

/// A parsed, validated `index.toml`. Unknown top-level/entry fields are
/// ignored, not rejected (`deny_unknown_fields` deliberately unset, mirroring
/// [`PluginManifest`] — a future registry publisher may add fields this
/// build doesn't know about yet).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RegistryIndex {
    /// Index format version. Not currently branched on — reserved for a
    /// future incompatible schema change.
    #[serde(default = "default_schema_version")]
    pub schema_version: i64,
    /// `[[plugin]]` — every plugin the registry publishes.
    #[serde(default, rename = "plugin")]
    pub plugins: Vec<RegistryEntry>,
}

fn default_schema_version() -> i64 {
    1
}

/// One `[[plugin]]` entry in `index.toml`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RegistryEntry {
    /// Stable identifier — same charset as [`PluginManifest::id`]
    /// (`^[A-Za-z0-9_-]+$`), since it becomes the installed manifest's
    /// filename stem too.
    pub id: String,
    /// Display name — reaches the install/update UI unsanitised and
    /// unbounded, aside from what [`RegistryIndex::validate`] checks at
    /// parse time: no control, invisible or directional characters, and at
    /// most [`REGISTRY_NAME_MAX_CHARS`].
    pub name: String,
    /// Publisher-declared version (compared with [`version_cmp`]).
    pub version: String,
    /// Optional one-line description shown before install — same two
    /// checks as [`Self::name`], bounded instead by
    /// [`REGISTRY_DESCRIPTION_MAX_CHARS`].
    #[serde(default)]
    pub description: Option<String>,
    /// Path to the manifest file, **relative to the index's own directory**
    /// (see [`resolve_manifest_url`]) — never a full URL. Validated to rule
    /// out a scheme, a leading path separator, or a `..` component (a
    /// compromised index pointing at a manifest hosted on a different host,
    /// or outside the registry's own tree).
    pub manifest: String,
    /// Expected sha256 of the manifest file's raw bytes, lowercase hex.
    pub sha256: String,
}

impl RegistryIndex {
    /// Parse and validate `index.toml` source. Rejects malformed TOML and
    /// every invariant [`RegistryIndex::validate`] checks; a corrupted or
    /// dishonest index is rejected wholesale rather than partially trusted.
    // Deliberately inherent rather than `FromStr`, for the reason
    // `PluginManifest::from_str` is: a `FromStr` delegating here would be
    // sound, but `.parse()` reads as a conversion, and this validates as well
    // — a named constructor says which is happening at the call site.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(input: &str) -> Result<Self, String> {
        let index: RegistryIndex =
            toml::from_str(input).map_err(|e| format!("invalid index TOML: {e}"))?;
        index.validate()?;
        Ok(index)
    }

    fn validate(&self) -> Result<(), String> {
        if self.plugins.len() > MAX_INDEX_ENTRIES {
            return Err(format!(
                "index lists {} plugins, more than the {MAX_INDEX_ENTRIES} this app will ever \
                 read — a corrupted or dishonest index is rejected wholesale",
                self.plugins.len()
            ));
        }
        let mut seen_ids: HashSet<&str> = HashSet::new();
        for p in &self.plugins {
            validate_registry_id(&p.id)?;
            if p.name.trim().is_empty() {
                return Err(format!("plugin \"{}\": `name` must not be empty", p.id));
            }
            refuse_control_chars(&p.id, "name", &p.name)?;
            refuse_too_long(&p.id, "name", &p.name, REGISTRY_NAME_MAX_CHARS)?;
            if p.version.trim().is_empty() {
                return Err(format!("plugin \"{}\": `version` must not be empty", p.id));
            }
            if let Some(description) = &p.description {
                refuse_control_chars(&p.id, "description", description)?;
                refuse_too_long(
                    &p.id,
                    "description",
                    description,
                    REGISTRY_DESCRIPTION_MAX_CHARS,
                )?;
            }
            validate_sha256_hex(&p.id, &p.sha256)?;
            validate_relative_manifest_path(&p.manifest)
                .map_err(|e| format!("plugin \"{}\": {e}", p.id))?;
            refuse_control_chars(&p.id, "manifest", &p.manifest)?;
            if !seen_ids.insert(p.id.as_str()) {
                return Err(format!(
                    "duplicate plugin id \"{}\" in index — a corrupted or dishonest index is \
                     rejected wholesale",
                    p.id
                ));
            }
        }
        Ok(())
    }
}

/// [`RegistryEntry::name`]'s cap — plenty for any real provider's display
/// name, and short enough that a hostile index can't hand the install/update
/// UI a caption built to overflow it. A constant of its own rather than
/// reusing `crate::plugin::PROVIDER_TEXT_MAX_CHARS`: that one bounds a
/// provider *response* string this app sanitises at every render because it
/// changes without notice, where registry text is validated once, here, at
/// index-parse time.
const REGISTRY_NAME_MAX_CHARS: usize = 64;

/// [`RegistryEntry::description`]'s cap — a one-line summary shown before
/// install, not a changelog.
const REGISTRY_DESCRIPTION_MAX_CHARS: usize = 256;

/// The most `[[plugin]]` entries an index may list. No real registry
/// approaches this (this repo ships a handful) — it exists purely so a 10
/// MiB [`fetch_bytes`]-capped index can't still hand the UI thread on the
/// order of a hundred thousand rows to sort, diff and draw, which an index
/// that paid for its size in short ids rather than useful content could
/// otherwise reach well inside that byte cap.
const MAX_INDEX_ENTRIES: usize = 500;

/// Refuse a control character, or an invisible/directional one, anywhere in
/// `value` (`field`, on plugin `id`'s entry) — the same class
/// [`crate::plugin::sanitize_provider_text`] strips from a provider
/// *response* (`char::is_control` alone is only the Unicode `Cc` category; it
/// does not reach a bidi override or a zero-width character, both of which
/// [`crate::plugin::is_invisible_or_directional`] does cover), refused
/// outright here instead since this text is checked once, at load, rather
/// than sanitised at every render. A `name`/`description`/`manifest`
/// carrying a raw `\n` could otherwise split one log line into two, or a
/// dialog caption into a shape its own layout never accounted for; a bidi
/// override or a zero-width character could make two different index
/// entries render identically.
fn refuse_control_chars(id: &str, field: &str, value: &str) -> Result<(), String> {
    if value
        .chars()
        .any(|c| c.is_control() || super::is_invisible_or_directional(c))
    {
        return Err(format!(
            "plugin \"{id}\": `{field}` must not contain control, invisible or directional \
             characters"
        ));
    }
    Ok(())
}

/// Refuse `value` (`field`, on plugin `id`'s entry) past `max_chars` Unicode
/// scalar values — mirrors [`crate::plugin::PROVIDER_TEXT_MAX_CHARS`]'s own
/// "characters" unit (a byte count would cut a multi-byte code point in
/// half; a grapheme-cluster count is a third thing again).
fn refuse_too_long(id: &str, field: &str, value: &str, max_chars: usize) -> Result<(), String> {
    let len = value.chars().count();
    if len > max_chars {
        return Err(format!(
            "plugin \"{id}\": `{field}` must be at most {max_chars} characters, got {len}"
        ));
    }
    Ok(())
}

/// Same charset rule as [`PluginManifest::validate`]'s `id` check — the
/// registry entry's id becomes `<id>.toml` on disk once installed.
fn validate_registry_id(id: &str) -> Result<(), String> {
    if id.trim().is_empty() {
        return Err("`id` must not be empty".to_string());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(format!(
            "`id = \"{id}\"` must contain only ASCII letters, digits, underscores and hyphens"
        ));
    }
    if is_windows_reserved_device_name(id) {
        return Err(format!(
            "`id = \"{id}\"` is a Windows reserved device name — `{id}.toml` is not an \
             ordinary file there"
        ));
    }
    Ok(())
}

/// The Windows device names no id may share the (extension-insensitive)
/// base of — `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`. An
/// installed registry entry's id becomes exactly `<id>.toml`, and on Windows
/// `CON.toml` is not an ordinary file at all — opening it for writing
/// addresses the same reserved device `CON` does, whatever extension
/// follows. Checked case-insensitively, matching Windows itself. A trailing
/// dot or space is the other classic Windows device-name trap, but
/// [`validate_registry_id`]'s own charset check already refuses both (`.`
/// and ` ` are outside `[A-Za-z0-9_-]`), so there is nothing left here for
/// this function to add for that half.
const WINDOWS_RESERVED_DEVICE_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

fn is_windows_reserved_device_name(id: &str) -> bool {
    WINDOWS_RESERVED_DEVICE_NAMES
        .iter()
        .any(|reserved| id.eq_ignore_ascii_case(reserved))
}

/// A sha256 hex string must be exactly 64 characters, every one of them a
/// *lowercase* hex digit — rejecting uppercase keeps every stored/compared
/// hash in one canonical form (see [`sha256_hex`], which only ever emits
/// lowercase).
fn validate_sha256_hex(id: &str, sha: &str) -> Result<(), String> {
    let ok = sha.len() == 64
        && sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !ok {
        return Err(format!(
            "plugin \"{id}\": `sha256` must be exactly 64 lowercase hex characters, got \"{sha}\""
        ));
    }
    Ok(())
}

/// Reject anything that isn't a plain relative path under the index's own
/// tree: a URL scheme (`://`), a leading path separator (absolute path), a
/// `?`/`#` (a query string or fragment — [`resolve_manifest_url`] appends
/// this path straight onto the index's own URL by string concatenation, and
/// either character would have the appended text read as part of the
/// *query*/*fragment* rather than the path once a real URL parser sees the
/// joined string, which is exactly the kind of reinterpretation
/// [`resolve_manifest_url`]'s own host re-check exists to catch but a bare
/// string check like this one otherwise couldn't), or any `..` component
/// (directory traversal). This is what closes "a compromised index tricks
/// the installer into fetching a manifest from a different host, or a file
/// outside the registry's own tree" — see the module docs' Trust model note.
/// The scheme, leading-separator and query/fragment checks run on the raw
/// string; the `..` check runs on it percent-decoded first (see
/// [`percent_decode_lossy`]), so a compromised index cannot spell a
/// traversal component `%2e%2e` and slip past a check written against the
/// literal bytes — a server on the other end of the resolved URL decodes it
/// the same way, and would read it as `..` whether or not this check ever
/// looked at it that way. [`resolve_manifest_url`] re-checks the joined
/// URL's host as a second, independent guard.
fn validate_relative_manifest_path(path: &str) -> Result<(), String> {
    if path.trim().is_empty() {
        return Err("`manifest` must not be empty".to_string());
    }
    if path.contains("://") {
        return Err(format!(
            "`manifest = \"{path}\"` must not contain a URL scheme"
        ));
    }
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(format!(
            "`manifest = \"{path}\"` must be relative (no leading path separator)"
        ));
    }
    if path.contains('?') || path.contains('#') {
        return Err(format!(
            "`manifest = \"{path}\"` must not contain a `?` or `#`"
        ));
    }
    if percent_decode_lossy(path)
        .split(['/', '\\'])
        .any(|seg| seg == "..")
    {
        return Err(format!(
            "`manifest = \"{path}\"` must not contain a `..` component"
        ));
    }
    Ok(())
}

/// Percent-decode `s` for the sole purpose of exposing what it would read as
/// once a server decodes it — not a full RFC 3986 decoder, just `%XX` -> byte,
/// with a malformed or trailing `%` left alone rather than rejected. Used
/// only so [`validate_relative_manifest_path`]'s `..`-component check sees a
/// manifest path the way the request at the other end will; the result is
/// never itself sent anywhere or written to disk. Byte-based throughout
/// (never slices `s` itself) so a multi-byte character sitting where a hex
/// pair would be expected can't be sliced across a char boundary and panic.
fn percent_decode_lossy(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let hi = (bytes[i + 1] as char).to_digit(16).unwrap() as u8;
            let lo = (bytes[i + 2] as char).to_digit(16).unwrap() as u8;
            out.push(hi * 16 + lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ── Manifest URL resolution ──────────────────────────────────────────────

/// Resolve a `[[plugin]].manifest` path (already validated relative, see
/// [`validate_relative_manifest_path`]) against the index's own URL.
/// `base_index_url` is the URL `index.toml` itself was fetched from; its
/// trailing `index.toml` (if present) is stripped, and `relative_manifest`
/// is appended. As a second, independent guard against a hostile relative
/// path smuggling a host change past the string checks above, the resolved
/// URL's host is re-checked against the base URL's host — belt-and-braces,
/// since a purely relative path (no scheme, no leading `/`) can't actually
/// change host through string concatenation alone, but this function is the
/// one place that would notice if it somehow did. Both hosts are read by
/// [`https_host`], so a base that is not itself `https` yields no host to
/// compare against and fails closed the same way an unparsable one does —
/// this app's own registry index is always fetched over `https`, but
/// nothing here assumes a caller keeps that true.
pub fn resolve_manifest_url(
    base_index_url: &str,
    relative_manifest: &str,
) -> Result<String, String> {
    validate_relative_manifest_path(relative_manifest)?;

    // A query string or fragment on the index URL is not part of the path a
    // manifest hangs off. Left on, `strip_suffix("/index.toml")` misses, and
    // the manifest name gets appended to the query instead of the directory —
    // a URL that resolves to the wrong thing, or to nothing.
    let base = base_index_url
        .split(['?', '#'])
        .next()
        .unwrap_or(base_index_url);
    // Anchored to the path separator, not a bare "index.toml": an index
    // published under a name that merely *ends* in those letters (a
    // "custom-index.toml", say) would otherwise have its suffix chopped
    // instead of its whole filename, mangling the directory this joins onto.
    let base = base.strip_suffix("/index.toml").unwrap_or(base);
    let base = base.trim_end_matches('/');
    let joined = format!("{base}/{relative_manifest}");

    let base_host = https_host(base_index_url)
        .ok_or_else(|| format!("cannot determine host of index URL \"{base_index_url}\""))?;
    let joined_host = https_host(&joined)
        .ok_or_else(|| format!("cannot determine host of resolved manifest URL \"{joined}\""))?;
    if !base_host.eq_ignore_ascii_case(&joined_host) {
        return Err(format!(
            "resolved manifest URL \"{joined}\" left the index's host \"{base_host}\""
        ));
    }
    Ok(joined)
}

// ── Version comparison (hand-rolled semver, no crate) ────────────────────

/// A version's numeric `major.minor.patch` base plus an optional prerelease
/// identifier string (the part after `-`, build metadata already stripped)
/// — [`parse_semver`]'s return shape, named so its callers don't repeat the
/// nested tuple type.
type SemverParts<'a> = ((u64, u64, u64), Option<&'a str>);

/// Compare two version strings as `major.minor.patch` integers when both
/// parse that way (so `"1.2.0" < "1.10.0"`, unlike a naive string compare),
/// with basic semver prerelease semantics on top: a `-<prerelease>` suffix
/// (e.g. `"1.0.0-alpha"`) is split off the numeric base by [`parse_semver`]
/// and compared per semver's own rules — a release outranks any prerelease
/// of the same base (`"1.0.0" > "1.0.0-alpha"`), and two prereleases of the
/// same base compare dot-segment by dot-segment via [`compare_prerelease`].
/// Build metadata (a trailing `+...`) is stripped and never affects the
/// comparison (`"1.0.0+build" == "1.0.0"`), per semver. When either side
/// isn't shaped like `x.y.z` (optionally followed by `-<prerelease>` and/or
/// `+<build>`) at all — a missing segment, a non-numeric major/minor/patch,
/// empty string, … — that side never counts as *newer* than one that does
/// parse: a version-shaped string always outranks a non-version-shaped one,
/// whichever argument position it's in. Without that rule a hostile
/// registry could publish `version = "beta"` and have it read as newer than
/// every properly-versioned installed manifest forever, purely because
/// `'b' > '1'` in ASCII — an update prompt with no version to actually
/// install and no way to ever resolve. When *both* sides fail to parse, they
/// compare as `Equal` rather than falling back to a plain string compare —
/// two strings this pair was never meant to hold a version-shaped opinion
/// about don't get to disagree about which is newer just because their
/// bytes happen to sort one way, and [`PluginManifest::version`] is
/// free-form, defaulting to `""` for a manifest that predates the plugin
/// registry entirely (see that field's own doc): exactly the shape that used
/// to make the registry's own declared version look "newer" purely from
/// being non-empty, and nag "update available" forever with nothing real to
/// update.
pub fn version_cmp(a: &str, b: &str) -> Ordering {
    match (parse_semver(a), parse_semver(b)) {
        (Some((base_a, pre_a)), Some((base_b, pre_b))) => match base_a.cmp(&base_b) {
            Ordering::Equal => match (pre_a, pre_b) {
                (None, None) => Ordering::Equal,
                // A plain release outranks a prerelease of the same base —
                // "1.0.0" is newer than "1.0.0-alpha".
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(pa), Some(pb)) => compare_prerelease(pa, pb),
            },
            other => other,
        },
        // A version-shaped string always outranks one that isn't — see this
        // function's own doc for why a non-version-shaped side must never
        // win a "newer" comparison just because its bytes happen to sort
        // higher.
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        // Neither side is version-shaped at all — see this function's own
        // doc for why a string-sort tiebreak here would be exactly the same
        // meaningless-bytes problem the asymmetric rule above closes, just
        // for the case where both sides have it at once.
        (None, None) => Ordering::Equal,
    }
}

/// Parse `v` into its numeric `major.minor.patch` base plus an optional
/// prerelease identifier string — `None` when `v` isn't shaped like `x.y.z`
/// (optionally followed by `-<prerelease>`), matching [`version_cmp`]'s own
/// documented fallback condition. Build metadata (everything from the first
/// `+` onward, if any) is stripped before anything else is parsed and simply
/// discarded — per semver, it never affects precedence.
fn parse_semver(v: &str) -> Option<SemverParts<'_>> {
    let v = v.split('+').next().unwrap_or(v); // strip build metadata, if any
    let (base, prerelease) = match v.split_once('-') {
        Some((b, p)) => (b, Some(p)),
        None => (v, None),
    };
    let mut parts = base.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch = parts.next()?.parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None; // more than three segments -> not a plain x.y.z
    }
    Some(((major, minor, patch), prerelease))
}

/// Compare two prerelease identifier strings (already split off the base
/// version's `major.minor.patch` by [`parse_semver`], e.g. `"alpha"` or
/// `"beta.2"`) dot-segment by dot-segment: a segment that parses as a
/// non-negative integer compares numerically, otherwise both segments
/// compare as plain ASCII strings — and a segment that parses as a number
/// always ranks below one that doesn't, whichever side it's on. That last
/// rule is full semver's own ("a numeric identifier always has lower
/// precedence than an alphanumeric identifier"), not a simplification of it:
/// the `(Ok(_), Err(_))`/`(Err(_), Ok(_))` arms below exist to implement it,
/// not merely to break a tie between two differently-shaped segments. A
/// prerelease with fewer segments than the other, once every shared segment
/// compares equal, sorts before the longer one (`"1.0.0-alpha" <
/// "1.0.0-alpha.1"`) — per semver, a larger set of fields has higher
/// precedence than a smaller set when all preceding identifiers are equal.
/// This is deliberately the *basic* semver semantics [`version_cmp`]'s own
/// doc comment scopes itself to — full semver also forbids leading zeros in
/// numeric identifiers, the one nuance still not enforced here: a segment
/// like `"01"` parses and compares as the integer `1`, which real semver
/// would refuse to accept as a version at all rather than compare.
fn compare_prerelease(a: &str, b: &str) -> Ordering {
    let mut ai = a.split('.');
    let mut bi = b.split('.');
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => {
                let cmp = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(nx), Ok(ny)) => nx.cmp(&ny),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => x.cmp(y),
                };
                if cmp != Ordering::Equal {
                    return cmp;
                }
            }
        }
    }
}

/// Whether `registry` is a newer version than `installed` — `false` for
/// equal or older ([`Ordering::Equal`]/[`Ordering::Less`]), never an
/// "unknown" third state; an unparsable pair still resolves via
/// [`version_cmp`]'s string fallback.
fn update_available(installed: &str, registry: &str) -> bool {
    version_cmp(registry, installed) == Ordering::Greater
}

// ── sha256 ────────────────────────────────────────────────────────────────

/// Lowercase hex sha256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Whether `bytes` hashes to `expected_hex` (case-insensitive on the
/// expected string — an index is required to publish lowercase via
/// [`validate_sha256_hex`], but this comparison doesn't rely on that having
/// been checked, e.g. when verifying an already-installed file's hash
/// against a hand-typed value in a test).
pub fn verify_sha256(bytes: &[u8], expected_hex: &str) -> bool {
    sha256_hex(bytes).eq_ignore_ascii_case(expected_hex)
}

// ── Byte-exact download verification ─────────────────────────────────────

/// Verify a downloaded manifest's raw bytes against the index's expected
/// sha256, and parse it as a gate ("does this even parse as a
/// [`PluginManifest`]") — **not** as the source of what gets written to
/// disk. The contract with the caller (`src/main.rs`'s registry UI):
///
/// 1. Download the manifest's raw bytes (via [`fetch_bytes`] — never
///    [`fetch_text`], whose `into_string` UTF-8-decodes the response body
///    before this function ever sees it; sha256 must be computed over the
///    exact bytes the server sent, not a decoded/re-encoded copy of them).
/// 2. Call this function with those exact bytes and the index's `sha256`.
/// 3. On `Ok`, write the **original, unmodified `raw_bytes`** to disk (never
///    a re-serialization of the returned [`PluginManifest`] — TOML
///    re-serialization is not guaranteed byte-identical, and the whole point
///    of the sha256 check is that the bytes on disk are the exact bytes that
///    were verified).
/// 4. Store the returned hash (already lowercase — see [`sha256_hex`]) as
///    that plugin's [`RegistryLockEntry::origin_sha256`].
///
/// Returns `Err` on a sha256 mismatch (before ever attempting to parse —
/// verify first, parse second) or on a hash match that still doesn't parse
/// as a valid [`PluginManifest`].
pub fn verify_and_prepare(
    raw_bytes: &[u8],
    expected_sha_hex: &str,
) -> Result<(PluginManifest, String), String> {
    let actual = sha256_hex(raw_bytes);
    if !actual.eq_ignore_ascii_case(expected_sha_hex) {
        return Err(format!(
            "sha256 mismatch: expected {expected_sha_hex}, downloaded bytes hash to {actual}"
        ));
    }
    let text = std::str::from_utf8(raw_bytes)
        .map_err(|e| format!("downloaded manifest is not valid UTF-8: {e}"))?;
    let manifest = PluginManifest::from_str(text)?;
    Ok((manifest, actual))
}

// ── Lockfile (registry-state.json) — provenance for the diff/state machine ─

/// One plugin's install provenance: what it was installed *from*, so a later
/// "check updates" run can tell a pristine install (safe to overwrite) apart
/// from one the user has since hand-edited (overwrite would destroy their
/// edits) — see [`diff_installed`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryLockEntry {
    /// The index URL this plugin was installed/updated from.
    pub origin_registry_url: String,
    /// The registry `version` at the time of install/update.
    pub origin_version: String,
    /// The sha256 (lowercase hex) of the exact bytes written to disk at
    /// install/update time — compared against the *current* file's hash
    /// (computed by the caller — this module never reads plugin files off
    /// disk) to detect local edits.
    pub origin_sha256: String,
    /// Unix seconds at install/update time. Set by the caller
    /// (`src/main.rs`); this module never reads the clock.
    pub installed_at: u64,
}

/// `registry-state.json`'s top-level shape: `{ "plugins": { "<id>": {...} } }`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RegistryLockState {
    #[serde(default)]
    pub plugins: std::collections::BTreeMap<String, RegistryLockEntry>,
}

impl RegistryLockState {
    /// This plugin's provenance record, if any (`None` for a plugin that was
    /// never installed via the registry — e.g. the bundled codex/claude
    /// manifests, or a hand-dropped third-party one).
    pub fn get(&self, id: &str) -> Option<&RegistryLockEntry> {
        self.plugins.get(id)
    }

    /// Record (or overwrite) a plugin's provenance after an install/update.
    pub fn set(&mut self, id: &str, entry: RegistryLockEntry) {
        self.plugins.insert(id.to_string(), entry);
    }

    /// Drop a plugin's provenance record (e.g. on removal), mirroring
    /// `crate::config::remove_plugin_keys`'s cleanup-on-delete role for the
    /// registry's own state.
    pub fn remove(&mut self, id: &str) {
        self.plugins.remove(id);
    }
}

/// Where the real lockfile lives: `<config dir>/tickover/registry-state.json`
/// — the same `tickover` base directory `crate::config` and
/// `crate::plugin::seed::plugins_dir` use. Never called by a test (every test
/// exercises [`load_lockfile`]/[`save_lockfile`] with an explicit tempdir
/// path instead — see their own docs); only `src/main.rs` calls this to get
/// the production path.
pub fn lockfile_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("tickover")
        .join("registry-state.json")
}

/// Load the lockfile at `path`. Best-effort, like `crate::config`'s own
/// `load`: a missing file, unreadable file, or corrupt JSON all quietly
/// resolve to [`RegistryLockState::default`] (an empty `plugins` map) rather
/// than an error — a missing/corrupt lockfile must never block reading or
/// installing plugins, only degrade the "was this locally modified"
/// provenance check in [`diff_installed`] to the no-record branch.
///
/// Read through [`crate::plugin::read_regular_file`] rather than a plain
/// `std::fs::read_to_string`: this runs on every "check updates" tick, and a
/// FIFO planted at this predictable path would otherwise hang it forever the
/// same way one at `config.json` would hang the app's own tick.
pub fn load_lockfile(path: &Path) -> RegistryLockState {
    crate::plugin::read_regular_file(path, crate::plugin::SMALL_FILE_MAX_BYTES)
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// How many `.corrupt-<unix secs>[-<n>]` names [`backup_if_corrupt`] tries
/// before giving up on saving a backup at all — mirrors `config.rs`'s own
/// `CORRUPT_BACKUP_MAX_ATTEMPTS` and the same reasoning: the name is only
/// second-resolution, so two corrupt lockfiles backed up inside the same
/// second would otherwise fight over one name. The count matches; the
/// numbering doesn't — `config.rs`'s first retry after the bare name is
/// `-2` (its own counter starts at the attempt number, 1, for the bare
/// name), where this one's first retry is `-1` (its own counter starts at
/// 0). Neither sequence is load-bearing outside its own module, so nothing
/// depends on the two agreeing.
const LOCKFILE_BACKUP_MAX_ATTEMPTS: u32 = 100;

/// Back up `path`'s current content, if any, before it's about to be
/// overwritten and doesn't parse as a [`RegistryLockState`] — mirrors
/// `config.rs`'s own `backup_if_corrupt` for `config.json`, for the same
/// reason: [`load_lockfile`] silently treats anything that doesn't parse as
/// an empty lockfile, so without this a corrupt lockfile is simply gone the
/// moment the next install/update writes a fresh one over it, taking every
/// provenance record it held with it. Best-effort and silent, unlike
/// `config.rs`'s own version, which logs via `diag::line`: this module lives
/// in the library crate, which `diag` (a binary-crate-only module, like
/// `config` itself) is not part of — there is no sink here to log to. A
/// caller that wants to know can still see for itself: the backup, when one
/// was made, sits right beside `path` as `<name>.corrupt-<unix-seconds>` (or
/// a `-<n>`-suffixed sibling, see [`LOCKFILE_BACKUP_MAX_ATTEMPTS`]).
///
/// Read through [`crate::plugin::read_regular_file`], not a plain
/// `std::fs::read_to_string` — same reason [`load_lockfile`] itself is: a
/// FIFO planted at this predictable path must not hang the save that is
/// about to happen. Written via `create_new`, never `std::fs::copy` — that
/// destination name is exactly as predictable (this second, not this
/// process), and `copy` opens its destination with truncate, following a
/// symlink planted there and overwriting whatever it points to rather than
/// the intended backup; `create_new` refuses any directory entry already at
/// that path, symlink included, and falls through to the next
/// counter-suffixed name instead.
fn backup_if_corrupt(path: &Path) {
    let Some(existing) =
        crate::plugin::read_regular_file(path, crate::plugin::SMALL_FILE_MAX_BYTES)
    else {
        return; // absent, unreadable, or not a regular file: nothing to save
    };
    if serde_json::from_str::<RegistryLockState>(&existing).is_ok() {
        return; // parses fine — an ordinary overwrite, nothing at risk
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let stem = path.file_name().unwrap_or_default().to_os_string();
    for attempt in 0..LOCKFILE_BACKUP_MAX_ATTEMPTS {
        let mut backup_name = stem.clone();
        if attempt == 0 {
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
            Ok(()) => return,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return, // best-effort, and no sink here to log it to — see this function's own doc
        }
    }
}

/// Persist `state` to `path`, creating its parent directory if needed
/// (mirrors `crate::plugin::seed::write_templates`'s `create_dir_all` before
/// `write`).
pub fn save_lockfile(path: &Path, state: &RegistryLockState) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    backup_if_corrupt(path);
    let text =
        serde_json::to_string_pretty(state).map_err(|e| std::io::Error::other(e.to_string()))?;
    // Temp file then rename, for the same reason `config.rs` does it: a
    // truncated lockfile reads as "nothing was ever installed from a
    // registry", which quietly turns every installed plugin's update check
    // into a version-only guess.
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    // Created rather than written through: a symlink left on the temp path
    // would otherwise be followed out of this directory (same reasoning as
    // `config::write_atomically` and `main::update_write`).
    let _ = std::fs::remove_file(&tmp);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .and_then(|mut f| std::io::Write::write_all(&mut f, text.as_bytes()))
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

// ── State machine: installed vs. registry ────────────────────────────────

/// One plugin's state relative to the registry, as decided by
/// [`diff_installed`]. Three states, not a richer taxonomy, matching the
/// registry's own "check updates" UI (`docs/PLUGIN-ARCHITECTURE.md`): offer
/// install, nothing to do, or offer an update (annotated with whether that
/// update would be a safe overwrite).
#[derive(Debug, Clone, PartialEq)]
pub enum RegistryPluginState {
    /// Not installed locally at all — the index lists an id with no matching
    /// local file. Offer install.
    New,
    /// Nothing to do: either the installed file provably matches its
    /// recorded origin and the registry hasn't moved (`locally_modified =
    /// false`), or the installed file has provably diverged from its
    /// recorded origin but the registry version is unchanged too — no update
    /// to offer either way, but `locally_modified = true` flags the
    /// divergence for display. `locally_modified` is a *positive* signal
    /// only (comes from a lockfile hash mismatch); its `false` value means
    /// "no evidence of local edits found", not "provably pristine" — see the
    /// no-lockfile-record branch of [`diff_installed`], where the file's
    /// origin is simply unknown and this is the best that can be said.
    UpToDate { locally_modified: bool },
    /// The registry has something different to offer than what's installed.
    ///
    /// **Not always strictly newer.** The no-lockfile-record branch of
    /// [`diff_installed`] does resolve `local_version`/`entry.version`
    /// through [`update_available`] — [`version_cmp`]'s strict-newer check,
    /// not merely noticing the two differ — but the lockfile branch (see the
    /// decision table below, `present` / `lockfile: yes` / `local == origin`
    /// / `index != origin`) does not: it fires on `origin_sha256`
    /// *inequality* alone, so an `index.toml` that reverted to an older
    /// manifest that was on offer at some earlier point reports this state
    /// with `overwrite_safe: true` exactly as a real update would — a
    /// downgrade offered as a safe update. Comparing versions there instead
    /// (`update_available(origin_version, entry.version)`) trades that for a
    /// worse problem: a byte-identical re-release published to correct
    /// something in it, under the *same* version number, would then compare
    /// `Equal` and never be offered at all. Refusing a downgrade is a real
    /// decision, just a separate one, not implied by this type.
    UpdateAvailable {
        /// `true` only when a lockfile record proves the installed file
        /// still matches what was last installed — overwriting it destroys
        /// nothing. `false` means overwriting *may* destroy local edits (or
        /// there's no provenance to know either way); `warning` explains why.
        overwrite_safe: bool,
        /// Human-readable warning to show before an unsafe overwrite; `None`
        /// only when `overwrite_safe` is `true`.
        warning: Option<String>,
    },
}

/// Decide each registry-listed plugin's state relative to what's installed
/// locally. **Returned in the same order as `index.plugins`, one state per
/// entry** — this function does not repeat each entry's `id` in the result,
/// so the caller must zip the two: `index.plugins.iter().zip(diff_installed(...))`.
///
/// `installed` is `(id, current_file_sha256, installed_version)` for every
/// plugin manifest currently on disk (both file's sha256 and the manifest's
/// own declared `version`, computed by the caller — this module never reads
/// the plugins directory itself); a plugin manifest on disk whose id isn't
/// in the index is simply never visited (the index, not the disk, drives
/// iteration — "check updates" only concerns itself with plugins the
/// registry actually knows about).
///
/// **`current_file_sha256` must be [`sha256_hex`] of the manifest file's raw
/// on-disk bytes** ([`std::fs::read`], not [`std::fs::read_to_string`] + a
/// round-trip through [`PluginManifest`]/`toml::to_string`) — the same
/// byte-exactness [`verify_and_prepare`] requires on the write side. Hashing
/// a re-serialized manifest instead would almost never match
/// `origin_sha256` (TOML re-serialization isn't guaranteed byte-identical to
/// the original file), making every installed plugin spuriously look
/// locally-modified/unsafe-to-overwrite.
///
/// Decision table (`lockfile` is this plugin's [`RegistryLockEntry`], when
/// one exists):
///
/// | local file | lockfile | local == origin | index == origin | state |
/// |---|---|---|---|---|
/// | absent | — | — | — | `New` |
/// | present | yes | yes | yes | `UpToDate { locally_modified: false }` |
/// | present | yes | yes | no  | `UpdateAvailable { overwrite_safe: true, .. }` |
/// | present | yes | no  | yes | `UpToDate { locally_modified: true }` |
/// | present | yes | no  | no  | `UpdateAvailable { overwrite_safe: false, .. }` |
/// | present | no  | — | (best-effort `installed_version` vs `index.version`) | `UpdateAvailable{overwrite_safe:false,..}` if newer, else `UpToDate{locally_modified:false}` |
pub fn diff_installed(
    index: &RegistryIndex,
    installed: &[(String, String, String)],
    lockfile: &RegistryLockState,
) -> Vec<RegistryPluginState> {
    // One pass to build a lookup, rather than `diff_one` re-scanning
    // `installed` with `.find()` once per index entry: `installed` already
    // has unique ids by the time it reaches here (`main.rs` builds it from
    // the loaded, de-duplicated plugin set), so collecting it into a map
    // loses nothing and turns what used to be an `entries × installed`
    // linear scan on every "check updates" click into one lookup per entry.
    let by_id: BTreeMap<&str, &(String, String, String)> = installed
        .iter()
        .map(|entry| (entry.0.as_str(), entry))
        .collect();
    index
        .plugins
        .iter()
        .map(|entry| diff_one(entry, &by_id, lockfile))
        .collect()
}

fn diff_one(
    entry: &RegistryEntry,
    installed: &BTreeMap<&str, &(String, String, String)>,
    lockfile: &RegistryLockState,
) -> RegistryPluginState {
    let Some((_, local_sha, local_version)) = installed.get(entry.id.as_str()).copied() else {
        return RegistryPluginState::New;
    };

    match lockfile.get(&entry.id) {
        Some(lock) => {
            let local_matches_origin = local_sha.eq_ignore_ascii_case(&lock.origin_sha256);
            let index_matches_origin = entry.sha256.eq_ignore_ascii_case(&lock.origin_sha256);
            match (local_matches_origin, index_matches_origin) {
                (true, true) => RegistryPluginState::UpToDate {
                    locally_modified: false,
                },
                (true, false) => RegistryPluginState::UpdateAvailable {
                    overwrite_safe: true,
                    warning: None,
                },
                (false, true) => RegistryPluginState::UpToDate {
                    locally_modified: true,
                },
                (false, false) => RegistryPluginState::UpdateAvailable {
                    overwrite_safe: false,
                    warning: Some(
                        "the installed file has local edits (it no longer matches what was \
                         last installed) and the registry has a different version too — \
                         updating will overwrite those edits"
                            .to_string(),
                    ),
                },
            }
        }
        None => {
            if update_available(local_version, &entry.version) {
                RegistryPluginState::UpdateAvailable {
                    overwrite_safe: false,
                    warning: Some(
                        "no install record for this plugin (installed before the registry, or \
                         dropped in by hand) — updating will overwrite the installed file; \
                         whether it has local edits can't be determined"
                            .to_string(),
                    ),
                }
            } else {
                RegistryPluginState::UpToDate {
                    locally_modified: false,
                }
            }
        }
    }
}

// ── Trust disclosure (not a verdict) ─────────────────────────────────────

/// Hosts trusted by default: `api.anthropic.com` (the bundled Claude
/// manifest's own endpoint) and `chatgpt.com` (the bundled Codex manifest's).
/// Callers pass their own trusted set; this is just the sensible default a
/// caller with no opinion can start from.
pub const TRUSTED_HOSTS: &[&str] = &["api.anthropic.com", "chatgpt.com"];

/// What a manifest declares about how it reads credentials and where it
/// sends them — a disclosure for the installer UI to show before writing a
/// manifest to disk, **not** a trust verdict (a hostile manifest can lie
/// about none of this — it's the manifest's own declared shape, same trust
/// boundary as everywhere else in this app; see the module docs).
#[derive(Debug, Clone, PartialEq)]
pub struct TrustDisclosure {
    /// Local files this manifest reads, including its credential stores: any
    /// `[[surface.auth]] path` (the `credentials-file`/`credentials-map`/
    /// `reject-when`/`oauth-refresh` file a step actually reads — not
    /// `token_json_path`, which names a place *inside* that file rather than
    /// a file of its own), `[[http.value]] path`, `[http.version] files`, and
    /// an `oauth-refresh` step's `[surface.auth.client] files`/`bins`/
    /// `id_env`/`secret_env`/`id_pattern`/`secret_pattern` — `bins` entries
    /// are the *program names* `bin_candidates` resolves on `PATH`, labelled
    /// `"<name> (resolved on PATH, or in ~/.local/bin, ~/.cargo/bin, nvm, or
    /// one of this app's other usual CLI install directories)"` rather than
    /// a path, since which file that resolves to isn't known until the
    /// client is actually installed — naming a few of those directories
    /// rather than the vaguer "the usual CLI install directories" this used
    /// to say: they are exactly the *user-writable* ones
    /// `crate::plugin::cli_install_dirs` searches, which is the fact worth a
    /// approving user's attention (anything running as this user can drop a binary
    /// in any of them), not merely that a search happens; `id_env`/
    /// `secret_env` are not a file at
    /// all, labelled `"$NAME (environment variable)"` so a registry manifest
    /// cannot name, say, `AWS_SECRET_ACCESS_KEY` and install unseen just
    /// because nothing here is technically a path; `id_pattern`/
    /// `secret_pattern` are not a place read from at all, labelled
    /// `"id_pattern: <pattern>"`/`"secret_pattern: <pattern>"` — without them
    /// the dialog would show only *where* a `client` table looks, never
    /// *what shape* it pulls out of there. What makes rendering the pattern
    /// *text* safe is `manifest::validate`'s `CLIENT_PATTERN_MAX_TEXT_BYTES`
    /// cap on the pattern's own source (512 bytes) — a **different** bound
    /// from `CLIENT_PATTERN_MAX_MATCH_BYTES`, which limits only what the
    /// pattern can *match* and says nothing about how long the pattern
    /// itself is (thousands of fixed-length alternatives could match a
    /// short string while running to kilobytes of source). Even so, this
    /// truncates each rendered pattern to 120 bytes plus `…` — a dialog line
    /// is meant to be read, not merely not-unbounded. `files`/
    /// `http.version.files` end up in a request
    /// header, so a manifest can turn any readable JSON file on the machine
    /// into something it sends; `client.files`/`bins`/env vars/patterns are
    /// read for a different reason (resolving an OAuth id/secret pair — see
    /// `auth::resolve_client`) but are exactly as much "this manifest reads
    /// a credential from somewhere of its own choosing" as the other two,
    /// and the installer has to be told before, not after, either way.
    ///
    /// Two more sources, added once it was clear the list above still had
    /// gaps a manifest could hide behind: `engine = "log-file"`'s own read
    /// scope — `[logfile] root`/`glob` rendered as one `"<root>/<glob>"`
    /// entry (`root` shown literally, `~` and all, exactly like every other
    /// entry in this list rather than resolved to a real path — this is a
    /// disclosure of what the manifest *says*, not a filesystem walk of its
    /// own; when `root_env` is set, `<root>` is `"$<root_env>"` instead,
    /// optionally joined with `root_env_join`, since that is what the engine
    /// actually reads whenever the named variable is set — which for a
    /// provider's own CLI it almost always is), so a manifest whose whole
    /// shape is `root = "~"`, `glob = "**/*.json"` cannot walk the entire
    /// home directory without the dialog naming exactly that; and `[account]
    /// path` (the `jwt-file` account lookup's own token file), missing
    /// before for the same reason a credential-file auth step's `path` once
    /// was. An `electron-safe-storage` step's `config_path` lands here too —
    /// see [`credential_sources`](TrustDisclosure::credential_sources)'s own
    /// doc for why it is named twice, once here as a file and once there as
    /// a credential source.
    pub local_files: Vec<String>,
    /// Every `[[surface.auth]]` step whose credential does not already show
    /// up as a path in `local_files` — `credentials-file`/`credentials-map`
    /// (and `oauth-refresh`, whose own `path` is the file it reads a refresh
    /// token out of) all read a named file, already disclosed there; this
    /// field exists for the kinds that read a credential from somewhere
    /// `local_files` has no room to name because it names files, not places:
    /// * `env` — `"env $<VAR>"`, the variable name itself, not merely the
    ///   word "env" — a registry manifest naming, say,
    ///   `AWS_SECRET_ACCESS_KEY` has to say so plainly, not hide behind
    ///   `auth_types` listing a step *kind* nobody reads twice.
    /// * `keychain` — `"keychain \"<service>\""`, the OS keychain service
    ///   queried.
    /// * `win-credential` — `"credential manager \"<target>\""`, one entry
    ///   per target tried, in the order the manifest lists them.
    ///
    /// `electron-safe-storage` gets both a `local_files` entry (its
    /// `config_path`, the file actually opened) and one here (`"electron
    /// safe storage <config_path> (key \"<macos_keychain_key>\")"`, the
    /// macOS keychain entry that unlocks it, omitted on the platforms/steps
    /// that leave it unset) — it is the one step that reads from a file and
    /// a second store at once, and neither list alone says both.
    ///
    /// Deliberately not populated for `reject-when` (reads nothing but a
    /// field that decides whether the chain stops) or `oauth-refresh` (its
    /// `path`/`token_url`/`client.*` are each already disclosed by name
    /// elsewhere in this struct — adding a fourth label for the same step
    /// would repeat, not add, information). Same first-seen order/dedup
    /// idiom as every other list here. See `requires_approval`'s own doc for
    /// why this list gates on its own, unlike `auth_types`.
    pub credential_sources: Vec<String>,
    /// The command this manifest runs after a window resets (`[ping]`), if it
    /// declares one — with a trailing " — also run when its token has
    /// expired or is no longer accepted" when `renews_token` is set, since
    /// that is a second trigger for the same command, not a fact this
    /// disclosure can leave to the schema alone. "Expired or is no longer
    /// accepted" names both halves of that trigger — a lapsed auth chain and
    /// an HTTP 401 — rather than only the first, which alone would
    /// understate it. It is the only field in a manifest that executes
    /// anything, so it is the last one that should be invisible here.
    pub ping: Option<String>,
    pub engine: EngineKind,
    /// Every distinct [`AuthType`] used by any `[[surface.auth]]` step
    /// across every surface, in first-seen order.
    pub auth_types: Vec<AuthType>,
    /// Every distinct host a request could reach: `[[http.request]].url`
    /// hosts, `[account].url`'s host (when `type = "http"`), and every
    /// `oauth-refresh` auth step's `token_url` host — a refresh step sends a
    /// refresh token there on its own, ahead of the engine's own request, so
    /// leaving it out would have this disclosure list say nothing about the
    /// one destination that receives a credential rather than merely a
    /// bearer token. In first-seen order, case-insensitively de-duplicated.
    pub dest_hosts: Vec<String>,
    /// The subset of `dest_hosts` that is **not** in the `trusted_hosts` set
    /// [`analyze_trust`] was called with, same order/case-insensitive
    /// dedup as `dest_hosts` — a UI can use this to highlight which
    /// destinations are unfamiliar without having to re-derive the trusted
    /// set itself. Purely informational: unlike the pre-widening rule, this
    /// list no longer feeds into `requires_approval` (see that field's doc).
    pub untrusted_hosts: Vec<String>,
    /// `true` when this manifest combines a credential-*store*-backed auth
    /// step (`credentials-file`/`keychain`/`electron-safe-storage`/
    /// `win-credential` — i.e. reads a secret out of some OS/app-managed
    /// store, as opposed to a plain `env` var the user set themselves) with
    /// `engine = "http-api"` — the combination `docs/PLUGIN-ARCHITECTURE.md`'s
    /// Trust model section flags as the actual exfiltration risk. Widened
    /// (2026-07): this used to also require a destination host outside
    /// `trusted_hosts`, but every path that calls [`analyze_trust`] is the
    /// *install* flow, where the manifest is by definition a third party —
    /// bundled codex/claude are seeded straight onto disk and never go
    /// through this gate — so gating on host as well as store-backed auth
    /// just gave a false sense of safety for a manifest that happens to
    /// (today) point at a trusted host but could point anywhere after an
    /// update. `dest_hosts`/`untrusted_hosts` are still disclosed so the UI
    /// can call out unfamiliar destinations, they just no longer decide
    /// whether approval is *required*.
    ///
    /// Also `true` whenever `local_files` or `credential_sources` is
    /// non-empty, whatever the engine: a manifest that names a local file of
    /// its own choosing, or an `env`/`keychain`/`win-credential`/
    /// `electron-safe-storage` credential source, needs a look regardless of
    /// whether it happens to be paired with `http-api` — a `log-file`
    /// manifest whose one auth step reads `AWS_SECRET_ACCESS_KEY` is exactly
    /// as worth stopping for as an `http-api` one that reads it and mails it
    /// somewhere, since nothing stops a later update from adding the mailing
    /// half once this one has already installed unseen. This is *not* the
    /// same test as `store_backed` above: `store_backed` only ever asks
    /// "does this combine a credential store with `http-api`", and `env`
    /// deliberately answers no to that one regardless — see its own match
    /// arm's comment — while still reaching a dialog through this clause the
    /// moment it names a variable.
    pub requires_approval: bool,
}

/// Push `url`'s host onto `dest_hosts` if it has one and isn't already
/// present (case-insensitive) — the de-duplication helper behind
/// [`analyze_trust`]'s `dest_hosts` list. The host is read by
/// [`https_host`]; `validate` already requires `url` to be `https`, so a
/// `None` here only means the URL slipped past validation somehow, and this
/// disclosure list simply says nothing about it rather than guess.
fn push_dest_host(url: &str, dest_hosts: &mut Vec<String>) {
    if let Some(h) = https_host(url) {
        if !dest_hosts
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&h))
        {
            dest_hosts.push(h);
        }
    }
}

/// [`push_dest_host`], but first substituting every `{option.<key>}` in
/// `url` at `option_defaults` — the plugin's own declared defaults, since
/// this disclosure runs before any config for the plugin exists to override
/// them (see [`analyze_trust`]'s own `option_defaults` for why the manifest
/// default is the only value there is). Without this, a request URL reading
/// `https://{option.beta}.evil.example/` would disclose the placeholder text
/// itself rather than the host it actually resolves to — `option.beta` reads
/// as a variable name, not a destination the person approving the install would stop at.
///
/// `{`/`}` are not forbidden host code points under the WHATWG URL standard
/// (the same parser `ureq` builds a request through) — they read as
/// ordinary host characters, same as any letter. So an unresolved
/// placeholder (one naming an option this manifest never declared) still
/// parses and still reaches `dest_hosts` verbatim through the ordinary path
/// below; nothing here needs to special-case it. The one shape that *can*
/// defeat the ordinary parse is
/// a placeholder sitting somewhere stricter than a hostname label, most
/// concretely a port (`https://host:{option.x}/`, `InvalidPort` however
/// `option.x` resolves) — `validate` only requires `[[http.request]] url`
/// and `[account] url` to be `https`-parseable when `[http]` is present at
/// all, so a `log-file` manifest's `[account] url` can carry exactly that
/// shape and still load. [`https_host`] returning `None` there would
/// otherwise make the destination vanish from this disclosure rather than
/// merely go unresolved — the fallback below catches that by reading the
/// authority text itself rather than trusting a real parser to make sense
/// of it; the trigger is [`https_host`] returning `None` at all, which it
/// also does for a `substituted` URL that parses cleanly but isn't `https`,
/// not only for one that fails to parse.
fn push_dest_host_for_disclosure(
    url: &str,
    option_defaults: &BTreeMap<String, bool>,
    dest_hosts: &mut Vec<String>,
) {
    let substituted = crate::plugin::substitute_options(url, option_defaults);
    if https_host(&substituted).is_some() {
        push_dest_host(&substituted, dest_hosts);
        return;
    }
    // Triggered by `https_host` returning `None` at all — an unparseable
    // URL or one that parsed but isn't `https` — full stop, not by whether
    // `{` is still visible in the authority. A declared option resolves to
    // the literal text `true`/`false` above, same as an undeclared one
    // resolves to nothing: either way the substituted URL can still fail to
    // parse (`https://host:true/` is exactly as much an `InvalidPort` as
    // `https://host:{option.x}/` was), and `contains('{')` only ever caught
    // the second case — silently dropping the destination from the dialog
    // whenever the manifest *did* declare the option.
    if let Some(authority) = raw_authority(&substituted) {
        if !dest_hosts
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(authority))
        {
            dest_hosts.push(authority.to_string());
        }
    }
}

/// `url`'s authority, read by eye rather than through a real URL parser:
/// everything after the first `//` up to the next `/`, `?` or `#` (or the
/// end of the string). Used only as
/// [`push_dest_host_for_disclosure`]'s fallback for a `url` [`https_host`]
/// can't make sense of at all — good enough to show *something* rather than
/// let a destination go missing from the dialog, never a stand-in for the
/// real parse anywhere a request is actually sent.
fn raw_authority(url: &str) -> Option<&str> {
    let after_scheme = url.split_once("//")?.1;
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..end];
    if authority.is_empty() {
        None
    } else {
        Some(authority)
    }
}

/// The most bytes of a `client.id_pattern`/`secret_pattern` [`analyze_trust`]
/// renders before cutting it short with `…` — smaller than
/// `manifest::CLIENT_PATTERN_MAX_TEXT_BYTES` (512, the *load-time* cap on
/// the pattern's own text) on purpose: a dialog line is meant to be read at
/// a glance, not merely bounded enough not to be a denial-of-service.
const PATTERN_DISPLAY_MAX_BYTES: usize = 120;

/// `s`, cut to at most [`PATTERN_DISPLAY_MAX_BYTES`] and marked with `…` if
/// it was — backed off to the nearest char boundary at or before the cap, so
/// a multi-byte character straddling the cut point is never split into
/// invalid UTF-8.
fn truncate_for_display(s: &str) -> String {
    if s.len() <= PATTERN_DISPLAY_MAX_BYTES {
        return s.to_string();
    }
    let mut cut = PATTERN_DISPLAY_MAX_BYTES;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &s[..cut])
}

/// The read scope `engine = "log-file"` declares, rendered as one
/// [`TrustDisclosure::local_files`] entry, `"<root>/<glob>"` — see that
/// field's own doc for the rationale. `<root>` is `lf.root` shown literally
/// (`~` included, unexpanded, exactly like every other entry in that list)
/// unless `root_env` is set, in which case it is `"$<root_env>"` instead —
/// joined with `root_env_join` when the manifest sets one — since that is
/// what [`crate::plugin::engine_logfile`]'s own `resolve_root` actually
/// reads whenever the named variable is set.
fn logfile_scope(lf: &LogFileConfig) -> String {
    let root = match &lf.root_env {
        Some(env_name) => match &lf.root_env_join {
            Some(join) => format!("${env_name}/{join}"),
            None => format!("${env_name}"),
        },
        None => lf.root.clone(),
    };
    format!("{root}/{}", lf.glob)
}

/// [`TrustDisclosure::credential_sources`] entries for one `[[surface.auth]]`
/// step — see that field's own doc for the full rationale, including why
/// `credentials-file`/`credentials-map`/`reject-when`/`oauth-refresh` return
/// nothing here (already disclosed, by path, in `local_files`). Every other
/// field this reads (`var`/`service`/`targets`/`config_path`) is required by
/// `manifest::validate` for the matching `kind`, but each is still read
/// through an `if let`/`for` rather than assumed present — a step whose
/// `kind` this match doesn't recognise as needing one falls through to no
/// entries rather than a field access that could panic on a manifest shape
/// this function hasn't been taught yet.
fn credential_source_labels(step: &AuthStep) -> Vec<String> {
    let mut labels = Vec::new();
    match step.kind {
        AuthType::Env => {
            if let Some(var) = &step.var {
                labels.push(format!("env ${var}"));
            }
        }
        AuthType::Keychain => {
            if let Some(service) = &step.service {
                labels.push(format!("keychain \"{service}\""));
            }
        }
        AuthType::WinCredential => {
            for target in step.targets.iter().flatten() {
                labels.push(format!("credential manager \"{target}\""));
            }
        }
        AuthType::ElectronSafeStorage => {
            if let Some(path) = &step.config_path {
                labels.push(match &step.macos_keychain_key {
                    Some(key) => format!("electron safe storage {path} (key \"{key}\")"),
                    None => format!("electron safe storage {path}"),
                });
            }
        }
        AuthType::CredentialsFile
        | AuthType::CredentialsMap
        | AuthType::RejectWhen
        | AuthType::OauthRefresh => {}
    }
    labels
}

/// Build a [`TrustDisclosure`] for `m` against `trusted_hosts` (pass
/// [`TRUSTED_HOSTS`] for the built-in default).
pub fn analyze_trust(m: &PluginManifest, trusted_hosts: &[&str]) -> TrustDisclosure {
    let mut auth_types: Vec<AuthType> = Vec::new();
    for surface in &m.surface {
        for step in &surface.auth {
            if !auth_types.contains(&step.kind) {
                auth_types.push(step.kind);
            }
        }
    }

    // A manifest's own declared `[[option]]` defaults — the value each
    // `{option.<key>}` placeholder resolves to until a user (or, here, an
    // install that hasn't happened yet) overrides it. This disclosure runs
    // before any config for the plugin exists, so the manifest's own default
    // is the only value there is to substitute; see
    // `push_dest_host_for_disclosure`'s doc for why substituting at all
    // matters for a host.
    let option_defaults: BTreeMap<String, bool> = m
        .option
        .iter()
        .map(|o| (o.key.clone(), o.default))
        .collect();

    let mut dest_hosts: Vec<String> = Vec::new();
    if let Some(http) = &m.http {
        for req in &http.request {
            push_dest_host_for_disclosure(&req.url, &option_defaults, &mut dest_hosts);
        }
    }
    if let Some(url) = &m.account.url {
        push_dest_host_for_disclosure(url, &option_defaults, &mut dest_hosts);
    }
    for surface in &m.surface {
        for step in &surface.auth {
            // `oauth-refresh` sends a refresh token here on its own, ahead
            // of the engine's own request — as much a "this manifest reaches
            // this host" fact as `[[http.request]].url`, and the one that
            // moves an actual credential rather than a bearer token.
            if let Some(token_url) = &step.token_url {
                push_dest_host_for_disclosure(token_url, &option_defaults, &mut dest_hosts);
            }
        }
    }

    let mut local_files: Vec<String> = Vec::new();
    // Scoped read of the whole filesystem under `root`, not a single named
    // file — the reason it goes first: it's the shape most worth naming
    // plainly, ahead of any narrower path below.
    if let Some(lf) = &m.logfile {
        let scope = logfile_scope(lf);
        if !local_files.contains(&scope) {
            local_files.push(scope);
        }
    }
    // `jwt-file`'s own token file — the same gap a credential-file auth
    // step's own `path` once was: nothing else here would have named it.
    if let Some(path) = &m.account.path {
        if !local_files.contains(path) {
            local_files.push(path.clone());
        }
    }
    if let Some(http) = &m.http {
        for v in &http.value {
            if let Some(path) = &v.path {
                if !local_files.contains(path) {
                    local_files.push(path.clone());
                }
            }
        }
        if let Some(version) = &http.version {
            for file in &version.files {
                if !local_files.contains(file) {
                    local_files.push(file.clone());
                }
            }
        }
    }
    let mut credential_sources: Vec<String> = Vec::new();
    for surface in &m.surface {
        for step in &surface.auth {
            // The credential file a step actually reads
            // (`credentials-file`/`credentials-map`/`reject-when`/
            // `oauth-refresh`) — not `token_json_path`, a place *inside* it,
            // not a file of its own. Every other store-backed type
            // (`keychain`, `electron-safe-storage`, `win-credential`) names
            // its own place a different way and has no `path` to carry.
            if let Some(path) = &step.path {
                if !local_files.contains(path) {
                    local_files.push(path.clone());
                }
            }
            for label in credential_source_labels(step) {
                if !credential_sources.contains(&label) {
                    credential_sources.push(label);
                }
            }
            // `electron-safe-storage`'s own config file: named above as a
            // credential source, and read here into `local_files` too —
            // it's the one step that reads from both a file and a second
            // store at once, and neither list alone says both (see
            // `TrustDisclosure::local_files`'s own doc).
            if step.kind == AuthType::ElectronSafeStorage {
                if let Some(path) = &step.config_path {
                    if !local_files.contains(path) {
                        local_files.push(path.clone());
                    }
                }
            }
            let Some(client) = &step.client else { continue };
            for file in &client.files {
                if !local_files.contains(file) {
                    local_files.push(file.clone());
                }
            }
            for name in &client.bins {
                let label = format!(
                    "{name} (resolved on PATH, or in ~/.local/bin, ~/.cargo/bin, nvm, or one \
                     of this app's other usual CLI install directories)"
                );
                if !local_files.contains(&label) {
                    local_files.push(label);
                }
            }
            // Not a file read, but the same "this manifest can turn into a
            // credential from somewhere the installer hasn't seen" shape:
            // `id_env`/`secret_env` name environment variables this step
            // reads outright, ahead of ever touching `files`/`bins`. Folded
            // into `local_files` rather than a list of its own — the field
            // this struct exposes is a flat disclosure of "things read off
            // this machine", and a `$NAME` reads unambiguously as not a path.
            for env_name in [&client.id_env, &client.secret_env].into_iter().flatten() {
                let label = format!("${env_name} (environment variable)");
                if !local_files.contains(&label) {
                    local_files.push(label);
                }
            }
            // Not a place read from either, but the shape a `files`/`bins`
            // candidate is searched for — without it the dialog would show
            // only *where* this step looks, never *what* it pulls out of
            // there. `manifest::validate` bounds the pattern's own text to
            // `CLIENT_PATTERN_MAX_TEXT_BYTES` (512) — a load-time ceiling,
            // not a rendering one; `truncate_for_display` is the rendering
            // one, shorter still, so a dialog line stays a dialog line.
            for (kind, pattern) in [
                ("id_pattern", &client.id_pattern),
                ("secret_pattern", &client.secret_pattern),
            ] {
                let Some(pattern) = pattern else { continue };
                let label = format!("{kind}: {}", truncate_for_display(pattern));
                if !local_files.contains(&label) {
                    local_files.push(label);
                }
            }
        }
    }

    let ping = m.ping.as_ref().map(|p| {
        let mut line = if p.args.is_empty() {
            p.bin.clone()
        } else {
            format!("{} {}", p.bin, p.args.join(" "))
        };
        // `renews_token`'s second trigger is worth disclosing beside the
        // command line itself: it is the one thing that makes this ping run
        // outside the schedule the rest of this dialog already describes.
        // Names both halves of that trigger — a lapsed auth chain and an
        // HTTP 401 the token still managed to reach the network with — since
        // "expired" alone would understate what can set this ping off.
        if p.renews_token {
            line.push_str(" — also run when its token has expired or is no longer accepted");
        }
        line
    });

    let untrusted_hosts: Vec<String> = dest_hosts
        .iter()
        .filter(|h| {
            !trusted_hosts
                .iter()
                .any(|trusted| trusted.eq_ignore_ascii_case(h))
        })
        .cloned()
        .collect();

    // An exhaustive match rather than `matches!`'s implicit wildcard: adding
    // a variant to `AuthType` without a decision here would otherwise
    // silently fall through to "not store-backed" — the wrong default for a
    // check that exists to be conservative — and the compiler catches it
    // instead of a manifest doing it live.
    let store_backed = auth_types.iter().any(|t| match t {
        AuthType::CredentialsFile
        | AuthType::Keychain
        | AuthType::ElectronSafeStorage
        | AuthType::WinCredential => true,
        // Added with the step itself, and nearly not: a `credentials-map`
        // step reads somebody's credential file exactly like
        // `credentials-file` does — it only picks the record out of a map
        // rather than out of a single object — so a manifest whose one
        // auth step is this used to install with no dialog at all,
        // because nothing else here would have flagged it. The rule this
        // list encodes is "does the manifest read a credential", not
        // "which spelling of reading one", and every future variant has
        // to be added here in the change that adds it.
        AuthType::CredentialsMap => true,
        // `oauth-refresh` does more than read a credential — it *sends*
        // one (a refresh token) to the network. If anything here needs
        // the trust dialog, it does; leaving it out would let a manifest
        // whose only step is this install with no dialog, reading a local
        // file and mailing a refresh token to a host. Added with the step
        // in the same change, exactly as `credentials-map` was.
        AuthType::OauthRefresh => true,
        // Not a credential *store* — `env` reads a variable the user set
        // themselves, not one this manifest goes digging for, and
        // `reject-when` reads nothing but a field that decides whether the
        // chain stops. Neither makes this predicate true, which only ever
        // feeds the http-api-plus-credential-store combination below; `env`
        // still gates `requires_approval` on its own once it names a
        // variable — through `credential_sources`, not through here — see
        // that field's own doc for why the two are no longer the same
        // question.
        AuthType::Env | AuthType::RejectWhen => false,
    });
    // Widened (2026-07): no longer conditioned on `dest_hosts` reaching
    // outside `trusted_hosts` — see `requires_approval`'s doc comment.
    //
    // Widened again: reading a credential is not the only thing worth
    // stopping for. A manifest that names a command to run needs approval
    // whatever its engine — that command is arbitrary, and the toggle that
    // later fires it cannot describe itself. So does one that reads local
    // files of its own choosing into a request header: that is the same
    // "somebody's file leaves this machine" shape as a credential, minus the
    // word credential.
    //
    // Widened again (complete trust disclosure): `credential_sources` gates
    // on its own, whatever the engine — a `log-file` manifest naming an
    // `env` credential step is exactly the shape this closes, and it is not
    // an `http-api` manifest for `store_backed` to have ever flagged.
    let requires_approval = (store_backed && m.engine == EngineKind::HttpApi)
        || ping.is_some()
        || !local_files.is_empty()
        || !credential_sources.is_empty();

    TrustDisclosure {
        engine: m.engine,
        auth_types,
        dest_hosts,
        untrusted_hosts,
        local_files,
        credential_sources,
        ping,
        requires_approval,
    }
}

// ── Network (the only part that isn't unit-tested) ───────────────────────

/// Whether `url` uses `https://` — split out of [`fetch_text`]/[`fetch_bytes`]
/// so the gate itself is testable without ever calling either networked
/// function. Delegates to [`https_host`] (already the one parser this module
/// trusts for "does this URL use `https`", used a few lines down in
/// [`resolve_manifest_url`]) rather than a bespoke prefix check: a bespoke
/// `starts_with("https://")` is case-sensitive where a real URL parser's
/// scheme is not, so an `HTTPS://…` URL used to read as non-https here and
/// get refused for a reason that had nothing to do with the transport being
/// insecure.
fn is_https(url: &str) -> bool {
    https_host(url).is_some()
}

/// GET `url` and return the raw response body as text. HTTPS-only (a
/// plain-`http://` URL is refused before any connection is attempted — the
/// registry's whole trust story rests on verified integrity *and* a
/// non-tampered transport). Built like `crate::plugin::engine_http::perform`:
/// `redirects(0)` (so a compromised/misconfigured CDN can't silently hand
/// back content from a different host — the caller's own URL is all that was
/// ever vetted) and an ~8s timeout.
///
/// Used only for the index's `.minisig` signature file — a short block of
/// base64 that `signature::verify_index` parses once and never hashes or
/// compares byte-for-byte, so `into_string`'s UTF-8 decode costs nothing.
/// `index.toml` itself, and a manifest file, both go through [`fetch_bytes`]
/// instead — see that function's own docs for why.
///
/// Capped at [`MAX_MINISIG_BYTES`], read through `into_reader()` rather than
/// `into_string()`'s own unbounded-by-comparison 10 MiB `INTO_STRING_LIMIT`:
/// a minisig block is a handful of lines of base64, nowhere near either
/// ceiling, so there is no reason for this function's one caller to ever
/// buffer megabytes of "signature" from a hostile or misbehaving server
/// before `signature::verify_index` gets a chance to reject it — the same
/// reasoning [`fetch_bytes`]'s own cap already gives, sized to what this
/// function is actually ever asked to fetch instead. Not exercised by any
/// test in this module — see the module docs.
pub fn fetch_text(url: &str) -> Result<String, String> {
    if !is_https(url) {
        return Err(format!("refusing non-https URL: {url}"));
    }
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let req = agent.get(url).timeout(Duration::from_secs(8));
    match req.call() {
        Ok(r) if (300..400).contains(&r.status()) => {
            Err(format!("HTTP {} (redirect blocked)", r.status()))
        }
        Ok(r) => {
            let mut buf = Vec::new();
            r.into_reader()
                .take(MAX_MINISIG_BYTES + 1)
                .read_to_end(&mut buf)
                .map_err(|e| format!("bad response: {e}"))?;
            if buf.len() as u64 > MAX_MINISIG_BYTES {
                return Err("response too big for fetch_text".to_string());
            }
            String::from_utf8(buf).map_err(|e| format!("bad response: {e}"))
        }
        Err(ureq::Error::Status(code, _)) => Err(format!("HTTP {code}")),
        Err(e) => Err(format!("network error: {e}")),
    }
}

/// [`fetch_text`]'s response-size cap — see its own doc comment for why 8
/// KiB, generous for a minisig block, is the right order of magnitude rather
/// than borrowing [`fetch_bytes`]'s much larger one.
const MAX_MINISIG_BYTES: u64 = 8 * 1024;

/// GET `url` and return the raw response body as bytes, **undecoded** —
/// unlike [`fetch_text`]'s `into_string`, which UTF-8-decodes the body first.
/// Used for anything a later step verifies against the exact bytes the
/// server sent: `index.toml` itself (`signature::verify_index` checks its
/// ed25519 signature over these bytes, not over a UTF-8 round-trip of them)
/// and a manifest file ([`verify_and_prepare`]'s sha256 check is equally only
/// meaningful against the exact bytes). Either one that isn't UTF-8-clean, or
/// that round-trips through decode/re-encode with different line endings or
/// a BOM, would then verify against something other than what was actually
/// published — a false mismatch, or worse, a false match against bytes that
/// were never actually served. Same HTTPS-only gate, `redirects(0)` and ~8s
/// timeout as [`fetch_text`] — see its own docs for the rationale, which
/// applies here unchanged; the response-size cap below has no counterpart
/// documented on `fetch_text`'s side, because it doesn't need one written
/// out: `into_string()` applies ureq's own 10MB `INTO_STRING_LIMIT`
/// internally before ever returning, silently, whereas `into_reader()`
/// enforces nothing at all — so this function re-imposes the same ceiling by
/// hand. Without it, a hostile or misbehaving registry could make this
/// function buffer an unbounded response into memory, and it would do so
/// *before* whichever check downstream (a signature, a sha256) ever gets a
/// chance to reject it.
///
/// Not exercised by any test in this module — see the module docs.
pub fn fetch_bytes(url: &str) -> Result<Vec<u8>, String> {
    if !is_https(url) {
        return Err(format!("refusing non-https URL: {url}"));
    }
    // Mirrors ureq's own private `Response::INTO_STRING_LIMIT` — see this
    // function's own doc comment for why `into_reader()` needs the same cap
    // re-imposed by hand.
    const MAX_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let req = agent.get(url).timeout(Duration::from_secs(8));
    match req.call() {
        Ok(r) if (300..400).contains(&r.status()) => {
            Err(format!("HTTP {} (redirect blocked)", r.status()))
        }
        Ok(r) => {
            let mut buf = Vec::new();
            r.into_reader()
                .take(MAX_RESPONSE_BYTES + 1)
                .read_to_end(&mut buf)
                .map_err(|e| format!("bad response: {e}"))?;
            if buf.len() as u64 > MAX_RESPONSE_BYTES {
                return Err("response too big for fetch_bytes".to_string());
            }
            Ok(buf)
        }
        Err(ureq::Error::Status(code, _)) => Err(format!("HTTP {code}")),
        Err(e) => Err(format!("network error: {e}")),
    }
}

// ── Tests (hermetic: no network — fetch_text/fetch_bytes never called) ───

#[cfg(test)]
mod tests {
    use super::*;

    // ── RegistryIndex::from_str ──────────────────────────────────────────

    const VALID_INDEX: &str = r#"
        schema_version = 1

        [[plugin]]
        id          = "some-provider"
        name        = "Some Provider"
        version     = "1.0.0"
        description = "Some Provider usage indicator"
        manifest    = "manifests/some-provider.toml"
        sha256      = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        [[plugin]]
        id       = "another"
        name     = "Another"
        version  = "2.3.4"
        manifest = "manifests/another.toml"
        sha256   = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    "#;

    #[test]
    fn parses_a_valid_index() {
        let idx = RegistryIndex::from_str(VALID_INDEX).expect("valid index");
        assert_eq!(idx.schema_version, 1);
        assert_eq!(idx.plugins.len(), 2);
        let first = &idx.plugins[0];
        assert_eq!(first.id, "some-provider");
        assert_eq!(first.name, "Some Provider");
        assert_eq!(first.version, "1.0.0");
        assert_eq!(
            first.description.as_deref(),
            Some("Some Provider usage indicator")
        );
        assert_eq!(first.manifest, "manifests/some-provider.toml");
        assert_eq!(first.sha256.len(), 64);
        assert!(
            idx.plugins[1].description.is_none(),
            "description is optional"
        );
    }

    #[test]
    fn schema_version_defaults_to_1_when_omitted() {
        let idx = RegistryIndex::from_str(
            r#"
            [[plugin]]
            id       = "x"
            name     = "X"
            version  = "1.0.0"
            manifest = "manifests/x.toml"
            sha256   = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        "#,
        )
        .expect("valid index");
        assert_eq!(idx.schema_version, 1);
    }

    #[test]
    fn empty_index_with_no_plugins_is_valid() {
        let idx = RegistryIndex::from_str("schema_version = 1").expect("valid empty index");
        assert!(idx.plugins.is_empty());
    }

    #[test]
    fn unknown_fields_are_ignored_not_rejected() {
        let idx = RegistryIndex::from_str(
            r#"
            schema_version = 1
            future_top_level_field = "ignored"

            [[plugin]]
            id                 = "x"
            name               = "X"
            version            = "1.0.0"
            manifest           = "manifests/x.toml"
            sha256             = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            future_entry_field = 123
        "#,
        )
        .expect("unknown fields must not break parsing");
        assert_eq!(idx.plugins[0].id, "x");
    }

    #[test]
    fn rejects_malformed_toml() {
        assert!(RegistryIndex::from_str("this is not [valid toml").is_err());
    }

    fn entry_with(field: &str, value: &str) -> String {
        let mut base = std::collections::BTreeMap::from([
            ("id", "x".to_string()),
            ("name", "X".to_string()),
            ("version", "1.0.0".to_string()),
            ("manifest", "manifests/x.toml".to_string()),
            (
                "sha256",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            ),
        ]);
        base.insert(field, value.to_string());
        let body: String = base
            .iter()
            .map(|(k, v)| format!("{k} = \"{v}\"\n"))
            .collect();
        format!("[[plugin]]\n{body}")
    }

    #[test]
    fn rejects_sha256_wrong_length() {
        let idx = entry_with("sha256", "abc123");
        let err = RegistryIndex::from_str(&idx).expect_err("short sha256 must be rejected");
        assert!(err.contains("sha256"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_sha256_non_hex() {
        let idx = entry_with(
            "sha256",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        );
        assert!(RegistryIndex::from_str(&idx).is_err());
    }

    #[test]
    fn rejects_sha256_uppercase() {
        let idx = entry_with(
            "sha256",
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        );
        let err = RegistryIndex::from_str(&idx).expect_err("uppercase sha256 must be rejected");
        assert!(err.contains("sha256"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_manifest_path_with_a_url_scheme() {
        let idx = entry_with("manifest", "https://evil.example.com/x.toml");
        let err =
            RegistryIndex::from_str(&idx).expect_err("scheme in manifest path must be rejected");
        assert!(err.contains("manifest"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_manifest_path_with_a_leading_slash() {
        let idx = entry_with("manifest", "/etc/passwd");
        assert!(RegistryIndex::from_str(&idx).is_err());
    }

    #[test]
    fn rejects_manifest_path_with_a_dotdot_component() {
        let idx = entry_with("manifest", "../../etc/passwd");
        assert!(RegistryIndex::from_str(&idx).is_err());
        let idx2 = entry_with("manifest", "manifests/../../secret.toml");
        assert!(RegistryIndex::from_str(&idx2).is_err());
    }

    #[test]
    fn rejects_a_percent_encoded_dotdot_component() {
        // The server on the other end of the resolved URL decodes `%2e%2e`
        // to `..` before it ever looks at the path; a check written against
        // the literal bytes alone would not.
        let idx = entry_with("manifest", "manifests/%2e%2e/%2e%2e/secret.toml");
        let err =
            RegistryIndex::from_str(&idx).expect_err("percent-encoded traversal must be rejected");
        assert!(err.contains(".."), "unexpected error: {err}");

        let idx_upper = entry_with("manifest", "manifests/%2E%2E/secret.toml");
        assert!(
            RegistryIndex::from_str(&idx_upper).is_err(),
            "the hex digits are matched case-insensitively"
        );
    }

    #[test]
    fn percent_decode_lossy_decodes_valid_escapes_and_leaves_the_rest_alone() {
        assert_eq!(percent_decode_lossy("%2e%2e"), "..");
        assert_eq!(percent_decode_lossy("%2E%2E"), "..");
        assert_eq!(percent_decode_lossy("plain/path"), "plain/path");
        // A trailing/malformed escape is left as literal bytes rather than
        // panicking or being dropped.
        assert_eq!(percent_decode_lossy("100%"), "100%");
        assert_eq!(percent_decode_lossy("100%2"), "100%2");
        assert_eq!(percent_decode_lossy("100%zz"), "100%zz");
    }

    #[test]
    fn rejects_empty_version() {
        let idx = entry_with("version", "");
        let err = RegistryIndex::from_str(&idx).expect_err("empty version must be rejected");
        assert!(err.contains("version"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_duplicate_ids() {
        let idx = format!("{VALID_INDEX}\n[[plugin]]\nid = \"some-provider\"\nname = \"Dup\"\nversion = \"1.0.0\"\nmanifest = \"manifests/dup.toml\"\nsha256 = \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"\n");
        let err = RegistryIndex::from_str(&idx).expect_err("duplicate id must be rejected");
        assert!(err.contains("duplicate"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_bad_id_charset() {
        let idx = entry_with("id", "../evil");
        assert!(RegistryIndex::from_str(&idx).is_err());
    }

    /// `char::is_control` alone (Unicode `Cc`) misses a bidi override or a
    /// zero-width character — `refuse_control_chars`'s own doc says it
    /// covers the same class `sanitize_provider_text` does, and this pins
    /// that it now actually does, not only C0/C1 controls.
    #[test]
    fn rejects_a_zero_width_character_in_a_name() {
        let idx = entry_with("name", "Some\u{200B}Provider");
        let err = RegistryIndex::from_str(&idx)
            .expect_err("a zero-width space in a name must be rejected");
        assert!(
            err.contains("control, invisible or directional characters"),
            "unexpected error: {err}"
        );
    }

    /// Same class, the other end of it: a bidi override.
    #[test]
    fn rejects_a_bidi_override_in_a_description() {
        let idx = entry_with("description", "safe\u{202E}provider");
        let err = RegistryIndex::from_str(&idx)
            .expect_err("a bidi override in a description must be rejected");
        assert!(
            err.contains("control, invisible or directional characters"),
            "unexpected error: {err}"
        );
    }

    // ── resolve_manifest_url ─────────────────────────────────────────────

    #[test]
    fn resolves_manifest_path_against_index_url_with_index_toml_suffix() {
        let url = resolve_manifest_url(
            "https://example.com/registry/index.toml",
            "manifests/some-provider.toml",
        )
        .expect("resolves");
        assert_eq!(
            url,
            "https://example.com/registry/manifests/some-provider.toml"
        );
    }

    #[test]
    fn resolves_manifest_path_against_index_url_without_index_toml_suffix() {
        let url = resolve_manifest_url("https://example.com/registry/", "manifests/x.toml")
            .expect("resolves");
        assert_eq!(url, "https://example.com/registry/manifests/x.toml");
    }

    #[test]
    fn the_index_toml_suffix_strip_is_anchored_to_a_path_separator() {
        // An unanchored `strip_suffix("index.toml")` would chop only the
        // letters "index.toml" off the end of "custom-index.toml", mangling
        // the directory the manifest is joined onto instead of stripping the
        // whole filename.
        let url = resolve_manifest_url(
            "https://example.com/registry/custom-index.toml",
            "manifests/x.toml",
        )
        .expect("resolves");
        assert_eq!(
            url, "https://example.com/registry/custom-index.toml/manifests/x.toml",
            "a filename that merely ends in \"index.toml\" is not the index's own name and \
             must be left in the base path, not chopped"
        );
    }

    #[test]
    fn resolve_manifest_url_rejects_a_traversal_path() {
        assert!(resolve_manifest_url(
            "https://example.com/registry/index.toml",
            "../../etc/passwd"
        )
        .is_err());
    }

    #[test]
    fn resolve_manifest_url_rejects_a_scheme_in_the_relative_path() {
        assert!(resolve_manifest_url(
            "https://example.com/registry/index.toml",
            "https://evil.example.com/x.toml"
        )
        .is_err());
    }

    // ── version_cmp / update_available ───────────────────────────────────

    #[test]
    fn version_cmp_compares_numerically_not_lexicographically() {
        assert_eq!(version_cmp("1.2.0", "1.10.0"), Ordering::Less);
        assert_eq!(version_cmp("1.10.0", "1.2.0"), Ordering::Greater);
    }

    #[test]
    fn version_cmp_equal_versions() {
        assert_eq!(version_cmp("1.2.3", "1.2.3"), Ordering::Equal);
    }

    #[test]
    fn version_cmp_when_neither_side_parses_they_compare_equal_not_by_string() {
        // Renamed from `version_cmp_unparsable_falls_back_to_string_comparison`:
        // that name (and the assertion it made) described exactly the
        // meaningless-bytes problem the doc comment now explains — two
        // non-version-shaped strings that happen to sort one way in ASCII
        // must not read as "newer", the same way an asymmetric pair already
        // never did.
        assert_eq!(
            version_cmp("abc", "abd"),
            Ordering::Equal,
            "neither side is version-shaped, so neither wins"
        );
        assert_eq!(
            version_cmp("", ""),
            Ordering::Equal,
            "the shape a manifest predating the plugin registry ships \
             (`PluginManifest::version` defaults to \"\")"
        );
        assert_eq!(version_cmp("1.2.3-beta", "1.2.3-beta"), Ordering::Equal);
        assert_ne!(
            version_cmp("1.2", "1.2.0"),
            Ordering::Equal,
            "\"1.2\" isn't a plain x.y.z"
        );
    }

    // ── version_cmp: semver prerelease/build semantics ───────────────────

    #[test]
    fn version_cmp_a_release_outranks_its_own_prerelease() {
        assert_eq!(version_cmp("1.0.0-alpha", "1.0.0"), Ordering::Less);
        assert_eq!(version_cmp("1.0.0", "1.0.0-alpha"), Ordering::Greater);
    }

    #[test]
    fn version_cmp_numeric_base_still_wins_over_prerelease_status() {
        assert_eq!(version_cmp("1.0.0", "1.0.1"), Ordering::Less);
        // A prerelease of a newer base still outranks an older release.
        assert_eq!(version_cmp("1.0.1-alpha", "1.0.0"), Ordering::Greater);
    }

    #[test]
    fn version_cmp_prereleases_of_the_same_base_compare_lexically_by_identifier() {
        assert_eq!(version_cmp("1.0.0-alpha", "1.0.0-beta"), Ordering::Less);
        assert_eq!(version_cmp("1.0.0-beta", "1.0.0-alpha"), Ordering::Greater);
    }

    #[test]
    fn version_cmp_prereleases_compare_numeric_identifiers_numerically() {
        // "9" < "10" numerically, unlike a naive lexical compare of the
        // dot-segment strings.
        assert_eq!(
            version_cmp("1.0.0-alpha.9", "1.0.0-alpha.10"),
            Ordering::Less
        );
    }

    #[test]
    fn version_cmp_a_shorter_prerelease_sorts_before_a_longer_one_with_the_same_prefix() {
        assert_eq!(version_cmp("1.0.0-alpha", "1.0.0-alpha.1"), Ordering::Less);
    }

    #[test]
    fn version_cmp_build_metadata_never_affects_precedence() {
        assert_eq!(version_cmp("1.0.0+build", "1.0.0"), Ordering::Equal);
        assert_eq!(version_cmp("1.0.0+build1", "1.0.0+build2"), Ordering::Equal);
        assert_eq!(
            version_cmp("1.0.0-alpha+build", "1.0.0-alpha"),
            Ordering::Equal
        );
    }

    #[test]
    fn update_available_true_when_registry_is_newer() {
        assert!(update_available("1.2.0", "1.10.0"));
    }

    #[test]
    fn update_available_false_when_versions_are_equal() {
        assert!(!update_available("1.2.3", "1.2.3"));
    }

    #[test]
    fn update_available_false_on_downgrade() {
        assert!(!update_available("2.0.0", "1.9.9"));
    }

    #[test]
    fn update_available_is_false_when_neither_version_parses() {
        // Renamed from
        // `update_available_unparsable_versions_compare_as_unequal_strings`,
        // whose own name described exactly the bug: two non-version-shaped
        // strings comparing as "newer"/"older" purely from an ASCII sort
        // that means nothing for either of them. `PluginManifest::version`
        // is free-form and defaults to `""` for a manifest that predates the
        // plugin registry (see that field's own doc) — this is the shape
        // that used to make a registry's own declared version look "newer"
        // than an installed manifest with no version at all, purely from
        // being non-empty, and nag "update available" forever with nothing
        // real behind it.
        assert!(!update_available("aaa", "bbb"));
        assert!(!update_available("bbb", "aaa"));
        assert!(
            !update_available("", "1.2"),
            "neither side is a real version"
        );
    }

    #[test]
    fn a_non_version_shaped_string_never_beats_a_real_version_on_ascii_alone() {
        // The exploit this closes: "beta" > "1.0.0" in plain ASCII order
        // ('b' > '1'), so a registry publishing `version = "beta"` used to
        // read as an update available forever against any properly-versioned
        // installed manifest — a prompt with nothing installable behind it
        // and no version comparison that could ever resolve it.
        assert_eq!(version_cmp("beta", "1.0.0"), Ordering::Less);
        assert_eq!(version_cmp("1.0.0", "beta"), Ordering::Greater);
        assert!(
            !update_available("1.0.0", "beta"),
            "a registry version that isn't shaped like a version must never look newer"
        );
        // The reverse direction is symmetric, not specially privileged: an
        // installed manifest with a garbage version does get offered a real
        // one, since there is nothing else honest to compare it against.
        assert!(update_available("garbage", "1.0.0"));
    }

    // ── sha256 ────────────────────────────────────────────────────────────

    #[test]
    fn sha256_hex_matches_known_test_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn verify_sha256_matches_case_insensitively() {
        assert!(verify_sha256(
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        ));
        assert!(verify_sha256(
            b"abc",
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        ));
    }

    #[test]
    fn verify_sha256_rejects_a_mismatch() {
        assert!(!verify_sha256(
            b"not abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        ));
    }

    // ── verify_and_prepare ────────────────────────────────────────────────

    const MINIMAL_MANIFEST: &str = r#"
        id         = "x"
        name       = "X"
        menu_label = "X"
        order      = 1
        engine     = "log-file"
        [[windows]]
        label = "5H"
        role  = "primary"
        [windows.period]
        mode = "assumed"
        assumed = 300
        [windows.source]
        used_percent_path = "p"
        resets_at_path = "r"
        [logfile]
        root = "~/.x"
        glob = "*.jsonl"
        container_key = "rate_limits"
    "#;

    #[test]
    fn verify_and_prepare_succeeds_on_matching_hash_and_valid_manifest() {
        let bytes = MINIMAL_MANIFEST.as_bytes();
        let expected = sha256_hex(bytes);
        let (manifest, hash) = verify_and_prepare(bytes, &expected).expect("verifies and parses");
        assert_eq!(manifest.id, "x");
        assert_eq!(hash, expected);
    }

    #[test]
    fn verify_and_prepare_rejects_a_hash_mismatch_before_parsing() {
        let bytes = MINIMAL_MANIFEST.as_bytes();
        let wrong = "0".repeat(64);
        let err = verify_and_prepare(bytes, &wrong).expect_err("hash mismatch must be rejected");
        assert!(err.contains("mismatch"), "unexpected error: {err}");
    }

    #[test]
    fn verify_and_prepare_rejects_bytes_that_hash_correctly_but_dont_parse() {
        let bytes = b"this is not valid toml at all";
        let expected = sha256_hex(bytes);
        assert!(verify_and_prepare(bytes, &expected).is_err());
    }

    // ── lockfile round-trip (tempdir only — never the real config dir) ───

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tickover-registry-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn lockfile_round_trips_through_a_tempdir() {
        let dir = temp_dir("lockfile-roundtrip");
        let path = dir.join("registry-state.json");

        let loaded_before = load_lockfile(&path);
        assert!(
            loaded_before.plugins.is_empty(),
            "missing file loads as empty state"
        );

        let mut state = RegistryLockState::default();
        state.set(
            "some-provider",
            RegistryLockEntry {
                origin_registry_url: "https://example.com/registry/index.toml".to_string(),
                origin_version: "1.0.0".to_string(),
                origin_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_string(),
                installed_at: 1_800_000_000,
            },
        );
        save_lockfile(&path, &state).expect("save");

        let loaded = load_lockfile(&path);
        std::fs::remove_dir_all(&dir).ok();

        let entry = loaded
            .get("some-provider")
            .expect("entry present after round-trip");
        assert_eq!(entry.origin_version, "1.0.0");
        assert_eq!(entry.installed_at, 1_800_000_000);
    }

    #[test]
    fn lockfile_load_of_corrupt_json_yields_empty_state() {
        let dir = temp_dir("lockfile-corrupt");
        let path = dir.join("registry-state.json");
        std::fs::write(&path, "not json at all").unwrap();
        let state = load_lockfile(&path);
        std::fs::remove_dir_all(&dir).ok();
        assert!(state.plugins.is_empty());
    }

    #[test]
    fn saving_over_a_corrupt_lockfile_backs_it_up_first() {
        // Without this, `load_lockfile`'s own "corrupt reads as empty" rule
        // means the very next install/update overwrites the corrupt file
        // with a fresh, empty-looking lockfile — taking every provenance
        // record it held (however it got corrupted) with it, with nothing
        // left to recover from.
        let dir = temp_dir("lockfile-backup-corrupt");
        let path = dir.join("registry-state.json");
        std::fs::write(&path, "not json at all").unwrap();

        save_lockfile(&path, &RegistryLockState::default()).expect("save");

        let backups: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .contains("registry-state.json.corrupt-")
            })
            .collect();
        assert_eq!(backups.len(), 1, "exactly one backup of the corrupt file");
        assert_eq!(
            std::fs::read_to_string(backups[0].path()).unwrap(),
            "not json at all",
            "the backup holds what was actually there"
        );
        assert!(
            load_lockfile(&path).plugins.is_empty(),
            "the real path now holds the freshly-saved (empty) state"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The backup name is predictable — this second, not this process — so
    /// anything running as this user can plant a symlink on it ahead of
    /// time. `std::fs::copy`'s destination-truncate would have followed that
    /// link and overwritten whatever it pointed to; `create_new` instead
    /// refuses the occupied name outright and falls through to the next
    /// counter-suffixed one, so the backup still lands somewhere.
    #[test]
    #[cfg(unix)]
    fn saving_over_a_corrupt_lockfile_will_not_follow_a_symlink_planted_on_its_backup_name() {
        let dir = temp_dir("lockfile-backup-symlink");
        let path = dir.join("registry-state.json");
        let corrupt = "not json at all";
        std::fs::write(&path, corrupt).unwrap();

        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let stem = path.file_name().unwrap().to_os_string();
        let name_for = |suffix: &str| {
            let mut n = stem.clone();
            n.push(suffix);
            path.with_file_name(n)
        };
        let predicted = name_for(&format!(".corrupt-{secs}"));
        let suffixed = name_for(&format!(".corrupt-{secs}-1"));

        let outside = path.with_file_name("precious-lockfile-backup-victim.txt");
        std::fs::write(&outside, b"do not touch").unwrap();
        std::os::unix::fs::symlink(&outside, &predicted).expect("plant the link");

        save_lockfile(&path, &RegistryLockState::default()).expect("save");

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

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn saving_over_a_valid_lockfile_leaves_no_backup_behind() {
        let dir = temp_dir("lockfile-backup-not-needed");
        let path = dir.join("registry-state.json");
        save_lockfile(&path, &RegistryLockState::default()).expect("first save");
        save_lockfile(&path, &RegistryLockState::default()).expect("second save");

        let backups = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".corrupt-"))
            .count();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(backups, 0, "an ordinary overwrite backs up nothing");
    }

    #[test]
    fn lockfile_set_and_remove() {
        let mut state = RegistryLockState::default();
        state.set(
            "x",
            RegistryLockEntry {
                origin_registry_url: "https://example.com/index.toml".to_string(),
                origin_version: "1.0.0".to_string(),
                origin_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_string(),
                installed_at: 0,
            },
        );
        assert!(state.get("x").is_some());
        state.remove("x");
        assert!(state.get("x").is_none());
    }

    // ── diff_installed: state machine ────────────────────────────────────

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const HASH_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn one_entry_index(sha256: &str, version: &str) -> RegistryIndex {
        RegistryIndex {
            schema_version: 1,
            plugins: vec![RegistryEntry {
                id: "prov".to_string(),
                name: "Prov".to_string(),
                version: version.to_string(),
                description: None,
                manifest: "manifests/prov.toml".to_string(),
                sha256: sha256.to_string(),
            }],
        }
    }

    fn lock_with(sha256: &str, version: &str) -> RegistryLockState {
        let mut state = RegistryLockState::default();
        state.set(
            "prov",
            RegistryLockEntry {
                origin_registry_url: "https://example.com/index.toml".to_string(),
                origin_version: version.to_string(),
                origin_sha256: sha256.to_string(),
                installed_at: 0,
            },
        );
        state
    }

    #[test]
    fn diff_new_when_no_local_file() {
        let idx = one_entry_index(HASH_A, "1.0.0");
        let states = diff_installed(&idx, &[], &RegistryLockState::default());
        assert_eq!(states, vec![RegistryPluginState::New]);
    }

    #[test]
    fn diff_up_to_date_when_local_and_index_both_match_origin() {
        let idx = one_entry_index(HASH_A, "1.0.0");
        let lockfile = lock_with(HASH_A, "1.0.0");
        let installed = vec![("prov".to_string(), HASH_A.to_string(), "1.0.0".to_string())];
        let states = diff_installed(&idx, &installed, &lockfile);
        assert_eq!(
            states,
            vec![RegistryPluginState::UpToDate {
                locally_modified: false
            }]
        );
    }

    #[test]
    fn diff_update_available_safe_when_local_matches_origin_but_index_moved() {
        let idx = one_entry_index(HASH_B, "1.1.0"); // index != origin (HASH_A)
        let lockfile = lock_with(HASH_A, "1.0.0");
        let installed = vec![("prov".to_string(), HASH_A.to_string(), "1.0.0".to_string())];
        let states = diff_installed(&idx, &installed, &lockfile);
        assert_eq!(
            states,
            vec![RegistryPluginState::UpdateAvailable {
                overwrite_safe: true,
                warning: None
            }]
        );
    }

    #[test]
    fn diff_up_to_date_but_locally_modified_when_local_diverges_and_index_matches_origin() {
        let idx = one_entry_index(HASH_A, "1.0.0"); // index == origin
        let lockfile = lock_with(HASH_A, "1.0.0");
        let installed = vec![("prov".to_string(), HASH_C.to_string(), "1.0.0".to_string())]; // local != origin
        let states = diff_installed(&idx, &installed, &lockfile);
        assert_eq!(
            states,
            vec![RegistryPluginState::UpToDate {
                locally_modified: true
            }]
        );
    }

    #[test]
    fn diff_update_available_unsafe_when_both_local_and_index_diverge_from_origin() {
        let idx = one_entry_index(HASH_B, "1.1.0"); // index != origin
        let lockfile = lock_with(HASH_A, "1.0.0");
        let installed = vec![("prov".to_string(), HASH_C.to_string(), "1.0.0".to_string())]; // local != origin
        let states = diff_installed(&idx, &installed, &lockfile);
        match &states[0] {
            RegistryPluginState::UpdateAvailable {
                overwrite_safe,
                warning,
            } => {
                assert!(!overwrite_safe);
                assert!(warning.is_some());
            }
            other => panic!("expected UpdateAvailable, got {other:?}"),
        }
    }

    #[test]
    fn diff_no_lockfile_record_falls_back_to_version_compare() {
        let idx = one_entry_index(HASH_B, "2.0.0");
        let installed = vec![("prov".to_string(), HASH_A.to_string(), "1.0.0".to_string())];
        let states = diff_installed(&idx, &installed, &RegistryLockState::default());
        match &states[0] {
            RegistryPluginState::UpdateAvailable {
                overwrite_safe,
                warning,
            } => {
                assert!(!overwrite_safe, "no provenance -> never a safe overwrite");
                assert!(warning.is_some());
            }
            other => panic!("expected UpdateAvailable, got {other:?}"),
        }
    }

    #[test]
    fn diff_no_lockfile_record_and_same_version_is_up_to_date() {
        let idx = one_entry_index(HASH_B, "1.0.0"); // same version, different hash
        let installed = vec![("prov".to_string(), HASH_A.to_string(), "1.0.0".to_string())];
        let states = diff_installed(&idx, &installed, &RegistryLockState::default());
        assert_eq!(
            states,
            vec![RegistryPluginState::UpToDate {
                locally_modified: false
            }]
        );
    }

    // ── analyze_trust ─────────────────────────────────────────────────────
    //
    // Widened rule (2026-07, widened further since): `requires_approval`
    // fires on any of four things — store-backed auth
    // (credentials-file/keychain/electron-safe-storage/win-credential/
    // credentials-map/oauth-refresh) combined with `engine = "http-api"`, a
    // declared `[ping]`, a non-empty `local_files` (which now includes an
    // auth step's own credential `path`, `[logfile] root`/`glob`, `[account]
    // path` and `[[surface.auth.client]]` discovery — not just
    // `[[http.value]]`), or a non-empty `credential_sources` (env/keychain/
    // win-credential/electron-safe-storage, whatever the engine) — no longer
    // conditioned on the destination host at all. `dest_hosts`/
    // `untrusted_hosts` are still disclosed (and still worth asserting on),
    // they just don't gate approval.

    fn http_api_manifest(url: &str, auth_type: &str) -> PluginManifest {
        // `path` is only wired in for the auth types that actually read a
        // file through it (`credentials-file`/`credentials-map`) — setting
        // it for `env`/`keychain`/`win-credential` too would have
        // `analyze_trust` disclose a file none of those steps ever opens,
        // which is exactly the "not a file" distinction `path`'s own doc on
        // `TrustDisclosure::local_files` draws.
        let path_line = matches!(auth_type, "credentials-file" | "credentials-map")
            .then(|| "path = \"~/.x/creds.json\"")
            .unwrap_or_default();
        // `macos_keychain_key` is `electron-safe-storage`'s own field
        // (`auth::electron_safe_storage_step`) — `validate` now refuses it on
        // any other step kind, same as `expiry_json_path` already was, so
        // this can no longer be wired in unconditionally like `service`/`var`/
        // `config_path`/`blob_json_path`, none of which `validate` checks.
        let macos_keychain_key_line = matches!(auth_type, "electron-safe-storage")
            .then(|| "macos_keychain_key = \"key\"")
            .unwrap_or_default();
        let toml = format!(
            r#"
            id         = "x"
            name       = "X"
            menu_label = "X"
            order      = 1
            engine     = "http-api"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "p"
            resets_at_path = "r"
            [http]
            [[http.request]]
            url = "{url}"
            [[surface]]
            id = "cli"
            label = "CLI"
            allowed_hosts = ["example.com"]
            [[surface.auth]]
            type = "{auth_type}"
            {path_line}
            token_json_path = "access_token"
            service = "svc"
            var = "SOME_VAR"
            config_path = "~/.x/config.json"
            blob_json_path = "blob"
            {macos_keychain_key_line}
            "#
        );
        PluginManifest::from_str(&toml).expect("valid manifest")
    }

    #[test]
    fn http_api_with_credentials_file_and_untrusted_host_requires_approval() {
        let m = http_api_manifest("https://evil.example.com/usage", "credentials-file");
        let disclosure = analyze_trust(&m, TRUSTED_HOSTS);
        assert!(disclosure.requires_approval);
        assert_eq!(disclosure.dest_hosts, vec!["evil.example.com".to_string()]);
        assert_eq!(
            disclosure.untrusted_hosts,
            vec!["evil.example.com".to_string()]
        );
        assert_eq!(disclosure.auth_types, vec![AuthType::CredentialsFile]);
        // The gap this closes: the credential file the step actually reads
        // used to be missing from `local_files` entirely — the dialog would
        // have printed "Reads local files: (none)" for a manifest whose
        // whole reason to need approval is reading a credential off disk.
        assert_eq!(
            disclosure.local_files,
            vec!["~/.x/creds.json".to_string()],
            "the credentials-file step's own path must be disclosed"
        );
    }

    #[test]
    fn http_api_with_credentials_file_and_trusted_host_still_requires_approval() {
        // Widened rule: store-backed auth + http-api gates on its own now —
        // the destination happening to be a trusted host no longer excuses
        // it (a later manifest update could point the same store-backed
        // auth at an untrusted host, and the install flow only asks once).
        let m = http_api_manifest("https://api.anthropic.com/usage", "credentials-file");
        let disclosure = analyze_trust(&m, TRUSTED_HOSTS);
        assert!(disclosure.requires_approval);
        assert!(
            disclosure.untrusted_hosts.is_empty(),
            "the host is still disclosed as trusted even though approval is required regardless"
        );
    }

    #[test]
    fn ping_disclosure_names_the_renewal_trigger_only_when_the_manifest_declares_it() {
        let base = r#"
            id         = "x"
            name       = "X"
            menu_label = "X"
            order      = 1
            engine     = "log-file"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "p"
            resets_at_path = "r"
            [logfile]
            root = "~/.x"
            glob = "*.jsonl"
            container_key = "rate_limits"
            [ping]
            bin  = "claude"
            args = ["-p", "hello"]
        "#;
        let m = PluginManifest::from_str(base).expect("valid manifest");
        assert_eq!(
            analyze_trust(&m, TRUSTED_HOSTS).ping.as_deref(),
            Some("claude -p hello")
        );

        let renewing = base.replace(
            "bin  = \"claude\"",
            "bin  = \"claude\"\n            renews_token = true",
        );
        let m = PluginManifest::from_str(&renewing).expect("valid manifest");
        assert_eq!(
            analyze_trust(&m, TRUSTED_HOSTS).ping.as_deref(),
            Some("claude -p hello — also run when its token has expired or is no longer accepted"),
        );
    }

    #[test]
    fn a_manifest_whose_only_auth_step_reads_a_credential_map_still_needs_approval() {
        // The gap this closes: nothing else in `analyze_trust` would have
        // flagged such a manifest. It declares no `[ping]`, and `local_files`
        // is fed only from `[[http.value]]` and `http.version.files` — never
        // from an auth step's own `path` — so a third-party plugin reading
        // somebody's `auth.json` and posting the token to its own host would
        // have installed in silence.
        let toml = r#"
            id         = "x"
            name       = "X"
            menu_label = "X"
            order      = 1
            engine     = "http-api"
            requires_reader = ["credentials-map"]
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "p"
            resets_at_path = "r"
            [http]
            [[http.request]]
            url = "https://evil.example.com/usage"
            [[surface]]
            id = "cli"
            label = "CLI"
            allowed_hosts = ["example.com"]
            [[surface.auth]]
            type = "credentials-map"
            path = "~/.x/auth.json"
            key_prefix = "https://issuer::"
            token_json_path = "key"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let disclosure = analyze_trust(&m, TRUSTED_HOSTS);
        assert!(
            disclosure.requires_approval,
            "reading a credential out of a map is reading a credential"
        );
        assert_eq!(disclosure.auth_types, vec![AuthType::CredentialsMap]);
    }

    #[test]
    fn http_api_with_keychain_and_untrusted_host_requires_approval() {
        let m = http_api_manifest("https://evil.example.com/usage", "keychain");
        let disclosure = analyze_trust(&m, TRUSTED_HOSTS);
        assert!(disclosure.requires_approval);
        assert_eq!(
            disclosure.untrusted_hosts,
            vec!["evil.example.com".to_string()]
        );
        assert_eq!(disclosure.auth_types, vec![AuthType::Keychain]);
    }

    #[test]
    fn an_oauth_refresh_step_is_credential_bearing_and_needs_approval() {
        // The most security-significant line in the hybrid: a manifest whose
        // step *sends* a refresh token to the network must not install without
        // the trust dialog. Asserted directly, on a trusted host so nothing but
        // the auth step could be what trips the approval.
        let toml = r#"
            id = "sample"
            name = "Sample"
            menu_label = "Sa"
            order = 1
            engine = "http-api"
            requires_reader = ["oauth-refresh"]
            [[windows]]
            label = "5H"
            role = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "p"
            resets_at_path = "r"
            [http]
            [[http.request]]
            url = "https://example.com/usage"
            [[surface]]
            id = "cli"
            label = "CLI"
            allowed_hosts = ["example.com", "oauth2.googleapis.com"]
            [[surface.auth]]
            type = "oauth-refresh"
            path = "~/.gemini/oauth_creds.json"
            token_json_path = "refresh_token"
            token_url = "https://oauth2.googleapis.com/token"
            client_id = "cid.apps.googleusercontent.com"
            client_secret = "secret"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let disclosure = analyze_trust(&m, TRUSTED_HOSTS);
        assert!(
            disclosure.requires_approval,
            "a step that mails a refresh token to the network must be gated by the trust dialog"
        );
        assert_eq!(disclosure.auth_types, vec![AuthType::OauthRefresh]);
    }

    #[test]
    fn an_oauth_refresh_steps_own_path_and_token_url_host_are_disclosed_the_antigravity_shape() {
        // The gap this closes, in two halves — this fixture is the shape
        // `plugins/antigravity.toml` actually ships (a `keychain`-then-
        // `oauth-refresh` chain reading `~/.gemini/.../antigravity-oauth-token`
        // and refreshing at `oauth2.googleapis.com`, alongside a request to a
        // *different* host): the step's own `path` used to be missing from
        // `local_files` (R2), and `token_url`'s host used to be missing from
        // `dest_hosts` (E1) — a manifest could read a local credential and
        // mail it to a second host the trust dialog said nothing about,
        // while also reading local files exactly like `[[http.value]] path`
        // does through its `client` table — a `files` entry directly, a
        // `bins` name after resolving it on `PATH` — and nothing else in
        // `analyze_trust` would have noticed either of those.
        let toml = r#"
            id = "sample"
            name = "Sample"
            menu_label = "Sa"
            order = 1
            engine = "http-api"
            requires_reader = ["oauth-refresh", "oauth-client-discovery"]
            [[windows]]
            label = "5H"
            role = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "p"
            resets_at_path = "r"
            [http]
            [[http.request]]
            url = "https://example.com/usage"
            [[surface]]
            id = "cli"
            label = "CLI"
            allowed_hosts = ["example.com", "oauth2.googleapis.com"]
            [[surface.auth]]
            type = "oauth-refresh"
            path = "~/.gemini/oauth_creds.json"
            token_json_path = "refresh_token"
            token_url = "https://oauth2.googleapis.com/token"
            [surface.auth.client]
            id_env         = "SAMPLE_CLIENT_ID"
            secret_env     = "SAMPLE_CLIENT_SECRET"
            id_pattern     = "[0-9]{1,10}-[a-z]{1,10}\\.apps\\.googleusercontent\\.com"
            secret_pattern = "GOCSPX-[A-Za-z0-9]{1,20}"
            files = ["/Applications/Sample.app/Contents/MacOS/sample"]
            bins  = ["sample-cli"]
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let disclosure = analyze_trust(&m, TRUSTED_HOSTS);
        // E1: the refresh endpoint reaches the trust dialog even though no
        // `[[http.request]]` ever names it.
        assert_eq!(
            disclosure.dest_hosts,
            vec![
                "example.com".to_string(),
                "oauth2.googleapis.com".to_string()
            ],
            "the oauth-refresh step's token_url host must be disclosed alongside the request host"
        );
        // R2: the credential file the step reads before ever exchanging
        // anything reaches the trust dialog too, not just the client
        // discovery table's own files/bins/patterns below.
        assert!(
            disclosure
                .local_files
                .contains(&"~/.gemini/oauth_creds.json".to_string()),
            "the oauth-refresh step's own path must be disclosed: {:?}",
            disclosure.local_files
        );
        assert!(
            disclosure
                .local_files
                .contains(&"/Applications/Sample.app/Contents/MacOS/sample".to_string()),
            "{:?}",
            disclosure.local_files
        );
        assert!(
            disclosure.local_files.contains(
                &"sample-cli (resolved on PATH, or in ~/.local/bin, ~/.cargo/bin, nvm, or one \
                  of this app's other usual CLI install directories)"
                    .to_string()
            ),
            "a `bins` name is disclosed labelled, naming the actual user-writable directories \
             searched, not as a bare path nobody can act on — {:?}",
            disclosure.local_files
        );
        // The env override is a way to hand this app a credential without
        // any file ever being read — a registry manifest naming, say,
        // `AWS_SECRET_ACCESS_KEY` must not install unseen just because
        // nothing here is technically a *file*.
        assert!(
            disclosure
                .local_files
                .contains(&"$SAMPLE_CLIENT_ID (environment variable)".to_string()),
            "{:?}",
            disclosure.local_files
        );
        assert!(
            disclosure
                .local_files
                .contains(&"$SAMPLE_CLIENT_SECRET (environment variable)".to_string()),
            "{:?}",
            disclosure.local_files
        );
        // The patterns themselves — not a place read from, but what a
        // `files`/`bins` candidate is searched for. Without these the
        // dialog would show only where this step looks, never what shape
        // it pulls out of there.
        assert!(
            disclosure.local_files.contains(
                &"id_pattern: [0-9]{1,10}-[a-z]{1,10}\\.apps\\.googleusercontent\\.com".to_string()
            ),
            "{:?}",
            disclosure.local_files
        );
        assert!(
            disclosure
                .local_files
                .contains(&"secret_pattern: GOCSPX-[A-Za-z0-9]{1,20}".to_string()),
            "{:?}",
            disclosure.local_files
        );
        assert!(
            disclosure.requires_approval,
            "reading a local file, however it's named, needs approval"
        );
    }

    #[test]
    fn a_client_pattern_longer_than_the_display_limit_is_truncated_with_an_ellipsis() {
        // `manifest::validate`'s own cap on a pattern's source text is 512
        // bytes — a load-time ceiling, not a rendering one. This pattern is
        // 150 bytes: valid, bounded, non-empty-match (a run of literal `1`s
        // matches only itself), so it loads fine — but is still well over
        // `PATTERN_DISPLAY_MAX_BYTES` (120), and the dialog line must not
        // grow to match it.
        let long_pattern = "1".repeat(150);
        let toml = r#"
            id = "sample"
            name = "Sample"
            menu_label = "Sa"
            order = 1
            engine = "http-api"
            requires_reader = ["oauth-refresh", "oauth-client-discovery"]
            [[windows]]
            label = "5H"
            role = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "p"
            resets_at_path = "r"
            [http]
            [[http.request]]
            url = "https://example.com/usage"
            [[surface]]
            id = "cli"
            label = "CLI"
            allowed_hosts = ["example.com", "oauth2.googleapis.com"]
            [[surface.auth]]
            type = "oauth-refresh"
            path = "~/.gemini/oauth_creds.json"
            token_json_path = "refresh_token"
            token_url = "https://oauth2.googleapis.com/token"
            [surface.auth.client]
            id_pattern     = "{long_pattern}"
            secret_pattern = "GOCSPX-[A-Za-z0-9]{1,20}"
            files = ["/Applications/Sample.app/Contents/MacOS/sample"]
        "#
        .replace("{long_pattern}", &long_pattern);
        let m = PluginManifest::from_str(&toml)
            .expect("valid manifest — 150 bytes is under the 512 limit");
        let disclosure = analyze_trust(&m, TRUSTED_HOSTS);

        let expected = format!(
            "id_pattern: {}…",
            &long_pattern[..PATTERN_DISPLAY_MAX_BYTES]
        );
        assert!(
            disclosure.local_files.contains(&expected),
            "{:?}",
            disclosure.local_files
        );
        assert!(
            !disclosure
                .local_files
                .iter()
                .any(|f| f.starts_with("id_pattern:") && f.len() > 140),
            "the rendered pattern must be cut short, not grown to match the source — {:?}",
            disclosure.local_files
        );
    }

    #[test]
    fn log_file_manifest_with_no_auth_still_requires_approval_for_its_own_read_scope() {
        // Widened (complete trust disclosure): `engine = "log-file"`'s own
        // `root`/`glob` used to be invisible to `analyze_trust` entirely — a
        // manifest with no `[[surface.auth]]`, no `[ping]`, and no `[http]`
        // installed with no dialog at all while still walking whatever
        // `root`/`glob` named, however broad. This fixture's own scope is
        // narrow (`~/.x/*.jsonl`), which is the point: the gate is on
        // reading a local file *at all*, not on how wide the glob happens
        // to be — the same "reading a local file, however it's named, needs
        // approval" rule every other `local_files` source already obeys.
        let toml = r#"
            id         = "x"
            name       = "X"
            menu_label = "X"
            order      = 1
            engine     = "log-file"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "p"
            resets_at_path = "r"
            [logfile]
            root = "~/.x"
            glob = "*.jsonl"
            container_key = "rate_limits"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let disclosure = analyze_trust(&m, TRUSTED_HOSTS);
        assert!(disclosure.requires_approval);
        assert_eq!(disclosure.local_files, vec!["~/.x/*.jsonl".to_string()]);
        assert!(disclosure.auth_types.is_empty());
        assert!(disclosure.dest_hosts.is_empty());
        assert_eq!(disclosure.engine, EngineKind::LogFile);
    }

    #[test]
    fn a_log_file_manifest_walking_the_whole_home_directory_discloses_that_scope() {
        // The exact shape the gap named: no surface, no auth, no ping, no
        // http — a registry manifest with only `[logfile] root = "~"`,
        // `glob = "**/*.json"` used to install with no dialog at all and
        // walk the user's entire home directory looking for JSON files.
        let toml = r#"
            id         = "x"
            name       = "X"
            menu_label = "X"
            order      = 1
            engine     = "log-file"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "p"
            resets_at_path = "r"
            [logfile]
            root = "~"
            glob = "**/*.json"
            container_key = "rate_limits"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let disclosure = analyze_trust(&m, TRUSTED_HOSTS);
        assert!(disclosure.requires_approval);
        assert_eq!(
            disclosure.local_files,
            vec!["~/**/*.json".to_string()],
            "the dialog must say plainly that this walks the home directory: {:?}",
            disclosure.local_files
        );
    }

    #[test]
    fn logfile_scope_prefers_root_env_and_joins_root_env_join_when_set() {
        // A manifest's `root` fallback is not what the engine actually reads
        // whenever `root_env` names a variable that is set — see
        // `resolve_root` — so the disclosure has to say `$VAR`, not the
        // fallback text, or it names something the manifest will not
        // actually touch.
        let toml = r#"
            id         = "x"
            name       = "X"
            menu_label = "X"
            order      = 1
            engine     = "log-file"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "p"
            resets_at_path = "r"
            [logfile]
            root_env      = "CODEX_HOME"
            root_env_join = "sessions"
            root          = "~/.codex"
            glob          = "**/rollout-*.jsonl"
            container_key = "rate_limits"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let disclosure = analyze_trust(&m, TRUSTED_HOSTS);
        assert_eq!(
            disclosure.local_files,
            vec!["$CODEX_HOME/sessions/**/rollout-*.jsonl".to_string()]
        );
    }

    #[test]
    fn env_only_auth_now_gates_approval_through_credential_sources() {
        // Widened (complete trust disclosure): naming the environment
        // variable a manifest reads a credential from is exactly the shape
        // this closes — a registry manifest whose one auth step is `env`,
        // `var = "AWS_SECRET_ACCESS_KEY"` used to disclose only the step
        // *kind* ("env") and install with no dialog at all. `store_backed`
        // (the http-api combination rule) still answers no for `env` — see
        // its own match arm — but `credential_sources` gates on its own now,
        // whatever the engine.
        let m = http_api_manifest("https://evil.example.com/usage", "env");
        let disclosure = analyze_trust(&m, TRUSTED_HOSTS);
        assert_eq!(
            disclosure.auth_types,
            vec![AuthType::Env],
            "env is still disclosed in auth_types too"
        );
        assert_eq!(
            disclosure.credential_sources,
            vec!["env $SOME_VAR".to_string()],
            "the variable name itself must be named, not just the step kind"
        );
        assert!(
            disclosure.requires_approval,
            "naming a specific environment variable to read a credential from needs a look"
        );
    }

    #[test]
    fn keychain_auth_names_the_service_in_credential_sources() {
        let m = http_api_manifest("https://evil.example.com/usage", "keychain");
        let disclosure = analyze_trust(&m, TRUSTED_HOSTS);
        assert_eq!(
            disclosure.credential_sources,
            vec!["keychain \"svc\"".to_string()]
        );
    }

    #[test]
    fn win_credential_auth_names_every_target_in_credential_sources() {
        // The shape `plugins/claude.toml`'s own Windows surface ships: more
        // than one target tried in order. Both have to be named, not just
        // the step kind — a manifest could name a target belonging to a
        // completely different application.
        let toml = r#"
            id         = "x"
            name       = "X"
            menu_label = "X"
            order      = 1
            engine     = "http-api"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "p"
            resets_at_path = "r"
            [http]
            [[http.request]]
            url = "https://example.com/usage"
            [[surface]]
            id = "cli"
            label = "CLI"
            allowed_hosts = ["example.com"]
            [[surface.auth]]
            type            = "win-credential"
            targets         = ["Provider-credentials", "Provider"]
            token_json_path = "access_token"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let disclosure = analyze_trust(&m, TRUSTED_HOSTS);
        assert_eq!(
            disclosure.credential_sources,
            vec![
                "credential manager \"Provider-credentials\"".to_string(),
                "credential manager \"Provider\"".to_string(),
            ]
        );
        assert!(disclosure.requires_approval);
    }

    #[test]
    fn electron_safe_storage_auth_names_the_config_file_and_keychain_key_and_discloses_the_file_too(
    ) {
        // The one auth kind that reads from both a file and a second store
        // at once — `config_path` has to land in both `local_files` (it is
        // a file this manifest opens) and `credential_sources` (the macOS
        // keychain entry that unlocks what's inside it), or one list would
        // say only half of what this step actually does.
        let toml = r#"
            id         = "x"
            name       = "X"
            menu_label = "X"
            order      = 1
            engine     = "http-api"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "p"
            resets_at_path = "r"
            [http]
            [[http.request]]
            url = "https://example.com/usage"
            [[surface]]
            id = "desktop"
            label = "Desktop"
            allowed_hosts = ["example.com"]
            [[surface.auth]]
            type                = "electron-safe-storage"
            config_path         = "{config_dir}/Sample/config.json"
            blob_json_path      = "blob"
            macos_keychain_key  = "Sample Safe Storage"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let disclosure = analyze_trust(&m, TRUSTED_HOSTS);
        assert_eq!(
            disclosure.credential_sources,
            vec!["electron safe storage {config_dir}/Sample/config.json (key \"Sample Safe Storage\")"
                .to_string()]
        );
        assert!(
            disclosure
                .local_files
                .contains(&"{config_dir}/Sample/config.json".to_string()),
            "the file the step actually opens must be disclosed too: {:?}",
            disclosure.local_files
        );
        assert!(disclosure.requires_approval);
    }

    #[test]
    fn jwt_file_account_path_is_disclosed_in_local_files() {
        let toml = r#"
            id         = "x"
            name       = "X"
            menu_label = "X"
            order      = 1
            engine     = "log-file"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "p"
            resets_at_path = "r"
            [logfile]
            root = "~/.x"
            glob = "*.jsonl"
            container_key = "rate_limits"
            [account]
            type       = "jwt-file"
            path       = "~/.x/token.jwt"
            token_path = "token"
            claim      = "email"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let disclosure = analyze_trust(&m, TRUSTED_HOSTS);
        assert!(
            disclosure
                .local_files
                .contains(&"~/.x/token.jwt".to_string()),
            "{:?}",
            disclosure.local_files
        );
    }

    #[test]
    fn an_option_placeholder_in_a_request_host_is_disclosed_substituted_at_its_default() {
        // `push_dest_host` used to run on the pre-substitution URL, so a
        // host reading `{option.beta}.evil.example` disclosed the
        // placeholder text itself rather than the destination it actually
        // resolves to.
        let toml = r#"
            id         = "x"
            name       = "X"
            menu_label = "X"
            order      = 1
            engine     = "http-api"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "p"
            resets_at_path = "r"
            [http]
            [[http.request]]
            url = "https://{option.beta}.evil.example/usage"
            [[surface]]
            id = "cli"
            label = "CLI"
            [[option]]
            key     = "beta"
            label   = "Beta"
            default = true
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let disclosure = analyze_trust(&m, TRUSTED_HOSTS);
        assert_eq!(disclosure.dest_hosts, vec!["true.evil.example".to_string()]);
    }

    #[test]
    fn push_dest_host_for_disclosure_leaves_an_unknown_placeholder_verbatim() {
        // `manifest::validate` already refuses a `{option.<key>}` naming an
        // option nothing declares, so no manifest that loads can actually
        // carry this shape — exercised directly against the function itself
        // (empty `option_defaults`, standing in for a key `substitute_options`
        // has never heard of) rather than through a manifest for that
        // reason, the same way `push_dest_host_sees_the_backslash_authority…`
        // exercises `push_dest_host` itself. Worth keeping anyway: `{`/`}`
        // are not forbidden host code points, so an unresolved placeholder
        // still parses and still has to be disclosed, not silently dropped,
        // whatever put it there.
        let mut hosts = Vec::new();
        push_dest_host_for_disclosure(
            "https://{option.x}.evil.example/usage",
            &BTreeMap::new(),
            &mut hosts,
        );
        assert_eq!(hosts, vec!["{option.x}.evil.example".to_string()]);
    }

    #[test]
    fn push_dest_host_for_disclosure_falls_back_to_the_raw_authority_when_https_host_cannot_parse_it(
    ) {
        // The one shape `https_host` cannot make sense of at all: a
        // placeholder sitting in the port rather than the hostname
        // (`InvalidPort`, however the placeholder resolves). `validate`
        // only requires `[[http.request]] url`/`[account] url` to be
        // `https`-parseable when `[http]` is declared at all, so a
        // `log-file` manifest's `[account] url` can carry exactly this
        // shape and still load — exercised directly here (not through a
        // manifest round trip) since that is the one place the ordinary
        // path cannot reach.
        let mut hosts = Vec::new();
        push_dest_host_for_disclosure(
            "https://{option.x}:{option.y}/me",
            &BTreeMap::new(),
            &mut hosts,
        );
        assert_eq!(hosts, vec!["{option.x}:{option.y}".to_string()]);
    }

    /// The declared-option counterpart to the test above: before this, the
    /// fallback fired only when the substituted authority still literally
    /// contained `{`, which is true only for an *undeclared* option
    /// (`substitute_options` leaves it untouched). A *declared* one resolves
    /// to the literal text `true`/`false`, and `https://host:true/` is
    /// exactly as much an `InvalidPort` as the placeholder it came from —
    /// but `contains('{')` was already false by the time this ran, so the
    /// destination silently vanished from the trust dialog instead of being
    /// shown as the resolved (if still nonsensical) authority.
    #[test]
    fn push_dest_host_for_disclosure_falls_back_when_a_declared_option_resolves_to_an_unparseable_authority(
    ) {
        let mut hosts = Vec::new();
        let mut option_defaults = BTreeMap::new();
        option_defaults.insert("port".to_string(), true);
        push_dest_host_for_disclosure(
            "https://evil.example:{option.port}/usage",
            &option_defaults,
            &mut hosts,
        );
        assert_eq!(hosts, vec!["evil.example:true".to_string()]);
    }

    #[test]
    fn dest_hosts_includes_account_url_host_alongside_the_request_host() {
        let toml = r#"
            id         = "x"
            name       = "X"
            menu_label = "X"
            order      = 1
            engine     = "http-api"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "p"
            resets_at_path = "r"
            [http]
            [[http.request]]
            url = "https://api.example.com/usage"
            [account]
            type      = "http"
            url       = "https://profile.example.com/me"
            json_path = "email"
            [[surface]]
            id = "cli"
            label = "CLI"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let disclosure = analyze_trust(&m, TRUSTED_HOSTS);
        let mut hosts = disclosure.dest_hosts.clone();
        hosts.sort();
        assert_eq!(
            hosts,
            vec![
                "api.example.com".to_string(),
                "profile.example.com".to_string()
            ]
        );
    }

    #[test]
    fn push_dest_host_sees_the_backslash_authority_terminator_ureq_sees() {
        // Same attack `auth::host_allowed`'s own test names: `\` ends a
        // `https` authority exactly as `/` does, so this URL's host is
        // `evil.example`, not `api.anthropic.com` — a manifest cannot make
        // this disclosure list say something the request itself will not
        // do.
        let mut hosts = Vec::new();
        push_dest_host(
            "https://evil.example\\@api.anthropic.com/api/oauth/usage",
            &mut hosts,
        );
        assert_eq!(hosts, vec!["evil.example".to_string()]);
    }

    #[test]
    fn untrusted_hosts_flags_only_the_dest_hosts_outside_trusted_hosts() {
        let toml = r#"
            id         = "x"
            name       = "X"
            menu_label = "X"
            order      = 1
            engine     = "http-api"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "p"
            resets_at_path = "r"
            [http]
            [[http.request]]
            url = "https://api.anthropic.com/usage"
            [account]
            type      = "http"
            url       = "https://profile.example.com/me"
            json_path = "email"
            [[surface]]
            id = "cli"
            label = "CLI"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let disclosure = analyze_trust(&m, TRUSTED_HOSTS);
        assert_eq!(
            disclosure.dest_hosts,
            vec![
                "api.anthropic.com".to_string(),
                "profile.example.com".to_string()
            ]
        );
        assert_eq!(
            disclosure.untrusted_hosts,
            vec!["profile.example.com".to_string()],
            "only the host outside TRUSTED_HOSTS is flagged, the trusted one is not"
        );
    }

    // ── is_https gate (fetch_text/fetch_bytes themselves are never called —
    //    see module docs) ─────────────────────────────────────────────────

    #[test]
    fn is_https_accepts_only_the_https_scheme() {
        assert!(is_https("https://example.com/index.toml"));
        assert!(!is_https("http://example.com/index.toml"));
        assert!(!is_https("ftp://example.com/index.toml"));
        assert!(!is_https("example.com/index.toml"));
    }

    #[test]
    fn is_https_is_case_insensitive_on_the_scheme_unlike_a_bare_prefix_check() {
        // A bespoke `starts_with("https://")` is case-sensitive; the
        // real URL parser `https_host` delegates to lowercases the scheme
        // during parsing, matching the scheme rule a browser or any other
        // spec-following client applies.
        assert!(is_https("HTTPS://example.com/index.toml"));
        assert!(is_https("HttpS://example.com/index.toml"));
    }
}
