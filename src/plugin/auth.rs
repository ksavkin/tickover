//! The `[[surface.auth]]` credential-lookup chain — a generic, manifest-driven
//! way to find a provider's token, without a per-provider Rust module.
//!
//! Each [`AuthStep`] is evaluated in order and classified as one of three
//! outcomes (mirrors the doc comment on `SurfaceConfig::auth` in
//! `manifest.rs` — the classification lives there, not on [`AuthStep`]
//! itself):
//!   * **Present-ok**   — the credential store exists and yielded a token.
//!     [`resolve_token`] returns it immediately.
//!   * **Present-err**  — the credential store exists but the token couldn't
//!     be read (bad JSON, Keychain access denied, wrong password, …).
//!     [`resolve_token`] stops here and returns the error — later steps are
//!     *not* tried: a credentials file, once present, is authoritative.
//!   * **Absent**       — the credential store simply doesn't exist on this
//!     machine (no such file, no such Keychain item, env var unset). The
//!     chain moves on to the next step.
//!
//! Internally every step function returns `Result<Option<String>, String>`:
//! `Ok(Some(token))` is Present-ok, `Err(msg)` is Present-err, `Ok(None)` is
//! Absent.

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::manifest::{
    split_fallback_keys, AuthClientDiscovery, AuthStep, AuthType, SurfaceConfig,
};

/// The [`resolve_token`] error text for "every auth step was absent" — the
/// one error string that means "this surface just isn't set up here", as
/// opposed to a real (Present-err) failure. `main.rs` matches this literal to
/// decide whether a surface's row should be hidden from the popup entirely
/// (no credentials → no section) rather than shown with an inline error.
pub const NO_CREDENTIALS: &str = "no credentials found";

/// The [`resolve_token`] error text for "every step was absent, but at least
/// one of them found a credential whose declared expiry had already passed"
/// — a `keychain`/`credentials-file`/`win-credential` step with an
/// `expiry_json_path` resolves Absent on a lapsed token exactly as it would
/// on no token at all (so a refresh step behind it still gets its turn), and
/// without this the two were indistinguishable once the chain ran out.
/// `plugin::engine_http` matches this literal to offer a renewal ping
/// (`[ping] renews_token`) instead of the plain "no credentials" treatment —
/// see its own docs for what a plugin without such a ping gets instead.
pub const TOKEN_LAPSED: &str = "the only credential found had lapsed";

/// Walk a surface's `[[surface.auth]]` chain and return the first token
/// found, paired with whether the step that yielded it declares
/// `expiry_json_path` — not whether some *other* step on this surface does
/// (that question is `SurfaceConfig::declares_token_expiry`, asked of the
/// surface as a whole, for the tick's own filter; this one is asked of the
/// one step that actually produced the token in hand, for
/// `plugin::engine_http::unauthorized_outcome`'s 401 rewrite). A two-step
/// `cli` surface whose first step is `credentials-file` with
/// `expiry_json_path` and whose second is a bare `env` fallback can still
/// hand back a token from the second step — one `[ping]`'s CLI run cannot
/// renew, since nothing about that env var's own lifetime was ever declared
/// — and the caller needs to tell the two apart.
///
/// Stops (and returns an error) at the first step that is present but
/// broken — the second element of that `Err` is always `None`, since a
/// Present-err message names a broken store, never a lapsed token. Returns
/// [`NO_CREDENTIALS`] (second element `None`) if every step is absent, or
/// [`TOKEN_LAPSED`] paired with `Some(expires_at)` if every step is absent
/// *and* at least one of them found a credential that had lapsed by its own
/// declared expiry rather than finding none at all — a later step still gets
/// first refusal (an `oauth-refresh` behind a lapsed `keychain` step, say),
/// so "lapsed" only ever describes how the chain as a whole came up empty,
/// never a token this function actually returned. `expires_at` is the Unix
/// timestamp the credential itself declared (see [`token_expiry`]) — carried
/// out so a caller (`plugin::engine_http`) can key a renewal ping on this one
/// token, not on "some token, whichever it was" — see
/// `crate::model::TokenRenewal::Lapsed`.
pub fn resolve_token(surface: &SurfaceConfig) -> Result<(String, bool), (String, Option<u64>)> {
    let mut lapsed_expiry: Option<u64> = None;
    for step in &surface.auth {
        match run_step(step, &surface.allowed_hosts, &mut lapsed_expiry) {
            Ok(Some(token)) => return Ok((token, step.expiry_json_path.is_some())),
            Ok(None) => continue,
            Err(e) => return Err((e, None)),
        }
    }
    Err(match lapsed_expiry {
        Some(expires_at) => (TOKEN_LAPSED.to_string(), Some(expires_at)),
        None => (NO_CREDENTIALS.to_string(), None),
    })
}

/// `allowed_hosts` is only read by `oauth-refresh` (see [`oauth_refresh_step`])
/// — every other step here never leaves the filesystem/Keychain, so it has no
/// host to check. Threaded through anyway, rather than reaching back into
/// `surface` from inside `oauth_refresh_step`, so this function's signature
/// says on its own which steps can reach the network.
///
/// `lapsed_expiry` is set — to the declared expiry, never cleared or
/// overwritten once set — by whichever of `credentials_file_step`/
/// `keychain_step`/`win_credential_step` is the *first* in the chain to find
/// a credential past its own `expiry_json_path`; a later step's own lapsed
/// finding is not this app's business once an earlier one has already named
/// one (two stores disagreeing about the same account's expiry is not a
/// state worth choosing between). Every other step kind leaves it exactly as
/// it found it, which is why a single `&mut Option<u64>` threaded through the
/// whole chain (rather than a richer per-step return type) is enough:
/// [`resolve_token`] only ever reads it once, after the loop, and only when
/// nothing else answered.
fn run_step(
    step: &AuthStep,
    allowed_hosts: &[String],
    lapsed_expiry: &mut Option<u64>,
) -> Result<Option<String>, String> {
    match step.kind {
        AuthType::CredentialsFile => credentials_file_step(step, lapsed_expiry),
        AuthType::Keychain => keychain_step(step, lapsed_expiry),
        AuthType::Env => env_step(step),
        AuthType::ElectronSafeStorage => electron_safe_storage_step(step),
        AuthType::WinCredential => win_credential_step(step, lapsed_expiry),
        AuthType::CredentialsMap => credentials_map_step(step),
        AuthType::RejectWhen => reject_when_step(step),
        AuthType::OauthRefresh => oauth_refresh_step(step, allowed_hosts),
    }
}

// ── Step: reject-when ─────────────────────────────────────────────────────

/// A diagnostic step: no credential of its own, it just turns a known dead
/// end into a sentence. Present-err (stopping the chain with `message`) when
/// the field at `json_path` resolves to a non-null value and the one at
/// `unless_json_path` — if the step names one — does not. Absent in every
/// other case, including a missing or unreadable file: a rule that can't be
/// evaluated must never stand in the way of a credential that might be there.
fn reject_when_step(step: &AuthStep) -> Result<Option<String>, String> {
    let path = require_str("reject-when", "path", step.path.as_deref())?;
    let json_path = require_str("reject-when", "json_path", step.json_path.as_deref())?;
    let message = require_str("reject-when", "message", step.message.as_deref())?;

    let file = super::expand_home(path);
    let Some(text) = super::read_regular_file(&file, super::SMALL_FILE_MAX_BYTES) else {
        return Ok(None);
    };
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return Ok(None);
    };
    if !json_path_present(&value, json_path) {
        return Ok(None);
    }
    if step
        .unless_json_path
        .as_deref()
        .is_some_and(|p| json_path_present(&value, p))
    {
        return Ok(None);
    }
    Err(message.to_string())
}

/// Whether a dotted path resolves to a value that is actually *there* — a
/// JSON `null` counts as absent, which is how `~/.codex/auth.json` spells "no
/// API key" (`"OPENAI_API_KEY": null`) while the key is present.
fn json_path_present(root: &Value, path: &str) -> bool {
    let mut cur = root;
    for seg in path.split('.') {
        match cur.get(seg) {
            Some(next) => cur = next,
            None => return false,
        }
    }
    !cur.is_null()
}

// ── Host allowlist ────────────────────────────────────────────────────────

/// Is `url` allowed for a surface with this `allowed_hosts` list? An empty
/// list allows every host (no restriction configured); a non-empty list
/// requires an exact match on `url`'s host (case-insensitive, no wildcards —
/// a subdomain of an allowed host does **not** match).
///
/// The host is read by [`super::https_host`] — the same WHATWG parser
/// `ureq` builds the request through — rather than by a hand-rolled split
/// on the URL's punctuation, and a `url` that isn't `https` at all is never
/// allowed: this function exists so a surface's token can never leak to a
/// host the manifest didn't name, and a request the http engine would have
/// refused to send in the clear is not a host worth comparing against.
pub fn host_allowed(allowed_hosts: &[String], url: &str) -> bool {
    if allowed_hosts.is_empty() {
        return true;
    }
    match super::https_host(url) {
        Some(host) => allowed_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&host)),
        None => false,
    }
}

// ── Step: credentials-file ────────────────────────────────────────────────

fn credentials_file_step(
    step: &AuthStep,
    lapsed_expiry: &mut Option<u64>,
) -> Result<Option<String>, String> {
    let path = require_str("credentials-file", "path", step.path.as_deref())?;
    let token_json_path = require_str(
        "credentials-file",
        "token_json_path",
        step.token_json_path.as_deref(),
    )?;

    let file = super::expand_home(path);
    if !file.is_file() {
        return Ok(None); // surface not present on this machine
    }
    // Regular and bounded: a credentials path comes from a manifest, and a
    // fetch thread blocked reading a FIFO never reports back at all.
    let text = super::read_regular_file(&file, super::SMALL_FILE_MAX_BYTES)
        .ok_or_else(|| format!("{} is not a readable regular file", file.display()))?;
    token_from_blob(
        &text,
        token_json_path,
        step.expiry_json_path.as_deref(),
        now_unix(),
        &file.display().to_string(),
        lapsed_expiry,
    )
}

// ── Step: credentials-map ─────────────────────────────────────────────────

/// Like `credentials-file`, but the JSON at `path` is a map of records rather
/// than one record: pick the entry whose top-level key starts with
/// `key_prefix`, then read `token_json_path` inside *that* entry.
///
/// Absent only when the file itself is missing — mirroring
/// `credentials_file_step`. Everything past that (broken JSON, a root that
/// isn't an object, zero matching entries, more than one, or the matched
/// entry not carrying the token) is Present-err: the store exists, so a rule
/// that cannot resolve it is this app's problem to report, not a reason to
/// keep trying other surfaces. Zero matches in particular is *not* Absent —
/// unlike a missing file, an auth.json with no entry for this prefix is a
/// state the manifest author did not anticipate (a login method the account
/// never used, a schema change upstream), and silently moving on to the next
/// step would hide that behind whatever step happens to follow.
fn credentials_map_step(step: &AuthStep) -> Result<Option<String>, String> {
    let path = require_str("credentials-map", "path", step.path.as_deref())?;
    let key_prefix = require_str("credentials-map", "key_prefix", step.key_prefix.as_deref())?;
    let token_json_path = require_str(
        "credentials-map",
        "token_json_path",
        step.token_json_path.as_deref(),
    )?;

    let file = super::expand_home(path);
    if !file.is_file() {
        return Ok(None); // surface not present on this machine
    }
    let text = super::read_regular_file(&file, super::SMALL_FILE_MAX_BYTES)
        .ok_or_else(|| format!("{} is not a readable regular file", file.display()))?;
    let value: Value =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", file.display()))?;
    let object = value
        .as_object()
        .ok_or_else(|| format!("{} is not a JSON object", file.display()))?;

    // The filtered iterator is advanced a second time rather than stopping
    // at the first hit: a second match has to be noticed, not silently
    // shadowed by whichever entry the map happens to iterate first.
    let mut matches = object.iter().filter(|(key, _)| key.starts_with(key_prefix));
    let Some((_, entry)) = matches.next() else {
        return Err(format!(
            "no entry with a key starting with `{key_prefix}` in {}",
            file.display()
        ));
    };
    if matches.next().is_some() {
        return Err(format!(
            "more than one entry in {} has a key starting with `{key_prefix}` — cannot tell \
             which account's token to use",
            file.display()
        ));
    }
    extract_token_at(entry, token_json_path)
        .map(Some)
        .ok_or_else(|| {
            format!(
                "no token at `{token_json_path}` in the entry matching `{key_prefix}` in {}",
                file.display()
            )
        })
}

// ── Step: keychain (macOS) ────────────────────────────────────────────────

fn keychain_step(
    step: &AuthStep,
    lapsed_expiry: &mut Option<u64>,
) -> Result<Option<String>, String> {
    #[cfg(target_os = "macos")]
    {
        let service = require_str("keychain", "service", step.service.as_deref())?;
        let token_json_path = require_str(
            "keychain",
            "token_json_path",
            step.token_json_path.as_deref(),
        )?;
        match keychain_password(service)? {
            Some(raw) => {
                let json = unwrap_go_keyring(&raw)?;
                token_from_blob(
                    &json,
                    token_json_path,
                    step.expiry_json_path.as_deref(),
                    now_unix(),
                    &format!("Keychain item '{service}'"),
                    lapsed_expiry,
                )
            }
            None => Ok(None),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (step, lapsed_expiry);
        Ok(None)
    }
}

/// The Go `zalando/go-keyring` library — which Antigravity's CLI stores its
/// OAuth token through — base64-encodes any value it cannot keep as a plain
/// Keychain string and marks it with a `go-keyring-base64:` prefix. A value
/// without that prefix (every other Keychain item this app reads, e.g. Claude
/// Desktop's) is already the JSON it will be parsed as, and is returned
/// untouched: a JSON object opens with `{`, so it can never collide with this
/// prefix, which makes recognising the wrapper safe to do unconditionally
/// rather than behind a manifest key. Split out of `keychain_step` so the
/// decode is unit-tested without a real Keychain — hence the extra `test` arm
/// on this function's own `cfg`, so a non-macOS build (where `keychain_step`'s
/// `cfg(target_os = "macos")` block, its only caller, never runs) does not
/// warn it as dead code outside of `cargo test`.
///
/// `zalando/go-keyring` writes one of two markers, and reads both: the current
/// `go-keyring-base64:` (standard base64, what Antigravity's item carries and
/// what the library emits on every write) and the legacy `go-keyring-encoded:`
/// (hex, still accepted on read for items an older version stored). Both are
/// handled so an item written by any version this app might meet unwraps to the
/// same JSON — matching the library's own read path
/// (`keyring_darwin.go`), rather than the current write format alone.
#[cfg(any(target_os = "macos", test))]
fn unwrap_go_keyring(raw: &str) -> Result<String, String> {
    const BASE64_PREFIX: &str = "go-keyring-base64:";
    const HEX_PREFIX: &str = "go-keyring-encoded:";
    // Trim the whole value before matching the marker, the way go-keyring does
    // (`TrimSpace` precedes its `HasPrefix`): the live path already trims in
    // `classify_keychain_output`, but doing it here keeps this function correct
    // on its own — a leading newline would otherwise leave the marker unmatched
    // and hand the wrapped payload back as if it were plain JSON.
    let raw = raw.trim();
    let bytes = if let Some(encoded) = raw.strip_prefix(BASE64_PREFIX) {
        use base64::{engine::general_purpose::STANDARD, Engine};
        STANDARD
            .decode(encoded.trim())
            .map_err(|e| format!("Keychain item's go-keyring-base64 payload did not decode: {e}"))?
    } else if let Some(encoded) = raw.strip_prefix(HEX_PREFIX) {
        hex_decode(encoded.trim()).ok_or_else(|| {
            "Keychain item's go-keyring-encoded payload was not valid hex".to_string()
        })?
    } else {
        // No marker: every other Keychain item this app reads (Claude Desktop's)
        // is already the JSON it will be parsed as. A JSON object opens with
        // `{`, which neither prefix can begin with, so an unwrapped value is
        // returned untouched.
        return Ok(raw.to_string());
    };
    String::from_utf8(bytes)
        .map_err(|e| format!("Keychain item's go-keyring payload was not UTF-8: {e}"))
}

/// The token-or-lapsed decision shared by every step whose credential store
/// hands back one JSON blob holding both the token and (optionally) its
/// expiry: `keychain`, `credentials-file`, and `win-credential` on Windows
/// all parse the same shape (see each `AuthStep` field's own doc — they share
/// `token_json_path`'s fallback grammar too), so this is written once rather
/// than three times. Split out of `keychain_step` originally, so the expiry
/// fall-through is tested with a fixed "now" and no real Keychain.
///
/// The token is extracted *first*, and the expiry checked only once one is
/// actually in hand: a blob with a stale `expiry_json_path` but no token at
/// `token_json_path` at all (a malformed or half-written credentials file,
/// say) is the ordinary "not found" error below, never "lapsed" — a
/// credential that was never present has nothing for `[ping] renews_token`
/// to renew, and reading it as lapsed would run that ping over a blob this
/// step never actually recognised as a credential.
///
/// When `expiry_json_path` is set and the extracted token has lapsed, this
/// sets `*lapsed_expiry = Some(expires_at)` (the credential's own declared
/// expiry, read by [`stale_expiry`]) and resolves **Absent** (`Ok(None)`)
/// rather than handing back the stale token — so a step behind it in the
/// chain gets its turn, and [`resolve_token`] can still say *why* the chain
/// came up empty, and *which* token, if none does. `*lapsed_expiry` is only
/// ever set, never cleared or overwritten: the caller starts it `None` once
/// per surface, and the first step to find a lapsed credential is the one
/// whose expiry survives to the end — two stores disagreeing about the same
/// account's expiry is not a state worth choosing between (see
/// [`resolve_token`]'s own doc). A token with no expiry path, or one whose
/// expiry cannot be read, is returned as before: reading the expiry wrong
/// never turns a working credential into a missing one. `context` names the
/// store in the not-found error (`"Keychain item 'x'"`, a credentials-file's
/// own path, `"credential"` for a Windows Credential Manager target).
fn token_from_blob(
    json: &str,
    token_json_path: &str,
    expiry_json_path: Option<&str>,
    now: i64,
    context: &str,
    lapsed_expiry: &mut Option<u64>,
) -> Result<Option<String>, String> {
    let Some(token) = extract_token(json, token_json_path) else {
        return Err(format!(
            "not JSON, or no token at `{token_json_path}` in {context}"
        ));
    };
    if let Some(expiry_path) = expiry_json_path {
        if let Some(expires_at) = stale_expiry(json, expiry_path, now) {
            if lapsed_expiry.is_none() {
                *lapsed_expiry = Some(expires_at);
            }
            return Ok(None);
        }
    }
    Ok(Some(token))
}

/// Current wall-clock time as Unix seconds, `0` on any error (the clock
/// reads before the Unix epoch). Reserved for the one thing only the wall
/// clock can answer — a comparison against a timestamp this process did not
/// itself produce, e.g. an expiry a provider's own token carries
/// (`stale_expiry`) — plus seeding [`cache_now`] once at its own first
/// call. Every purely in-process pacing decision elsewhere in this module
/// (the refresh cache's expiry/backoff, the client discovery caches' own
/// backoff) reads [`cache_now`] instead, not this: see that function's own
/// doc for why a value that can be `0`, or can run backwards under a
/// stepped-back wall clock, is the wrong clock for a decision nothing
/// outside this process ever needs to agree with.
fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A large, made-up "now" [`cache_now`] falls back to when the wall clock
/// itself cannot produce one (`now_unix() == 0` — the clock reads before the
/// Unix epoch). Never compared against a real date; only ever against other
/// values [`cache_now`] itself built from this same fallback within the same
/// process, so the only property that matters is that it sits far from both
/// `0` and any plausible real `now_unix()` reading — `2^40` seconds is well
/// into the tens of thousands of years past the epoch, comfortably clear of
/// either.
const CACHE_CLOCK_FALLBACK_UNIX: i64 = 1i64 << 40;

/// [`cache_now`]'s clock base, set exactly once by whichever call reaches
/// [`cache_now`] first: the wall-clock reading at that moment (or
/// [`CACHE_CLOCK_FALLBACK_UNIX`] if the wall clock cannot produce one) paired
/// with the [`std::time::Instant`] taken in the same breath.
static CACHE_CLOCK_BASE: std::sync::OnceLock<(std::time::Instant, i64)> =
    std::sync::OnceLock::new();

/// The clock every purely in-process pacing decision in this module reads —
/// the refresh cache's `expires_at_unix`/`retry_after_unix`, and the client
/// discovery caches' own backoff — instead of [`now_unix`]. Built once per
/// process (see [`CACHE_CLOCK_BASE`]) from a wall-clock reading paired with
/// an [`std::time::Instant`], then always answered afterward by adding how
/// far the monotonic clock has moved since — never by reading the wall clock
/// again. That is what gives it the two properties none of these decisions
/// can do without, and a plain [`now_unix`] cannot promise:
///
/// * **never `0`** — a `0` "now" is `now_unix`'s own sentinel for "the wall
///   clock is broken", and every backoff/expiry comparison in this module
///   used to special-case it (`if now != 0 { … }`) rather than trust a
///   stored value against a broken clock. `cache_now` needs no such
///   special-casing: its fallback ([`CACHE_CLOCK_FALLBACK_UNIX`]) is nowhere
///   near `0`, so the comparisons that used to be skipped now simply run.
/// * **never runs backwards within the process** — [`std::time::Instant`] is
///   documented never to (on every platform this crate targets), so neither
///   can a value built only by adding its elapsed time to a base captured
///   once. A wall clock stepped backwards mid-process (an NTP correction, a
///   laptop waking with a bad RTC read) would otherwise hand two
///   consecutive calls a `retry_after` target that moves the wrong way — an
///   entry that "has not lapsed yet" by one reading and "lapsed already
///   ages ago" by the next, from the same backoff.
///
/// It does not need to be *correct* wall-clock time to do either job — only
/// monotonic and non-zero — but tracking the real wall clock (bar an actual
/// mid-process step) rather than counting from `0` keeps its values in the
/// same range as `now_unix`'s own. That is a resemblance, not an equivalence:
/// this function floors the wall clock once at init and separately floors
/// the elapsed time added on top, while `now_unix` floors their sum in one
/// step, so the two can read a second apart whenever the two fractional
/// parts carry past a whole second the other has not crossed yet. A test
/// that reasons about this module's caches — the refresh cache, the client
/// discovery caches — must build its own `now_before`/`now_after`/lookup
/// arguments from `cache_now()`, never `now_unix()`: the one second of
/// slack is exactly wide enough to flip an assertion pinned to a boundary.
fn cache_now() -> i64 {
    let &(start, base) = CACHE_CLOCK_BASE.get_or_init(|| {
        let wall = now_unix();
        let base = if wall == 0 {
            CACHE_CLOCK_FALLBACK_UNIX
        } else {
            wall
        };
        (std::time::Instant::now(), base)
    });
    base.saturating_add(start.elapsed().as_secs() as i64)
}

/// Whether the token in `json` has lapsed, judged by the value at
/// `expiry_path` — see [`token_expiry`] for the shapes read. Pure and
/// fail-safe: an expiry this cannot place in time at all, or places
/// somewhere implausible, reads as not stale — reading it wrong must never
/// discard a token that might still work, only ever let a provably-expired
/// one fall through.
///
/// `#[cfg(test)]`: [`token_from_blob`] needs the expiry itself
/// (`crate::model::TokenRenewal::Lapsed` is keyed on it) and calls
/// [`stale_expiry`] directly, so nothing in production asks this a plain
/// yes/no any more — kept as the readable bool assertion the numeric/margin
/// test surface below is written against.
#[cfg(test)]
fn token_is_stale(json: &str, expiry_path: &str, now: i64) -> bool {
    stale_expiry(json, expiry_path, now).is_some()
}

/// `token_is_stale`'s decision, but naming *which* expiry made it stale
/// rather than only answering yes/no: [`token_from_blob`] needs the number
/// itself so a renewal ping can be keyed on this one token
/// (`crate::model::TokenRenewal::Lapsed`), not merely told "something
/// lapsed" — a credential that stays lapsed (its own refresh token has
/// expired too, say, and the CLI now needs an interactive login) must be
/// pinged once, not once every ten minutes forever.
///
/// `Some(expires_at)` when [`token_expiry`] reads a timestamp at or before
/// `now` plus a 60-second margin (a token about to expire is already
/// treated as stale, so a refresh happens *before* a request would 401 on
/// it); `None` when it reads a later timestamp, or none at all.
fn stale_expiry(json: &str, expiry_path: &str, now: i64) -> Option<u64> {
    const MARGIN_SECS: i64 = 60;
    let expires_at = token_expiry(json, expiry_path)?;
    // `expires_at` came from `expiry_seconds`'s own `i64`, never negative
    // either way it was produced (the numeric branch is bounded below by
    // `MIN_PLAUSIBLE_EXPIRY_UNIX`, the RFC3339 branch clamps to 0), so
    // converting it back to compare against `now` never wraps.
    let expires_at_i64 = i64::try_from(expires_at).ok()?;
    (expires_at_i64 <= now.saturating_add(MARGIN_SECS)).then_some(expires_at)
}

/// The value at `expiry_path` inside `json`, read as Unix seconds: an
/// RFC3339 timestamp (Antigravity's `token.expiry`), or a JSON
/// number/numeric string read as epoch seconds or milliseconds (Claude's
/// `claudeAiOauth.expiresAt`) — see [`expiry_seconds`] for how the two
/// numeric shapes are told apart. `None` when `json` doesn't parse,
/// `expiry_path` doesn't resolve, or the value there is neither shape
/// [`expiry_seconds`] reads.
fn token_expiry(json: &str, expiry_path: &str) -> Option<u64> {
    let value: Value = serde_json::from_str(json).ok()?;
    let expiry_value = json_path_value(&value, expiry_path)?;
    u64::try_from(expiry_seconds(expiry_value)?).ok()
}

/// The absolute floor a normalized `expiry_json_path` value's Unix seconds
/// must clear to be trusted at all — 2000-01-01T00:00:00Z. Below it,
/// [`expiry_seconds`] answers `None` (unreadable) rather than a timestamp: no
/// OAuth token this app has ever seen expires before this app existed, so a
/// number that small is a schema this manifest did not anticipate (a
/// counter, an offset, a placeholder) rather than a real expiry — and per
/// [`stale_expiry`]'s own fail-safe, an expiry that cannot be trusted must
/// never mark a token stale.
const MIN_PLAUSIBLE_EXPIRY_UNIX: i64 = 946_684_800;

/// How large a normalized `expiry_json_path` number has to be before
/// [`expiry_seconds`] reads it as epoch milliseconds rather than seconds:
/// `1e11`. `1e11` seconds is the year 5138 — no genuine expiry states
/// that — and `1e11` milliseconds is 1973, comfortably inside the plausible
/// range once divided down. No real seconds-scale timestamp this app will
/// see before the year 5138 can be misread as milliseconds by this line, and
/// no genuine millisecond-scale one (any expiry this century) reads as
/// anything but.
const MS_MAGNITUDE_THRESHOLD: i64 = 100_000_000_000;

/// One `expiry_json_path` value read as Unix seconds: an RFC3339 string, or —
/// because a CLI's own credentials file is at least as likely to state an
/// expiry as a plain epoch number (Claude's `claudeAiOauth.expiresAt` is
/// epoch milliseconds) — a JSON number or a numeric string, read through
/// [`crate::plugin::time::read_unix_timestamp`] and then told seconds from
/// milliseconds by magnitude ([`MS_MAGNITUDE_THRESHOLD`]).
///
/// [`MIN_PLAUSIBLE_EXPIRY_UNIX`] only guards the numeric branch: a bare
/// number below it is a schema this manifest did not anticipate (a counter,
/// an offset), not a real expiry, so it reads as unreadable rather than
/// stale. An RFC3339 string is not ambiguous that way — parsing it at all
/// already says the field holds a date — so any date it names, however old,
/// is trusted; a pre-1970 one clamps to 0 (matching
/// [`crate::plugin::time::parse_iso8601`]'s own convention) rather than
/// going negative or being discarded, so it reads as maximally stale
/// instead of unreadable. `None` when `value` is neither shape, or when it
/// is a string that parses as neither RFC3339 nor a number.
fn expiry_seconds(value: &Value) -> Option<i64> {
    if let Some(rfc3339) = value
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
    {
        return Some(rfc3339.timestamp().max(0));
    }
    let unix = i64::try_from(super::time::read_unix_timestamp(value)?).ok()?;
    let raw = if unix >= MS_MAGNITUDE_THRESHOLD {
        unix / 1000
    } else {
        unix
    };
    (raw >= MIN_PLAUSIBLE_EXPIRY_UNIX).then_some(raw)
}

/// Decode a hex string to bytes, `None` on any non-hex byte or an odd length.
/// Small and local rather than a dependency: it is used on exactly one legacy
/// code path (see [`unwrap_go_keyring`]).
///
/// Works over `s.as_bytes()`, never `&s[i..i+2]`: a hex digit is one ASCII byte,
/// and byte-slicing a `&str` panics across a UTF-8 char boundary — so a
/// multi-byte character in a corrupt payload would crash the credential path
/// (which must return `Err`, never panic) instead of being rejected. Any
/// non-ASCII byte simply fails `is_ascii_hexdigit` and yields `None`.
#[cfg(any(target_os = "macos", test))]
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

// ── Step: env ─────────────────────────────────────────────────────────────

fn env_step(step: &AuthStep) -> Result<Option<String>, String> {
    let var = require_str("env", "var", step.var.as_deref())?;
    // A set-but-blank variable is Absent, not a present empty token — the
    // same rule every other step's token lookup applies (see
    // `client_env_pair`'s identical filter), so unsetting a shell export by
    // exporting it empty behaves the same as not exporting it at all.
    Ok(std::env::var(var).ok().filter(|v| !v.trim().is_empty()))
}

// ── Step: electron-safe-storage ───────────────────────────────────────────

/// The Chromium/Electron Safe Storage payload this app cares about is always
/// the Claude desktop app's `claudeAiOauth`/`access_token` shape, so this is
/// the default `token_json_path` when a manifest doesn't set one for this
/// step (the real seed manifest doesn't — see module docs on
/// `crate::plugin::manifest::AuthStep::token_json_path`).
const ELECTRON_DEFAULT_TOKEN_JSON_PATH: &str = "claudeAiOauth.accessToken|access_token";

fn electron_safe_storage_step(step: &AuthStep) -> Result<Option<String>, String> {
    let config_path = require_str(
        "electron-safe-storage",
        "config_path",
        step.config_path.as_deref(),
    )?;
    let blob_json_path = require_str(
        "electron-safe-storage",
        "blob_json_path",
        step.blob_json_path.as_deref(),
    )?;
    let token_json_path = step
        .token_json_path
        .as_deref()
        .unwrap_or(ELECTRON_DEFAULT_TOKEN_JSON_PATH);

    let file = super::expand_home(config_path);
    if !file.is_file() {
        return Ok(None); // desktop app not installed
    }
    // Regular and bounded, same as `credentials_file_step`: this path also
    // comes from a manifest, and a fetch thread blocked reading a FIFO never
    // reports back at all.
    let text = super::read_regular_file(&file, super::SMALL_FILE_MAX_BYTES)
        .ok_or_else(|| format!("{} is not a readable regular file", file.display()))?;
    let value: Value =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", file.display()))?;
    let enc = match extract_token_at(&value, blob_json_path) {
        Some(enc) => enc,
        None => return Ok(None), // config present but never logged in
    };

    use base64::{engine::general_purpose::STANDARD, Engine};
    let blob = STANDARD
        .decode(enc.trim())
        .map_err(|e| format!("base64: {e}"))?;

    let plain = match electron_decrypt(&blob, step.macos_keychain_key.as_deref())? {
        Some(p) => p,
        // The Keychain item that holds the Safe Storage key doesn't exist
        // (e.g. desktop app config present but never actually logged in, or
        // reinstalled without a fresh Keychain entry) — Absent, not
        // Present-err: the whole step is skipped rather than surfaced as an
        // inline error, per the three-way classification in the module docs.
        None => return Ok(None),
    };
    token_from_decrypted(&plain, token_json_path)
        .map(Some)
        .ok_or_else(|| format!("not JSON, or no token at `{token_json_path}` in decrypted payload"))
}

/// Extract the token from a decrypted Safe Storage payload, which may carry
/// trailing bytes after the JSON (PKCS7 padding remnants, a stray byte the
/// scheme leaves behind); cut at the JSON's own top-level closing brace
/// first, via [`first_top_level_object_end`] — not the *last* `}` anywhere
/// in the buffer, which the trailing bytes can push past the real one (see
/// that function's own doc).
fn token_from_decrypted(plain: &[u8], token_json_path: &str) -> Option<String> {
    let json = String::from_utf8_lossy(plain);
    let json = match first_top_level_object_end(&json) {
        Some(end) => &json[..end],
        None => &json,
    };
    extract_token(json, token_json_path)
}

/// The byte offset one past the closing `}` of the first top-level JSON
/// object in `text`, tracking brace depth and skipping the contents of
/// quoted strings (a `}` or an escaped `"` a value happens to contain must
/// never be mistaken for a structural one) — `None` if `text` never opens an
/// object, or never closes the one it opens. Deliberately the *first*
/// top-level close, not the last `}` anywhere in `text`: a decrypted Safe
/// Storage payload can carry trailing bytes past the JSON `serde_json`
/// itself wrote, and if those bytes happen to contain a `}` of their own, a
/// scan for the last one in the whole buffer would include that garbage in
/// what gets handed to `serde_json` — reporting an object that fails to
/// parse instead of the valid one that was actually there.
fn first_top_level_object_end(text: &str) -> Option<usize> {
    let mut depth: i32 = 0;
    let mut in_string = false;
    let mut escaped = false;
    let mut opened = false;
    for (i, ch) in text.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' => {
                depth += 1;
                opened = true;
            }
            '}' => {
                depth -= 1;
                if opened && depth == 0 {
                    return Some(i + ch.len_utf8());
                }
            }
            _ => {}
        }
    }
    None
}

/// `Ok(Some(bytes))` — decrypted; `Ok(None)` — either the Keychain item that
/// holds the Safe Storage key doesn't exist on this machine, or this OS has
/// no Safe Storage backend at all (Absent either way, the caller must treat
/// both the same as "config not present" — the same convention every other
/// step's off-platform arm follows, e.g. `keychain_step`'s); `Err` — the
/// item exists but couldn't be read (access denied) or decryption itself
/// failed.
fn electron_decrypt(
    blob: &[u8],
    macos_keychain_key: Option<&str>,
) -> Result<Option<Vec<u8>>, String> {
    #[cfg(target_os = "macos")]
    {
        let service = require_str(
            "electron-safe-storage",
            "macos_keychain_key",
            macos_keychain_key,
        )?;
        match keychain_password(service)? {
            Some(pw) => safe_storage_decrypt(blob, &pw).map(Some),
            None => Ok(None), // Keychain item not found -> Absent, not an error
        }
    }
    #[cfg(target_os = "windows")]
    {
        let _ = macos_keychain_key;
        windows_dpapi_decrypt(blob).map(Some)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        // No Safe Storage backend on this OS at all — Absent, not an error,
        // the same as a `keychain`/`win-credential` step's own off-platform
        // arm: the chain moves on to whatever step follows rather than
        // reporting a store that was never going to exist here as broken.
        let _ = (blob, macos_keychain_key);
        Ok(None)
    }
}

// ── Step: win-credential (Windows) ────────────────────────────────────────

#[cfg(target_os = "windows")]
fn win_credential_step(
    step: &AuthStep,
    lapsed_expiry: &mut Option<u64>,
) -> Result<Option<String>, String> {
    let targets = require_vec("win-credential", "targets", step.targets.as_deref())?;
    let token_json_path = require_str(
        "win-credential",
        "token_json_path",
        step.token_json_path.as_deref(),
    )?;
    // Tolerant of any per-target failure (not found, a blob present but
    // without the token at `token_json_path`, or one whose declared expiry
    // has lapsed): try the next target name; only if every target comes up
    // empty is the whole step Absent. A target that *is* found but doesn't
    // yield a token moves on rather than stopping there — Claude's manifest
    // ships two Credential Manager targets, and the first one existing with
    // the wrong shape (or a lapsed token) must not hide a token sitting in
    // the second. The last such error is only returned if no later target
    // produces a token either — a lapsed target sets `lapsed_expiry` but
    // leaves `last_err` alone, the same "Absent, not broken" treatment
    // `token_from_blob` gives every other step it backs.
    let mut last_err = None;
    for target in targets {
        if let Some(raw) = win_credential(target) {
            match token_from_blob(
                &raw,
                token_json_path,
                step.expiry_json_path.as_deref(),
                now_unix(),
                "credential",
                lapsed_expiry,
            ) {
                Ok(Some(token)) => return Ok(Some(token)),
                Ok(None) => {} // lapsed — `token_from_blob` already recorded it
                Err(e) => last_err = Some(e),
            }
        }
    }
    match last_err {
        Some(err) => Err(err),
        None => Ok(None),
    }
}

#[cfg(not(target_os = "windows"))]
fn win_credential_step(
    _step: &AuthStep,
    _lapsed_expiry: &mut Option<u64>,
) -> Result<Option<String>, String> {
    Ok(None)
}

// ── Step: oauth-refresh ───────────────────────────────────────────────────

/// One cache entry: either a token good until a Unix second, or a failed
/// exchange not to be retried until one. The second half is a backoff — a
/// refresh that 4xxs (a revoked grant, say) must not be re-attempted on every
/// tick, or the step floods the token endpoint with a valid client id and
/// earns a 429 for the whole client.
///
/// Only `Failed` carries the `client_id` (and a hash of the `client_secret`
/// — never the secret itself, same discipline as [`REFRESH_CACHE`]'s own
/// key) it was produced with — not part of the *key* (see
/// [`refresh_cache_key`]), but readable at lookup time so a `Backoff` hit
/// can tell a still-relevant failure apart from one that belongs to a pair
/// this config no longer uses, rotated secret included: a client id an
/// operator keeps while only replacing its secret must still be retried
/// right away, not punished for the old secret's failure. `Fresh`
/// deliberately does **not** carry either, even though an earlier version of
/// this change did: a still-valid access token is served purely by expiry,
/// exactly the fix this whole change makes (see [`REFRESH_CACHE`]'s own
/// doc) — comparing it against a freshly-*resolved* pair on every `Fresh`
/// hit would mean resolving the client on every hit, reopening the very
/// hole ("a transient discovery miss must not discard a still-valid cached
/// access token") this closes. `Backoff` has no such risk: there is no
/// valid token to discard by resolving there, only a decision between
/// "still backed off" and "try again now". `Failed` also carries the
/// message the failed attempt produced, so a `Backoff` hit that is not
/// retried can report exactly why the last attempt failed instead of a
/// message that says only that one happened.
enum CacheEntry {
    Fresh {
        access_token: String,
        expires_at_unix: i64,
    },
    Failed {
        retry_after_unix: i64,
        client_id: String,
        secret_hash: u64,
        message: String,
    },
}

/// The three answers a cache lookup can give.
enum CacheLookup {
    /// A token still inside its life — return it, no exchange, and — the
    /// whole point of *not* keying on `client_id` — no need to resolve the
    /// client pair at all to serve it.
    Hit(String),
    /// A recent failure still in its backoff — the `client_id`/`secret_hash`
    /// it failed with, so this can tell "still that pair, do not exchange
    /// again yet" from "the pair has since changed, retry immediately" —
    /// and the message it failed with, for when it is still that pair.
    Backoff {
        client_id: String,
        secret_hash: u64,
        message: String,
    },
    /// Nothing usable cached — go exchange.
    Miss,
}

/// In-memory cache keyed on a hash of `(token_url, refresh_token)`, never
/// either in the clear. The point is pacing: `oauth_refresh_step` runs inside
/// `resolve_token`, which runs ahead of `throttle::decide` (see
/// `engine_http::fetch_surface`) — so without a cache it would exchange a
/// token on every panel open, every Refresh, every tick, and a fresh token
/// each time would move `throttle::fingerprint(&token, …)` and defeat the
/// cache one layer up too. Keyed by expiry, the same token comes back for its
/// life (~an hour) and the fingerprint holds, so `throttle.rs` stays frozen.
///
/// `client_id` is deliberately **not** part of the key (it used to be — see
/// [`CacheEntry`]'s own doc for where it moved). A `client` table's
/// discovery scan is exactly the cost this cache exists to avoid paying on
/// every tick, and `oauth_refresh_step` reads this cache *before* resolving
/// the pair, precisely so a transient discovery miss (the miss-cache
/// backoff active, a candidate that failed to read this tick, …) can never
/// discard a still-valid cached access token — the token remains a valid
/// credential regardless of which currently-configured pair would resolve
/// right now. The one place the id still matters is a `Backoff` hit: there,
/// `oauth_refresh_step` resolves the pair specifically to compare it against
/// the entry's stored `client_id` — so a rotated or corrected pair bypasses
/// the old failure's backoff rather than being punished for it, but only
/// when `resolve_pair` actually comes back with the new one right then and
/// there: for a `client` table, that still costs whatever the discovery
/// scan (or its own miss-cache backoff) costs, "immediately" only in the
/// sense of "not made to wait out `REFRESH_BACKOFF_SECS` on top". The literal
/// `client_id`/`client_secret` fields, and the env-var override
/// (`client_env_pair`), have no cache of their own and *are* re-read fresh
/// on every single call — for those two sources alone is a rotation retried
/// immediately in the plain sense.
///
/// Nor does the key carry anything about *which surface or manifest* is
/// asking: two `oauth-refresh` steps — in the same manifest, or two
/// different ones — that happen to read the same `token_json_path` out of
/// the same `path` and send it to the same `token_url` collide on this key
/// and share one entry. Accepted rather than guarded against, because it is
/// correct, not merely harmless: the token such a pair produces is a fact
/// about the account behind the OAuth server, not about which manifest's
/// config asked for it, so a `Fresh` hit for one is a `Fresh` hit for the
/// other and a `Failed` backoff for one really does mean the other would
/// fail identically right now — the exact same exchange, byte for byte,
/// would be sent either way. Two surfaces reading the *same* refresh-token
/// file already share the credential itself; sharing the pacing cache over
/// it besides costs nothing beyond what was already shared.
///
/// That separation is by distinctness, not by proof: this is a 64-bit hash,
/// and two pairs that collided would share an entry. Left as a hash
/// deliberately — engineering a collision means authoring both manifests,
/// and a manifest that far in can already read the same token file and send
/// it to a host of its own choosing, so the collision buys nothing that was
/// not already available. The map is process-local and dies with the
/// process — and does not merely grow for the rest of it: see
/// [`refresh_cache_store`]'s own doc for the prune that keeps it from
/// holding one entry forever per distinct pair this process has ever seen.
///
/// Every `Mutex` this module keeps recovers from poison the same way
/// (`.lock().unwrap_or_else(|e| e.into_inner())`, `throttle::with_state`'s
/// own convention): a panic in some other thread while holding one of these
/// must not be what stops this module's caching and diagnostics from ever
/// working again for the rest of the process.
static REFRESH_CACHE: std::sync::Mutex<Option<std::collections::HashMap<u64, CacheEntry>>> =
    std::sync::Mutex::new(None);

/// A stable, non-reversible key over `(token_url, refresh_token)` — see
/// [`REFRESH_CACHE`]'s own doc for why `client_id` is not a third input here
/// even though it once was.
fn refresh_cache_key(token_url: &str, refresh_token: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    // Length-prefixed so `("ab","c")` and `("a","bc")` cannot collide by
    // concatenation.
    for part in [token_url, refresh_token] {
        part.len().hash(&mut hasher);
        part.hash(&mut hasher);
    }
    hasher.finish()
}

/// A non-reversible fingerprint of a `client_secret`, stored in
/// [`CacheEntry::Failed`] instead of the secret itself — the same "never
/// either in the clear" discipline [`REFRESH_CACHE`]'s own key follows.
/// Distinctness, not proof, exactly as that key's own doc says of itself: a
/// hash collision would mean a different secret is read back as
/// unchanged, but engineering one buys an attacker nothing they could not
/// already do with the secret in hand.
fn secret_hash(secret: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    secret.len().hash(&mut hasher);
    secret.hash(&mut hasher);
    hasher.finish()
}

/// What the cache holds for `key` as of `now`.
fn refresh_cache_lookup(key: u64, now: i64) -> CacheLookup {
    let guard = REFRESH_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref().and_then(|m| m.get(&key)) {
        Some(CacheEntry::Fresh {
            access_token,
            expires_at_unix,
        }) if *expires_at_unix > now => CacheLookup::Hit(access_token.clone()),
        Some(CacheEntry::Failed {
            retry_after_unix,
            client_id,
            secret_hash,
            message,
        }) if *retry_after_unix > now => CacheLookup::Backoff {
            client_id: client_id.clone(),
            secret_hash: *secret_hash,
            message: message.clone(),
        },
        _ => CacheLookup::Miss,
    }
}

/// The message the most recent `Failed` entry stored under `key` carries,
/// whether or not its own `retry_after_unix` has lapsed — unlike
/// [`refresh_cache_lookup`], which folds a lapsed `Failed` into `Miss`
/// exactly as if nothing were cached at all, because a `Backoff` result is
/// specifically "still being retried against". This answers the opposite
/// question, for the one caller that needs it (`oauth_refresh_step`'s own
/// `Miss` arm): "did anything fail recently enough to still be worth
/// reporting", for the window between the refresh backoff itself lapsing
/// and a `client` table's own, longer discovery-miss backoff still
/// declining to even attempt a rescan. `None` for a `Fresh` entry too — a
/// still-valid token was never a failure to report, and
/// `refresh_cache_lookup` would have served it as a `Hit` long before this
/// is ever reached — and `None` once [`refresh_cache_store`]'s own grace
/// period has pruned the entry away entirely.
fn refresh_cache_last_failed_message(key: u64) -> Option<String> {
    let guard = REFRESH_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref()?.get(&key)? {
        CacheEntry::Failed { message, .. } => Some(message.clone()),
        CacheEntry::Fresh { .. } => None,
    }
}

/// How long a `Failed` entry is kept past its own `retry_after_unix` before
/// [`refresh_cache_store`]'s prune sweep removes it — longer than
/// [`REFRESH_BACKOFF_SECS`] itself, and pinned to
/// [`CLIENT_DISCOVERY_RETRY_SECS`] (the longer of the two client-discovery
/// backoffs) rather than picked independently, because that is exactly how
/// long [`refresh_cache_last_failed_message`]'s one caller may still need to
/// read this entry after the refresh backoff it was stored under has
/// already lapsed (see that function's own doc, and the `Miss` arm in
/// `oauth_refresh_step`). A `Fresh` entry needs no such grace — nothing
/// reads a dead access token's own value once it has expired — so only
/// `Failed` entries get one; see [`refresh_cache_store`]'s own doc for where
/// that split is made.
const REFRESH_CACHE_FAILED_GRACE_SECS: i64 = CLIENT_DISCOVERY_RETRY_SECS;

/// Store an entry (fresh token or a failure to back off from) under `key`,
/// first dropping every entry in the map — not only this one — whose own
/// life or backoff (plus, for a `Failed` entry, its
/// [`REFRESH_CACHE_FAILED_GRACE_SECS`] grace period) has already passed as
/// of [`cache_now`]. Nothing else in this module ever removes an entry:
/// without this sweep, a process that goes on to see many distinct
/// `(token_url, refresh_token)` pairs over its life — an operator rotating
/// between accounts on the same surface, a manifest reinstalled with a
/// fresh refresh token — would keep every stale one forever, one `HashMap`
/// entry per pair for as long as the process runs: cheap individually,
/// unbounded in aggregate. Pruned on every store rather than capped by
/// size: a size cap would drop whichever entry a `HashMap`'s own iteration
/// order happens to land on first, which could just as easily be the one
/// still live.
fn refresh_cache_store(key: u64, entry: CacheEntry) {
    let now = cache_now();
    let mut guard = REFRESH_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(std::collections::HashMap::new);
    map.retain(|_, e| match e {
        CacheEntry::Fresh {
            expires_at_unix, ..
        } => *expires_at_unix > now,
        CacheEntry::Failed {
            retry_after_unix, ..
        } => retry_after_unix.saturating_add(REFRESH_CACHE_FAILED_GRACE_SECS) > now,
    });
    map.insert(key, entry);
}

/// How long a failed exchange is not retried, in seconds. Must be well over one
/// fetch interval (`refresh_secs`, 60 for Antigravity), or the backoff is a
/// no-op: stored as `now + 60` it would already have passed by the next tick at
/// `now + 60`, and a persistently revoked grant would hit the endpoint every
/// tick — the 429 this exists to prevent. Five minutes is several ticks, still
/// short enough that a fresh sign-in is picked up promptly.
const REFRESH_BACKOFF_SECS: i64 = 300;

/// The one auth step that spends a credential instead of only reading one —
/// exchanging a stored `refresh_token` for a fresh `access_token` over the
/// network, for Google's Antigravity. `path`/`token_json_path` name the file
/// and the refresh token inside it; `token_url`/`client_id`/`client_secret`
/// are what OAuth2's refresh grant (RFC 6749 §6) needs. The fresh token is
/// handed back and **never written anywhere**: the file at `path` belongs to
/// Antigravity's own client, and overwriting it is the same intrusion this
/// project refused for Codex, for the same reason.
///
/// It exists because every other step here follows "read, never renew", and
/// for Antigravity that alone would report "sign in again" almost always: the
/// access token on disk goes stale in hours whenever the IDE that would refresh
/// it isn't running (measured, see the provider spec). Placed *after* an
/// expiry-aware keychain step in the chain, so the common case — Antigravity
/// running, keychain token fresh — never reaches the network at all; this fires
/// only when that token has lapsed.
///
/// The scheme/host allow-list check runs *first*, ahead of everything else
/// this step does: reading `token_url` out of the already-parsed manifest
/// costs nothing, so a misconfigured (or actively probing) manifest never
/// gets to charge for even opening the refresh-token file, let alone a
/// `client` table's discovery scan (a candidate hundreds of megabytes long)
/// or the cache read that follows. Checked here because `resolve_token` runs
/// ahead of the engine's own `allowed_hosts` check; an empty list — which
/// reads as "no restriction" everywhere else `host_allowed` is used — is
/// refused outright, since this step always sends a credential. The scheme
/// check reads the host through [`super::https_host`] rather than a
/// hand-rolled `starts_with("https://")` — the same WHATWG parser
/// `manifest::validate` reads a `token_url` through at load, so a URL that
/// passed validation there (`Url::parse` lowercases the scheme, so
/// `HTTPS://…` is valid `https` to it) is never rejected here, forever, by a
/// second, stricter parser that disagrees with the first.
///
/// The cache read itself runs *before* the pair is resolved (see
/// [`REFRESH_CACHE`]'s own doc) — a `Hit` needs no client at all, and a
/// `Backoff` resolves one only to compare it against the entry's own
/// `client_id`.
fn oauth_refresh_step(step: &AuthStep, allowed_hosts: &[String]) -> Result<Option<String>, String> {
    let path = require_str("oauth-refresh", "path", step.path.as_deref())?;
    let token_json_path = require_str(
        "oauth-refresh",
        "token_json_path",
        step.token_json_path.as_deref(),
    )?;
    let token_url = require_str("oauth-refresh", "token_url", step.token_url.as_deref())?;

    if super::https_host(token_url).is_none() {
        return Err(format!("`oauth-refresh` token_url must be https — refusing to send a refresh token over {token_url}"));
    }
    if allowed_hosts.is_empty() || !host_allowed(allowed_hosts, token_url) {
        return Err(format!(
            "surface's `allowed_hosts` does not include `token_url`'s host — refusing to send a \
             refresh token to {token_url}"
        ));
    }

    // The refresh-token file next, now that the request this step would
    // eventually make is known to be allowed at all: someone who has never
    // signed in to this surface has nothing at `path` — the common case for
    // most people this manifest reaches — but that check comes *after* the
    // allow-list precisely so a manifest whose `token_url` was never going
    // to be permitted does not even get to read a file that might not be
    // there, before a `client` table's discovery scan (hundreds of
    // megabytes) is reached either.
    let file = super::expand_home(path);
    if !file.is_file() {
        return Ok(None); // not signed in here, or never has been
    }
    let text = super::read_regular_file(&file, super::SMALL_FILE_MAX_BYTES)
        .ok_or_else(|| format!("{} is not a readable regular file", file.display()))?;
    let refresh_token = extract_token(&text, token_json_path).ok_or_else(|| {
        format!(
            "no refresh token at `{token_json_path}` in {}",
            file.display()
        )
    })?;

    // The installed-app pair, resolved only where it is actually needed
    // below (a cache `Hit` never calls this). Without a `client` table this
    // is the step's original, simpler contract: `client_id`/`client_secret`
    // are required fields, missing either is Present-err, same as ever —
    // every existing manifest that still ships them literally is unaffected.
    // With one, `resolve_client` tries the env override, then discovery from
    // the installed client's own binaries (a manifest may no longer set both
    // a `client` table and the literal fields — `manifest::validate` refuses
    // that combination, so the literal fields are never read once `client`
    // is set) — and "found nothing this run" is `Ok(None)`, not an error,
    // since a client that hasn't been installed yet is exactly the same
    // shape as a credential store that isn't there.
    let resolve_pair = || -> Result<Option<(String, String)>, String> {
        if step.client.is_some() {
            Ok(resolve_client(step))
        } else {
            let client_id = require_str("oauth-refresh", "client_id", step.client_id.as_deref())?;
            let client_secret = require_str(
                "oauth-refresh",
                "client_secret",
                step.client_secret.as_deref(),
            )?;
            Ok(Some((client_id.to_string(), client_secret.to_string())))
        }
    };

    // Pacing: a still-live token comes straight back — no client resolved at
    // all — and a recent failure is not retried until its backoff passes,
    // *unless* the pair has since changed (see `REFRESH_CACHE`'s own doc).
    // `now` comes from `cache_now`, not `now_unix`: every comparison below is
    // purely in-process (nothing here is checked against a timestamp the
    // network handed back), so this takes the clock that is guaranteed
    // never to be zero and never to run backwards mid-process rather than
    // the wall clock a stepped-back correction could otherwise hand two
    // consecutive calls in the wrong order — see `cache_now`'s own doc. A
    // `Backoff` hit that cannot resolve *any* pair right now reports the
    // same backoff error a still-current pair would (see that arm below for
    // why) rather than falling to Absent — unlike `Miss`'s own `None` arm,
    // which normally has no cached failure to report and stays Absent,
    // except for the one case that arm itself carves out below.
    let now = cache_now();
    let key = refresh_cache_key(token_url, &refresh_token);
    let (client_id, client_secret) = match refresh_cache_lookup(key, now) {
        CacheLookup::Hit(token) => return Ok(Some(token)),
        CacheLookup::Backoff {
            client_id: cached_id,
            secret_hash: cached_secret_hash,
            message,
        } => match resolve_pair()? {
            Some(pair) if pair.0 != cached_id || secret_hash(&pair.1) != cached_secret_hash => pair,
            Some(_) => {
                return Err(message);
            }
            // Nothing resolves right now: unlike `Some(_)` just above
            // (proven to be the exact same pair that failed), there is
            // no pair here at all to compare against the one that
            // failed — no proof either way that it has changed. This
            // used to resolve Absent anyway, the same as `Miss`'s own
            // `None` arm below, but a client that cannot currently be
            // resolved is very often exactly *why* the exchange failed
            // in the first place — a binary mid-reinstall, or
            // `on_exchange_error`'s own `client_discovery_evict` having
            // just armed a fresh discovery-miss backoff over it (see
            // that function's own doc) — and Absent silently hides the
            // row instead of explaining it, for as long as this cache
            // entry's own backoff says the failure is still current.
            // Reporting the same `message` the proven-unchanged case
            // above reports keeps the row, and the reason, visible
            // until this backoff lapses; only then does an
            // unresolvable client fall back to Absent, same as
            // `Miss`'s own arm.
            None => return Err(message),
        },
        CacheLookup::Miss => {
            // Read *before* `resolve_pair` runs, not after: a `client`
            // table's own discovery arms a fresh miss backoff as a matter
            // of course whenever a scan completes and finds nothing (see
            // `discover_client_within`'s own doc), so checking after the
            // call would always see one just armed by this very attempt —
            // indistinguishable from a scan that was blocked from running
            // at all. What this needs is the state *before* the call: was
            // discovery already declining to even attempt a rescan this
            // tick, the one case where `resolve_pair` coming back empty
            // means "backed off", not "looked and found nothing".
            let discovery_was_already_backed_off = step
                .client
                .as_ref()
                .is_some_and(|client| client_discovery_miss_lookup(client_config_key(client), now));
            match resolve_pair()? {
                Some(pair) => pair,
                None => {
                    // `refresh_cache_lookup` reports `Miss` here whether
                    // nothing was ever cached, or the last failure's own
                    // `REFRESH_BACKOFF_SECS` backoff has since lapsed — and
                    // a `client` table's own discovery-miss backoff
                    // (`CLIENT_DISCOVERY_RETRY_SECS`/`_TRUNCATED_RETRY_SECS`)
                    // is longer than that refresh backoff, so there is a
                    // real window where the refresh cache has moved on to
                    // `Miss` but `resolve_pair` still comes back empty
                    // because discovery itself declined to even attempt a
                    // rescan this tick — not because a fresh scan looked and
                    // found nothing. Reported the same way the `Backoff`
                    // arm's own unresolvable-client case is: the last
                    // message this cache entry remembers, if it still
                    // remembers one, rather than silently falling to Absent
                    // and losing the reason along with the row. A genuine
                    // first-time (or backoff-expired) scan that simply finds
                    // nothing installed stays Absent, exactly as it always
                    // has.
                    if discovery_was_already_backed_off {
                        if let Some(message) = refresh_cache_last_failed_message(key) {
                            return Err(message);
                        }
                    }
                    return Ok(None);
                }
            }
        }
    };

    // A failed exchange, and a 200 that carried no usable token, both back
    // off, so a stuck endpoint is not hit on every tick with no exchange
    // ever succeeding. The message is stored alongside it, so a later
    // `Backoff` hit that is not retried can report exactly this failure
    // rather than a placeholder that only says one happened.
    let store_backoff = |message: String| {
        refresh_cache_store(
            key,
            CacheEntry::Failed {
                retry_after_unix: now.saturating_add(REFRESH_BACKOFF_SECS),
                client_id: client_id.clone(),
                secret_hash: secret_hash(&client_secret),
                message,
            },
        );
    };
    let response =
        match oauth_refresh_request(token_url, &client_id, &client_secret, &refresh_token) {
            Ok(r) => r,
            Err(e) => {
                store_backoff(e.clone());
                on_exchange_error(step, &e);
                return Err(e);
            }
        };
    let (access_token, expires_in) = match extract_access_token(&response) {
        Some(v) => v,
        None => {
            // A 200 with no token (or one too short-lived to cache usefully) is
            // still a reason to back off — otherwise a stuck endpoint is hit
            // every tick with no exchange ever succeeding.
            let message = "token refresh response carried no usable access_token".to_string();
            store_backoff(message.clone());
            return Err(message);
        }
    };
    // A 60s margin, same as the keychain step's, so the cached token is
    // retired before a request would 401 on it. `saturating_*` so a
    // hostile/huge `expires_in` cannot overflow the clock — belt and braces
    // alongside `extract_access_token`'s own clamp to `EXPIRES_IN_MAX_SECS`,
    // which is what actually keeps a dead token from being served forever
    // (see that constant's own doc). `extract_access_token` already
    // rejected anything `<= 60`, so `expires_at` is always ahead of `now`
    // here.
    let expires_at = now.saturating_add(expires_in).saturating_sub(60);
    refresh_cache_store(
        key,
        CacheEntry::Fresh {
            access_token: access_token.clone(),
            expires_at_unix: expires_at,
        },
    );
    Ok(Some(access_token))
}

/// Reacts to a failed exchange the one way that matters beyond the caller's
/// own backoff: `is_invalid_client(err)` means the *pair itself* is wrong,
/// not merely that this attempt failed — a discovered pair cached from
/// before the client was reinstalled with a new secret, say. Evicting here
/// means the stale pair is never replayed again — but not that the very
/// next attempt rescans: `client_discovery_evict` also arms a fresh
/// [`CLIENT_DISCOVERY_RETRY_SECS`] miss backoff over the same config (see
/// its own doc), so a rescan only happens once *that* has lapsed too, the
/// same as any other discovery miss. Without evicting the found-cache entry
/// at all, though, the stale pair would keep being served for as long as
/// the file at that path keeps the same identity — [`CLIENT_DISCOVERY_FOUND`]
/// is re-validated by the candidate's length and modification time on every
/// lookup, not by a clock, so nothing else would ever notice this pair had
/// gone bad. Nothing happens for a step without a `client` table — there is
/// no discovery cache to evict for one that ships its pair literally.
///
/// A free function, not inlined into [`oauth_refresh_step`], so it is
/// directly testable against a stubbed error string rather than a live
/// exchange: this crate has no HTTPS test-server infrastructure, and
/// `oauth_refresh_step` itself refuses anything but an `https://` `token_url`
/// before it would ever reach here, which rules out a plain-HTTP local stub.
fn on_exchange_error(step: &AuthStep, err: &str) {
    if let Some(client) = &step.client {
        if is_invalid_client(err) {
            client_discovery_evict(client);
        }
    }
}

// ── The installed-app pair: env override, literal fields, discovery ──────

/// The client id/secret pair `oauth-refresh` needs, in the order the schema
/// documents (`docs/PLUGIN-ARCHITECTURE.md`, "`[[surface.auth]]`"): both env
/// vars named by `step.client`, if set and non-blank; else discovery from
/// the installed client's own binaries (see [`discover_client`]). `None`
/// when every source comes up empty — [`oauth_refresh_step`] then resolves
/// the step Absent, exactly like any other missing credential store.
///
/// A step's literal `client_id`/`client_secret` are never consulted here —
/// `client` and the literal pair together are refused at load
/// (`manifest::validate`; a step may not set both, see the manifest comment
/// on `oauth-refresh`), and the caller only reaches this function once it
/// has already confirmed `step.client.is_some()`, taking the literal fields
/// itself otherwise. There is nothing left for a literal-pair fallback here
/// to ever run against.
///
/// Only ever called with `step.client.is_some()` — see the caller.
fn resolve_client(step: &AuthStep) -> Option<(String, String)> {
    let client = step.client.as_ref()?;
    if let Some(pair) = client_env_pair(client) {
        return Some(pair);
    }
    discover_client(client)
}

/// Both env vars named by `client`, read and non-blank — the resolution
/// order's first and cheapest rung, tried on every call rather than cached:
/// an operator flipping the override on or off is meant to take effect on
/// the very next fetch, not up to ten minutes later.
///
/// Three outcomes, not two: both set is the override; neither set is
/// silently "not using it"; **exactly one** set is worth a diagnostic — an
/// operator who set `TICKOVER_ANTIGRAVITY_CLIENT_ID` and not
/// `_CLIENT_SECRET` (or the reverse) almost certainly meant to set both, and
/// falling through to discovery without saying so would hide that mistake
/// behind whatever discovery happens to find.
///
/// The two `?`s below — "no `id_env`/`secret_env` named at all" — are
/// effectively unreachable for a manifest that passed `manifest::validate`:
/// it requires the pair set together or not at all, so `client.id_env`
/// being `None` already implies `client.secret_env` is too. Kept as `?`
/// rather than asserted away, the same way `resolve_client`'s literal-field
/// fallback is kept: a hand-built `AuthStep` in this module's own tests can
/// still set one without the other, and this must not panic on that.
fn client_env_pair(client: &AuthClientDiscovery) -> Option<(String, String)> {
    let id_env = client.id_env.as_deref()?;
    let secret_env = client.secret_env.as_deref()?;
    let id = std::env::var(id_env).ok().filter(|v| !v.trim().is_empty());
    let secret = std::env::var(secret_env)
        .ok()
        .filter(|v| !v.trim().is_empty());
    match (id, secret) {
        (Some(id), Some(secret)) => Some((id, secret)),
        (None, None) => None,
        _ => {
            queue_diag_once(half_set_env_key(client), half_set_env_diag(client));
            None
        }
    }
}

/// One process-wide cache entry: a `client.files`/`client.bins` candidate
/// this process has already scanned and found both patterns in, keyed by
/// *(the discovery config that found it, its resolved path)* — not by path
/// alone, so a second `oauth-refresh` step whose own candidate list happens
/// to include the same installed binary, but a different pattern pair, does
/// not inherit the first step's match. Re-validated by file identity
/// (`len`+`mtime`) on every lookup rather than trusted forever: a client
/// reinstalled with a new secret lands its binary back at the very same
/// path, and a cache keyed on path alone would keep serving the old pair.
/// What this exists to prevent either way is scanning Antigravity's ~180 MB
/// `agy` binary again on every `refresh_secs` tick for the life of the
/// process.
struct ClientFound {
    id: String,
    secret: String,
    len: u64,
    mtime: std::time::SystemTime,
}

static CLIENT_DISCOVERY_FOUND: std::sync::Mutex<
    Option<std::collections::HashMap<(u64, PathBuf), ClientFound>>,
> = std::sync::Mutex::new(None);

fn client_discovery_found_lookup(config_key: u64, path: &Path) -> Option<(String, String)> {
    // `len`/`mtime` are `Copy`, and the two strings are cloned here rather
    // than borrowed past this block — the lock is released before the `stat`
    // below runs, not held across it. Fetches for different plugins run on
    // concurrent threads, each capable of reaching this same cache; holding
    // a process-wide `Mutex` through a filesystem call would serialize every
    // one of them on this plugin's `stat`, for the length of however long the
    // OS takes to answer it.
    let (len, mtime, id, secret) = {
        let guard = CLIENT_DISCOVERY_FOUND
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = guard.as_ref()?.get(&(config_key, path.to_path_buf()))?;
        (
            entry.len,
            entry.mtime,
            entry.id.clone(),
            entry.secret.clone(),
        )
    };
    // The file's current identity, not the cached one — a changed length or
    // modification time means whatever is at this path now is not what was
    // scanned, and the cached pair is treated as though nothing were cached
    // at all (the caller rescans). The `stat` runs against `path` after the
    // lock above is released, never against a second, independently-`stat`ed
    // copy taken *before* the lock: that shape would compare two different
    // moments in time against each other and call it a match — this compares
    // the disk exactly once, against the values the cache actually held.
    let disk_meta = std::fs::metadata(path).ok()?;
    let disk_mtime = disk_meta.modified().ok()?;
    if disk_meta.len() != len || disk_mtime != mtime {
        return None;
    }
    Some((id, secret))
}

/// `len`/`mtime` come from [`scan_candidate`]'s own handle-level `stat` —
/// see [`ScanOutcome::Found`]'s own doc for why this does not take a fresh
/// one of its own against `path`: by the time this runs, the file at `path`
/// may already be something else, and a re-`stat` here would tag the pair
/// actually found with whatever identity that something-else has, not the
/// one it was actually read out of.
fn client_discovery_found_store(
    config_key: u64,
    path: PathBuf,
    id: String,
    secret: String,
    len: u64,
    mtime: std::time::SystemTime,
) {
    let mut guard = CLIENT_DISCOVERY_FOUND
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    guard
        .get_or_insert_with(std::collections::HashMap::new)
        .insert(
            (config_key, path),
            ClientFound {
                id,
                secret,
                len,
                mtime,
            },
        );
}

/// The other half of the discovery cache: "nothing in `client.files`/
/// `client.bins` right now", one entry per discovery *config* (there is no
/// file to key a miss by — nothing matched). Retried at most once every
/// [`CLIENT_DISCOVERY_RETRY_SECS`] (a genuine miss or a read error) or
/// [`CLIENT_DISCOVERY_TRUNCATED_RETRY_SECS`] (a truncated pass — shorter,
/// but never absent), so a client installed after this process started is
/// picked up without a restart, but a stuck config — whichever way it is
/// stuck — is not rescanned, and its (possibly enormous) candidate files
/// reopened and reread, on every single tick.
static CLIENT_DISCOVERY_MISS: std::sync::Mutex<Option<std::collections::HashMap<u64, i64>>> =
    std::sync::Mutex::new(None);

/// How long a discovery miss is not retried, in seconds. Ten minutes, per the
/// schema's own contract for this field — long enough that a `refresh_secs =
/// 60` tick isn't rescanning a multi-hundred-megabyte binary every minute,
/// short enough that installing the client mid-session is noticed the same
/// day without restarting the app.
const CLIENT_DISCOVERY_RETRY_SECS: i64 = 600;

/// How long a *truncated* pass is not retried, in seconds — shorter than
/// [`CLIENT_DISCOVERY_RETRY_SECS`], not absent: a truncated pass was never a
/// completed attempt (see [`discover_client`]'s own doc), so it must not earn
/// the full ten-minute miss backoff, but a candidate set that is *always*
/// truncated (an oversized `bins` match, say) still must not be re-read in
/// full on every single `refresh_secs` tick — the exact cost this whole
/// backoff mechanism exists to avoid. Two minutes: short enough that a
/// one-off truncation (a slow disk, a momentarily large pass budget already
/// spent by an earlier candidate) is retried the next tick or two, long
/// enough that a config stuck this way is not scanned in full every minute.
const CLIENT_DISCOVERY_TRUNCATED_RETRY_SECS: i64 = 120;

/// [`scan_candidate`]'s chunk size: a megabyte at a time, with a few KiB of
/// the previous chunk carried forward — comfortably longer than either
/// pattern could ever match, so a hit split across the boundary is whole
/// again in the next chunk's carried prefix. Module-level (not local to
/// `scan_candidate`) so the boundary test below can compute its fixture's
/// byte offsets from the same constants the scan actually uses, rather than
/// a copy that silently stops testing the seam the day one of them changes.
const CLIENT_DISCOVERY_CHUNK_BYTES: usize = 1024 * 1024;
const CLIENT_DISCOVERY_OVERLAP_BYTES: usize = 8 * 1024;
/// Several times an installed client's own binaries (measured, see the
/// module docs' provider notes) — bounds a hostile or corrupt file without
/// making a real scan give up early.
const CLIENT_DISCOVERY_MAX_SCAN_BYTES: u64 = 512 * 1024 * 1024;
/// Total bytes [`discover_client`] will read across *every* candidate in one
/// pass — 1 GiB. `CLIENT_DISCOVERY_MAX_SCAN_BYTES` bounds what a single file
/// can cost; this bounds what the whole pass can cost, so a manifest naming
/// several large candidates cannot multiply the per-file cap by however many
/// it lists.
const CLIENT_DISCOVERY_PASS_BUDGET_BYTES: u64 = 1024 * 1024 * 1024;

/// The two byte limits a discovery pass runs under, pulled out of the pair
/// of constants above into one value so [`discover_client_within`] can be
/// handed something other than production's own gigabyte-sized numbers.
/// Production always builds this from [`CLIENT_DISCOVERY_MAX_SCAN_BYTES`]
/// and [`CLIENT_DISCOVERY_PASS_BUDGET_BYTES`] (see [`CLIENT_DISCOVERY_LIMITS`]
/// below) — this exists so a test can instead pass a few-kilobyte pair of
/// its own, and exercise the aggregation those constants gate (a truncated
/// pass earns the short backoff, a candidate skipped for lack of budget
/// counts as truncation too, a per-file cap does not stop the pass) without
/// a fixture large enough to actually trip the real limits.
#[derive(Debug, Clone, Copy)]
struct ScanLimits {
    pass_budget: u64,
    per_file_cap: u64,
}

/// The limits [`discover_client`] actually runs a pass under — see
/// [`ScanLimits`] for why that is a parameter at all rather than the two
/// constants it is built from used directly.
const CLIENT_DISCOVERY_LIMITS: ScanLimits = ScanLimits {
    pass_budget: CLIENT_DISCOVERY_PASS_BUDGET_BYTES,
    per_file_cap: CLIENT_DISCOVERY_MAX_SCAN_BYTES,
};

fn client_discovery_miss_lookup(key: u64, now: i64) -> bool {
    let guard = CLIENT_DISCOVERY_MISS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    matches!(guard.as_ref().and_then(|m| m.get(&key)), Some(retry_after) if *retry_after > now)
}

fn client_discovery_miss_store(key: u64, retry_after_unix: i64) {
    let mut guard = CLIENT_DISCOVERY_MISS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    guard
        .get_or_insert_with(std::collections::HashMap::new)
        .insert(key, retry_after_unix);
}

/// Drop what a discovery config has cached as a *found* credential — so the
/// next attempt rescans rather than replaying a pair the OAuth endpoint has
/// just said is wrong — and replace whatever it had cached as a miss with a
/// fresh [`CLIENT_DISCOVERY_RETRY_SECS`] backoff, the same window a genuine
/// miss or read error already gets. Called from `oauth_refresh_step` on an
/// `invalid_client` response (see there); nothing else ever learns that a
/// cached pair has gone stale.
///
/// The backoff matters as much as the found-cache clear: a pair the OAuth
/// endpoint keeps rejecting — a revoked grant, say, with the client binary
/// on disk unchanged — calls this function again on every single refresh
/// attempt, and an outright-cleared miss cache would let each of those
/// immediately rescan from scratch, for as long as the rejection persists.
/// For Antigravity's ~180 MB `agy` binary, scanned on every tick forever
/// rather than once per ten minutes, that is the exact cost this cache
/// exists to avoid.
///
/// Deliberately does **not** clear [`CLIENT_DISCOVERY_LOGGED`]: the
/// once-per-process "not found"/"half-set env" notifications are about a
/// *config*, not about the credential this evicts, and an operator who has
/// already read one has no reason to see it a second time just because a
/// pair it found earlier turned out to be stale. Eviction is "forget the
/// credential and let discovery run again, no sooner than the usual backoff
/// allows", not "reset what has already been told".
fn client_discovery_evict(client: &AuthClientDiscovery) {
    let key = client_config_key(client);
    let mut guard = CLIENT_DISCOVERY_FOUND
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(map) = guard.as_mut() {
        map.retain(|(config_key, _path), _| *config_key != key);
    }
    // `cache_now`, not `now_unix`: this backoff is a purely in-process
    // pacing decision (see `cache_now`'s own doc), never compared against
    // anything the network sent.
    client_discovery_miss_store(key, cache_now().saturating_add(CLIENT_DISCOVERY_RETRY_SECS));
}

/// One process-wide line per *key* that has ever been queued with it — the
/// "per process" the manifest schema promises for a discovery diagnostic.
/// Shared by every diagnostic this module queues (not found, a half-set env
/// pair, a read error): each caller derives its own key so the three kinds
/// never collide with each other or with a different config's own entry.
static CLIENT_DISCOVERY_LOGGED: std::sync::Mutex<Option<std::collections::HashSet<u64>>> =
    std::sync::Mutex::new(None);

/// Diagnostics this module produced that only the binary can write:
/// `crate::diag` lives in `main.rs`, beside the `crate::config::dir()` it
/// appends its log to, and this crate deliberately does not reach into
/// either (`engine_http`'s own doc makes the same call: "this engine is
/// hermetic and never reads config itself"). Pushed here instead of called
/// directly, and drained by `main.rs`'s fetch loop once per pass via
/// [`take_pending_diagnostics`].
static PENDING_DIAGNOSTICS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Every diagnostic line queued since the last call, removing them — the
/// binary's side of [`PENDING_DIAGNOSTICS`]. Meant to be drained once per
/// fetch pass and handed to `diag::line`; harmless to call more or less
/// often (a queue not drained this tick is drained the next one, and an
/// empty queue costs a lock).
pub fn take_pending_diagnostics() -> Vec<String> {
    let mut guard = PENDING_DIAGNOSTICS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    std::mem::take(&mut *guard)
}

/// Queue `message` under `key`, the first time only — every diagnostic this
/// module writes goes through here so "once per process" is one mechanism,
/// not three copies of it.
fn queue_diag_once(key: u64, message: String) {
    let should_log = CLIENT_DISCOVERY_LOGGED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(std::collections::HashSet::new)
        .insert(key);
    if should_log {
        PENDING_DIAGNOSTICS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(message);
    }
}

fn client_discovery_log_once(key: u64, client: &AuthClientDiscovery) {
    queue_diag_once(key, client_not_found_diag(client));
}

/// The line [`client_discovery_log_once`] queues — names the env vars, if
/// the manifest names any, since setting them is the fix that needs nothing
/// installed at all.
fn client_not_found_diag(client: &AuthClientDiscovery) -> String {
    match (&client.id_env, &client.secret_env) {
        (Some(id_env), Some(secret_env)) => format!(
            "oauth-refresh: no OAuth client id/secret found on this machine — set {id_env} and \
             {secret_env}, or install the client this plugin reads them from"
        ),
        _ => "oauth-refresh: no OAuth client id/secret found on this machine — install the \
              client this plugin reads them from"
            .to_string(),
    }
}

/// The line [`client_env_pair`] queues when exactly one of `id_env`/
/// `secret_env` is set in the environment.
fn half_set_env_diag(client: &AuthClientDiscovery) -> String {
    format!(
        "oauth-refresh: only one of {}/{} is set in the environment — both are required for the \
         override to apply; falling back to the usual discovery order",
        client.id_env.as_deref().unwrap_or("?"),
        client.secret_env.as_deref().unwrap_or("?"),
    )
}

/// Hash `s` into `hasher`, length-prefixed so `("ab","c")` and `("a","bc")`
/// cannot collide by concatenation — the discipline every key function in
/// this module (and [`refresh_cache_key`], for its own unrelated pair)
/// hashes its parts with.
fn hash_part(hasher: &mut std::collections::hash_map::DefaultHasher, s: &str) {
    use std::hash::Hash;
    s.len().hash(hasher);
    s.hash(hasher);
}

/// A stable key over a discovery config — everything that decides what
/// `discover_client` would do. Used for the found cache, the miss cache and
/// the once-only "not found" log; a *found* result is additionally keyed by
/// the file it was found in (see [`CLIENT_DISCOVERY_FOUND`]), since two
/// configs sharing a candidate list must not share a match.
fn client_config_key(client: &AuthClientDiscovery) -> u64 {
    use std::hash::Hasher;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write_usize(client.files.len());
    for f in &client.files {
        hash_part(&mut hasher, f);
    }
    hasher.write_usize(client.bins.len());
    for b in &client.bins {
        hash_part(&mut hasher, b);
    }
    hash_part(
        &mut hasher,
        client.id_pattern.as_deref().unwrap_or_default(),
    );
    hash_part(
        &mut hasher,
        client.secret_pattern.as_deref().unwrap_or_default(),
    );
    // The env names too: two configs differing only in which variables
    // they'd check are different configs, and must not share a
    // miss/backoff/logged/found-cache entry.
    hash_part(&mut hasher, client.id_env.as_deref().unwrap_or_default());
    hash_part(
        &mut hasher,
        client.secret_env.as_deref().unwrap_or_default(),
    );
    hasher.finish()
}

/// A key for [`half_set_env_diag`]'s dedup, distinct from [`client_config_key`]'s
/// own hash space (a literal tag as the first part) so an env-name pair that
/// happened to hash to the same bits as some config's files/bins/patterns
/// still could not collide with it.
fn half_set_env_key(client: &AuthClientDiscovery) -> u64 {
    use std::hash::Hasher;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hash_part(&mut hasher, "half-set-env");
    hash_part(&mut hasher, client.id_env.as_deref().unwrap_or_default());
    hash_part(
        &mut hasher,
        client.secret_env.as_deref().unwrap_or_default(),
    );
    hasher.finish()
}

/// A key for a scan-error diagnostic's dedup — the config and the one
/// candidate path that failed to read, tagged the same way
/// [`half_set_env_key`] is.
fn scan_error_key(config_key: u64, path: &Path) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hash_part(&mut hasher, "scan-error");
    config_key.hash(&mut hasher);
    hash_part(&mut hasher, &path.to_string_lossy());
    hasher.finish()
}

/// A key for the truncated-pass diagnostic's dedup — one per *config*, not
/// per candidate: a pass that ran out of budget is a fact about the whole
/// pass, unlike a read error, which is a fact about one file.
fn truncated_key(config_key: u64) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hash_part(&mut hasher, "truncated");
    config_key.hash(&mut hasher);
    hasher.finish()
}

/// The line queued when [`discover_client`]'s pass stopped before every
/// candidate was fully read (the per-file or whole-pass byte budget ran
/// out) — distinct from [`client_not_found_diag`], which claims something
/// this outcome cannot: that every candidate was actually read to the end.
/// Takes no `client` argument, unlike its siblings: nothing about a
/// discovery config changes what this line says.
fn client_truncated_diag() -> String {
    "oauth-refresh: stopped scanning for the OAuth client before finishing every \
     candidate (size limit) — it may still be installed here"
        .to_string()
}

/// Discovery itself: `client.files` (after `~` expansion), then each of
/// `client.bins` resolved on this machine (see [`bin_candidates`]), scanned
/// in order for the first candidate that carries both patterns. `None` when
/// nothing does — the manifest-level validation this reaches through already
/// refused a `client` table with no field to search at all, so an empty
/// result here means every named candidate is either absent or does not
/// carry the shape, not a misconfigured step.
///
/// Precedence matches a plain, cache-free scan exactly: candidates are
/// tried in the order they are named, and the first one that actually
/// carries both patterns wins — cache or no cache. That guarantee only
/// covers candidates the pass actually settles, though: `NotFound` and
/// `Found` are the two verdicts that answer "does this one carry both
/// patterns", but `Truncated` and `Error` both leave that question open and
/// move straight on to the next candidate (see the loop below) rather than
/// stopping the pass to insist on an answer first. A candidate that never
/// gets read past a budget cutoff or an I/O error might well have matched
/// too — this precedence is silent on it, not a claim that it did not — and
/// a later candidate that *does* get fully read and matches is served
/// instead, exactly as it would be if the truncated/errored one had simply
/// come back `NotFound`. The found-cache lookup
/// is the first thing each iteration below does, the same as it always was
/// before there was a cache at all; it is never consulted for every
/// candidate up front, because that would let a pair cached under a later
/// candidate shadow a fresh, different pair a manifest author (or an
/// installer) has since written into an earlier one — cache identity is
/// `len`+`mtime`, not content, and only an `invalid_client` response
/// (`client_discovery_evict`) ever forces a rescan, so a shadowed pair
/// would stay shadowed indefinitely, not just for one pass. A cached pair
/// in a later candidate is only ever served instead of scanning an earlier
/// one when that earlier one cannot be scanned *at all* this pass — the
/// shared budget already spent by candidates before it (see the `budget ==
/// 0` branch below) — never merely because the cache happens to have an
/// answer for something further down the list.
///
/// One shared byte budget across the whole pass
/// ([`CLIENT_DISCOVERY_PASS_BUDGET_BYTES`]), not per candidate. Neither a
/// read error nor a budget cutoff stops the pass early — a later candidate
/// may still resolve — but both are tracked separately from a genuine miss:
///
/// * an **error** still buys the usual [`CLIENT_DISCOVERY_RETRY_SECS`]
///   backoff (a permanently unreadable candidate must not turn every
///   `refresh_secs` tick into a full rescan of everything else in the
///   list), but is never mistaken for "not installed here" — it gets its
///   own once-per-candidate diagnostic instead of the "not found" one;
/// * a **truncated** pass (the per-file or whole-pass byte budget ran out
///   before every candidate was fully read) is not a completed attempt, so
///   "read everything and found nothing" is a claim it specifically cannot
///   make — it gets its own once-per-config diagnostic instead of the "not
///   found" one, and a shorter [`CLIENT_DISCOVERY_TRUNCATED_RETRY_SECS`]
///   backoff rather than none: a candidate set that is *always* truncated
///   must not be re-read in full on every single tick either.
///
/// When a single pass has both — an error on one candidate, a truncation
/// on another — the stored backoff is the shorter truncated one, not the
/// longer error one: the pass was still not a completed attempt either
/// way, and [`CLIENT_DISCOVERY_TRUNCATED_RETRY_SECS`] already accepts a
/// full rescan of a large candidate set at that cadence.
///
/// A thin wrapper over [`discover_client_within`], which runs against a
/// [`ScanLimits`] argument rather than reading the two byte constants above
/// directly — the split exists purely so the aggregation described above
/// (the short backoff, the budget-exhausted skip counting as truncation, a
/// capped candidate not stopping the pass) can be driven with byte-sized
/// limits in a test, without a fixture large enough to trip a real
/// gigabyte-scale one.
fn discover_client(client: &AuthClientDiscovery) -> Option<(String, String)> {
    discover_client_within(client, CLIENT_DISCOVERY_LIMITS)
}

/// [`discover_client`]'s body — see there for what this does, why, and what
/// `limits` stands in for.
fn discover_client_within(
    client: &AuthClientDiscovery,
    limits: ScanLimits,
) -> Option<(String, String)> {
    let key = client_config_key(client);
    // `cache_now`, not `now_unix`: this whole backoff is a purely
    // in-process pacing decision (see `cache_now`'s own doc). Checked before
    // either pattern below is compiled — a real `regex::bytes::Regex::new`,
    // twice — since a hit here answers `None` regardless of whether either
    // pattern would even compile, and compiling both first only to throw the
    // work away is exactly the compile-for-nothing the backoff exists to
    // save the scan itself from.
    let now = cache_now();
    if client_discovery_miss_lookup(key, now) {
        return None;
    }

    // `?`, not `unwrap_or_default()`: `manifest::validate` requires both
    // patterns present (and non-blank) on any `client` table, so `None` here
    // means this was reached some other way, e.g. a hand-built `AuthStep` in
    // this module's own tests. `unwrap_or_default()` would instead compile
    // `""` — a pattern that matches every position with a zero-length match —
    // and hand `discover_client` a "found" empty id/secret; `?` reports
    // nothing found instead, the same as any other candidate that doesn't
    // carry the shape.
    let id_pattern = compile_scan_pattern(client.id_pattern.as_deref()?)?;
    let secret_pattern = compile_scan_pattern(client.secret_pattern.as_deref()?)?;

    let candidates: Vec<PathBuf> = client
        .files
        .iter()
        .map(|f| super::expand_home(f))
        .chain(bin_candidates(&client.bins))
        .collect();

    let mut budget: u64 = limits.pass_budget;
    let mut had_error = false;
    let mut had_truncation = false;
    for path in &candidates {
        if let Some(cached) = client_discovery_found_lookup(key, path) {
            return Some(cached);
        }
        if budget == 0 {
            // The shared pass budget has already run out — this candidate,
            // and everything after it, cannot be *read* any further this
            // pass. That is not a reason to stop asking the cache about
            // them too, though: the lookup just above already ran for this
            // one, and `continue` — not `break` — lets every candidate
            // still left in the list get that same lookup on its own
            // iteration, so a pair a previous pass already found and
            // cached under one of them is still served even though this
            // pass has nothing left to scan its way there with. The budget
            // stops reading, not remembering.
            had_truncation = true;
            continue;
        }
        match scan_candidate(
            path,
            &id_pattern,
            &secret_pattern,
            &mut budget,
            limits.per_file_cap,
        ) {
            ScanOutcome::Found(id, secret, len, mtime) => {
                client_discovery_found_store(
                    key,
                    path.clone(),
                    id.clone(),
                    secret.clone(),
                    len,
                    mtime,
                );
                return Some((id, secret));
            }
            ScanOutcome::NotFound => continue,
            ScanOutcome::Truncated => had_truncation = true,
            ScanOutcome::Error(msg) => {
                had_error = true;
                queue_diag_once(
                    scan_error_key(key, path),
                    format!("oauth-refresh: could not read {}: {msg}", path.display()),
                );
            }
        }
    }

    // Backoff applies to an error the same way it applies to a genuine
    // miss — see the doc comment above — and to a truncated pass too, just
    // shorter: it was never a completed attempt, so it must not be mistaken
    // for one at the next tick, but it must not be retried in full on every
    // tick either.
    let retry_secs = if had_truncation {
        CLIENT_DISCOVERY_TRUNCATED_RETRY_SECS
    } else {
        CLIENT_DISCOVERY_RETRY_SECS
    };
    // Stamped from a fresh read, not `now` from before the scan: a truncated
    // pass has by definition just spent its whole `pass_budget` (up to 1 GiB)
    // reading candidates, and on a slow disk that can take real time — long
    // enough that `now.saturating_add(retry_secs)` lands in the past before
    // this even stores it, so the very next fetch scans the same gigabyte
    // again instead of backing off at all.
    client_discovery_miss_store(key, cache_now().saturating_add(retry_secs));
    if had_truncation {
        queue_diag_once(truncated_key(key), client_truncated_diag());
    }
    if !had_error && !had_truncation {
        client_discovery_log_once(key, client);
    }
    None
}

/// Resolve each of `names` to a file on this machine, in the order given —
/// mirroring `main.rs`'s `find_bin` (the same install directories that
/// binary's own auto-ping already appends first, then the inherited `PATH`
/// — [`super::cli_install_dirs`] is the canonical list; see its own doc for
/// why it lives here and not beside `find_bin`). Same order, same filters,
/// both resolvers: a relative (or empty) `PATH` entry is refused below and
/// by `find_bin` alike, and on unix [`super::is_executable_file`] is what
/// both call in place of a plain `is_file()`, so a regular file without the
/// executable bit set can't shadow the real binary in either one — a machine
/// with two installs of the same client on `PATH` at once has this step
/// discover the same pair `find_bin` would have pinged. A name not found
/// anywhere contributes nothing, exactly like a `files` candidate that
/// doesn't exist — discovery treats "not installed here" the same way
/// regardless of which list named the candidate.
fn bin_candidates(names: &[String]) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = super::cli_install_dirs();
    if let Some(p) = std::env::var_os("PATH") {
        // An empty `PATH` entry (a leading, trailing or doubled `:`) means
        // "the current directory" — POSIX's own convention, and never a
        // place this app should go looking for a client's binary: "current
        // directory" for a menu-bar app is wherever it happened to be
        // launched from, not anywhere the manifest author had in mind.
        // `is_absolute()` refuses that and any other relative entry.
        dirs.extend(std::env::split_paths(&p).filter(|d| d.is_absolute()));
    }
    let mut found = Vec::new();
    for name in names {
        // Windows resolves a bare command name through `PATHEXT`, which a
        // manifest author writing `bins = ["agy"]` has no reason to know
        // about — the suffixes tried here are the ones that matter for a
        // CLI (`.exe`, plus the two shell-script wrapper extensions several
        // of these tools ship as). `""` first, so an extensionless match
        // (already how every other platform resolves `bins`) still wins
        // when there is one. Directories are the outer loop and suffixes the
        // inner one — `PATH` order is what an operator actually controls
        // (which install wins when two are on `PATH` at once), and must
        // outrank `PATHEXT` order; nesting it the other way would let a
        // `.cmd` shim earlier on `PATHEXT` beat a real `.exe` from a
        // directory that comes first on `PATH`.
        #[cfg(target_os = "windows")]
        let candidate = dirs
            .iter()
            .flat_map(|d| {
                ["", ".exe", ".cmd", ".bat"]
                    .iter()
                    .map(move |suffix| d.join(format!("{name}{suffix}")))
            })
            .find(|c| c.is_file());
        #[cfg(not(target_os = "windows"))]
        let candidate = dirs
            .iter()
            .map(|d| d.join(name))
            .find(|c| super::is_executable_file(c));
        if let Some(c) = candidate {
            found.push(c);
        }
    }
    found
}

/// The four things [`scan_candidate`] can report. Kept distinct from a plain
/// `Option` because [`discover_client`] treats each failure mode
/// differently: an I/O error and a budget/cap cutoff both queue their own
/// diagnostic and must not earn the same miss-cache backoff a genuine "not
/// installed, read to the end and neither pattern matched" does.
#[derive(Debug, PartialEq)]
enum ScanOutcome {
    /// The id, the secret, and the length/modification time of the file
    /// they were actually read out of — taken from the very same
    /// handle-level `stat` [`scan_candidate`] already does for `file_len`,
    /// not a fresh one after the fact. [`client_discovery_found_store`]
    /// caches by this identity rather than re-`stat`ing the path itself
    /// once scanning is done: between "the scan finished" and "the cache
    /// was updated" the file could have been rewritten, and a re-`stat` at
    /// that point would tag the pair actually found with a *different*
    /// file's identity, breaking the promise the found-cache's own doc
    /// makes — that a cache hit's identity check reflects what was
    /// actually scanned.
    Found(String, String, u64, std::time::SystemTime),
    /// Read to EOF (or the candidate wasn't a regular file, or didn't
    /// exist) without a match — a genuine "not this candidate".
    NotFound,
    /// Stopped before EOF because [`scan_candidate`]'s own `per_file_cap`
    /// (this candidate — [`CLIENT_DISCOVERY_MAX_SCAN_BYTES`] in production,
    /// by way of [`CLIENT_DISCOVERY_LIMITS`]) or the pass's shared budget
    /// ran out first — this candidate was never fully read, so "neither
    /// pattern matched" is not a fact this outcome can claim.
    Truncated,
    Error(String),
}

/// One discovery pattern — `id_pattern` or `secret_pattern` — compiled once
/// per pass and paired with the most bytes any of its matches could ever be.
/// Bundled into a single value rather than threading a second argument
/// alongside the bare `regex::bytes::Regex` everywhere it travels
/// (`scan_candidate` already takes five parameters; two more, for a value
/// that is always used together, would only invite passing one half without
/// the other): compiled once, in [`discover_client_within`], the same place
/// the regex itself always was.
struct ScanPattern {
    re: regex::bytes::Regex,
    /// [`super::manifest::regex_max_match_len`] against this pattern's own
    /// source text, or `None` when it could not be computed at all — not
    /// merely a hypothetical gap: `re` above compiles through
    /// `regex::bytes::Regex`, which parses with UTF-8 matching disabled,
    /// while the measurement parses through `regex_syntax`'s own default,
    /// UTF-8 *enabled* — a pattern built on an explicit byte-level class
    /// such as `(?-u:.){1,5}` compiles perfectly well as `re` but has no
    /// measurable maximum under that stricter default, so this is `None`
    /// for it even though `re` itself is entirely usable. Fails closed
    /// either way: `None` is treated the same as "unbounded" wherever this
    /// is read — the conservative choice is to keep deferring, not to
    /// assume a match already known to be maximal when it might not be —
    /// and `manifest::validate` refuses a pattern shaped like this outright
    /// regardless, so a shipped manifest never reaches
    /// [`compile_scan_pattern`] carrying one.
    max_len: Option<usize>,
}

/// Compile `pattern` and measure its own maximum match length in the same
/// step, so the two can never drift out of sync with each other the way
/// computing them at two different call sites might invite. `None` on
/// either failure — an invalid pattern, same as a bare `Regex::new(..).ok()`
/// — mirrors [`discover_client_within`]'s own `?`-chain: a `client` table
/// that reached this some other way (a hand-built `AuthStep` in this
/// module's own tests, say) than through `manifest::validate` reports
/// nothing found, the same as any other candidate that doesn't carry the
/// shape. The length itself comes from `super::manifest`'s own
/// `regex_max_match_len` (`pub(crate)` for exactly this call — see its own
/// doc), not a second copy of that parse kept here: `manifest::validate`'s
/// finite-maximum requirement and [`accept_settled_match`]'s deferral rule
/// read the same figure, so the two can never disagree about what a given
/// pattern's maximum actually is.
fn compile_scan_pattern(pattern: &str) -> Option<ScanPattern> {
    let re = regex::bytes::Regex::new(pattern).ok()?;
    Some(ScanPattern {
        max_len: super::manifest::regex_max_match_len(pattern),
        re,
    })
}

/// One pattern's match attempt against the bytes read so far — factored out
/// of [`scan_candidate`]'s loop because the id and secret halves were
/// otherwise identical apart from which `Option<String>` they wrote into and
/// which word appeared in the `debug_assert!`.
///
/// `eof` is most of the reason this exists rather than being a one-line
/// `if let`: `pattern.re.find(carry)` on a still-growing buffer can return a
/// match that only *looks* complete because the buffer ran out, not because
/// the underlying run of matching bytes did. A validated, merely *bounded*
/// pattern (`{10,40}`, say — it still has a finite maximum, so
/// `manifest::validate` accepts it) is greedy: asked to match as much as it
/// can, it happily consumes every remaining byte in `carry` if they all fit
/// the class, and stops at `carry`'s end not because the real value ends
/// there but because there is nothing left to look at yet. Accepting that
/// match immediately means handing the OAuth exchange the first `n`
/// characters of a secret that actually continues into the next chunk — and
/// unlike a wrong guess, that failure is *sticky*: `discover_client`'s own
/// doc has `oauth_refresh_step` evict the cached pair on `invalid_client`
/// and rescan, but the rescan reads the same chunk boundary in the same
/// place and produces the exact same truncated match every time.
///
/// So: a match whose end touches `carry`'s current end (`m.end() ==
/// carry.len()`) is deferred (neither accepted nor recorded as a miss)
/// unless one of two things is already true of it.
///
/// The first is `eof` — not literally "`read` has just returned `0`":
/// [`scan_candidate`]'s own two cutoff sites pass `eof = true` directly,
/// without waiting for a further read, on the one occasion each stops
/// having already read every byte the candidate holds (see there) — but
/// always "nothing will ever be read into `carry` again", the fact that
/// actually matters here.
///
/// The second is `pattern.max_len`: a match already as long as its own
/// pattern's computed maximum cannot be a truncated prefix of a longer one
/// no matter what follows it, so it needs no deferral regardless of `eof` —
/// this is exactly what keeps every pattern this crate actually ships
/// (`{13}`, `{32}`, `{28}`, all exact) behaving precisely as it did before
/// this whole deferral mechanism existed: an exact-length match always
/// already equals its own maximum on the read that produces it, so it is
/// never deferred, cutoff or no cutoff. `None` (the maximum could not be
/// computed) is treated the same as "not yet known to be maximal" — keep
/// deferring, per [`ScanPattern::max_len`]'s own doc. Only a genuinely
/// variable-length pattern (bounded or not) ever pays the one-read delay,
/// and only when it also lands right on a chunk boundary.
///
/// Deferred either way, a match's start is always still sitting in the
/// carried-forward overlap on a later iteration —
/// [`CLIENT_DISCOVERY_OVERLAP_BYTES`] (8 KiB) is far larger than
/// [`super::CLIENT_PATTERN_MAX_MATCH_BYTES`] (256 bytes), the validated
/// upper bound on any pattern's match length — and is re-found whole on a
/// later iteration, once bytes follow it (or at `eof`).
///
/// A no-op once `found` already holds a value — same short-circuit the
/// inlined `if found_id.is_none()` blocks used to give each pattern, kept so
/// a settled match is never overwritten by a later, coincidental one further
/// into the file.
fn accept_settled_match(
    carry: &[u8],
    pattern: &ScanPattern,
    eof: bool,
    found: &mut Option<String>,
) {
    if found.is_some() {
        return;
    }
    let Some(m) = pattern.re.find(carry) else {
        return;
    };
    // See this function's own doc for why either half of this condition,
    // on its own, is enough to settle a match that touches `carry`'s
    // current end.
    let already_maximal = pattern.max_len.is_some_and(|max| m.len() >= max);
    if !eof && m.end() == carry.len() && !already_maximal {
        // Touches the end of what has been read so far, is not yet known to
        // be as long as it can get, and more may still come — not settled,
        // wait for the next chunk (or for `eof`).
        return;
    }
    // Validation bounds every shipped pattern to
    // `CLIENT_PATTERN_MAX_MATCH_BYTES` (`manifest::validate`); a longer
    // match here means this step reached the scan some other way, and is
    // treated as no match rather than trusted — the same guarantee
    // validation gives a manifest that went through it, kept for one that
    // did not. An empty match is the same story from the other direction:
    // validation also requires `minimum_len() >= 1`, so a zero-length match
    // here means a pattern that got past that check some other way —
    // treated as no match rather than handed to the OAuth exchange as a
    // client id or secret of `""`.
    if m.len() <= super::CLIENT_PATTERN_MAX_MATCH_BYTES && !m.is_empty() {
        *found = Some(String::from_utf8_lossy(m.as_bytes()).into_owned());
    }
}

/// Read `path` in bounded chunks, carrying a small overlap across each
/// boundary so a match straddling two chunks is not missed, and stop the
/// moment both `id_pattern` and `secret_pattern` have settled (see
/// [`accept_settled_match`] for what "settled", rather than merely
/// "matched", means here). Built for a file the size of an installed
/// client's own binary — Antigravity's `agy` is upward of 150 MB — so
/// reading the whole thing into memory at once is the one thing this must
/// not do. `budget` is [`discover_client`]'s shared byte-budget for the
/// whole pass, decremented as bytes are actually read and never exceeded
/// even mid-chunk. `per_file_cap` is this one candidate's own limit
/// ([`CLIENT_DISCOVERY_MAX_SCAN_BYTES`] in production, by way of
/// [`ScanLimits`]) — checked after each read, so it cuts a candidate short
/// only if that candidate is bigger than one read: ordinarily a full
/// chunk, but `want` below is `min(chunk, budget)`, so when the shared
/// pass budget has less than a chunk left, "one read" is that smaller
/// amount instead, and the cap can still cut a candidate short at that
/// size. Anything no bigger than the read that covers it is always read
/// to EOF before the check next runs. Either cutoff — the shared budget or
/// this cap — is treated as EOF, not as a cutoff, on the one occasion it
/// coincides exactly with `file_len`: every byte the candidate holds was
/// read either way, so a match still deferred at that point gets the same
/// settle pass a natural end-of-file `read` would give it, rather than
/// being dropped as though the candidate had been cut short. The cap in
/// particular bounds this one candidate's own cost regardless of whether
/// `file_len` (a `stat` taken once, before any of these reads — see the
/// comment on it below) is still accurate by the time it is checked: it
/// never lets the loop read on past it hoping a further `read` will report
/// `0` and confirm the file was already finished, since a file that grew
/// after that one `stat` would keep handing back real bytes instead, and
/// the pass's own *shared* budget, not this candidate's cap, would be what
/// finally stopped it.
///
/// A genuine cutoff (`scanned < file_len`, at either site) that lands with
/// a match already deferred right at that byte is a `Truncated` result, not
/// a `Found` one — see [`accept_settled_match`] — and, the cutoff falling
/// at the same byte on every rescan, this is not merely usually true but
/// deterministic: that one candidate is never resolved through this cutoff,
/// on any pass, until something about the candidate itself changes. The
/// stronger reason this is not a live concern for any pattern this crate
/// actually ships today is not merely production's own byte-scale limits
/// (though a genuine mid-candidate cutoff can come from those too — either
/// this cap, or the shared 1 GiB pass budget spread thin over several large
/// candidates at once, and the largest known client binary, Antigravity's
/// `agy`, is measured at about a third of
/// [`CLIENT_DISCOVERY_MAX_SCAN_BYTES`] alone): every shipped pattern is
/// exact-length (73 bytes for the id, 35 for the secret — see
/// [`ScanPattern::max_len`]'s own doc for what that means for
/// `accept_settled_match`), and an exact-length pattern's `find` never
/// returns a match short of its own full count in the first place. There is
/// no partial match ever sitting in `carry` for a cutoff, of any kind, to
/// catch mid-flight — nothing is ever deferred here to be lost. This is
/// squarely a third-party manifest's own risk, with a merely bounded,
/// variable-length pattern of its own choosing, not a shipped one — worth
/// naming anyway, because the honest alternative to it is not "accept the
/// deferred match instead": that is exactly the truncated-secret defect
/// this whole deferral mechanism exists to remove, just moved from every
/// chunk boundary to one specific, cutoff-sized one. `Truncated`, retried
/// later, is the correct answer here the same way it already was there.
///
/// A non-blocking stat first — a cheap early exit for the common case (the
/// candidate isn't a regular file, or doesn't exist at all) that never even
/// opens a handle. It does **not** prevent the open below from blocking: the
/// path can change kind between this stat and that open (a classic TOCTOU),
/// so what actually keeps a FIFO from hanging this process is `O_NONBLOCK`
/// on the open itself, on the platforms that have it (see below) — not this
/// stat. What *is* taken from `super::read_regular_file` is the criterion,
/// `is_file()`, applied twice: once against the path here, and once more
/// against the *open handle* afterward — closing the race between the two,
/// since a symlink swapped in between would otherwise have its new target
/// read on the strength of a check that never actually looked at it —
/// `read_regular_file` follows the same technique for the identical race.
/// Symlinks are followed on purpose here, same as there: a `bins` candidate
/// is routinely one.
fn scan_candidate(
    path: &Path,
    id_pattern: &ScanPattern,
    secret_pattern: &ScanPattern,
    budget: &mut u64,
    per_file_cap: u64,
) -> ScanOutcome {
    use std::io::Read;

    match std::fs::metadata(path) {
        Ok(meta) if meta.file_type().is_file() => {}
        Ok(_) => return ScanOutcome::NotFound,
        // "Doesn't exist" is a candidate that was never installed — the same
        // fact an absent `files` entry always was, still a miss. Anything
        // else (permission denied, a path through a non-directory, an I/O
        // error from the filesystem itself) is not that: it says nothing
        // about whether the client is installed, and must not earn the
        // miss-cache backoff a genuine "not here" does.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ScanOutcome::NotFound,
        Err(e) => return ScanOutcome::Error(e.to_string()),
    }
    let mut open_options = std::fs::OpenOptions::new();
    open_options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // The actual FIFO-hang guard (see the doc comment above): opening
        // read-only with `O_NONBLOCK` set returns immediately no matter what
        // is at `path` right now, rather than blocking until a writer
        // connects — a FIFO opened this way still succeeds (POSIX), so the
        // handle-level `is_file()` check just below is what turns that
        // success into `NotFound` instead of a read. Never cleared
        // afterward: a regular file's reads ignore `O_NONBLOCK` entirely, so
        // there is nothing for a later `fcntl` to buy back.
        open_options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = match open_options.open(path) {
        Ok(f) => f,
        Err(e) => return ScanOutcome::Error(e.to_string()),
    };
    // The handle's own length, not merely its type: used below to tell a
    // budget/cap cutoff that happens to land exactly at `file_len` — not a
    // cutoff at all, since every byte the candidate holds was read; it gets
    // the same EOF settle pass a natural `read` returning `0` would, and can
    // still come back `Found` — apart from one that lands short of it (some
    // of the file was never looked at — a real `Truncated`). A file that
    // grows or shrinks mid-scan can still fool this, the same TOCTOU every
    // length-based check here already accepts — and this trusts the
    // metadata's reported length outright rather than re-measuring it; a
    // `files`/`bins` candidate is always a regular file by the time this
    // line runs (the match above just confirmed it), so there is no
    // `/proc`-style entry with an unreliable stat in the shapes this scans.
    // `mtime` travels alongside `file_len` for the same reason: both come
    // from this one handle-level `stat`, taken before any of the reads
    // below, so a `Found` result can report the exact identity of what was
    // actually scanned — see `ScanOutcome::Found`'s own doc — rather than
    // `client_discovery_found_store` re-`stat`ing the path afterward and
    // risking a *different* file's identity if it changed in between.
    let (file_len, mtime) = match file.metadata() {
        Ok(meta) if meta.file_type().is_file() => match meta.modified() {
            Ok(mtime) => (meta.len(), mtime),
            Err(e) => return ScanOutcome::Error(e.to_string()),
        },
        Ok(_) => return ScanOutcome::NotFound,
        Err(e) => return ScanOutcome::Error(e.to_string()),
    };

    let mut chunk = vec![0u8; CLIENT_DISCOVERY_CHUNK_BYTES];
    let mut carry: Vec<u8> = Vec::new();
    let mut found_id: Option<String> = None;
    let mut found_secret: Option<String> = None;
    let mut scanned: u64 = 0;
    // Set the moment the loop below exits for a reason other than EOF — a
    // genuine budget or cap cutoff that stopped short of `file_len`, not
    // "read the whole candidate and it wasn't there". Checked once, after
    // the loop, to turn that fact into `Truncated` rather than `NotFound`;
    // each of the loop's two cutoff sites still runs its own settle pass
    // when the cutoff instead coincides exactly with `file_len` (not a
    // genuine cutoff at all — see there), since only that site knows
    // whether both patterns are now known.
    let mut truncated = false;
    loop {
        if *budget == 0 {
            // Coincidentally exhausted on the very byte this candidate's
            // last chunk finished on is not a cutoff — `scanned < file_len`
            // is what tells the two apart (see the comment on `file_len`).
            if scanned < file_len {
                truncated = true;
                break;
            }
            // `scanned == file_len`: every byte this candidate holds is
            // already in `carry` (or was, before the overlap trim below
            // dropped everything but its tail — still enough, since a
            // deferred match can only start within
            // `CLIENT_DISCOVERY_OVERLAP_BYTES` of wherever it last touched
            // the read-so-far boundary). The file is not what stopped this
            // loop, the shared budget's exact exhaustion did, coincidentally,
            // on the very read that finished the file — genuinely EOF, just
            // not EOF `read` will ever get the chance to report: with
            // `*budget == 0`, `want` below would be `0`, and
            // `read(&mut buf[..0])` returns `Ok(0)` for any file, exhausted
            // or not, so looping once more to let `n == 0` say so would be
            // trusting a signal that, at this exact `want`, no longer means
            // anything. Settle directly instead — the same acceptance the
            // real EOF branch below gives a match once nothing more can
            // ever follow it.
            accept_settled_match(&carry, id_pattern, true, &mut found_id);
            accept_settled_match(&carry, secret_pattern, true, &mut found_secret);
            if let (Some(id), Some(secret)) = (&found_id, &found_secret) {
                return ScanOutcome::Found(id.clone(), secret.clone(), file_len, mtime);
            }
            break;
        }
        let want = (chunk.len() as u64).min(*budget) as usize;
        let n = loop {
            match file.read(&mut chunk[..want]) {
                Ok(n) => break n,
                // A signal landing mid-read is not a failure to read the
                // file — retried rather than reported, like any other
                // interruptible syscall this app makes.
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return ScanOutcome::Error(e.to_string()),
            }
        };
        if n == 0 {
            // EOF — genuinely nothing more to read, not an error. Run the
            // match once more first, though: see `accept_settled_match`'s
            // own doc for why a match already sitting in `carry` might still
            // be waiting on this — `eof = true` here is what lets it settle.
            // Reached only when neither cutoff site ever fired first this
            // iteration — the shared budget's, checked above at this
            // iteration's own top, or the cap's, checked below after a
            // read — so a candidate smaller than both the shared budget and
            // `per_file_cap` runs to a natural end here, the ordinary case.
            // A genuine budget or cap cutoff (`scanned < file_len`, at
            // either site) never reaches this branch at all — a match
            // deferred right up to a real cutoff is never accepted, and the
            // candidate comes back `Truncated` instead, which is the honest
            // answer; a truncated pass is retried later rather than served
            // a possibly-wrong guess now. A cutoff that instead coincides
            // exactly with `file_len` is not a genuine cutoff at all — see
            // the `scanned == file_len` branches at both sites — and
            // settles there directly, the same acceptance this branch
            // gives, without ever waiting on a further read to report `0`:
            // neither site relies on this branch to get here.
            accept_settled_match(&carry, id_pattern, true, &mut found_id);
            accept_settled_match(&carry, secret_pattern, true, &mut found_secret);
            if let (Some(id), Some(secret)) = (&found_id, &found_secret) {
                return ScanOutcome::Found(id.clone(), secret.clone(), file_len, mtime);
            }
            break;
        }
        *budget = budget.saturating_sub(n as u64);
        carry.extend_from_slice(&chunk[..n]);
        scanned = scanned.saturating_add(n as u64);
        accept_settled_match(&carry, id_pattern, false, &mut found_id);
        accept_settled_match(&carry, secret_pattern, false, &mut found_secret);
        if let (Some(id), Some(secret)) = (&found_id, &found_secret) {
            return ScanOutcome::Found(id.clone(), secret.clone(), file_len, mtime);
        }
        if carry.len() > CLIENT_DISCOVERY_OVERLAP_BYTES {
            let drop = carry.len() - CLIENT_DISCOVERY_OVERLAP_BYTES;
            carry.drain(..drop);
        }
        if scanned >= per_file_cap {
            // The cap is a bound on how many bytes this one candidate may
            // cost the pass, and must hold even when `file_len` (a `stat`
            // taken once, before any of these reads — see the comment
            // there) turns out to have been wrong: a file that grew after
            // that `stat` keeps handing back real bytes on every further
            // `read`, never the `0` that would actually mean "nothing more
            // to read". Falling through here on the strength of `scanned
            // >= file_len` was trusting that stale number in exactly the
            // direction that matters — measured directly: a stat of `0`
            // against an actual 8 MiB file, a 1 MiB cap and a 6 MiB shared
            // budget read the full 6 MiB instead of stopping at the cap's
            // own 1 MiB. So this site now settles and leaves rather than
            // ever reading on, the same as the top-of-loop `*budget == 0`
            // site it mirrors:
            if scanned < file_len {
                // A genuine cutoff — the candidate holds more than was
                // read, so `truncated = true`, and no further byte of it is
                // ever read.
                truncated = true;
                break;
            }
            // `scanned >= file_len`: whether or not this candidate is
            // still readable beyond `per_file_cap` (the very question the
            // stale-stat case above answers "yes" to), this call has
            // already decided to stop reading it either way — so settle
            // directly, the same acceptance the real EOF branch below
            // gives a match once nothing more will ever be read from this
            // candidate.
            accept_settled_match(&carry, id_pattern, true, &mut found_id);
            accept_settled_match(&carry, secret_pattern, true, &mut found_secret);
            if let (Some(id), Some(secret)) = (&found_id, &found_secret) {
                return ScanOutcome::Found(id.clone(), secret.clone(), file_len, mtime);
            }
            break;
        }
    }
    if truncated {
        ScanOutcome::Truncated
    } else {
        ScanOutcome::NotFound
    }
}

/// The most a token-refresh response body is ever read as, in bytes — 1 MiB,
/// read through `into_reader().take(...)` on *both* the success and error
/// paths below (see [`read_capped_body`]) rather than trusting
/// `Response::into_json` to buffer whatever `token_url` sends: an
/// `allowed_hosts` entry names a host, not a promise that whatever answers
/// there behaves, and a token endpoint (compromised, or simply broken) that
/// streams gigabytes must not be read into memory in full before this ever
/// gets to look at it. A real access-token response is a handful of short
/// fields; 1 MiB is generous for that and nowhere near what a captured
/// endpoint could use to exhaust memory on every refresh attempt.
const OAUTH_RESPONSE_MAX_BYTES: u64 = 1024 * 1024;

/// Read `reader` fully into memory, refusing anything past
/// [`OAUTH_RESPONSE_MAX_BYTES`] rather than buffering an unbounded body (see
/// that constant's own doc for why). `take(CAP + 1)`, one byte over the cap
/// on purpose: a body of *exactly* `CAP` bytes and one that keeps going both
/// read exactly `CAP` bytes through a plain `take(CAP)`, and would be
/// indistinguishable from each other — reading the one extra byte is what
/// lets this tell "ended right at the cap" from "still going" apart.
fn read_capped_body(reader: impl std::io::Read) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut buf = Vec::new();
    reader
        .take(OAUTH_RESPONSE_MAX_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("token refresh: reading the response body failed: {e}"))?;
    if buf.len() as u64 > OAUTH_RESPONSE_MAX_BYTES {
        return Err(format!(
            "token refresh: response body exceeded {OAUTH_RESPONSE_MAX_BYTES} bytes"
        ));
    }
    Ok(buf)
}

fn oauth_refresh_request(
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<Value, String> {
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(std::time::Duration::from_secs(15))
        .build();
    let result = agent.post(token_url).send_form(&[
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("refresh_token", refresh_token),
        ("grant_type", "refresh_token"),
    ]);
    match result {
        Ok(r) => {
            let body = read_capped_body(r.into_reader())?;
            serde_json::from_slice(&body).map_err(|e| format!("token refresh: bad response ({e})"))
        }
        Err(ureq::Error::Status(code, resp)) => {
            // The `error` field is an OAuth error code (`invalid_grant`,
            // `invalid_client`, …) — safe to name, and the only part worth
            // naming. The response is consumed for it, nothing else. A body
            // over the cap simply fails to yield an `oauth_error` at all —
            // the match below already degrades an unreadable/unparsed body
            // to the bare status, the same outcome as if the endpoint had
            // sent no `error` field to begin with.
            let oauth_error = read_capped_body(resp.into_reader())
                .ok()
                .and_then(|body| serde_json::from_slice::<Value>(&body).ok())
                .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_owned));
            // The `error` value comes from the endpoint that just received the
            // secret, so it is never printed raw — only matched against the
            // fixed RFC 6749 §5.2 vocabulary. A code outside it degrades to the
            // bare status, so nothing the server chose to put there reaches the
            // message.
            const KNOWN: &[&str] = &[
                "invalid_request",
                "invalid_client",
                "invalid_grant",
                "unauthorized_client",
                "unsupported_grant_type",
                "invalid_scope",
            ];
            Err(match oauth_error.as_deref() {
                Some("invalid_grant") => "token refresh: the saved sign-in is no longer valid — sign in to Antigravity again".to_string(),
                Some(code_str) if KNOWN.contains(&code_str) => oauth_error_message(code_str, code),
                _ => format!("token refresh failed: HTTP {code}"),
            })
        }
        Err(e) => Err(format!("token refresh failed: {e}")),
    }
}

/// The fixed prefix [`oauth_error_message`] builds every known RFC 6749
/// §5.2 error code onto (`invalid_grant` is the one exception — see
/// `oauth_refresh_request`, it gets its own, different message before this
/// ever runs). Shared with [`is_invalid_client`] so the producer and the
/// check can never drift apart the way two copies of the same literal
/// string eventually would.
const OAUTH_ERROR_PREFIX: &str = "token refresh failed: ";

/// The message [`oauth_refresh_request`] builds for a *known* OAuth error
/// `code` at HTTP `status` — pulled out to a named function precisely so
/// [`is_invalid_client`] checks against the same prefix this produces,
/// rather than a second literal that could silently stop matching the day
/// one of the two changes and the other does not.
fn oauth_error_message(code: &str, status: u16) -> String {
    format!("{OAUTH_ERROR_PREFIX}{code} (HTTP {status})")
}

/// True for exactly the error text [`oauth_error_message`] builds for the
/// code `invalid_client` — the code [`oauth_refresh_step`] reacts to by
/// evicting a cached discovery result (see `client_discovery_evict`'s own
/// doc: the pair itself is wrong, not merely that this attempt failed).
/// Checked as an exact prefix, not a bare substring: `oauth_refresh_request`'s
/// `Err(e)` arm can carry a transport-layer error's own text through
/// unmodified, and this must not mistake whatever a lower layer happened to
/// say (a DNS or TLS error that merely *mentions* the words "invalid
/// client") for the endpoint itself calling the pair wrong. Deliberately
/// does not call `oauth_error_message` itself — that needs a `status` this
/// has no reason to know, since any status is still `invalid_client`.
fn is_invalid_client(err: &str) -> bool {
    err.starts_with(&format!("{OAUTH_ERROR_PREFIX}invalid_client "))
}

/// The most a refreshed token is ever cached as living, in seconds — 24
/// hours. A real OAuth2 access token runs minutes to a handful of hours;
/// nothing legitimate needs longer, and without this cap a token endpoint
/// sending an implausible `expires_in` (`i64::MAX`, or simply ten years —
/// whether by bug or by a captured `token_url` an operator's own
/// `allowed_hosts` mistakenly let through) would have `oauth_refresh_step`
/// cache a `Fresh` entry this process goes on serving for as long as it
/// runs, dead credential and all, with `throttle::fingerprint`'s own escape
/// hatch (a changed token forces a redraw) never getting the chance to fire.
/// Clamped, not refused outright — the access token itself is still good;
/// only the endpoint's claim about how long is not believed past this
/// point — and logged once per process when it actually bites, since a
/// provider sending this every single refresh is worth knowing about, not
/// silently absorbing forever.
const EXPIRES_IN_MAX_SECS: i64 = 24 * 60 * 60;

/// The two fields this step needs out of a refresh response: the access token
/// and how long it lasts. Pure, so the success path is tested without a
/// network call. A non-string/blank `access_token` is "no usable token". A
/// missing `expires_in` falls back to a conservative hour; one that is zero
/// or negative is rejected outright (`None`) — a token already dead on
/// arrival would be cached expired and re-fetched on every tick, reopening
/// the very pacing hole the cache exists to close — and one implausibly far
/// in the future is clamped to [`EXPIRES_IN_MAX_SECS`] rather than believed
/// (see that constant's own doc for why an unbounded value is a real hole,
/// not merely an odd one). `expires_in` itself is read as whatever shape an
/// OAuth2 server actually sends it in — a JSON integer, a JSON float
/// (`3599.0`, truncated: a fractional second of validity is not worth
/// keeping), or a numeric string (`"3600"`) some deployments send instead —
/// through [`numeric_expires_in`] rather than `Value::as_i64` alone, which
/// silently reads `None` (and so the conservative-hour default, potentially
/// wrong either way) for any of the last two.
fn extract_access_token(value: &Value) -> Option<(String, i64)> {
    let token = value.get("access_token")?.as_str()?.trim();
    if token.is_empty() {
        return None;
    }
    let expires_in = value
        .get("expires_in")
        .and_then(numeric_expires_in)
        .unwrap_or(3600);
    // `<= 60`, not just `<= 0`: a token that outlives the 60s cache margin by
    // nothing would be cached already expired (`now + expires_in - 60 <= now`)
    // and re-fetched every tick. Below the margin it is useless to this step,
    // so it is treated as no token — the caller backs off instead of looping.
    if expires_in <= 60 {
        return None;
    }
    let expires_in = if expires_in > EXPIRES_IN_MAX_SECS {
        queue_diag_once(
            expires_in_clamped_key(),
            format!(
                "oauth-refresh: token endpoint sent expires_in={expires_in}s — clamped to \
                 {EXPIRES_IN_MAX_SECS}s"
            ),
        );
        EXPIRES_IN_MAX_SECS
    } else {
        expires_in
    };
    Some((token.to_string(), expires_in))
}

/// Dedup key for [`queue_diag_once`]'s once-per-process "expires_in
/// clamped" notice — a fixed value, not derived from anything about the
/// call it is about: a token endpoint sending one implausible value tonight
/// and another tomorrow does not need two lines saying essentially the same
/// thing.
fn expires_in_clamped_key() -> u64 {
    use std::hash::Hasher;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hash_part(&mut hasher, "expires_in-clamped");
    hasher.finish()
}

/// `expires_in` as OAuth2 servers actually send it: a JSON integer in the
/// common case, sometimes a JSON float, and at least one deployment we've
/// measured sends it as a numeric string. Anything else (`null`, an object,
/// `"soon"`) reads back `None`, the same as the field being absent
/// altogether, so the caller's own default takes over rather than this
/// guessing at a number. Truncates toward zero on a fractional value —
/// `3599.7` is kept as `3599`, never rounded up past what the endpoint
/// actually promised.
fn numeric_expires_in(value: &Value) -> Option<i64> {
    if let Some(i) = value.as_i64() {
        return Some(i);
    }
    if let Some(f) = value.as_f64() {
        return Some(f as i64);
    }
    value.as_str()?.trim().parse::<f64>().ok().map(|f| f as i64)
}

// ── JSON token-path helpers ───────────────────────────────────────────────

/// Resolve a `token_json_path`-style spec (`|`-separated fallback candidates,
/// each a `.`-separated path of object keys — see
/// [`crate::plugin::manifest::split_fallback_keys`]) against a JSON string,
/// returning the first candidate that resolves to a non-empty string.
fn extract_token(json_text: &str, token_json_path: &str) -> Option<String> {
    let value: Value = serde_json::from_str(json_text).ok()?;
    extract_token_at(&value, token_json_path)
}

fn extract_token_at(value: &Value, token_json_path: &str) -> Option<String> {
    for candidate in split_fallback_keys(token_json_path) {
        if let Some(t) = json_path_str(value, candidate) {
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

fn json_path_str<'v>(root: &'v Value, path: &str) -> Option<&'v str> {
    json_path_value(root, path)?.as_str()
}

/// Resolve a `.`-separated dotted path against a JSON value, returning
/// whatever it names — not only a string ([`json_path_str`]'s own job), so
/// [`token_expiry`] can read an `expiry_json_path` that names a number.
fn json_path_value<'v>(root: &'v Value, path: &str) -> Option<&'v Value> {
    let mut cur = root;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

// ── Small validation helper ───────────────────────────────────────────────

/// Every `Option<...>` field on [`AuthStep`] is only meaningful for a subset
/// of [`AuthType`]s; a manifest that picks a `type` without the fields it
/// needs is a configuration bug, reported as a (Present-err-shaped) error
/// rather than silently treated as absent.
fn require_str<'a>(kind: &str, field: &str, value: Option<&'a str>) -> Result<&'a str, String> {
    value.ok_or_else(|| format!("`{kind}` auth step: missing required field `{field}`"))
}

#[cfg(target_os = "windows")]
fn require_vec<'a>(
    kind: &str,
    field: &str,
    value: Option<&'a [String]>,
) -> Result<&'a [String], String> {
    match value {
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(format!(
            "`{kind}` auth step: missing required field `{field}`"
        )),
    }
}

// ── macOS credential helpers ──────────────────────────────────────────────

/// How long `keychain_password` waits for `security find-generic-password`
/// before treating it as hung, killing it, and reporting a timeout instead
/// of blocking this step — and the throttle gate behind it in
/// `resolve_token`, and every other surface this process is watching along
/// with it — for as long as a wedged Keychain daemon (or a first-run access
/// prompt nobody is there to answer) keeps `security` from ever exiting.
/// Thirty seconds: a prompt a user is actually answering can take a while,
/// but nothing legitimate needs longer than that.
#[cfg(any(target_os = "macos", test))]
const KEYCHAIN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// The current fetch pass, bumped by [`begin_fetch_pass`] and read by
/// [`keychain_password`]'s memo below. Not gated to macOS — `main.rs` calls
/// `begin_fetch_pass` from the one-second tick unconditionally, the same
/// call on every platform, and the counter itself is a plain atomic with
/// nothing OS-specific about it; only the memo that reads it is macOS-only,
/// alongside the Keychain call it exists to save.
static FETCH_PASS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Start a new fetch pass. [`keychain_password`]'s memo is scoped to this
/// number rather than to the process: a surface asked again minutes later
/// (its own next `refresh_secs`) still gets a live Keychain read — this is
/// not a TTL, and deliberately not one, since a short TTL would not save
/// anything at that cadence and a long one would hide a token CLI-side
/// rotation just replaced, handing the surface a stale credential and the
/// wrong 401 — but several surfaces sharing one tick's wave of spawned
/// fetches (or one surface asked twice in quick succession, an impatient
/// tray click while the previous fetch is still settling) share one read per
/// distinct `service` instead of one each. Called once per one-second tick,
/// before any fetch for it is spawned, never from inside a fetch itself —
/// that would just be another process-lifetime static with extra steps.
pub fn begin_fetch_pass() -> u64 {
    FETCH_PASS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
}

/// One `service`'s most recent [`keychain_password`] outcome, alongside the
/// pass it was read under — see [`begin_fetch_pass`] for what a pass is.
#[cfg(target_os = "macos")]
type KeychainMemo = std::collections::HashMap<String, (u64, Result<Option<String>, String>)>;

/// [`keychain_password`]'s memo, keyed by `service` — see [`begin_fetch_pass`]
/// for the pass it is scoped to. Every `Mutex` this module keeps recovers
/// from poison the same way (`.lock().unwrap_or_else(|e| e.into_inner())`,
/// [`REFRESH_CACHE`]'s own convention): a panic in some other thread while
/// holding one of these must not be what stops every later Keychain read in
/// the process.
#[cfg(target_os = "macos")]
static KEYCHAIN_MEMO: std::sync::Mutex<Option<KeychainMemo>> = std::sync::Mutex::new(None);

/// The read half of a pass-scoped memo: `Some(value)` only when `key` was
/// last stored under exactly `pass`, `None` for a miss or a value stored
/// under any other pass — pulled out of [`keychain_password`] pure, with no
/// `Mutex` or Keychain call of its own, so the one property this memo exists
/// for ("bound to a pass, not to the process") is directly testable without
/// a real `security` invocation anywhere near the test. `cfg`-gated the same
/// way as its only real caller, plus `test`: on a platform build with no
/// Keychain to memoise, nothing else calls this, and the tests below call it
/// directly regardless of platform.
#[cfg(any(target_os = "macos", test))]
fn pass_memo_get<T: Clone>(
    memo: &Option<std::collections::HashMap<String, (u64, T)>>,
    key: &str,
    pass: u64,
) -> Option<T> {
    memo.as_ref()?
        .get(key)
        .filter(|(cached_pass, _)| *cached_pass == pass)
        .map(|(_, value)| value.clone())
}

/// Read a Keychain "generic password" item. `Ok(None)` means the item
/// doesn't exist (Absent); `Err` means it exists but couldn't be read
/// (usually a denied access prompt) — or that `security` did not finish
/// within [`KEYCHAIN_DEADLINE`] and was killed.
///
/// Memoised for the current [`begin_fetch_pass`] pass, by `service`: three
/// surfaces (or one, asked more than once) sharing one pass collapse into
/// one `security` spawn — two threads to drain its pipes and a `try_wait`
/// loop against [`KEYCHAIN_DEADLINE`], every time this would otherwise run —
/// without losing freshness, since a pass this stale is never served (see
/// `begin_fetch_pass`'s own doc for why that is a pass boundary and not a
/// TTL).
///
/// Check-then-act, not a single atomic lookup-or-insert: the miss check
/// below and the store after `security` returns are two separate critical
/// sections, so two fetch threads that both miss the memo for the same
/// `service` in the same pass can both spawn `security` and both write the
/// result. Deliberate — the alternative is holding the lock across the
/// subprocess itself, which would make every other plugin's fetch (any
/// service, not just this one) wait out this one's up-to-[`KEYCHAIN_DEADLINE`]
/// call before it could even check its own memo. The shipped manifests as of
/// this writing name three distinct services (Claude CLI's Keychain item,
/// Claude Desktop's Safe Storage key, and Antigravity's), so today this memo
/// has nothing to collapse *across* surfaces — it pays off on a surface
/// asked more than once in one pass, and on any future manifest that reuses
/// a `service` another one already names.
#[cfg(target_os = "macos")]
fn keychain_password(service: &str) -> Result<Option<String>, String> {
    let pass = FETCH_PASS.load(std::sync::atomic::Ordering::Relaxed);
    {
        let memo = KEYCHAIN_MEMO.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(hit) = pass_memo_get(&memo, service, pass) {
            return hit;
        }
    }
    let result = (|| {
        let out = run_command_with_deadline(
            "security",
            &["find-generic-password", "-s", service, "-w"],
            KEYCHAIN_DEADLINE,
        )?;
        classify_keychain_output(out.success, &out.stdout, &out.stderr, service)
    })();
    let mut memo = KEYCHAIN_MEMO.lock().unwrap_or_else(|e| e.into_inner());
    memo.get_or_insert_with(std::collections::HashMap::new)
        .insert(service.to_string(), (pass, result.clone()));
    result
}

/// What [`run_command_with_deadline`] collected: whatever a command wrote to
/// each stream, and whether it exited successfully — the same three things
/// `std::process::Output` carries, kept as a struct of this module's own
/// rather than reusing that type directly: a timed-out run has no real
/// `ExitStatus` to report (the command was killed, not exited), and
/// `run_command_with_deadline` reports that case as `Err` instead, so this
/// only ever needs to represent a run that actually finished.
#[cfg(any(target_os = "macos", test))]
#[derive(Debug)]
struct DeadlineOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Kill `child` and reap it — the same two calls at each of
/// [`run_command_with_deadline`]'s three exits that give up on a child
/// rather than wait for it to exit on its own, named once here so a test can
/// point it at a real child and prove the kill directly, the same way a real
/// `Builder::spawn` failure (the one exit that reaches this through
/// [`pipe_drain_failure_message`] rather than a timeout or a `try_wait`
/// error) cannot be forced on demand.
#[cfg(any(target_os = "macos", test))]
fn kill_and_wait(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Spawn `program` with `args`, capturing both stdout and stderr, and wait at
/// most `deadline` for it to exit — the pattern `main.rs`'s own
/// `run_with_deadline` established for the auto-ping subprocess (kill on
/// timeout, drain the pipes on threads of their own rather than block
/// reading them while also blocking on the wait), reimplemented here rather
/// than imported: this is the library crate, `run_with_deadline` belongs to
/// the binary, and nothing under `src/plugin` can reach across that
/// boundary. `program`/`args` are parameters, not a `security` call baked
/// in, precisely so a test can point this at a stand-in (`sleep`, `sh -c
/// …`) and prove the kill without a real Keychain ever hanging a test.
///
/// Killed and reported (`Err`) on timeout, never left running: the whole
/// point is that a caller waiting on this gets an answer inside `deadline`,
/// one way or another. Stdout/stderr are drained on threads of their own
/// while this waits rather than read after the fact, the same "shared, not
/// joined" reasoning `main.rs`'s own version documents for its stderr drain
/// — a killed command's pipe can still be held open by a grandchild it
/// spawned, and joining the drain thread here would reinstate, inside this
/// function's own cleanup, the exact hang the deadline exists to end.
#[cfg(any(target_os = "macos", test))]
fn run_command_with_deadline(
    program: &str,
    args: &[&str],
    deadline: std::time::Duration,
) -> Result<DeadlineOutput, String> {
    use std::time::Instant;

    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("{program}: {e}"))?;

    // Both drains have to at least be attempted before either failure is
    // acted on, or a stdout thread the OS happily hands out would be started
    // (and would have to be torn down again) for a stderr one it refuses.
    let stdout_buf = drain_pipe(child.stdout.take());
    let stderr_buf = drain_pipe(child.stderr.take());
    // Whichever failed left its own end of the pipe closed under the child
    // (see `drain_pipe`'s own doc): honest here is killing it outright and
    // reporting why, not waiting to see what a `SIGPIPE` it never asked for
    // does to it.
    if let Some(msg) = pipe_drain_failure_message(program, &stdout_buf, &stderr_buf) {
        kill_and_wait(&mut child);
        return Err(msg);
    }
    let (stdout_buf, stderr_buf) = (
        stdout_buf.expect("checked by pipe_drain_failure_message above"),
        stderr_buf.expect("checked by pipe_drain_failure_message above"),
    );

    let expiry = Instant::now() + deadline;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= expiry => {
                // One more check first, the same race `main.rs`'s own
                // version closes the same way: a process that finished
                // during the last sleep is not one this deadline killed.
                if let Ok(Some(status)) = child.try_wait() {
                    break Some(status);
                }
                kill_and_wait(&mut child);
                break None;
            }
            // Polled rather than blocked on, because a blocking wait can't
            // be woken by a deadline.
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
            Err(_) => {
                kill_and_wait(&mut child);
                break None;
            }
        }
    };
    let Some(status) = status else {
        return Err(format!(
            "{program} did not finish within {}s — killed",
            deadline.as_secs()
        ));
    };
    Ok(DeadlineOutput {
        success: status.success(),
        stdout: stdout_buf.lock().map(|b| b.clone()).unwrap_or_default(),
        stderr: stderr_buf.lock().map(|b| b.clone()).unwrap_or_default(),
    })
}

/// Drain `pipe` into a buffer on a thread of its own, handing back the other
/// end of that same buffer rather than the thread's `JoinHandle` — see
/// [`run_command_with_deadline`]'s own doc for why that thread is never
/// joined. `None` (no pipe at all) reads back as an empty buffer, the same as
/// a command that wrote nothing on this stream — but the OS refusing to hand
/// out a thread is `Err`, not that: the closure this never runs is dropped
/// right along with the pipe it moved, closing this process's read end, and
/// `Command` leaves the child's `SIGPIPE` disposition at `SIG_DFL`, so the
/// very next line it writes on this stream kills it outright. That is not
/// "wrote nothing" — the caller has to know, and kill the rest of it.
/// Read `source` to EOF, appending every byte into `sink` — the loop
/// [`drain_pipe`]'s own thread runs, pulled out so a test can drive it
/// against anything that implements `Read`, not only a real pipe.
///
/// A signal landing mid-read is not a failure to read the pipe — retried
/// rather than treated as EOF, the same convention the file-scan loop above
/// uses for the same syscall. Any other `Err` *is* treated as EOF.
#[cfg(any(target_os = "macos", test))]
fn drain_into(mut source: impl std::io::Read, sink: &std::sync::Mutex<Vec<u8>>) {
    let mut chunk = [0u8; 4096];
    loop {
        match source.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if let Ok(mut kept) = sink.lock() {
                    kept.extend_from_slice(&chunk[..n]);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn drain_pipe(
    pipe: Option<impl std::io::Read + Send + 'static>,
) -> Result<std::sync::Arc<std::sync::Mutex<Vec<u8>>>, std::io::Error> {
    let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let Some(pipe) = pipe else {
        return Ok(buf);
    };
    let sink = std::sync::Arc::clone(&buf);
    std::thread::Builder::new().spawn(move || drain_into(pipe, &sink))?;
    Ok(buf)
}

/// Whether either [`drain_pipe`] call failed to even start, and if so, the
/// one line [`run_command_with_deadline`] reports for it — stdout's error
/// ahead of stderr's when, somehow, both did, since a caller staring at "no
/// output at all" is more likely checking stdout's failure first. Pure so
/// this policy — which of the two wins, and the exact message — is provable
/// without an OS that will actually refuse a thread on demand.
#[cfg(any(target_os = "macos", test))]
fn pipe_drain_failure_message(
    program: &str,
    stdout: &Result<std::sync::Arc<std::sync::Mutex<Vec<u8>>>, std::io::Error>,
    stderr: &Result<std::sync::Arc<std::sync::Mutex<Vec<u8>>>, std::io::Error>,
) -> Option<String> {
    let e = stdout.as_ref().err().or(stderr.as_ref().err())?;
    Some(format!(
        "{program}: could not start a pipe-drain thread: {e}"
    ))
}

/// Classify the raw result of `security find-generic-password …` into the
/// three-way Present-ok / Present-err / Absent outcome the auth chain uses:
/// success with a non-empty password is Present-ok (`Ok(Some(_))`); success
/// with an empty password, and a failure whose stderr says the item doesn't
/// exist, are both Absent (`Ok(None)`) — the chain moves on / the surface
/// hides, exactly like a missing file; any other failure (almost always a
/// denied access prompt) is Present-err (`Err`).
/// Split out of `keychain_password` so this stderr-sniffing logic can be
/// unit-tested without a real Keychain (see `tests::classify_keychain_*`).
#[cfg(any(target_os = "macos", test))]
fn classify_keychain_output(
    success: bool,
    stdout: &[u8],
    stderr: &[u8],
    service: &str,
) -> Result<Option<String>, String> {
    if success {
        let s = String::from_utf8_lossy(stdout).trim().to_string();
        Ok(if s.is_empty() { None } else { Some(s) })
    } else {
        let err = String::from_utf8_lossy(stderr);
        if err.contains("could not be found") {
            Ok(None)
        } else {
            Err(format!("allow Keychain access to '{service}'"))
        }
    }
}

/// Chromium/Electron Safe Storage scheme (macOS): AES-128-CBC, key =
/// PBKDF2-HMAC-SHA1(pw, "saltysalt", 1003, 16), IV = 16 spaces, PKCS7
/// padding. An optional `v10` prefix marks the ciphertext.
#[cfg(any(target_os = "macos", test))]
fn safe_storage_decrypt(blob: &[u8], pw: &str) -> Result<Vec<u8>, String> {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};

    let ct = blob.strip_prefix(b"v10").unwrap_or(blob);

    let mut key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(pw.as_bytes(), b"saltysalt", 1003, &mut key);
    let iv = [0x20u8; 16];

    type Dec = cbc::Decryptor<aes::Aes128>;
    let mut buf = ct.to_vec();
    let pt = Dec::new(&key.into(), &iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| "Safe Storage decrypt failed".to_string())?;
    Ok(pt.to_vec())
}

// ── Windows credential helpers (written against the Win32 APIs; built and
//    run on Windows 11 x86_64 MSVC — reached, but not yet against a real
//    stored credential, per SECURITY.md's own note) ────────────────────────

/// Read a Windows Credential Manager "generic" credential. `None` on *any*
/// failure (no such target, or an unreadable/non-UTF8 blob) — the caller
/// tries the next target name rather than distinguishing failure kinds (see
/// `win_credential_step`).
#[cfg(target_os = "windows")]
fn win_credential(target: &str) -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::Security::Credentials::{
        CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
    };
    let wide: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let mut cred: *mut CREDENTIALW = std::ptr::null_mut();
        CredReadW(PCWSTR(wide.as_ptr()), CRED_TYPE_GENERIC, 0, &mut cred).ok()?;
        let c = &*cred;
        // An empty stored credential (deliberately blanked out, or never
        // written a value) leaves `CredentialBlob` null with size 0;
        // `slice::from_raw_parts` requires a non-null pointer even for a
        // zero-length slice, so that combination is checked for before the
        // slice is built rather than after — a null blob just yields no
        // token, the same as any other credential that doesn't carry one.
        let token = if c.CredentialBlob.is_null() || c.CredentialBlobSize == 0 {
            None
        } else {
            let bytes = std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize)
                .to_vec();
            String::from_utf8(bytes).ok()
        };
        CredFree(cred as *const _ as *const core::ffi::c_void);
        token
    }
}

/// Decrypt an Electron Safe Storage blob on Windows via DPAPI (per-user).
#[cfg(target_os = "windows")]
fn windows_dpapi_decrypt(blob: &[u8]) -> Result<Vec<u8>, String> {
    use windows::Win32::Foundation::LocalFree;
    use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

    // Newer Electron prefixes DPAPI blobs; strip a possible marker.
    let data = if blob.starts_with(b"v10") || blob.starts_with(b"v11") {
        &blob[3..]
    } else {
        blob
    };
    unsafe {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB::default();
        CryptUnprotectData(&in_blob, None, None, None, None, 0, &mut out_blob)
            .map_err(|e| format!("DPAPI: {e}"))?;
        // Same guard as `win_credential`'s blob: a zero-length decrypted
        // result can come back with `pbData` null, and `from_raw_parts`
        // requires a non-null pointer even then.
        let slice = if out_blob.pbData.is_null() || out_blob.cbData == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
        };
        let _ = LocalFree(windows::Win32::Foundation::HLOCAL(out_blob.pbData as _));
        Ok(slice)
    }
}

// ── Tests (hermetic: no network, no real Keychain, isolated temp dirs) ────

#[cfg(test)]
mod tests {
    use super::super::manifest::PluginManifest;
    use super::*;
    use serde_json::json;

    /// Guards **every** test in this module that calls `std::env::set_var`/
    /// `remove_var` — not only the discovery env tests below, but the older
    /// `PATH`/`TICKOVER_AUTH_TEST_*` tests further down this file too: all of
    /// them read/write real process environment, which is process-wide state
    /// `cargo test`'s default parallelism does not otherwise serialize.
    /// Distinct variable names per test already stop them from reading each
    /// other's values, but do not stop the underlying set/remove calls
    /// themselves from racing (a documented hazard of mutating environment
    /// from multiple threads at once), and `bin_candidates_ignores_relative_path_entries`
    /// clobbers `PATH` itself — a variable every other test that touches
    /// `PATH` (directly or via `super::cli_install_dirs`) shares, not one it
    /// owns. `.unwrap_or_else(|e| e.into_inner())`, not `.unwrap()`, at every
    /// call site: one test panicking while holding this lock must not poison
    /// it for every test queued behind it.
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Guards every test that calls [`take_pending_diagnostics`] —
    /// [`PENDING_DIAGNOSTICS`] is one process-wide queue shared by every
    /// test in this module, not one per key. A test's own unique key
    /// (a `std::process::id()`-suffixed env var name, say) stops it from
    /// *misreading* another test's line, but does nothing to stop a drain
    /// from *stealing* one: two tests racing `take_pending_diagnostics()` at
    /// once can each walk away with half of what was queued, and the one
    /// that expected to see its own line — queued a moment before it
    /// drained — finds an empty vec instead. Same poison-safety discipline
    /// as `ENV_TEST_LOCK`: `.unwrap_or_else(|e| e.into_inner())`, never
    /// `.unwrap()`.
    static DIAG_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn auth_step(kind: AuthType) -> AuthStep {
        AuthStep {
            kind,
            path: None,
            token_json_path: None,
            expiry_json_path: None,
            key_prefix: None,
            service: None,
            var: None,
            config_path: None,
            blob_json_path: None,
            macos_keychain_key: None,
            targets: None,
            json_path: None,
            unless_json_path: None,
            message: None,
            token_url: None,
            client_id: None,
            client_secret: None,
            client: None,
        }
    }

    fn surface(auth: Vec<AuthStep>) -> SurfaceConfig {
        SurfaceConfig {
            id: "test".to_string(),
            label: "Test".to_string(),
            opt_in: false,
            in_menu_bar: true,
            allowed_hosts: Vec::new(),
            no_credentials_message: None,
            auth,
        }
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tickover-auth-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    // ── extract_token / json path resolution ─────────────────────────────

    #[test]
    fn extract_token_finds_nested_camel_case_key() {
        let json = r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-abc","refreshToken":"r"}}"#;
        assert_eq!(
            extract_token(json, "claudeAiOauth.accessToken|access_token").as_deref(),
            Some("sk-ant-oat01-abc")
        );
    }

    #[test]
    fn extract_token_falls_back_to_flat_snake_case_key() {
        assert_eq!(
            extract_token(
                r#"{"access_token":"tok"}"#,
                "claudeAiOauth.accessToken|access_token"
            )
            .as_deref(),
            Some("tok")
        );
    }

    #[test]
    fn extract_token_missing_or_empty_is_none() {
        assert_eq!(
            extract_token(
                r#"{"claudeAiOauth":{"accessToken":""}}"#,
                "claudeAiOauth.accessToken|access_token"
            ),
            None
        );
        assert_eq!(
            extract_token("{}", "claudeAiOauth.accessToken|access_token"),
            None
        );
        assert_eq!(
            extract_token("not json", "claudeAiOauth.accessToken|access_token"),
            None
        );
    }

    #[test]
    fn unwrap_go_keyring_decodes_the_wrapped_payload() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let json = r#"{"token":{"access_token":"ya29.fresh"}}"#;
        let wrapped = format!("go-keyring-base64:{}", STANDARD.encode(json));
        assert_eq!(unwrap_go_keyring(&wrapped).unwrap(), json);
        // And the token then reads out of it exactly as a plain item would.
        assert_eq!(
            extract_token(&unwrap_go_keyring(&wrapped).unwrap(), "token.access_token").as_deref(),
            Some("ya29.fresh")
        );
    }

    #[test]
    fn unwrap_go_keyring_leaves_an_unwrapped_value_untouched() {
        // Every other Keychain item this app reads (Claude Desktop's) is plain
        // JSON with no prefix — it must pass through byte-for-byte.
        let plain = r#"{"claudeAiOauth":{"accessToken":"tok"}}"#;
        assert_eq!(unwrap_go_keyring(plain).unwrap(), plain);
    }

    #[test]
    fn unwrap_go_keyring_decodes_the_legacy_hex_marker() {
        // go-keyring reads a legacy `go-keyring-encoded:` (hex) marker too, not
        // only the base64 one it writes today — an item stored by an older
        // version of the library must unwrap the same way.
        let json = r#"{"token":{"access_token":"ya29.x"}}"#;
        let hex: String = json.bytes().map(|b| format!("{b:02x}")).collect();
        let wrapped = format!("go-keyring-encoded:{hex}");
        assert_eq!(unwrap_go_keyring(&wrapped).unwrap(), json);
        assert_eq!(
            extract_token(&unwrap_go_keyring(&wrapped).unwrap(), "token.access_token").as_deref(),
            Some("ya29.x")
        );
    }

    #[test]
    fn unwrap_go_keyring_reports_a_corrupt_payload() {
        let err = unwrap_go_keyring("go-keyring-base64:not valid base64!!")
            .expect_err("a wrapper marker over garbage is an error, not silent");
        assert!(err.contains("go-keyring-base64"), "{err}");
        // The hex marker over non-hex is equally an error, not a silent pass.
        let err = unwrap_go_keyring("go-keyring-encoded:zzzz")
            .expect_err("a hex marker over non-hex is an error");
        assert!(err.contains("go-keyring-encoded"), "{err}");
        // And a multi-byte char in the payload is an error, not a panic — the
        // credential path must never crash the tray. `€€` is six bytes (even
        // length, so the length guard passes) and would panic a byte-index
        // slice mid-character.
        assert!(
            unwrap_go_keyring("go-keyring-encoded:€€").is_err(),
            "a non-ASCII hex payload must error, not panic"
        );
    }

    #[test]
    fn read_capped_body_accepts_a_response_exactly_at_the_cap() {
        let body = vec![b'a'; OAUTH_RESPONSE_MAX_BYTES as usize];
        let out = read_capped_body(std::io::Cursor::new(body.clone()))
            .expect("exactly at the cap is fine");
        assert_eq!(out, body);
    }

    #[test]
    fn read_capped_body_refuses_a_response_one_byte_over_the_cap() {
        let body = vec![b'a'; (OAUTH_RESPONSE_MAX_BYTES + 1) as usize];
        let err = read_capped_body(std::io::Cursor::new(body))
            .expect_err("one byte over the cap must be refused, not silently truncated");
        assert!(err.contains("exceeded"), "{err}");
    }

    // ── oauth-refresh (up to, but not touching, the network) ─────────────

    fn oauth_refresh_step_for(dir: &std::path::Path, body: &str) -> AuthStep {
        let file = dir.join("oauth_creds.json");
        std::fs::write(&file, body).unwrap();
        AuthStep {
            path: Some(file.to_string_lossy().into_owned()),
            token_json_path: Some("refresh_token".to_string()),
            token_url: Some("https://oauth2.googleapis.com/token".to_string()),
            client_id: Some("test-client-id".to_string()),
            client_secret: Some("test-client-secret".to_string()),
            ..auth_step(AuthType::OauthRefresh)
        }
    }

    #[test]
    fn oauth_refresh_step_absent_when_file_missing() {
        let dir = temp_dir("oauth-absent");
        let mut step = oauth_refresh_step_for(&dir, r#"{"refresh_token":"r-1"}"#);
        step.path = Some(dir.join("no-such-file.json").to_string_lossy().into_owned());
        assert_eq!(
            oauth_refresh_step(&step, &["oauth2.googleapis.com".to_string()]),
            Ok(None)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oauth_refresh_step_present_err_when_refresh_token_is_missing() {
        let dir = temp_dir("oauth-no-token");
        // The stored access_token is what a plain read step would find instead
        // — present, and exactly the stale value this step exists to not rely on.
        let step = oauth_refresh_step_for(&dir, r#"{"access_token":"stale"}"#);
        let err = oauth_refresh_step(&step, &["oauth2.googleapis.com".to_string()])
            .expect_err("a file without a refresh token is Present-err, not Absent");
        assert!(
            err.contains("refresh_token") || err.contains("refresh token"),
            "{err}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oauth_refresh_step_refuses_a_token_url_outside_allowed_hosts() {
        let dir = temp_dir("oauth-blocked-host");
        let step = oauth_refresh_step_for(&dir, r#"{"refresh_token":"r-secret-value"}"#);
        let err = oauth_refresh_step(&step, &["example.com".to_string()])
            .expect_err("a token_url outside allowed_hosts must never be reached");
        assert!(err.contains("allowed_hosts"), "{err}");
        // The refresh token and client secret must never land in an error a
        // user could paste into a bug report.
        assert!(
            !err.contains("r-secret-value"),
            "refresh token leaked: {err}"
        );
        assert!(
            !err.contains("test-client-secret"),
            "client_secret leaked: {err}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oauth_refresh_step_refuses_an_empty_allowed_hosts() {
        let dir = temp_dir("oauth-no-hosts");
        let step = oauth_refresh_step_for(&dir, r#"{"refresh_token":"r-1"}"#);
        let err = oauth_refresh_step(&step, &[])
            .expect_err("an empty allowed_hosts must not default to \"anywhere\" here");
        assert!(err.contains("allowed_hosts"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oauth_refresh_step_missing_required_field_is_error() {
        let step = auth_step(AuthType::OauthRefresh);
        assert!(oauth_refresh_step(&step, &[]).is_err());
    }

    #[test]
    fn oauth_refresh_step_refuses_a_blocked_host_without_ever_reading_the_refresh_token_file() {
        // `path` never resolves to a real file — if the allow-list check
        // ran *after* the file read (the old order), this would hit the
        // "not signed in here" branch first and resolve `Ok(None)`, not an
        // error. Getting the `allowed_hosts` error instead proves the check
        // now runs before the file is ever touched.
        let dir = temp_dir("oauth-blocked-host-no-file");
        let mut step = oauth_refresh_step_for(&dir, r#"{"refresh_token":"r-1"}"#);
        step.path = Some(
            dir.join("does-not-exist.json")
                .to_string_lossy()
                .into_owned(),
        );
        let err = oauth_refresh_step(&step, &["example.com".to_string()]).expect_err(
            "a token_url outside allowed_hosts must be refused before the missing \
                         refresh-token file is ever reached",
        );
        assert!(err.contains("allowed_hosts"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oauth_refresh_step_refuses_a_plaintext_token_url() {
        // A credential-bearing request must be over TLS — an http token_url,
        // even to an allowed host, would put the refresh token and secret on
        // the wire in the clear. A non-routable local address, not a real
        // host: this must never be reached at all, but a test naming one
        // gives a false sense that it was ever going to be, and a real
        // domain has no reason to appear in a fixture that is never
        // actually contacted.
        let dir = temp_dir("oauth-http");
        let mut step = oauth_refresh_step_for(&dir, r#"{"refresh_token":"r-1"}"#);
        step.token_url = Some("http://127.0.0.1:1/token".to_string());
        let err = oauth_refresh_step(&step, &["127.0.0.1".to_string()])
            .expect_err("an http token_url must be refused before any request");
        assert!(err.contains("https"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── oauth-refresh's `client` discovery ────────────────────────────────
    //
    // Every fixture below hangs its uniqueness on a fresh `temp_dir` (a
    // nanosecond-timestamped path) somewhere in `files`, `bins` or an env var
    // name — the process-wide statics this module keeps
    // (`CLIENT_DISCOVERY_FOUND`/`_MISS`/`_LOGGED`, `PENDING_DIAGNOSTICS`) are
    // shared with every other test in this binary running in parallel, and a
    // config two tests happened to build identically would collide in all
    // four.

    fn synthetic_id_pattern() -> String {
        r"[0-9]+-[a-z]+\.apps\.googleusercontent\.com".to_string()
    }

    fn synthetic_secret_pattern() -> String {
        r"GOCSPX-[A-Za-z0-9]{10,}".to_string()
    }

    // The two shapes these fixtures need — a client id
    // (`\d{6,}-[a-z0-9]+\.apps\.googleusercontent\.com`) and a client secret
    // (`GOCSPX-` + 28 chars of `[A-Za-z0-9_-]`) — are exactly the shape a
    // public repository's secret scanner looks for, and a scanner can only
    // match a shape; it cannot tell a fixture value apart from a real one.
    // Every fixture below is therefore assembled at *run time* from parts
    // kept short of either shape on their own, through these two functions,
    // so no contiguous string in this file's *source* ever matches what the
    // scanner flags — the value that exists at test time is exactly as fake
    // as it always was, only never written down whole.
    fn fake_client_id(digits: &str, alnum: &str) -> String {
        format!("{digits}-{alnum}.apps.googleusercontent.com")
    }

    fn fake_secret(tail: &str) -> String {
        format!("GOCSPX-{tail}")
    }

    /// A [`ScanPattern`] built the same way `discover_client_within` builds
    /// one, for the tests below that call `scan_candidate` directly and so
    /// must supply their own — never a hand-written `max_len`, which could
    /// silently drift from whatever `compile_scan_pattern`/
    /// `regex_max_match_len` actually computes once either changed.
    fn scan_pattern(pattern: &str) -> ScanPattern {
        compile_scan_pattern(pattern).expect("test pattern must compile")
    }

    /// The `Found` a real `scan_candidate` call against `file` would build —
    /// same length/mtime read straight off the file, for a test asserting
    /// equality against `scan_candidate`'s own return value. Only correct
    /// when nothing touches `file` between it being written and scanned,
    /// true of every test that uses this: each writes its fixture once and
    /// scans it immediately after, with no further write in between.
    fn found(file: &Path, id: &str, secret: &str) -> ScanOutcome {
        let meta = std::fs::metadata(file).expect("fixture file must exist");
        ScanOutcome::Found(
            id.to_string(),
            secret.to_string(),
            meta.len(),
            meta.modified().expect("this platform must report mtime"),
        )
    }

    #[test]
    fn discover_client_finds_both_in_one_file() {
        let dir = temp_dir("discover-basic");
        let file = dir.join("client-binary");
        let id = fake_client_id("444444", "basicfind");
        let secret = fake_secret("basicfindsecret0123456789ABCD");
        std::fs::write(
            &file,
            format!("noise noise {id} more noise {secret} trailing"),
        )
        .unwrap();
        let client = AuthClientDiscovery {
            id_env: None,
            secret_env: None,
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![file.to_string_lossy().into_owned()],
            bins: Vec::new(),
        };

        assert_eq!(discover_client(&client), Some((id, secret)));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scan_candidate_with_the_shipped_exact_id_pattern_does_not_swallow_a_leading_digit() {
        // The exact motivation for shipping `{13}`/`{32}` (the counts
        // measured against the real Antigravity binaries) instead of a
        // merely *bounded* `{1,20}`/`{1,40}`: with the bounded form, a stray
        // digit immediately before the real id in the binary extends the
        // digit run the pattern is willing to match, and `find`'s leftmost
        // match then starts one byte too early — a 14-digit run is a
        // *different, wrong* id, not the real 13-digit one with an extra
        // character in front. An exact `{13}` cannot match that longer run
        // at all: consuming its first 13 digits leaves a 14th digit where
        // the literal `-` is required, the attempt fails, and `find` retries
        // one position later — landing exactly on the real id.
        let dir = temp_dir("scan-shipped-id-pattern");
        let file = dir.join("client-binary");
        let real_id = fake_client_id("1234567890123", "abcdefghijklmnopqrstuvwxyz012345");
        let real_secret = fake_secret("shippedpatterntestsecret0123456789AB");
        let mut content = b"leading padding text ending in a digit9".to_vec();
        content.extend_from_slice(real_id.as_bytes());
        content.push(b' ');
        content.extend_from_slice(real_secret.as_bytes());
        std::fs::write(&file, &content).unwrap();

        // The exact pattern this crate ships in `plugins/antigravity.toml`,
        // not the loosely-bounded `synthetic_id_pattern()` every other test
        // in this module uses — that pattern is deliberately the thing
        // under test here.
        let id_pattern = scan_pattern(r"[0-9]{13}-[a-z0-9]{32}\.apps\.googleusercontent\.com");
        let secret_pattern = scan_pattern(&synthetic_secret_pattern());
        let mut budget = CLIENT_DISCOVERY_PASS_BUDGET_BYTES;
        assert_eq!(
            scan_candidate(
                &file,
                &id_pattern,
                &secret_pattern,
                &mut budget,
                CLIENT_DISCOVERY_MAX_SCAN_BYTES
            ),
            found(&file, &real_id, &real_secret),
            "the leading digit must not be swallowed into the match"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_shipped_antigravity_id_pattern_skips_the_twelve_digit_client_that_precedes_the_real_one()
    {
        // Both installed binaries this pattern is measured against carry a
        // second, unrelated Google client id ahead of Antigravity's own — a
        // twelve-digit project number, one digit short of the thirteen
        // Antigravity's own client's project number carries. The patterns
        // under test are read straight off `plugins/antigravity.toml`, not
        // retyped here, so a manifest edit that drifted the digit count back
        // to twelve fails this assertion before it ever reaches the second
        // one below.
        let manifest_text = include_str!("../../plugins/antigravity.toml");
        let manifest =
            PluginManifest::from_str(manifest_text).expect("plugins/antigravity.toml must parse");
        let client = manifest
            .surface
            .first()
            .expect("antigravity.toml declares one surface")
            .auth
            .iter()
            .find_map(|step| step.client.as_ref())
            .expect("an auth step with a client table");
        let shipped_id_pattern = client
            .id_pattern
            .clone()
            .expect("the oauth-refresh step's client table names an id_pattern");
        let shipped_secret_pattern = client
            .secret_pattern
            .clone()
            .expect("the oauth-refresh step's client table names a secret_pattern");
        assert_eq!(
            shipped_id_pattern, r"[0-9]{13}-[a-z0-9]{32}\.apps\.googleusercontent\.com",
            "the pattern this test scans with must be the one the manifest actually ships"
        );
        assert_eq!(
            shipped_secret_pattern, "GOCSPX-[A-Za-z0-9_-]{28}",
            "the pattern this test scans with must be the one the manifest actually ships"
        );

        // filler, the foreign (twelve-digit) client id, filler, Antigravity's
        // own (thirteen-digit) client id, filler, then two secrets — all
        // synthetic, laid out in the same relative order the two installed
        // binaries carry them in.
        let foreign_id = fake_client_id("222233334444", "foreignprojectclientidzzzzzzzzz1");
        let real_id = fake_client_id("1234567890123", "antigravityownclientidxxxxxxxxxx");
        let first_secret = fake_secret("firstsecretbytesinthefile123");
        let second_secret = fake_secret("secondsecretbytesinthefile12");
        let mut content = b"binary noise before the foreign client id -- ".to_vec();
        content.extend_from_slice(foreign_id.as_bytes());
        content.extend_from_slice(b" -- more noise between the two client ids -- ");
        content.extend_from_slice(real_id.as_bytes());
        content.extend_from_slice(b" -- noise before the two secrets -- ");
        content.extend_from_slice(first_secret.as_bytes());
        content.extend_from_slice(b" -- ");
        content.extend_from_slice(second_secret.as_bytes());
        content.extend_from_slice(b" -- trailing noise");
        let dir = temp_dir("scan-shipped-id-pattern-skips-foreign-client");
        let file = dir.join("client-binary");
        std::fs::write(&file, &content).unwrap();

        let id_pattern = scan_pattern(&shipped_id_pattern);
        let secret_pattern = scan_pattern(&shipped_secret_pattern);
        let mut budget = CLIENT_DISCOVERY_PASS_BUDGET_BYTES;
        assert_eq!(
            scan_candidate(
                &file,
                &id_pattern,
                &secret_pattern,
                &mut budget,
                CLIENT_DISCOVERY_MAX_SCAN_BYTES
            ),
            found(&file, &real_id, &first_secret),
            "the shipped, thirteen-digit pattern must land on Antigravity's own id and \
             the first secret, not the foreign twelve-digit id ahead of it"
        );

        // Why the digit count is pinned: the very same buffer, scanned with
        // the old twelve-digit pattern, finds the foreign id instead — it
        // appears first in the file, and a pattern that admits twelve digits
        // has no way to tell it apart from the real one.
        let old_id_pattern = scan_pattern(r"[0-9]{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com");
        let mut old_budget = CLIENT_DISCOVERY_PASS_BUDGET_BYTES;
        assert_eq!(
            scan_candidate(
                &file,
                &old_id_pattern,
                &secret_pattern,
                &mut old_budget,
                CLIENT_DISCOVERY_MAX_SCAN_BYTES
            ),
            found(&file, &foreign_id, &first_secret),
            "a pattern admitting twelve digits finds the foreign client id first"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discover_client_finds_a_match_straddling_a_chunk_boundary() {
        // The id is positioned so it starts a handful of bytes *before*
        // `CLIENT_DISCOVERY_CHUNK_BYTES` and finishes after it: the first
        // `scan_candidate` read ends mid-match, and only the carried overlap
        // reassembles it whole for the second. A match landing entirely
        // inside one chunk would prove nothing about that carry.
        let dir = temp_dir("discover-boundary");
        let id_text = fake_client_id("999999", "boundarytest");
        let secret_text = fake_secret("boundarytestsecret0123456789ABCDEFGH");
        let lead_len = CLIENT_DISCOVERY_CHUNK_BYTES - 10;
        let mut content = vec![b'x'; lead_len];
        content.extend_from_slice(id_text.as_bytes());
        content.extend_from_slice(b" -- ");
        content.extend_from_slice(secret_text.as_bytes());
        let file = dir.join("client-binary");
        std::fs::write(&file, &content).unwrap();

        let id_pattern = scan_pattern(&synthetic_id_pattern());
        let secret_pattern = scan_pattern(&synthetic_secret_pattern());
        let mut budget = CLIENT_DISCOVERY_PASS_BUDGET_BYTES;
        assert_eq!(
            scan_candidate(
                &file,
                &id_pattern,
                &secret_pattern,
                &mut budget,
                CLIENT_DISCOVERY_MAX_SCAN_BYTES
            ),
            found(&file, &id_text, &secret_text)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scan_candidate_does_not_accept_a_variable_length_match_cut_by_a_chunk_boundary() {
        // `synthetic_secret_pattern()` (`GOCSPX-[A-Za-z0-9]{10,}`), used by
        // most of this module's other fixtures, has no *upper* bound at
        // all, so `manifest::validate` would refuse it outright — it exists
        // here only for tests that never run it through validation. This
        // one instead uses `GOCSPX-[A-Za-z0-9]{10,40}`: bounded (40 is a
        // finite maximum, so validation accepts it), but still
        // variable-length, unlike every pattern this crate actually ships
        // (`{13}`, `{32}`, `{28}` — all exact). That variability is exactly
        // what let a chunk boundary cut the match short: an exact-length
        // pattern stops matching at its own count regardless of what chunk
        // it lands in, but this one is greedy, and greedy means "as much as
        // the buffer currently holds", not "as much as the real value is".
        let dir = temp_dir("scan-boundary-variable-length");
        let id_text = fake_client_id("321321", "varcut");
        // 40 alphanumerics — the pattern's own upper bound — assembled by
        // repeating a two-character unit rather than typed out by hand, so
        // the count is provably exact rather than merely believed to be.
        let secret_tail = "A1".repeat(20);
        assert_eq!(secret_tail.len(), 40);
        let secret_text = fake_secret(&secret_tail);
        assert_eq!(secret_text.len(), 47, "\"GOCSPX-\" (7) + 40 alphanumerics");

        // The id, then `-` padding (outside `[A-Za-z0-9]`, so it can never
        // extend a match into itself) up to exactly
        // `CLIENT_DISCOVERY_CHUNK_BYTES - 20`: the secret's first 20 bytes
        // ("GOCSPX-" plus 13 of its 40 trailing alphanumerics) then land in
        // the last 20 bytes of the first chunk read, and the remaining 27
        // land in the second. More `-` padding follows the secret so its
        // match cannot touch the end of the *second* chunk's carry either
        // — this test is about the boundary between reads, not about EOF
        // (that is `scan_candidate_finds_a_match_that_ends_exactly_at_eof`,
        // below).
        let mut content = id_text.as_bytes().to_vec();
        content.resize(CLIENT_DISCOVERY_CHUNK_BYTES - 20, b'-');
        content.extend_from_slice(secret_text.as_bytes());
        content.extend(std::iter::repeat_n(b'-', 256));
        let file = dir.join("client-binary");
        std::fs::write(&file, &content).unwrap();

        let id_pattern = scan_pattern(&synthetic_id_pattern());
        let secret_pattern = scan_pattern(r"GOCSPX-[A-Za-z0-9]{10,40}");
        let mut budget = CLIENT_DISCOVERY_PASS_BUDGET_BYTES;

        // Before this change: the first chunk's read ends exactly at
        // `CLIENT_DISCOVERY_CHUNK_BYTES`, 20 bytes into the secret — a
        // leftmost match of just those 20 bytes ("GOCSPX-" plus 13
        // alphanumerics) that the old, immediate-accept code took as
        // final and returned as `Found`. The full 47-byte secret is what
        // must come back instead.
        assert_eq!(
            scan_candidate(
                &file,
                &id_pattern,
                &secret_pattern,
                &mut budget,
                CLIENT_DISCOVERY_MAX_SCAN_BYTES
            ),
            found(&file, &id_text, &secret_text)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scan_candidate_finds_a_match_that_ends_exactly_at_eof() {
        // Same patterns as the sibling test above — a bounded but
        // variable-length secret, greedy enough to touch the end of
        // whatever has been read so far the moment nothing follows it.
        let id_pattern = scan_pattern(&synthetic_id_pattern());
        let secret_pattern = scan_pattern(r"GOCSPX-[A-Za-z0-9]{10,40}");

        // Variant 1: a small file (3000 bytes, not a multiple of the chunk
        // size) whose secret's last byte is the file's very last byte. The
        // single read that covers this whole file returns `n = 3000`, not
        // `0` — the match is deferred exactly as in the sibling test — and
        // it is only the *next* read, returning `0`, that settles it. This
        // is the ordinary "small candidate" shape and proves the EOF pass
        // runs at all.
        {
            let dir = temp_dir("scan-eof-small-file");
            let id_text = fake_client_id("222333", "eofsmall");
            let secret_tail = "B2".repeat(20);
            let secret_text = fake_secret(&secret_tail);
            let mut content = id_text.as_bytes().to_vec();
            content.push(b' ');
            let filler_len = 3000 - content.len() - secret_text.len();
            content.extend(std::iter::repeat_n(b'-', filler_len));
            content.extend_from_slice(secret_text.as_bytes());
            assert_eq!(content.len(), 3000);
            let file = dir.join("client-binary");
            std::fs::write(&file, &content).unwrap();

            let mut budget = CLIENT_DISCOVERY_PASS_BUDGET_BYTES;
            assert_eq!(
                scan_candidate(
                    &file,
                    &id_pattern,
                    &secret_pattern,
                    &mut budget,
                    CLIENT_DISCOVERY_MAX_SCAN_BYTES
                ),
                found(&file, &id_text, &secret_text)
            );
            std::fs::remove_dir_all(&dir).ok();
        }

        // Variant 2: the file is exactly `CLIENT_DISCOVERY_CHUNK_BYTES`
        // long, with the secret's last byte as the file's last byte too.
        // The first read requests (and gets) exactly one full chunk —
        // `n == CLIENT_DISCOVERY_CHUNK_BYTES`, still not `0` — so the read
        // that finally returns `0` only happens on the *next* call, once
        // the loop comes back around. If EOF were instead inferred from
        // `n < chunk.len()`, this read (`n == chunk.len()` exactly) would
        // never be recognised as reaching it, and the deferred match would
        // never settle.
        {
            let dir = temp_dir("scan-eof-exact-chunk");
            let id_text = fake_client_id("222444", "eofchunk");
            let secret_tail = "C3".repeat(20);
            let secret_text = fake_secret(&secret_tail);
            let mut content = id_text.as_bytes().to_vec();
            content.push(b' ');
            let filler_len = CLIENT_DISCOVERY_CHUNK_BYTES - content.len() - secret_text.len();
            content.extend(std::iter::repeat_n(b'-', filler_len));
            content.extend_from_slice(secret_text.as_bytes());
            assert_eq!(content.len(), CLIENT_DISCOVERY_CHUNK_BYTES);
            let file = dir.join("client-binary");
            std::fs::write(&file, &content).unwrap();

            let mut budget = CLIENT_DISCOVERY_PASS_BUDGET_BYTES;
            assert_eq!(
                scan_candidate(
                    &file,
                    &id_pattern,
                    &secret_pattern,
                    &mut budget,
                    CLIENT_DISCOVERY_MAX_SCAN_BYTES
                ),
                found(&file, &id_text, &secret_text)
            );
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn scan_candidate_accepts_a_deferred_match_when_the_budget_ends_exactly_at_eof() {
        // Same variable-length secret pattern as the two sibling tests
        // above — deferred (not accepted) on the single read that covers
        // this whole file, since its match touches that read's own end.
        // The shared pass budget is set to exactly the file's own length,
        // so that same read also exhausts the budget in the same step: this
        // guards the top-of-loop `*budget == 0` site's own `scanned ==
        // file_len` branch specifically — remove its settle pass (leaving
        // only the unconditional `break`) and this fully read secret is
        // dropped, reporting `NotFound` with a full, undeserved miss
        // backoff stored on top, instead of the `Found` it actually is.
        let id_pattern = scan_pattern(&synthetic_id_pattern());
        let secret_pattern = scan_pattern(r"GOCSPX-[A-Za-z0-9]{10,40}");

        let dir = temp_dir("scan-budget-ends-at-eof");
        let id_text = fake_client_id("222555", "budgeteof");
        let secret_tail = "D4".repeat(20);
        let secret_text = fake_secret(&secret_tail);
        let mut content = id_text.as_bytes().to_vec();
        content.push(b' ');
        let filler_len = 3000 - content.len() - secret_text.len();
        content.extend(std::iter::repeat_n(b'-', filler_len));
        content.extend_from_slice(secret_text.as_bytes());
        assert_eq!(content.len(), 3000);
        let file = dir.join("client-binary");
        std::fs::write(&file, &content).unwrap();

        let mut budget: u64 = 3000;
        assert_eq!(
            scan_candidate(
                &file,
                &id_pattern,
                &secret_pattern,
                &mut budget,
                CLIENT_DISCOVERY_MAX_SCAN_BYTES
            ),
            found(&file, &id_text, &secret_text)
        );
        assert_eq!(
            budget, 0,
            "the budget must still be fully spent, not left short by the settle pass"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scan_candidate_accepts_a_deferred_match_when_the_cap_ends_exactly_at_eof() {
        // Same fixture as the sibling test above, but this time it is
        // `per_file_cap`, not the shared budget, that lands exactly on
        // `file_len` — an ample budget proves the cap itself is what is
        // under test. Guards the bottom-of-loop `scanned >= per_file_cap`
        // site's matching `scanned == file_len` branch: remove its own
        // settle pass and this fully read, deferred secret is dropped the
        // same way, reporting `NotFound` instead of `Found`.
        let id_pattern = scan_pattern(&synthetic_id_pattern());
        let secret_pattern = scan_pattern(r"GOCSPX-[A-Za-z0-9]{10,40}");

        let dir = temp_dir("scan-cap-ends-at-eof");
        let id_text = fake_client_id("222666", "capeof");
        let secret_tail = "E5".repeat(20);
        let secret_text = fake_secret(&secret_tail);
        let mut content = id_text.as_bytes().to_vec();
        content.push(b' ');
        let filler_len = 3000 - content.len() - secret_text.len();
        content.extend(std::iter::repeat_n(b'-', filler_len));
        content.extend_from_slice(secret_text.as_bytes());
        assert_eq!(content.len(), 3000);
        let file = dir.join("client-binary");
        std::fs::write(&file, &content).unwrap();

        let mut budget = CLIENT_DISCOVERY_PASS_BUDGET_BYTES;
        assert_eq!(
            scan_candidate(&file, &id_pattern, &secret_pattern, &mut budget, 3000),
            found(&file, &id_text, &secret_text)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scan_candidate_never_reads_past_the_cap_regardless_of_what_file_len_says() {
        // A wrong `file_len` (a real `stat` that is stale by the time the
        // reads happen) is hard to fake honestly with a real file — it is
        // read from the very same `stat` this test would also have to fake
        // being wrong — so a genuinely stale stat is not what this
        // exercises. What it pins instead is the *observable* bound the
        // bottom-of-loop cap site must never violate regardless: reading
        // past `per_file_cap` at all, whatever `file_len` happens to say.
        // Measured against the actual defect this guards: a stale `stat` of
        // `0` bytes against a real 8 MiB file, a 1 MiB cap and a 6 MiB
        // shared budget read the full 6 MiB instead of stopping at the
        // cap's own 1 MiB, because a cap site that read on past its limit —
        // trusting `scanned >= file_len` (`0 >= 0`, immediately) to mean
        // "the next `read` will report EOF" — would be exactly backwards
        // when the file is *larger* than the stat said, not smaller.
        let id_pattern = scan_pattern(&synthetic_id_pattern());
        let secret_pattern = scan_pattern(&synthetic_secret_pattern());

        let dir = temp_dir("scan-cap-bound-regardless-of-file-len");
        let file = dir.join("no-pair");
        std::fs::write(&file, vec![b'x'; CLIENT_DISCOVERY_CHUNK_BYTES * 2 + 100]).unwrap();

        let mut budget = CLIENT_DISCOVERY_PASS_BUDGET_BYTES;
        assert_eq!(
            scan_candidate(
                &file,
                &id_pattern,
                &secret_pattern,
                &mut budget,
                CLIENT_DISCOVERY_CHUNK_BYTES as u64
            ),
            ScanOutcome::Truncated,
            "a file twice the cap's own size must still be cut off at the cap"
        );
        assert_eq!(
            CLIENT_DISCOVERY_PASS_BUDGET_BYTES - budget,
            CLIENT_DISCOVERY_CHUNK_BYTES as u64,
            "exactly one read's worth of the shared budget may be spent on this candidate, \
             never a second chunk beyond the cap it was already over"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scan_candidate_accepts_an_exact_length_match_that_ends_on_a_genuine_cutoff() {
        // The shipped-shape exact secret pattern (`{28}`, the same count
        // `plugins/antigravity.toml` ships) — not the loosely-bounded
        // `synthetic_secret_pattern()` most tests in this module use.
        // Exact-length means `regex_max_match_len` reports a maximum equal
        // to the minimum, so `accept_settled_match` treats *any* match of
        // it as already maximal the moment it is found — never deferred,
        // cutoff or no cutoff.
        let id_pattern = scan_pattern(&synthetic_id_pattern());
        let secret_pattern = scan_pattern(r"GOCSPX-[A-Za-z0-9_-]{28}");

        // The id early, then `-` padding up to byte 1965, then the 28-char
        // secret ending exactly at byte 2000 (`fake_secret` needs exactly
        // 28 class-matching characters — built by repeating a two-character
        // unit, not typed out by hand, so the count is provably exact), then
        // more padding out to 4000 bytes total — well past the cutoff, so
        // `file_len` genuinely exceeds what gets read.
        let id_text = fake_client_id("222888", "exactcutoff");
        let secret_tail = "G1".repeat(14);
        assert_eq!(secret_tail.len(), 28);
        let secret_text = fake_secret(&secret_tail);
        assert_eq!(secret_text.len(), 35, "\"GOCSPX-\" (7) + 28 characters");
        let mut content = id_text.as_bytes().to_vec();
        content.push(b' ');
        content.resize(2000 - secret_text.len(), b'-');
        content.extend_from_slice(secret_text.as_bytes());
        assert_eq!(
            content.len(),
            2000,
            "the secret's last byte must land exactly on byte 2000"
        );
        content.extend(std::iter::repeat_n(b'-', 2000));
        assert_eq!(content.len(), 4000);
        let dir = temp_dir("scan-exact-length-budget-cutoff");
        let file = dir.join("client-binary");
        std::fs::write(&file, &content).unwrap();

        // `budget = 2000`: the single read that reaches the cutoff also
        // covers the secret's entire 35 bytes, so this is a *genuine*
        // cutoff (`scanned == 2000 < file_len == 4000`), not one that
        // happens to coincide with the file's own end — the top-of-loop
        // `*budget == 0` site's `scanned < file_len` branch, which never
        // runs a settle pass at all. Without the `already_maximal`
        // short-circuit, `accept_settled_match` would defer every match
        // touching a read's end regardless of length, so this fully
        // formed, exact-length secret would be deferred here and then
        // dropped at the cutoff, same as any other deferred match — the
        // candidate would come back `Truncated`. It must instead be found
        // on the very read that produces it.
        let mut budget: u64 = 2000;
        assert_eq!(
            scan_candidate(
                &file,
                &id_pattern,
                &secret_pattern,
                &mut budget,
                CLIENT_DISCOVERY_MAX_SCAN_BYTES
            ),
            found(&file, &id_text, &secret_text)
        );
        assert_eq!(
            budget, 0,
            "the budget must still be fully spent, not left short"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scan_candidate_accepts_an_exact_length_match_that_ends_on_a_genuine_cap_cutoff() {
        // Same claim as the sibling test above, but via `per_file_cap`
        // rather than the shared budget. `per_file_cap` cannot bound a
        // single `read` below `min(chunk, budget)` — it is only checked
        // *after* one completes (see `scan_candidate`'s own doc) — so an
        // ample budget and a small file cannot land a cap cutoff at an
        // arbitrary byte the way a small budget can: with a file no bigger
        // than one chunk, an ample budget always reads it whole in a single
        // call, landing on `scanned == file_len` (already covered by
        // `scan_candidate_accepts_a_deferred_match_when_the_cap_ends_exactly_at_eof`),
        // never `scanned < file_len`. A *genuine* cap cutoff at all,
        // therefore, only exists at chunk granularity: the fixture here
        // places the secret's last byte at exactly
        // `CLIENT_DISCOVERY_CHUNK_BYTES`, with the file continuing another
        // 100 bytes past it — the same shape
        // `discover_client_still_resolves_a_later_candidate_after_a_capped_one`
        // uses for its own "big" candidate, except the match now lands
        // exactly on the boundary that test leaves as plain padding.
        let id_pattern = scan_pattern(&synthetic_id_pattern());
        let secret_pattern = scan_pattern(r"GOCSPX-[A-Za-z0-9_-]{28}");

        let id_text = fake_client_id("222999", "exactcapcutoff");
        let secret_tail = "H2".repeat(14);
        assert_eq!(secret_tail.len(), 28);
        let secret_text = fake_secret(&secret_tail);
        let mut content = id_text.as_bytes().to_vec();
        content.push(b' ');
        content.resize(CLIENT_DISCOVERY_CHUNK_BYTES - secret_text.len(), b'-');
        content.extend_from_slice(secret_text.as_bytes());
        assert_eq!(content.len(), CLIENT_DISCOVERY_CHUNK_BYTES);
        content.extend(std::iter::repeat_n(b'-', 100));
        let dir = temp_dir("scan-exact-length-cap-cutoff");
        let file = dir.join("client-binary");
        std::fs::write(&file, &content).unwrap();

        // Ample budget: the first (and, for this fixture, only) read is a
        // full `CLIENT_DISCOVERY_CHUNK_BYTES` chunk — the secret's exact
        // 35-byte match ends right at that read's own end, and
        // `scanned == CLIENT_DISCOVERY_CHUNK_BYTES < file_len` (100 bytes
        // remain unread) makes this a genuine cap cutoff, not an
        // end-of-file coincidence. Without the `already_maximal`
        // short-circuit, the deferred match would be dropped here the
        // same way, reporting `Truncated`.
        let mut budget = CLIENT_DISCOVERY_PASS_BUDGET_BYTES;
        assert_eq!(
            scan_candidate(
                &file,
                &id_pattern,
                &secret_pattern,
                &mut budget,
                CLIENT_DISCOVERY_CHUNK_BYTES as u64
            ),
            found(&file, &id_text, &secret_text)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scan_candidate_still_defers_a_variable_length_match_at_a_genuine_cutoff() {
        // The exact-length short-circuit the two sibling tests above rely
        // on must not swallow a genuinely variable-length pattern too: this
        // is the same defect `scan_candidate_does_not_accept_a_variable_length_match_cut_by_a_chunk_boundary`
        // guards against, but at a *genuine* cutoff (the budget runs out
        // for good) rather than a chunk boundary the scan carries past —
        // proving the fix added for shipped exact-length patterns did not
        // quietly bring back the truncated-secret defect this whole
        // deferral mechanism exists to remove.
        let id_pattern = scan_pattern(&synthetic_id_pattern());
        let secret_pattern = scan_pattern(r"GOCSPX-[A-Za-z0-9]{10,40}");

        let id_text = fake_client_id("223000", "variablecutoff");
        let secret_tail = "F6".repeat(20);
        assert_eq!(secret_tail.len(), 40, "the pattern's own upper bound");
        let secret_text = fake_secret(&secret_tail);
        let mut content = id_text.as_bytes().to_vec();
        content.push(b' ');
        content.extend(std::iter::repeat_n(b'-', 50));
        let secret_start = content.len();
        content.extend_from_slice(secret_text.as_bytes());
        // The file continues well past the cutoff below — a genuine
        // cutoff, not one that happens to land on `file_len`.
        content.extend(std::iter::repeat_n(b'-', 200));
        let dir = temp_dir("scan-variable-length-genuine-cutoff");
        let file = dir.join("client-binary");
        std::fs::write(&file, &content).unwrap();

        // The budget ends exactly 20 characters into the secret's 40-char
        // tail — `"GOCSPX-"` (7 bytes) plus the first 20 — a match the
        // pattern's own `{10,40}` bound accepts as complete on its own
        // terms (20 is within `10..=40`), touching the read's own end.
        // `max_len` for this pattern is 47 (`"GOCSPX-"` plus 40), and this
        // match is only 27 bytes — nowhere near maximal — so it is deferred
        // exactly as before this change, and dropped at the genuine cutoff
        // that follows: never a 20-character `Found`.
        let mut budget = (secret_start + 7 + 20) as u64;
        assert_eq!(
            scan_candidate(
                &file,
                &id_pattern,
                &secret_pattern,
                &mut budget,
                CLIENT_DISCOVERY_MAX_SCAN_BYTES
            ),
            ScanOutcome::Truncated,
            "a variable-length match that has not reached its pattern's own maximum must still \
             be deferred, and dropped, at a genuine cutoff"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discover_client_requires_both_patterns_in_the_same_file() {
        let dir = temp_dir("discover-split");
        let file_id = dir.join("only-id");
        let file_secret = dir.join("only-secret");
        std::fs::write(&file_id, fake_client_id("333333", "idonly")).unwrap();
        std::fs::write(&file_secret, fake_secret("secretonly0123456789ABCDEFGH")).unwrap();
        let client = AuthClientDiscovery {
            id_env: None,
            secret_env: None,
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![
                file_id.to_string_lossy().into_owned(),
                file_secret.to_string_lossy().into_owned(),
            ],
            bins: Vec::new(),
        };

        assert_eq!(
            discover_client(&client),
            None,
            "a pair split across two files is not a pair"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_client_prefers_the_env_override_over_a_discoverable_file() {
        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = temp_dir("resolve-env-wins");
        let file = dir.join("client-binary");
        std::fs::write(
            &file,
            format!(
                "{} {}",
                fake_client_id("111111", "fromfile"),
                fake_secret("fromfilesecret0123456789AB")
            ),
        )
        .unwrap();
        let id_env = format!("TICKOVER_AUTH_TEST_CLIENT_ID_{}", std::process::id());
        let secret_env = format!("TICKOVER_AUTH_TEST_CLIENT_SECRET_{}", std::process::id());
        std::env::set_var(&id_env, "env-client-id");
        std::env::set_var(&secret_env, "env-client-secret");
        let client = AuthClientDiscovery {
            id_env: Some(id_env.clone()),
            secret_env: Some(secret_env.clone()),
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![file.to_string_lossy().into_owned()],
            bins: Vec::new(),
        };
        let step = AuthStep {
            client: Some(client),
            ..auth_step(AuthType::OauthRefresh)
        };

        assert_eq!(
            resolve_client(&step),
            Some(("env-client-id".to_string(), "env-client-secret".to_string())),
            "the env override must win even though the file would resolve to something else"
        );

        std::env::remove_var(&id_env);
        std::env::remove_var(&secret_env);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_client_falls_back_to_discovery_when_nothing_else_is_set() {
        let dir = temp_dir("resolve-discovery-fallback");
        let file = dir.join("client-binary");
        let id = fake_client_id("222222", "onlyfile");
        let secret = fake_secret("onlyfilesecret0123456789AB");
        std::fs::write(&file, format!("{id} {secret}")).unwrap();
        let client = AuthClientDiscovery {
            id_env: None,
            secret_env: None,
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![file.to_string_lossy().into_owned()],
            bins: Vec::new(),
        };
        let step = AuthStep {
            client: Some(client),
            ..auth_step(AuthType::OauthRefresh)
        };

        assert_eq!(resolve_client(&step), Some((id, secret)));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn client_discovery_log_once_only_queues_the_first_call_for_a_given_key() {
        let _diag_guard = DIAG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Deterministic, unlike an integration test through `discover_client`
        // — that path is also gated by the miss cache's real-clock backoff,
        // which would make a second call within the same test short-circuit
        // before ever reaching this function, proving nothing about *its*
        // own dedup. Called directly instead, three times, same key.
        let id_env = format!("TICKOVER_AUTH_TEST_LOG_ONCE_ID_{}", std::process::id());
        let secret_env = format!("TICKOVER_AUTH_TEST_LOG_ONCE_SECRET_{}", std::process::id());
        let client = AuthClientDiscovery {
            id_env: Some(id_env.clone()),
            secret_env: Some(secret_env.clone()),
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: Vec::new(),
            bins: Vec::new(),
        };
        let key = client_config_key(&client);
        client_discovery_log_once(key, &client);
        client_discovery_log_once(key, &client);
        client_discovery_log_once(key, &client);

        // The queue is process-wide and shared with every other test that
        // might be logging in parallel — filtered by this test's own unique
        // env var name rather than asserted on the queue's total length,
        // which would flake under a different `--test-threads` order.
        let drained = take_pending_diagnostics();
        let mine = drained.iter().filter(|line| line.contains(&id_env)).count();
        assert_eq!(
            mine, 1,
            "three calls with the same key must queue the line exactly once — got {drained:?}"
        );
    }

    #[test]
    fn resolve_client_with_a_half_set_env_pair_queues_one_diagnostic_and_falls_back() {
        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _diag_guard = DIAG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = temp_dir("resolve-half-env");
        let file = dir.join("client-binary");
        let discoverable_id = fake_client_id("444444", "halfenv");
        let discoverable_secret = fake_secret("halfenvsecret0123456789ABC");
        std::fs::write(&file, format!("{discoverable_id} {discoverable_secret}")).unwrap();
        let id_env = format!("TICKOVER_AUTH_TEST_HALF_ID_{}", std::process::id());
        let secret_env = format!("TICKOVER_AUTH_TEST_HALF_SECRET_{}", std::process::id());
        std::env::remove_var(&secret_env);
        std::env::set_var(&id_env, "only-the-id-is-set");
        let client = AuthClientDiscovery {
            id_env: Some(id_env.clone()),
            secret_env: Some(secret_env.clone()),
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![file.to_string_lossy().into_owned()],
            bins: Vec::new(),
        };
        let step = AuthStep {
            client: Some(client),
            ..auth_step(AuthType::OauthRefresh)
        };

        // Falls back to discovery rather than treating the half-set env as
        // the override — it plainly is not a usable pair.
        assert_eq!(
            resolve_client(&step),
            Some((discoverable_id, discoverable_secret))
        );

        let drained = take_pending_diagnostics();
        let mine: Vec<&String> = drained.iter().filter(|l| l.contains(&id_env)).collect();
        assert_eq!(
            mine.len(),
            1,
            "exactly one of two env vars set must queue one line — got {drained:?}"
        );
        assert!(mine[0].contains(&secret_env), "{}", mine[0]);

        std::env::remove_var(&id_env);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oauth_refresh_step_checks_the_refresh_token_file_before_touching_the_client() {
        let _diag_guard = DIAG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // No credentials file at all: the step must resolve Absent without
        // ever reaching `resolve_client` — proven here by a `client` table
        // naming a `files` entry that does not exist. `scan_candidate`
        // treats a missing path as a harmless miss, not something that could
        // panic or hang, so this fixture is not itself dangerous to scan;
        // what it actually shows is that a discovery attempt against it
        // never happens at all — no diagnostic, the one thing only a real
        // attempt queues, shows up here.
        let dir = temp_dir("no-refresh-file-yet");
        let mut step = oauth_refresh_step_for(&dir, r#"{"refresh_token":"r-1"}"#);
        step.path = Some(
            dir.join("does-not-exist.json")
                .to_string_lossy()
                .into_owned(),
        );
        step.client_id = None;
        step.client_secret = None;
        let id_env = format!("TICKOVER_AUTH_TEST_NEVER_TOUCHED_{}", std::process::id());
        step.client = Some(AuthClientDiscovery {
            id_env: Some(id_env.clone()),
            secret_env: Some(format!(
                "TICKOVER_AUTH_TEST_NEVER_TOUCHED_SECRET_{}",
                std::process::id()
            )),
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![dir.join("would-be-scanned").to_string_lossy().into_owned()],
            bins: Vec::new(),
        });

        assert_eq!(
            oauth_refresh_step(&step, &["oauth2.googleapis.com".to_string()]),
            Ok(None)
        );

        let drained = take_pending_diagnostics();
        let mine: Vec<&String> = drained.iter().filter(|l| l.contains(&id_env)).collect();
        assert!(
            mine.is_empty(),
            "no credentials file means the client is never resolved at all — got {mine:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oauth_refresh_step_serves_a_cached_token_without_ever_resolving_the_client() {
        // The exact bug this closes: `resolve_client` used to run before the
        // cache read, so a transient discovery miss (nothing found on the
        // machine *this* tick) discarded a still-valid cached access token.
        // The `client` table here names a candidate that does not exist —
        // discovery would resolve `Absent` if it ever ran — so getting the
        // cached token back proves the cache is read, and served, without
        // ever reaching `resolve_client` at all.
        let dir = temp_dir("oauth-cache-hit-skips-client");
        let mut step =
            oauth_refresh_step_for(&dir, r#"{"refresh_token":"r-cache-hit-skips-client"}"#);
        step.client_id = None;
        step.client_secret = None;
        step.client = Some(AuthClientDiscovery {
            id_env: None,
            secret_env: None,
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![dir.join("does-not-exist").to_string_lossy().into_owned()],
            bins: Vec::new(),
        });
        let key = refresh_cache_key(
            step.token_url.as_deref().unwrap(),
            "r-cache-hit-skips-client",
        );
        refresh_cache_store(
            key,
            CacheEntry::Fresh {
                access_token: "still-valid-cached-token".to_string(),
                expires_at_unix: cache_now() + 3600,
            },
        );

        assert_eq!(
            oauth_refresh_step(&step, &["oauth2.googleapis.com".to_string()]),
            Ok(Some("still-valid-cached-token".to_string())),
            "a still-valid cached token must be served even though discovery would find nothing this tick"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oauth_refresh_step_honors_backoff_when_the_client_id_is_unchanged() {
        let dir = temp_dir("oauth-backoff-unchanged-client");
        let step = oauth_refresh_step_for(&dir, r#"{"refresh_token":"r-backoff-same"}"#);
        // `oauth_refresh_step_for` sets the literal `client_id`/`client_secret`
        // to "test-client-id"/"test-client-secret" — the same pair this
        // entry says it failed with.
        let key = refresh_cache_key(step.token_url.as_deref().unwrap(), "r-backoff-same");
        refresh_cache_store(
            key,
            CacheEntry::Failed {
                retry_after_unix: cache_now() + 300,
                client_id: "test-client-id".to_string(),
                secret_hash: secret_hash("test-client-secret"),
                message: "stale mock failure message".to_string(),
            },
        );

        assert_eq!(
            oauth_refresh_step(&step, &["oauth2.googleapis.com".to_string()]),
            Err("stale mock failure message".to_string()),
            "the same pair that just failed must not be retried before its backoff passes, and \
             must report exactly what that failure said"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oauth_refresh_step_bypasses_backoff_when_only_the_secret_has_changed() {
        // The other half of "the pair has changed": the same `client_id` as
        // the cached failure, but a different `client_secret` — an operator
        // rotating just the secret (the client id, an installed app's, does
        // not change) must not be judged by the old secret's failure either.
        let dir = temp_dir("oauth-backoff-changed-secret");
        let mut step = oauth_refresh_step_for(&dir, r#"{"refresh_token":"r-backoff-newsecret"}"#);
        step.token_url = Some("https://127.0.0.1:1/token".to_string());
        step.client_secret = Some("rotated-client-secret".to_string());
        let key = refresh_cache_key(step.token_url.as_deref().unwrap(), "r-backoff-newsecret");
        refresh_cache_store(
            key,
            CacheEntry::Failed {
                retry_after_unix: cache_now() + 300,
                client_id: "test-client-id".to_string(),
                secret_hash: secret_hash("test-client-secret"),
                message: "stale mock failure message".to_string(),
            },
        );

        let err = oauth_refresh_step(&step, &["127.0.0.1".to_string()])
            .expect_err("nothing listens on 127.0.0.1:1 — some connection error is expected");
        assert!(
            !err.contains("stale mock failure message"),
            "a changed secret must bypass the old backoff and attempt a fresh exchange: {err}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oauth_refresh_step_bypasses_backoff_when_the_client_id_has_changed() {
        // No live network needed to prove this: `127.0.0.1:1` refuses the
        // connection immediately (nothing listens there), so this reaches
        // `oauth_refresh_request` — proving the backoff was *not* honored —
        // without needing a real HTTPS endpoint or hanging.
        let dir = temp_dir("oauth-backoff-changed-client");
        let mut step = oauth_refresh_step_for(&dir, r#"{"refresh_token":"r-backoff-changed"}"#);
        step.token_url = Some("https://127.0.0.1:1/token".to_string());
        // `step`'s own literal client_id is "test-client-id" (from
        // `oauth_refresh_step_for`) — different from the entry below, so the
        // pair has changed since the failure that produced this backoff.
        let key = refresh_cache_key(step.token_url.as_deref().unwrap(), "r-backoff-changed");
        refresh_cache_store(
            key,
            CacheEntry::Failed {
                retry_after_unix: cache_now() + 300,
                client_id: "an-old-superseded-client-id".to_string(),
                secret_hash: secret_hash("an-old-superseded-client-secret"),
                message: "stale mock failure message".to_string(),
            },
        );

        let err = oauth_refresh_step(&step, &["127.0.0.1".to_string()])
            .expect_err("nothing listens on 127.0.0.1:1 — some connection error is expected");
        assert!(
            !err.contains("stale mock failure message"),
            "a changed client_id must bypass the old backoff and attempt a fresh exchange: {err}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oauth_refresh_step_reports_the_backoff_message_not_absent_when_the_client_cannot_resolve() {
        // The interaction this closes (see the `None` arm's own doc in
        // `oauth_refresh_step`): a client that cannot currently be resolved
        // during an active refresh backoff is very often exactly *why* the
        // backoff exists in the first place, not an unrelated fact — so
        // this reports the same message a proven-unchanged pair would,
        // instead of falling to Absent and hiding the row and its reason.
        let dir = temp_dir("oauth-backoff-unresolvable-client");
        let mut step =
            oauth_refresh_step_for(&dir, r#"{"refresh_token":"r-backoff-unresolvable"}"#);
        step.client_id = None;
        step.client_secret = None;
        step.client = Some(AuthClientDiscovery {
            id_env: None,
            secret_env: None,
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![dir.join("does-not-exist").to_string_lossy().into_owned()],
            bins: Vec::new(),
        });
        let key = refresh_cache_key(step.token_url.as_deref().unwrap(), "r-backoff-unresolvable");
        refresh_cache_store(
            key,
            CacheEntry::Failed {
                retry_after_unix: cache_now() + 300,
                client_id: "some-old-client-id".to_string(),
                secret_hash: secret_hash("some-old-client-secret"),
                message: "stale mock failure message".to_string(),
            },
        );

        assert_eq!(
            oauth_refresh_step(&step, &["oauth2.googleapis.com".to_string()]),
            Err("stale mock failure message".to_string()),
            "an unresolvable client during an active backoff must report the backoff's own \
             message, not Absent"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oauth_refresh_step_resolves_absent_once_the_backoff_has_lapsed_and_the_client_still_cannot_resolve(
    ) {
        // The other side of the sibling test above: once the refresh
        // backoff itself is over, `refresh_cache_lookup` reports `Miss`,
        // not `Backoff` — there is no message left in the cache to report,
        // and an unresolvable client really is "not here", the same as it
        // always was and the same as `Miss`'s own `None` arm still is.
        let dir = temp_dir("oauth-backoff-lapsed-unresolvable-client");
        let mut step =
            oauth_refresh_step_for(&dir, r#"{"refresh_token":"r-backoff-lapsed-unresolvable"}"#);
        step.client_id = None;
        step.client_secret = None;
        step.client = Some(AuthClientDiscovery {
            id_env: None,
            secret_env: None,
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![dir.join("does-not-exist").to_string_lossy().into_owned()],
            bins: Vec::new(),
        });
        let key = refresh_cache_key(
            step.token_url.as_deref().unwrap(),
            "r-backoff-lapsed-unresolvable",
        );
        refresh_cache_store(
            key,
            CacheEntry::Failed {
                retry_after_unix: cache_now() - 1,
                client_id: "some-old-client-id".to_string(),
                secret_hash: secret_hash("some-old-client-secret"),
                message: "stale mock failure message".to_string(),
            },
        );

        assert_eq!(
            oauth_refresh_step(&step, &["oauth2.googleapis.com".to_string()]),
            Ok(None),
            "once the backoff has lapsed, an unresolvable client is Absent again — there is no \
             message left to report"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oauth_refresh_step_reports_the_stale_pair_message_while_a_discovery_miss_backoff_evict_armed_hides_it(
    ) {
        // The exact interaction `on_exchange_error`'s and
        // `client_discovery_evict`'s own docs name: an `invalid_client`
        // response evicts the found-cache entry and arms a fresh
        // discovery-miss backoff over it — so the very next call's
        // `resolve_pair()` finds nothing, not because the client vanished,
        // but because discovery itself is now in its own backoff. Before
        // the `None` arm fix, resolving nothing here fell straight to
        // Absent regardless of why, hiding the row and its reason for as
        // long as either backoff stayed active — for the one real
        // `client`-table provider this ships (Antigravity), on every
        // `invalid_client` response.
        let dir = temp_dir("oauth-evict-armed-miss-reports-message");
        let file = dir.join("client-binary");
        let id = fake_client_id("600006", "backoffmessage");
        let secret = fake_secret("backoffmessagesecret0123456789ABCD");
        std::fs::write(&file, format!("{id} {secret}")).unwrap();
        let client = AuthClientDiscovery {
            id_env: None,
            secret_env: None,
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![file.to_string_lossy().into_owned()],
            bins: Vec::new(),
        };
        assert!(
            discover_client(&client).is_some(),
            "sanity: the pair must resolve and be cached before eviction is asserted"
        );

        let mut step = oauth_refresh_step_for(&dir, r#"{"refresh_token":"r-evict-armed-miss"}"#);
        step.client_id = None;
        step.client_secret = None;
        step.client = Some(client.clone());
        // Refused immediately, not a real endpoint — this must never
        // actually reach `oauth_refresh_request` in the first assertion
        // below; the second assertion needs exactly this same refusal once
        // the step does proceed to a fresh exchange.
        step.token_url = Some("https://127.0.0.1:1/token".to_string());
        let key = refresh_cache_key(step.token_url.as_deref().unwrap(), "r-evict-armed-miss");
        let message = "token refresh failed: invalid_client (HTTP 400)".to_string();
        refresh_cache_store(
            key,
            CacheEntry::Failed {
                retry_after_unix: cache_now() + 300,
                client_id: id.clone(),
                secret_hash: secret_hash(&secret),
                message: message.clone(),
            },
        );
        // The reaction a real `invalid_client` response drives.
        client_discovery_evict(&client);

        assert_eq!(
            oauth_refresh_step(&step, &["127.0.0.1".to_string()]),
            Err(message.clone()),
            "an undiscoverable client during an active refresh backoff must report the \
             backoff's own message, not Absent — the row must stay, with the reason, instead \
             of vanishing"
        );

        // Both backoffs cleared: the pair really is still there (the file
        // was never touched), so discovery finds it again and the step
        // proceeds — past the Absent/backoff-error gate and into an actual
        // exchange attempt, proven the same way the sibling backoff tests
        // do, against a connection nothing answers.
        client_discovery_miss_store(client_config_key(&client), 0);
        refresh_cache_store(
            key,
            CacheEntry::Failed {
                retry_after_unix: 0,
                client_id: id.clone(),
                secret_hash: secret_hash(&secret),
                message: message.clone(),
            },
        );
        let err = oauth_refresh_step(&step, &["127.0.0.1".to_string()])
            .expect_err("nothing listens on 127.0.0.1:1 — some connection error is expected");
        assert!(
            !err.contains("invalid_client"),
            "once both backoffs lapse, the step must attempt a fresh exchange rather than \
             replay the stale backoff message: {err}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oauth_refresh_step_reports_the_last_failure_while_only_the_discovery_miss_backoff_is_still_armed(
    ) {
        // The window between the refresh backoff (`REFRESH_BACKOFF_SECS`,
        // 300s) itself lapsing and a `client` table's own, longer
        // discovery-miss backoff (`CLIENT_DISCOVERY_RETRY_SECS`, 600s)
        // still declining to even attempt a rescan — t in [300, 600) after
        // the original failure. `refresh_cache_lookup` reports `Miss`, not
        // `Backoff`, here — without the `Miss` arm's own fallback this
        // would silently go Absent even though the refresh cache still
        // remembers exactly why the last attempt failed.
        let dir = temp_dir("oauth-miss-with-armed-discovery-backoff");
        let mut step =
            oauth_refresh_step_for(&dir, r#"{"refresh_token":"r-discovery-miss-window"}"#);
        step.client_id = None;
        step.client_secret = None;
        let client = AuthClientDiscovery {
            id_env: None,
            secret_env: None,
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![dir.join("would-be-scanned").to_string_lossy().into_owned()],
            bins: Vec::new(),
        };
        step.client = Some(client.clone());

        let key = refresh_cache_key(
            step.token_url.as_deref().unwrap(),
            "r-discovery-miss-window",
        );
        let message = "token refresh failed: invalid_client (HTTP 400)".to_string();
        // The refresh backoff itself has already lapsed — `refresh_cache_lookup`
        // reports `Miss`, exactly the arm this test is about.
        refresh_cache_store(
            key,
            CacheEntry::Failed {
                retry_after_unix: cache_now() - 1,
                client_id: "some-client-id".to_string(),
                secret_hash: secret_hash("some-client-secret"),
                message: message.clone(),
            },
        );
        // The client-discovery miss backoff, armed separately and still
        // live — `discover_client_within`'s own top-of-function gate
        // returns `None` without even attempting a scan.
        client_discovery_miss_store(client_config_key(&client), cache_now() + 500);

        assert_eq!(
            oauth_refresh_step(&step, &["oauth2.googleapis.com".to_string()]),
            Err(message),
            "the last known failure must still be reported while the discovery-miss backoff is \
             armed, rather than silently going Absent"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discover_client_rescans_when_the_cached_files_identity_changes() {
        let dir = temp_dir("discover-rescan-on-change");
        let file = dir.join("client-binary");
        let original_id = fake_client_id("555555", "original");
        let original_secret = fake_secret("originalsecret0123456789A");
        std::fs::write(&file, format!("{original_id} {original_secret}")).unwrap();
        let client = AuthClientDiscovery {
            id_env: None,
            secret_env: None,
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![file.to_string_lossy().into_owned()],
            bins: Vec::new(),
        };

        assert_eq!(
            discover_client(&client),
            Some((original_id, original_secret))
        );

        // A file system's mtime resolution can be coarser than this test
        // runs in — sleeping past it would be the usual fix, but a sleep in
        // a test is its own kind of flake. The length changes here too
        // (a longer replacement), which `client_discovery_found_lookup`
        // checks independently of mtime, so the rewrite is caught either way.
        let replaced_id = fake_client_id("666666", "replaced");
        let replaced_secret = fake_secret("replacedsecretXYZ0123456789AB");
        std::fs::write(&file, format!("{replaced_id} {replaced_secret}")).unwrap();

        assert_eq!(
            discover_client(&client),
            Some((replaced_id, replaced_secret)),
            "a changed file identity must be rescanned, not served the stale cached pair"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discover_client_does_not_share_a_result_between_two_configs_on_the_same_file() {
        // Two genuinely distinct pairs in one file, the second positioned
        // after the first: `base`'s patterns are the unrestricted synthetic
        // ones, which match the *first* pair by construction (leftmost
        // match); `distinct`'s patterns require a literal only the *second*
        // pair carries, so they cannot match the first even though they
        // share the file. An earlier version of this test used a pattern
        // that still happened to match the first pair (its digit/letter
        // *counts* matched, coincidentally) and asserted the two configs
        // resolved to the *same* pair — proving the cache doesn't corrupt an
        // unrelated lookup, not that two configs are actually isolated. This
        // asserts isolation directly: two different results.
        let dir = temp_dir("discover-two-configs-one-file");
        let file = dir.join("client-binary");
        let shared_id = fake_client_id("777777", "shared");
        let shared_secret = fake_secret("sharedsecret0123456789ABCDE");
        let second_id = fake_client_id("424242", "second");
        let second_secret = fake_secret("secondsecret0123456789ABCDEF");
        std::fs::write(
            &file,
            format!("{shared_id} {shared_secret} noise noise {second_id} {second_secret}"),
        )
        .unwrap();
        let base = AuthClientDiscovery {
            id_env: None,
            secret_env: None,
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![file.to_string_lossy().into_owned()],
            bins: Vec::new(),
        };
        let found = discover_client(&base);
        assert_eq!(
            found,
            Some((shared_id, shared_secret)),
            "sanity: the base config must resolve the first pair"
        );

        // Same file, a different (config, not merely a differently-worded
        // equivalent) pattern pair — required to match only the second pair,
        // never the first, so a shared cache entry would be provably wrong,
        // not merely different-looking.
        let distinct = AuthClientDiscovery {
            id_pattern: Some(r"4[0-9]{5}-second\.apps\.googleusercontent\.com".to_string()),
            secret_pattern: Some(r"GOCSPX-second[A-Za-z0-9]{5,}".to_string()),
            ..base
        };
        let found_distinct = discover_client(&distinct);
        assert_eq!(
            found_distinct,
            Some((second_id, second_secret)),
            "sanity: the distinct config must resolve the second pair"
        );
        assert_ne!(
            found, found_distinct,
            "two configs on the same file must not share a found-cache result — each \
             resolved its own pair, and they must differ"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn client_discovery_evict_clears_a_configs_cached_entries() {
        let dir = temp_dir("discover-evict");
        let file = dir.join("client-binary");
        std::fs::write(
            &file,
            format!(
                "{} {}",
                fake_client_id("888888", "evictme"),
                fake_secret("evictmesecret0123456789AB")
            ),
        )
        .unwrap();
        let client = AuthClientDiscovery {
            id_env: None,
            secret_env: None,
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![file.to_string_lossy().into_owned()],
            bins: Vec::new(),
        };
        assert!(discover_client(&client).is_some());
        let key = client_config_key(&client);
        assert!(
            client_discovery_found_lookup(key, &super::super::expand_home(&client.files[0]))
                .is_some(),
            "sanity: the pair must actually be cached before eviction is asserted"
        );

        client_discovery_evict(&client);

        assert!(
            client_discovery_found_lookup(key, &super::super::expand_home(&client.files[0]))
                .is_none(),
            "eviction must clear the found-cache entry for this config"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn client_discovery_evict_does_not_clear_the_once_only_logged_set() {
        let _diag_guard = DIAG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Eviction is about a *credential* going stale — see
        // `client_discovery_evict`'s own doc — not about resetting what an
        // operator has already been told about this config. Proven directly:
        // log once, evict, log again with the same key — the second call
        // must still queue nothing.
        let id_env = format!("TICKOVER_AUTH_TEST_EVICT_LOGGED_ID_{}", std::process::id());
        let secret_env = format!(
            "TICKOVER_AUTH_TEST_EVICT_LOGGED_SECRET_{}",
            std::process::id()
        );
        let client = AuthClientDiscovery {
            id_env: Some(id_env.clone()),
            secret_env: Some(secret_env.clone()),
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: Vec::new(),
            bins: Vec::new(),
        };
        let key = client_config_key(&client);

        client_discovery_log_once(key, &client);
        let first = take_pending_diagnostics();
        let first_mine = first.iter().filter(|l| l.contains(&id_env)).count();
        assert_eq!(
            first_mine, 1,
            "sanity: the first call must queue exactly one line naming {id_env} — got {first:?}"
        );

        client_discovery_evict(&client);

        client_discovery_log_once(key, &client);
        let second = take_pending_diagnostics();
        let second_mine = second.iter().filter(|l| l.contains(&id_env)).count();
        assert_eq!(
            second_mine, 0,
            "eviction must not clear the once-only logged set — a second \
             `client_discovery_log_once` with the same key must queue nothing more, got {second:?}"
        );
    }

    #[test]
    fn client_discovery_evict_arms_a_miss_backoff_rather_than_clearing_it() {
        // The bug this closes: an outright clear left a persistently invalid
        // pair (the endpoint rejects it every time; the binary on disk never
        // changes) rescanning from scratch on the very next call — for as
        // long as the rejection kept coming, on every single refresh
        // attempt, forever. Evicting must instead leave the same
        // `CLIENT_DISCOVERY_RETRY_SECS` backoff a genuine miss gets.
        let dir = temp_dir("discover-evict-arms-backoff");
        let file = dir.join("client-binary");
        std::fs::write(
            &file,
            format!(
                "{} {}",
                fake_client_id("777888", "evictbackoff"),
                fake_secret("evictbackoffsecret0123456789AB")
            ),
        )
        .unwrap();
        let client = AuthClientDiscovery {
            id_env: None,
            secret_env: None,
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![file.to_string_lossy().into_owned()],
            bins: Vec::new(),
        };
        assert!(discover_client(&client).is_some());
        let key = client_config_key(&client);

        client_discovery_evict(&client);

        assert!(
            client_discovery_miss_lookup(key, cache_now()),
            "eviction must arm a miss backoff, not merely clear one — a persistently invalid \
             pair must not be rescanned on the very next call"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn is_invalid_client_matches_only_the_invalid_client_response_shape() {
        assert!(is_invalid_client(
            "token refresh failed: invalid_client (HTTP 400)"
        ));
        assert!(is_invalid_client(
            "token refresh failed: invalid_client (HTTP 401)"
        ));
        // `invalid_grant` gets its own distinct message before the generic
        // formatter ever runs (see `oauth_refresh_request`) — never this shape.
        assert!(!is_invalid_client(
            "token refresh: the saved sign-in is no longer valid — sign in to Antigravity again"
        ));
        // The other four RFC 6749 §5.2 codes this app recognizes — same
        // formatter, different code, must not match.
        assert!(!is_invalid_client(
            "token refresh failed: invalid_request (HTTP 400)"
        ));
        assert!(!is_invalid_client(
            "token refresh failed: unauthorized_client (HTTP 400)"
        ));
        assert!(!is_invalid_client(
            "token refresh failed: unsupported_grant_type (HTTP 400)"
        ));
        assert!(!is_invalid_client(
            "token refresh failed: invalid_scope (HTTP 400)"
        ));
        // An unrecognized code, and a transport failure with no OAuth error
        // field at all.
        assert!(!is_invalid_client("token refresh failed: HTTP 500"));
        assert!(!is_invalid_client(
            "token refresh: bad response (some serde error)"
        ));
        // The shape this checks, not a bare substring: a transport-layer
        // message that merely *mentions* the words must not match.
        assert!(!is_invalid_client(
            "token refresh failed: dns lookup mentioned invalid_client somewhere in its own text"
        ));
    }

    #[test]
    fn is_invalid_client_matches_a_message_built_through_the_producer() {
        // Unlike the test above (hand-written literal strings, pinning the
        // exact shape), this builds the message the same way
        // `oauth_refresh_request` actually does — through
        // `oauth_error_message`, the one function both it and
        // `is_invalid_client` share a prefix with — so the two can never
        // silently drift apart the way two independently hand-maintained
        // copies of the same literal eventually would.
        for status in [400, 401, 403] {
            assert!(
                is_invalid_client(&oauth_error_message("invalid_client", status)),
                "HTTP {status}"
            );
        }
        // Any other known code, produced the same way, must still not match.
        for code in [
            "invalid_request",
            "unauthorized_client",
            "unsupported_grant_type",
            "invalid_scope",
        ] {
            assert!(
                !is_invalid_client(&oauth_error_message(code, 400)),
                "{code}"
            );
        }
    }

    #[test]
    fn on_exchange_error_evicts_the_cached_pair_on_invalid_client() {
        // No HTTPS test-server infrastructure exists in this crate (and
        // `oauth_refresh_step` refuses anything but `https://` before it
        // would ever reach the exchange), so this proves the *reaction* to
        // the exact error text a real `invalid_client` response produces —
        // pinned separately, and exactly, by
        // `is_invalid_client_matches_only_the_invalid_client_response_shape` —
        // rather than a live round-trip.
        let dir = temp_dir("on-exchange-error-evict");
        let file = dir.join("client-binary");
        std::fs::write(
            &file,
            format!(
                "{} {}",
                fake_client_id("555555", "onexchange"),
                fake_secret("onexchangesecret0123456789AB")
            ),
        )
        .unwrap();
        let client = AuthClientDiscovery {
            id_env: None,
            secret_env: None,
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![file.to_string_lossy().into_owned()],
            bins: Vec::new(),
        };
        assert!(
            discover_client(&client).is_some(),
            "sanity: the pair must resolve and be cached"
        );
        let key = client_config_key(&client);
        let path = super::super::expand_home(&client.files[0]);
        assert!(
            client_discovery_found_lookup(key, &path).is_some(),
            "sanity: the pair must actually be cached before eviction is asserted"
        );

        let step = AuthStep {
            client: Some(client),
            ..auth_step(AuthType::OauthRefresh)
        };
        on_exchange_error(&step, "token refresh failed: invalid_client (HTTP 400)");

        assert!(
            client_discovery_found_lookup(key, &path).is_none(),
            "an invalid_client response must evict the cached pair"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn on_exchange_error_leaves_the_cache_alone_for_an_unrelated_failure() {
        let dir = temp_dir("on-exchange-error-no-evict");
        let file = dir.join("client-binary");
        std::fs::write(
            &file,
            format!(
                "{} {}",
                fake_client_id("666666", "noevict"),
                fake_secret("noevictsecret0123456789ABCDEF")
            ),
        )
        .unwrap();
        let client = AuthClientDiscovery {
            id_env: None,
            secret_env: None,
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![file.to_string_lossy().into_owned()],
            bins: Vec::new(),
        };
        assert!(discover_client(&client).is_some());
        let key = client_config_key(&client);
        let path = super::super::expand_home(&client.files[0]);

        let step = AuthStep {
            client: Some(client),
            ..auth_step(AuthType::OauthRefresh)
        };
        on_exchange_error(
            &step,
            "token refresh: the saved sign-in is no longer valid — sign in to Antigravity again",
        );

        assert!(
            client_discovery_found_lookup(key, &path).is_some(),
            "a failure that isn't invalid_client must not evict a good cached pair"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn bin_candidates_ignores_relative_path_entries() {
        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // A relative (or empty) `PATH` entry means "the current directory" —
        // never where this app should go looking for a client's binary.
        // Proving that needs a relative entry that would actually resolve
        // if `bin_candidates`'s own `is_absolute()` filter were deleted:
        // `cargo test` runs with the crate root as its working directory
        // (confirmed empirically, not merely assumed), so a directory
        // created *under* it, named by a path relative to it, is exactly
        // such an entry. This fixture used to name only a directory's own
        // `file_name()` under `std::env::temp_dir()` — a relative path that
        // could never resolve from the crate root no matter what
        // `bin_candidates` did with it, so the assertion below passed
        // whether the filter it was meant to prove existed or not.
        //
        // This *does* mutate the real `PATH` env var (restored below,
        // before any assertion) — there is no other way to reach the branch
        // in `bin_candidates` that reads it. The replacement `PATH` is the
        // relative entry (plus an empty component, the other shape
        // `is_absolute()` refuses) *alone*, not those plus the real,
        // absolute `PATH`: the directories this app *always* appends
        // (`super::cli_install_dirs`) are still there regardless, and would
        // otherwise make a false positive indistinguishable from a true one
        // on a machine that happens to have a matching binary in one of
        // them — mixing in the rest of the real `PATH` on top of that would
        // only add more ways for an unrelated absolute entry to explain a
        // pass, not fewer.
        let relative = format!("target/tickover-test-bin-candidates-{}", std::process::id());
        let dir = std::env::current_dir()
            .expect("cwd resolvable in test env")
            .join(&relative);
        std::fs::create_dir_all(&dir).unwrap();
        let name = format!("tickover-test-bin-{}", std::process::id());
        std::fs::write(dir.join(&name), "#!/bin/sh\n").unwrap();

        let real_path = std::env::var_os("PATH");
        let joined =
            std::env::join_paths([std::ffi::OsStr::new(""), std::ffi::OsStr::new(&relative)])
                .unwrap();
        std::env::set_var("PATH", &joined);
        let found = bin_candidates(&[name]);
        if let Some(p) = real_path {
            std::env::set_var("PATH", p);
        } else {
            std::env::remove_var("PATH");
        }

        assert!(
            found.is_empty(),
            "a relative PATH entry (including the empty component) must never be searched, \
             even one that would actually resolve from the crate root: {found:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// On unix, `is_file()` alone is not "this is the client's binary": a
    /// regular, non-executable file satisfies it exactly as well as the real
    /// one does, and sitting in an earlier `PATH` directory would shadow the
    /// real install rather than be skipped over the way this proves it now
    /// is — the same property `main.rs`'s own
    /// `find_bin_in_skips_a_non_executable_file_for_an_executable_one_further_down`
    /// proves for the sibling resolver.
    #[test]
    #[cfg(unix)]
    fn bin_candidates_skips_a_non_executable_file_for_an_executable_one_further_down_path() {
        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let shadowing = temp_dir("bin-candidates-non-executable");
        let real = temp_dir("bin-candidates-real-executable");
        let name = format!("tickover-test-bin-candidates-exec-{}", std::process::id());
        std::fs::write(shadowing.join(&name), "not a binary, just a file").unwrap();
        let bin = real.join(&name);
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let real_path = std::env::var_os("PATH");
        let joined = std::env::join_paths([&shadowing, &real]).unwrap();
        std::env::set_var("PATH", &joined);
        let found = bin_candidates(&[name]);
        if let Some(p) = real_path {
            std::env::set_var("PATH", p);
        } else {
            std::env::remove_var("PATH");
        }

        std::fs::remove_dir_all(&shadowing).ok();
        std::fs::remove_dir_all(&real).ok();
        assert_eq!(
            found,
            vec![bin],
            "the non-executable file in the earlier PATH directory must not win"
        );
    }

    // FIFOs, and the `mkfifo` binary that makes one, are a Unix concept —
    // `scan_candidate`'s `O_NONBLOCK` open is itself `#[cfg(unix)]`-only,
    // and there is nothing on Windows for this test to exercise.
    #[cfg(unix)]
    #[test]
    fn scan_candidate_never_reads_a_fifo() {
        // A writerless FIFO's own end-of-file behaviour — a read on a FIFO
        // nobody has open for writing returns `0` immediately, no different
        // from an empty regular file — would make this test pass even with
        // the metadata-before-open guard deleted: `scan_candidate` opening
        // and reading it would just find nothing either way. Keeping a
        // writer attached, with a matching id/secret pair already sitting in
        // the pipe, closes that gap: if `scan_candidate` ever actually
        // opened and read this path, it would find both patterns waiting
        // and report `Found`, not `NotFound` — so `NotFound` here proves the
        // path is never opened at all, not merely that nothing was there to
        // read.
        //
        // `mkfifo` failing to spawn or exit clean is not "this environment
        // has no FIFO support" — every Unix this crate targets does — so it
        // is not skipped quietly here. A silent skip would let a sandboxed
        // test runner missing `mkfifo` on `PATH` report a green check for a
        // scan path this test never actually exercised.
        let dir = temp_dir("scan-candidate-fifo");
        let fifo = dir.join("blocks");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo must be runnable on any Unix this test runs on");
        assert!(
            status.success(),
            "mkfifo {} failed: {status}",
            fifo.display()
        );

        let id_text = fake_client_id("444555", "fifotest");
        let secret_text = fake_secret("fifotestsecret0123456789ABCDEFGHIJ");
        let mut content = id_text.as_bytes().to_vec();
        content.push(b' ');
        content.extend_from_slice(secret_text.as_bytes());
        // A plain write-only open of a FIFO blocks until a reader connects —
        // one this test must never provide, since providing one is exactly
        // what this test is checking `scan_candidate` does not do. POSIX
        // leaves `O_RDWR` (read *and* write) on a FIFO unspecified, but it
        // does not have that wait on macOS — the only platform this
        // `#[cfg(unix)]` test actually runs on in this crate's matrix — so
        // it is what gets a writer attached, and kept attached for the
        // FIFO's whole lifetime, without a reader ever being involved. If a
        // future platform in that matrix *did* block on it, this `open`
        // hangs rather than fails; nothing here retries or times it out.
        use std::io::Write;
        let mut writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fifo)
            .expect("O_RDWR open of a FIFO must not block");
        writer.write_all(&content).unwrap();

        let id_pattern = scan_pattern(&synthetic_id_pattern());
        let secret_pattern = scan_pattern(&synthetic_secret_pattern());
        let mut budget = CLIENT_DISCOVERY_PASS_BUDGET_BYTES;
        assert_eq!(
            scan_candidate(
                &fifo,
                &id_pattern,
                &secret_pattern,
                &mut budget,
                CLIENT_DISCOVERY_MAX_SCAN_BYTES
            ),
            ScanOutcome::NotFound,
            "a FIFO must never be read, even one already holding a matching pair"
        );
        drop(writer);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scan_candidate_respects_the_byte_budget() {
        // The match sits well past a budget too small to reach it — proving
        // the budget actually bounds how much of the file is read, not just
        // that it's threaded through as a parameter nothing enforces.
        let dir = temp_dir("scan-candidate-budget");
        let file = dir.join("client-binary");
        let mut content = vec![b'x'; CLIENT_DISCOVERY_CHUNK_BYTES * 3];
        content.extend_from_slice(fake_client_id("999000", "budget").as_bytes());
        std::fs::write(&file, &content).unwrap();

        let id_pattern = scan_pattern(&synthetic_id_pattern());
        let secret_pattern = scan_pattern(&synthetic_secret_pattern());

        let mut tiny_budget: u64 = CLIENT_DISCOVERY_CHUNK_BYTES as u64;
        assert_eq!(
            scan_candidate(
                &file,
                &id_pattern,
                &secret_pattern,
                &mut tiny_budget,
                CLIENT_DISCOVERY_MAX_SCAN_BYTES
            ),
            ScanOutcome::Truncated,
            "a budget smaller than the file must stop before reaching the match, and must \
             say so — this candidate was never actually finished, so it is not the same \
             claim as `NotFound`"
        );
        assert_eq!(
            tiny_budget, 0,
            "the budget must be fully spent, not merely checked once"
        );

        let mut ample_budget: u64 = content.len() as u64;
        // The fixture carries only an id, no secret, so a budget large
        // enough to read the whole file can never come back `Found` —
        // `secret_pattern` has nothing to match. Asserting the specific
        // outcome, not just "not `Truncated`", is what actually proves the
        // budget stopped mattering once it covers the whole file.
        assert_eq!(
            scan_candidate(
                &file,
                &id_pattern,
                &secret_pattern,
                &mut ample_budget,
                CLIENT_DISCOVERY_MAX_SCAN_BYTES
            ),
            ScanOutcome::NotFound
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn scan_candidate_reports_a_permission_error_distinctly_from_not_found() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("scan-candidate-permission-denied");
        let file = dir.join("unreadable");
        std::fs::write(&file, fake_client_id("999999", "perm")).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();

        // Root (and this crate's own CI, some sandboxes) ignores file
        // permissions outright — skip rather than false-fail somewhere that
        // isn't actually exercising the denial this test is about.
        if std::fs::File::open(&file).is_ok() {
            eprintln!(
                "skip: scan_candidate_reports_a_permission_error_distinctly_from_not_found — \
                 running as root (or a sandbox that ignores file permissions), so a chmod 0 \
                 file still opens and there is no denial left to exercise"
            );
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).ok();
            std::fs::remove_dir_all(&dir).ok();
            return;
        }

        let id_pattern = scan_pattern(&synthetic_id_pattern());
        let secret_pattern = scan_pattern(&synthetic_secret_pattern());
        let mut budget = CLIENT_DISCOVERY_PASS_BUDGET_BYTES;
        assert!(
            matches!(
                scan_candidate(
                    &file,
                    &id_pattern,
                    &secret_pattern,
                    &mut budget,
                    CLIENT_DISCOVERY_MAX_SCAN_BYTES
                ),
                ScanOutcome::Error(_)
            ),
            "a permission-denied open is a read failure, not a quiet miss"
        );

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).ok();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn discover_client_backs_off_on_a_read_error_with_its_own_diagnostic() {
        let _diag_guard = DIAG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // A permanently unreadable candidate must not turn every
        // `refresh_secs` tick into a full rescan (the same backoff a
        // genuine miss buys), but the line queued about it must still say
        // "could not read", never "not found" — the two are different
        // facts, and an operator debugging a permission error should not
        // be told to go install something that already is.
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("discover-error-backoff");
        let file = dir.join("unreadable");
        std::fs::write(&file, fake_client_id("111222", "permdiscover")).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&file).is_ok() {
            eprintln!(
                "skip: discover_client_backs_off_on_a_read_error_with_its_own_diagnostic — \
                 running as root (or a sandbox that ignores file permissions), so a chmod 0 \
                 file still opens and there is no denial left to exercise"
            );
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).ok();
            std::fs::remove_dir_all(&dir).ok();
            return;
        }

        let client = AuthClientDiscovery {
            id_env: None,
            secret_env: None,
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![file.to_string_lossy().into_owned()],
            bins: Vec::new(),
        };

        assert_eq!(discover_client(&client), None);
        let key = client_config_key(&client);
        let now = cache_now();
        assert!(
            client_discovery_miss_lookup(key, now),
            "a read error must buy the same backoff a genuine miss does — a permanently \
             unreadable candidate must not be rescanned every tick"
        );
        let drained = take_pending_diagnostics();
        // Filtered by the candidate's own path, which only the read-error
        // message (`could not read <path>: ...`) carries — the generic
        // "not found" line never names a path.
        let mine: Vec<&String> = drained
            .iter()
            .filter(|l| l.contains(&file.to_string_lossy().into_owned()))
            .collect();
        assert_eq!(
            mine.len(),
            1,
            "exactly one read-error diagnostic — got {drained:?}"
        );
        assert!(mine[0].contains("could not read"), "{}", mine[0]);
        assert!(
            !mine[0].contains("no OAuth client id/secret found"),
            "{}",
            mine[0]
        );

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).ok();
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── discover_client_within's aggregation, at byte-sized limits ───────
    //
    // `discover_client`'s own hard limits are gigabytes — `scan_candidate`'s
    // own truncation is already proven, but only with a chunk-sized budget
    // (`scan_candidate_respects_the_byte_budget`), not at that gigabyte
    // scale. The aggregation *around* it — a truncated pass buys the short
    // backoff and its own diagnostic instead of the "not found" one, a
    // candidate skipped because the shared budget already hit zero counts
    // as truncation too, and a per-file cap does not stop the pass from
    // reaching a later candidate — was untestable at that scale without
    // gigabyte fixtures. `discover_client_within` exists so these three can
    // run against a `ScanLimits` of a few kilobytes instead.
    //
    // Five tests exercise this aggregation (the three behaviours above, plus
    // two more about how a cache hit interacts with the shared budget). None
    // of the five sets or removes an environment variable, so there is no
    // race for `ENV_TEST_LOCK` to guard here — but `discover_client_within`
    // does read `PATH` through `bin_candidates` on every call. With `bins`
    // empty on every config below, that result is discarded before it can
    // affect anything, so a concurrent `PATH` rewrite by
    // `bin_candidates_ignores_relative_path_entries` cannot change an
    // outcome here — the same footing every older `discover_client_*` test
    // in this module already stands on. `DIAG_TEST_LOCK` is still held for
    // the whole body of each, since all five drain
    // `take_pending_diagnostics`.

    #[test]
    fn discover_client_backs_off_briefly_when_a_candidate_is_truncated_and_says_so() {
        let _diag_guard = DIAG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // `id_env`/`secret_env` below are never actually set in the
        // environment — they exist only so this config's would-be "not
        // found" line (`client_not_found_diag` names them) is identifiable
        // in the diagnostics queue this test shares with every other test
        // running under `DIAG_TEST_LOCK`, and so this config's cache key is
        // unique among every other test in this module.
        let id_env = format!("TICKOVER_TRUNC_A_ID_{}", std::process::id());
        let secret_env = format!("TICKOVER_TRUNC_A_SECRET_{}", std::process::id());
        let dir = temp_dir("discover-truncated-short-backoff");
        let file = dir.join("client-binary");
        let id = fake_client_id("600000", "truncbriefid");
        let secret = fake_secret("truncbriefsecret0123456789ABC");
        // The pair sits at byte 6000 — past the 4096-byte pass budget
        // below, so the scan must stop before ever reaching it. Padded to
        // 8192 with `-`, not more `x`: the eviction below rescans this same
        // file at production's own limits, and `secret_pattern`'s `{10,}`
        // has no upper bound of its own — alphanumeric padding right after
        // the real secret would extend that match into the padding itself,
        // well past `CLIENT_PATTERN_MAX_MATCH_BYTES`, and trip the
        // `debug_assert` in `scan_candidate` on a match this test never
        // meant to produce.
        let mut content = vec![b'x'; 6000];
        content.extend_from_slice(id.as_bytes());
        content.push(b' ');
        content.extend_from_slice(secret.as_bytes());
        content.resize(8192, b'-');
        std::fs::write(&file, &content).unwrap();

        let client = AuthClientDiscovery {
            id_env: Some(id_env.clone()),
            secret_env: Some(secret_env),
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![file.to_string_lossy().into_owned()],
            bins: Vec::new(),
        };
        let key = client_config_key(&client);
        let tiny = ScanLimits {
            pass_budget: 4096,
            per_file_cap: CLIENT_DISCOVERY_MAX_SCAN_BYTES,
        };

        // `now_before`, captured immediately ahead of the call, gives an
        // elapsed-time-independent lower bound on the stored retry-after:
        // it is `t_call + CLIENT_DISCOVERY_TRUNCATED_RETRY_SECS` with
        // `t_call >= now_before`, so it must be at least `now_before +
        // CLIENT_DISCOVERY_TRUNCATED_RETRY_SECS`, whatever the call itself
        // cost.
        let now_before = cache_now();
        assert_eq!(discover_client_within(&client, tiny), None);
        let now_after = cache_now();
        assert!(
            client_discovery_miss_lookup(
                key,
                now_before + CLIENT_DISCOVERY_TRUNCATED_RETRY_SECS - 1
            ),
            "the stored retry-after must be at least `now_before + \
             {CLIENT_DISCOVERY_TRUNCATED_RETRY_SECS}` (it is `t_call + \
             {CLIENT_DISCOVERY_TRUNCATED_RETRY_SECS}` and `t_call \u{2265} now_before`) — so it \
             must still be active one second short of that, regardless of how long the call \
             itself took"
        );
        assert!(
            !client_discovery_miss_lookup(key, now_after + CLIENT_DISCOVERY_TRUNCATED_RETRY_SECS),
            "the stored retry-after must be the short truncated backoff — at most `t_call + \
             {CLIENT_DISCOVERY_TRUNCATED_RETRY_SECS}` \u{2264} `now_after + \
             {CLIENT_DISCOVERY_TRUNCATED_RETRY_SECS}` (`t_call \u{2264} now_after`) — whereas \
             the full {CLIENT_DISCOVERY_RETRY_SECS}s miss backoff would still be active this \
             far out"
        );

        let drained = take_pending_diagnostics();
        let stopped: Vec<&String> = drained
            .iter()
            .filter(|l| l.contains("stopped scanning"))
            .collect();
        assert_eq!(
            stopped.len(),
            1,
            "exactly one truncated-pass diagnostic — got {drained:?}"
        );
        assert!(
            !drained.iter().any(|l| l.contains(&id_env)),
            "a pass that never finished must not also queue the \"not found\" line — got \
             {drained:?}"
        );

        // A second call under the same tiny limits would return `None` at
        // the miss-backoff gate at the very top of `discover_client_within`
        // — before ever reaching the queueing point — which would prove
        // only the backoff above again, not the once-per-process dedup on
        // `queue_diag_once`. `client_discovery_evict` no longer merely
        // clears that gate — it arms a fresh backoff of its own (see its
        // own doc) — so what actually needs clearing here, and what this
        // does directly, is the stored retry-after itself: zeroing it (any
        // real `cache_now()` is `> 0`) is "not in backoff" without touching
        // `CLIENT_DISCOVERY_LOGGED`, unlike eviction. The call below
        // genuinely re-runs the scan to the same truncation, reaches
        // `queue_diag_once` a second time with the same key, and it is
        // that call which must decline to queue a second "stopped
        // scanning" line — the same distinction
        // `client_discovery_evict_does_not_clear_the_once_only_logged_set`
        // exercises directly.
        client_discovery_miss_store(key, 0);
        assert_eq!(discover_client_within(&client, tiny), None);
        let drained_again = take_pending_diagnostics();
        assert!(
            !drained_again.iter().any(|l| l.contains("stopped scanning")),
            "a pass that ran to the same truncation a second time must not queue a second copy \
             of the diagnostic — `CLIENT_DISCOVERY_LOGGED` is per config, not per call — got \
             {drained_again:?}"
        );

        // Cleared once more, and now with production's own limits: the
        // pair really was reachable all along — a truncated pass poisoned
        // neither the found cache nor the result.
        client_discovery_miss_store(key, 0);
        assert_eq!(
            discover_client_within(&client, CLIENT_DISCOVERY_LIMITS),
            Some((id, secret))
        );
        let drained_final = take_pending_diagnostics();
        assert!(
            !drained_final.iter().any(|l| l.contains("stopped scanning")),
            "a found pass must not resurrect the once-only truncated line either — got \
             {drained_final:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discover_client_counts_a_candidate_skipped_for_lack_of_budget_as_truncation() {
        let _diag_guard = DIAG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Same note as the test above: no env var is ever actually set —
        // `id_env` only names this config's would-be "not found" line for
        // the diagnostics-queue search below, and keeps this config's cache
        // key distinct from every other test's.
        let id_env = format!("TICKOVER_TRUNC_B_ID_{}", std::process::id());
        let secret_env = format!("TICKOVER_TRUNC_B_SECRET_{}", std::process::id());
        let dir = temp_dir("discover-truncated-skipped-candidate");
        const N: u64 = 4096;
        // The fixture relies on `first` being read whole in a single
        // `read()` (`want = min(chunk, budget)`) — that only holds if `N`
        // fits inside one chunk.
        const _: () = assert!(N < CLIENT_DISCOVERY_CHUNK_BYTES as u64);
        // `first` carries no pair and is exactly `N` bytes — its own scan
        // reads it whole, landing on EOF with `scanned == file_len`, a
        // genuine `NotFound` that happens to spend the entire shared
        // budget doing it. `second` (the pair) is listed right after it.
        let first = dir.join("first-no-pair");
        std::fs::write(&first, vec![b'x'; N as usize]).unwrap();
        let second = dir.join("second-has-pair");
        let id = fake_client_id("600001", "truncskipid");
        let secret = fake_secret("truncskipsecret0123456789ABCD");
        std::fs::write(&second, format!("{id} {secret}")).unwrap();

        let client = AuthClientDiscovery {
            id_env: Some(id_env.clone()),
            secret_env: Some(secret_env),
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![
                first.to_string_lossy().into_owned(),
                second.to_string_lossy().into_owned(),
            ],
            bins: Vec::new(),
        };
        let key = client_config_key(&client);
        // What this pins is the aggregate contract, not which exact line
        // inside `discover_client_within` records it: `first` spends the
        // whole shared budget just reading itself (a genuine `NotFound`,
        // `scanned == file_len`), leaving `second` — the pair — a
        // candidate the exhausted budget prevents from ever being read.
        // Whichever line catches that (in the current code, the `budget ==
        // 0` pre-check ahead of `second`, there precisely to avoid opening
        // a file it already knows it cannot afford to read, rather than
        // `scan_candidate` itself reporting `Truncated` on a zero budget),
        // the pass as a whole must still count it as truncation: the short
        // backoff, the "stopped scanning" diagnostic, and not the "not
        // found" one.
        let tiny = ScanLimits {
            pass_budget: N,
            per_file_cap: CLIENT_DISCOVERY_MAX_SCAN_BYTES,
        };

        // See the sibling test above for why `now_before` (captured ahead
        // of the call) gives an elapsed-time-independent lower bound.
        let now_before = cache_now();
        assert_eq!(discover_client_within(&client, tiny), None);
        let now_after = cache_now();
        assert!(
            client_discovery_miss_lookup(
                key,
                now_before + CLIENT_DISCOVERY_TRUNCATED_RETRY_SECS - 1
            ),
            "the stored retry-after must be at least `now_before + \
             {CLIENT_DISCOVERY_TRUNCATED_RETRY_SECS}` (it is `t_call + \
             {CLIENT_DISCOVERY_TRUNCATED_RETRY_SECS}` and `t_call \u{2265} now_before`) — so it \
             must still be active one second short of that, regardless of how long the call \
             itself took"
        );
        assert!(
            !client_discovery_miss_lookup(key, now_after + CLIENT_DISCOVERY_TRUNCATED_RETRY_SECS),
            "the stored retry-after must be the short truncated backoff — at most `t_call + \
             {CLIENT_DISCOVERY_TRUNCATED_RETRY_SECS}` \u{2264} `now_after + \
             {CLIENT_DISCOVERY_TRUNCATED_RETRY_SECS}` (`t_call \u{2264} now_after`) — whereas \
             the full {CLIENT_DISCOVERY_RETRY_SECS}s miss backoff would still be active this \
             far out"
        );

        let drained = take_pending_diagnostics();
        let stopped: Vec<&String> = drained
            .iter()
            .filter(|l| l.contains("stopped scanning"))
            .collect();
        assert_eq!(
            stopped.len(),
            1,
            "exactly one truncated-pass diagnostic — got {drained:?}"
        );
        assert!(
            !drained.iter().any(|l| l.contains(&id_env)),
            "a candidate skipped for lack of budget is truncation, not \"read it and it wasn't \
             there\" — the \"not found\" line must not also be queued, got {drained:?}"
        );

        // Sanity: the pair really was only missed because `second` was
        // skipped, not because the fixture is wrong — clearing the stored
        // retry-after (standing in for the backoff elapsing; not
        // `client_discovery_evict`, which now arms a fresh one of its own
        // rather than clearing this one — see its own doc) plus
        // production's own limits finds it.
        client_discovery_miss_store(key, 0);
        assert_eq!(
            discover_client_within(&client, CLIENT_DISCOVERY_LIMITS),
            Some((id, secret))
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discover_client_still_resolves_a_later_candidate_after_a_capped_one() {
        let _diag_guard = DIAG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Same note as the two tests above — nothing here touches the
        // environment either; the names below only make this config's
        // cache key unique.
        let id_env = format!("TICKOVER_TRUNC_C_ID_{}", std::process::id());
        let secret_env = format!("TICKOVER_TRUNC_C_SECRET_{}", std::process::id());
        let dir = temp_dir("discover-capped-then-resolved");
        // `big` must exceed one full chunk read (see `scan_candidate`'s own
        // doc: the cap is checked after each read, and a read can be
        // smaller than a chunk when little of the pass budget is left —
        // the pass budget here is the production 1 GiB, though, so a read
        // is a whole chunk). A file no bigger than that one read is always
        // read to EOF before the cap check ever runs, and could never
        // actually be cut short by it.
        let big = dir.join("big-no-pair");
        std::fs::write(&big, vec![b'x'; CLIENT_DISCOVERY_CHUNK_BYTES + 100]).unwrap();
        let small = dir.join("small-has-pair");
        let id = fake_client_id("600002", "trunccappedid");
        let secret = fake_secret("trunccappedsecret0123456789AB");
        std::fs::write(&small, format!("{id} {secret}")).unwrap();

        let client = AuthClientDiscovery {
            id_env: Some(id_env),
            secret_env: Some(secret_env),
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![
                big.to_string_lossy().into_owned(),
                small.to_string_lossy().into_owned(),
            ],
            bins: Vec::new(),
        };
        let key = client_config_key(&client);
        let limits = ScanLimits {
            pass_budget: CLIENT_DISCOVERY_PASS_BUDGET_BYTES,
            per_file_cap: CLIENT_DISCOVERY_CHUNK_BYTES as u64,
        };

        assert_eq!(
            discover_client_within(&client, limits),
            Some((id, secret)),
            "a candidate cut short by the per-file cap must not stop the pass — the pair in \
             the next candidate must still resolve"
        );
        let now_after = cache_now();
        assert!(
            !client_discovery_miss_lookup(key, now_after),
            "a found result must not also store a miss backoff"
        );

        // The diagnostics queue is shared with every other test in this
        // module; a found pass queues nothing, but proving its absence
        // here is not this test's job — only drained so nothing of this
        // config's own is left behind for whichever test runs next under
        // `DIAG_TEST_LOCK`.
        take_pending_diagnostics();

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discover_client_serves_a_cached_later_candidate_even_when_earlier_ones_exhaust_the_budget() {
        let _diag_guard = DIAG_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Same note as the truncation tests above: neither env var is ever
        // actually set — they only keep this config's cache key (and its
        // would-be "not found" line) unique among every other test sharing
        // `DIAG_TEST_LOCK`.
        let id_env = format!("TICKOVER_CACHE_LATER_ID_{}", std::process::id());
        let secret_env = format!("TICKOVER_CACHE_LATER_SECRET_{}", std::process::id());
        let dir = temp_dir("discover-cached-later-candidate");
        // Three candidates, not two: with just `[first, cached]`, `first`
        // alone exhausts the budget, and `cached`'s own lookup — the very
        // first thing its iteration does, before that iteration's own
        // `budget == 0` check is ever reached — already runs and hits,
        // proving nothing about what happens *after* budget hits zero.
        // `middle` sits between them precisely so `budget == 0` is reached,
        // on an iteration whose own lookup already missed, before the loop
        // ever gets to `third`'s cache entry — the case this test is
        // actually about: `continue`, not `break`, so that lookup still
        // runs.
        let first = dir.join("first-no-pair");
        std::fs::write(&first, vec![b'x'; 8192]).unwrap();
        let middle = dir.join("middle-no-pair");
        std::fs::write(&middle, vec![b'x'; 100]).unwrap();
        let third = dir.join("third-has-pair");
        let id = fake_client_id("600003", "cachelaterid");
        let secret = fake_secret("cachelatersecret0123456789AB");
        std::fs::write(&third, format!("{id} {secret}")).unwrap();

        let client = AuthClientDiscovery {
            id_env: Some(id_env),
            secret_env: Some(secret_env),
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![
                first.to_string_lossy().into_owned(),
                middle.to_string_lossy().into_owned(),
                third.to_string_lossy().into_owned(),
            ],
            bins: Vec::new(),
        };
        let key = client_config_key(&client);

        // Pass 1, at production's own limits: every candidate is read in
        // full, `third` resolves, and its pair is cached under `third`'s
        // own path — the sanity check the rest of this test leans on.
        assert_eq!(
            discover_client_within(&client, CLIENT_DISCOVERY_LIMITS),
            Some((id.clone(), secret.clone())),
            "sanity: the pair really is reachable at production's own limits"
        );
        take_pending_diagnostics();

        // Pass 2, at a shared budget (4096 bytes) too small even for
        // `first` alone (8192 bytes) to finish, let alone reach `middle` or
        // `third`: a candidate the budget cannot reach still has its cache
        // consulted. `budget == 0` fires on `middle`'s own iteration — its
        // own lookup already having missed — and `continue`s rather than
        // stopping the loop outright, so `third`'s iteration still runs its
        // own lookup and finds the pair pass 1 already cached there. Two
        // 512 MiB `bins` candidates ahead of a cached third do exactly this
        // in production.
        let tiny = ScanLimits {
            pass_budget: 4096,
            per_file_cap: CLIENT_DISCOVERY_MAX_SCAN_BYTES,
        };
        assert_eq!(
            discover_client_within(&client, tiny),
            Some((id, secret)),
            "a candidate cached on an earlier pass must be served even when this pass's shared \
             budget is exhausted by candidates ahead of it"
        );
        assert!(
            !client_discovery_miss_lookup(key, cache_now()),
            "a cache hit must not also store a truncated-pass backoff"
        );
        let drained = take_pending_diagnostics();
        assert!(
            !drained.iter().any(|l| l.contains("stopped scanning")),
            "a cache hit must not queue the truncated-pass diagnostic either — got {drained:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discover_client_prefers_a_fresh_earlier_candidate_over_a_cached_later_one() {
        // Neither env var is ever actually set — see the sibling tests
        // above for why they exist at all (cache-key uniqueness).
        let id_env = format!("TICKOVER_PRECEDENCE_ID_{}", std::process::id());
        let secret_env = format!("TICKOVER_PRECEDENCE_SECRET_{}", std::process::id());
        let dir = temp_dir("discover-precedence-fresh-earlier");
        let first = dir.join("first-fresh-later");
        let second = dir.join("second-cached-first");
        let p2_id = fake_client_id("600004", "precedencesecond");
        let p2_secret = fake_secret("precedencesecondsecret0123456789AB");
        std::fs::write(&second, format!("{p2_id} {p2_secret}")).unwrap();

        let client = AuthClientDiscovery {
            id_env: Some(id_env),
            secret_env: Some(secret_env),
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![
                first.to_string_lossy().into_owned(),
                second.to_string_lossy().into_owned(),
            ],
            bins: Vec::new(),
        };

        // Pass 1: `first` does not exist yet — a genuine miss, not a
        // truncation or an error — so `second` resolves, and its pair is
        // cached under `second`'s own path.
        assert_eq!(
            discover_client_within(&client, CLIENT_DISCOVERY_LIMITS),
            Some((p2_id.clone(), p2_secret.clone())),
            "sanity: with `first` absent, `second`'s pair is what pass 1 finds and caches"
        );

        // `first` now exists, carrying a genuinely different pair — a
        // fresh install landing in the earlier-named candidate. With a
        // cache pre-pass ahead of the scan, every candidate's cache entry
        // would be consulted before any scanning began, so `second`'s
        // still-valid entry (unchanged file, same `len`/`mtime`) would be
        // served here — the stale P2 pair — without `first` ever being
        // looked at again. Precedence instead goes the other way: the
        // first candidate that actually carries both patterns wins, cache
        // or no cache, exactly as it would with no cache at all.
        let p1_id = fake_client_id("600005", "precedencefirst");
        let p1_secret = fake_secret("precedencefirstsecret0123456789ABC");
        std::fs::write(&first, format!("{p1_id} {p1_secret}")).unwrap();

        assert_eq!(
            discover_client_within(&client, CLIENT_DISCOVERY_LIMITS),
            Some((p1_id, p1_secret)),
            "a fresh pair in an earlier candidate must win over a cached pair in a later one"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oauth_refresh_step_with_nothing_discoverable_resolves_absent() {
        let dir = temp_dir("discover-absent");
        let mut step = oauth_refresh_step_for(&dir, r#"{"refresh_token":"r-1"}"#);
        // The base fixture sets a literal `client_id`/`client_secret`
        // (see `oauth_refresh_step_for`) — cleared here so this run has
        // nothing but the `client` table to resolve from.
        step.client_id = None;
        step.client_secret = None;
        step.client = Some(AuthClientDiscovery {
            id_env: None,
            secret_env: None,
            id_pattern: Some(synthetic_id_pattern()),
            secret_pattern: Some(synthetic_secret_pattern()),
            files: vec![dir
                .join("no-such-client-binary")
                .to_string_lossy()
                .into_owned()],
            bins: Vec::new(),
        });

        assert_eq!(
            oauth_refresh_step(&step, &["oauth2.googleapis.com".to_string()]),
            Ok(None),
            "nothing discoverable resolves the step Absent, not an error"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn extract_access_token_reads_the_token_and_its_life() {
        let value = json!({ "access_token": "fresh", "expires_in": 3599 });
        assert_eq!(
            extract_access_token(&value),
            Some(("fresh".to_string(), 3599))
        );
        // A response with no expires_in still paces, at a conservative hour.
        let no_exp = json!({ "access_token": "fresh" });
        assert_eq!(
            extract_access_token(&no_exp),
            Some(("fresh".to_string(), 3600))
        );
    }

    #[test]
    fn extract_access_token_is_none_when_missing_blank_not_a_string_or_already_dead() {
        assert_eq!(extract_access_token(&json!({ "expires_in": 3599 })), None);
        assert_eq!(extract_access_token(&json!({ "access_token": "" })), None);
        assert_eq!(
            extract_access_token(&json!({ "access_token": "   " })),
            None
        );
        assert_eq!(
            extract_access_token(&json!({ "access_token": 12345 })),
            None
        );
        // At or below the 60s cache margin the token would be cached already
        // expired, so it is treated as no token — the caller backs off.
        assert_eq!(
            extract_access_token(&json!({ "access_token": "x", "expires_in": 0 })),
            None
        );
        assert_eq!(
            extract_access_token(&json!({ "access_token": "x", "expires_in": -5 })),
            None
        );
        assert_eq!(
            extract_access_token(&json!({ "access_token": "x", "expires_in": 60 })),
            None
        );
        assert_eq!(
            extract_access_token(&json!({ "access_token": "x", "expires_in": 30 })),
            None
        );
        // Just above the margin is fine.
        assert_eq!(
            extract_access_token(&json!({ "access_token": "x", "expires_in": 61 })),
            Some(("x".to_string(), 61))
        );
    }

    #[test]
    fn extract_access_token_clamps_an_implausibly_long_expires_in() {
        assert_eq!(
            extract_access_token(&json!({ "access_token": "x", "expires_in": i64::MAX })),
            Some(("x".to_string(), EXPIRES_IN_MAX_SECS)),
            "a hostile or buggy expires_in must never cache a token that outlives \
             EXPIRES_IN_MAX_SECS"
        );
        // Just past the cap is clamped down to it; just at the cap is left
        // alone — the clamp is `>`, not `>=`.
        assert_eq!(
            extract_access_token(
                &json!({ "access_token": "x", "expires_in": EXPIRES_IN_MAX_SECS + 1 })
            ),
            Some(("x".to_string(), EXPIRES_IN_MAX_SECS))
        );
        assert_eq!(
            extract_access_token(
                &json!({ "access_token": "x", "expires_in": EXPIRES_IN_MAX_SECS })
            ),
            Some(("x".to_string(), EXPIRES_IN_MAX_SECS))
        );
    }

    #[test]
    fn extract_access_token_accepts_expires_in_as_a_float_or_a_numeric_string() {
        // A float, truncated toward zero rather than rounded.
        assert_eq!(
            extract_access_token(&json!({ "access_token": "x", "expires_in": 3599.9 })),
            Some(("x".to_string(), 3599))
        );
        // A numeric string, the shape at least one real deployment sends.
        assert_eq!(
            extract_access_token(&json!({ "access_token": "x", "expires_in": "3600" })),
            Some(("x".to_string(), 3600))
        );
        // `"0"` as a string must be read as the number `0`, not silently
        // fall through to the conservative-hour default the way reading
        // only `Value::as_i64` would (a JSON string is never an `i64`).
        assert_eq!(
            extract_access_token(&json!({ "access_token": "x", "expires_in": "0" })),
            None,
            "a zero expires_in sent as a string must be rejected, not defaulted to an hour"
        );
        // A float string, and garbage that parses as neither.
        assert_eq!(
            extract_access_token(&json!({ "access_token": "x", "expires_in": "3599.0" })),
            Some(("x".to_string(), 3599))
        );
        assert_eq!(
            extract_access_token(&json!({ "access_token": "x", "expires_in": "soon" })),
            Some(("x".to_string(), 3600)),
            "unparseable falls back to the conservative-hour default, same as absent"
        );
    }

    #[test]
    fn refresh_cache_serves_a_token_until_it_expires_then_misses() {
        // Distinct key per run so parallel tests never share the process-wide
        // static. The expiry is anchored to `cache_now()`, not a small
        // literal like `1000` — `refresh_cache_store`'s own prune sweep (see
        // its doc) judges every other entry in the map against the real
        // `cache_now()` on every call, and a literal that far in the past by
        // that clock could be pruned away by some unrelated, concurrently
        // running test's own store before this test ever gets to look it up.
        // Offset comfortably clear of both the real clock and
        // `REFRESH_CACHE_FAILED_GRACE_SECS`/`REFRESH_BACKOFF_SECS`, the same
        // relative before/at/after structure just measured from there.
        let key = refresh_cache_key("u", &format!("rt-fresh-{}", std::process::id()));
        let base = cache_now() + 1_000_000;
        refresh_cache_store(
            key,
            CacheEntry::Fresh {
                access_token: "cached".to_string(),
                expires_at_unix: base,
            },
        );
        assert!(
            matches!(refresh_cache_lookup(key, base - 1), CacheLookup::Hit(t) if t == "cached"),
            "before expiry"
        );
        assert!(
            matches!(refresh_cache_lookup(key, base), CacheLookup::Miss),
            "at expiry, retired"
        );
        assert!(
            matches!(refresh_cache_lookup(key, base + 1), CacheLookup::Miss),
            "past expiry"
        );
    }

    #[test]
    fn refresh_cache_backs_off_a_recent_failure() {
        // See the sibling test above for why this is anchored to
        // `cache_now()` rather than a small literal.
        let key = refresh_cache_key("u", &format!("rt-fail-{}", std::process::id()));
        let base = cache_now() + 1_000_000;
        refresh_cache_store(
            key,
            CacheEntry::Failed {
                retry_after_unix: base,
                client_id: "c".to_string(),
                secret_hash: secret_hash("s"),
                message: "exchange failed".to_string(),
            },
        );
        assert!(
            matches!(
                refresh_cache_lookup(key, base - 1),
                CacheLookup::Backoff { client_id, secret_hash: sh, message }
                    if client_id == "c" && sh == secret_hash("s") && message == "exchange failed"
            ),
            "inside backoff, carrying the client_id/secret_hash/message it failed with"
        );
        assert!(
            matches!(refresh_cache_lookup(key, base), CacheLookup::Miss),
            "backoff over, retry"
        );
    }

    #[test]
    fn refresh_cache_key_separates_different_token_urls_or_refresh_tokens() {
        // `client_id` is deliberately not part of the key any more (see
        // `REFRESH_CACHE`'s own doc) — this now proves distinctness on the
        // two inputs that *are* the key, not on a third one that used to be.
        let rt = format!("rt-{}", std::process::id());
        assert_ne!(
            refresh_cache_key("https://a/token", &rt),
            refresh_cache_key("https://b/token", &rt),
            "different token_url must not collide"
        );
        let rt2 = format!("rt2-{}", std::process::id());
        assert_ne!(
            refresh_cache_key("https://a/token", &rt),
            refresh_cache_key("https://a/token", &rt2),
            "different refresh_token must not collide"
        );
    }

    #[test]
    fn cache_now_is_never_zero_and_never_runs_backwards() {
        let a = cache_now();
        assert!(
            a > 0,
            "cache_now must never be zero or negative, unlike now_unix on a broken clock"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
        let b = cache_now();
        assert!(
            b >= a,
            "cache_now must never run backwards within the process: {a} then {b}"
        );
    }

    /// The one property [`keychain_password`]'s memo exists to have: a hit
    /// under the exact pass it was stored at, a miss — never a stale reuse —
    /// under any other. Exercised through [`pass_memo_get`] directly, with no
    /// `Mutex` and no real Keychain call anywhere near it.
    #[test]
    fn pass_memo_get_serves_a_hit_only_under_the_pass_it_was_stored_at() {
        let mut map: std::collections::HashMap<String, (u64, Result<Option<String>, String>)> =
            std::collections::HashMap::new();
        map.insert("svc".to_string(), (5, Ok(Some("tok".to_string()))));
        let memo = Some(map);

        assert_eq!(
            pass_memo_get(&memo, "svc", 5),
            Some(Ok(Some("tok".to_string()))),
            "a lookup under the pass it was stored at is a hit"
        );
        assert_eq!(
            pass_memo_get(&memo, "svc", 6),
            None,
            "a different pass — even one number over — is a miss, not a stale reuse"
        );
        assert_eq!(
            pass_memo_get(&memo, "other-svc", 5),
            None,
            "a different key is a miss regardless of the pass"
        );
        assert_eq!(
            pass_memo_get::<Result<Option<String>, String>>(&None, "svc", 5),
            None,
            "an empty memo (nothing stored yet this process) is a miss"
        );
    }

    /// [`begin_fetch_pass`] is what keeps the memo from becoming a
    /// process-lifetime static in practice: every call must move it forward,
    /// on a shared, process-wide counter (concurrent test threads calling it
    /// at the same time are exactly what `main.rs`'s tick and a fetch thread
    /// unlucky enough to straddle two ticks would do for real).
    #[test]
    fn begin_fetch_pass_is_strictly_increasing() {
        let a = begin_fetch_pass();
        let b = begin_fetch_pass();
        assert!(
            b > a,
            "every call starts a newer pass than the one before it: {a} then {b}"
        );
    }

    #[test]
    fn refresh_cache_store_prunes_a_failed_entry_once_its_grace_period_has_passed() {
        // Distinct keys so this cannot collide with any other test's own
        // entries in the shared, process-wide `REFRESH_CACHE`.
        let stale_key = refresh_cache_key(
            "https://example.test/prune-grace-elapsed",
            &format!("prune-grace-elapsed-{}", std::process::id()),
        );
        let now = cache_now();
        // Past its own `retry_after_unix` *and* past the grace period this
        // module keeps a `Failed` entry alive for afterward (see
        // `REFRESH_CACHE_FAILED_GRACE_SECS`'s own doc) — nothing should
        // still want to read this one.
        refresh_cache_store(
            stale_key,
            CacheEntry::Failed {
                retry_after_unix: now - REFRESH_CACHE_FAILED_GRACE_SECS - 100,
                client_id: "irrelevant".to_string(),
                secret_hash: 0,
                message: "irrelevant".to_string(),
            },
        );
        // A second, unrelated store — the only way `refresh_cache_store`
        // ever prunes anything (see its own doc: pruning happens on store,
        // not on a timer).
        let other_key = refresh_cache_key(
            "https://example.test/prune-grace-other",
            &format!("prune-grace-other-{}", std::process::id()),
        );
        refresh_cache_store(
            other_key,
            CacheEntry::Failed {
                retry_after_unix: now + REFRESH_BACKOFF_SECS,
                client_id: "irrelevant".to_string(),
                secret_hash: 0,
                message: "irrelevant".to_string(),
            },
        );

        let guard = REFRESH_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        let map = guard.as_ref().expect("something was stored");
        assert!(
            !map.contains_key(&stale_key),
            "an entry past its own grace period must be pruned once another store call runs"
        );
        assert!(
            map.contains_key(&other_key),
            "storing one entry must not prune a still-live one"
        );
    }

    #[test]
    fn refresh_cache_store_keeps_a_recently_lapsed_failed_entry_within_its_grace_period() {
        // The other side of the sibling test above: a `Failed` entry whose
        // own backoff has lapsed, but not by more than
        // `REFRESH_CACHE_FAILED_GRACE_SECS` yet, must survive a subsequent
        // store call — this is exactly the window
        // `refresh_cache_last_failed_message` exists to still read from.
        let recent_key = refresh_cache_key(
            "https://example.test/prune-grace-recent",
            &format!("prune-grace-recent-{}", std::process::id()),
        );
        let now = cache_now();
        refresh_cache_store(
            recent_key,
            CacheEntry::Failed {
                retry_after_unix: now - 1,
                client_id: "irrelevant".to_string(),
                secret_hash: 0,
                message: "still within grace".to_string(),
            },
        );
        let other_key = refresh_cache_key(
            "https://example.test/prune-grace-recent-other",
            &format!("prune-grace-recent-other-{}", std::process::id()),
        );
        refresh_cache_store(
            other_key,
            CacheEntry::Failed {
                retry_after_unix: now + REFRESH_BACKOFF_SECS,
                client_id: "irrelevant".to_string(),
                secret_hash: 0,
                message: "irrelevant".to_string(),
            },
        );

        assert_eq!(
            refresh_cache_last_failed_message(recent_key).as_deref(),
            Some("still within grace"),
            "a `Failed` entry inside its grace period must survive another key's store call"
        );
    }

    #[test]
    fn token_is_stale_reads_an_expiry_beside_the_token() {
        // 2026-08-21T18:39:49+03:00 == 1787326789 Unix.
        const EXP: i64 = 1787326789;
        let json = r#"{"token":{"access_token":"ya29.x","expiry":"2026-08-21T18:39:49+03:00"}}"#;
        // A minute past expiry (plus the margin) is stale.
        assert!(token_is_stale(json, "token.expiry", EXP + 61));
        // Comfortably before expiry is fresh.
        assert!(!token_is_stale(json, "token.expiry", EXP - 3600));
        // Inside the 60s margin counts as stale — refresh before the 401.
        assert!(token_is_stale(json, "token.expiry", EXP - 30));
    }

    #[test]
    fn token_is_stale_reads_an_old_rfc3339_expiry_as_stale_regardless_of_plausibility() {
        // `MIN_PLAUSIBLE_EXPIRY_UNIX` guards the numeric branch only: an
        // RFC3339 string that parses at all already says the field holds a
        // date, however old, so a pre-2000 one must still read as stale
        // rather than unreadable.
        let pre_2000 = r#"{"token":{"expiry":"1999-12-31T23:59:59Z"}}"#;
        assert!(token_is_stale(pre_2000, "token.expiry", i64::MAX));

        // A pre-1970 date clamps to 0 (same convention as
        // `time::parse_iso8601`) rather than going negative or being
        // discarded — still stale, never "unreadable".
        let pre_1970 = r#"{"token":{"expiry":"1960-01-01T00:00:00Z"}}"#;
        assert!(token_is_stale(pre_1970, "token.expiry", i64::MAX));
    }

    #[test]
    fn keychain_blob_falls_through_when_the_token_has_lapsed() {
        // The composed fall-through the whole hybrid rests on: a keychain step
        // with an expiry path and a lapsed token resolves Absent, so the chain
        // reaches the oauth-refresh step behind it. EXP = 2026-08-21T18:39:49+03:00.
        const EXP: i64 = 1787326789;
        let blob =
            r#"{"token":{"access_token":"ya29.stale","expiry":"2026-08-21T18:39:49+03:00"}}"#;
        // Lapsed → Absent, chain falls through, and the caller learns the
        // declared expiry itself, not merely that one was found.
        let mut lapsed_expiry = None;
        assert_eq!(
            token_from_blob(
                blob,
                "token.access_token",
                Some("token.expiry"),
                EXP + 61,
                "gemini",
                &mut lapsed_expiry,
            ),
            Ok(None),
            "a lapsed keychain token must resolve Absent, not Present-ok"
        );
        assert_eq!(
            lapsed_expiry,
            Some(EXP as u64),
            "the caller must be told which expiry the lapsed token declared"
        );

        // Fresh → the token, no fall-through, and the sink stays as it was.
        let mut lapsed_expiry = None;
        assert_eq!(
            token_from_blob(
                blob,
                "token.access_token",
                Some("token.expiry"),
                EXP - 3600,
                "gemini",
                &mut lapsed_expiry,
            ),
            Ok(Some("ya29.stale".to_string()))
        );
        assert_eq!(lapsed_expiry, None);

        // No expiry path → returned regardless of age, as every other manifest
        // relies on.
        assert_eq!(
            token_from_blob(
                blob,
                "token.access_token",
                None,
                EXP + 999_999,
                "gemini",
                &mut None,
            ),
            Ok(Some("ya29.stale".to_string()))
        );
    }

    #[test]
    fn token_from_blob_names_the_first_lapsed_expiry_not_the_last() {
        // Two calls sharing one sink, as two auth steps in a chain would: the
        // first step's own lapsed expiry is the one that survives — a second,
        // different expiry a later step happens to find is not this app's
        // business to choose between (see `resolve_token`'s own doc).
        const FIRST: i64 = 1_700_000_000;
        const SECOND: i64 = 1_800_000_000;
        let first_blob = format!(r#"{{"token":{{"access_token":"a","expiry":{FIRST}}}}}"#);
        let second_blob = format!(r#"{{"token":{{"access_token":"b","expiry":{SECOND}}}}}"#);
        let mut lapsed_expiry = None;
        assert_eq!(
            token_from_blob(
                &first_blob,
                "token.access_token",
                Some("token.expiry"),
                i64::MAX,
                "first",
                &mut lapsed_expiry,
            ),
            Ok(None)
        );
        assert_eq!(
            token_from_blob(
                &second_blob,
                "token.access_token",
                Some("token.expiry"),
                i64::MAX,
                "second",
                &mut lapsed_expiry,
            ),
            Ok(None)
        );
        assert_eq!(lapsed_expiry, Some(FIRST as u64));
    }

    #[test]
    fn token_from_blob_reads_a_stale_expiry_beside_a_missing_token_as_not_found_not_lapsed() {
        // A stale `expiresAt` with no `accessToken` at all — a malformed or
        // half-written credentials file, not a credential this step ever
        // actually held. Must be the ordinary "not found" error, and must
        // never set `lapsed_expiry`: nothing here found a token to call
        // lapsed, so `[ping] renews_token` has nothing to act on.
        let blob = r#"{"claudeAiOauth":{"expiresAt":1577836800000}}"#; // 2020-01-01, ms
        let mut lapsed_expiry = None;
        let err = token_from_blob(
            blob,
            "claudeAiOauth.accessToken",
            Some("claudeAiOauth.expiresAt"),
            i64::MAX,
            "credentials file",
            &mut lapsed_expiry,
        )
        .expect_err("no token at the path is Present-err, not a lapsed Absent");
        assert!(
            err.contains("no token at `claudeAiOauth.accessToken`"),
            "{err}"
        );
        assert_eq!(
            lapsed_expiry, None,
            "a token that was never found cannot also be the one that lapsed"
        );
    }

    #[test]
    fn token_is_stale_is_false_when_the_expiry_cannot_be_read() {
        // Missing, a number too small to be a plausible expiry, non-RFC3339,
        // and a shape that is neither a string nor a number all fail safe to
        // "not stale" — a token that might still work is never discarded on
        // a bad parse.
        assert!(!token_is_stale(
            r#"{"token":{"access_token":"x"}}"#,
            "token.expiry",
            i64::MAX
        ));
        // 123 parses as a number, but as epoch seconds it names 1970 — under
        // `MIN_PLAUSIBLE_EXPIRY_UNIX`, so this is the "implausible" case, not
        // the "cannot parse" one; the fail-safe treats them the same.
        assert!(!token_is_stale(
            r#"{"token":{"expiry":123}}"#,
            "token.expiry",
            i64::MAX
        ));
        assert!(!token_is_stale(
            r#"{"token":{"expiry":"whenever"}}"#,
            "token.expiry",
            i64::MAX
        ));
        // Neither a string nor a number at all.
        assert!(!token_is_stale(
            r#"{"token":{"expiry":true}}"#,
            "token.expiry",
            i64::MAX
        ));
        assert!(!token_is_stale("not json", "token.expiry", i64::MAX));
    }

    #[test]
    fn token_is_stale_reads_an_epoch_number_as_seconds_or_milliseconds() {
        // 2026-08-21T18:39:49Z == 1787329189 Unix.
        const EXP_SECS: i64 = 1_787_329_189;
        let seconds = format!(r#"{{"claudeAiOauth":{{"expiresAt":{EXP_SECS}}}}}"#);
        assert!(
            token_is_stale(&seconds, "claudeAiOauth.expiresAt", EXP_SECS + 61),
            "a minute past an epoch-seconds expiry is stale"
        );
        assert!(
            !token_is_stale(&seconds, "claudeAiOauth.expiresAt", EXP_SECS - 3600),
            "comfortably before an epoch-seconds expiry is fresh"
        );
        assert!(
            token_is_stale(&seconds, "claudeAiOauth.expiresAt", EXP_SECS - 30),
            "inside the 60s margin counts as stale, same as the RFC3339 form"
        );

        // Claude's own shape: the same instant, in epoch milliseconds — well
        // past `MS_MAGNITUDE_THRESHOLD`, so it is divided down rather than
        // read as three hundred thousand centuries away.
        let millis = format!(r#"{{"claudeAiOauth":{{"expiresAt":{}}}}}"#, EXP_SECS * 1000);
        assert!(token_is_stale(
            &millis,
            "claudeAiOauth.expiresAt",
            EXP_SECS + 61
        ));
        assert!(!token_is_stale(
            &millis,
            "claudeAiOauth.expiresAt",
            EXP_SECS - 3600
        ));

        // A quoted number — some credential files stringify theirs — reads
        // the same as a bare one.
        let quoted = format!(
            r#"{{"claudeAiOauth":{{"expiresAt":"{}"}}}}"#,
            EXP_SECS * 1000
        );
        assert!(token_is_stale(
            &quoted,
            "claudeAiOauth.expiresAt",
            EXP_SECS + 61
        ));
        assert!(!token_is_stale(
            &quoted,
            "claudeAiOauth.expiresAt",
            EXP_SECS - 3600
        ));
    }

    #[test]
    fn unwrap_go_keyring_trims_before_matching_the_marker() {
        // go-keyring trims the whole value before checking the prefix; a
        // leading newline must not leave the marker unmatched and the wrapped
        // payload mistaken for plain JSON.
        use base64::{engine::general_purpose::STANDARD, Engine};
        let json = r#"{"token":{"access_token":"ya29.z"}}"#;
        let wrapped = format!("  \n go-keyring-base64:{}\n", STANDARD.encode(json));
        assert_eq!(unwrap_go_keyring(&wrapped).unwrap(), json);
    }

    #[test]
    fn token_from_decrypted_trims_trailing_bytes() {
        let plain = b"{\"claudeAiOauth\":{\"accessToken\":\"tok-desktop\"}}\x07\x07\x07";
        assert_eq!(
            token_from_decrypted(plain, "claudeAiOauth.accessToken|access_token").as_deref(),
            Some("tok-desktop")
        );
        assert_eq!(
            token_from_decrypted(b"no json here", "claudeAiOauth.accessToken|access_token"),
            None
        );
    }

    #[test]
    fn token_from_decrypted_cuts_at_the_first_top_level_close_not_the_last() {
        // Trailing garbage that itself contains a `}` — proves this finds
        // the JSON's own top-level close, not merely the last `}` anywhere
        // in the buffer. The last `}` here sits inside "garbage}more{stuff",
        // which would hand `serde_json` `{...}garbage}` (a trailing-garbage
        // parse failure) were this still cutting at `rfind('}')`.
        let plain = b"{\"claudeAiOauth\":{\"accessToken\":\"tok-desktop\"}}garbage}more{stuff";
        assert_eq!(
            token_from_decrypted(plain, "claudeAiOauth.accessToken|access_token").as_deref(),
            Some("tok-desktop")
        );
    }

    #[test]
    fn first_top_level_object_end_skips_braces_inside_quoted_strings() {
        // A value carrying a literal `}` (escaped, as valid JSON requires)
        // must not be mistaken for the object's own close.
        let text = r#"{"a":"x}y","b":1}"#;
        assert_eq!(first_top_level_object_end(text), Some(text.len()));
        assert_eq!(first_top_level_object_end("no braces here"), None);
        assert_eq!(first_top_level_object_end("{\"unterminated\": 1"), None);
    }

    /// Round-trip through the real Safe Storage scheme: encrypt with the
    /// same derivation (PBKDF2-SHA1/saltysalt/1003 -> AES-128-CBC, IV =
    /// spaces) and a `v10` prefix, then decrypt with the code under test.
    #[test]
    fn safe_storage_roundtrip() {
        use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

        let pw = "keychain-password";
        let plain = br#"{"claudeAiOauth":{"accessToken":"tok-safe-storage"}}"#;

        let mut key = [0u8; 16];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(pw.as_bytes(), b"saltysalt", 1003, &mut key);
        let iv = [0x20u8; 16];

        type Enc = cbc::Encryptor<aes::Aes128>;
        let mut buf = vec![0u8; plain.len() + 16];
        buf[..plain.len()].copy_from_slice(plain);
        let ct = Enc::new(&key.into(), &iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plain.len())
            .expect("encrypt");

        let mut blob = b"v10".to_vec();
        blob.extend_from_slice(ct);

        let out = safe_storage_decrypt(&blob, pw).expect("decrypt");
        assert_eq!(out, plain);
        assert_eq!(
            token_from_decrypted(&out, "claudeAiOauth.accessToken|access_token").as_deref(),
            Some("tok-safe-storage")
        );

        // Wrong password must fail (padding check), not return garbage.
        assert!(safe_storage_decrypt(&blob, "wrong").is_err());
    }

    // ── keychain output classification (item-not-found vs denied) ───────
    //
    // Hermetic: no real `security`/Keychain call — fed fake stdout/stderr
    // bytes, exactly as `keychain_password` would pass along the real
    // `Command::output()`. Covers the FIX 5 regression: a Keychain item that
    // simply doesn't exist must be Absent (`Ok(None)`, chain moves on /
    // surface hides), never a Present-err shown inline; a denied-access
    // failure is the opposite.

    #[test]
    fn classify_keychain_output_success_with_password_is_present_ok() {
        assert_eq!(
            classify_keychain_output(true, b"tok-from-keychain\n", b"", "svc"),
            Ok(Some("tok-from-keychain".to_string()))
        );
    }

    #[test]
    fn classify_keychain_output_success_with_empty_password_is_absent() {
        assert_eq!(classify_keychain_output(true, b"", b"", "svc"), Ok(None));
    }

    #[test]
    fn classify_keychain_output_item_not_found_is_absent() {
        let stderr = b"security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n";
        assert_eq!(
            classify_keychain_output(false, b"", stderr, "svc"),
            Ok(None)
        );
    }

    #[test]
    fn classify_keychain_output_access_denied_is_a_present_err() {
        let stderr = b"security: SecKeychainItemCopyContent: User interaction is not allowed.\n";
        let err = classify_keychain_output(false, b"", stderr, "Claude Safe Storage")
            .expect_err("denied access must be a Present-err, not Absent");
        assert!(
            err.contains("Claude Safe Storage"),
            "unexpected error: {err}"
        );
        assert!(err.contains("Keychain access"), "unexpected error: {err}");
    }

    /// The wiring `pipe_drain_failure_message_reports_whichever_drain_failed_to_start`
    /// cannot reach on its own: that test proves *which* message a failed
    /// drain reports, but nothing there ever touches a real child, and a
    /// real `Builder::spawn` failure cannot be forced on demand to prove the
    /// `if let Some(msg) = …` branch actually kills the one it names.
    /// `kill_and_wait` is exactly what that branch (and the other two exits
    /// that give up on a child) calls — proven directly against a real one
    /// here instead: `kill(pid, 0)` polled until it reports the process
    /// gone, the same technique `main.rs`'s own grandchild-kill test uses.
    #[cfg(unix)]
    #[test]
    fn kill_and_wait_actually_kills_a_real_child() {
        let mut child = std::process::Command::new("sh")
            .args(["-c", "sleep 30"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("sh");
        let pid = child.id() as libc::pid_t;

        kill_and_wait(&mut child);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        // SAFETY: signal `0` sends nothing — it only asks the kernel whether
        // `pid` still exists, the standard liveness probe.
        while unsafe { libc::kill(pid, 0) } == 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_ne!(
            unsafe { libc::kill(pid, 0) },
            0,
            "the child must be gone once kill_and_wait returns"
        );
    }

    /// The stand-in `run_command_with_deadline`'s own doc promises: `security`
    /// needs a real Keychain, but the deadline logic itself does not — a
    /// command guaranteed to outlive the deadline proves the kill.
    #[cfg(unix)]
    #[test]
    fn run_command_with_deadline_kills_a_command_that_outlives_it() {
        let started = std::time::Instant::now();
        let err = run_command_with_deadline(
            "sh",
            &["-c", "sleep 30"],
            std::time::Duration::from_millis(300),
        )
        .expect_err("a command that outlives the deadline must be reported, not returned");
        assert!(err.contains("did not finish"), "{err}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "returned promptly, not after the full sleep"
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_command_with_deadline_reports_a_command_that_ends_on_its_own() {
        let out = run_command_with_deadline(
            "sh",
            &["-c", "printf ok; exit 0"],
            std::time::Duration::from_secs(30),
        )
        .expect("a command that exits well within the deadline must not be treated as a timeout");
        assert!(out.success);
        assert_eq!(out.stdout, b"ok");
    }

    #[cfg(unix)]
    #[test]
    fn run_command_with_deadline_reports_a_failing_command_as_unsuccessful_not_an_error() {
        let out = run_command_with_deadline(
            "sh",
            &["-c", "printf trouble 1>&2; exit 3"],
            std::time::Duration::from_secs(30),
        )
        .expect("a command that runs to completion, even with a non-zero exit, is not a timeout");
        assert!(!out.success);
        assert_eq!(out.stderr, b"trouble");
    }

    /// A `Read` that answers exactly the way an interrupted syscall would:
    /// `Err(Interrupted)` once, then the real bytes, then EOF. Standing in
    /// for a real pipe, which cannot be made to return `EINTR` on demand.
    struct InterruptOnceThenData {
        interrupted_yet: bool,
        data: &'static [u8],
        pos: usize,
    }
    impl std::io::Read for InterruptOnceThenData {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted_yet {
                self.interrupted_yet = true;
                return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
            }
            let remaining = &self.data[self.pos..];
            let n = remaining.len().min(buf.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.pos += n;
            Ok(n)
        }
    }

    /// An `Err` from a read must not end the drain when it is
    /// `Interrupted` — `EINTR` mid-read on an otherwise perfectly fine pipe
    /// must be retried, not mistaken for the pipe's own end and lose every
    /// byte still to come.
    #[test]
    fn drain_into_retries_after_an_interrupted_read_instead_of_stopping() {
        let source = InterruptOnceThenData {
            interrupted_yet: false,
            data: b"hello",
            pos: 0,
        };
        let sink = std::sync::Mutex::new(Vec::new());
        drain_into(source, &sink);
        assert_eq!(
            *sink.lock().unwrap(),
            b"hello",
            "the interrupted read must not be mistaken for EOF"
        );
    }

    /// A thread the OS refuses to hand out for either pipe must not be
    /// swallowed the way it once was (`let _ = …spawn(…)`, no report, and the
    /// child left to find out about the closed pipe from `SIGPIPE` on its own
    /// next write): `run_command_with_deadline` has to see it and say so.
    /// Pure inputs stand in for the actual `Builder::spawn` failure, which
    /// nothing here can trigger on demand.
    #[test]
    fn pipe_drain_failure_message_reports_whichever_drain_failed_to_start() {
        let ok = || Ok(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
        let stdout_err = Err(std::io::Error::other("boom-stdout"));
        let stderr_err = Err(std::io::Error::other("boom-stderr"));

        assert_eq!(
            pipe_drain_failure_message("security", &ok(), &ok()),
            None,
            "both drains started — nothing to report"
        );
        assert_eq!(
            pipe_drain_failure_message("security", &stdout_err, &ok()),
            Some("security: could not start a pipe-drain thread: boom-stdout".to_string())
        );
        assert_eq!(
            pipe_drain_failure_message("security", &ok(), &stderr_err),
            Some("security: could not start a pipe-drain thread: boom-stderr".to_string())
        );
        assert_eq!(
            pipe_drain_failure_message(
                "security",
                &Err(std::io::Error::other("boom-stdout")),
                &Err(std::io::Error::other("boom-stderr"))
            ),
            Some("security: could not start a pipe-drain thread: boom-stdout".to_string()),
            "stdout's failure wins when both did"
        );
    }

    // ── reject-when step ──────────────────────────────────────────────────

    /// A `~/.codex/auth.json` in each of the shapes the real CLI writes.
    fn reject_when_step_for(dir: &std::path::Path, body: &str) -> AuthStep {
        let file = dir.join("auth.json");
        std::fs::write(&file, body).unwrap();
        AuthStep {
            path: Some(file.to_string_lossy().into_owned()),
            json_path: Some("OPENAI_API_KEY".to_string()),
            unless_json_path: Some("tokens.access_token".to_string()),
            message: Some("an API key has no subscription limits".to_string()),
            ..auth_step(AuthType::RejectWhen)
        }
    }

    #[test]
    fn reject_when_fires_for_an_api_key_only_login() {
        let dir = temp_dir("rw-apikey");
        let step = reject_when_step_for(&dir, r#"{"auth_mode":"apikey","OPENAI_API_KEY":"sk-x"}"#);
        assert_eq!(
            reject_when_step(&step),
            Err("an API key has no subscription limits".to_string())
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reject_when_stands_down_when_the_real_token_is_there() {
        // Both fields set: the OAuth token wins and the chain moves on to the
        // step that reads it, rather than the row claiming "API key".
        let dir = temp_dir("rw-both");
        let step = reject_when_step_for(
            &dir,
            r#"{"OPENAI_API_KEY":"sk-x","tokens":{"access_token":"tok-1"}}"#,
        );
        assert_eq!(reject_when_step(&step), Ok(None));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reject_when_treats_an_explicit_null_as_absent() {
        // How a ChatGPT login actually spells "no API key": the key is present
        // in the JSON, its value is null.
        let dir = temp_dir("rw-null");
        let step = reject_when_step_for(
            &dir,
            r#"{"auth_mode":"chatgpt","OPENAI_API_KEY":null,"tokens":{"access_token":"tok-1"}}"#,
        );
        assert_eq!(reject_when_step(&step), Ok(None));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reject_when_is_absent_when_the_file_is_missing_or_unreadable() {
        let dir = temp_dir("rw-missing");
        let mut step = reject_when_step_for(&dir, r#"{"OPENAI_API_KEY":"sk-x"}"#);
        step.path = Some(dir.join("no-such-file.json").to_string_lossy().into_owned());
        assert_eq!(
            reject_when_step(&step),
            Ok(None),
            "a missing file rejects nobody"
        );

        let broken = reject_when_step_for(&dir, "{not json");
        assert_eq!(
            reject_when_step(&broken),
            Ok(None),
            "a rule that cannot be evaluated must not block a credential that may follow"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reject_when_stops_the_chain_before_a_later_step_is_tried() {
        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = temp_dir("rw-chain");
        let reject = reject_when_step_for(&dir, r#"{"OPENAI_API_KEY":"sk-x"}"#);
        let never = AuthStep {
            var: Some("TICKOVER_TEST_REJECT_WHEN_UNREACHED".to_string()),
            ..auth_step(AuthType::Env)
        };
        std::env::set_var("TICKOVER_TEST_REJECT_WHEN_UNREACHED", "tok-unreached");
        let got = resolve_token(&surface(vec![reject, never]));
        std::env::remove_var("TICKOVER_TEST_REJECT_WHEN_UNREACHED");

        assert_eq!(
            got,
            Err(("an API key has no subscription limits".to_string(), None))
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── credentials-file step ─────────────────────────────────────────────

    #[test]
    fn credentials_file_step_absent_when_file_missing() {
        let dir = temp_dir("cf-absent");
        let step = AuthStep {
            path: Some(dir.join("no-such-file.json").to_string_lossy().into_owned()),
            token_json_path: Some("claudeAiOauth.accessToken|access_token".to_string()),
            ..auth_step(AuthType::CredentialsFile)
        };
        assert_eq!(credentials_file_step(&step, &mut None), Ok(None));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn credentials_file_step_present_ok_when_token_found() {
        let dir = temp_dir("cf-ok");
        let file = dir.join("creds.json");
        std::fs::write(&file, r#"{"claudeAiOauth":{"accessToken":"tok-1"}}"#).unwrap();
        let step = AuthStep {
            path: Some(file.to_string_lossy().into_owned()),
            token_json_path: Some("claudeAiOauth.accessToken|access_token".to_string()),
            ..auth_step(AuthType::CredentialsFile)
        };
        assert_eq!(
            credentials_file_step(&step, &mut None),
            Ok(Some("tok-1".to_string()))
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn credentials_file_step_present_err_when_json_broken() {
        let dir = temp_dir("cf-broken");
        let file = dir.join("creds.json");
        std::fs::write(&file, "this is not json").unwrap();
        let step = AuthStep {
            path: Some(file.to_string_lossy().into_owned()),
            token_json_path: Some("claudeAiOauth.accessToken|access_token".to_string()),
            ..auth_step(AuthType::CredentialsFile)
        };
        assert!(credentials_file_step(&step, &mut None).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn credentials_file_step_missing_required_field_is_error() {
        let step = auth_step(AuthType::CredentialsFile); // no path, no token_json_path
        assert!(credentials_file_step(&step, &mut None).is_err());
    }

    #[test]
    fn credentials_file_step_falls_through_and_marks_lapsed_when_the_token_has_expired() {
        let dir = temp_dir("cf-lapsed");
        let file = dir.join("creds.json");
        std::fs::write(
            &file,
            r#"{"claudeAiOauth":{"accessToken":"tok-old","expiresAt":"2020-01-01T00:00:00Z"}}"#,
        )
        .unwrap();
        let step = AuthStep {
            path: Some(file.to_string_lossy().into_owned()),
            token_json_path: Some("claudeAiOauth.accessToken".to_string()),
            expiry_json_path: Some("claudeAiOauth.expiresAt".to_string()),
            ..auth_step(AuthType::CredentialsFile)
        };
        let mut lapsed_expiry = None;
        assert_eq!(
            credentials_file_step(&step, &mut lapsed_expiry),
            Ok(None),
            "a lapsed credentials-file token resolves Absent, same as keychain's"
        );
        assert_eq!(
            lapsed_expiry,
            Some(1_577_836_800), // 2020-01-01T00:00:00Z
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── resolve_token: lapsed vs. no credentials at all ───────────────────

    /// A surface named a credential, and it had lapsed — a different fact
    /// than never finding one, and `resolve_token` must say which: nothing
    /// downstream can renew a token it never learned had expired.
    #[test]
    fn resolve_token_reports_lapsed_when_the_only_credential_found_had_expired() {
        let dir = temp_dir("resolve-lapsed-only");
        let file = dir.join("creds.json");
        std::fs::write(
            &file,
            r#"{"claudeAiOauth":{"accessToken":"tok-old","expiresAt":"2020-01-01T00:00:00Z"}}"#,
        )
        .unwrap();
        let step = AuthStep {
            path: Some(file.to_string_lossy().into_owned()),
            token_json_path: Some("claudeAiOauth.accessToken".to_string()),
            expiry_json_path: Some("claudeAiOauth.expiresAt".to_string()),
            ..auth_step(AuthType::CredentialsFile)
        };
        assert_eq!(
            resolve_token(&surface(vec![step])),
            Err((TOKEN_LAPSED.to_string(), Some(1_577_836_800))) // 2020-01-01T00:00:00Z
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The same lapsed step, with a working one behind it: the chain still
    /// falls through to it, exactly as it does today — `resolve_token`
    /// reporting *why* an empty chain came up empty must never change what
    /// a chain that is not empty returns.
    #[test]
    fn resolve_token_falls_through_a_lapsed_credential_to_a_later_step() {
        let dir = temp_dir("resolve-lapsed-fallthrough");
        let file = dir.join("creds.json");
        std::fs::write(
            &file,
            r#"{"claudeAiOauth":{"accessToken":"tok-old","expiresAt":"2020-01-01T00:00:00Z"}}"#,
        )
        .unwrap();
        let lapsed_step = AuthStep {
            path: Some(file.to_string_lossy().into_owned()),
            token_json_path: Some("claudeAiOauth.accessToken".to_string()),
            expiry_json_path: Some("claudeAiOauth.expiresAt".to_string()),
            ..auth_step(AuthType::CredentialsFile)
        };
        let var = format!(
            "TICKOVER_TEST_RESOLVE_LAPSED_FALLTHROUGH_{}",
            std::process::id()
        );
        let env_step = AuthStep {
            var: Some(var.clone()),
            ..auth_step(AuthType::Env)
        };
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(&var, "tok-fresh");
        let got = resolve_token(&surface(vec![lapsed_step, env_step]));
        std::env::remove_var(&var);
        assert_eq!(
            got,
            Ok(("tok-fresh".to_string(), false)),
            "the token came from the env step, which declares no expiry of its own"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The flag on a successful resolution names the *yielding* step, not
    /// any other step on the same surface: an `env` fallback behind a lapsed
    /// `credentials-file` step still answers `false`, because nothing about
    /// that fallback's own lifetime was ever declared — a `[ping]` run
    /// cannot renew an env var.
    #[test]
    fn resolve_token_reports_false_when_a_fresh_step_behind_a_lapsed_one_yields_the_token() {
        let dir = temp_dir("resolve-fresh-behind-lapsed");
        let file = dir.join("creds.json");
        std::fs::write(
            &file,
            r#"{"claudeAiOauth":{"accessToken":"tok-old","expiresAt":"2020-01-01T00:00:00Z"}}"#,
        )
        .unwrap();
        let lapsed_step = AuthStep {
            path: Some(file.to_string_lossy().into_owned()),
            token_json_path: Some("claudeAiOauth.accessToken".to_string()),
            expiry_json_path: Some("claudeAiOauth.expiresAt".to_string()),
            ..auth_step(AuthType::CredentialsFile)
        };
        let var = format!(
            "TICKOVER_TEST_RESOLVE_STEP_FLAG_FRESH_{}",
            std::process::id()
        );
        let env_step = AuthStep {
            var: Some(var.clone()),
            ..auth_step(AuthType::Env)
        };
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(&var, "tok-fresh");
        let got = resolve_token(&surface(vec![lapsed_step, env_step]));
        std::env::remove_var(&var);
        assert_eq!(got, Ok(("tok-fresh".to_string(), false)));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The same shape, but the yielding step *is* the one declaring the
    /// expiry: the flag must read `true` here, the mirror case to the one
    /// above.
    #[test]
    fn resolve_token_reports_true_when_the_expiring_step_itself_yields_the_token() {
        let dir = temp_dir("resolve-fresh-expiring-step");
        let file = dir.join("creds.json");
        // 2099-01-01T00:00:00Z — comfortably unexpired.
        std::fs::write(
            &file,
            r#"{"claudeAiOauth":{"accessToken":"tok-fresh","expiresAt":"2099-01-01T00:00:00Z"}}"#,
        )
        .unwrap();
        let step = AuthStep {
            path: Some(file.to_string_lossy().into_owned()),
            token_json_path: Some("claudeAiOauth.accessToken".to_string()),
            expiry_json_path: Some("claudeAiOauth.expiresAt".to_string()),
            ..auth_step(AuthType::CredentialsFile)
        };
        assert_eq!(
            resolve_token(&surface(vec![step])),
            Ok(("tok-fresh".to_string(), true))
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// No credential anywhere in the chain is still the plain
    /// [`NO_CREDENTIALS`] answer — the new sentinel exists for "found, but
    /// lapsed", not for every empty chain.
    #[test]
    fn resolve_token_reports_no_credentials_when_nothing_was_ever_found() {
        let dir = temp_dir("resolve-nothing");
        let step = AuthStep {
            path: Some(dir.join("absent.json").to_string_lossy().into_owned()),
            token_json_path: Some("claudeAiOauth.accessToken".to_string()),
            ..auth_step(AuthType::CredentialsFile)
        };
        assert_eq!(
            resolve_token(&surface(vec![step])),
            Err((NO_CREDENTIALS.to_string(), None))
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── credentials-map step ──────────────────────────────────────────────

    fn credentials_map_step_for(dir: &std::path::Path, body: &str) -> AuthStep {
        let file = dir.join("auth.json");
        std::fs::write(&file, body).unwrap();
        AuthStep {
            path: Some(file.to_string_lossy().into_owned()),
            key_prefix: Some("https://auth.x.ai::".to_string()),
            token_json_path: Some("key".to_string()),
            ..auth_step(AuthType::CredentialsMap)
        }
    }

    #[test]
    fn credentials_map_step_absent_when_file_missing() {
        let dir = temp_dir("cm-absent");
        let mut step = credentials_map_step_for(&dir, "{}");
        step.path = Some(dir.join("no-such-file.json").to_string_lossy().into_owned());
        assert_eq!(credentials_map_step(&step), Ok(None));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn credentials_map_step_present_ok_when_exactly_one_entry_matches_the_prefix() {
        let dir = temp_dir("cm-ok");
        let step = credentials_map_step_for(
            &dir,
            r#"{"https://auth.x.ai::11111111-1111-1111-1111-111111111111":{"key":"tok-grok"}}"#,
        );
        assert_eq!(
            credentials_map_step(&step),
            Ok(Some("tok-grok".to_string()))
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn credentials_map_step_present_err_when_no_entry_matches_the_prefix() {
        let dir = temp_dir("cm-no-match");
        let step =
            credentials_map_step_for(&dir, r#"{"https://other.example::abc":{"key":"tok"}}"#);
        let err = credentials_map_step(&step)
            .expect_err("a store that exists but names no matching entry must not be Absent");
        assert!(err.contains("https://auth.x.ai::"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn credentials_map_step_present_err_when_more_than_one_entry_matches_the_prefix() {
        // The regression this step exists to guard against: picking between
        // two accounts by map order would send the wrong one's token.
        let dir = temp_dir("cm-ambiguous");
        let step = credentials_map_step_for(
            &dir,
            r#"{
                "https://auth.x.ai::11111111-1111-1111-1111-111111111111": {"key": "tok-a"},
                "https://auth.x.ai::22222222-2222-2222-2222-222222222222": {"key": "tok-b"}
            }"#,
        );
        let err = credentials_map_step(&step).expect_err("ambiguous match must be a Present-err");
        assert!(err.contains("more than one"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn credentials_map_step_present_err_when_root_is_not_an_object() {
        let dir = temp_dir("cm-not-object");
        let step = credentials_map_step_for(&dir, r#"["not", "an", "object"]"#);
        assert!(credentials_map_step(&step).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn credentials_map_step_present_err_when_json_broken() {
        let dir = temp_dir("cm-broken");
        let step = credentials_map_step_for(&dir, "not json");
        assert!(credentials_map_step(&step).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn credentials_map_step_present_err_when_matched_entry_has_no_token() {
        let dir = temp_dir("cm-no-token");
        let step = credentials_map_step_for(
            &dir,
            r#"{"https://auth.x.ai::11111111-1111-1111-1111-111111111111":{"other":"x"}}"#,
        );
        let err = credentials_map_step(&step)
            .expect_err("a matched entry without the token field is Present-err");
        assert!(err.contains('`'), "{err}"); // names the token_json_path
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn credentials_map_step_missing_required_field_is_error() {
        let step = auth_step(AuthType::CredentialsMap); // no path, no key_prefix, no token_json_path
        assert!(credentials_map_step(&step).is_err());
    }

    // ── electron-safe-storage step (up to, but not touching, the Keychain) ─

    #[test]
    fn electron_step_absent_when_config_missing() {
        let dir = temp_dir("es-absent");
        let step = AuthStep {
            config_path: Some(dir.join("config.json").to_string_lossy().into_owned()),
            blob_json_path: Some("oauth:tokenCacheV2|oauth:tokenCache".to_string()),
            macos_keychain_key: Some("Claude Safe Storage".to_string()),
            ..auth_step(AuthType::ElectronSafeStorage)
        };
        assert_eq!(electron_safe_storage_step(&step), Ok(None));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn electron_step_absent_when_blob_key_missing() {
        let dir = temp_dir("es-no-blob");
        let file = dir.join("config.json");
        std::fs::write(&file, r#"{"unrelated":true}"#).unwrap();
        let step = AuthStep {
            config_path: Some(file.to_string_lossy().into_owned()),
            blob_json_path: Some("oauth:tokenCacheV2|oauth:tokenCache".to_string()),
            macos_keychain_key: Some("Claude Safe Storage".to_string()),
            ..auth_step(AuthType::ElectronSafeStorage)
        };
        assert_eq!(electron_safe_storage_step(&step), Ok(None));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn electron_step_present_err_on_bad_base64() {
        let dir = temp_dir("es-bad-b64");
        let file = dir.join("config.json");
        std::fs::write(&file, r#"{"oauth:tokenCacheV2":"not-base64!!"}"#).unwrap();
        let step = AuthStep {
            config_path: Some(file.to_string_lossy().into_owned()),
            blob_json_path: Some("oauth:tokenCacheV2|oauth:tokenCache".to_string()),
            macos_keychain_key: Some("Claude Safe Storage".to_string()),
            ..auth_step(AuthType::ElectronSafeStorage)
        };
        assert!(electron_safe_storage_step(&step).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn electron_step_missing_required_field_is_error() {
        let step = auth_step(AuthType::ElectronSafeStorage); // no config_path, no blob_json_path
        assert!(electron_safe_storage_step(&step).is_err());
    }

    // ── env step ──────────────────────────────────────────────────────────

    #[test]
    fn env_step_present_when_var_set() {
        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("TICKOVER_AUTH_TEST_ENV_1", "tok-env");
        let step = AuthStep {
            var: Some("TICKOVER_AUTH_TEST_ENV_1".to_string()),
            ..auth_step(AuthType::Env)
        };
        assert_eq!(env_step(&step), Ok(Some("tok-env".to_string())));
        std::env::remove_var("TICKOVER_AUTH_TEST_ENV_1");
    }

    #[test]
    fn env_step_absent_when_var_unset() {
        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("TICKOVER_AUTH_TEST_ENV_UNSET");
        let step = AuthStep {
            var: Some("TICKOVER_AUTH_TEST_ENV_UNSET".to_string()),
            ..auth_step(AuthType::Env)
        };
        assert_eq!(env_step(&step), Ok(None));
    }

    #[test]
    fn env_step_absent_when_var_set_but_blank() {
        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Set, not unset — exported as whitespace, the shell-script
        // equivalent of "export FOO=" — and must still resolve Absent, the
        // same way an unset var does, rather than a present token of "".
        std::env::set_var("TICKOVER_AUTH_TEST_ENV_BLANK", "   ");
        let step = AuthStep {
            var: Some("TICKOVER_AUTH_TEST_ENV_BLANK".to_string()),
            ..auth_step(AuthType::Env)
        };
        assert_eq!(env_step(&step), Ok(None));
        std::env::remove_var("TICKOVER_AUTH_TEST_ENV_BLANK");
    }

    // ── chain semantics ───────────────────────────────────────────────────

    #[test]
    fn chain_stops_at_first_present_err_and_does_not_try_later_steps() {
        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = temp_dir("chain-stop");
        let broken = dir.join("broken.json");
        std::fs::write(&broken, "not json").unwrap();

        std::env::set_var("TICKOVER_AUTH_TEST_CHAIN_STOP", "tok-from-env-must-not-win");
        let s = surface(vec![
            AuthStep {
                path: Some(broken.to_string_lossy().into_owned()),
                token_json_path: Some("claudeAiOauth.accessToken|access_token".to_string()),
                ..auth_step(AuthType::CredentialsFile)
            },
            AuthStep {
                var: Some("TICKOVER_AUTH_TEST_CHAIN_STOP".to_string()),
                ..auth_step(AuthType::Env)
            },
        ]);

        let (err, lapsed_expiry) =
            resolve_token(&s).expect_err("broken file must stop the chain, not fall through");
        assert!(!err.contains("tok-from-env-must-not-win"));
        assert_eq!(
            lapsed_expiry, None,
            "a Present-err message never carries a lapsed expiry"
        );

        std::env::remove_var("TICKOVER_AUTH_TEST_CHAIN_STOP");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn chain_skips_absent_steps_and_succeeds_on_next() {
        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = temp_dir("chain-skip");
        std::env::set_var("TICKOVER_AUTH_TEST_CHAIN_SKIP", "tok-from-env");
        let s = surface(vec![
            AuthStep {
                path: Some(
                    dir.join("does-not-exist.json")
                        .to_string_lossy()
                        .into_owned(),
                ),
                token_json_path: Some("claudeAiOauth.accessToken|access_token".to_string()),
                ..auth_step(AuthType::CredentialsFile)
            },
            AuthStep {
                var: Some("TICKOVER_AUTH_TEST_CHAIN_SKIP".to_string()),
                ..auth_step(AuthType::Env)
            },
        ]);

        assert_eq!(resolve_token(&s), Ok(("tok-from-env".to_string(), false)));

        std::env::remove_var("TICKOVER_AUTH_TEST_CHAIN_SKIP");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn chain_all_absent_is_no_credentials_found_error() {
        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = temp_dir("chain-all-absent");
        std::env::remove_var("TICKOVER_AUTH_TEST_CHAIN_ALL_ABSENT");
        let s = surface(vec![
            AuthStep {
                path: Some(
                    dir.join("does-not-exist.json")
                        .to_string_lossy()
                        .into_owned(),
                ),
                token_json_path: Some("claudeAiOauth.accessToken|access_token".to_string()),
                ..auth_step(AuthType::CredentialsFile)
            },
            AuthStep {
                var: Some("TICKOVER_AUTH_TEST_CHAIN_ALL_ABSENT".to_string()),
                ..auth_step(AuthType::Env)
            },
        ]);

        assert_eq!(
            resolve_token(&s),
            Err(("no credentials found".to_string(), None))
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn chain_with_no_auth_steps_is_an_error() {
        let s = surface(Vec::new());
        assert_eq!(
            resolve_token(&s),
            Err(("no credentials found".to_string(), None))
        );
    }

    // ── host_allowed ──────────────────────────────────────────────────────

    #[test]
    fn host_allowed_empty_list_allows_any_host() {
        assert!(host_allowed(&[], "https://anything.example.com/path"));
    }

    #[test]
    fn host_allowed_matches_exact_host_ignoring_scheme_port_and_path() {
        let allowed = vec!["api.anthropic.com".to_string()];
        assert!(host_allowed(
            &allowed,
            "https://api.anthropic.com/api/oauth/usage"
        ));
        assert!(host_allowed(&allowed, "https://api.anthropic.com:443/x"));
        assert!(
            host_allowed(&allowed, "https://API.ANTHROPIC.COM/x"),
            "case-insensitive"
        );
    }

    #[test]
    fn host_allowed_rejects_different_host() {
        let allowed = vec!["api.anthropic.com".to_string()];
        assert!(!host_allowed(&allowed, "https://evil.example.com/steal"));
    }

    #[test]
    fn host_allowed_rejects_subdomain_of_an_allowed_host() {
        let allowed = vec!["anthropic.com".to_string()];
        assert!(
            !host_allowed(&allowed, "https://evil.anthropic.com/x"),
            "a subdomain must not match its parent domain"
        );
    }

    #[test]
    fn host_allowed_accepts_userinfo_ahead_of_the_real_host() {
        let allowed = vec!["api.anthropic.com".to_string()];
        assert!(host_allowed(
            &allowed,
            "https://user:pass@api.anthropic.com/x"
        ));
    }

    #[test]
    fn host_allowed_rejects_the_backslash_authority_terminator_attack() {
        // `\` ends an authority in a WHATWG special scheme (`https` is one)
        // exactly as `/` does — a hand-rolled split on `/`, `?`, `#` and `@`
        // never looked for it, and would read this URL's host as
        // `api.anthropic.com` instead of the `evil.example` it actually is.
        let allowed = vec!["api.anthropic.com".to_string()];
        assert!(!host_allowed(
            &allowed,
            "https://evil.example\\@api.anthropic.com/api/oauth/usage"
        ));
    }

    #[test]
    fn host_allowed_rejects_a_plaintext_url() {
        let allowed = vec!["api.anthropic.com".to_string()];
        assert!(!host_allowed(&allowed, "http://api.anthropic.com/x"));
    }

    #[test]
    fn host_allowed_handles_a_bracketed_ipv6_literal_without_panicking() {
        let allowed = vec!["[::1]".to_string()];
        assert!(host_allowed(&allowed, "https://[::1]/x"));
    }
}
