//! Generic HTTP-API usage engine (`engine = "http-api"`).
//!
//! For each active `[[surface]]` (an account this provider's usage can be
//! read from — the Claude Code CLI, the Claude desktop app, …) it resolves a
//! bearer token via [`crate::plugin::auth`], calls the provider's
//! `[[http.request]]` endpoint, and turns the JSON response into a
//! [`ProviderReading`] using `[[windows]]`. One generic engine plus a
//! provider's own manifest (`plugins/claude.toml`, say) is what reads that
//! provider's usage — no per-provider Rust module needed.
//!
//! Two things this engine has to do that a single hardcoded surface would
//! not:
//!
//! * **Multiple surfaces, filtered by the caller.** Whether to include an
//!   opt-in account (the desktop app, say) is the caller's decision
//!   (`active_surface_ids`) — this engine just iterates `m.surface` in
//!   manifest order and fetches exactly the ones asked for, one
//!   [`ProviderReading`] each.
//! * **`allowed_hosts` enforcement.** A manifest is data a user (or a
//!   third-party plugin) can edit; before a surface's token is ever attached
//!   to a request, the target host is checked against that surface's
//!   `allowed_hosts` (see [`crate::plugin::auth::host_allowed`]). This guards a
//!   *trusted* manifest against its own mistakes (a typo'd URL, an open
//!   redirect on the declared host) — it is **not** a sandbox against a hostile
//!   author, who supplies both the URL and the allow-list. A blocked host is a
//!   normal `reading.error`, and the request is never attempted. The host is
//!   read by [`crate::plugin::https_host`] — the same parser `ureq` sends the
//!   request through — and [`perform`] refuses anything that isn't `https`
//!   outright, before either check runs. The allow-list check only ever looks
//!   at the request's own URL, so [`perform`] also disables HTTP redirects
//!   (`redirects(0)`) — otherwise a 3xx on a permitted host could hand the
//!   token to an unlisted host the allowlist check never saw. See
//!   `docs/PLUGIN-ARCHITECTURE.md` (Trust model) for the full picture.
//!
//! [`fetch`] is the engine's public entry point. Everything else here is
//! split into small, hermetic, network-free functions ([`build_request`],
//! [`parse_usage`], [`resolve_version`], [`json_path_get`], …) with
//! [`perform`] the only piece that touches the network — mirroring the
//! `crate::plugin::engine_logfile` split between file/JSON parsing and I/O.

use std::collections::{BTreeMap, HashMap};
use std::io::Read as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::model::{ProviderReading, TokenRenewal, Window};
use crate::plugin::auth;
use crate::plugin::manifest::{
    AccountType, AmountConfig, AmountKind, BalanceConfig, HttpMethod, HttpRequestConfig,
    HttpValueConfig, HttpValueType, HttpVersionConfig, PeriodMode, PingConfig, PluginManifest,
    SurfaceConfig, TagFrom, TagTransform, WindowConfig,
};
use crate::plugin::throttle;

/// The reading error for HTTP 401 — a token this engine may not renew (see
/// the comment on [`perform`]'s 401 match arm for why no provider's refresh
/// token is ever spent here), so the only way out is the user signing in
/// again. Named because [`crate::plugin::throttle`] recognises it as the one
/// failure retrying cannot fix.
pub const UNAUTHORIZED: &str = "session expired — sign in again";

// ── Public entry point ───────────────────────────────────────────────────

/// Read usage for every surface named in `active_surface_ids`, in the order
/// they appear in `m.surface` (not the order `active_surface_ids` lists
/// them). The caller decides which surfaces are active — e.g. gating the
/// Claude desktop account behind a user opt-in — this engine only fetches,
/// never decides.
///
/// `options` is the plugin's declared `[[option]]` set resolved to its
/// current value (`crate::config::plugin_option`, read by the caller —
/// this engine is hermetic and never reads config itself); it drives the
/// `{option.<key>}` substitution in request headers/URL (see
/// [`build_request`]).
pub fn fetch(
    m: &PluginManifest,
    active_surface_ids: &[String],
    options: &BTreeMap<String, bool>,
) -> Vec<ProviderReading> {
    m.surface
        .iter()
        .filter(|s| active_surface_ids.iter().any(|id| id == &s.id))
        .map(|s| fetch_surface(m, s, options))
        .collect()
}

/// Read usage for a single surface. Always returns exactly one
/// [`ProviderReading`], even on failure — a surface that can't be read still
/// needs a row in the popup carrying its error message.
fn fetch_surface(
    m: &PluginManifest,
    surface: &SurfaceConfig,
    options: &BTreeMap<String, bool>,
) -> ProviderReading {
    let mut reading = ProviderReading {
        id: surface_reading_id(m, surface),
        name: m.name.clone(),
        short: m.menu_label.clone(),
        // Resolved without a response body when possible (surface label,
        // `[tag] from = "static"/"none"`); filled in from the JSON response
        // below only for `from = "field"` — see `resolve_tag`.
        tag: resolve_tag(m, surface, None),
        account: None,
        windows: Vec::new(),
        quota_status: None,
        balances: Vec::new(),
        error: None,
        token_renewal: TokenRenewal::No,
        in_menu_bar: surface.in_menu_bar,
        bare_when_sole: false,
    };

    let (token, from_expiring_step) = match auth::resolve_token(surface) {
        Ok(t) => t,
        Err((e, lapsed_expiry)) => {
            // A chain that ended "lapsed" (`lapsed_expiry` is `Some` — see
            // `auth::TOKEN_LAPSED`) is a token this app cannot renew on its
            // own — unless the manifest names a ping that can, as a side
            // effect of running (`[ping] renews_token`). Checked before the
            // `NO_CREDENTIALS` rewrite below, which is exactly where a
            // plugin *without* such a ping still ends up: to it, "found but
            // lapsed" and "never found" read as the same fact.
            //
            // Needs no explicit `declares_token_expiry` check of its own:
            // `lapsed_expiry` can only be `Some` here because some step on
            // *this* surface both found a token at its `token_json_path`
            // *and* saw that token's own declared expiry in the past (see
            // `auth::token_from_blob` — the expiry is checked only once a
            // token is actually in hand, never on a blob a step never
            // recognised as a credential at all). A step whose expiry is
            // stale but whose token was never found produces
            // `NO_CREDENTIALS` below instead, not this arm. So `Some` here
            // already implies exactly what `SurfaceConfig::
            // declares_token_expiry` asks (some step on this surface set
            // `expiry_json_path`) — this surface is scoped by the same rule
            // `unauthorized_outcome` below applies explicitly, not by
            // accident.
            if let Some(expires_at) = lapsed_expiry {
                if let Some(ping) = m.ping.as_ref().filter(|p| p.renews_token) {
                    reading.token_renewal = TokenRenewal::Lapsed { expires_at };
                    reading.fail(renewal_text(&ping.bin));
                    return reading;
                }
            }
            // "No credential store here at all" is the one error a surface may
            // rename: for most providers it means "not installed", and the row
            // is hidden on the strength of this exact string; for one that is
            // worth naming in that state, the manifest supplies the sentence.
            // A lapsed credential without a renewing ping folds back into
            // `NO_CREDENTIALS` here: a manifest with no `[ping] renews_token`
            // gets the same hide-the-row/custom-message treatment for a
            // lapsed credential as for no credential at all, not a second,
            // unrecognised string. `lapsed_expiry` is `Some` only alongside
            // `auth::TOKEN_LAPSED` (see `resolve_token`'s own doc) — a real
            // (Present-err) failure always pairs `None`, so this never
            // rewrites a genuine broken-store message.
            let e = if lapsed_expiry.is_some() {
                auth::NO_CREDENTIALS.to_string()
            } else {
                e
            };
            reading.fail(
                match (e == auth::NO_CREDENTIALS, &surface.no_credentials_message) {
                    (true, Some(message)) => message.clone(),
                    _ => e,
                },
            );
            return reading;
        }
    };

    let Some(http) = m.http.as_ref() else {
        reading.fail("http-api engine invoked without an [http] section".to_string());
        return reading;
    };
    let Some(req) = http.request.first() else {
        reading.fail("[http] section has no [[http.request]] entries".to_string());
        return reading;
    };

    // The URL needs only `{option.<key>}` substitution (`{token}`/`{version}`
    // never reach it — see `build_request`'s docs), so it costs nothing to
    // resolve ahead of everything below. Checking `allowed_hosts` here, before
    // `resolve_version`/`resolve_values` do any file I/O, means a blocked host
    // is refused without either of those ever running.
    let url = crate::plugin::substitute_options(&req.url, options);
    if !auth::host_allowed(&surface.allowed_hosts, &url) {
        // Defence in depth: never let a surface's token reach a host the
        // manifest didn't explicitly allow — no request of any kind for this
        // surface, including the account/profile lookup below.
        reading.fail(format!("blocked by allowed_hosts: {url}"));
        return reading;
    }

    // Header values a request can't be built without ({value.<name>}): a
    // request sent with an unresolved placeholder would be answered — wrongly,
    // or with a 4xx that reads like an auth failure — so it is never sent.
    // Resolved here, ahead of `resolve_version`, because the throttle
    // fingerprint below needs it — `{version}` never enters a fingerprint, so
    // reading it can wait until there is actually a request to make.
    let values = match resolve_values(&http.value) {
        Ok(v) => v,
        Err(e) => {
            reading.fail(e);
            return reading;
        }
    };

    // How often this surface may be asked at all — see `crate::plugin::throttle`.
    // The gate sits ahead of *every* request this function makes, the
    // account/profile lookup included, and it is keyed on the credentials so
    // signing in as somebody else is never answered from the previous
    // account's cache. Everything above this point is either free (the URL
    // substitution) or needed to compute the fingerprint itself (`values`);
    // everything below is real work — a file read for `{version}`, a network
    // request — that a `Serve`/`Blocked` decision means this tick never has
    // to pay for.
    let throttle_key = throttle::key(&m.id, &surface.id);
    let fingerprint = throttle::fingerprint(&token, &values);
    let limits = throttle::Limits::from_http(http);
    let now = Instant::now();
    match throttle::decide(&throttle_key, fingerprint, limits, now) {
        throttle::Decision::Fetch => {}
        throttle::Decision::Serve(cached) => return *cached,
        throttle::Decision::Blocked(message) => {
            reading.fail(message);
            return reading;
        }
    }

    let version = http
        .version
        .as_ref()
        .map(resolve_version)
        .unwrap_or_default();
    let (url, headers, timeout) = build_request(req, &token, &version, options, &values);
    // Same substitution set as a header value, kept out of `build_request`
    // itself so that function's existing signature (and the tests pinned to
    // it) stay exactly as they were — a request's body is one more
    // substituted string, not a reason to reshape what already works.
    let body = build_body(req, &token, &version, options, &values);

    // After substitution, never before: `{token}`/`{value.<name>}` are a live
    // credential's own bytes, not something `validate` can check at load
    // time. A violation here is refused by name only — see this function's
    // doc and `perform`'s BadHeader arm for why the value itself must never
    // reach a message this app writes anywhere.
    if let Err(e) = refuse_unsafe_header_values(&headers) {
        reading.fail(e);
        return reading;
    }

    // Account/profile lookup is a separate request to a different endpoint
    // than the main usage fetch; it is best-effort and its failures never
    // become `reading.error` — the result is a plain `Option`, not a
    // `Result`, silently `None` on any failure. `type = "response-field"`
    // needs no request at all: the email is in the usage body, read below
    // once it arrives.
    //
    // The address behind a second endpoint (Claude's profile) is asked for
    // once per set of credentials, not once a minute: it cannot change without
    // the credentials changing, and that empties this cache on its own. Before
    // this, a provider with `[account] type = "http"` quietly made two
    // requests per refresh — and a profile lookup that failed was swallowed
    // whole, so it never even reached the pacing that would have slowed it.
    reading.account = throttle::remembered_account(&throttle_key, fingerprint).or_else(|| {
        let ctx = RequestContext {
            token: &token,
            version: &version,
            options,
            values: &values,
        };
        resolve_account(m, surface, req, ctx, limits.min_interval)
    });

    match perform(&url, req.method, body.as_deref(), &headers, timeout) {
        Ok(value) => {
            if reading.tag.is_none() {
                reading.tag = resolve_tag(m, surface, Some(&value));
            }
            if reading.account.is_none() {
                reading.account = resolve_account_from_response(m, &value);
            }
            match parse_usage(&value, m) {
                Ok(windows) => {
                    reading.windows = windows;
                    // Inside the `Ok` arm deliberately: a `required` window
                    // that did not arrive means the manifest's author declared
                    // the whole response untrustworthy, and a balance parsed
                    // out of an untrustworthy response is untrustworthy too.
                    // `fail()` clears all three together.
                    reading.balances = parse_balances(&value, m);
                    // Read after the windows and kept independently of them:
                    // the case this exists for is a quota that arrives blocked
                    // with no window at all, where `windows` is legitimately
                    // empty and the status is the only thing the provider said.
                    reading.quota_status = parse_quota(&value, m);
                }
                Err(message) => reading.fail(message),
            }
            // Cached even when the body carried no window: the provider did
            // answer, and asking it again a second later would get the same
            // answer. What it costs is one stale minute after the quota
            // starts reporting again; what it saves is a request per panel
            // open, forever.
            throttle::record_success(
                &throttle_key,
                fingerprint,
                reading.clone(),
                reading.account.clone(),
            );
        }
        Err(failure) => {
            // A 401 is the one `Failure` this app ever rewrites — see
            // `unauthorized_outcome`'s own doc for why. `failure.terminal`
            // itself is untouched by the rewrite and used as `perform` set
            // it, just below. `fingerprint` is reused as the renewal key
            // rather than hashing anything new — it is already a hash of
            // `(token, values)`, already documented as never persisted or
            // logged (see `throttle::fingerprint`), and exactly what a "same
            // token, don't ping again" dedup needs. `from_expiring_step`
            // came back from `auth::resolve_token` above, alongside `token`
            // itself — it names the one step that actually produced *this*
            // token, not merely some step on this surface (that broader
            // question, `surface.declares_token_expiry()`, is main.rs's tick
            // scan's to ask, not this rewrite's).
            let (message, token_renewal) = unauthorized_outcome(
                failure.message,
                m.ping.as_ref(),
                from_expiring_step,
                fingerprint,
            );
            // Measured from when the request *finished*, not from when it was
            // sent: a request that spent ten seconds timing out has already
            // eaten ten seconds of any cool-off started at `now`.
            throttle::record_failure(
                &throttle_key,
                fingerprint,
                &message,
                failure.terminal,
                limits,
                Instant::now(),
            );
            reading.token_renewal = token_renewal;
            reading.fail(message);
        }
    }
    reading
}

/// The text an engine hands back when a surface's credential has lapsed (or
/// just 401'd) and the manifest's own `[ping]` can renew it — used for both
/// the pre-request "lapsed, no later auth step" case ([`fetch_surface`]'s
/// `auth::resolve_token` arm) and an HTTP 401 ([`unauthorized_outcome`]), so
/// the two read identically to whoever is watching
/// [`crate::model::ProviderReading::token_renewal`] for the signal. `bin` is
/// `ping.bin` exactly as the manifest wrote it.
fn renewal_text(bin: &str) -> String {
    format!("token expired — renews on the next {bin} run")
}

/// The message and renewal signal [`fetch_surface`] hands back for a
/// `perform` failure — pure, so the rewrite is tested without a network
/// call. `UNAUTHORIZED` is `perform`'s own text for a 401 for every
/// provider (it stays provider-neutral — it has no manifest to name a ping
/// with); a manifest whose `[ping] renews_token` names one, when
/// `from_expiring_step` is true, turns that same dead end into
/// [`renewal_text`] and [`TokenRenewal::Unauthorized`] instead, since this
/// app never spends a provider's refresh token — the run is `main.rs`'s to
/// make, not this engine's.
///
/// `from_expiring_step` is `auth::resolve_token`'s own answer to "did the
/// *step that produced this token* declare `expiry_json_path`?" — not
/// `SurfaceConfig::declares_token_expiry`'s broader "does *some* step on
/// this surface?" (that question is for main.rs's tick scan, gating which
/// surfaces are consulted at all; this one gates the rewrite itself). The
/// two disagree exactly when a surface's chain mixes step kinds: a two-step
/// `cli` surface whose `credentials-file` step declares an expiry but whose
/// `env` fallback does not can still 401 on a token that came from the
/// `env` step — a token `[ping]`'s CLI run cannot renew, since nothing
/// about that env var's own lifetime was ever declared. Rewriting that 401
/// would be false in exactly the way a non-renewable *surface*'s 401 would
/// be (Claude's `desktop`, its own separate credential): the ping's binary
/// would not touch the credential that actually 401'd.
///
/// Unlike a lapsed auth chain, a 401 carries no declared expiry to key a
/// "once per token" ping on — nothing here ever parsed a credential's own
/// JSON to get one — so it is keyed on the token itself instead:
/// `token_hash` is `throttle::fingerprint`'s hash of `(token, values)`,
/// reused rather than recomputed, never the token itself and never
/// persisted (see `TokenRenewal::Unauthorized`'s own doc for the dedup this
/// enables in `main.rs`). Any other failure (`terminal` or not) passes
/// through unchanged, [`TokenRenewal::No`] — a 429, a timeout, or a changed
/// API shape names nothing a ping can fix. `terminal` (whether `perform`
/// marked this failure retrying cannot fix) is untouched by this rewrite
/// either way — that decision belongs to `perform`'s own status-code match,
/// not to whether a ping happens to exist for it.
fn unauthorized_outcome(
    message: String,
    ping: Option<&PingConfig>,
    from_expiring_step: bool,
    token_hash: u64,
) -> (String, TokenRenewal) {
    match ping.filter(|p| p.renews_token && from_expiring_step) {
        Some(ping) if message == UNAUTHORIZED => (
            renewal_text(&ping.bin),
            TokenRenewal::Unauthorized { token_hash },
        ),
        _ => (message, TokenRenewal::No),
    }
}

/// A surface's `[[surface]]` entry named `"default"` (the single one
/// `PluginManifest::apply_defaults` synthesizes for a manifest that omits
/// `[[surface]]` entirely) reads under the plugin's own id; any other,
/// explicitly-named surface reads under `"{id}-{surface}"` — e.g. Claude's
/// `"cli"`/`"desktop"` surfaces become `"claude-cli"`/`"claude-desktop"`.
fn surface_reading_id(m: &PluginManifest, surface: &SurfaceConfig) -> String {
    if surface.id == "default" {
        m.id.clone()
    } else {
        format!("{}-{}", m.id, surface.id)
    }
}

// ── Tag / account (manifest-driven) ──────────────────────────────────────

/// Whether the manifest declares its own `[[surface]]` entries, as opposed to
/// relying on the single `"default"` surface `PluginManifest::apply_defaults`
/// synthesizes for a manifest that omits `[[surface]]` entirely (see its
/// module docs). Drives the tag precedence in [`resolve_tag`].
fn has_explicit_surfaces(m: &PluginManifest) -> bool {
    !(m.surface.len() == 1 && m.surface[0].id == "default")
}

/// `[tag]` resolution, with one addition over
/// `engine_logfile::resolve_tag`: when the manifest declares explicit
/// `[[surface]]` entries, the surface's own label always wins — this is what
/// makes claude.toml's CLI/Desktop surfaces show "CLI"/"Desktop" chips, with
/// no `[tag]` section needed at all. Otherwise falls back to the `[tag]`
/// config: `"static"`
/// (`tag.value` verbatim), `"field"` (`tag.path` read out of `value` — the
/// usage response body — hence `None` until a response is available), or
/// `"none"` (no tag).
fn resolve_tag(
    m: &PluginManifest,
    surface: &SurfaceConfig,
    value: Option<&Value>,
) -> Option<String> {
    if has_explicit_surfaces(m) {
        return Some(surface.label.clone());
    }
    let raw = match m.tag.from {
        TagFrom::Static => m.tag.value.clone(),
        // The manifest names the field, but the *value* in it is the
        // provider's own answer (Codex's `plan_type`, live) — sanitised like
        // any other response-supplied text before it reaches the tag chip.
        TagFrom::Field => {
            let path = m.tag.path.as_deref()?;
            json_path_get(value?, path)?
                .as_str()
                .map(crate::plugin::sanitize_provider_text)
                .filter(|s| !s.is_empty())
        }
        TagFrom::None => None,
    }?;
    Some(match m.tag.transform {
        TagTransform::None => raw,
        TagTransform::Uppercase => raw.to_uppercase(),
    })
}

/// The four values every header substitution needs, bundled only so
/// [`resolve_account`] doesn't have to take them as four separate arguments
/// on top of everything else it needs — see its own doc.
struct RequestContext<'a> {
    token: &'a str,
    version: &'a str,
    options: &'a BTreeMap<String, bool>,
    values: &'a BTreeMap<String, String>,
}

/// `[account]` resolution for `type = "http"`: GET `account.url` with the
/// same headers/token as the main `[[http.request]]` entry, then read
/// `account.json_path` out of the JSON body. Best-effort: a missing URL, a
/// blocked host, a network error or a missing field all quietly resolve to
/// `None` — a broken profile lookup must never turn into a `reading.error`
/// (see `fetch_surface`'s docs).
///
/// Always a GET, whatever `req.method` is: a profile lookup is a read
/// against a *different* endpoint than the main request, not a repeat of it,
/// and no provider's account/profile endpoint has needed anything else.
///
/// `min_interval` (the surface's own `http.min_interval_secs`) paces this
/// endpoint's *failures* apart from the main request's own pacing: before
/// this, a profile lookup that started failing was retried with the token on
/// every single fetch of the main usage endpoint, however that one was
/// paced, because a `None` here has always been silent and free-looking to
/// its caller. [`account_lookup_recently_failed`] holds it back instead,
/// keyed the same way the main request's throttle state is (`m.id` +
/// `surface.id`, a *different* map — this is not that pacing, only the same
/// key shape).
///
/// `ctx` bundles the four values a header substitution needs
/// (`token`/`version`/`options`/`values`) — for this function's own argument
/// count only. `build_request`/`build_body`/`substitute_headers` keep taking
/// them separately, unbundled here right before the one call that needs
/// them, so their signatures (and the tests pinned to them) stay exactly as
/// they were.
fn resolve_account(
    m: &PluginManifest,
    surface: &SurfaceConfig,
    req: &HttpRequestConfig,
    ctx: RequestContext<'_>,
    min_interval: Duration,
) -> Option<String> {
    let url = resolve_account_url(m, surface, ctx.options)?;
    let json_path = m.account.json_path.as_deref()?;
    let key = throttle::key(&m.id, &surface.id);
    let now = Instant::now();
    if account_lookup_recently_failed(&key, min_interval, now) {
        return None;
    }
    let headers = substitute_headers(
        &req.headers,
        ctx.token,
        ctx.version,
        ctx.options,
        ctx.values,
    );
    if refuse_unsafe_header_values(&headers).is_err() {
        return None;
    }
    let timeout = Duration::from_secs(req.timeout_secs);
    match perform(&url, HttpMethod::Get, None, &headers, timeout) {
        Ok(value) => {
            record_account_lookup_success(&key);
            sanitized_account(json_path_get(&value, json_path)?.as_str()?)
        }
        Err(_) => {
            record_account_lookup_failure(&key, now);
            None
        }
    }
}

/// How long a failing `[account] type = "http"` profile lookup goes unretried
/// once it has failed, keyed per surface. A separate map from
/// `crate::plugin::throttle`'s own `STATES` on purpose: that one paces (and
/// caches the outcome of) the *main* usage request, and a profile endpoint
/// going down must not stop or slow that request in any way, nor should a
/// slow main endpoint's own backoff pace a profile lookup that is answering
/// fine.
static ACCOUNT_LOOKUP_FAILED_AT: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);

/// Whether `key`'s profile lookup failed within the last `min_interval`, and
/// so should not be attempted again yet.
fn account_lookup_recently_failed(key: &str, min_interval: Duration, now: Instant) -> bool {
    ACCOUNT_LOOKUP_FAILED_AT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|m| m.get(key).copied())
        .is_some_and(|last| now.saturating_duration_since(last) < min_interval)
}

fn record_account_lookup_failure(key: &str, now: Instant) {
    ACCOUNT_LOOKUP_FAILED_AT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashMap::new)
        .insert(key.to_string(), now);
}

/// Clears a previously recorded failure: the endpoint just answered, so the
/// next attempt should be tried on its own terms rather than inheriting a
/// cool-off from before it recovered.
fn record_account_lookup_success(key: &str) {
    if let Some(map) = ACCOUNT_LOOKUP_FAILED_AT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()
    {
        map.remove(key);
    }
}

/// `[account]` resolution for `type = "response-field"` — the email is
/// already in the usage response, so it costs no request at all. Codex's
/// `/wham/usage` returns `email`, `account_id` and `plan_type` next to the
/// windows; asking a second endpoint for what the first one just said would
/// double this provider's request count for nothing.
fn resolve_account_from_response(m: &PluginManifest, value: &Value) -> Option<String> {
    if m.account.kind != AccountType::ResponseField {
        return None;
    }
    let json_path = m.account.json_path.as_deref()?;
    sanitized_account(json_path_get(value, json_path)?.as_str()?)
}

/// An `[account]` field, whichever of the two routes above produced it,
/// reduced to what the panel is allowed to show: sanitised the way any other
/// provider-supplied string is ([`crate::plugin::sanitize_provider_text`]) and
/// rejected outright if that leaves nothing — an address is either a real
/// address or it is no account at all, never a blank row in the picker. One
/// helper so the http-type and response-field-type paths can't quietly grow
/// two different ideas of what counts as blank.
fn sanitized_account(raw: &str) -> Option<String> {
    let s = crate::plugin::sanitize_provider_text(raw);
    (!s.is_empty()).then_some(s)
}

// ── `{value.<name>}` header values (local files, no network) ─────────────

/// Resolve every `[[http.value]]` to its current string, for substitution
/// into header values. An entry that can't be resolved is an error, not an
/// empty string: these carry request identity (Codex's `chatgpt-account-id`),
/// and a request that names the wrong account — or none — is worse than one
/// never sent.
fn resolve_values(values: &[HttpValueConfig]) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for v in values {
        let resolved = match v.kind {
            HttpValueType::JsonFile => resolve_json_file_value(v),
        }
        .ok_or_else(|| {
            format!(
                "could not read `{}` from `{}` for the {{value.{}}} header",
                v.name,
                v.path.as_deref().unwrap_or("(no path declared)"),
                v.name
            )
        })?;
        out.insert(v.name.clone(), resolved);
    }
    Ok(out)
}

/// One `type = "json-file"` value: read the file, walk `json_path`, take a
/// non-empty string. Numbers and booleans are deliberately *not* coerced — a
/// header value that isn't a string in the source file is more likely a
/// changed file format than an intended value.
fn resolve_json_file_value(v: &HttpValueConfig) -> Option<String> {
    let path = crate::plugin::expand_home(v.path.as_deref()?);
    let text = crate::plugin::read_regular_file(&path, crate::plugin::SMALL_FILE_MAX_BYTES)?;
    let json: Value = serde_json::from_str(&text).ok()?;
    let found = json_path_get(&json, v.json_path.as_deref()?)?
        .as_str()?
        .trim();
    (!found.is_empty()).then(|| found.to_string())
}

/// The `(substitute, then allow-list check)` half of [`resolve_account`],
/// split out — pure, no network — so the substitute-before-check order is
/// directly testable. `account.url` gets the same `{option.<key>}`
/// substitution as `[[http.request]].url` ([`build_request`]); like that URL,
/// `{token}`/`{version}` are deliberately never substituted here (they stay
/// confined to headers). The `allowed_hosts` check runs on the *substituted*
/// URL — the same order `fetch_surface` already used for the main usage
/// request — so a manifest can't use an option placeholder to smuggle a
/// request past the allow-list.
fn resolve_account_url(
    m: &PluginManifest,
    surface: &SurfaceConfig,
    options: &BTreeMap<String, bool>,
) -> Option<String> {
    if m.account.kind != AccountType::Http {
        return None;
    }
    let raw = m.account.url.as_deref()?;
    let url = crate::plugin::substitute_options(raw, options);
    auth::host_allowed(&surface.allowed_hosts, &url).then_some(url)
}

// ── Request building (pure — no network) ─────────────────────────────────

/// Build the `(url, headers, timeout)` for one `[[http.request]]` entry.
/// Header values get the full `{token}`/`{version}`/`{option.<key>}`
/// substitution ([`substitute`]); the URL only ever gets `{option.<key>}`
/// ([`crate::plugin::substitute_options`]) — `{token}`/`{version}` are
/// deliberately never substituted into a URL, keeping the bearer token
/// confined to headers (defence in depth alongside `allowed_hosts` /
/// `redirects(0)` — see module docs).
fn build_request(
    req: &HttpRequestConfig,
    token: &str,
    version: &str,
    options: &BTreeMap<String, bool>,
    values: &BTreeMap<String, String>,
) -> (String, Vec<(String, String)>, Duration) {
    (
        crate::plugin::substitute_options(&req.url, options),
        substitute_headers(&req.headers, token, version, options, values),
        Duration::from_secs(req.timeout_secs),
    )
}

/// The request body, substituted exactly like a header value ([`substitute`])
/// — it can carry `{token}` and never reaches the URL, same as one. Kept out
/// of [`build_request`] itself (see the call site in `fetch_surface`) so that
/// function's return shape, and the tests pinned to it, are untouched by a
/// field only some manifests declare. `None` when the manifest names no
/// `body` at all, which `perform` then sends as an empty one — see
/// [`crate::plugin::manifest::HttpRequestConfig::body`] for why that split
/// (declared-empty vs. not declared) is not meaningful past this point: a GET
/// may not declare `body` at all (`PluginManifest::validate`), so by the time
/// this runs, `Some("")` and `None` are the same request.
fn build_body(
    req: &HttpRequestConfig,
    token: &str,
    version: &str,
    options: &BTreeMap<String, bool>,
    values: &BTreeMap<String, String>,
) -> Option<String> {
    req.body
        .as_deref()
        .map(|b| substitute(b, token, version, options, values))
}

/// Substitute `{token}`/`{version}`/`{option.<key>}`/`{value.<name>}` into
/// every value of a header map, returning a sorted (for determinism) `Vec` —
/// `ureq`'s header API takes key/value pairs one at a time, not a map.
fn substitute_headers(
    headers: &HashMap<String, String>,
    token: &str,
    version: &str,
    options: &BTreeMap<String, bool>,
    values: &BTreeMap<String, String>,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.clone(), substitute(v, token, version, options, values)))
        .collect();
    out.sort();
    out
}

/// Fixed text for a header `ureq` itself refuses to send. Never `ureq`'s own
/// message, which quotes the whole `"Name: value"` line — see `perform`'s
/// `BadHeader` arm.
const BAD_HEADER_MESSAGE: &str = "a header value is not valid ASCII";

/// After substitution, every header value must be visible ASCII — the RFC
/// 7230 `field-value` grammar (`SP`/`HTAB`/`0x21`–`0x7E`) that `ureq` itself
/// enforces before sending anything. Checked here, ahead of every call this
/// engine makes, so a violation is a `reading.error` this engine wrote rather
/// than whatever `ureq`'s own refusal happens to quote (`perform`'s
/// `BadHeader` arm is the backstop for the one case this cannot run ahead
/// of: `ureq` validates its own synthesized headers too, past whatever this
/// engine passed in).
///
/// `validate` cannot enforce this at load time: `{token}` and
/// `{value.<name>}` are unknown until substitution runs, and a violating byte
/// then is a live credential's own bytes, not a manifest mistake — which is
/// exactly why the message below names the header, never the value. That
/// byte must not appear in anything this app writes to the panel or the log.
fn refuse_unsafe_header_values(headers: &[(String, String)]) -> Result<(), String> {
    for (name, value) in headers {
        let safe = value
            .bytes()
            .all(|b| b == b'\t' || b == b' ' || (0x21..=0x7E).contains(&b));
        if !safe {
            return Err(format!(
                "header `{name}` contains a byte that is not valid ASCII"
            ));
        }
    }
    Ok(())
}

/// Replace every `{token}`/`{version}`/`{option.<key>}`/`{value.<name>}`
/// placeholder in `template`. A header may name any subset of these, or none.
fn substitute(
    template: &str,
    token: &str,
    version: &str,
    options: &BTreeMap<String, bool>,
    values: &BTreeMap<String, String>,
) -> String {
    // One pass over the template, never a chain of `replace` calls: with a
    // chain, whatever the first substitution inserts is itself searched by the
    // next one, so a token or a file-read value that happens to contain
    // `{version}` or `{option.x}` would come out mangled — and the request
    // would fail as an auth error rather than as the nonsense it is.
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open..];
        let Some(close) = after.find('}') else {
            break; // an unclosed brace is literal text, not a placeholder
        };
        let name = &after[1..close];
        let replacement = match name {
            "token" => Some(token.to_string()),
            "version" => Some(version.to_string()),
            _ => name
                .strip_prefix("value.")
                .and_then(|key| values.get(key).cloned())
                .or_else(|| {
                    name.strip_prefix("option.")
                        .and_then(|key| options.get(key))
                        .map(|v| {
                            if *v {
                                "true".to_string()
                            } else {
                                "false".to_string()
                            }
                        })
                }),
        };
        match replacement {
            Some(value) => out.push_str(&value),
            // An unknown placeholder stays visible rather than vanishing into
            // an empty string, so the mistake shows up in whatever field it
            // lands in (same rule as `crate::plugin::substitute_options`).
            None => out.push_str(&after[..=close]),
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

/// Resolve the `{version}` placeholder value: read `files` in order, parse
/// the first one that exists and yields a string at `json_path`, else use
/// `fallback`. claude.toml uses this to read the installed Claude Code CLI's
/// own `package.json`. Each candidate path is `~`/`{config_dir}`-expanded
/// (see [`crate::plugin::expand_home`]), though claude.toml's own candidates
/// are already absolute.
fn resolve_version(v: &HttpVersionConfig) -> String {
    for file in &v.files {
        let path = crate::plugin::expand_home(file);
        if let Some(text) =
            crate::plugin::read_regular_file(&path, crate::plugin::SMALL_FILE_MAX_BYTES)
        {
            if let Ok(value) = serde_json::from_str::<Value>(&text) {
                if let Some(s) = json_path_get(&value, &v.json_path).and_then(Value::as_str) {
                    return s.to_string();
                }
            }
        }
    }
    v.fallback.clone()
}

// ── Response parsing (pure — no network) ─────────────────────────────────

/// The windows this response reports, or why it cannot be used — see
/// [`crate::plugin::collect_windows`], which is where the rule lives so that
/// both engines keep the same one.
fn parse_usage(value: &Value, m: &PluginManifest) -> Result<Vec<Window>, String> {
    crate::plugin::collect_windows(m, "response", |i, w| build_windows(i, w, value))
}

/// How many elements of a `for_each` array [`build_windows`] will ever look
/// at. A provider's array is data this app trusts to be honest about its own
/// account, not data it trusts to be small, and nothing shipped has ever come
/// close — Claude's `limits[]` runs to a handful of entries. 64 leaves
/// headroom for a plan with many scoped models while still bounding the
/// per-element work (a filter check, an identity read, a label fill) at a
/// fixed cost regardless of what a provider actually sends.
const FOR_EACH_MAX_ELEMENTS: usize = 64;

/// Diagnostics only the binary can write — the same split as
/// `crate::plugin::time`'s own `PENDING_DIAGNOSTICS` (`crate::diag` lives in
/// `main.rs`'s binary crate, not this library one), kept as this engine's own
/// queue rather than borrowed from `time`'s: what gets queued here is about a
/// `for_each` array, not a timestamp.
static PENDING_DIAGNOSTICS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Whether the one diagnostic this queue ever carries has already gone out,
/// this process. A single flag, not a per-label key: a manifest whose
/// `for_each` array is oversized says so on the first window it happens to,
/// and does not need a second line to say the same thing about a second one.
static FOR_EACH_TRUNCATED_LOGGED: AtomicBool = AtomicBool::new(false);

fn queue_for_each_truncated_diag(label: &str) {
    if !FOR_EACH_TRUNCATED_LOGGED.swap(true, Ordering::SeqCst) {
        PENDING_DIAGNOSTICS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(format!(
                "a `for_each` array for \"{label}\" carried more than \
                 {FOR_EACH_MAX_ELEMENTS} elements; the rest were not considered"
            ));
    }
}

/// Every diagnostic line queued since the last call, removing them.
pub fn take_pending_diagnostics() -> Vec<String> {
    let mut guard = PENDING_DIAGNOSTICS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    std::mem::take(&mut *guard)
}

/// The rows one `[[windows]]` entry produces: exactly one, as it always was,
/// unless the entry enumerates (`for_each`) — then one per element of the
/// array it names that survives its filter and can be named.
///
/// Why an entry may need to expand at all: Claude reports its session and
/// weekly windows in fixed fields, and repeats them inside a `limits[]` array
/// that also carries a third kind — a weekly allowance scoped to a single
/// model, `kind = "weekly_scoped"`, with the model named inside the element.
/// How many of those an account has is the provider's business and changes
/// with its plan, so no fixed number of entries can describe it: a selector
/// would take the first and drop the rest, silently.
///
/// Elements *considered* are capped at [`FOR_EACH_MAX_ELEMENTS`], applied
/// before `for_each_where` rather than after: the cost this bounds is
/// scanning and building a row for each one, and a filter that happened to
/// keep only elements past the cap would still have paid that cost for every
/// element ahead of them. A provider is free to answer with more than that —
/// nothing here has ever been observed to — and the elements past the cap
/// are silently unreachable rather than reported one by one; the truncation
/// itself is reported once, not each one it drops.
fn build_windows(index: usize, w: &WindowConfig, value: &Value) -> Vec<Window> {
    let Some(path) = w
        .for_each
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
    else {
        return build_window(index, w, value).into_iter().collect();
    };
    // A path that resolves to something other than an array is not an error
    // here for the same reason a missing figure is not: the entry reports
    // nothing, and `required` (checked in `collect_windows`) is what says
    // whether that absence is the provider being wrong.
    let Some(elements) = json_path_get(value, path).and_then(Value::as_array) else {
        return Vec::new();
    };
    if elements.len() > FOR_EACH_MAX_ELEMENTS {
        queue_for_each_truncated_diag(&w.label);
    }
    let mut produced: Vec<Window> = elements
        .iter()
        .take(FOR_EACH_MAX_ELEMENTS)
        .filter(|element| element_matches(element, w.for_each_where.as_deref()))
        .filter_map(|element| build_enumerated_window(index, w, element))
        .collect();
    // Ordered by identity, not by position. The provider promises no order —
    // Claude's `limits[]` is whatever its backend assembled — so keeping the
    // array's order would let the rows change places between two fetches for
    // no reason a reader could see. Sorting by the key also makes the dedup
    // below a neighbour check rather than a scan.
    produced.sort_by_key(|w| w.key.clone());
    // Two elements with the same identity are one row, not two: a key is a
    // path in the user's config, and two rows writing the same one would take
    // turns overwriting each other's registry entry. The first wins, which
    // after the sort is the one the provider sent first among equals.
    produced.dedup_by(|a, b| a.key == b.key);
    produced
}

/// Whether one element passes `for_each_where`. No filter keeps everything;
/// the comparison is the one `pick` makes for a path selector — against the
/// field's text, since everything in a manifest is a string by the time it
/// gets here.
fn element_matches(element: &Value, filter: Option<&str>) -> bool {
    let Some(filter) = filter else { return true };
    let Some((field, wanted)) = filter.split_once('=') else {
        return false;
    };
    // Both halves trimmed, because a manifest is written by a human in a file
    // that aligns its `=` signs: `for_each_where = "kind = weekly_scoped"` is
    // the natural way to type it, and comparing against `" weekly_scoped"`
    // would match nothing forever. `validate` refuses the shapes that cannot
    // match at all; this is the one that would look right and still fail.
    field_says(element, field.trim(), wanted.trim())
}

/// Whether one object's `field` says exactly `wanted`.
///
/// The comparison is against the field's text — a number or a boolean compares
/// as it prints — because a manifest is TOML and everything in a path or a
/// filter is a string by the time it gets here. Both `field` and `wanted` are
/// taken as given: trimming, if the caller's manifest syntax needs it, is the
/// caller's job ([`pick`] and [`element_matches`] both do it before calling
/// in). One function for both callers on purpose: a path selector
/// (`limits[kind=weekly_scoped]`, one element) and an enumeration filter
/// (`for_each_where`, every element) differ in how many elements they keep
/// and in nothing else, and two copies of this would be two chances for that
/// to stop being true.
// `cmp_owned` says to compare the `Value` directly, and that is wrong here:
// `Value == &str` is true only for a `Value::String`, so every number and every
// boolean would stop matching — the case the line below exists for.
#[allow(clippy::cmp_owned)]
fn field_says(item: &Value, field: &str, wanted: &str) -> bool {
    item.get(field).is_some_and(|v| match v.as_str() {
        Some(text) => text == wanted,
        None => v.to_string() == wanted,
    })
}

/// One row of an enumerating entry.
///
/// The element *is* the window's container: every path in `[windows.source]`
/// is read inside it, which is what lets one entry describe a shape the
/// provider repeats. Two things then come from the element rather than from
/// the manifest — the identity the row is filed under and the caption that
/// names it — and both are refused rather than guessed when the element does
/// not carry them: a row this app cannot name is worse than no row.
fn build_enumerated_window(index: usize, w: &WindowConfig, element: &Value) -> Option<Window> {
    let id_path = w
        .element_id_path
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())?;
    let element_id = element_identity(element, id_path)?;
    let label = fill_label(&w.label, element)?;
    let mut window = build_window(index, w, element)?;
    window.key = crate::plugin::window_element_key(w, index, &element_id);
    window.label = label;
    Some(window)
}

/// A `{path}` template filled from one element, or `None` when a placeholder
/// names something the element does not carry.
///
/// Every substituted value goes through the same sanitiser as any other string
/// from the network (`reached_type` takes the same route): this text lands in
/// the panel, and a caption is not a place a provider gets to put a newline or
/// a bidi override.
///
/// The sanitiser caps each *substitution* at `PROVIDER_TEXT_MAX_CHARS`, not
/// the label as a whole — a template naming two or three placeholders
/// (`"{a} weekly, {b}"`) can still run well past that cap once they are all
/// concatenated with the template's own literal text. So the finished label
/// is capped again here, the same trim-then-cut-then-trim order
/// `sanitize_provider_text` uses and for the same reason: cutting first would
/// spend the budget on whatever padding sits at either end rather than on
/// content.
fn fill_label(template: &str, element: &Value) -> Option<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = rest[open..].find('}')? + open;
        let filled = element_text(element, &rest[open + 1..close])?;
        // Sanitised here and not in `element_text`, because this is the half
        // that reaches the screen: the identity above must stay lossless.
        let filled = crate::plugin::sanitize_provider_text(&filled);
        if filled.is_empty() {
            return None;
        }
        out.push_str(&filled);
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    let out: String = out
        .trim()
        .chars()
        .take(crate::plugin::PROVIDER_TEXT_MAX_CHARS)
        .collect();
    let out = out.trim().to_string();
    (!out.is_empty()).then_some(out)
}

/// One field of an element as text. A number or a boolean prints as it would in
/// the response — this is tolerance rather than a mechanism: a quota keyed by
/// an integer id is keyed by something, and answering it with silence would be
/// a row that vanishes for a reason the panel cannot show. An object or an
/// array is not text and yields nothing.
fn element_text(element: &Value, path: &str) -> Option<String> {
    match json_path_get(element, path.trim())? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// The `<element>` half of a row's key, from the element itself.
///
/// **Not sanitised, deliberately.** Sanitising is for text that reaches the
/// screen, and it is lossy: two model names differing only by a directional
/// mark come out identical, and two rows would then share one path in the
/// user's config. The identity instead goes through `encode_key_part`
/// ([`window_element_key`](crate::plugin::window_element_key), where the
/// caller encodes it), which is not lossy — every byte outside
/// `[A-Za-z0-9_-]` becomes `%XX`, including the `%` and the `:` that would
/// otherwise forge a separator.
///
/// Bounded, since a provider is free to send a name of any length and this
/// becomes a path segment on disk — but *truncating* the raw text before
/// that single encode step, the way this used to, reopens the same collision
/// the encoder exists to close: two names sharing their first
/// [`crate::plugin::PROVIDER_TEXT_MAX_CHARS`] characters would truncate to
/// one identical identity, and `build_windows`' dedup (which has nothing but
/// this to key on) would then keep one row and drop the other silently. So a
/// name past the cap is truncated *and* given a fixed-width hash suffix of
/// the whole raw text, in the same character budget — two names differing
/// anywhere, including past the visible prefix, hash apart. (Two names that
/// happen to be genuinely identical still collide, which is the dedup this
/// function exists to make possible in the first place. And a provider
/// naming something that literally *is* `<truncated prefix>#<16 hex
/// digits>` could in principle collide with a hashed one — a boundary this
/// scheme cannot express, the same way `json_path_get`'s own grammar has
/// one; nothing observed here has ever come close.)
///
/// The hash is [`Sha256`], truncated to its first 8 bytes, never `std`'s
/// `DefaultHasher`: this suffix lands in `config.json`'s own keys through
/// `window_element_key`, so it has to keep producing the same value for the
/// same name across every future toolchain this app is ever rebuilt with.
/// `DefaultHasher`'s algorithm is an unspecified implementation detail of
/// the standard library, free to change between Rust releases — a change
/// that would silently reshuffle every stored per-window key on the next
/// upgrade, the same class of break a cryptographic hash's fixed
/// specification does not have.
fn element_identity(element: &Value, path: &str) -> Option<String> {
    let raw = element_text(element, path)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let cap = crate::plugin::PROVIDER_TEXT_MAX_CHARS;
    if trimmed.chars().count() <= cap {
        return Some(trimmed.to_string());
    }
    let digest = Sha256::digest(trimmed.as_bytes());
    let suffix = format!(
        "#{}",
        digest[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let head: String = trimmed
        .chars()
        .take(cap.saturating_sub(suffix.chars().count()))
        .collect();
    Some(format!("{head}{suffix}"))
}

/// What the response says about the quota itself, or `None` when the manifest
/// declares no `[status]` — which is not the same as a provider saying nothing
/// is wrong, and is why this is an `Option` rather than a default.
///
/// Read from the response **root**, never from a window's container: this is
/// the statement that outlives its windows. Codex puts `allowed` and
/// `limit_reached` beside the two optional window slots for exactly that
/// reason, so a blocked account with nothing running still says so.
fn parse_quota(value: &Value, m: &PluginManifest) -> Option<crate::model::QuotaStatus> {
    let cfg = m.status.as_ref()?;
    // A blank path is not a path. `StatusConfig::is_empty` already trims when
    // deciding whether the section says anything, and reading it without
    // trimming here would let `allowed_path = " "` pass validation beside a
    // real second path and then resolve to `None` — silently, and looking
    // exactly like a provider that did not answer.
    let flag = |path: &Option<String>| -> Option<bool> {
        let path = path.as_deref().map(str::trim).filter(|p| !p.is_empty())?;
        json_path_get(value, path)?.as_bool()
    };
    let status = crate::model::QuotaStatus {
        allowed: flag(&cfg.allowed_path),
        limit_reached: flag(&cfg.limit_reached_path),
        // Sanitised on the way in, not on the way to the screen: this string
        // is the provider's own word for which limit was hit, it goes into the
        // panel *and* the log, and it is the one field here that carries free
        // text from the network. A non-string is not coerced — a provider that
        // answers with an object has changed shape, and inventing a rendering
        // for it would hide that.
        // `"none"`/`"null"` count as not naming anything, the same as an
        // absent or blank field: `QuotaStatus::limit_was_reached` infers a
        // refusal from this field being present at all when neither boolean
        // above was, and a provider that fills it with one of these words in
        // the *ordinary*, not-blocked case (the comment on `is_blocked`
        // names exactly this shape: `"type": "none"`) would otherwise be
        // read as refusing every account it has.
        reached_type: cfg
            .reached_type_path
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .and_then(|p| json_path_get(value, p))
            .and_then(Value::as_str)
            .map(crate::plugin::sanitize_provider_text)
            .filter(|s| !s.is_empty())
            .filter(|s| !matches!(s.to_ascii_lowercase().as_str(), "none" | "null")),
    };
    // A section that resolved to nothing is a response that did not answer,
    // and saying so with an empty status would be this app inventing the
    // sentence. The manifest declaring the section is not the provider
    // speaking.
    status.is_stated().then_some(status)
}

/// Which object in `value` holds this window's numbers.
///
/// With no `source.containers` declared, that is the response body itself —
/// every path in `[windows.source]` is absolute, the behaviour every existing
/// manifest (Claude's) relies on. With candidates declared, the window's
/// numbers live in whichever candidate *is* this window, and a provider need
/// not put it in a fixed slot: Codex answers with its weekly window in
/// `primary_window` and `secondary_window` null whenever the 5-hour window has
/// nothing to report, so slot position says nothing about window length.
///
/// When the window's length comes `from_field` *and* the manifest declares
/// at least one of `[min_period_minutes, max_period_minutes]`, candidates
/// are classified the way `engine_logfile::classify_slot` classifies a log
/// line's `primary`/`secondary` pair: scan them in declared order and take
/// the first whose own length falls inside those bounds. First-match is the
/// rule the log-file engine has always used, so both engines resolve an
/// ambiguous provider the same way. A candidate that is absent, null, or
/// carries no readable length can't be classified and is skipped; when
/// nothing matches, the window has no source at all and every field of it
/// reads `None` — the same shape a missing window has always produced
/// (`src/main.rs` renders a reading whose windows are all blank as "no usage
/// reported yet").
///
/// Without a bound to check against — no bound declared, or the window's
/// length is `assumed` rather than `from_field` (a bound declared there is
/// never consulted; there is nothing in the response to compare it to, and
/// `validate` refuses that combination at load, so no manifest that actually
/// parses reaches this arm — the check stays as this function's own defence
/// in depth) — no classification happens at all: candidates are scanned in
/// declared order and the first one that isn't null wins, whatever length it
/// actually carries. A manifest with several containers and no bound is
/// relying on that order rather than on content to tell its windows apart.
fn select_container<'v>(w: &WindowConfig, value: &'v Value) -> Option<&'v Value> {
    // One rule, whatever the shape: a length the *response* states is checked
    // against the bounds the manifest declares, and nothing else is checked at
    // all. So bounds hold wherever they appear — over several candidates
    // (which is what they are for), over a single one, over the response root
    // — and a window whose length is `assumed` has nothing to check them
    // against, so it classifies nothing rather than silently matching
    // everything or nothing.
    let classify = (w.source.min_period_minutes.is_some() || w.source.max_period_minutes.is_some())
        && w.period.mode == PeriodMode::FromField;
    let min_bound = w.source.min_period_minutes.unwrap_or(0);
    let max_bound = w.source.max_period_minutes.unwrap_or(u64::MAX);
    let fits = |candidate: &Value| {
        !classify
            || matches!(container_period_minutes(w, candidate), Some(m) if m >= min_bound && m <= max_bound)
    };

    if w.source.containers.is_empty() {
        return fits(value).then_some(value);
    }
    for path in &w.source.containers {
        let Some(candidate) = json_path_get(value, path).filter(|c| !c.is_null()) else {
            continue;
        };
        if fits(candidate) {
            return Some(candidate);
        }
    }
    None
}

/// This window's declared length as read out of `container`, in minutes.
/// `None` for `period.mode = "assumed"` (the length is a constant, not
/// something the response states), when the field is missing/unparsable, or
/// when the value is not [`crate::plugin::time::plausible_period_minutes`] —
/// a saturating `as u64` on an absurd float, or a field a provider fills in a
/// different unit than declared, is a length nothing here should draw a
/// window from. The one implementation both [`select_container`]'s
/// classification and [`build_window`]'s own `period_minutes` field call —
/// they used to carry a second copy of this, which is exactly the kind of
/// place a bound like this is easy to add to one and forget on the other.
fn container_period_minutes(w: &WindowConfig, container: &Value) -> Option<u64> {
    if w.period.mode != PeriodMode::FromField {
        return None;
    }
    let raw = json_path_get(container, w.period.field.as_deref()?).and_then(Value::as_u64)?;
    let minutes = w.period.unit.to_minutes(raw);
    crate::plugin::time::plausible_period_minutes(minutes).then_some(minutes)
}

/// This window as the response reports it, or `None` when the response does
/// not report it at all.
///
/// "Does not report it" is one answer for two shapes — no candidate container
/// is this window, or the container is there without a usable percentage —
/// because they mean the same thing to a reader: there is no figure. What they
/// must not mean is "there is a window here and it is blank", which is what an
/// emitted all-`None` row said, and which the panel then had to filter out
/// again on its way to the screen. Saying it once, here, is what lets
/// `required` above tell a plan without a limit from an endpoint that changed
/// shape.
fn build_window(index: usize, w: &WindowConfig, value: &Value) -> Option<Window> {
    let value = select_container(w, value)?;
    // Exactly one of the two paths is set (`validate` enforces it for the
    // http engine). A remaining fraction (0..1) is complemented into the same
    // consumed-percent the window contract holds — `(1 − f)·100`, then
    // clamped like any other percent; an absent path short-circuits with `?`
    // to no window, which for Antigravity's proto3 responses is exactly right:
    // a bucket the server omits at zero means "did not say", never "spent" —
    // claiming a figure the provider did not state would be this app's
    // invention. The clamp below is the window's own scale contract — a
    // percent is always 0..100, whichever path produced it — applied to
    // both forms identically.
    let used_percent = match (
        &w.source.used_percent_path,
        &w.source.remaining_fraction_path,
    ) {
        (Some(path), _) => json_path_get(value, path).and_then(Value::as_f64)?,
        (None, Some(path)) => {
            let remaining = json_path_get(value, path).and_then(Value::as_f64)?;
            (1.0 - remaining) * 100.0
        }
        (None, None) => return None,
    }
    .clamp(0.0, 100.0);
    // Both of these used to be gated on `used_percent` being present, so that
    // a window with a reset time but no usage figure presented as a fully
    // missing one. The `?` above is that same rule, said once and earlier:
    // past it there *is* a figure, so nothing here needs to ask again.
    let resets_at = json_path_get(value, &w.source.resets_at_path)
        .and_then(|v| crate::plugin::time::resets_at(v, w.source.resets_at_format));
    let period_minutes = match w.period.mode {
        PeriodMode::Assumed => w.period.assumed,
        PeriodMode::FromField => container_period_minutes(w, value),
    };
    Some(Window {
        // The declared entry, never the container this window resolved to: at
        // Codex that container moves between ticks (see `select_container`).
        key: crate::plugin::window_key(w, index),
        label: w.label.clone(),
        role: crate::plugin::map_role(w.role),
        used_percent: Some(used_percent),
        resets_at,
        period_minutes,
    })
}

/// The balances this response reports, one per declared `[[balances]]` entry
/// that resolved to something.
///
/// An entry that resolved to nothing emits no row at all — the same rule
/// presence applies to windows, and for the same reason: a caption beside empty
/// space says "this provider has a balance of unknown size", which is a claim
/// nobody made. There is no `required` counterpart here yet, because no
/// provider has been observed to make a balance's absence an error.
fn parse_balances(value: &Value, m: &PluginManifest) -> Vec<crate::model::Balance> {
    m.balances
        .iter()
        .enumerate()
        .filter_map(|(i, b)| build_balance(i, b, value))
        .collect()
}

fn build_balance(index: usize, b: &BalanceConfig, value: &Value) -> Option<crate::model::Balance> {
    let balance = crate::model::Balance {
        key: crate::plugin::balance_key(b, index),
        label: b.label.clone(),
        used: b.used.as_ref().and_then(|a| read_amount(value, a)),
        cap: b.cap.as_ref().and_then(|a| read_amount(value, a)),
        remaining: b.remaining.as_ref().and_then(|a| read_amount(value, a)),
        // The provider's own percentage, never computed and never adjusted.
        // There is no path in the grammar that would produce a derived one.
        // Not clamped, unlike a window's percentage. A window's percent is
        // this app's own contract — a bar has ends — while a balance's is a
        // number the provider published, and 101 clamped to 100 is a figure
        // nobody sent, printed beside figures that are. If a provider reports
        // something out of range, the panel shows what it reported.
        // `is_finite` is defence in depth rather than a live branch: serde_json
        // refuses a literal outside f64's range at parse time ("number out of
        // range"), and JSON has no NaN or infinity to write, so a body cannot
        // carry one through. It stays because the alternative — a percentage
        // that is not a number reaching the panel — used to render as a tidy
        // `0% used` once it had been clamped and rounded.
        stated_percent: path_of(&b.source.percent_path)
            .and_then(|p| json_path_get(value, p))
            .and_then(Value::as_f64)
            .filter(|p| p.is_finite()),
        period_end: path_of(&b.source.period_end_path)
            .and_then(|p| json_path_get(value, p))
            .and_then(|v| crate::plugin::time::resets_at(v, b.source.period_end_format)),
        limit_reached: path_of(&b.source.limit_reached_path)
            .and_then(|p| json_path_get(value, p))
            .and_then(Value::as_bool),
    };
    // A period end on its own is not a balance: every month has one, and a row
    // showing a date beside nothing would be this app announcing a figure it
    // does not have.
    balance.is_stated().then_some(balance)
}

/// A declared path that is actually a path. Mirrors `parse_quota`: a blank
/// string passes validation beside a real one and then resolves to `None`,
/// looking exactly like a provider that did not answer.
fn path_of(path: &Option<String>) -> Option<&str> {
    path.as_deref().map(str::trim).filter(|p| !p.is_empty())
}

/// One figure, in whichever form its entry declares.
///
/// Every kind is all-or-nothing. A money triplet missing its currency or its
/// exponent yields **no figure at all** rather than a bare number: the amount
/// alone is meaningless (1999 of what, at what scale), and showing it would be
/// the app supplying the half the provider did not.
fn read_amount(value: &Value, cfg: &AmountConfig) -> Option<crate::model::BalanceAmount> {
    match cfg.kind {
        AmountKind::MoneyMinor => {
            let minor = json_path_get(value, path_of(&cfg.amount_path)?)?.as_i64()?;
            let currency = json_path_get(value, path_of(&cfg.currency_path)?)?.as_str()?;
            let exponent = json_path_get(value, path_of(&cfg.exponent_path)?)?.as_u64()?;
            // A currency code is a unit, and it reaches the screen: it goes
            // through the same sanitiser as every other string from the
            // network. An exponent past a few digits is not a scale any
            // currency has — it is a response that changed shape, and
            // rendering it would produce a number off by orders of magnitude.
            let currency = crate::plugin::sanitize_provider_text(currency);
            if currency.is_empty() || exponent > 9 {
                return None;
            }
            Some(crate::model::BalanceAmount::Money {
                minor,
                currency,
                exponent: exponent as u32,
            })
        }
        AmountKind::Number => {
            let n = json_path_get(value, path_of(&cfg.path)?)?.as_f64()?;
            // The unit is the manifest author's literal, not the response's,
            // so it is sanitised for length and shape like any label and then
            // carried *with* the value: two numbers are only ever drawn as a
            // pair when they count the same thing.
            let unit = cfg
                .unit_label
                .as_deref()
                .map(str::trim)
                .filter(|u| !u.is_empty())
                .map(crate::plugin::sanitize_provider_text)
                .filter(|u| !u.is_empty());
            n.is_finite()
                .then_some(crate::model::BalanceAmount::Number { value: n, unit })
        }
        AmountKind::Text => {
            let s = json_path_get(value, path_of(&cfg.path)?)?.as_str()?;
            let s = crate::plugin::sanitize_provider_text(s);
            (!s.is_empty()).then_some(crate::model::BalanceAmount::Text(s))
        }
    }
}

/// Resolve a dotted JSON path (`"a.b.c"`) against an arbitrary value — object
/// keys only, mirrors `crate::plugin::auth::json_path_str` /
/// `engine_logfile::json_path`.
fn json_path_get<'v>(root: &'v Value, path: &str) -> Option<&'v Value> {
    let mut cur = root;
    for seg in segments(path) {
        // A selector is a segment that both opens and closes one — and when
        // reading it that way finds nothing, the segment is tried again whole,
        // as a key. A provider is entitled to a field called `counts[daily]`,
        // and a syntax added beside the existing paths must not take names
        // away from them. Only a real array with a matching element beats a
        // real key of that exact name, and no provider has both.
        let stepped = match seg.strip_suffix(']').and_then(|open| open.split_once('[')) {
            Some((key, selector)) => {
                let container = if key.is_empty() {
                    Some(cur)
                } else {
                    cur.get(key)
                };
                container.and_then(|c| pick(c, selector))
            }
            None => None,
        };
        cur = match stepped {
            Some(found) => found,
            None => cur.get(seg)?,
        };
    }
    Some(cur)
}

/// Split a path on `.`, except inside `[...]`. A selector's value is arbitrary
/// text a provider chose — `GPT-5.3-Codex-Spark` has two dots in it — and
/// splitting through one would leave a path nothing could ever match, in the
/// most confusing way possible: silently, as a missing field.
///
/// The sequence `].` inside a value is what this grammar cannot express: the
/// `]` closes the selector and the `.` then splits the path, so the selector
/// ends up shorter than it was written. A plain `]` is fine (the closing one
/// is the last), and so is any number of dots. No escape is offered rather
/// than invented — a manifest is meant to be read — and the boundary is
/// pinned by a test rather than left to be discovered.
fn segments(path: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut depth) = (0usize, 0u32);
    for (i, c) in path.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth = depth.saturating_sub(1),
            '.' if depth == 0 => {
                out.push(&path[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    out.push(&path[start..]);
    out
}

/// One element of an array, chosen the way the manifest asked: by position
/// (`[0]`) or by a field of its own (`[limit_name=GPT-5.3-Codex-Spark]`).
///
/// The second form is what a list of quotas needs. A provider that answers
/// with an array of per-model allowances puts them in no fixed order and adds
/// to them over time, so "the second one" is not a thing a manifest can mean;
/// "the one that calls itself this" is. The comparison is against the field's
/// text — a number or a boolean compares as it prints — because a manifest is
/// TOML and everything in a path is a string by the time it gets here. Both
/// halves are trimmed before the comparison, the same reason
/// [`element_matches`] trims `for_each_where`'s: `limits[kind = weekly_scoped]`
/// is the natural way to align a manifest's `=` signs, and comparing the
/// field's text against `" weekly_scoped"` would match nothing forever.
fn pick<'v>(container: &'v Value, selector: &str) -> Option<&'v Value> {
    let array = container.as_array()?;
    match selector.split_once('=') {
        None => array.get(selector.parse::<usize>().ok()?),
        Some((field, wanted)) => array
            .iter()
            .find(|item| field_says(item, field.trim(), wanted.trim())),
    }
}

// ── Network (the only part that isn't unit-tested) ───────────────────────

/// GET or POST `url` (per `method`), with `headers` attached, `body`
/// attached when `method` is a POST, and `timeout`; returns the parsed JSON
/// body, and gives the 401 case its own error text (an expired OAuth token
/// needs a real re-login, not a retry).
///
/// Built on an agent with `redirects(0)`: both callers of this function
/// (`fetch_surface`'s usage request and `resolve_account`'s profile request,
/// which is always a GET regardless of `method` — see its own docs) only
/// ever check `allowed_hosts` against `url` itself — with redirects
/// disabled, a 3xx response can't silently carry the bearer token on to a
/// host the surface's manifest never listed. `ureq` returns a redirect
/// response as `Ok` (only `>= 400` becomes `Err`), so it's matched explicitly
/// below and turned into an error rather than parsed as JSON.
///
/// `body` is sent exactly as the manifest wrote it (after substitution) —
/// this engine reads more than one provider, so it assumes nothing about a
/// body's shape; whatever `Content-Type` the manifest declared travels with
/// it via `headers` like any other header, and `ureq` is told nothing more.
/// `send_string("")` for a POST with no declared body is a normal, complete
/// request (see `HttpRequestConfig::body`'s docs on why that split is legal),
/// not a placeholder for one that failed to build.
///
/// `url` must be `https`, checked here before any connection is opened —
/// `manifest::validate` already refuses a non-`https` `[[http.request]] url`
/// or `[account] url` at load, so a request reaching this function with any
/// other scheme means validation was somehow bypassed, not that the token
/// this function is about to attach was ever meant to leave the machine in
/// the clear. Defence in depth, the same reasoning as `allowed_hosts` below.
fn perform(
    url: &str,
    method: HttpMethod,
    body: Option<&str>,
    headers: &[(String, String)],
    timeout: Duration,
) -> Result<Value, Failure> {
    if super::https_host(url).is_none() {
        let scheme = url::Url::parse(url).map(|u| u.scheme().to_string());
        return Err(Failure::transient(match scheme {
            Ok(scheme) => format!("refusing to fetch a non-https URL (scheme \"{scheme}\")"),
            Err(_) => format!("refusing to fetch an unparsable URL: {url}"),
        }));
    }
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let mut req = match method {
        HttpMethod::Get => agent.get(url),
        HttpMethod::Post => agent.post(url),
    }
    .timeout(timeout);
    for (k, v) in headers {
        req = req.set(k, v);
    }
    let result = match method {
        HttpMethod::Get => req.call(),
        HttpMethod::Post => req.send_string(body.unwrap_or("")),
    };
    match result {
        Ok(r) if (300..400).contains(&r.status()) => Err(Failure::transient(format!(
            "HTTP {} (redirect blocked)",
            r.status()
        ))),
        Ok(r) => read_json_body(r).map_err(Failure::transient),
        // Terminal, and the only one: this app never spends a provider's
        // refresh token (that can invalidate the copy the provider's own CLI
        // holds), so a dead access token stays dead until the user signs in
        // again. Retrying it on a timer is a request that cannot succeed.
        //
        // The text is provider-neutral on purpose: this engine reads more
        // than one provider, and naming the wrong app sends the user to the
        // wrong place.
        Err(ureq::Error::Status(401, _)) => Err(Failure::terminal(UNAUTHORIZED)),
        Err(ureq::Error::Status(429, _)) => Err(Failure::transient("rate-limited (try later)")),
        Err(ureq::Error::Status(code, _)) => Err(Failure::transient(format!("HTTP {code}"))),
        // `ureq` validates every header — including its own, synthesized
        // ones — right before it sends anything (`Header::validate`), and its
        // own message for a violation quotes the whole `"Name: value"` line.
        // `refuse_unsafe_header_values` already keeps this from firing for a
        // header this engine built; this is the backstop for one it did not
        // (a proxy's own default header, say), so the token can never surface
        // through this path either.
        Err(ureq::Error::Transport(t)) if t.kind() == ureq::ErrorKind::BadHeader => {
            Err(Failure::transient(BAD_HEADER_MESSAGE))
        }
        Err(e) => Err(Failure::transient(redact_header_values(
            &format!("network error: {e}"),
            headers,
        ))),
    }
}

/// Ceiling on a provider response body, checked before any JSON parsing is
/// attempted. `Response::into_json` (`ureq`'s own helper) hands the raw
/// stream straight to `serde_json::from_reader` with no limit of its own — a
/// provider (or anything sitting between this app and it) answering with an
/// unbounded stream would have this app read all of it into memory before
/// ever finding out it wasn't going to stop. 4 MiB is generous for any usage
/// payload a provider has ever sent and far short of anything that hurts.
const MAX_PROVIDER_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

/// Read `response`'s body and parse it as JSON, refusing outright — with its
/// own message — when it is larger than [`MAX_PROVIDER_RESPONSE_BYTES`].
///
/// `take(MAX_PROVIDER_RESPONSE_BYTES + 1)`, not `take(MAX_PROVIDER_RESPONSE_BYTES)`:
/// `Read::take` truncates silently, so reading exactly the cap can never tell
/// "the body was exactly this large" from "the body was larger and got cut
/// off here" — the one extra byte is what lets the length check below tell
/// them apart, rather than the truncated tail failing to parse for an
/// unrelated reason and this engine reporting a "bad response" that was
/// actually an oversized one.
fn read_json_body(response: ureq::Response) -> Result<Value, String> {
    let mut buf = Vec::new();
    response
        .into_reader()
        .take(MAX_PROVIDER_RESPONSE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("bad response: {e}"))?;
    if buf.len() as u64 > MAX_PROVIDER_RESPONSE_BYTES {
        return Err(format!(
            "response body exceeds {MAX_PROVIDER_RESPONSE_BYTES} bytes, refusing to parse it"
        ));
    }
    serde_json::from_slice(&buf).map_err(|e| format!("bad response: {e}"))
}

/// `message`, verbatim, unless it happens to quote one of this request's own
/// header values — which would mean a credential (the bearer token, most
/// often) ended up inside an error string this app then shows on the panel
/// and writes to `crate::diag`. Checked against the *formatted* message
/// rather than prevented at its source, because by this point the message
/// can come from anywhere: some other `Display` impl this engine did not
/// write, quoting text it was never told was sensitive.
fn redact_header_values(message: &str, headers: &[(String, String)]) -> String {
    let leaked = headers
        .iter()
        .any(|(_, v)| !v.is_empty() && message.contains(v.as_str()));
    if leaked {
        "a header value could not be sent".to_string()
    } else {
        message.to_string()
    }
}

/// A failed request, and whether waiting could ever change its answer.
///
/// Everything except an expired session is `transient` — including a 4xx from
/// a changed API. Those don't get retried *hard*: they back off to the same
/// ceiling as an outage (see [`crate::plugin::throttle`]). What they must not
/// do is stop the polling forever on the strength of a status code this app
/// happened not to expect.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Failure {
    message: String,
    terminal: bool,
}

impl Failure {
    fn transient(message: impl Into<String>) -> Self {
        Failure {
            message: message.into(),
            terminal: false,
        }
    }

    fn terminal(message: impl Into<String>) -> Self {
        Failure {
            message: message.into(),
            terminal: true,
        }
    }
}

// ── Tests (hermetic: no network, no real Keychain, isolated env vars) ────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::plugin::manifest::{
        PeriodConfig, PeriodUnit, ResetsAtFormat, Role as ManifestRole, SourceConfig,
    };
    use crate::plugin::time::parse_iso8601;

    // 2026-01-01T00:00:00Z
    const NY2026: u64 = 1767225600;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tickover-http-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// Guards the three tests below that call `std::env::set_var`/
    /// `remove_var`: real process environment is process-wide state
    /// `cargo test`'s default parallelism does not otherwise serialize, and
    /// each test's own uniquely-named variable stops it from *reading*
    /// another test's value but not from *racing* the underlying set/remove
    /// calls themselves. `.unwrap_or_else(|e| e.into_inner())`, not
    /// `.unwrap()`: one test panicking while holding this lock must not
    /// poison it for every test queued behind it — the same discipline as
    /// `auth.rs`'s own, distinct `ENV_TEST_LOCK` (a separate mutex, scoped to
    /// this module, since env var mutation only races within one test
    /// binary's shared state either way).
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A Claude-like manifest: `engine = "http-api"`, two explicit surfaces,
    /// each with an `env`-backed auth step so tests never touch the real
    /// filesystem, Keychain or network — mirrors the `CLAUDE_LIKE` fixture in
    /// `manifest.rs`, but with `credentials-file`/`keychain`/`electron-safe-
    /// storage` steps replaced by `env` ones for hermetic token resolution.
    fn claude_like_manifest() -> PluginManifest {
        let toml = r#"
            id         = "claude"
            name       = "Claude"
            menu_label = "Cl"
            order      = 20
            engine     = "http-api"

            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode    = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "five_hour.utilization"
            resets_at_path    = "five_hour.resets_at"
            resets_at_format  = "iso8601"

            [[windows]]
            label = "WK"
            role  = "secondary"
            [windows.period]
            mode    = "assumed"
            assumed = 10080
            [windows.source]
            used_percent_path = "seven_day.utilization"
            resets_at_path    = "seven_day.resets_at"
            resets_at_format  = "iso8601"

            [http]
            [[http.request]]
            url          = "https://api.anthropic.com/api/oauth/usage"
            timeout_secs = 8
            [http.request.headers]
            Authorization    = "Bearer {token}"
            "anthropic-beta" = "oauth-2025-04-20"
            "User-Agent"     = "claude-code/{version}"

            [account]
            type      = "http"
            url       = "https://api.anthropic.com/api/oauth/profile"
            json_path = "account.email"

            [[surface]]
            id     = "cli"
            label  = "CLI"
            opt_in = false
            allowed_hosts = ["api.anthropic.com"]
            [[surface.auth]]
            type = "env"
            var  = "TICKOVER_TEST_ENGINE_HTTP_CLI_TOKEN"

            [[surface]]
            id     = "desktop"
            label  = "Desktop"
            opt_in = true
            in_menu_bar = false
            allowed_hosts = ["api.anthropic.com"]
            [[surface.auth]]
            type = "env"
            var  = "TICKOVER_TEST_ENGINE_HTTP_DESKTOP_TOKEN"
        "#;
        PluginManifest::from_str(toml).expect("valid test manifest")
    }

    /// A single-surface, single-step manifest whose one auth step is a
    /// `credentials-file` pointing at `dir/creds.json`, already written with
    /// a token past `expiry_json_path` — so `auth::resolve_token` ends
    /// "lapsed" (see `auth::TOKEN_LAPSED`) with no real filesystem surprises
    /// and no network at all: `fetch_surface` returns before `perform` is
    /// ever reached. `renews_token` drives whether `[ping]` names a
    /// renewing command.
    fn claude_like_manifest_with_a_lapsed_cli_token(
        dir: &std::path::Path,
        renews_token: bool,
    ) -> PluginManifest {
        let file = dir.join("creds.json");
        std::fs::write(
            &file,
            r#"{"claudeAiOauth":{"accessToken":"tok-old","expiresAt":"2020-01-01T00:00:00Z"}}"#,
        )
        .unwrap();
        let ping = if renews_token {
            "\n            [ping]\n            bin          = \"claude\"\n            renews_token = true\n"
        } else {
            ""
        };
        let toml = format!(
            r#"
            id         = "claude"
            name       = "Claude"
            menu_label = "Cl"
            order      = 20
            engine     = "http-api"
            requires_reader = ["keychain-expiry"]

            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode    = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "five_hour.utilization"
            resets_at_path    = "five_hour.resets_at"
            resets_at_format  = "iso8601"

            [http]
            [[http.request]]
            url = "https://api.anthropic.com/api/oauth/usage"

            [[surface]]
            id     = "cli"
            label  = "CLI"
            opt_in = false
            allowed_hosts = ["api.anthropic.com"]
            [[surface.auth]]
            type             = "credentials-file"
            path             = '{path}'
            token_json_path  = "claudeAiOauth.accessToken"
            expiry_json_path = "claudeAiOauth.expiresAt"
            {ping}
        "#,
            path = file.to_string_lossy(),
        );
        PluginManifest::from_str(&toml).expect("valid test manifest")
    }

    #[test]
    fn a_lapsed_auth_chain_with_a_renewing_ping_fails_terminally_with_the_renewal_text() {
        let dir = temp_dir("lapsed-cli-renews");
        let m = claude_like_manifest_with_a_lapsed_cli_token(&dir, true);
        let readings = fetch(&m, &["cli".to_string()], &no_options());
        assert_eq!(readings.len(), 1);
        assert_eq!(
            readings[0].error.as_deref(),
            Some("token expired — renews on the next claude run")
        );
        assert_eq!(
            readings[0].token_renewal,
            TokenRenewal::Lapsed {
                expires_at: 1_577_836_800, // 2020-01-01T00:00:00Z
            },
            "the declared expiry itself must reach the reading, not just a bool"
        );
        assert!(readings[0].windows.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_lapsed_auth_chain_without_a_renewing_ping_reads_as_no_credentials() {
        let dir = temp_dir("lapsed-cli-no-ping");
        let m = claude_like_manifest_with_a_lapsed_cli_token(&dir, false);
        let readings = fetch(&m, &["cli".to_string()], &no_options());
        assert_eq!(readings.len(), 1);
        assert_eq!(
            readings[0].error.as_deref(),
            Some(auth::NO_CREDENTIALS),
            "without a ping that can renew it, a lapsed token reads exactly like none at all"
        );
        assert_eq!(readings[0].token_renewal, TokenRenewal::No);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Two surfaces sharing one `[ping] renews_token = true` manifest: `cli`
    /// is `claude_like_manifest_with_a_lapsed_cli_token`'s own shape (a
    /// `credentials-file` step with `expiry_json_path`, already lapsed);
    /// `desktop` is an `env` step with no `expiry_json_path` at all and no
    /// credential ever set — Claude's real `desktop` surface reads its own
    /// separate credential the same way (a declared expiry only `cli`
    /// states), minus the Electron-specific machinery this test has no
    /// reason to exercise. Drives `SurfaceConfig::declares_token_expiry`
    /// through `fetch_surface` itself, not the pure helper alone: `perform`
    /// (the network call a real 401 would need) has no test harness in this
    /// module by design, so this proves the surface rule the way a lapsed
    /// chain can — a 401's own rewrite is covered separately, and only
    /// through the pure `unauthorized_outcome` (see
    /// `unauthorized_outcome_leaves_a_401_unchanged_on_a_surface_with_no_declared_expiry`).
    fn claude_like_manifest_with_a_renewable_and_a_non_renewable_surface(
        dir: &std::path::Path,
    ) -> PluginManifest {
        let file = dir.join("creds.json");
        std::fs::write(
            &file,
            r#"{"claudeAiOauth":{"accessToken":"tok-old","expiresAt":"2020-01-01T00:00:00Z"}}"#,
        )
        .unwrap();
        let toml = format!(
            r#"
            id         = "claude"
            name       = "Claude"
            menu_label = "Cl"
            order      = 20
            engine     = "http-api"
            requires_reader = ["keychain-expiry"]

            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode    = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "five_hour.utilization"
            resets_at_path    = "five_hour.resets_at"
            resets_at_format  = "iso8601"

            [http]
            [[http.request]]
            url = "https://api.anthropic.com/api/oauth/usage"

            [[surface]]
            id     = "cli"
            label  = "CLI"
            opt_in = false
            allowed_hosts = ["api.anthropic.com"]
            [[surface.auth]]
            type             = "credentials-file"
            path             = '{path}'
            token_json_path  = "claudeAiOauth.accessToken"
            expiry_json_path = "claudeAiOauth.expiresAt"

            [[surface]]
            id     = "desktop"
            label  = "Desktop"
            opt_in = true
            in_menu_bar = false
            allowed_hosts = ["api.anthropic.com"]
            [[surface.auth]]
            type = "env"
            var  = "TICKOVER_TEST_ENGINE_HTTP_NONRENEWABLE_DESKTOP_TOKEN"

            [ping]
            bin          = "claude"
            renews_token = true
        "#,
            path = file.to_string_lossy(),
        );
        PluginManifest::from_str(&toml).expect("valid test manifest")
    }

    #[test]
    fn only_the_surface_that_declares_a_token_expiry_carries_a_renewal_signal() {
        let dir = temp_dir("renewable-and-not");
        let m = claude_like_manifest_with_a_renewable_and_a_non_renewable_surface(&dir);
        // The fixture is the non-renewable half of this test's own claim, so
        // pin it directly rather than leave it implied by the desktop
        // surface's `env` step never naming `expiry_json_path`.
        assert!(m.surface[0].declares_token_expiry());
        assert!(!m.surface[1].declares_token_expiry());

        let readings = fetch(
            &m,
            &["cli".to_string(), "desktop".to_string()],
            &no_options(),
        );
        assert_eq!(readings.len(), 2);

        let cli = readings
            .iter()
            .find(|r| r.id == "claude-cli")
            .expect("cli reading");
        assert_eq!(
            cli.error.as_deref(),
            Some("token expired — renews on the next claude run")
        );
        assert_eq!(
            cli.token_renewal,
            TokenRenewal::Lapsed {
                expires_at: 1_577_836_800, // 2020-01-01T00:00:00Z
            },
            "cli declares expiry_json_path, so its lapsed chain is renewal-eligible"
        );

        // Desktop's own env var is never set, so this also reaches
        // `TokenRenewal::No` by the ordinary "no credential" path rather
        // than through the surface-eligibility gate — the gate itself is
        // pinned above and exercised for a 401 in
        // `unauthorized_outcome_leaves_a_401_unchanged_on_a_surface_with_no_declared_expiry`.
        // Asserted here anyway, alongside the concrete error text: a plugin
        // whose `[ping] renews_token` is true must still read this surface
        // as an ordinary missing credential, not as anything renewal-shaped.
        let desktop = readings
            .iter()
            .find(|r| r.id == "claude-desktop")
            .expect("desktop reading");
        assert_eq!(desktop.error.as_deref(), Some(auth::NO_CREDENTIALS));
        assert_eq!(
            desktop.token_renewal,
            TokenRenewal::No,
            "desktop declares no expiry at all, so it never carries a renewal \
             signal even under a plugin whose [ping] renews_token is true"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `perform`'s network path is the one part of this engine deliberately
    /// left untested (see this module's own docs) — including its 401 arm,
    /// which is why the rewrite it feeds is factored into
    /// `unauthorized_outcome` and tested directly here, pure.
    fn renewing_ping() -> PingConfig {
        PingConfig {
            bin: "claude".to_string(),
            args: Vec::new(),
            renews_token: true,
        }
    }

    #[test]
    fn unauthorized_outcome_rewrites_a_401_when_the_ping_renews_the_token() {
        let (message, renewal) =
            unauthorized_outcome(UNAUTHORIZED.to_string(), Some(&renewing_ping()), true, 42);
        assert_eq!(message, "token expired — renews on the next claude run");
        assert_eq!(renewal, TokenRenewal::Unauthorized { token_hash: 42 });
    }

    #[test]
    fn unauthorized_outcome_leaves_a_401_unchanged_without_a_renewing_ping() {
        let (message, renewal) = unauthorized_outcome(UNAUTHORIZED.to_string(), None, true, 42);
        assert_eq!(message, UNAUTHORIZED);
        assert_eq!(renewal, TokenRenewal::No);

        let non_renewing = PingConfig {
            bin: "claude".to_string(),
            args: Vec::new(),
            renews_token: false,
        };
        let (message, renewal) =
            unauthorized_outcome(UNAUTHORIZED.to_string(), Some(&non_renewing), true, 42);
        assert_eq!(message, UNAUTHORIZED);
        assert_eq!(renewal, TokenRenewal::No);
    }

    #[test]
    fn unauthorized_outcome_leaves_a_non_401_failure_unchanged_even_with_a_renewing_ping() {
        let (message, renewal) = unauthorized_outcome(
            "rate-limited (try later)".to_string(),
            Some(&renewing_ping()),
            true,
            42,
        );
        assert_eq!(message, "rate-limited (try later)");
        assert_eq!(
            renewal,
            TokenRenewal::No,
            "only a 401 is a token this app cannot help but a ping might"
        );
    }

    #[test]
    fn unauthorized_outcome_leaves_a_401_unchanged_when_the_token_came_from_a_non_expiring_step() {
        // Same renewing ping as `unauthorized_outcome_rewrites_a_401_...`,
        // but `from_expiring_step = false` — the token this 401 actually
        // named came from a step that never declared a lifetime for it (an
        // `env` fallback, say), so the ping's CLI run has nothing it can
        // renew. Must not be rewritten into text promising otherwise.
        let (message, renewal) =
            unauthorized_outcome(UNAUTHORIZED.to_string(), Some(&renewing_ping()), false, 42);
        assert_eq!(message, UNAUTHORIZED);
        assert_eq!(
            renewal,
            TokenRenewal::No,
            "a token that never came from an expiry-declaring step is never renewal-eligible"
        );
    }

    /// A two-step `cli` surface: `credentials-file` (declares
    /// `expiry_json_path`) first, a bare `env` fallback behind it.
    /// `lapsed` controls whether the file step's own credential has already
    /// expired — lapsed, it resolves Absent and the env step's token wins
    /// instead; fresh, it wins outright and the env step is never reached.
    /// Exists to drive `auth::resolve_token`'s `from_expiring_step` flag
    /// through both step kinds on one chain, into `unauthorized_outcome`,
    /// rather than asserting the flag alone.
    fn claude_like_two_step_cli_surface(
        dir: &std::path::Path,
        lapsed: bool,
    ) -> crate::plugin::manifest::SurfaceConfig {
        let file = dir.join("creds.json");
        let expires_at = if lapsed {
            "2020-01-01T00:00:00Z" // long past
        } else {
            "2099-01-01T00:00:00Z" // comfortably unexpired
        };
        std::fs::write(
            &file,
            format!(
                r#"{{"claudeAiOauth":{{"accessToken":"tok-file","expiresAt":"{expires_at}"}}}}"#
            ),
        )
        .unwrap();
        let toml = format!(
            r#"
            id         = "claude"
            name       = "Claude"
            menu_label = "Cl"
            order      = 20
            engine     = "http-api"
            requires_reader = ["keychain-expiry"]

            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode    = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "five_hour.utilization"
            resets_at_path    = "five_hour.resets_at"
            resets_at_format  = "iso8601"

            [http]
            [[http.request]]
            url = "https://api.anthropic.com/api/oauth/usage"

            [[surface]]
            id     = "cli"
            label  = "CLI"
            opt_in = false
            allowed_hosts = ["api.anthropic.com"]
            [[surface.auth]]
            type             = "credentials-file"
            path             = '{path}'
            token_json_path  = "claudeAiOauth.accessToken"
            expiry_json_path = "claudeAiOauth.expiresAt"
            [[surface.auth]]
            type = "env"
            var  = "TICKOVER_TEST_ENGINE_HTTP_TWO_STEP_ENV_FALLBACK"
        "#,
            path = file.to_string_lossy(),
        );
        let m = PluginManifest::from_str(&toml).expect("valid test manifest");
        m.surface.into_iter().next().expect("one surface")
    }

    #[test]
    fn a_401_on_a_token_from_the_env_fallback_behind_a_lapsed_step_keeps_the_plain_text() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = temp_dir("two-step-lapsed-then-env");
        let surface = claude_like_two_step_cli_surface(&dir, true);
        std::env::set_var("TICKOVER_TEST_ENGINE_HTTP_TWO_STEP_ENV_FALLBACK", "tok-env");
        let resolved = auth::resolve_token(&surface);
        std::env::remove_var("TICKOVER_TEST_ENGINE_HTTP_TWO_STEP_ENV_FALLBACK");
        let (token, from_expiring_step) =
            resolved.expect("the env fallback must still yield a token");
        assert_eq!(token, "tok-env");
        assert!(
            !from_expiring_step,
            "the token came from the env step, which declares no expiry"
        );

        let (message, renewal) = unauthorized_outcome(
            UNAUTHORIZED.to_string(),
            Some(&renewing_ping()),
            from_expiring_step,
            42,
        );
        assert_eq!(message, UNAUTHORIZED);
        assert_eq!(renewal, TokenRenewal::No);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_401_on_a_token_from_the_expiring_step_itself_is_rewritten() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = temp_dir("two-step-fresh-file");
        let surface = claude_like_two_step_cli_surface(&dir, false);
        let (token, from_expiring_step) =
            auth::resolve_token(&surface).expect("the file step yields its own token");
        assert_eq!(token, "tok-file");
        assert!(from_expiring_step);

        let (message, renewal) = unauthorized_outcome(
            UNAUTHORIZED.to_string(),
            Some(&renewing_ping()),
            from_expiring_step,
            42,
        );
        assert_eq!(message, "token expired — renews on the next claude run");
        assert_eq!(renewal, TokenRenewal::Unauthorized { token_hash: 42 });
        std::fs::remove_dir_all(&dir).ok();
    }

    fn win(
        role: ManifestRole,
        mode: PeriodMode,
        field: Option<&str>,
        assumed: Option<u64>,
    ) -> WindowConfig {
        WindowConfig {
            id: String::new(),
            label: "5H".to_string(),
            role,
            required: false,
            period: PeriodConfig {
                mode,
                field: field.map(str::to_string),
                assumed,
                unit: PeriodUnit::Minutes,
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

    // ── substitute / build_request ───────────────────────────────────────

    /// The windows a response reports, for the tests that expect it to report
    /// some.
    fn reported_windows(value: &Value, m: &PluginManifest) -> Vec<Window> {
        parse_usage(value, m).expect("this test's response reports at least one window")
    }

    /// Whether a response reported no window at all — a positive claim, not
    /// `windows.iter().all(|w| w.used_percent.is_none())`, which passes
    /// vacuously on an empty list and so tested nothing once unreported
    /// windows stopped being emitted.
    fn reports_nothing(value: &Value, m: &PluginManifest) -> bool {
        parse_usage(value, m).is_ok_and(|windows| windows.is_empty())
    }

    fn no_options() -> BTreeMap<String, bool> {
        BTreeMap::new()
    }

    fn no_values() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    #[test]
    fn substitute_replaces_token_and_version_placeholders() {
        let opts = no_options();
        assert_eq!(
            substitute("Bearer {token}", "tok-1", "9.9.9", &opts, &no_values()),
            "Bearer tok-1"
        );
        assert_eq!(
            substitute(
                "claude-code/{version}",
                "tok-1",
                "9.9.9",
                &opts,
                &no_values()
            ),
            "claude-code/9.9.9"
        );
        assert_eq!(
            substitute("{token}-{version}", "tok-1", "9.9.9", &opts, &no_values()),
            "tok-1-9.9.9",
            "a header naming both placeholders substitutes both"
        );
        assert_eq!(
            substitute("no placeholders", "tok-1", "9.9.9", &opts, &no_values()),
            "no placeholders"
        );
    }

    #[test]
    fn substitute_also_replaces_option_placeholders() {
        let mut opts = BTreeMap::new();
        opts.insert("include_beta".to_string(), true);
        assert_eq!(
            substitute(
                "Bearer {token}; beta={option.include_beta}",
                "tok-1",
                "9.9.9",
                &opts,
                &no_values()
            ),
            "Bearer tok-1; beta=true",
            "a header can name {{token}} and {{option.<key>}} together"
        );
        assert_eq!(
            substitute(
                "beta={option.unknown_key}",
                "tok-1",
                "9.9.9",
                &opts,
                &no_values()
            ),
            "beta={option.unknown_key}",
            "an undeclared option key is left untouched"
        );
    }

    #[test]
    fn build_request_substitutes_every_header_and_carries_url_timeout() {
        let m = claude_like_manifest();
        let req = &m.http.as_ref().unwrap().request[0];
        let (url, headers, timeout) =
            build_request(req, "tok-1", "9.9.9", &no_options(), &no_values());

        assert_eq!(url, "https://api.anthropic.com/api/oauth/usage");
        assert_eq!(timeout, Duration::from_secs(8));
        let get = |k: &str| {
            headers
                .iter()
                .find(|(hk, _)| hk == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("Authorization"), Some("Bearer tok-1"));
        assert_eq!(get("anthropic-beta"), Some("oauth-2025-04-20"));
        assert_eq!(get("User-Agent"), Some("claude-code/9.9.9"));
    }

    #[test]
    fn build_request_substitutes_option_placeholders_in_the_url() {
        let req = HttpRequestConfig {
            url: "https://example.com/usage?beta={option.include_beta}".to_string(),
            timeout_secs: 8,
            method: HttpMethod::Get,
            body: None,
            headers: HashMap::new(),
        };
        let mut opts = BTreeMap::new();
        opts.insert("include_beta".to_string(), true);
        let (url, _headers, _timeout) = build_request(&req, "tok-1", "9.9.9", &opts, &no_values());
        assert_eq!(url, "https://example.com/usage?beta=true");
    }

    #[test]
    fn build_request_never_substitutes_token_or_version_into_the_url() {
        // Defence in depth: {token}/{version} must stay confined to headers,
        // never leak into the URL (see module docs / build_request docs).
        let req = HttpRequestConfig {
            url: "https://example.com/usage?tok={token}&v={version}".to_string(),
            timeout_secs: 8,
            method: HttpMethod::Get,
            body: None,
            headers: HashMap::new(),
        };
        let (url, _headers, _timeout) =
            build_request(&req, "tok-1", "9.9.9", &no_options(), &no_values());
        assert_eq!(url, "https://example.com/usage?tok={token}&v={version}");
    }

    #[test]
    fn build_body_substitutes_the_same_placeholders_as_a_header() {
        // Not a JSON object: a body shaped like one hits the naive scanner's
        // leading-brace limitation (see `PluginManifest::validate`'s
        // `swallowed_placeholder`, which refuses that shape at load time —
        // now for header values and the URL too, not just the body — rather
        // than let it reach here half-substituted). This shape — no leading
        // `{` before the first placeholder — is exactly what the scanner
        // (shared with headers) resolves correctly.
        let mut opts = BTreeMap::new();
        opts.insert("plugin".to_string(), true);
        let req = HttpRequestConfig {
            url: "https://example.com/usage".to_string(),
            timeout_secs: 8,
            method: HttpMethod::Post,
            body: Some("plugin={option.plugin}&auth=Bearer {token}".to_string()),
            headers: HashMap::new(),
        };
        let body = build_body(&req, "tok-1", "9.9.9", &opts, &no_values());
        assert_eq!(body.as_deref(), Some("plugin=true&auth=Bearer tok-1"));
    }

    #[test]
    fn build_body_is_none_when_the_manifest_declares_no_body() {
        let req = HttpRequestConfig {
            url: "https://example.com/usage".to_string(),
            timeout_secs: 8,
            method: HttpMethod::Get,
            body: None,
            headers: HashMap::new(),
        };
        assert_eq!(
            build_body(&req, "tok-1", "9.9.9", &no_options(), &no_values()),
            None
        );
    }

    // ── resolve_version ──────────────────────────────────────────────────

    #[test]
    fn resolve_version_falls_back_when_no_file_exists() {
        let cfg = HttpVersionConfig {
            files: vec![
                "/nonexistent/one.json".to_string(),
                "/nonexistent/two.json".to_string(),
            ],
            json_path: "version".to_string(),
            fallback: "2.1.78".to_string(),
        };
        assert_eq!(resolve_version(&cfg), "2.1.78");
    }

    #[test]
    fn resolve_version_reads_the_first_matching_file() {
        let dir = temp_dir("version");
        let missing = dir.join("missing.json");
        let present = dir.join("package.json");
        std::fs::write(&present, json!({ "version": "1.2.3" }).to_string()).unwrap();

        let cfg = HttpVersionConfig {
            files: vec![
                missing.to_string_lossy().into_owned(),
                present.to_string_lossy().into_owned(),
            ],
            json_path: "version".to_string(),
            fallback: "0.0.0".to_string(),
        };
        assert_eq!(resolve_version(&cfg), "1.2.3");
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── json_path_get ────────────────────────────────────────────────────

    #[test]
    fn json_path_get_picks_an_array_element_by_a_field_of_its_own() {
        // The shape Codex answers with, taken from a live response.
        let body = json!({
            "additional_rate_limits": [
                { "limit_name": "code_review", "rate_limit": { "primary_window": { "used_percent": 3 } } },
                { "limit_name": "GPT-5.3-Codex-Spark",
                  "metered_feature": "codex_bengalfox",
                  "rate_limit": {
                      "primary_window": { "used_percent": 0, "limit_window_seconds": 604800, "reset_at": 1787693714 },
                      "secondary_window": null } }
            ]
        });
        let at = |p| json_path_get(&body, p);

        // By name, through a value with two dots in it — the reason paths are
        // not split inside brackets.
        assert_eq!(
            at("additional_rate_limits[limit_name=GPT-5.3-Codex-Spark].rate_limit.primary_window.limit_window_seconds")
                .and_then(Value::as_u64),
            Some(604_800)
        );
        // By position, for a provider whose array order does mean something.
        assert_eq!(
            at("additional_rate_limits[0].limit_name").and_then(Value::as_str),
            Some("code_review")
        );
        // A name nothing answers to, an index past the end, a selector on an
        // object: no match, which reads as a window with nothing in it.
        assert_eq!(
            at("additional_rate_limits[limit_name=GPT-9-Nope].rate_limit"),
            None
        );
        assert_eq!(at("additional_rate_limits[7].limit_name"), None);
        assert_eq!(
            at("additional_rate_limits[limit_name=x].rate_limit[0]"),
            None
        );
    }

    #[test]
    fn a_path_selector_trims_both_halves_the_way_for_each_where_does() {
        // A human aligning `=` signs writes `limits[kind = weekly_scoped]`,
        // not `limits[kind=weekly_scoped]` — `pick` has to accept the spaced
        // form the same way `element_matches` already does for
        // `for_each_where`, or a manifest that looks right stops matching.
        let body = json!({
            "limits": [{ "kind": "weekly_scoped", "used_percent": 40 }]
        });
        assert_eq!(
            json_path_get(&body, "limits[kind = weekly_scoped].used_percent")
                .and_then(Value::as_u64),
            Some(40),
            "spaces around `=` in a path selector must not stop the match"
        );
    }

    #[test]
    fn a_selector_matches_a_number_or_a_boolean_by_the_text_it_prints() {
        // A manifest is TOML, so both halves of `field = wanted` arrive here as
        // strings whatever the JSON holds. `field_says` is documented to
        // compare against the field's *text* for exactly that reason, and this
        // is the half no other test covers: a clippy suggestion to compare the
        // `Value` directly (`*v == wanted`) type-checks, reads as a
        // simplification, and silently stops matching every non-string field —
        // `Value == &str` is true only for `Value::String`.
        let body = json!({
            "limits": [
                { "tier": 1, "scoped": false, "id": "five_hour" },
                { "tier": 2, "scoped": true,  "id": "seven_day" }
            ]
        });
        let at = |p| json_path_get(&body, p);

        assert_eq!(
            at("limits[tier=2].id").and_then(Value::as_str),
            Some("seven_day")
        );
        assert_eq!(
            at("limits[scoped=true].id").and_then(Value::as_str),
            Some("seven_day")
        );
        assert_eq!(
            at("limits[scoped=false].id").and_then(Value::as_str),
            Some("five_hour")
        );
        // The same rule through the enumeration filter, which shares the
        // predicate so that the two can never answer differently.
        let elements = body["limits"].as_array().expect("array");
        assert!(element_matches(&elements[1], Some("tier = 2")));
        assert!(!element_matches(&elements[0], Some("tier = 2")));
        // A number that only looks equal: text comparison, not numeric.
        assert_eq!(at("limits[tier=2.0].id"), None);
    }

    #[test]
    fn a_malformed_selector_finds_nothing_and_breaks_nothing() {
        // A path comes out of a manifest a third party wrote. Every shape of
        // bracket has to end in "no match" — never a panic, and never a
        // *different* element than the one asked for.
        let body = json!({
            "list": [ { "n": "zero" }, { "n": "один" } ],
            // A provider is allowed to call a field this.
            "counts[daily]": 7,
            "plain": { "inner": 1 }
        });
        for path in [
            "list[",
            "list]",
            "list[]",
            "list[=]",
            "list[n=]",
            "list[=zero]",
            "list[0",
            "list[-1]",
            "list[99999999999999999999]",
            "list[n=nothing]",
            "plain[0]",
            "plain[k=v]",
            "list[n=один].missing",
            "list[[0]]",
        ] {
            assert_eq!(
                json_path_get(&body, path),
                None,
                "`{path}` must match nothing"
            );
        }
        // …while the shapes that are well formed still work, including a
        // multi-byte value and a key that merely contains a bracket.
        assert_eq!(
            json_path_get(&body, "list[n=один].n").and_then(Value::as_str),
            Some("один")
        );
        assert_eq!(
            json_path_get(&body, "counts[daily]").and_then(Value::as_u64),
            Some(7)
        );
        assert_eq!(
            json_path_get(&body, "plain.inner").and_then(Value::as_u64),
            Some(1)
        );
    }

    #[test]
    fn the_two_things_this_path_syntax_cannot_say_it_says_nothing_about() {
        // Stated rather than discovered later. `].` inside a value ends the
        // selector early — the `]` closes it and the `.` splits the path —
        // and selectors do not chain. Both must come out as "no match", never
        // as a match on something else.
        let body = json!({ "list": [ { "n": "a].b", "v": 1 }, { "n": "a]b", "v": 2 },
                                     { "n": "a", "v": 3 } ],
                           "grid": [ [ { "v": 4 } ] ] });
        assert_eq!(
            json_path_get(&body, "list[n=a].b].v"),
            None,
            "a value with `].` in it cannot be selected"
        );
        assert_eq!(
            json_path_get(&body, "list[n=a]b].v").and_then(Value::as_u64),
            Some(2),
            "a plain `]` is fine: the one that closes the selector is the last"
        );
        assert_eq!(
            json_path_get(&body, "grid[0][0].v"),
            None,
            "one selector per segment; chaining finds nothing rather than the wrong thing"
        );
        // The caveat, said out loud: when a value is cut short this way, the
        // shortened form may itself be a real element — and that one is what
        // gets selected. Nothing here can tell the two apart.
        assert_eq!(
            json_path_get(&body, "list[n=a].v").and_then(Value::as_u64),
            Some(3)
        );
    }

    #[test]
    fn a_path_without_a_selector_is_split_exactly_as_before() {
        assert_eq!(segments("a.b.c"), vec!["a", "b", "c"]);
        assert_eq!(segments("solo"), vec!["solo"]);
        assert_eq!(
            segments("list[name=x.y].inner"),
            vec!["list[name=x.y]", "inner"],
            "a dot inside a selector belongs to the value, not to the path"
        );
    }

    #[test]
    fn a_model_quota_cannot_take_the_subscription_quotas_place() {
        // The defect this row exists to not repeat: a `codex exec` run wrote
        // the GPT-5.3-Codex-Spark limit into a rollout log, the reader took
        // the newest line, and the panel showed 0% used while the real weekly
        // window sat at 69%. Here the two live at different paths and in
        // different roles, so neither can be read as the other.
        let m =
            PluginManifest::from_str(crate::plugin::seed::builtin_contents("codex.toml").unwrap())
                .expect("the shipped codex manifest");
        let body = json!({
            "email": "you@example.com",
            "plan_type": "pro",
            "rate_limit": {
                "primary_window": null,
                "secondary_window": { "used_percent": 69, "limit_window_seconds": 604800, "reset_at": 1787207494 }
            },
            "additional_rate_limits": [
                { "limit_name": "GPT-5.3-Codex-Spark",
                  "metered_feature": "codex_bengalfox",
                  "rate_limit": {
                      "primary_window": { "used_percent": 0, "limit_window_seconds": 604800, "reset_at": 1787693714 },
                      "secondary_window": null } }
            ]
        });
        let windows = reported_windows(&body, &m);

        let weekly = windows.iter().find(|w| w.label == "WK").expect("WK window");
        assert_eq!(
            weekly.used_percent,
            Some(69.0),
            "the subscription's own number, not the model's"
        );
        assert_eq!(weekly.role, crate::model::Role::Secondary);

        assert!(
            windows.iter().all(|w| w.label != "5H"),
            "Codex reported no 5-hour window at all, so there is no 5-hour row"
        );

        let spark = windows
            .iter()
            .find(|w| w.label == "GPT-5.3-Codex-Spark")
            .expect("model window");
        assert_eq!(spark.used_percent, Some(0.0));
        assert_eq!(spark.resets_at, Some(1_787_693_714));
        assert_eq!(spark.period_minutes, Some(10_080));
        assert_eq!(spark.role, crate::model::Role::Extra);

        // And the two accessors every headline reading goes through — the
        // menu-bar pill, the tray title, the auto-ping — cannot reach it.
        let reading = crate::model::ProviderReading {
            id: "codex".into(),
            name: "Codex".into(),
            short: "Cx".into(),
            tag: None,
            account: None,
            windows,
            error: None,
            token_renewal: TokenRenewal::No,
            quota_status: None,
            balances: Vec::new(),
            in_menu_bar: true,
            bare_when_sole: false,
        };
        assert_eq!(
            reading.secondary_window().and_then(|w| w.used_percent),
            Some(69.0)
        );
        assert_eq!(reading.primary_window().and_then(|w| w.used_percent), None);
    }

    #[test]
    fn a_model_quota_that_the_provider_stops_reporting_leaves_no_row() {
        // Codex renames a model, or drops it: the selector matches nothing and
        // the row has no percentage, which is what keeps it off the panel
        // (`src/main.rs` draws only windows that reported one). It must not
        // fall back to some other element of the array.
        let m =
            PluginManifest::from_str(crate::plugin::seed::builtin_contents("codex.toml").unwrap())
                .expect("the shipped codex manifest");
        let body = json!({
            "rate_limit": { "primary_window": { "used_percent": 12, "limit_window_seconds": 18000, "reset_at": 1787207494 } },
            "additional_rate_limits": [
                { "limit_name": "GPT-6-Something-Else",
                  "rate_limit": { "primary_window": { "used_percent": 88, "limit_window_seconds": 604800, "reset_at": 1 } } }
            ]
        });
        let windows = reported_windows(&body, &m);
        assert!(
            windows.iter().all(|w| w.label != "GPT-5.3-Codex-Spark"),
            "88% belongs to a different model, so this row is not reported at all"
        );
        assert_eq!(
            windows
                .iter()
                .find(|w| w.label == "5H")
                .unwrap()
                .used_percent,
            Some(12.0)
        );
    }

    #[test]
    fn json_path_get_walks_nested_dotted_paths() {
        let v = json!({ "five_hour": { "utilization": 34.5 } });
        assert_eq!(
            json_path_get(&v, "five_hour.utilization").and_then(Value::as_f64),
            Some(34.5)
        );
        assert_eq!(json_path_get(&v, "five_hour.missing"), None);
        assert_eq!(json_path_get(&v, "missing.at.all"), None);
    }

    // ── parse_balances / read_amount ─────────────────────────────────────

    /// A manifest with one balance entry, `body` being everything under the
    /// `[[balances]]` header.
    fn balance_manifest(body: &str) -> PluginManifest {
        PluginManifest::from_str(&format!(
            r#"
            id         = "sample"
            name       = "Sample"
            menu_label = "Sa"
            order      = 1
            engine     = "http-api"
            requires_reader = ["reading-balances"]

            [[balances]]
            {body}

            [http]
            [[http.request]]
            url = "https://example.com/usage"

            [[surface]]
            id            = "default"
            label         = "Default"
            allowed_hosts = ["example.com"]
            [[surface.auth]]
            type            = "credentials-file"
            path            = "~/.sample/auth.json"
            token_json_path = "token"
            "#
        ))
        .expect("valid balance manifest")
    }

    #[test]
    fn a_money_figure_needs_its_whole_triplet_or_it_is_not_a_figure() {
        let m = balance_manifest(
            "label = \"Spend\"\n[balances.used]\nkind = \"money-minor\"\n\
             amount_path = \"spend.used.amount_minor\"\n\
             currency_path = \"spend.used.currency\"\n\
             exponent_path = \"spend.used.exponent\"",
        );

        let whole = json!({ "spend": { "used": { "amount_minor": 1999, "currency": "USD", "exponent": 2 } } });
        assert_eq!(
            parse_balances(&whole, &m)[0].used,
            Some(crate::model::BalanceAmount::Money {
                minor: 1999,
                currency: "USD".into(),
                exponent: 2
            })
        );

        // 1999 of what, at what scale? Without the other two the number is not
        // a smaller truth, it is a different one — so no row at all.
        let no_currency = json!({ "spend": { "used": { "amount_minor": 1999, "exponent": 2 } } });
        assert!(parse_balances(&no_currency, &m).is_empty());
        let no_exponent =
            json!({ "spend": { "used": { "amount_minor": 1999, "currency": "USD" } } });
        assert!(parse_balances(&no_exponent, &m).is_empty());

        // A scale no currency has is a response that changed shape; drawing it
        // would move the figure by orders of magnitude.
        let absurd = json!({ "spend": { "used": { "amount_minor": 1999, "currency": "USD", "exponent": 42 } } });
        assert!(parse_balances(&absurd, &m).is_empty());
    }

    #[test]
    fn a_stated_percentage_is_read_and_a_missing_one_is_never_computed() {
        let m = balance_manifest(
            "label = \"Spend\"\n[balances.used]\nkind = \"number\"\npath = \"used\"\n\
             [balances.cap]\nkind = \"number\"\npath = \"cap\"\n\
             [balances.source]\npercent_path = \"percent\"",
        );

        let stated = json!({ "used": 25.0, "cap": 100.0, "percent": 25.0 });
        assert_eq!(parse_balances(&stated, &m)[0].stated_percent, Some(25.0));

        // The same body without the provider's own percentage: used and cap are
        // both there and the division is obvious, and the answer is still
        // `None`. A figure this app derived would look on screen exactly like
        // one the provider published.
        let unstated = json!({ "used": 25.0, "cap": 100.0 });
        assert_eq!(parse_balances(&unstated, &m)[0].stated_percent, None);
    }

    #[test]
    fn a_stated_percentage_is_passed_through_untouched() {
        let m = balance_manifest(
            "label = \"Spend\"\n[balances.remaining]\nkind = \"number\"\npath = \"left\"\n\
             [balances.source]\npercent_path = \"percent\"",
        );
        // Neither rounded nor clamped: 25.5 rounded to 26, or 101 clamped to
        // 100, is a figure the provider never sent sitting beside figures it
        // did. Out-of-range is the provider's statement to answer for.
        for stated in [25.5_f64, 101.0, -1.0] {
            let body = json!({ "left": 1.0, "percent": stated });
            assert_eq!(parse_balances(&body, &m)[0].stated_percent, Some(stated));
        }
    }

    #[test]
    fn a_cap_of_zero_is_carried_through_rather_than_discarded() {
        let m = balance_manifest(
            "label = \"Spend\"\n[balances.used]\nkind = \"number\"\npath = \"used\"\n\
             [balances.cap]\nkind = \"number\"\npath = \"cap\"",
        );
        let rows = parse_balances(&json!({ "used": 3.0, "cap": 0.0 }), &m);
        // Dropping it would print the decision "there is no cap", which no
        // provider stated — as unmeasured as deciding the zero is a real
        // ceiling. Nothing is inferred from it either: no ratio is computed
        // from any cap, so a zero costs nothing to carry.
        assert_eq!(
            rows[0].cap,
            Some(crate::model::BalanceAmount::Number {
                value: 0.0,
                unit: None
            })
        );
    }

    #[test]
    fn a_declared_unit_travels_with_the_number_it_labels() {
        let m = balance_manifest(
            "label = \"Credits\"\n[balances.remaining]\nkind = \"number\"\npath = \"left\"\n\
             unit_label = \"credits\"",
        );
        assert_eq!(
            parse_balances(&json!({ "left": 12.0 }), &m)[0].remaining,
            Some(crate::model::BalanceAmount::Number {
                value: 12.0,
                unit: Some("credits".into())
            }),
            "a manifest that names the unit must reach the row that prints it"
        );

        // And a figure whose manifest names none carries none — Grok's do not,
        // and inventing one here would be the app supplying a fact.
        let bare = balance_manifest(
            "label = \"Credits\"\n[balances.remaining]\nkind = \"number\"\npath = \"left\"",
        );
        assert_eq!(
            parse_balances(&json!({ "left": 12.0 }), &bare)[0].remaining,
            Some(crate::model::BalanceAmount::Number {
                value: 12.0,
                unit: None
            })
        );
    }

    #[test]
    fn a_balance_that_resolved_to_nothing_emits_no_row() {
        let m = balance_manifest(
            "label = \"Credits\"\n[balances.remaining]\nkind = \"text\"\npath = \"credits.balance\"\n\
             [balances.source]\nperiod_end_path = \"period_end\"\nperiod_end_format = \"iso8601\"",
        );

        // A period end and nothing else: every month has one, and a row would
        // announce a balance whose size nobody stated.
        let only_period = json!({ "period_end": "2026-09-01T00:00:00Z" });
        assert!(parse_balances(&only_period, &m).is_empty());

        let with_text =
            json!({ "credits": { "balance": "$5.00" }, "period_end": "2026-09-01T00:00:00Z" });
        let rows = parse_balances(&with_text, &m);
        assert_eq!(
            rows[0].remaining,
            Some(crate::model::BalanceAmount::Text("$5.00".into()))
        );
        assert_eq!(rows[0].period_end, Some(1_788_220_800));
    }

    #[test]
    fn provider_text_reaches_the_row_sanitised() {
        let m = balance_manifest(
            "label = \"Credits\"\n[balances.remaining]\nkind = \"text\"\npath = \"credits.balance\"",
        );
        let hostile = json!({ "credits": { "balance": "  $5\u{202e}\n\nleft  " } });
        match &parse_balances(&hostile, &m)[0].remaining {
            Some(crate::model::BalanceAmount::Text(s)) => {
                assert!(
                    !s.contains('\u{202e}'),
                    "a bidi override must not reach the panel: {s:?}"
                );
                assert!(
                    !s.contains('\n'),
                    "newlines must not reach the panel: {s:?}"
                );
            }
            other => panic!("expected sanitised text, got {other:?}"),
        }
    }

    #[test]
    fn a_balance_key_is_the_declared_entry_not_the_label() {
        let m = balance_manifest(
            "id = \"credits\"\nlabel = \"Credits\"\n\
             [balances.remaining]\nkind = \"text\"\npath = \"b\"",
        );
        let rows = parse_balances(&json!({ "b": "$5" }), &m);
        // The label is a caption and may be reworded on any manifest bump; the
        // key is what the row reconciler addresses this row by.
        assert_eq!(rows[0].key, "credits:");
    }

    // ── parse_usage / build_window ───────────────────────────────────────

    #[test]
    fn parse_usage_reads_both_windows_from_the_real_response_shape() {
        let m = claude_like_manifest();
        let body = json!({
            "five_hour": { "utilization": 34.5, "resets_at": "2026-01-01T00:00:00Z" },
            "seven_day": { "utilization": 61,   "resets_at": "2026-01-01T02:00:00+02:00" },
        });
        let windows = reported_windows(&body, &m);
        assert_eq!(windows.len(), 2);

        let five = windows.iter().find(|w| w.label == "5H").expect("5H window");
        assert_eq!(five.used_percent, Some(34.5));
        assert_eq!(five.resets_at, Some(NY2026));
        assert_eq!(five.period_minutes, Some(300), "period.mode = assumed");

        let week = windows.iter().find(|w| w.label == "WK").expect("WK window");
        assert_eq!(
            week.used_percent,
            Some(61.0),
            "integer utilization must parse"
        );
        assert_eq!(
            week.resets_at,
            Some(NY2026),
            "offset timestamps normalize to UTC"
        );
        assert_eq!(week.period_minutes, Some(10080), "period.mode = assumed");
    }

    #[test]
    fn parse_usage_clamps_utilization_to_0_100() {
        let m = claude_like_manifest();
        let body = json!({
            "five_hour": { "utilization": 132.5 },
            "seven_day": { "utilization": -4.0 },
        });
        let windows = reported_windows(&body, &m);
        assert_eq!(
            windows
                .iter()
                .find(|w| w.label == "5H")
                .unwrap()
                .used_percent,
            Some(100.0)
        );
        assert_eq!(
            windows
                .iter()
                .find(|w| w.label == "WK")
                .unwrap()
                .used_percent,
            Some(0.0)
        );
    }

    #[test]
    fn the_shipped_antigravity_manifest_reads_its_quota_summary_shape() {
        // The end-to-end check the golden in `manifest_corpus` cannot make: not
        // that the manifest parses, but that its bucketId selectors resolve
        // against the real response shape and its remaining fractions
        // complement correctly. The buckets inside each group are ordered
        // 5h-then-weekly here, the reverse of the manifest's window order, to
        // prove the rows are addressed by bucketId and not by array position.
        let m = PluginManifest::from_str(include_str!("../../plugins/antigravity.toml"))
            .expect("antigravity.toml is valid");
        let body = json!({
            "groups": [
                {
                    "displayName": "Gemini Models",
                    "buckets": [
                        { "bucketId": "gemini-5h",     "remainingFraction": 0.75, "resetTime": "2026-01-01T00:00:00Z" },
                        { "bucketId": "gemini-weekly", "remainingFraction": 0.5,  "resetTime": "2026-01-01T00:00:00Z" },
                    ],
                },
                {
                    "displayName": "Claude and GPT models",
                    "buckets": [
                        { "bucketId": "3p-5h",     "remainingFraction": 1.0,  "resetTime": "2026-01-01T00:00:00Z" },
                        { "bucketId": "3p-weekly", "remainingFraction": 0.25, "resetTime": "2026-01-01T00:00:00Z" },
                    ],
                },
            ],
        });
        let windows = reported_windows(&body, &m);
        assert_eq!(windows.len(), 4, "all four buckets resolve");
        let used = |id: &str| {
            windows
                .iter()
                .find(|w| w.key.contains(id))
                .unwrap_or_else(|| panic!("{id}"))
                .used_percent
        };
        // (1 − remaining)·100, clamped: what is left, complemented into spent.
        // Values chosen to land on exact binary fractions — the complement is a
        // real float op, and 0.8 would arrive as 19.9999…, which is the panel's
        // rounding to make, not this test's to hide.
        assert_eq!(used("gemini-5h"), Some(25.0));
        assert_eq!(used("gemini-wk"), Some(50.0));
        assert_eq!(
            used("3p-5h"),
            Some(0.0),
            "a full remaining fraction is nothing spent"
        );
        assert_eq!(used("3p-wk"), Some(75.0));
    }

    #[test]
    fn an_antigravity_bucket_the_response_omits_at_zero_is_no_window() {
        // proto3 drops a zero field, so an exhausted bucket arrives with no
        // remainingFraction key. This reads as "did not say" (no row), never
        // as "100% spent". Here gemini-5h's fraction is gone.
        let m = PluginManifest::from_str(include_str!("../../plugins/antigravity.toml"))
            .expect("antigravity.toml is valid");
        let body = json!({
            "groups": [
                {
                    "displayName": "Gemini Models",
                    "buckets": [
                        { "bucketId": "gemini-5h",     "resetTime": "2026-01-01T00:00:00Z" },
                        { "bucketId": "gemini-weekly", "remainingFraction": 0.5, "resetTime": "2026-01-01T00:00:00Z" },
                    ],
                },
            ],
        });
        let windows = reported_windows(&body, &m);
        assert!(
            !windows.iter().any(|w| w.key.contains("gemini-5h")),
            "a bucket with no fraction is not a window"
        );
        assert!(
            windows.iter().any(|w| w.key.contains("gemini-wk")),
            "the stated one still reads"
        );
    }

    #[test]
    fn a_window_the_response_does_not_report_is_not_emitted_at_all() {
        // It used to be emitted with every field `None`, which the panel then
        // filtered out again on its way to the screen — so the row said "this
        // window exists and we know nothing about it" to everything upstream
        // of the filter, including the menu-bar pill and the auto-ping, while
        // the response had said "there is no such window".
        let m = claude_like_manifest();
        let body = json!({ "five_hour": { "utilization": 12.0 } });
        let windows = reported_windows(&body, &m);

        assert_eq!(windows.len(), 1, "only the window the response reported");
        assert_eq!(windows[0].label, "5H");
        assert_eq!(windows[0].used_percent, Some(12.0));
    }

    #[test]
    fn the_shipped_manifests_against_the_shapes_their_providers_really_send() {
        // Synthetic manifests prove the rule; these prove the two files that
        // ship with the app say what was meant, against bodies copied from
        // live responses.
        let codex = PluginManifest::from_str(
            crate::plugin::seed::builtin_contents("codex.toml").expect("shipped"),
        )
        .expect("the shipped codex manifest");

        // Codex on a pro plan: no 5-hour window exists at all, and the weekly
        // one arrives in the slot named `primary_window`.
        let pro = json!({
            "plan_type": "pro",
            "rate_limit": {
                "primary_window": { "used_percent": 68, "limit_window_seconds": 604800, "reset_at": 1787207494u64 },
                "secondary_window": null
            }
        });
        let windows =
            parse_usage(&pro, &codex).expect("the weekly window is there, in the other slot");
        assert_eq!(
            windows.len(),
            1,
            "one honest row, not one row and one blank"
        );
        assert_eq!(windows[0].label, "WK");
        assert_eq!(windows[0].used_percent, Some(68.0));

        // The same provider with nothing in either slot. Neither window is
        // marked `required` here — deliberately, since a window Codex has
        // stopped reporting because it is empty is exactly the state this
        // provider gets into — so what catches this is the older rule: a
        // reading with nothing in it at all is not a plan without limits.
        // Both of this provider's windows can be empty at once — in the hours
        // after a weekly reset, with nothing spent since — and Codex reports
        // an empty window by not reporting it. So this body is not an error:
        // it is the state the auto-ping exists to end, and refusing it would
        // replace the provider with an error message and stop the ping in the
        // one state that needs it. Neither window is `required` for exactly
        // this reason.
        let empty = json!({ "plan_type": "pro", "rate_limit": { "primary_window": null, "secondary_window": null } });
        assert_eq!(
            parse_usage(&empty, &codex).expect("an empty account is not a broken response"),
            Vec::new(),
            "no rows, and no error either"
        );

        let claude = PluginManifest::from_str(
            crate::plugin::seed::builtin_contents("claude.toml").expect("shipped"),
        )
        .expect("the shipped claude manifest");
        let both = json!({
            "five_hour": { "utilization": 2.0, "resets_at": "2026-08-20T14:40:00Z" },
            "seven_day": { "utilization": 41.0, "resets_at": "2026-08-24T00:00:00Z" }
        });
        assert_eq!(parse_usage(&both, &claude).expect("both windows").len(), 2);

        // Claude sends both for every account, so half a response is a
        // changed endpoint. This is stricter than the rule it replaces, which
        // only complained when *nothing* parsed — and the strictness is the
        // point: half a response drawn confidently is a row that reads as
        // "nothing used".
        assert_eq!(
            parse_usage(&json!({ "five_hour": { "utilization": 2.0 } }), &claude).unwrap_err(),
            "no \"WK\" window in the response"
        );
    }

    #[test]
    fn only_a_required_window_going_missing_is_a_refusal() {
        // A manifest that declares no invariant gets no error, however little
        // comes back. "Nothing resolved, so the response must be broken" is a
        // rule that was tried here and removed: it is false for Codex, whose
        // windows can all be legitimately absent at once, and it cost the
        // whole provider — see `crate::plugin::collect_windows`.
        let optional = claude_like_manifest();
        assert_eq!(
            parse_usage(&json!({}), &optional).expect("nothing declared, nothing promised"),
            Vec::new()
        );

        let mut strict = claude_like_manifest();
        strict.windows[1].required = true; // the weekly one
        assert_eq!(
            parse_usage(&json!({ "five_hour": { "utilization": 1.0 } }), &strict).unwrap_err(),
            "no \"WK\" window in the response",
            "a response missing a window this provider always sends is the provider being wrong"
        );

        // And when nothing arrived at all, the message does not claim the
        // other windows did: naming one of them would send the author looking
        // for a difference that isn't there.
        assert_eq!(
            parse_usage(&json!({}), &strict).unwrap_err(),
            "no limit data in response"
        );

        let whole = parse_usage(
            &json!({ "five_hour": { "utilization": 1.0 }, "seven_day": { "utilization": 2.0 } }),
            &strict,
        )
        .expect("both windows reported");
        assert_eq!(whole.len(), 2);
    }

    #[test]
    fn build_window_unix_format_reads_an_integer_timestamp() {
        let w = win(ManifestRole::Primary, PeriodMode::Assumed, None, Some(300));
        let body = json!({ "used_percent": 10.0, "resets_at": 1_800_000_000 });
        let out = build_window(0, &w, &body).expect("the response reports this window");
        assert_eq!(out.used_percent, Some(10.0));
        assert_eq!(out.resets_at, Some(1_800_000_000));
        assert_eq!(out.period_minutes, Some(300));
    }

    #[test]
    fn build_window_period_from_field_reads_the_response_body() {
        let w = win(
            ManifestRole::Primary,
            PeriodMode::FromField,
            Some("window_minutes"),
            None,
        );
        let body = json!({ "used_percent": 10.0, "window_minutes": 45 });
        assert_eq!(
            build_window(0, &w, &body).expect("reported").period_minutes,
            Some(45)
        );
    }

    #[test]
    fn a_reset_time_without_a_usage_figure_is_not_a_window() {
        // The percentage is what makes a window worth a row; a reset time
        // beside it and nothing else is a half-read response, and used to
        // present as a window with `resets_at: None` — the same shape as a
        // fully missing one, arrived at by explicitly dropping the fields that
        // *had* parsed. Now there is no window to half-populate.
        let w = win(ManifestRole::Primary, PeriodMode::Assumed, None, Some(300));
        assert_eq!(
            build_window(0, &w, &json!({ "resets_at": 1_800_000_000 })),
            None
        );

        // Including when the period is one the response states rather than one
        // the manifest assumes: a length without a figure is still not a
        // window.
        let from_field = win(
            ManifestRole::Primary,
            PeriodMode::FromField,
            Some("window_minutes"),
            None,
        );
        assert_eq!(
            build_window(0, &from_field, &json!({ "window_minutes": 45 })),
            None
        );
    }

    /// A window pointed at a remaining fraction instead of a spent percent —
    /// Antigravity's shape.
    fn remaining_win() -> WindowConfig {
        let mut w = win(ManifestRole::Primary, PeriodMode::Assumed, None, Some(300));
        w.source.used_percent_path = None;
        w.source.remaining_fraction_path = Some("remainingFraction".to_string());
        w
    }

    #[test]
    fn a_remaining_fraction_is_complemented_into_the_used_percent() {
        // 0.75 left is 25% spent — a unit change of the stated figure, not a
        // number computed from something the provider did not say.
        let w = remaining_win();
        let body = json!({ "remainingFraction": 0.75, "resets_at": 1_800_000_000 });
        assert_eq!(
            build_window(0, &w, &body).expect("reported").used_percent,
            Some(25.0)
        );
    }

    #[test]
    fn a_full_remaining_fraction_reads_as_nothing_spent() {
        let w = remaining_win();
        let body = json!({ "remainingFraction": 1.0, "resets_at": 1_800_000_000 });
        assert_eq!(
            build_window(0, &w, &body).expect("reported").used_percent,
            Some(0.0)
        );
    }

    #[test]
    fn a_remaining_fraction_out_of_range_clamps_like_any_other_percent() {
        // A fraction the provider states outside 0..1 (a promo allowance over
        // 100%, or a server glitch) complements to a percent outside 0..100,
        // and the same clamp every window's percent already gets brings it to
        // the bar's end — the window's scale is this app's own contract
        // (always 0..100), applied identically to spent and remaining.
        let w = remaining_win();
        let over = json!({ "remainingFraction": 1.5, "resets_at": 1_800_000_000 });
        assert_eq!(
            build_window(0, &w, &over).expect("reported").used_percent,
            Some(0.0)
        );
        let under = json!({ "remainingFraction": -0.5, "resets_at": 1_800_000_000 });
        assert_eq!(
            build_window(0, &w, &under).expect("reported").used_percent,
            Some(100.0)
        );
    }

    #[test]
    fn an_absent_remaining_fraction_is_no_window_not_zero_left() {
        // Antigravity's proto3 responses drop a zero field entirely; an
        // exhausted bucket most likely arrives with no `remainingFraction` at
        // all. Reading that absence as "did not say" (no window) rather than
        // as "0 left / 100% spent" is deliberate — silence is not exhaustion.
        let w = remaining_win();
        assert_eq!(
            build_window(0, &w, &json!({ "resets_at": 1_800_000_000 })),
            None
        );
    }

    // ── container classification (the Codex usage shape) ─────────────────

    /// A Codex-like manifest: both windows read the same pair of candidate
    /// containers and are told apart by their own length, in seconds.
    fn codex_like_manifest() -> PluginManifest {
        let toml = r#"
            id         = "codex"
            name       = "Codex"
            menu_label = "Cx"
            order      = 10
            engine     = "http-api"

            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode  = "from_field"
            field = "limit_window_seconds"
            unit  = "seconds"
            [windows.source]
            containers         = ["rate_limit.primary_window", "rate_limit.secondary_window"]
            used_percent_path  = "used_percent"
            resets_at_path     = "reset_at"
            max_period_minutes = 720

            [[windows]]
            label = "WK"
            role  = "secondary"
            [windows.period]
            mode  = "from_field"
            field = "limit_window_seconds"
            unit  = "seconds"
            [windows.source]
            containers         = ["rate_limit.primary_window", "rate_limit.secondary_window"]
            used_percent_path  = "used_percent"
            resets_at_path     = "reset_at"
            min_period_minutes = 721

            [http]
            [[http.request]]
            url = "https://chatgpt.com/backend-api/wham/usage"
        "#;
        PluginManifest::from_str(toml).expect("valid test manifest")
    }

    /// The response Codex actually returned when this engine was written:
    /// the *weekly* window in the `primary_window` slot, `secondary_window`
    /// null. Reading slots positionally would print the weekly figure on the
    /// 5H row; classification by length is what keeps that from happening.
    #[test]
    fn weekly_window_in_the_primary_slot_lands_on_the_weekly_row() {
        let m = codex_like_manifest();
        let body = json!({
            "rate_limit": {
                "primary_window": {
                    "used_percent": 69,
                    "limit_window_seconds": 604800,
                    "reset_at": 1787207494u64,
                },
                "secondary_window": null,
            },
        });
        let windows = reported_windows(&body, &m);

        assert!(
            windows.iter().all(|w| w.label != "5H"),
            "no 5-hour window was reported, so there is no 5-hour row"
        );

        let week = windows.iter().find(|w| w.label == "WK").expect("WK row");
        assert_eq!(week.used_percent, Some(69.0));
        assert_eq!(week.resets_at, Some(1787207494));
        assert_eq!(week.period_minutes, Some(10080), "604800s -> 10080 min");
    }

    #[test]
    fn both_windows_are_matched_by_length_regardless_of_slot_order() {
        let m = codex_like_manifest();
        // The 5-hour window in the *secondary* slot and the weekly one in the
        // primary: each still lands on its own row.
        let body = json!({
            "rate_limit": {
                "primary_window":   { "used_percent": 61, "limit_window_seconds": 604800, "reset_at": 200 },
                "secondary_window": { "used_percent": 12, "limit_window_seconds": 18000,  "reset_at": 100 },
            },
        });
        let windows = reported_windows(&body, &m);
        let five = windows.iter().find(|w| w.label == "5H").unwrap();
        assert_eq!(five.used_percent, Some(12.0));
        assert_eq!(five.resets_at, Some(100));
        assert_eq!(five.period_minutes, Some(300), "18000s -> 300 min");

        let week = windows.iter().find(|w| w.label == "WK").unwrap();
        assert_eq!(week.used_percent, Some(61.0));
        assert_eq!(week.period_minutes, Some(10080));
    }

    #[test]
    fn a_candidate_with_no_readable_length_is_never_classified() {
        let m = codex_like_manifest();
        let body = json!({
            "rate_limit": {
                "primary_window": { "used_percent": 50 }, // no limit_window_seconds
                "secondary_window": null,
            },
        });
        assert!(
            reports_nothing(&body, &m),
            "a window that can't be told apart from another must not be guessed into a row"
        );
    }

    #[test]
    fn a_single_declared_container_is_taken_without_classification() {
        // One candidate is *this* window by declaration — no length needed.
        let toml = r#"
            id         = "one"
            name       = "One"
            menu_label = "On"
            order      = 1
            engine     = "http-api"
            [[windows]]
            label = "WK"
            role  = "secondary"
            [windows.period]
            mode    = "assumed"
            assumed = 10080
            [windows.source]
            containers        = ["rate_limit.primary_window"]
            used_percent_path = "used_percent"
            resets_at_path    = "reset_at"
            [http]
            [[http.request]]
            url = "https://example.com/usage"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let body =
            json!({ "rate_limit": { "primary_window": { "used_percent": 7, "reset_at": 9 } } });
        let w = &reported_windows(&body, &m)[0];
        assert_eq!(w.used_percent, Some(7.0));
        assert_eq!(w.resets_at, Some(9));
        assert_eq!(w.period_minutes, Some(10080));
    }

    #[test]
    fn a_single_container_still_has_to_pass_a_declared_bound() {
        // One candidate is not a licence to ignore what the window says about
        // itself: a weekly row handed a five-hour window must stay empty.
        let toml = r#"
            id         = "bounded"
            name       = "Bounded"
            menu_label = "Bd"
            order      = 1
            engine     = "http-api"
            [[windows]]
            label = "WK"
            role  = "secondary"
            [windows.period]
            mode  = "from_field"
            field = "limit_window_seconds"
            unit  = "seconds"
            [windows.source]
            containers         = ["rate_limit.primary_window"]
            used_percent_path  = "used_percent"
            resets_at_path     = "reset_at"
            min_period_minutes = 721
            [http]
            [[http.request]]
            url = "https://example.com/usage"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");

        let five_hour = json!({
            "rate_limit": { "primary_window": { "used_percent": 12, "limit_window_seconds": 18000 } }
        });
        assert!(
            reports_nothing(&five_hour, &m),
            "a 5-hour window does not become the weekly row just by being the only one"
        );

        let weekly = json!({
            "rate_limit": { "primary_window": { "used_percent": 12, "limit_window_seconds": 604800 } }
        });
        assert_eq!(reported_windows(&weekly, &m)[0].used_percent, Some(12.0));
    }

    #[test]
    fn a_bound_declared_on_an_assumed_period_is_never_consulted() {
        // There is no length in the response to check the bound against, so
        // the window reads its candidate rather than rejecting every one of
        // them and going permanently blank. Built directly with `win()`
        // rather than through `PluginManifest::from_str`: `validate` refuses
        // this exact combination at load (a bound only means something
        // alongside `mode = "from_field"`), so no manifest can reach this
        // shape anymore — this is `select_container`'s own defence in
        // depth, pinned so it can't quietly start mattering again if that
        // load-time rule is ever loosened.
        let mut w = win(
            ManifestRole::Secondary,
            PeriodMode::Assumed,
            None,
            Some(10_080),
        );
        w.source.containers = vec!["rate_limit.primary_window".to_string()];
        w.source.min_period_minutes = Some(721);

        let body =
            json!({ "rate_limit": { "primary_window": { "used_percent": 3, "resets_at": 7 } } });
        let out = build_window(0, &w, &body).expect("reported");
        assert_eq!(out.used_percent, Some(3.0));
        assert_eq!(out.period_minutes, Some(10080));
    }

    #[test]
    fn a_bound_holds_at_the_response_root_too() {
        let toml = r#"
            id         = "root-bound"
            name       = "RootBound"
            menu_label = "Rb"
            order      = 1
            engine     = "http-api"
            [[windows]]
            label = "WK"
            role  = "secondary"
            [windows.period]
            mode  = "from_field"
            field = "limit_window_seconds"
            unit  = "seconds"
            [windows.source]
            used_percent_path  = "used_percent"
            resets_at_path     = "reset_at"
            min_period_minutes = 721
            [http]
            [[http.request]]
            url = "https://example.com/usage"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        assert!(
            reports_nothing(
                &json!({ "used_percent": 9, "limit_window_seconds": 18000 }),
                &m
            ),
            "a bound is a bound wherever the numbers are read from"
        );
        assert_eq!(
            reported_windows(
                &json!({ "used_percent": 9, "limit_window_seconds": 604800 }),
                &m
            )[0]
            .used_percent,
            Some(9.0)
        );
    }

    #[test]
    fn a_manifest_without_containers_still_reads_from_the_response_root() {
        // Claude's shape — the behaviour every pre-existing manifest relies on.
        let m = claude_like_manifest();
        let body =
            json!({ "five_hour": { "utilization": 34.5, "resets_at": "2026-01-01T00:00:00Z" } });
        let five = reported_windows(&body, &m)
            .into_iter()
            .find(|w| w.label == "5H")
            .unwrap();
        assert_eq!(five.used_percent, Some(34.5));
        assert_eq!(five.resets_at, Some(NY2026));
    }

    #[test]
    fn additional_rate_limits_are_never_mistaken_for_the_main_quota() {
        // Codex reports separate model-specific quotas ("GPT-5.3-Codex-Spark")
        // in their own list. They are deliberately not shown, and — this is
        // the part worth a test — a container path never reaches into them, so
        // a 0%-used side quota can't overwrite a 69%-used main one. (The
        // rollout-log reader had exactly that bug: newest line wins, whatever
        // limit it belongs to.)
        let m = codex_like_manifest();
        let body = json!({
            "rate_limit": {
                "primary_window": { "used_percent": 69, "limit_window_seconds": 604800, "reset_at": 1 },
                "secondary_window": null,
            },
            "additional_rate_limits": [{
                "limit_name": "GPT-5.3-Codex-Spark",
                "rate_limit": {
                    "primary_window": { "used_percent": 0, "limit_window_seconds": 604800, "reset_at": 2 },
                    "secondary_window": null,
                },
            }],
        });
        let week = reported_windows(&body, &m)
            .into_iter()
            .find(|w| w.label == "WK")
            .unwrap();
        assert_eq!(
            week.used_percent,
            Some(69.0),
            "the main quota, not the side one"
        );
        assert_eq!(week.resets_at, Some(1));
    }

    // ── {value.<name>} header values ─────────────────────────────────────

    #[test]
    fn substitute_replaces_value_placeholders() {
        let mut values = BTreeMap::new();
        values.insert("account_id".to_string(), "acc-42".to_string());
        assert_eq!(
            substitute("{value.account_id}", "tok", "9.9.9", &no_options(), &values),
            "acc-42"
        );
        assert_eq!(
            substitute("{value.unknown}", "tok", "9.9.9", &no_options(), &values),
            "{value.unknown}",
            "an undeclared value name stays visible rather than vanishing"
        );
    }

    #[test]
    fn resolve_values_reads_a_json_file_and_errors_when_it_cannot() {
        let dir = temp_dir("values");
        let file = dir.join("auth.json");
        std::fs::write(
            &file,
            json!({ "tokens": { "account_id": "acc-7" } }).to_string(),
        )
        .unwrap();

        let ok = HttpValueConfig {
            name: "account_id".to_string(),
            kind: HttpValueType::JsonFile,
            path: Some(file.to_string_lossy().into_owned()),
            json_path: Some("tokens.account_id".to_string()),
        };
        let resolved = resolve_values(std::slice::from_ref(&ok)).expect("resolves");
        assert_eq!(
            resolved.get("account_id").map(String::as_str),
            Some("acc-7")
        );

        let missing_field = HttpValueConfig {
            json_path: Some("tokens.nope".to_string()),
            ..ok.clone()
        };
        assert!(
            resolve_values(&[missing_field]).is_err(),
            "a header value that can't be resolved must stop the request, not be sent empty"
        );

        let gone = dir.join("gone.json");
        let missing_file = HttpValueConfig {
            path: Some(gone.to_string_lossy().into_owned()),
            ..ok
        };
        let err = resolve_values(&[missing_file]).expect_err("the file does not exist");
        assert!(
            err.contains(&gone.to_string_lossy().into_owned()),
            "the error must name the path it tried to read, not just the value's own name: {err}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_unresolvable_value_errors_before_any_request_is_attempted() {
        let toml = r#"
            id         = "valfail"
            name       = "ValFail"
            menu_label = "Vf"
            order      = 1
            engine     = "http-api"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "utilization"
            resets_at_path    = "resets_at"
            [http]
            [[http.request]]
            url = "https://api.example.com/usage"
            [http.request.headers]
            "x-account" = "{value.account_id}"
            [[http.value]]
            name      = "account_id"
            type      = "json-file"
            path      = "/nonexistent/tickover-test/auth.json"
            json_path = "tokens.account_id"
            [[surface]]
            id = "default"
            label = "Default"
            allowed_hosts = ["api.example.com"]
            [[surface.auth]]
            type = "env"
            var  = "TICKOVER_TEST_ENGINE_HTTP_VALUE_TOKEN"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("TICKOVER_TEST_ENGINE_HTTP_VALUE_TOKEN", "tok");
        let readings = fetch(&m, &["default".to_string()], &no_options());
        std::env::remove_var("TICKOVER_TEST_ENGINE_HTTP_VALUE_TOKEN");

        let err = readings[0].error.as_deref().expect("must error");
        assert!(err.contains("account_id"), "unexpected error: {err}");
        assert!(readings[0].windows.is_empty());
    }

    // ── [account] type = "response-field" ────────────────────────────────

    #[test]
    fn account_can_be_read_out_of_the_usage_response() {
        let toml = r#"
            id         = "resp"
            name       = "Resp"
            menu_label 	= "Rp"
            order      = 1
            engine     = "http-api"
            [account]
            type      = "response-field"
            json_path = "email"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "utilization"
            resets_at_path    = "resets_at"
            [http]
            [[http.request]]
            url = "https://example.com/usage"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let body = json!({ "email": "you@example.com" });
        assert_eq!(
            resolve_account_from_response(&m, &body).as_deref(),
            Some("you@example.com")
        );
        assert_eq!(
            resolve_account_from_response(&m, &json!({ "email": "  " })),
            None,
            "a blank address names nobody"
        );
        assert_eq!(resolve_account_from_response(&m, &json!({})), None);
        assert_eq!(
            resolve_account_from_response(&claude_like_manifest(), &json!({ "email": "x@y.z" })),
            None,
            "only [account] type = \"response-field\" reads the usage body"
        );
        assert_eq!(
            resolve_account_from_response(&m, &json!({ "email": "you@example.com\u{200B}\r" }))
                .as_deref(),
            Some("you@example.com"),
            "an address is response-supplied text like any other and gets the same sanitising"
        );
    }

    // ── iso8601 parsing ──────────────────────────────────────────────────

    #[test]
    fn iso8601_parsing_handles_z_and_offsets() {
        assert_eq!(parse_iso8601("2026-01-01T00:00:00Z"), Some(NY2026));
        assert_eq!(parse_iso8601("2026-01-01T02:00:00+02:00"), Some(NY2026));
        assert_eq!(
            parse_iso8601("1969-12-31T23:59:00Z"),
            Some(0),
            "pre-epoch clamps to 0"
        );
        assert_eq!(parse_iso8601("yesterday"), None);
    }

    // ── tag resolution ───────────────────────────────────────────────────

    #[test]
    fn tag_uses_surface_label_when_surfaces_are_declared_explicitly() {
        let m = claude_like_manifest();
        assert_eq!(resolve_tag(&m, &m.surface[0], None).as_deref(), Some("CLI"));
        assert_eq!(
            resolve_tag(&m, &m.surface[1], None).as_deref(),
            Some("Desktop")
        );
    }

    #[test]
    fn tag_from_field_reads_the_response_body_when_no_explicit_surfaces() {
        let toml = r#"
            id         = "generic"
            name       = "Generic"
            menu_label = "Ge"
            order      = 1
            engine     = "http-api"
            [tag]
            from = "field"
            path = "plan"
            transform = "uppercase"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "utilization"
            resets_at_path    = "resets_at"
            [http]
            [[http.request]]
            url = "https://example.com/usage"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let surface = &m.surface[0]; // synthesized "default"

        assert_eq!(
            resolve_tag(&m, surface, None),
            None,
            "no response body yet -> no tag"
        );
        let body = json!({ "plan": "pro" });
        assert_eq!(
            resolve_tag(&m, surface, Some(&body)).as_deref(),
            Some("PRO")
        );
    }

    #[test]
    fn tag_from_field_sanitises_the_response_value_before_the_chip_sees_it() {
        let toml = r#"
            id         = "generic"
            name       = "Generic"
            menu_label = "Ge"
            order      = 1
            engine     = "http-api"
            [tag]
            from = "field"
            path = "plan"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "utilization"
            resets_at_path    = "resets_at"
            [http]
            [[http.request]]
            url = "https://example.com/usage"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let surface = &m.surface[0];

        let body = json!({ "plan": "pro\nplan\u{200B}" });
        assert_eq!(
            resolve_tag(&m, surface, Some(&body)).as_deref(),
            Some("proplan"),
            "a provider's own field value is response-supplied text like any \
             other, and gets the same treatment"
        );

        let body = json!({ "plan": "\u{200B}" });
        assert_eq!(
            resolve_tag(&m, surface, Some(&body)),
            None,
            "a value that sanitises away to nothing is not a tag"
        );
    }

    // ── account email ────────────────────────────────────────────────────

    #[test]
    fn resolve_account_url_substitutes_option_placeholders_before_the_allowed_hosts_check() {
        let toml = r#"
            id         = "acct"
            name       = "Acct"
            menu_label = "Ac"
            order      = 1
            engine     = "http-api"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "utilization"
            resets_at_path    = "resets_at"
            [http]
            [[http.request]]
            url = "https://api.example.com/usage"
            [account]
            type      = "http"
            url       = "https://{option.use_eu}.example.com/profile"
            json_path = "email"
            [[option]]
            key     = "use_eu"
            label   = "EU endpoint"
            default = false
            [[surface]]
            id = "cli"
            label = "CLI"
            allowed_hosts = ["true.example.com"]
            [[surface.auth]]
            type = "env"
            var  = "TICKOVER_TEST_ENGINE_HTTP_ACCOUNT_URL_TOKEN"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let surface = &m.surface[0];

        let mut opts = BTreeMap::new();
        opts.insert("use_eu".to_string(), true);
        assert_eq!(
            resolve_account_url(&m, surface, &opts).as_deref(),
            Some("https://true.example.com/profile"),
            "{{option.<key>}} must be substituted into account.url before the allowed_hosts check"
        );

        opts.insert("use_eu".to_string(), false);
        assert_eq!(
            resolve_account_url(&m, surface, &opts),
            None,
            "the *substituted* host (false.example.com) is checked, and it isn't in allowed_hosts"
        );
    }

    #[test]
    fn resolve_account_url_is_none_when_account_type_is_not_http() {
        let m = claude_like_manifest();
        // `claude_like_manifest`'s [account] is `type = "http"`; swap in a
        // manifest with no [account] section at all (defaults to "none").
        let toml = r#"
            id         = "no-account"
            name       = "NoAccount"
            menu_label = "Na"
            order      = 1
            engine     = "http-api"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "utilization"
            resets_at_path    = "resets_at"
            [http]
            [[http.request]]
            url = "https://example.com/usage"
        "#;
        let none_account = PluginManifest::from_str(toml).expect("valid manifest");
        assert_eq!(
            resolve_account_url(&none_account, &none_account.surface[0], &no_options()),
            None
        );
        // Sanity: the http-typed fixture's own surface/url are set up as expected.
        assert_eq!(m.account.kind, AccountType::Http);
    }

    /// The caching primitive [`resolve_account`] holds a failing profile
    /// endpoint back with — exercised on its own because `resolve_account`
    /// itself reaches the network and this engine's tests never do. Before
    /// this, a profile lookup that started failing was retried with the
    /// token on *every* fetch of the main usage endpoint, however that one
    /// was paced.
    #[test]
    fn account_lookup_recently_failed_holds_back_a_retry_within_the_interval() {
        let key = "test-account-lookup-cache";
        let min_interval = Duration::from_secs(60);
        let t0 = Instant::now();

        assert!(
            !account_lookup_recently_failed(key, min_interval, t0),
            "nothing has failed yet"
        );
        record_account_lookup_failure(key, t0);
        assert!(
            account_lookup_recently_failed(key, min_interval, t0 + Duration::from_secs(1)),
            "a fresh failure holds the next attempt back"
        );
        assert!(
            !account_lookup_recently_failed(key, min_interval, t0 + Duration::from_secs(61)),
            "past the interval, an attempt is allowed again"
        );

        // A success in between clears the cool-off outright.
        record_account_lookup_failure(key, t0);
        record_account_lookup_success(key);
        assert!(
            !account_lookup_recently_failed(key, min_interval, t0 + Duration::from_secs(1)),
            "a recorded success lifts the cool-off a failure set"
        );
    }

    #[test]
    fn account_email_is_read_via_json_path() {
        let value = json!({ "account": { "email": "user@example.com" } });
        assert_eq!(
            json_path_get(&value, "account.email").and_then(Value::as_str),
            Some("user@example.com")
        );
    }

    // ── fetch(): surface iteration, id scheme, error propagation ────────

    #[test]
    fn fetch_filters_by_active_surface_ids_and_preserves_manifest_order() {
        let m = claude_like_manifest();
        // Neither surface has a token in the environment, so each errors out
        // of `auth::resolve_token` immediately — no filesystem, Keychain or
        // network access — but the iteration/id logic under test still runs.
        let readings = fetch(
            &m,
            &["desktop".to_string(), "cli".to_string()],
            &no_options(),
        );
        assert_eq!(readings.len(), 2, "both requested surfaces are returned");
        assert_eq!(
            readings[0].id, "claude-cli",
            "manifest order (cli, then desktop), not request order"
        );
        assert_eq!(readings[1].id, "claude-desktop");
    }

    #[test]
    fn fetch_only_returns_readings_for_active_surfaces() {
        let m = claude_like_manifest();
        let readings = fetch(&m, &["desktop".to_string()], &no_options());
        assert_eq!(readings.len(), 1);
        assert_eq!(readings[0].id, "claude-desktop");
        assert!(!readings[0].in_menu_bar, "desktop surface is popup-only");
    }

    #[test]
    fn fetch_default_surface_id_uses_the_plugin_id_verbatim() {
        let toml = r#"
            id         = "simple"
            name       = "Simple"
            menu_label = "Sp"
            order      = 1
            engine     = "http-api"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "utilization"
            resets_at_path    = "resets_at"
            [http]
            [[http.request]]
            url = "https://example.com/usage"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let readings = fetch(&m, &["default".to_string()], &no_options());
        assert_eq!(readings.len(), 1);
        assert_eq!(
            readings[0].id, "simple",
            "the synthesized default surface reads under the plugin id"
        );
    }

    #[test]
    fn missing_token_produces_an_error_reading_with_empty_windows() {
        let m = claude_like_manifest(); // no env vars set -> NO_CREDENTIALS
        let readings = fetch(&m, &["cli".to_string()], &no_options());
        assert_eq!(readings.len(), 1);
        assert_eq!(readings[0].error.as_deref(), Some(auth::NO_CREDENTIALS));
        assert!(readings[0].windows.is_empty());
        assert_eq!(readings[0].id, "claude-cli");
    }

    #[test]
    fn blocked_host_produces_an_error_without_making_a_request() {
        let toml = r#"
            id         = "blocked"
            name       = "Blocked"
            menu_label = "Bl"
            order      = 1
            engine     = "http-api"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "utilization"
            resets_at_path    = "resets_at"
            [http]
            [[http.request]]
            url = "https://evil.example.com/usage"
            [[surface]]
            id = "cli"
            label = "CLI"
            allowed_hosts = ["api.anthropic.com"]
            [[surface.auth]]
            type = "env"
            var  = "TICKOVER_TEST_ENGINE_HTTP_BLOCKED_TOKEN"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("TICKOVER_TEST_ENGINE_HTTP_BLOCKED_TOKEN", "tok");
        let readings = fetch(&m, &["cli".to_string()], &no_options());
        std::env::remove_var("TICKOVER_TEST_ENGINE_HTTP_BLOCKED_TOKEN");

        assert_eq!(readings.len(), 1);
        let err = readings[0]
            .error
            .as_deref()
            .expect("must error, not attempt the request");
        assert!(
            err.contains("blocked by allowed_hosts"),
            "unexpected error: {err}"
        );
        assert!(readings[0].windows.is_empty());
    }

    /// A header value with a byte outside SP/HTAB/0x21–0x7E is refused before
    /// any request is attempted, by a message that names the header and never
    /// its bytes — the token this header carries, or the offending byte
    /// itself. `\u{00A0}` (non-breaking space) is baked into the template
    /// right after `{token}`, the shape a substitution can produce that no
    /// static check at load time could have caught (see
    /// `refuse_unsafe_header_values`'s doc).
    #[test]
    fn a_header_value_outside_visible_ascii_is_refused_by_name_never_by_its_bytes() {
        let toml = format!(
            r#"
            id         = "badheader"
            name       = "BadHeader"
            menu_label = "Bh"
            order      = 1
            engine     = "http-api"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "utilization"
            resets_at_path    = "resets_at"
            [http]
            [[http.request]]
            url = "https://api.anthropic.com/usage"
            [http.request.headers]
            Authorization = "Bearer {{token}}{nbsp}"
            [[surface]]
            id = "cli"
            label = "CLI"
            allowed_hosts = ["api.anthropic.com"]
            [[surface.auth]]
            type = "env"
            var  = "TICKOVER_TEST_ENGINE_HTTP_BADHEADER_TOKEN"
        "#,
            nbsp = '\u{00A0}'
        );
        let m = PluginManifest::from_str(&toml).expect("valid manifest");
        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(
            "TICKOVER_TEST_ENGINE_HTTP_BADHEADER_TOKEN",
            "top-secret-token",
        );
        let readings = fetch(&m, &["cli".to_string()], &no_options());
        std::env::remove_var("TICKOVER_TEST_ENGINE_HTTP_BADHEADER_TOKEN");

        assert_eq!(readings.len(), 1);
        let err = readings[0]
            .error
            .as_deref()
            .expect("must refuse, not attempt the request");
        assert!(err.contains("Authorization"), "names the header: {err}");
        assert!(!err.contains("top-secret-token"), "never the token: {err}");
        assert!(
            !err.contains('\u{00A0}'),
            "never the offending byte itself: {err}"
        );
        assert!(readings[0].windows.is_empty());
    }

    /// `perform`'s own backstop for a header `ureq` refuses at send time
    /// (`ureq` validates its own synthesized headers too, past whatever this
    /// engine passed in — see its doc): the message is fixed, never
    /// `ureq`'s own, which would otherwise quote the whole `"Name: value"`
    /// line.
    #[test]
    fn perform_never_surfaces_ureqs_own_bad_header_message() {
        let failure = perform(
            "https://example.com/usage",
            HttpMethod::Get,
            None,
            &[("X-Test".to_string(), "value\u{0001}".to_string())],
            Duration::from_secs(1),
        )
        .expect_err("an invalid header byte must refuse, not connect");
        assert_eq!(failure.message, BAD_HEADER_MESSAGE);
        assert!(
            !failure.message.contains("X-Test"),
            "never ureq's own 'Name: value' line: {}",
            failure.message
        );
    }

    #[test]
    fn redact_header_values_hides_a_leaked_header_from_an_arbitrary_message() {
        let headers = vec![(
            "Authorization".to_string(),
            "Bearer secret-token".to_string(),
        )];
        assert_eq!(
            redact_header_values("network error: Bearer secret-token", &headers),
            "a header value could not be sent"
        );
        assert_eq!(
            redact_header_values("network error: timed out", &headers),
            "network error: timed out",
            "a message that names nothing sensitive passes through unchanged"
        );
    }

    #[test]
    fn fetch_substitutes_declared_options_into_the_request_url() {
        // No network access needed: the URL is substituted, then rejected by
        // `allowed_hosts` before any request is attempted — the resulting
        // error message still carries the substituted URL, proving `fetch`
        // threads `options` all the way through `fetch_surface`/`build_request`.
        let toml = r#"
            id         = "opt-url"
            name       = "OptUrl"
            menu_label = "Ou"
            order      = 1
            engine     = "http-api"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "utilization"
            resets_at_path    = "resets_at"
            [http]
            [[http.request]]
            url = "https://evil.example.com/usage?beta={option.include_beta}"
            # Declared, because an option the manifest does not declare is
            # never substituted at runtime either: `main::plugin_options`
            # builds the map from this list and nothing else.
            [[option]]
            key     = "include_beta"
            label   = "Include beta"
            default = false
            [[surface]]
            id = "cli"
            label = "CLI"
            allowed_hosts = ["api.anthropic.com"]
            [[surface.auth]]
            type = "env"
            var  = "TICKOVER_TEST_ENGINE_HTTP_OPT_URL_TOKEN"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let _env_guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("TICKOVER_TEST_ENGINE_HTTP_OPT_URL_TOKEN", "tok");
        let mut opts = BTreeMap::new();
        opts.insert("include_beta".to_string(), true);
        let readings = fetch(&m, &["cli".to_string()], &opts);
        std::env::remove_var("TICKOVER_TEST_ENGINE_HTTP_OPT_URL_TOKEN");

        assert_eq!(readings.len(), 1);
        let err = readings[0]
            .error
            .as_deref()
            .expect("must error, not attempt the request");
        assert!(
            err.contains("beta=true"),
            "the {{option.include_beta}} placeholder must resolve before the allowed_hosts check: {err}"
        );
    }

    // ── window identity ─────────────────────────────────────────────────

    /// The property the whole key scheme exists for, on the case that produced
    /// it: Codex moves its weekly window into `primary_window` whenever the
    /// 5-hour one has nothing to report, and that is the ordinary state the
    /// hysteresis was written for. A key built on the slot would hand the
    /// weekly row a new identity at exactly that moment — losing its registry
    /// entry, its remembered boundary, and the auto-ping working from it.
    #[test]
    fn the_weekly_windows_key_does_not_change_with_the_slot_it_arrives_in() {
        let m = codex_like_manifest();

        // Both windows reported: weekly sits in the *secondary* slot.
        let both = json!({ "rate_limit": {
            "primary_window":   { "used_percent": 4.0,  "limit_window_seconds": 18_000,  "reset_at": 1 },
            "secondary_window": { "used_percent": 69.0, "limit_window_seconds": 604_800, "reset_at": 2 },
        }});
        // Nothing spent in the 5-hour window, so Codex reports only the weekly
        // one — in the *primary* slot, with `secondary_window` null.
        let weekly_only = json!({ "rate_limit": {
            "primary_window":   { "used_percent": 69.0, "limit_window_seconds": 604_800, "reset_at": 2 },
            "secondary_window": Value::Null,
        }});

        let key_of = |body: &Value| {
            parse_usage(body, &m)
                .expect("a manifest with no `required` refuses nothing")
                .into_iter()
                .find(|w| w.label == "WK")
                .expect("the weekly window resolved")
                .key
        };

        assert_eq!(
            key_of(&both),
            key_of(&weekly_only),
            "the weekly window keeps one identity across the slot it happened to arrive in"
        );

        // And the two declared windows are still told apart — the other half
        // of what the key has to do.
        let windows = parse_usage(&both, &m).expect("both resolved");
        assert_ne!(
            windows[0].key, windows[1].key,
            "two declared windows, two identities"
        );
    }

    /// The encoder itself, on the characters it exists for.
    ///
    /// Split out because the test below cannot reach them: a window `id` is
    /// validated to a whitelist, so a dot never gets that far through a
    /// manifest — and a test that only feeds it safe input proves the encoder
    /// runs, not that it encodes. An enumerating entry's element half
    /// (`windows.for_each`) takes values straight out of a response, where
    /// all of these are reachable.
    #[test]
    fn the_key_encoder_removes_every_byte_that_could_split_a_key_or_a_path() {
        use crate::plugin::encode_key_part;

        assert_eq!(
            encode_key_part("five.hour"),
            "five%2Ehour",
            "a dot would split the config path"
        );
        assert_eq!(
            encode_key_part("a:b"),
            "a%3Ab",
            "a colon is the entry/element boundary"
        );
        assert_eq!(
            encode_key_part("a~b"),
            "a%7Eb",
            "a tilde is the boundary between element parts"
        );
        assert_eq!(
            encode_key_part("100%"),
            "100%25",
            "the escape character escapes itself"
        );
        assert_eq!(encode_key_part("a b"), "a%20b");
        assert_eq!(encode_key_part("Claude Fable"), "Claude%20Fable");
        assert_eq!(
            encode_key_part("модель"),
            "%D0%BC%D0%BE%D0%B4%D0%B5%D0%BB%D1%8C",
            "UTF-8, byte by byte"
        );
        assert_eq!(
            encode_key_part("ok-key_9"),
            "ok-key_9",
            "the unreserved set passes through"
        );

        // The property the whole scheme rests on: distinct inputs stay
        // distinct, so two windows cannot end up sharing one registry entry.
        assert_ne!(encode_key_part("a-b"), encode_key_part("a~b"));
        assert_ne!(encode_key_part("a"), encode_key_part("a:"));
    }

    /// A key is a segment of a dotted path in the user's `config.json`. A `.`
    /// in it would not be a wrong key — it would be a key in a different table.
    #[test]
    fn a_window_key_is_built_from_the_declared_entry_and_never_from_its_caption() {
        let toml = r#"
            id         = "sample"
            name       = "Sample"
            menu_label = "Sa"
            order      = 1
            engine     = "http-api"
            requires_reader = ["window-identity"]

            [[windows]]
            id    = "five-hour"
            label = "5H"
            role  = "primary"
            [windows.period]
            mode    = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "used_percent"
            resets_at_path    = "resets_at"

            [http]
            [[http.request]]
            url = "https://example.com/usage"
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        let w = build_window(0, &m.windows[0], &json!({ "used_percent": 1.0 })).expect("reported");
        assert_eq!(
            w.key, "five-hour:",
            "the declared id, then the empty element half"
        );
        assert!(
            !w.key.contains('.'),
            "a dot would split the config path this key lands in"
        );

        // An entry with no id falls back to its position rather than to its
        // label, which is a caption and may be reworded freely.
        let mut anonymous = m.clone();
        anonymous.windows[0].id = String::new();
        let w = build_window(3, &anonymous.windows[0], &json!({ "used_percent": 1.0 }))
            .expect("reported");
        assert_eq!(w.key, "w3:");
    }

    // ── quota status ────────────────────────────────────────────────────

    fn status_manifest() -> PluginManifest {
        let toml = r#"
            id         = "sample"
            name       = "Sample"
            menu_label = "Sa"
            order      = 1
            engine     = "http-api"
            requires_reader = ["reading-status"]

            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode    = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "used_percent"
            resets_at_path    = "resets_at"

            [status]
            allowed_path       = "rate_limit.allowed"
            limit_reached_path = "rate_limit.limit_reached"
            reached_type_path  = "rate_limit_reached_type.type"

            [http]
            [[http.request]]
            url = "https://example.com/usage"
        "#;
        PluginManifest::from_str(toml).expect("valid manifest")
    }

    /// The case the quota level exists for. Codex's own schema makes `allowed`
    /// and `limit_reached` required fields of `rate_limit` while both window
    /// slots are optional, so this body is not a hypothetical: an account that
    /// is cut off and has nothing running reports exactly this. Read off the
    /// windows, there would be nothing to show.
    #[test]
    fn a_blocked_quota_is_read_even_when_the_response_reports_no_window_at_all() {
        let m = status_manifest();
        let body = json!({
            "rate_limit": { "allowed": false, "limit_reached": true },
            "rate_limit_reached_type": { "type": "rate_limit_reached" },
        });

        assert_eq!(
            parse_usage(&body, &m).expect("nothing required"),
            Vec::new(),
            "no window resolved"
        );

        let status = parse_quota(&body, &m).expect("the response stated a status");
        assert!(status.is_blocked(), "the provider is refusing this account");
        assert_eq!(status.reached_type.as_deref(), Some("rate_limit_reached"));
    }

    /// `None` is "did not say", and the difference matters: a manifest
    /// declaring `[status]` is not the provider speaking.
    #[test]
    fn a_status_section_that_resolved_to_nothing_states_nothing() {
        let m = status_manifest();
        assert_eq!(parse_quota(&json!({ "rate_limit": {} }), &m), None);
        assert_eq!(parse_quota(&json!({}), &m), None);

        // And a provider that answers "you are fine" is recorded as having
        // said so, rather than as having said nothing.
        let fine = parse_quota(
            &json!({ "rate_limit": { "allowed": true, "limit_reached": false } }),
            &m,
        )
        .expect("it did answer");
        assert!(fine.is_stated());
        assert!(!fine.is_blocked());
    }

    /// A manifest with no `[status]` gets no quota — Claude's response carries
    /// no such statement, and a blank one would be this app inventing it.
    #[test]
    fn a_manifest_that_declares_no_status_section_reports_no_quota() {
        let m = claude_like_manifest();
        assert_eq!(parse_quota(&json!({ "anything": true }), &m), None);
    }

    /// Any of the three ways of saying it counts, and silence is not a refusal.
    #[test]
    fn blocked_means_the_provider_said_no_not_that_it_said_nothing() {
        use crate::model::QuotaStatus;
        let said_nothing = QuotaStatus::default();
        assert!(!said_nothing.is_stated() && !said_nothing.is_blocked());

        let reached = QuotaStatus {
            limit_reached: Some(true),
            ..Default::default()
        };
        let refused = QuotaStatus {
            allowed: Some(false),
            ..Default::default()
        };
        assert!(reached.is_blocked() && refused.is_blocked());

        // Naming which limit was hit is itself a refusal: Codex sends
        // `rate_limit_reached_type` only when one has been. Read as "not
        // blocked", this body would have answered a locked-out account with
        // "no usage reported yet".
        let named_only = QuotaStatus {
            reached_type: Some("rate_limit_reached".into()),
            ..Default::default()
        };
        assert!(named_only.is_stated() && named_only.is_blocked());

        // But that inference is about a field being *present*, and the path it
        // comes from is whatever a manifest points at. A provider that fills
        // the same field in the ordinary case would otherwise be reported as
        // refusing every account it has — so an explicit "no limit has been
        // reached" wins over it. The provider answered the question directly;
        // inferring the opposite from a neighbouring field is the invention
        // the rest of this type exists to prevent.
        let says_fine_but_names_a_type = QuotaStatus {
            limit_reached: Some(false),
            reached_type: Some("none".into()),
            ..Default::default()
        };
        assert!(says_fine_but_names_a_type.is_stated());
        assert!(
            !says_fine_but_names_a_type.is_blocked(),
            "the direct answer wins"
        );

        // And a refusal on the other axis is still a refusal, whatever
        // `limit_reached` says: an account that may not spend is blocked even
        // if no limit was the reason.
        let suspended = QuotaStatus {
            allowed: Some(false),
            limit_reached: Some(false),
            ..Default::default()
        };
        assert!(suspended.is_blocked());
    }

    /// The flagship case, run against the manifest that actually ships.
    ///
    /// Every other test here uses a hand-written fixture, and a fixture proves
    /// the reader works on the manifest the test wrote. If the shipped
    /// `codex.toml` spelled a path differently — or if container
    /// classification behaved differently on a body with no windows in it —
    /// all of them would stay green and the one state the quota status
    /// exists for would be broken in the file the user actually has.
    #[test]
    fn the_shipped_codex_manifest_reads_a_refusal_out_of_a_body_with_no_windows() {
        let (_, contents) = crate::plugin::seed::DEFAULT_TEMPLATES
            .iter()
            .find(|(name, _)| *name == "codex.toml")
            .expect("codex.toml ships");
        let m = PluginManifest::from_str(contents).expect("the shipped manifest parses");

        // What Codex sends an account it is refusing with nothing running:
        // the two window slots are optional and absent, the two booleans are
        // required and present.
        let body = json!({
            "plan_type": "pro",
            "rate_limit": { "allowed": false, "limit_reached": true },
            "rate_limit_reached_type": { "type": "rate_limit_reached" },
        });

        assert_eq!(
            parse_usage(&body, &m).expect("no window of codex.toml is `required`"),
            Vec::new(),
            "presence draws no row for a window nobody reported"
        );
        let status = parse_quota(&body, &m).expect("and yet the provider did say something");
        assert!(status.is_blocked());
        assert_eq!(status.reached_type.as_deref(), Some("rate_limit_reached"));
    }

    /// The same flagship idea for `copilot.toml`, whose whole reading is a
    /// balance: the manifest that ships, run against a body rather than
    /// against a fixture written to suit it.
    ///
    /// Four bodies, and only the first was measured. The other three are
    /// constructed, and each says so where it stands: they pin what *this
    /// manifest's paths* do on a free plan, on a body carrying neither plan's
    /// fields, and on a bucket marked unlimited — properties of the manifest,
    /// not claims about what GitHub answers a plan nobody here holds.
    ///
    /// The two plans are the point. Each is metered through fields the other
    /// does not carry, and this manifest reads both sets, so the thing that
    /// has to hold is that they stay out of each other's way: a paid body
    /// draws the premium row and no free rows, a free body draws the two free
    /// rows and no premium one, and a body with neither draws nothing at all —
    /// not a row of zeroes standing in for a bucket that never arrived.
    #[test]
    fn the_shipped_copilot_manifest_reads_the_premium_allowance_and_nothing_else() {
        let (_, contents) = crate::plugin::seed::DEFAULT_TEMPLATES
            .iter()
            .find(|(name, _)| *name == "copilot.toml")
            .expect("copilot.toml ships");
        let m = PluginManifest::from_str(contents).expect("the shipped manifest parses");
        let number = |v: f64| {
            Some(crate::model::BalanceAmount::Number {
                value: v,
                unit: Some("interactions".into()),
            })
        };
        // Every field the live response carries, with the *structure* as
        // measured and the figures invented. Two of them are worth naming,
        // because a fixture that guessed them would teach the next reader
        // something untrue:
        //
        //  * `has_quota` is `true` on every bucket, including the two that are
        //    `unlimited` — measured, and the opposite of what "has a quota"
        //    sounds like. It is the field one would reach for to tell an
        //    unlimited bucket from an exhausted one, and it does not tell them
        //    apart.
        //  * `quota_reset_at` is `0` on every bucket — an epoch this endpoint
        //    does not fill, which is why the manifest reads the top-level date.
        //
        // The rest are stand-ins for figures nothing here reads: the
        // percentage a bucket with no entitlement carries was not recorded,
        // and `credits_used` is a token-billing counter unrelated to this pair
        // (measured: `entitlement − quota_remaining` is not it).
        let bucket = |id: &str, unlimited: bool, entitlement: i64, remaining: f64| {
            let percent = match entitlement {
                0 => 0.0,
                e => 100.0 * remaining / e as f64,
            };
            json!({
                "unlimited": unlimited, "has_quota": true, "quota_id": id,
                "entitlement": entitlement, "remaining": remaining as i64,
                "quota_remaining": remaining, "percent_remaining": percent,
                "overage_count": 0, "overage_permitted": false, "overage_entitlement": 0,
                "credits_used": 0, "token_based_billing": true, "quota_reset_at": 0,
                "timestamp_utc": "2026-08-22T09:00:00.000Z",
            })
        };

        // The paid shape, field for field as measured — figures invented, the
        // structure not. `chat` and `completions` arrive unlimited and empty.
        let paid = json!({
            "copilot_plan": "individual",
            "quota_reset_date": "2026-09-01",
            "quota_reset_date_utc": "2026-09-01T00:00:00.000Z",
            "quota_snapshots": {
                "chat": bucket("chat", true, 0, 0.0),
                "completions": bucket("completions", true, 0, 0.0),
                "premium_interactions": bucket("premium_interactions", false, 300, 271.6),
            },
        });

        let balances = parse_balances(&paid, &m);
        assert_eq!(
            balances.len(),
            1,
            "one row: the other two buckets are not read, and no free-plan field is present"
        );
        let premium = &balances[0];
        // Both figures carry the manifest's unit — which is what makes them
        // count the same thing, and what a `unit_label` on one side only would
        // break. Note what this does *not* buy today: the panel pairs `used`
        // with `cap` and nothing else, so this row draws as two lines whatever
        // the units say (`a_ceiling_with_what_is_left_of_it_...` in `main.rs`
        // pins that, and the unit rule itself is pinned beside it).
        assert_eq!(premium.cap, number(300.0), "the ceiling, with its unit");
        assert_eq!(
            premium.remaining,
            number(271.6),
            "the fraction, not its floored twin"
        );
        assert!(
            premium.used.is_none(),
            "nothing states a spent figure, and none is derived"
        );
        assert_eq!(
            premium.stated_percent, None,
            "the response's percentage is a *remaining* one, and the panel prints a stated one as used"
        );
        assert!(
            premium.period_end.is_some(),
            "quota_reset_date_utc parses as the period end"
        );
        // Asked of the manifest, because that is what the sentence claims:
        // `copilot.toml` declares no `[status]`. Asking the parse result
        // instead would be green for a manifest that declares one whose paths
        // simply miss — the reading is `None` either way.
        assert!(m.status.is_none(), "copilot.toml declares no [status]");
        assert!(
            parse_quota(&paid, &m).is_none(),
            "so nothing reads a standing out of this body"
        );

        // The free plan's own branch, in the shape the client's source reads it
        // — constructed, since no free account was observed here. The figures
        // are invented; what is pinned is which field the manifest treats as
        // the remainder and which as the ceiling. The client's own division
        // (`limited_user_quotas / monthly_quotas`) is what settles that, and
        // getting it backwards would draw a full month's allowance as what is
        // left of it.
        let free = json!({
            "access_type_sku": "free_limited_copilot",
            "copilot_plan": "free",
            "limited_user_quotas": { "chat": 20, "completions": 1000 },
            "monthly_quotas": { "chat": 50, "completions": 2000 },
            "limited_user_reset_date": "2026-09-01",
        });
        let free_rows = parse_balances(&free, &m);
        assert_eq!(
            free_rows.len(),
            2,
            "chat and completions — and no premium row"
        );
        let plain = |v: f64| {
            Some(crate::model::BalanceAmount::Number {
                value: v,
                unit: None,
            })
        };
        assert_eq!(free_rows[0].key, "free-chat:");
        assert_eq!(
            free_rows[0].remaining,
            plain(20.0),
            "what is left, per the client's division"
        );
        assert_eq!(free_rows[0].cap, plain(50.0), "and the month's ceiling");
        assert_eq!(free_rows[1].key, "free-completions:");
        assert_eq!(free_rows[1].remaining, plain(1000.0));
        assert_eq!(free_rows[1].cap, plain(2000.0));
        // The period end, both ways, because the shape of that field was not
        // observed either. A bare `YYYY-MM-DD` — what its paid-side sibling
        // sends — is not RFC3339, so it does not parse and the row draws its
        // figures without a date; the same field sent as a timestamp does
        // parse. Declaring the path is therefore free: it costs nothing in the
        // first case and works in the second.
        assert!(
            free_rows[0].period_end.is_none(),
            "a zoneless date is not a timestamp"
        );
        let dated = json!({
            "limited_user_quotas": { "chat": 20 },
            "monthly_quotas": { "chat": 50 },
            "limited_user_reset_date": "2026-09-01T00:00:00Z",
        });
        assert!(
            parse_balances(&dated, &m)[0].period_end.is_some(),
            "and the same field as a timestamp does draw a date"
        );

        // One path resolving and the other not — the case neither "all" nor
        // "nothing" covers. A balance draws on any figure it can read, so a
        // response carrying `monthly_quotas` without `limited_user_quotas`
        // puts a lone ceiling on the panel. Nothing invents the other half,
        // and no plan measured here sends one without the other; pinned so
        // that if one ever does, this is a known shape rather than a surprise.
        let half = json!({ "monthly_quotas": { "chat": 50 } });
        let half_rows = parse_balances(&half, &m);
        assert_eq!(half_rows.len(), 1);
        assert_eq!(half_rows[0].cap, plain(50.0));
        assert!(
            half_rows[0].remaining.is_none(),
            "and nothing stands in for what was not sent"
        );

        // A body carrying neither plan's fields: no row at all.
        let neither = json!({
            "quota_reset_date_utc": "2026-09-01T00:00:00.000Z",
            "quota_snapshots": { "chat": bucket("chat", true, 0, 0.0) },
        });
        assert!(
            parse_balances(&neither, &m).is_empty(),
            "a path that resolves to nothing draws no row, not a 0-of-0"
        );

        // And the case the manifest comment names as this row's known weakness.
        // Constructed, like the two above: the measured account has this bucket
        // metered, and `unlimited` was seen only on the two buckets nothing
        // reads. What it pins is again a property of the manifest — a bucket
        // marked unlimited is read exactly like any other, so its zeroes are
        // drawn as sent. Nothing concludes "exhausted" from them, and nothing
        // distinguishes them either, which is why this is written down rather
        // than discovered later.
        let unlimited = json!({
            "quota_reset_date_utc": "2026-09-01T00:00:00.000Z",
            "quota_snapshots": { "premium_interactions": bucket("premium_interactions", true, 0, 0.0) },
        });
        let drawn = parse_balances(&unlimited, &m);
        assert_eq!(
            drawn.len(),
            1,
            "the row is still drawn — `unlimited` is a field nothing here reads"
        );
        // The whole pair, not just one half: a regression that dropped
        // `remaining` would leave a lone `cap 0` on the panel and still satisfy
        // an assertion about the ceiling alone.
        assert_eq!(drawn[0].cap, number(0.0));
        assert_eq!(drawn[0].remaining, number(0.0));
        assert!(drawn[0].used.is_none());
        assert!(drawn[0].period_end.is_some());
    }

    /// Enumerating windows (`windows.for_each`) on the manifest that ships,
    /// against the shape Anthropic actually answers with (structure measured
    /// 2026-08-22; figures invented).
    ///
    /// The count is the assertion that matters. `limits[]` carries the session
    /// and weekly-all windows *as well as* the scoped one, and the two fixed
    /// entries above already draw those from `five_hour`/`seven_day` — so a
    /// filter that matched them too would silently draw five rows where the
    /// provider reports three, two of them the same figure under a different
    /// caption, and nothing else on the panel would object.
    #[test]
    fn the_shipped_claude_manifest_expands_one_row_per_scoped_model_and_no_more() {
        let (_, contents) = crate::plugin::seed::DEFAULT_TEMPLATES
            .iter()
            .find(|(name, _)| *name == "claude.toml")
            .expect("claude.toml ships");
        let m = PluginManifest::from_str(contents).expect("the shipped manifest parses");
        let limit = |kind: &str, percent: i64, resets: &str, model: Option<&str>| {
            json!({
                "kind": kind,
                "group": if kind == "session" { "session" } else { "weekly" },
                "percent": percent,
                "severity": "normal",
                "resets_at": resets,
                "scope": model.map(|m| json!({ "model": { "id": null, "display_name": m } })),
                "is_active": true,
            })
        };
        let body = json!({
            "five_hour": { "utilization": 22.0, "resets_at": "2026-01-01T00:00:00Z" },
            "seven_day": { "utilization": 53.0, "resets_at": "2026-01-01T00:00:00Z" },
            "seven_day_opus": null,
            "limits": [
                limit("session", 22, "2026-01-01T00:00:00Z", None),
                limit("weekly_all", 53, "2026-01-01T00:00:00Z", None),
                limit("weekly_scoped", 32, "2026-01-02T09:31:00Z", Some("Fable")),
            ],
        });

        let windows = parse_usage(&body, &m).expect("both required windows are present");
        assert_eq!(
            windows.len(),
            3,
            "two fixed rows and one scoped model — not five"
        );
        let scoped = windows
            .iter()
            .find(|w| w.label == "Fable weekly")
            .expect("the scoped row");
        assert_eq!(
            scoped.used_percent,
            Some(32.0),
            "read from the element, not from the root"
        );
        // A different *instant*, not the same one written another way: the
        // weekly rows reset at NY2026, and an assertion that passed for both
        // would be green even if these paths resolved from the response root.
        assert_eq!(
            scoped.resets_at,
            Some(1_767_346_260),
            "its own reset moment, read from the element"
        );
        assert_ne!(
            scoped.resets_at, windows[1].resets_at,
            "and not the weekly one"
        );
        assert_eq!(
            scoped.role,
            crate::model::Role::Extra,
            "out of the menu bar and the 5H/WK slots"
        );
        assert_eq!(
            scoped.key, "claude-wk-model:Fable",
            "the element half of the key is the model, so the row keeps its registry entry"
        );

        // A second scoped model is a second row, keyed apart from the first —
        // the case a fixed selector could not express at all.
        let mut two = body.clone();
        two["limits"].as_array_mut().expect("array").push(limit(
            "weekly_scoped",
            7,
            "2026-01-01T00:00:00Z",
            Some("Opus 4.6"),
        ));
        let windows = parse_usage(&two, &m).expect("still readable");
        assert_eq!(windows.len(), 4);
        assert_eq!(
            windows
                .iter()
                .filter(|w| w.key.starts_with("claude-wk-model:"))
                .count(),
            2,
            "one row per scoped model"
        );
        assert!(
            windows
                .iter()
                .any(|w| w.key == "claude-wk-model:Opus%204%2E6"),
            "a space and a dot in a model name are both encoded — the dot especially, since this \
             key becomes a segment of a dotted path in the user's config"
        );

        // Two elements that name the same model are one row: a key is a path in
        // the user's config, and two rows writing the same one would take turns
        // overwriting each other.
        let mut twice = body.clone();
        twice["limits"].as_array_mut().expect("array").push(limit(
            "weekly_scoped",
            9,
            "2026-01-02T09:31:00Z",
            Some("Fable"),
        ));
        let windows = parse_usage(&twice, &m).expect("still readable");
        assert_eq!(
            windows.len(),
            3,
            "the duplicate identity collapses into the row it names"
        );

        // The identity is the raw text, not the sanitised caption. Two names
        // that differ only by a directional mark are two models as far as the
        // provider is concerned, and sanitising before keying would file both
        // rows under one path.
        let mut invisible = body.clone();
        invisible["limits"]
            .as_array_mut()
            .expect("array")
            .push(limit(
                "weekly_scoped",
                9,
                "2026-01-02T09:31:00Z",
                Some("Fab\u{202E}le"),
            ));
        let windows = parse_usage(&invisible, &m).expect("still readable");
        assert_eq!(windows.len(), 4, "two identities, two rows");
        assert!(
            windows.iter().all(|w| !w.label.contains('\u{202E}')),
            "while the caption that reaches the screen is sanitised"
        );

        // Rows come out ordered by identity rather than by the array's order,
        // which the provider promises nothing about.
        let mut reordered = body.clone();
        reordered["limits"]
            .as_array_mut()
            .expect("array")
            .push(limit(
                "weekly_scoped",
                7,
                "2026-01-02T09:31:00Z",
                Some("Aardvark"),
            ));
        let windows = parse_usage(&reordered, &m).expect("still readable");
        let scoped: Vec<&str> = windows
            .iter()
            .filter(|w| w.key.starts_with("claude-wk-model:"))
            .map(|w| w.label.as_str())
            .collect();
        assert_eq!(
            scoped,
            vec!["Aardvark weekly", "Fable weekly"],
            "sorted, not as sent"
        );

        // An account whose plan scopes nothing: the entry is not `required`,
        // so the two fixed rows still read and no third appears.
        let mut none_scoped = body.clone();
        none_scoped["limits"]
            .as_array_mut()
            .expect("array")
            .truncate(2);
        assert_eq!(
            parse_usage(&none_scoped, &m).expect("still readable").len(),
            2
        );

        // And an element the manifest cannot name draws no row rather than an
        // anonymous one: same rule as everywhere else on this panel.
        let mut unnamed = body.clone();
        unnamed["limits"][2]["scope"] = json!({ "model": { "id": null } });
        assert_eq!(parse_usage(&unnamed, &m).expect("still readable").len(), 2);
    }

    // ── for_each caps / element identity ─────────────────────────────────

    /// A manifest that enumerates a bare array by name — the minimal shape
    /// [`FOR_EACH_MAX_ELEMENTS`] and [`element_identity`]'s hash suffix need
    /// to exercise, as opposed to claude.toml's own `limits[]` (three fixed
    /// captions plus scoped models mixed in, which would make either test
    /// about the filter rather than about the cap or the identity).
    fn for_each_manifest() -> PluginManifest {
        let toml = r#"
            id         = "sample"
            name       = "Sample"
            menu_label = "Sa"
            order      = 1
            engine     = "http-api"
            requires_reader = ["window-identity", "for-each-windows"]

            [[windows]]
            label = "{name}"
            role  = "extra"
            for_each = "items"
            element_id_path = "name"
            [windows.period]
            mode    = "assumed"
            assumed = 10080
            [windows.source]
            used_percent_path = "used_percent"
            resets_at_path    = "resets_at"

            [http]
            [[http.request]]
            url = "https://example.com/usage"
        "#;
        PluginManifest::from_str(toml).expect("valid manifest")
    }

    /// Elements past the cap are never scanned at all — not filtered out
    /// after the fact — so a provider sending far more than
    /// `FOR_EACH_MAX_ELEMENTS` elements costs this engine a fixed amount of
    /// work rather than one proportional to whatever it sent. The truncation
    /// itself is reported once, not once per dropped element.
    #[test]
    fn a_for_each_array_past_the_cap_is_truncated_and_reported_once() {
        let m = for_each_manifest();
        let items: Vec<Value> = (0..(FOR_EACH_MAX_ELEMENTS + 6))
            .map(|i| json!({ "name": format!("item-{i}"), "used_percent": 1.0, "resets_at": 1 }))
            .collect();
        let body = json!({ "items": items });

        let windows = parse_usage(&body, &m).expect("nothing here is `required`");
        assert_eq!(
            windows.len(),
            FOR_EACH_MAX_ELEMENTS,
            "only the first {FOR_EACH_MAX_ELEMENTS} elements are ever considered"
        );

        let diag = take_pending_diagnostics();
        assert!(
            diag.iter().any(|line| line.contains("for_each")),
            "the truncation is reported once: {diag:?}"
        );
    }

    /// The defect `element_identity`'s hash suffix exists to close: two
    /// elements whose identity text agrees for the first
    /// `PROVIDER_TEXT_MAX_CHARS` characters and only differs after it used to
    /// truncate to one identical row key, and `build_windows`' dedup — which
    /// has nothing else to key on — silently kept one and dropped the other.
    #[test]
    fn two_elements_sharing_a_long_identity_prefix_still_produce_two_rows() {
        let m = for_each_manifest();
        let shared_prefix = "x".repeat(crate::plugin::PROVIDER_TEXT_MAX_CHARS + 10);
        let body = json!({ "items": [
            { "name": format!("{shared_prefix}-A"), "used_percent": 1.0, "resets_at": 1 },
            { "name": format!("{shared_prefix}-B"), "used_percent": 2.0, "resets_at": 1 },
        ]});

        let windows = parse_usage(&body, &m).expect("nothing here is `required`");
        assert_eq!(
            windows.len(),
            2,
            "two distinct elements must produce two rows, neither dropped by dedup"
        );
        assert_ne!(windows[0].key, windows[1].key);
    }

    /// The identity function itself, on the boundary the test above exercises
    /// end to end: two names sharing a prefix longer than the cap hash apart
    /// rather than truncating to the same text, and the result never exceeds
    /// the cap either way.
    #[test]
    fn element_identity_hashes_the_tail_of_a_name_longer_than_the_cap() {
        let cap = crate::plugin::PROVIDER_TEXT_MAX_CHARS;
        let shared_prefix = "x".repeat(cap + 10);
        let a = element_identity(&json!({ "name": format!("{shared_prefix}-A") }), "name")
            .expect("resolves");
        let b = element_identity(&json!({ "name": format!("{shared_prefix}-B") }), "name")
            .expect("resolves");
        assert_ne!(
            a, b,
            "sharing the visible prefix must not collapse the identity"
        );
        assert!(a.chars().count() <= cap);
        assert!(b.chars().count() <= cap);

        // A name within the cap is untouched — only a truncated one pays for
        // the hash suffix.
        let short = element_identity(&json!({ "name": "Fable" }), "name").expect("resolves");
        assert_eq!(short, "Fable");
    }

    /// A template naming several placeholders can still run well past
    /// `PROVIDER_TEXT_MAX_CHARS` once they are all concatenated, even though
    /// each one alone was sanitised under the cap.
    #[test]
    fn fill_label_caps_the_whole_substituted_label_not_just_each_placeholder() {
        let cap = crate::plugin::PROVIDER_TEXT_MAX_CHARS;
        let element = json!({ "a": "x".repeat(50), "b": "y".repeat(50) });
        let filled = fill_label("{a}-{b}", &element).expect("both placeholders resolve");
        assert_eq!(
            filled.chars().count(),
            cap,
            "the finished label is capped as a whole, not per placeholder"
        );
    }

    /// `reached_type` is free text from the network, and it lands in the panel
    /// and in the log. It is the one field here a provider fills in.
    #[test]
    fn a_hostile_reached_type_is_cut_down_before_it_reaches_the_screen() {
        let m = status_manifest();
        let quota_for = |v: Value| {
            parse_quota(&json!({ "rate_limit_reached_type": { "type": v } }), &m)
                .map(|s| s.reached_type)
        };

        // Newlines would turn one line into several — in the log too, where
        // the next line is a different record.
        assert_eq!(
            quota_for(json!("rate\nlimit\r\nreached"))
                .flatten()
                .as_deref(),
            Some("ratelimitreached")
        );
        // A bidi override can visually reverse the text printed after it.
        assert_eq!(
            quota_for(json!("safe\u{202E}reversed"))
                .flatten()
                .as_deref(),
            Some("safereversed")
        );
        // Zero-width characters hide a difference between two strings that
        // look identical.
        assert_eq!(
            quota_for(json!("a\u{200B}b")).flatten().as_deref(),
            Some("ab")
        );
        // The directional marks (distinct from the overrides above), the word
        // joiner, and the Unicode line and paragraph separators: `is_control`
        // does not catch any of these, so a provider could still end a line
        // inside one without a control character in sight.
        for (name, hostile) in [
            ("left-to-right mark", "a\u{200E}b"),
            ("right-to-left mark", "a\u{200F}b"),
            ("arabic letter mark", "a\u{061C}b"),
            ("word joiner", "a\u{2060}b"),
            ("line separator", "a\u{2028}b"),
            ("paragraph separator", "a\u{2029}b"),
            ("soft hyphen", "a\u{00AD}b"),
        ] {
            assert_eq!(
                quota_for(json!(hostile)).flatten().as_deref(),
                Some("ab"),
                "{name} has to be stripped like the rest of its class"
            );
        }
        // And a provider deciding to answer with a megabyte does not get to
        // decide how tall the panel is.
        let long = "x".repeat(10_000);
        let cut = quota_for(json!(long)).flatten().expect("still a string");
        assert_eq!(cut.chars().count(), crate::plugin::PROVIDER_TEXT_MAX_CHARS);

        // A non-string is not coerced into one: a provider answering with an
        // object here has changed shape, and rendering it would hide that.
        assert_eq!(quota_for(json!({ "nested": true })).flatten(), None);
        assert_eq!(quota_for(json!(7)).flatten(), None);
        // A value that sanitises away to nothing is not a statement.
        assert_eq!(quota_for(json!("\u{200B}\u{200B}")).flatten(), None);
    }

    /// `"none"`/`"null"` name no reason at all — the shape a provider that
    /// fills this field in the *ordinary*, not-blocked case uses (Codex's own
    /// comment on `QuotaStatus::is_blocked` names exactly this: `"type":
    /// "none"`). A manifest declaring only `reached_type_path`, no booleans,
    /// must not read either word as a refusal.
    #[test]
    fn reached_type_of_none_or_null_is_read_as_no_statement_at_all() {
        let m = status_manifest();
        let quota_for =
            |v: Value| parse_quota(&json!({ "rate_limit_reached_type": { "type": v } }), &m);
        assert_eq!(quota_for(json!("none")), None);
        assert_eq!(quota_for(json!("null")), None);
        // Case doesn't rescue it either.
        assert_eq!(quota_for(json!("None")), None);
        assert_eq!(quota_for(json!("NULL")), None);
        // A real reason still reads through.
        assert_eq!(
            quota_for(json!("rate_limit_reached"))
                .and_then(|s| s.reached_type)
                .as_deref(),
            Some("rate_limit_reached")
        );
    }

    // ── perform's scheme guard ────────────────────────────────────────────
    //
    // The one corner of `perform` that runs before any network I/O, so it is
    // the one corner of `perform` a test can exercise at all — no agent is
    // ever built for a rejected scheme.

    #[test]
    fn perform_refuses_a_non_https_url_before_opening_any_connection() {
        let err = perform(
            "http://example.com/usage",
            HttpMethod::Get,
            None,
            &[],
            Duration::from_secs(1),
        )
        .expect_err("a plaintext URL must never be dispatched");
        assert!(
            err.message.contains("https"),
            "the refusal must name what it wanted: {}",
            err.message
        );
        assert!(
            !err.terminal,
            "fixed by editing the manifest, not by a fresh sign-in — this backs off, it does \
             not stop forever"
        );
    }

    #[test]
    fn perform_refuses_an_unparsable_url_the_same_way() {
        let err = perform(
            "not a url at all",
            HttpMethod::Get,
            None,
            &[],
            Duration::from_secs(1),
        )
        .expect_err("nothing not even shaped like a URL may reach an agent");
        assert!(!err.terminal);
    }

    // ── read_json_body's byte cap ────────────────────────────────────────

    #[test]
    fn read_json_body_parses_an_ordinary_body() {
        let response =
            ureq::Response::new(200, "OK", r#"{"used_percent": 42}"#).expect("build a response");
        let value = read_json_body(response).expect("an ordinary small body parses");
        assert_eq!(value["used_percent"].as_i64(), Some(42));
    }

    #[test]
    fn read_json_body_refuses_a_body_over_the_cap_rather_than_reading_it_all() {
        // One byte over: `into_json()` (`ureq`'s own helper, unbounded) would
        // have read this whole thing into memory before ever finding out it
        // wasn't going to stop.
        let oversized = "x".repeat(MAX_PROVIDER_RESPONSE_BYTES as usize + 1);
        let body = format!("{{\"padding\":\"{oversized}\"}}");
        let response = ureq::Response::new(200, "OK", &body).expect("build a response");
        let err = read_json_body(response).expect_err("a body over the cap must be refused");
        assert!(
            err.contains(&MAX_PROVIDER_RESPONSE_BYTES.to_string()),
            "the refusal should name the cap: {err}"
        );
    }

    // ── refuse_unsafe_header_values ──────────────────────────────────────

    #[test]
    fn refuse_unsafe_header_values_names_the_header_never_the_value() {
        let headers = vec![(
            "Authorization".to_string(),
            "Bearer tok\u{00A0}".to_string(),
        )];
        let err = refuse_unsafe_header_values(&headers).expect_err("must refuse");
        assert!(err.contains("Authorization"));
        assert!(!err.contains("tok"), "the value must never appear: {err}");

        let ok = vec![("Authorization".to_string(), "Bearer tok-1".to_string())];
        assert!(refuse_unsafe_header_values(&ok).is_ok());

        // Tab and space are both legal inside a header value.
        let with_space = vec![("User-Agent".to_string(), "app/1.0 (mac)".to_string())];
        assert!(refuse_unsafe_header_values(&with_space).is_ok());
    }
}
