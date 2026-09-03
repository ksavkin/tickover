//! The provider plugin manifest: a per-provider TOML file that describes how
//! to read its usage windows without a dedicated Rust module.
//!
//! This schema is a **stable, additive contract**: the engines
//! ([`crate::plugin::engine_logfile`], [`crate::plugin::engine_http`]) and the
//! credential chain ([`crate::plugin::auth`]) are built against the types
//! here, and it grows only by adding new optional fields.
//! `#[serde(deny_unknown_fields)]` is deliberately **not** used: a manifest
//! field a future version of this reader doesn't know about yet must be
//! ignored, not rejected.
//!
//! ```text
//! id            = "codex"
//! name          = "Codex"
//! menu_label    = "Cx"
//! order         = 10
//! engine        = "log-file"        # | "http-api"
//! refresh_secs  = 15                # default 60
//! enabled       = true              # default true
//!
//! [tag]
//! from  = "field"                   # "static" | "field" | "none" (default)
//! path  = "plan_type"
//!
//! [account]
//! type       = "jwt-file"           # "none" (default) | "jwt-file" | "http"
//! path       = "~/.codex/auth.json"
//! token_path = "tokens.id_token"
//! claim      = "email"
//!
//! [[windows]]
//! label = "5H"
//! role  = "primary"                 # | "secondary"
//! [windows.period]
//! mode  = "from_field"              # "assumed" | "from_field"
//! field = "window_minutes"
//! [windows.source]
//! used_percent_path = "used_percent"
//! resets_at_path    = "resets_at"
//!
//! [logfile]                        # required when engine = "log-file"
//! root          = "~/.codex/sessions"
//! glob          = "**/rollout-*.jsonl"
//! container_key = "rate_limits"
//!
//! [http]                           # required when engine = "http-api"
//! [[http.request]]
//! url = "https://api.anthropic.com/api/oauth/usage"
//! [http.request.headers]
//! Authorization = "Bearer {token}"
//!
//! [[surface]]                      # optional; default: one "default", no auth
//! id = "cli"
//! [[surface.auth]]
//! type = "credentials-file"
//! path = "~/.claude/.credentials.json"
//! token_json_path = "claudeAiOauth.accessToken|access_token"
//!
//! [[option]]                       # optional; declarative bool options
//! key     = "include_beta"          # substitution-safe: {option.include_beta}
//! label   = "Include beta usage"
//! default = false
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

// ── Top level ─────────────────────────────────────────────────────────────

/// One provider's plugin manifest, parsed and validated.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PluginManifest {
    /// Stable identifier ("codex", "claude"). Must be non-empty.
    pub id: String,
    /// Display name for the popup section header ("Codex" / "Claude"). Must
    /// be non-empty.
    pub name: String,
    /// Short label for the menu-bar pill and title ("Cx" / "Cl"). Must be
    /// non-empty.
    pub menu_label: String,
    /// Sort key across providers; ties break on `id`.
    pub order: i64,
    /// Plugin version (free-form; compared as semver by
    /// `crate::plugin::registry::version_cmp` where a registry is involved).
    /// Defaults to `""` for manifests predating the plugin registry — a
    /// blank version is backward-compatible (not an `Option`, so registry
    /// comparisons never have to unwrap it; an unset version simply loses
    /// every semver-vs-string comparison it's involved in).
    #[serde(default)]
    pub version: String,
    /// Which engine reads this provider's usage data.
    pub engine: EngineKind,
    /// Poll interval in seconds.
    #[serde(default = "default_refresh_secs")]
    pub refresh_secs: u64,
    /// Whether the plugin is active at all.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// `requires_reader` — the reader capabilities this manifest needs, by
    /// name (see [`crate::plugin::capability`]). Absent means `[]`: a manifest
    /// that asks for nothing beyond the base schema, which is every manifest
    /// written before this field existed.
    ///
    /// Checked in [`PluginManifest::from_str`] rather than in
    /// [`PluginManifest::validate`], because the check that a manifest
    /// *declares* what it uses reads the raw TOML — the point of it is to
    /// recognise fields this build has nowhere to put.
    #[serde(default)]
    pub requires_reader: Vec<String>,

    /// `[tag]` — the plan/surface chip next to the provider name.
    #[serde(default)]
    pub tag: TagConfig,
    /// `[account]` — where the account email comes from.
    #[serde(default)]
    pub account: AccountConfig,
    /// `[[windows]]` — the quota windows this provider reports. A manifest
    /// needs at least one window **or** at least one balance; see `balances`.
    #[serde(default)]
    pub windows: Vec<WindowConfig>,
    /// `[[balances]]` — figures against a calendar period (credits left, spent
    /// this month). Empty for a provider that reports only windows, which is
    /// both shipped manifests today.
    #[serde(default)]
    pub balances: Vec<BalanceConfig>,
    /// `[status]` — where the provider states the standing of the quota
    /// itself, as opposed to the standing of one of its windows.
    ///
    /// Optional, and absent is a real answer rather than a gap: Claude's
    /// response carries no such statement at all (its `severity` lives inside
    /// `limits[]`, and `spend` is a balance), so its manifest declares none and
    /// its panel section says exactly what it said before.
    ///
    /// Needs `requires_reader = ["reading-status"]`.
    pub status: Option<StatusConfig>,

    /// `[logfile]` — required when `engine = "log-file"`.
    pub logfile: Option<LogFileConfig>,
    /// `[http]` — required when `engine = "http-api"`.
    pub http: Option<HttpConfig>,

    /// `[[surface]]` — the surfaces (accounts/installs) this provider can be
    /// read from. Defaults to a single opt-out "default" surface with no
    /// auth chain when omitted entirely — see [`PluginManifest::from_str`].
    #[serde(default)]
    pub surface: Vec<SurfaceConfig>,

    /// `[ping]` — optional auto-ping command run after a window resets.
    pub ping: Option<PingConfig>,

    /// `[[option]]` — declarative bool options the plugin exposes to its own
    /// engine substitution (`{option.<key>}` in a header, URL or log-file
    /// path — see the engines' own docs). Purely declarative here: this
    /// schema layer only carries the key/label/default triple, and nothing
    /// in this module reads or stores a *value* — that's
    /// `crate::config::plugin_option`, resolved once per fetch by
    /// `src/main.rs` and passed into the engines (which never read config
    /// themselves).
    #[serde(default)]
    pub option: Vec<OptionConfig>,
}

fn default_refresh_secs() -> u64 {
    60
}

fn default_true() -> bool {
    true
}

impl PluginManifest {
    /// Parse and validate a manifest from its TOML source.
    ///
    /// Four steps, in this order:
    ///
    /// 1. **Parse as a document** — a `toml::Value`, which holds every key the
    ///    file has rather than every key this build has a field for.
    /// 2. **Capabilities** ([`crate::plugin::capability::check`]) — does this
    ///    build understand what the manifest is asking for, and did the
    ///    manifest say what it is asking for.
    /// 3. **Parse as this struct**, then fill in missing-but-defaulted fields
    ///    (see the per-field docs); an absent `[[surface]]` list is replaced
    ///    with a single opt-out "default" surface with no auth chain, matching
    ///    the schema's stated default.
    /// 4. **Validation** — see [`PluginManifest::validate`].
    ///
    /// The capability check sits above the typed parse rather than after it,
    /// and that ordering is the point of it. A manifest from the future does
    /// not only add fields — it also changes the type of one that exists, and
    /// deserialization answers a `label` that became a table with a TOML type
    /// error while the `requires_reader` line naming the capability sits
    /// unread a few lines above. Checked first, the same file hears "update
    /// the app", which is both true and actionable.
    // Deliberately an inherent method rather than `FromStr`. Not because a
    // trait impl would be unsound — one delegating here would behave
    // identically — but because `.parse()` reads as "turn this text into a
    // value", and this runs the capability gate before the typed parse and
    // then validates, refusing documents a parse would accept. A named
    // constructor says at the call site which of the two is happening. A
    // judgment call, recorded as one.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(input: &str) -> Result<Self, String> {
        // Every manifest arrives here — seeded, hand-written, imported or
        // downloaded — so this is the one place a byte-order mark has to be
        // dealt with, and it has to be before either parse: a BOM makes both
        // of them fail on line 1. See [`crate::plugin::strip_bom`].
        let input = crate::plugin::strip_bom(input);
        let raw: toml::Value =
            toml::from_str(input).map_err(|e| format!("invalid manifest TOML: {e}"))?;
        crate::plugin::capability::check(&raw)?;
        // Parsed a second time, now into this struct. The two passes are the
        // same parser over the same bytes, so they cannot disagree about the
        // document; what differs is that this one keeps only the fields this
        // build knows, which is exactly what the check above had to see past.
        let mut manifest: PluginManifest =
            toml::from_str(input).map_err(|e| format!("invalid manifest TOML: {e}"))?;
        manifest.apply_defaults();
        manifest.validate()?;
        Ok(manifest)
    }

    fn apply_defaults(&mut self) {
        // The gate trims before comparing, so `" window-presence"` gets past
        // it. Store what it accepted, not what was typed — otherwise code
        // asking `requires_reader.contains("window-presence")` would answer
        // no for a manifest the gate already agreed declares it.
        for name in &mut self.requires_reader {
            *name = name.trim().to_string();
        }
        if self.surface.is_empty() {
            self.surface.push(SurfaceConfig {
                id: "default".to_string(),
                label: "Default".to_string(),
                opt_in: false,
                in_menu_bar: true,
                allowed_hosts: Vec::new(),
                no_credentials_message: None,
                auth: Vec::new(),
            });
        }
    }

    /// Validate the required-field and cross-field invariants of the
    /// manifest. Called by [`PluginManifest::from_str`]; exposed separately
    /// so callers who construct a `PluginManifest` some other way (tests,
    /// future config UI) can re-check it.
    ///
    /// **This is not the whole gate.** The `requires_reader` check
    /// ([`crate::plugin::capability`]) runs in [`PluginManifest::from_str`]
    /// and nowhere else, because it reads the raw TOML rather than this
    /// struct — a manifest that reaches this app as text has been through it,
    /// and one assembled in memory has not. Anything that starts accepting
    /// manifests by some other route has to call that check itself.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("`id` must not be empty".to_string());
        }
        // `id` is used as a filename stem (`add-plugin`/`find_plugin_manifest_path`
        // in `src/main.rs` write/scan `<id>.toml` inside the plugins directory)
        // and as a config-key segment (`plugin.<id>.*` in `crate::config`) — a
        // path separator or a `..` component in an unvalidated id would let a
        // hostile third-party manifest write/delete outside that directory.
        // Restricting to a safe charset closes that off at the source; the
        // filesystem write path in `src/main.rs` still double-checks
        // containment as defence in depth (see `plugin_manifest_target`).
        if !self
            .id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(format!(
                "`id = \"{}\"` must contain only ASCII letters, digits, underscores and hyphens",
                self.id
            ));
        }
        if self.name.trim().is_empty() {
            return Err("`name` must not be empty".to_string());
        }
        if self.menu_label.trim().is_empty() {
            return Err("`menu_label` must not be empty".to_string());
        }

        if self.refresh_secs == 0 {
            return Err("`refresh_secs` must be greater than 0".to_string());
        }

        match self.engine {
            EngineKind::LogFile if self.logfile.is_none() => {
                return Err("engine = \"log-file\" requires a [logfile] section".to_string());
            }
            EngineKind::HttpApi => match &self.http {
                None => {
                    return Err("engine = \"http-api\" requires an [http] section".to_string());
                }
                Some(http) if http.request.len() != 1 => {
                    return Err(format!(
                        "engine = \"http-api\" requires exactly one [[http.request]], found {}",
                        http.request.len()
                    ));
                }
                Some(_) => {}
            },
            _ => {}
        }

        // A section can be present and still say nothing. `root`, `glob` and
        // `container_key` are what the log engine walks, matches and reads;
        // any of them left empty is a provider that reports "no matching
        // files" forever, for a reason the row it lands on cannot express.
        // Required-and-present is not the same as usable.
        if let Some(lf) = &self.logfile {
            let blank: &[(&str, bool)] = &[
                ("root", lf.root.trim().is_empty()),
                ("glob", lf.glob.trim().is_empty()),
                ("container_key", lf.container_key.trim().is_empty()),
            ];
            if let Some((field, _)) = blank.iter().find(|(_, empty)| *empty) {
                return Err(format!("`[logfile] {field}` must not be empty"));
            }
        }
        // Same for the one endpoint an http manifest calls: an empty URL is a
        // request that cannot be sent, and `allowed_hosts` has no host to
        // check it against either.
        if let Some(http) = &self.http {
            if let Some(req) = http.request.iter().find(|r| r.url.trim().is_empty()) {
                let _ = req;
                return Err("`[[http.request]] url` must not be empty".to_string());
            }
        }
        // A GET has nowhere to put a body — `perform` only ever attaches one
        // to a POST — so `body` under the default `method = "get"` is a
        // request that cannot be sent as written, not a body silently
        // dropped. The reverse is not the same shape of mistake: `method =
        // "post"` with no `body` is a complete, sendable POST (its payload is
        // the URL and the credentials in its headers) — exactly what
        // Antigravity's `:retrieveUserQuotaSummary` needs — so it is legal
        // rather than required to spell out `body = ""`.
        if let Some(http) = &self.http {
            if http
                .request
                .iter()
                .any(|r| r.body.is_some() && r.method != HttpMethod::Post)
            {
                return Err(
                    "`[[http.request]] body` requires `method = \"post\"` — a GET request has \
                     nowhere to put a body"
                        .to_string(),
                );
            }
        }
        // A `{` earlier in the body than a placeholder — most commonly a JSON
        // object's own opening brace — can swallow that placeholder before
        // this app, or the engine, ever reads its name; see
        // `body_swallows_a_placeholder` for the exact failure this catches.
        // Checked here, at load, rather than left to be discovered as a
        // request sent with a literal `{token}` still in it.
        if let Some(http) = &self.http {
            for req in &http.request {
                if let Some(body) = &req.body {
                    if let Some(marker) = body_swallows_a_placeholder(body) {
                        return Err(format!(
                            "`[[http.request]] body` names {marker}, but an earlier `{{` in the \
                             body — typically a JSON object's own opening brace — pairs with that \
                             placeholder's closing brace before its name is ever read, so it would \
                             be sent on the wire exactly as written"
                        ));
                    }
                }
            }
        }

        // A provider has to report *something*. Windows were the only shape
        // this could take until Grok, whose response carries no window key at
        // all — only a monthly billing period — so "at least one [[windows]]"
        // made a whole class of provider unwritable as a plugin. The rule is
        // the same rule with the second shape added, not a weaker one: a
        // manifest that declares neither still cannot draw a row.
        if self.windows.is_empty() && self.balances.is_empty() {
            return Err("at least one [[windows]] or [[balances]] section is required".to_string());
        }

        let primary_count = self
            .windows
            .iter()
            .filter(|w| w.role == Role::Primary)
            .count();
        if primary_count > 1 {
            return Err(format!(
                "at most one window may have role = \"primary\", found {primary_count}"
            ));
        }

        // `[[windows]] id` becomes a segment of the seen-window registry key in
        // the user's `config.json`, whose paths are dot-separated — a `.` in it
        // would split the path and grow a neighbouring table in their config.
        // The charset is a whitelist for the same reason the plugin `id` above
        // has one, and the length cap is because the key is written to disk
        // once per window per tick.
        for w in &self.windows {
            if w.id.is_empty() {
                continue;
            }
            let ok = w.id.len() <= WINDOW_ID_MAX_BYTES
                && w.id
                    .starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                && w.id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
            if !ok {
                return Err(format!(
                    "windows[label = \"{}\"]: `id = \"{}\"` must be at most {WINDOW_ID_MAX_BYTES} \
                     bytes of lowercase ASCII letters, digits and hyphens, starting with a letter \
                     or digit",
                    w.label, w.id
                ));
            }
        }
        // Two entries sharing an identity share a registry entry, a row in the
        // reconciler and a target for the ping. Compared on the *resolved*
        // entry key rather than on the declared `id`, because the two can
        // collide: an entry with no id falls back to its position, so a
        // manifest whose first window declares `id = "w1"` and whose second
        // declares nothing produces `w1` twice — no duplicate ids anywhere in
        // the file, and one identity for two windows.
        for i in 0..self.windows.len() {
            let key = self.windows[i].entry_key(i);
            if let Some(j) = (0..i).find(|&j| self.windows[j].entry_key(j) == key) {
                return Err(format!(
                    "windows[{i}] and windows[{j}] resolve to the same identity `{key}` — a \
                     window's `id` must be unique, and must not collide with the `wN` an entry \
                     without one falls back to"
                ));
            }
        }

        // ── Enumerating entries (`for_each`) ────────────────────────────
        //
        // Eight refusals, each closing a way for an expansion to go wrong
        // silently rather than loudly — and silence is the failure mode this
        // mechanism is prone to, since an entry that resolves to nothing draws
        // no row and says nothing about why. The corpus has a line for every
        // one of them (`tests/manifest_corpus.rs`).
        for w in &self.windows {
            let enumerating = w
                .for_each
                .as_deref()
                .map(str::trim)
                .is_some_and(|p| !p.is_empty());
            if !enumerating {
                // The two keys that only mean anything on an expansion. Read on
                // an ordinary entry they would be ignored in silence, and the
                // author would be left looking at one row wondering where the
                // filter went. Refused one by one rather than in a loop, so
                // each key has a refusal — and a corpus line — of its own.
                if w.for_each_where.is_some() {
                    return Err(format!(
                        "windows[label = \"{}\"]: `for_each_where` needs `for_each` — it says \
                         which elements to keep, and without an array there is nothing to keep",
                        w.label
                    ));
                }
                if w.element_id_path.is_some() {
                    return Err(format!(
                        "windows[label = \"{}\"]: `element_id_path` needs `for_each` — it names \
                         the identity of one element, and an ordinary entry has no elements",
                        w.label
                    ));
                }
                // A label is a literal everywhere else, and a `{` in one is
                // either a template on an entry that cannot expand or a
                // provider's brace typed into a caption. Both are worth a
                // sentence at load rather than a puzzling row later.
                if w.label.contains('{') {
                    return Err(format!(
                        "windows[label = \"{}\"]: a `{{placeholder}}` in a label needs \
                         `for_each` — off an enumerating entry a label is a literal",
                        w.label
                    ));
                }
                continue;
            }
            // Only the http engine reads a response it can index into. The log
            // engine's windows come from a log record's own fields, and there
            // is no array there to walk.
            if self.engine != EngineKind::HttpApi {
                return Err(format!(
                    "windows[label = \"{}\"]: `for_each` needs engine = \"http-api\" — the \
                     log-file engine reads a record's fields, not an array in a response",
                    w.label
                ));
            }
            // Without an identity path every row this entry draws would be
            // filed under the same key, or under its position in an array
            // whose order nobody promised.
            match w.element_id_path.as_deref().map(str::trim) {
                Some(p) if !p.is_empty() => {}
                _ => {
                    return Err(format!(
                        "windows[label = \"{}\"]: `for_each` needs `element_id_path` — every row \
                         it draws needs an identity of its own",
                        w.label
                    ));
                }
            }
            // The filter, whose every failure mode is the same one: it matches
            // nothing, forever, and the entry draws no rows for a reason no row
            // can express. So the shapes that cannot match are refused at load
            // — `field=value` with both halves present, and a field that is one
            // key of the element rather than a path into it. The last is the
            // sharpest: `element_id_path` and the label's `{path}` *are* paths,
            // so a filter written as one looks right and never matches (this
            // reads a field with `Value::get`, one segment, like a path
            // selector does).
            if let Some(filter) = w.for_each_where.as_deref() {
                let complaint = match filter.split_once('=') {
                    None => Some("must be `field=value`"),
                    Some((field, value)) => filter_complaint(field.trim(), value.trim()),
                };
                if let Some(complaint) = complaint {
                    return Err(format!(
                        "windows[label = \"{}\"]: `for_each_where = \"{filter}\"` {complaint}",
                        w.label
                    ));
                }
            }
            // The label's own template, checked here because `fill_label` can
            // only answer an unclosed brace with silence: no row, on every
            // element, for a typo the author cannot see from the panel.
            if let Some(complaint) = template_complaint(&w.label) {
                return Err(format!("windows[label = \"{}\"]: {complaint}", w.label));
            }
            // The 5H and WK slots carry one window each — the menu bar reads
            // the primary, and `src/main.rs`'s "not started" placeholder is
            // keyed by role — while an expansion produces as many rows as the
            // provider sends. `primary_count` above counts declared entries and
            // cannot see past an expansion, so the refusal has to be here, and
            // it covers `secondary` for the same reason it covers `primary`.
            if w.role != Role::Extra {
                return Err(format!(
                    "windows[label = \"{}\"]: an enumerating entry must be `role = \"extra\"` \
                     — the 5H and WK slots hold one window each, and this entry draws as many as \
                     the response has elements",
                    w.label
                ));
            }
        }

        // A window states its consumed figure through exactly one of
        // `used_percent_path` (spent) or `remaining_fraction_path` (what is
        // left, complemented on read) — the same slot said two ways, so
        // naming both leaves the engine to pick, which is not a choice a
        // manifest should make silently. Naming neither, on the http engine,
        // is a window that resolves to nothing every fetch; the log-file
        // engine reads neither path (it takes `used_percent` from the log
        // record itself — see `engine_logfile`), so it is exempt from the "at
        // least one" half while still barred from naming both.
        for w in &self.windows {
            let has_used = w.source.used_percent_path.is_some();
            let has_remaining = w.source.remaining_fraction_path.is_some();
            if has_used && has_remaining {
                return Err(format!(
                    "windows[label = \"{}\"]: name only one of `used_percent_path` or \
                     `remaining_fraction_path` — a window states its figure one way",
                    w.label
                ));
            }
            if !has_used && !has_remaining && self.engine == EngineKind::HttpApi {
                return Err(format!(
                    "windows[label = \"{}\"]: an `http-api` window needs `used_percent_path` or \
                     `remaining_fraction_path` — it has no figure to show otherwise",
                    w.label
                ));
            }
        }

        // A `[status]` that names no path is a section that cannot answer the
        // question it exists for, and it would read as "this provider states a
        // status" everywhere upstream.
        if let Some(status) = &self.status {
            if status.is_empty() {
                return Err(
                    "`[status]` must name at least one of `allowed_path`, `limit_reached_path` \
                     or `reached_type_path`"
                        .to_string(),
                );
            }
            // Only the HTTP engine reads it. A log line records what one
            // session saw, not the standing of the account, so there is
            // nothing there to read — and accepting the section anyway would
            // let a manifest state a guarantee this app does not keep, which
            // is exactly what `required` being dead in one engine once cost.
            if self.engine != EngineKind::HttpApi {
                return Err(
                    "`[status]` is read only by `engine = \"http-api\"` — a log line states what \
                     one session saw, not the standing of the quota"
                        .to_string(),
                );
            }
        }

        // Only the HTTP engine reads balances, for the reason `[status]` is
        // http-only: a log line records the windows one session saw, and this
        // app's log reader has nowhere to take a balance from. Accepting the
        // section under `log-file` would let a manifest declare figures that
        // silently never appear — the failure mode the whole capability
        // mechanism exists to turn into a loud refusal.
        if !self.balances.is_empty() && self.engine != EngineKind::HttpApi {
            return Err(
                "`[[balances]]` is read only by `engine = \"http-api\"` — a log line records the \
                 windows a session saw, not a balance"
                    .to_string(),
            );
        }

        for b in &self.balances {
            if b.label.trim().is_empty() {
                return Err("`[[balances]] label` must not be empty".to_string());
            }
            // Same charset and cap as `[[windows]] id`, and for the same
            // reason: it becomes a segment of a dotted key on disk.
            if !b.id.is_empty() {
                let ok = b.id.len() <= WINDOW_ID_MAX_BYTES
                    && b.id
                        .starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                    && b.id
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
                if !ok {
                    return Err(format!(
                        "balances[label = \"{}\"]: `id = \"{}\"` must be at most \
                         {WINDOW_ID_MAX_BYTES} bytes of lowercase ASCII letters, digits and \
                         hyphens, starting with a letter or digit",
                        b.label, b.id
                    ));
                }
            }
            // An entry that names no source is a caption beside empty space.
            if b.reads_nothing() {
                return Err(format!(
                    "balances[label = \"{}\"] names no figure — declare at least one of `used`, \
                     `cap`, `remaining`, `source.percent_path` or `source.limit_reached_path`",
                    b.label
                ));
            }
            // A path present but blank passes every `is_some()` check above and
            // then resolves to nothing at fetch time, so the figure silently
            // never appears — a manifest that looks accepted and reads air.
            // Same gap the `[logfile]` blank check closes for `root`/`glob`.
            let source_paths = [
                ("source.percent_path", &b.source.percent_path),
                ("source.limit_reached_path", &b.source.limit_reached_path),
                ("source.period_end_path", &b.source.period_end_path),
            ];
            let amount_paths = [
                ("used", &b.used),
                ("cap", &b.cap),
                ("remaining", &b.remaining),
            ]
            .into_iter()
            .filter_map(|(field, a)| a.as_ref().map(|a| (field, a)))
            // Prefixed with the figure it belongs to: three amounts in one
            // entry all have a `path`, and a complaint that names only the
            // key leaves the author checking all three.
            .flat_map(|(field, a)| {
                [
                    (format!("{field}.path"), &a.path),
                    (format!("{field}.amount_path"), &a.amount_path),
                    (format!("{field}.currency_path"), &a.currency_path),
                    (format!("{field}.exponent_path"), &a.exponent_path),
                ]
            });
            let source_paths = source_paths.into_iter().map(|(f, p)| (f.to_string(), p));
            for (field, path) in source_paths.chain(amount_paths) {
                if path.as_deref().is_some_and(|p| p.trim().is_empty()) {
                    return Err(format!(
                        "balances[label = \"{}\"]: `{field}` is present but blank — a path that \
                         reads nothing is not a path",
                        b.label
                    ));
                }
            }
            for (field, amount) in [
                ("used", &b.used),
                ("cap", &b.cap),
                ("remaining", &b.remaining),
            ] {
                let Some(amount) = amount else { continue };
                // A money figure is the triplet or it is nothing: an amount
                // without its currency and scale is a number this app would
                // have to guess the meaning of, and guessing is the one thing
                // it does not do with somebody else's figures. Split from the
                // single-path kinds below so each refusal names the paths its
                // own kind needs — and so the corpus has one row per rule.
                if amount.kind == AmountKind::MoneyMinor {
                    if let Some(missing) = amount.missing_path() {
                        return Err(format!(
                            "balances[label = \"{}\"].{field}: `kind = \"money-minor\"` requires \
                             `amount_path`, `currency_path` and `exponent_path` — `{missing}` is \
                             missing",
                            b.label
                        ));
                    }
                } else if let Some(missing) = amount.missing_path() {
                    return Err(format!(
                        "balances[label = \"{}\"].{field}: `kind = \"{}\"` requires `{missing}`",
                        b.label,
                        match amount.kind {
                            AmountKind::Number => "number",
                            _ => "text",
                        }
                    ));
                }
                // A label that is present and blank — or that the sanitiser
                // reduces to nothing — is accepted by every check here and
                // then silently prints no unit at fetch time. Same defect as a
                // blank path above, in the one key of this table the reader
                // actually renders, and worse in one way: a blanked label
                // changes what pairs with what, so the author sees two rows
                // where they wrote a pair, with nothing said.
                if let Some(label) = &amount.unit_label {
                    if crate::plugin::sanitize_provider_text(label).is_empty() {
                        return Err(format!(
                            "balances[label = \"{}\"].{field}: `unit_label` is present but has \
                             nothing printable in it",
                            b.label
                        ));
                    }
                }
                // A unit label on money would compete with the currency the
                // response states; on text it would annotate a sentence.
                if amount.unit_label.is_some() && amount.kind != AmountKind::Number {
                    return Err(format!(
                        "balances[label = \"{}\"].{field}: `unit_label` belongs to \
                         `kind = \"number\"` only — money carries the currency the response \
                         states, and text is the provider's own wording",
                        b.label
                    ));
                }
            }
        }

        // Two balances with one identity share a row in the reconciler, the
        // same collision `[[windows]] id` is checked for, and compared the same
        // way — on the resolved entry key, so a declared `b1` colliding with
        // the fallback of a later entry is caught too.
        for i in 0..self.balances.len() {
            let key = self.balances[i].entry_key(i);
            if let Some(j) = (0..i).find(|&j| self.balances[j].entry_key(j) == key) {
                return Err(format!(
                    "balances[{i}] and balances[{j}] resolve to the same identity `{key}` — a \
                     balance's `id` must be unique, and must not collide with the `bN` an entry \
                     without one falls back to"
                ));
            }
        }

        for w in &self.windows {
            match w.period.mode {
                PeriodMode::Assumed if w.period.assumed.is_none() => {
                    return Err(format!(
                        "windows[label = \"{}\"]: period.mode = \"assumed\" requires period.assumed",
                        w.label
                    ));
                }
                PeriodMode::FromField if w.period.field.is_none() => {
                    return Err(format!(
                        "windows[label = \"{}\"]: period.mode = \"from_field\" requires period.field",
                        w.label
                    ));
                }
                _ => {}
            }
        }

        // A window that lists more than one candidate container has to be able
        // to tell them apart, and length is the only thing it classifies on
        // (see `SourceConfig::containers`). Catching this here means a typo'd
        // manifest is rejected at load, not silently mis-attributed to a row.
        for w in &self.windows {
            if w.source.containers.len() > 1 && w.period.mode != PeriodMode::FromField {
                return Err(format!(
                    "windows[label = \"{}\"]: source.containers lists {} candidates, so \
                     period.mode must be \"from_field\" to tell them apart by length",
                    w.label,
                    w.source.containers.len()
                ));
            }
        }

        if let Some(http) = &self.http {
            // `{token}`, `{version}` and `{value.<name>}` are header-only, by
            // design: a URL is where a credential is most easily logged by
            // whatever sits in front of the endpoint (see `build_request`).
            // Naming one in a URL is a manifest that cannot work — it would be
            // sent with the braces still in it — so say so at load rather than
            // let it fail as a puzzling 404.
            for req in &http.request {
                if let Some(bad) = url_placeholder(&req.url) {
                    return Err(format!(
                        "`[[http.request]] url` may not contain {bad} — {{token}}, {{version}} \
                         and {{value.<name>}} are substituted into headers only"
                    ));
                }
            }
            if let Some(url) = &self.account.url {
                if let Some(bad) = url_placeholder(url) {
                    return Err(format!(
                        "`[account] url` may not contain {bad} — {{token}}, {{version}} and \
                         {{value.<name>}} are substituted into headers only"
                    ));
                }
            }
            // A surface that carries a credential must say where it may go.
            // An empty `allowed_hosts` means "no restriction configured",
            // which is a fine default for a manifest that sends nothing —
            // and exactly the wrong one for a manifest that sends a token.
            for surface in &self.surface {
                let carries_credentials = surface
                    .auth
                    .iter()
                    .any(|step| step.kind != AuthType::RejectWhen);
                if carries_credentials && surface.allowed_hosts.is_empty() {
                    return Err(format!(
                        "surface \"{}\": a surface with a credential chain must declare \
                         `allowed_hosts` — an empty list would let its token be sent anywhere",
                        surface.id
                    ));
                }
            }
            if http.backoff_start_secs == 0 {
                return Err("`[http] backoff_start_secs` must be greater than 0".to_string());
            }
            if http.unauthorized_retry_secs == 0 {
                return Err("`[http] unauthorized_retry_secs` must be greater than 0".to_string());
            }
            if http.backoff_max_secs < http.backoff_start_secs {
                return Err(format!(
                    "`[http] backoff_max_secs` ({}) must be at least backoff_start_secs ({})",
                    http.backoff_max_secs, http.backoff_start_secs
                ));
            }
            let mut seen_value_names: std::collections::HashSet<&str> =
                std::collections::HashSet::new();
            for v in &http.value {
                if v.name.trim().is_empty() {
                    return Err("`[[http.value]]` entries must have a non-empty `name`".to_string());
                }
                if !v
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    return Err(format!(
                        "`[[http.value]] name = \"{}\"` must contain only ASCII letters, digits and \
                         underscores (it drives the substitution placeholder {{value.{}}})",
                        v.name, v.name
                    ));
                }
                if !seen_value_names.insert(v.name.as_str()) {
                    return Err(format!(
                        "`[[http.value]]` name \"{}\" is declared more than once",
                        v.name
                    ));
                }
                match v.kind {
                    HttpValueType::JsonFile => {
                        if v.path.is_none() || v.json_path.is_none() {
                            return Err(format!(
                                "`[[http.value]] name = \"{}\"`: type = \"json-file\" requires both \
                                 `path` and `json_path`",
                                v.name
                            ));
                        }
                    }
                }
            }
        }

        // Every auth step, checked against what its own type needs. Without
        // this a manifest missing, say, a `credentials-file`'s `path` loads
        // fine and then fails on every single fetch, with an error about a
        // field the user cannot see from the row it lands on.
        for surface in &self.surface {
            for step in &surface.auth {
                let missing: &[(&str, bool)] = match step.kind {
                    AuthType::CredentialsFile => &[
                        ("path", step.path.is_none()),
                        ("token_json_path", step.token_json_path.is_none()),
                    ],
                    AuthType::Keychain => &[
                        ("service", step.service.is_none()),
                        ("token_json_path", step.token_json_path.is_none()),
                    ],
                    AuthType::Env => &[("var", step.var.is_none())],
                    // `token_json_path` is optional here on purpose: the
                    // engine has a default for it (see
                    // `auth::ELECTRON_DEFAULT_TOKEN_JSON_PATH`).
                    AuthType::ElectronSafeStorage => &[
                        ("config_path", step.config_path.is_none()),
                        ("blob_json_path", step.blob_json_path.is_none()),
                    ],
                    AuthType::WinCredential => &[(
                        "targets",
                        step.targets.as_ref().is_none_or(|t| t.is_empty()),
                    )],
                    AuthType::CredentialsMap => &[
                        ("path", step.path.is_none()),
                        ("key_prefix", step.key_prefix.is_none()),
                        ("token_json_path", step.token_json_path.is_none()),
                    ],
                    AuthType::RejectWhen => &[
                        ("path", step.path.is_none()),
                        ("json_path", step.json_path.is_none()),
                        ("message", step.message.is_none()),
                    ],
                    AuthType::OauthRefresh => &[
                        ("path", step.path.is_none()),
                        ("token_json_path", step.token_json_path.is_none()),
                        ("token_url", step.token_url.is_none()),
                        // The pair is required, but not from these two fields
                        // specifically any more — a `client` table below can
                        // supply it instead, so these only count as missing
                        // when there is no such table to fall back on.
                        (
                            "client_id",
                            step.client.is_none() && step.client_id.is_none(),
                        ),
                        (
                            "client_secret",
                            step.client.is_none() && step.client_secret.is_none(),
                        ),
                    ],
                };
                if let Some((field, _)) = missing.iter().find(|(_, absent)| *absent) {
                    return Err(format!(
                        "surface \"{}\": a `{}` auth step requires `{field}`",
                        surface.id,
                        auth_type_name(step.kind)
                    ));
                }
                // `client` is `oauth-refresh`'s own sub-table; a manifest
                // that wrote it under, say, a `keychain` step is not asking
                // for anything this app knows how to do with it, and the
                // fields inside it would otherwise be validated (or silently
                // ignored) against a step that never reads them.
                if step.client.is_some() && step.kind != AuthType::OauthRefresh {
                    return Err(format!(
                        "surface \"{}\": a `client` table only makes sense on an `oauth-refresh` \
                         auth step, not `{}`",
                        surface.id,
                        auth_type_name(step.kind)
                    ));
                }
                // A step naming both is not "belt and braces" — it is a
                // manifest that cannot say which one it means, since
                // `auth::resolve_client` would otherwise try the literal pair
                // as a fallback rung between the env override and discovery,
                // which is exactly the ambiguity a manifest author reading
                // this file back would trip on. Refused outright rather than
                // picking an order silently.
                if step.client.is_some()
                    && (step.client_id.is_some() || step.client_secret.is_some())
                {
                    return Err(format!(
                        "surface \"{}\": a `{}` auth step may not set both `client_id`/`client_secret` \
                         and a `client` table — pick one",
                        surface.id,
                        auth_type_name(step.kind)
                    ));
                }
                // Present-and-blank passes the check above (`is_none()` is
                // false for `Some("")`) and would then fail on every single
                // fetch, with an error naming a field the user cannot see
                // from the row it lands on — the same gap `[logfile]`'s blank
                // check above closes for `root`/`glob`/`container_key`. Only
                // `credentials-map` needs it here: its other siblings either
                // have no field a manifest could plausibly leave blank
                // (`env`'s `var`, `keychain`'s `service`) or are already
                // covered elsewhere (`win-credential`'s `targets` is checked
                // non-empty, not non-blank, by the table above). `oauth-refresh`
                // needs it for the same reason — a blank `client_secret` loads
                // and then fails every exchange. One `return Err` shared by both;
                // only the field list differs per kind.
                if matches!(step.kind, AuthType::CredentialsMap | AuthType::OauthRefresh) {
                    let is_blank =
                        |f: &Option<String>| f.as_deref().unwrap_or_default().trim().is_empty();
                    // Present-and-blank only, unlike `is_blank` above: `client_id`
                    // /`client_secret` are legitimately absent the moment a
                    // `client` table is doing the discovery instead, and an
                    // absent field must read as "not used", never as "blank".
                    let is_present_but_blank =
                        |f: &Option<String>| f.as_deref().is_some_and(|s| s.trim().is_empty());
                    let mut blank: Vec<(&str, bool)> = vec![
                        ("path", is_blank(&step.path)),
                        ("token_json_path", is_blank(&step.token_json_path)),
                    ];
                    match step.kind {
                        AuthType::CredentialsMap => {
                            blank.push(("key_prefix", is_blank(&step.key_prefix)))
                        }
                        AuthType::OauthRefresh => {
                            blank.push(("token_url", is_blank(&step.token_url)));
                            blank.push(("client_id", is_present_but_blank(&step.client_id)));
                            blank
                                .push(("client_secret", is_present_but_blank(&step.client_secret)));
                            // The `client` table's own fields, walked here
                            // rather than in a table of their own: the same
                            // "present and still says nothing" rule, so a
                            // blank `client.id_pattern` reaches the exact
                            // sentence a blank `client_secret` already does,
                            // instead of a second `return Err` this file's
                            // own corpus counter would have to grow a row
                            // for. `id_pattern`/`secret_pattern` use `is_blank`
                            // (missing counts too — both are required), while
                            // `id_env`/`secret_env` use `is_present_but_blank`
                            // — one without the other is a legitimate "no env
                            // override", not a mistake.
                            if let Some(client) = &step.client {
                                blank.push(("client.id_env", is_present_but_blank(&client.id_env)));
                                blank.push((
                                    "client.secret_env",
                                    is_present_but_blank(&client.secret_env),
                                ));
                                blank.push(("client.id_pattern", is_blank(&client.id_pattern)));
                                blank.push((
                                    "client.secret_pattern",
                                    is_blank(&client.secret_pattern),
                                ));
                            }
                        }
                        _ => unreachable!("guarded by the `matches!` above"),
                    }
                    if let Some((field, _)) = blank.iter().find(|(_, empty)| *empty) {
                        return Err(format!(
                            "surface \"{}\": a `{}` auth step's `{field}` must not be blank",
                            surface.id,
                            auth_type_name(step.kind)
                        ));
                    }
                }
                // The rest of `client`: patterns compilable, no blank entry
                // in `files`/`bins`, and something for `auth::discover_client`
                // to actually search — checked only once the block above has
                // already ruled out `None`/blank on the fields it reads here.
                if let Some(client) = &step.client {
                    for (field, pattern) in [
                        ("client.id_pattern", client.id_pattern.as_deref()),
                        ("client.secret_pattern", client.secret_pattern.as_deref()),
                    ] {
                        // `unwrap_or_default()`'s `""` cannot reach here — the
                        // blank check above already refused it — so this is
                        // only ever compiling text a manifest actually wrote.
                        if let Some(pattern) = pattern {
                            // The pattern's own source text, not what it can
                            // match: a real `id_pattern`/`secret_pattern` is
                            // a few dozen characters, but a *compact* match
                            // bound says nothing about how long the text
                            // that produces it is — thousands of
                            // fixed-length alternatives, say, all matching
                            // well within `CLIENT_PATTERN_MAX_MATCH_BYTES`
                            // while the pattern itself runs to kilobytes.
                            // This is also the text `registry::analyze_trust`
                            // renders in the install-time trust dialog, so a
                            // pattern this long is refused before it can
                            // reach that dialog, not merely truncated there.
                            if pattern.len() > super::CLIENT_PATTERN_MAX_TEXT_BYTES {
                                return Err(format!(
                                    "surface \"{}\": a `{}` auth step's `{field}` is {} bytes of \
                                     pattern text — the limit is {}",
                                    surface.id,
                                    auth_type_name(step.kind),
                                    pattern.len(),
                                    super::CLIENT_PATTERN_MAX_TEXT_BYTES
                                ));
                            }
                            // Compiled with the engine the scan actually
                            // runs (`regex::bytes::Regex`, over raw bytes),
                            // not the text engine: the two share a grammar
                            // for everything a pattern like this needs, but
                            // accepting one and running the other would mean
                            // a pattern that fails at scan time — after the
                            // manifest already loaded — for a reason
                            // validation never saw.
                            if let Err(e) = regex::bytes::Regex::new(pattern) {
                                return Err(format!(
                                    "surface \"{}\": a `{}` auth step's `{field}` is not a valid \
                                     regular expression: {e}",
                                    surface.id,
                                    auth_type_name(step.kind)
                                ));
                            }
                            // Bounded, not merely valid: a client id or
                            // secret is never remotely `CLIENT_PATTERN_MAX_MATCH_BYTES`
                            // long (the shipped Antigravity ones measure 72
                            // and 35), so a pattern whose match has no
                            // ceiling — or one set too high — is refused
                            // here rather than left to `scan_candidate`'s own
                            // defensive `debug_assert` at scan time, which
                            // exists for a manifest that got past this check
                            // some other way, not as the primary guard.
                            let max_len = regex_max_match_len(pattern);
                            if !matches!(max_len, Some(len) if len <= super::CLIENT_PATTERN_MAX_MATCH_BYTES)
                            {
                                return Err(format!(
                                    "surface \"{}\": a `{}` auth step's `{field}` may match at most \
                                     {} bytes ({}) — an unbounded pattern could read an unbounded \
                                     slice of the file it scans and call the slice the client",
                                    surface.id,
                                    auth_type_name(step.kind),
                                    super::CLIENT_PATTERN_MAX_MATCH_BYTES,
                                    max_len.map(|n| n.to_string()).unwrap_or_else(|| "unbounded".to_string())
                                ));
                            }
                            // Bounded above is not bounded below: `a*` and
                            // `(?:foo)?` both pass the check above (their
                            // maximum is finite) while still being able to
                            // match zero bytes, which `discover_client`
                            // would then treat as a found — but empty —
                            // client id or secret. Every real client id or
                            // secret is at least one byte; a pattern that
                            // cannot guarantee that much is refused here
                            // rather than left for `discover_client`'s own
                            // `!m.is_empty()` check at scan time, which
                            // exists only as the last line of defense for a
                            // pattern that got past this some other way.
                            if !matches!(regex_min_match_len(pattern), Some(len) if len >= 1) {
                                return Err(format!(
                                    "surface \"{}\": a `{}` auth step's `{field}` can match the \
                                     empty string — every client id or secret is at least one byte",
                                    surface.id,
                                    auth_type_name(step.kind)
                                ));
                            }
                        }
                    }
                    let blank_entry = client
                        .files
                        .iter()
                        .map(|f| ("files", f))
                        .chain(client.bins.iter().map(|b| ("bins", b)))
                        .find(|(_, entry)| entry.trim().is_empty());
                    if let Some((which, _)) = blank_entry {
                        return Err(format!(
                            "surface \"{}\": a `{}` auth step's `client.{which}` names a blank \
                             entry",
                            surface.id,
                            auth_type_name(step.kind)
                        ));
                    }
                    // `bins` resolves on `PATH` (`auth::bin_candidates`) by
                    // joining a directory onto whatever is written here — a
                    // `/`, a `\`, a `..` component or a drive prefix would
                    // turn that join into an absolute or escaping path, i.e.
                    // a manifest naming any file it likes rather than a
                    // program name to look up. `files` has no such rule: it
                    // is already a path, by design.
                    if let Some(bad) = client.bins.iter().find(|b| !is_bare_program_name(b)) {
                        return Err(format!(
                            "surface \"{}\": a `{}` auth step's `client.bins` entry \"{bad}\" must \
                             be a bare program name, not a path",
                            surface.id,
                            auth_type_name(step.kind)
                        ));
                    }
                    // `files` is a path, not a program name — but a relative
                    // one resolves against whatever directory this process
                    // happens to be running from, which is never the intent
                    // of naming an installed client's binary. Checked
                    // against what `super::expand_home` returns, not the
                    // raw spec: a spec starting with `~` is what every
                    // shipped entry looks like, and is exactly as absolute
                    // as the path it expands to (`expand_home` falls back
                    // to the literal spec — still relative — only when the
                    // home directory itself can't be resolved). It is the
                    // one function, not a `~`-specific step plus a separate
                    // `{config_dir}` one — `discover_client` expands `files`
                    // through the very same call, so what this refuses is
                    // exactly what a fetch would otherwise try to scan.
                    // `is_absolute_on_any_platform`, not `Path::is_absolute`,
                    // because a manifest is data that ships to every
                    // platform this app runs on — the shipped Antigravity
                    // manifest's own `/Applications/…` entry is a perfectly
                    // well-formed absolute path that a Windows build of
                    // `Path::is_absolute()` refuses (it wants a drive letter
                    // or a UNC prefix), and a macOS-only candidate on a
                    // Windows machine should simply not exist at discovery
                    // time, not fail to load the manifest at all.
                    if let Some(bad) = client
                        .files
                        .iter()
                        .find(|f| !is_absolute_on_any_platform(&super::expand_home(f)))
                    {
                        return Err(format!(
                            "surface \"{}\": a `{}` auth step's `client.files` entry \"{bad}\" must \
                             be an absolute path",
                            surface.id,
                            auth_type_name(step.kind)
                        ));
                    }
                    // `id_env`/`secret_env` name a variable `std::env::var`
                    // reads verbatim — a name outside the POSIX/Windows
                    // environment-variable charset is either a typo nothing
                    // could ever set, or a manifest testing what this app
                    // does with one, and refusing it here is a clearer
                    // answer than "never set" would be at every fetch.
                    for (field, name) in [
                        ("client.id_env", client.id_env.as_deref()),
                        ("client.secret_env", client.secret_env.as_deref()),
                    ] {
                        if let Some(name) = name {
                            if !is_valid_env_var_name(name) {
                                return Err(format!(
                                    "surface \"{}\": a `{}` auth step's `{field}` = \"{name}\" is not \
                                     a valid environment variable name",
                                    surface.id,
                                    auth_type_name(step.kind)
                                ));
                            }
                        }
                    }
                    // `id_env`/`secret_env` name one pair, not two independent
                    // switches — half a pair (`id_env` set, `secret_env`
                    // absent, or the reverse) can never resolve anything by
                    // itself, since `auth::client_env_pair` only returns an
                    // override when both are set. Left unrefused, that half
                    // pair would fall through to discovery every fetch while
                    // `auth::client_env_pair` queues a "half set" diagnostic
                    // nobody asked to read — a manifest bug is a clearer
                    // answer at load time than a diagnostic at every fetch.
                    if client.id_env.is_some() != client.secret_env.is_some() {
                        return Err(format!(
                            "surface \"{}\": a `{}` auth step's `client.id_env`/`client.secret_env` \
                             must be set together or not at all",
                            surface.id,
                            auth_type_name(step.kind)
                        ));
                    }
                    // Both `id_env`/`secret_env` set (and, by the blank check
                    // above, non-blank) is a complete override on its own —
                    // `files`/`bins` naming nothing to search is then not a
                    // mistake, since the environment is always tried first.
                    // Without that pair, an empty `files` and an empty `bins`
                    // together mean this step can never resolve anything.
                    let env_pair_named = client.id_env.is_some() && client.secret_env.is_some();
                    if client.files.is_empty() && client.bins.is_empty() && !env_pair_named {
                        return Err(format!(
                            "surface \"{}\": a `{}` auth step's `client` table names neither \
                             `files` nor `bins` to search, and no `id_env`/`secret_env` pair to \
                             skip searching for",
                            surface.id,
                            auth_type_name(step.kind)
                        ));
                    }
                }
            }
            // `allowed_hosts` is an exact-match list — no wildcards, by design
            // (see `crate::plugin::auth::host_allowed`). A manifest writing
            // `"*"` is asking for something this app deliberately doesn't do,
            // and would otherwise silently match nothing at all.
            if let Some(bad) = surface.allowed_hosts.iter().find(|h| h.contains('*')) {
                return Err(format!(
                    "surface \"{}\": `allowed_hosts` entry \"{bad}\" — hosts are matched exactly, \
                     wildcards are not supported",
                    surface.id
                ));
            }
        }

        // `[account]`, checked the same way and for the same reason.
        let account_missing: &[(&str, bool)] = match self.account.kind {
            AccountType::None => &[],
            AccountType::JwtFile => &[
                ("path", self.account.path.is_none()),
                ("token_path", self.account.token_path.is_none()),
                ("claim", self.account.claim.is_none()),
            ],
            AccountType::Http => &[
                ("url", self.account.url.is_none()),
                ("json_path", self.account.json_path.is_none()),
            ],
            AccountType::ResponseField => &[("json_path", self.account.json_path.is_none())],
        };
        if let Some((field, _)) = account_missing.iter().find(|(_, absent)| *absent) {
            return Err(format!("`[account]` of this type requires `{field}`"));
        }

        // A `[ping]` runs a program. Naming it by path is not something a
        // manifest needs — `find_bin` looks the name up on PATH and in the
        // usual install locations — and "the plugin runs /some/absolute/thing"
        // is a worse sentence to have to put in a trust dialog than it is to
        // simply refuse.
        if let Some(ping) = &self.ping {
            if ping.bin.trim().is_empty() {
                return Err("`[ping] bin` must not be empty".to_string());
            }
            if ping.bin.contains('/') || ping.bin.contains('\\') {
                return Err(format!(
                    "`[ping] bin = \"{}\"` must be a bare program name, not a path",
                    ping.bin
                ));
            }
        }

        let mut seen_option_keys: std::collections::HashSet<&str> =
            std::collections::HashSet::new();
        for opt in &self.option {
            if opt.key.trim().is_empty() {
                return Err("`[[option]]` entries must have a non-empty `key`".to_string());
            }
            if !opt
                .key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return Err(format!(
                    "`[[option]] key = \"{}\"` must contain only ASCII letters, digits and underscores \
                     (it drives the substitution placeholder {{option.{}}})",
                    opt.key, opt.key
                ));
            }
            if opt.label.trim().is_empty() {
                return Err(format!(
                    "`[[option]] key = \"{}\"` must have a non-empty `label`",
                    opt.key
                ));
            }
            if !seen_option_keys.insert(opt.key.as_str()) {
                return Err(format!(
                    "`[[option]]` key \"{}\" is declared more than once",
                    opt.key
                ));
            }
        }

        // A placeholder has to be spelled where something will read it, and it
        // has to name something declared. Both engines substitute what they
        // know and deliberately leave anything else *visible* rather than
        // blanking it (`engine_http::substitute`,
        // `crate::plugin::substitute_options`) — right for a value missing at
        // runtime, and wrong for a name that was never declared or a field
        // nothing substitutes at all. A header written
        // `Bearer {value.acount_id}` is not a request that fails to
        // authenticate; it is a request sent with the braces in it, and the
        // row says the session expired while the typo sits in another file.
        //
        // Which fields substitute what is not symmetric, so the table says so:
        // `{value.<name>}` is read out of local files for headers and nowhere
        // else, while `{option.<key>}` reaches a URL and the log engine's
        // paths as well. A `{value.…}` in a log-file root looks like it should
        // work and never will — the log engine has no values to substitute.
        let declared_values: std::collections::HashSet<&str> = self
            .http
            .iter()
            .flat_map(|http| http.value.iter().map(|v| v.name.as_str()))
            .collect();
        let mut templates: Vec<(String, &str, Substituted)> = Vec::new();
        if let Some(http) = &self.http {
            for req in &http.request {
                templates.push((
                    "`[[http.request]] url`".to_string(),
                    req.url.as_str(),
                    Substituted::OptionsOnly,
                ));
                for (header, value) in &req.headers {
                    templates.push((
                        format!("`[[http.request]]` header `{header}`"),
                        value.as_str(),
                        Substituted::ValuesAndOptions,
                    ));
                }
                // `body` gets the same substitution set as a header value —
                // it is one, in every way that matters here (it can carry
                // `{token}`, and it never reaches the URL).
                if let Some(body) = &req.body {
                    templates.push((
                        "`[[http.request]] body`".to_string(),
                        body.as_str(),
                        Substituted::ValuesAndOptions,
                    ));
                }
            }
            // Outside the request loop, where it belongs: a `[[http.value]]`
            // is declared once for the section, not once per request. Nested,
            // it was checked as many times as there were requests — which is
            // once for the one request an `http-api` manifest may declare, and
            // *never* for a manifest that has an `[http]` section without one.
            for value in &http.value {
                templates.push((
                    format!("`[[http.value]] name = \"{}\"` path", value.name),
                    value.path.as_deref().unwrap_or(""),
                    Substituted::Nothing,
                ));
            }
        }
        if let Some(url) = &self.account.url {
            templates.push((
                "`[account] url`".to_string(),
                url.as_str(),
                Substituted::OptionsOnly,
            ));
        }
        if let Some(path) = &self.account.path {
            templates.push((
                "`[account] path`".to_string(),
                path.as_str(),
                Substituted::Nothing,
            ));
        }
        if let Some(lf) = &self.logfile {
            templates.push((
                "`[logfile] root`".to_string(),
                lf.root.as_str(),
                Substituted::OptionsOnly,
            ));
            templates.push((
                "`[logfile] glob`".to_string(),
                lf.glob.as_str(),
                Substituted::OptionsOnly,
            ));
            if let Some(join) = &lf.root_env_join {
                templates.push((
                    "`[logfile] root_env_join`".to_string(),
                    join.as_str(),
                    Substituted::OptionsOnly,
                ));
            }
        }
        for surface in &self.surface {
            for step in &surface.auth {
                // `token_url`/`client_id`/`client_secret` get no substitution of
                // their own (this step's network call is not the engine's — see
                // `auth::oauth_refresh_step`), so they belong beside
                // `path`/`config_path` here: a stray `{token}` in `client_secret`
                // would otherwise be sent as nine literal characters, silently.
                for (field, text) in [
                    ("path", &step.path),
                    ("config_path", &step.config_path),
                    ("token_url", &step.token_url),
                    ("client_id", &step.client_id),
                    ("client_secret", &step.client_secret),
                ] {
                    if let Some(text) = text {
                        templates.push((
                            format!(
                                "surface \"{}\": a `{}` auth step's `{field}`",
                                surface.id,
                                auth_type_name(step.kind)
                            ),
                            text.as_str(),
                            Substituted::Nothing,
                        ));
                    }
                }
                // `client`'s own fields, same treatment: nothing substitutes
                // a pattern, an env var name or a file/bin candidate either,
                // so a stray `{token}` in one of them would be read literally
                // by `auth::discover_client` rather than rejected here.
                if let Some(client) = &step.client {
                    for (field, text) in [
                        ("client.id_env", &client.id_env),
                        ("client.secret_env", &client.secret_env),
                        ("client.id_pattern", &client.id_pattern),
                        ("client.secret_pattern", &client.secret_pattern),
                    ] {
                        if let Some(text) = text {
                            templates.push((
                                format!(
                                    "surface \"{}\": a `{}` auth step's `{field}`",
                                    surface.id,
                                    auth_type_name(step.kind)
                                ),
                                text.as_str(),
                                Substituted::Nothing,
                            ));
                        }
                    }
                    for (which, entries) in [("files", &client.files), ("bins", &client.bins)] {
                        for (i, entry) in entries.iter().enumerate() {
                            templates.push((
                                format!(
                                    "surface \"{}\": a `{}` auth step's `client.{which}[{i}]`",
                                    surface.id,
                                    auth_type_name(step.kind)
                                ),
                                entry.as_str(),
                                Substituted::Nothing,
                            ));
                        }
                    }
                }
            }
        }
        for (where_it_is, template, substituted) in templates {
            for placeholder in placeholders(template) {
                let kind = match () {
                    _ if placeholder.starts_with("value.") => Substituted::ValuesAndOptions,
                    _ if placeholder.starts_with("option.") => Substituted::OptionsOnly,
                    // `{token}`, `{version}`, `{config_dir}` and anything a
                    // future engine adds are not this rule's business.
                    _ => continue,
                };
                if !substituted.covers(kind) {
                    return Err(format!(
                        "{where_it_is} names {{{placeholder}}}, which nothing substitutes there — \
                         it would be used as literal text"
                    ));
                }
                if let Some(name) = placeholder.strip_prefix("value.") {
                    if !declared_values.contains(name) {
                        return Err(format!(
                            "{where_it_is} names {{value.{name}}}, which no `[[http.value]]` \
                             declares — the request would be sent with the placeholder still in it"
                        ));
                    }
                } else if let Some(key) = placeholder.strip_prefix("option.") {
                    if !seen_option_keys.contains(key) {
                        return Err(format!(
                            "{where_it_is} names {{option.{key}}}, which no `[[option]]` \
                             declares — the placeholder would be used verbatim"
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

/// What a given field's text gets substituted into it before use. Not the
/// same everywhere, and the difference is invisible from the manifest: a
/// `{value.<name>}` reads a local file for a request header and is meaningless
/// in a log-file path, because only the HTTP engine resolves values at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Substituted {
    /// Request headers: `{token}`, `{version}`, `{value.<name>}`, `{option.<key>}`.
    ValuesAndOptions,
    /// URLs and the log engine's paths: `{option.<key>}` only.
    OptionsOnly,
    /// Read verbatim (after `~`/`{config_dir}` expansion, which is a different
    /// mechanism and not a manifest placeholder).
    Nothing,
}

impl Substituted {
    fn covers(self, needed: Substituted) -> bool {
        match self {
            Substituted::ValuesAndOptions => needed != Substituted::Nothing,
            Substituted::OptionsOnly => needed == Substituted::OptionsOnly,
            Substituted::Nothing => false,
        }
    }
}

/// Every `{…}` placeholder in a template, in the order they appear. Mirrors
/// the one-pass scan the engine substitutes with (`engine_http::substitute`)
/// exactly, including its rule that an unclosed brace is literal text rather
/// than the start of anything: a check that disagreed with the substitution
/// about what a placeholder even is would reject manifests that work, or pass
/// ones that don't.
fn placeholders(template: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let after = &rest[open..];
        let Some(close) = after.find('}') else {
            break;
        };
        found.push(&after[1..close]);
        rest = &after[close + 1..];
    }
    found
}

/// Whether `body` contains a raw placeholder marker more times than
/// [`placeholders`] actually recognised out of it — the signature of one
/// having been swallowed.
///
/// [`placeholders`] (and `engine_http::substitute`, which it mirrors) pairs a
/// `{` with the *first* `}` that follows it, whatever text sits in between —
/// exactly right for a header or a URL, neither of which is ever written
/// starting with an unrelated `{`. A request body can be: every JSON object
/// opens with `{`, and that leading, purely structural brace pairs with a
/// real placeholder's own closing one before either scanner ever reads the
/// placeholder's name — `{"auth":"{token}"}` finds its first `}` closing
/// `{token}`, not the (later, real) end of the object, so `{token}` is
/// mailed on the wire exactly as written. The garbled "name" this produces
/// starts with neither `value.` nor `option.`, so the undeclared-placeholder
/// loop in `validate` never sees it either — this is the one shape that loop
/// cannot catch, which is why it gets a check of its own rather than folding
/// into it.
///
/// Checked one marker at a time, and by raw-vs-recognised count rather than
/// by position, because the two counts can disagree in only one direction —
/// swallowed placeholders are always undercounted, never overcounted — and
/// because a body can swallow one marker while substituting another
/// correctly a few characters later (the case that found this: `{token}`
/// resolved fine while `{option.plugin}` earlier in the same string did
/// not).
fn body_swallows_a_placeholder(body: &str) -> Option<&'static str> {
    let names = placeholders(body);
    let raw = |marker: &str| body.matches(marker).count();
    let recognized_exact = |name: &str| names.iter().filter(|n| **n == name).count();
    let recognized_prefix = |prefix: &str| names.iter().filter(|n| n.starts_with(prefix)).count();
    if raw("{token}") > recognized_exact("token") {
        return Some("{token}");
    }
    if raw("{version}") > recognized_exact("version") {
        return Some("{version}");
    }
    if raw("{value.") > recognized_prefix("value.") {
        return Some("{value.<name>}");
    }
    if raw("{option.") > recognized_prefix("option.") {
        return Some("{option.<key>}");
    }
    None
}

/// Which engine reads a provider's usage data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EngineKind {
    /// Tail local log files (Codex-style rollout JSONL).
    LogFile,
    /// Call an authenticated HTTP endpoint (Claude-style oauth/usage).
    HttpApi,
}

// ── [tag] ─────────────────────────────────────────────────────────────────

/// `[tag]` — the small chip shown next to the provider name ("PROLITE",
/// "CLI", "Desktop").
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct TagConfig {
    /// Where the tag text comes from.
    #[serde(default)]
    pub from: TagFrom,
    /// Literal tag text, used when `from = "static"`.
    pub value: Option<String>,
    /// JSON path to the tag text, used when `from = "field"`.
    pub path: Option<String>,
    /// Text transform applied to the resolved tag.
    #[serde(default)]
    pub transform: TagTransform,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TagFrom {
    /// Use `value` verbatim.
    Static,
    /// Read the tag from `path` inside the provider's reading.
    Field,
    /// No tag.
    #[default]
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TagTransform {
    #[default]
    None,
    Uppercase,
}

// ── [account] ─────────────────────────────────────────────────────────────

/// `[account]` — where the account email shown next to the tag comes from.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct AccountConfig {
    /// Which lookup strategy to use.
    #[serde(rename = "type", default)]
    pub kind: AccountType,
    /// For `type = "jwt-file"`: path to the file holding the token.
    pub path: Option<String>,
    /// For `type = "jwt-file"`: JSON path to the JWT string inside the file.
    pub token_path: Option<String>,
    /// For `type = "jwt-file"`: claim name to read out of the decoded JWT.
    pub claim: Option<String>,
    /// For `type = "http"`: URL to fetch the account profile from.
    pub url: Option<String>,
    /// For `type = "http"`: JSON path to the email in the response body.
    /// Headers and auth are shared with the provider's `[http]`/surface
    /// configuration — there is no separate header map here.
    pub json_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccountType {
    #[default]
    None,
    JwtFile,
    Http,
    /// The email is already in the usage response the engine just fetched —
    /// read it from `json_path` instead of issuing a second request. Codex's
    /// `/wham/usage` returns `email` alongside the windows, so a profile
    /// lookup would double the request count for data already in hand.
    ResponseField,
}

// ── [[windows]] ───────────────────────────────────────────────────────────

/// One `[[windows]]` entry — a quota window this provider reports.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct WindowConfig {
    /// Stable identity of this declared window, used to build
    /// [`crate::model::Window::key`]. Empty (the default) means the entry has
    /// none and its position stands in — see [`WindowConfig::entry_key`].
    ///
    /// Deliberately **not** defaulted to `label`. A label is a human caption:
    /// on an enumerating entry it is a template (`for_each`), so identity
    /// would come off the network, and on an ordinary entry rewording it would
    /// rotate the registry key of every window the entry produces — and every
    /// shipped-manifest bump reaches an existing install. A caption is the one
    /// thing about a window that is expected to change freely.
    ///
    /// Needs `requires_reader = ["window-identity"]`.
    #[serde(default)]
    pub id: String,
    /// Short row label shown in the popup ("5H" / "WK").
    ///
    /// A literal, with one exception: on an enumerating entry
    /// ([`for_each`](Self::for_each)) it may carry `{path}` placeholders,
    /// resolved against each element and sanitised on the way in
    /// (`plugin::sanitize_provider_text`), because a row per model has to be
    /// able to say *which* model — a fixed caption over a figure scoped to one
    /// of them would be worse than no row. An element whose placeholder does
    /// not resolve draws no row rather than a row this app cannot name. Off an
    /// enumerating entry a `{` in a label is refused, so the exception cannot
    /// leak into an ordinary caption.
    pub label: String,
    /// UI slot this window fills. At most one window may be `primary`.
    pub role: Role,
    /// Whether this provider always reports this window, so its absence from
    /// an otherwise readable response is the provider's error rather than a
    /// fact about the account.
    ///
    /// The two are not the same thing and must not be drawn the same way. A
    /// Codex plan with no 5-hour allowance reports no 5-hour window, and the
    /// honest thing to show is no 5-hour row; a Claude response with no
    /// `five_hour.utilization` in it means the endpoint changed shape under
    /// us, and the honest thing to show is that we could not read it. Only
    /// the manifest knows which of its windows are which, so only the manifest
    /// can say — the reader used to guess, by treating a response in which
    /// *nothing* resolved as an error, which called a 5-hour-less plan broken
    /// and a half-changed response fine.
    ///
    /// Needs `requires_reader = ["window-presence"]` — an older build has no
    /// notion of a window being absent at all, so it would read this as a
    /// field that does not exist. See [`crate::plugin::capability`].
    #[serde(default)]
    pub required: bool,
    /// `[windows.period]` — how long the window is.
    pub period: PeriodConfig,
    /// `[windows.source]` — where the window's numbers come from.
    pub source: SourceConfig,
    /// Dotted path to an **array** in the response, each element of which is
    /// its own window: this entry then draws a row per element instead of one
    /// row, and every path in `[windows.source]` (and `period.field`) is read
    /// *relative to the element*.
    ///
    /// The case it exists for is a provider that scopes a limit to a model and
    /// does not tell you in advance how many such limits there are. Claude
    /// reports its session and weekly windows in fixed fields *and* repeats
    /// them inside a `limits[]` array, which also carries a third kind — a
    /// weekly allowance scoped to one model (`kind = "weekly_scoped"`, the
    /// model named inside the element). Reading that with a fixed selector
    /// would take whichever such limit happens to be first and silently drop
    /// the rest, and would have to caption it with a literal that cannot name
    /// the model it is about.
    ///
    /// Needs `requires_reader = ["for-each-windows"]`. An older build has no
    /// notion of expansion: it would read the entry as a single window and
    /// resolve its paths against the array itself — one row where there should
    /// be several, filled with nothing.
    #[serde(default)]
    pub for_each: Option<String>,
    /// `field=value` — keep only the elements whose own `field` says exactly
    /// that. Written as a separate key rather than as a selector inside
    /// [`for_each`](Self::for_each), because the selector grammar in a path
    /// (`limits[kind=weekly_scoped]`) picks **one** element and this keeps
    /// **all** the matching ones: the same spelling meaning two different
    /// things depending on which key it sits in is exactly the kind of trap
    /// this file exists to refuse.
    ///
    /// Optional. Without it every element of the array is a row — which is
    /// wrong for Claude (its `limits[]` also carries the two windows the fixed
    /// entries already draw) and right for a provider whose array is nothing
    /// but per-model quotas.
    #[serde(default)]
    pub for_each_where: Option<String>,
    /// Where inside an element its **identity** comes from — the `<element>`
    /// half of [`crate::model::Window::key`], and so the segment under which
    /// the row is filed in the user's config.
    ///
    /// Required on an enumerating entry, and deliberately not defaulted to the
    /// element's position: an array of per-model quotas has no order a provider
    /// promises to keep, so position would re-file every row the day the
    /// provider sorts them differently. It is also not the label: a caption may
    /// be reworded, an identity may not (see [`WindowConfig::id`], which says
    /// the same thing about the entry half).
    #[serde(default)]
    pub element_id_path: Option<String>,
}

/// What is wrong with the two halves of a `for_each_where`, if anything. Each
/// of these matches nothing at read time, forever, and says nothing about why —
/// which is the whole reason they are answered here instead.
fn filter_complaint(field: &str, value: &str) -> Option<&'static str> {
    if field.is_empty() {
        return Some("names no field before its `=`");
    }
    if value.is_empty() {
        return Some("names no value after its `=`");
    }
    if field.contains('.') {
        // The filter reads one key of the element (`Value::get`), the way a
        // path selector does — while `element_id_path` and the label's
        // `{path}` are full dotted paths. A filter written as a path looks
        // right beside them and matches nothing.
        return Some(
            "names a field of the element, not a path into it — a `.` here is read as part of \
             the key and matches nothing",
        );
    }
    None
}

/// What is wrong with an enumerating entry's label template, if anything.
///
/// Only the shapes [`crate::plugin::engine_http`] cannot act on: an unclosed
/// `{`, an empty `{}`, and a `{` inside a placeholder (which would make the
/// first `}` close a path nobody wrote). A placeholder naming a field the
/// response does not carry is *not* checked here — that is the provider's
/// business and is answered at read time by drawing no row, the same as any
/// other path that does not resolve.
fn template_complaint(label: &str) -> Option<&'static str> {
    let mut rest = label;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            return Some("a `{placeholder}` is never closed — the row would silently not draw");
        };
        let inner = &after[..close];
        if inner.trim().is_empty() {
            return Some("`{}` names no path — a placeholder is `{some.field}`");
        }
        if inner.contains('{') {
            return Some("a `{` inside a `{placeholder}` — the first `}` would close it early");
        }
        rest = &after[close + 1..];
    }
    match rest.contains('}') {
        true => Some("a `}` with no `{` before it"),
        false => None,
    }
}

/// Cap on `[[windows]] id`.
///
/// It bounds a string that becomes part of a window's identity, and would
/// become a segment of a key inside the user's `config.json` the day that
/// identity is used to persist state there. Capped now rather than then,
/// because a manifest that already shipped with a 4 KB id would have to keep
/// working.
pub const WINDOW_ID_MAX_BYTES: usize = 64;

impl WindowConfig {
    /// The `<entry>` half of this window's key: the declared `id`, or the
    /// entry's position when it has none.
    ///
    /// Position is a poor identity and a deliberate one. It moves when the
    /// manifest is edited — inserting a window renumbers every later entry —
    /// but a manifest edit is exactly the moment a window may legitimately
    /// become a different window, and nothing else on offer is better: the
    /// label is a caption, and the response slot moves on its own (Codex sends
    /// its weekly window in `primary_window` whenever the 5-hour one has
    /// nothing to report). A third-party manifest that wants its rows to keep
    /// their registry entries across edits declares `id`; both shipped
    /// manifests do.
    pub fn entry_key(&self, index: usize) -> String {
        match self.id.is_empty() {
            true => format!("w{index}"),
            false => self.id.clone(),
        }
    }
}

/// Which UI slot a window fills — mirrors [`crate::model::Role`], but kept
/// as its own type here since the manifest is a raw-schema layer; the engine
/// that turns a [`WindowConfig`] into a [`crate::model::Window`] maps between
/// the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Primary,
    Secondary,
    /// A quota that is not this provider's subscription: a per-model
    /// allowance, a credit pool. Shown as its own row and kept out of the
    /// menu bar and the 5H/WK slots entirely — see [`crate::model::Role`].
    Extra,
}

/// `[windows.period]` — how the window's nominal length is determined.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PeriodConfig {
    /// How to determine the period length.
    pub mode: PeriodMode,
    /// JSON path to the period length; required when `mode = "from_field"`.
    /// Read in `unit`, stored in minutes.
    pub field: Option<String>,
    /// Fixed period length in minutes; required when `mode = "assumed"`.
    pub assumed: Option<u64>,
    /// Unit the value at `field` is expressed in. Defaults to minutes, which
    /// is what Codex's rollout logs report (`window_minutes`); its usage API
    /// reports the same window as `limit_window_seconds`, hence the knob.
    /// Ignored when `mode = "assumed"` (`assumed` is always minutes).
    #[serde(default)]
    pub unit: PeriodUnit,
}

/// Unit of the value at [`PeriodConfig::field`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PeriodUnit {
    #[default]
    Minutes,
    Seconds,
}

impl PeriodUnit {
    /// Convert a raw period value into minutes. Seconds round *down*, so a
    /// window shorter than a minute reads as 0 rather than as a whole minute
    /// it never was.
    pub fn to_minutes(self, raw: u64) -> u64 {
        match self {
            PeriodUnit::Minutes => raw,
            PeriodUnit::Seconds => raw / 60,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeriodMode {
    /// The period length is a fixed constant (`assumed`).
    Assumed,
    /// The period length is read from the reading itself (`field`).
    FromField,
}

/// `[windows.source]` — where a window's numbers live in the provider's raw
/// reading (a JSONL line for `log-file`, a JSON response body for
/// `http-api`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SourceConfig {
    /// Candidate objects a window's numbers may live in (http-api engine),
    /// each a dotted JSON path into the response body — e.g.
    /// `["rate_limit.primary_window", "rate_limit.secondary_window"]`. The
    /// remaining paths in this section are then read *relative to* whichever
    /// candidate this window classifies to; with the list empty (the default)
    /// they are read from the response root, exactly as before.
    ///
    /// This exists because a provider need not put a given window in a fixed
    /// slot: Codex reports its weekly window as `primary_window` with
    /// `secondary_window` null whenever the 5-hour window has nothing to say,
    /// so reading "primary" as "the 5-hour window" would show a weekly figure
    /// on the 5H row. Candidates are classified by their own length against
    /// `min_period_minutes`/`max_period_minutes`, mirroring what the log-file
    /// engine already does with `primary`/`secondary` slots
    /// (`engine_logfile::classify_slot`).
    #[serde(default)]
    pub containers: Vec<String>,
    /// JSON path to the consumed-percent number (0–100). Optional since the
    /// arrival of [`remaining_fraction_path`](Self::remaining_fraction_path):
    /// an `http-api` window states its figure through exactly one of the two
    /// (`validate` enforces that), and the log-file engine reads neither — it
    /// takes `used_percent` from the log record's own fields
    /// (`engine_logfile`), so `source` there carries only the classification
    /// bounds. A window that names neither, on the http engine, is refused at
    /// load rather than left to resolve to nothing every fetch.
    #[serde(default)]
    pub used_percent_path: Option<String>,
    /// JSON path to a **remaining** fraction (0..1), for a provider that
    /// states what is left rather than what is spent — Antigravity's
    /// `remainingFraction`. The engine complements it into the same
    /// consumed-percent a window contract holds (`(1 − fraction)·100`, then
    /// clamped): a unit change of a figure the provider stated, reversible and
    /// information-preserving, not a percent computed from something it did
    /// not say. Mutually exclusive with [`used_percent_path`](Self::used_percent_path);
    /// needs `requires_reader = ["remaining-fraction"]`, since an older build
    /// has no notion of it and would read a window stating only this as one
    /// stating nothing.
    #[serde(default)]
    pub remaining_fraction_path: Option<String>,
    /// JSON path to the absolute reset timestamp.
    pub resets_at_path: String,
    /// Format of the value at `resets_at_path`.
    #[serde(default)]
    pub resets_at_format: ResetsAtFormat,
    /// Optional classification bound (log-file engine): a window is this
    /// slot only if its period is at most this many minutes.
    pub max_period_minutes: Option<u64>,
    /// Optional classification bound (log-file engine): a window is this
    /// slot only if its period is at least this many minutes.
    pub min_period_minutes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResetsAtFormat {
    #[default]
    Unix,
    Iso8601,
}

// ── [[balances]] ──────────────────────────────────────────────────────────

/// `[[balances]]` — a figure the provider reports against a calendar period,
/// as opposed to a `[[windows]]` percentage against a rolling one.
///
/// A separate section rather than a window with extra keys, for the reason
/// [`crate::model::Balance`] is a separate type: a window's percent and length
/// are its contract, and a balance has neither to give. Grok reports no window
/// at all — only a monthly billing period — which is why a manifest carrying
/// balances and no windows has to be legal (see [`PluginManifest::validate`]).
///
/// Needs `requires_reader = ["reading-balances"]`: an older build has no notion
/// of a balance, and would show such a provider as one that reported nothing.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BalanceConfig {
    /// Stable identity of this entry, used to build
    /// [`crate::model::Balance::key`] — same rules and same reasoning as
    /// [`WindowConfig::id`]: a label is a caption and may be reworded, so it
    /// cannot be an identity.
    #[serde(default)]
    pub id: String,
    /// Row label, a literal written by the manifest author. Never a template:
    /// a caption filled from the response would put provider text on a row
    /// this app vouches for.
    pub label: String,
    /// Where "spent" comes from.
    pub used: Option<AmountConfig>,
    /// Where the ceiling comes from, if the provider states one.
    pub cap: Option<AmountConfig>,
    /// Where "what is left" comes from, for providers that report the
    /// remainder instead of a used/cap pair.
    pub remaining: Option<AmountConfig>,
    /// `[balances.source]` — the non-amount figures: a stated percentage, a
    /// period end, a "limit reached" flag.
    #[serde(default)]
    pub source: BalanceSourceConfig,
}

/// One figure inside a `[[balances]]` entry, and where to read it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AmountConfig {
    /// Which form the provider states this figure in.
    pub kind: AmountKind,
    /// JSON path to the value — `number` and `text` only.
    pub path: Option<String>,
    /// `money-minor`: JSON path to the amount in minor units.
    pub amount_path: Option<String>,
    /// `money-minor`: JSON path to the ISO currency code.
    pub currency_path: Option<String>,
    /// `money-minor`: JSON path to the scale (how many minor units make a
    /// major one, as a power of ten). Required, and never assumed: "cents have
    /// two digits" holds until the first currency for which it does not, and
    /// the providers that state money state this beside it.
    pub exponent_path: Option<String>,
    /// `number` only: what the number counts, as a literal from the manifest.
    /// Not available to the other kinds — money carries its currency from the
    /// response, and text is the provider's own wording.
    pub unit_label: Option<String>,
}

/// The forms a balance figure arrives in. Exactly the three observed filled
/// by live providers; a fourth would be a branch nothing can test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AmountKind {
    /// Amount in minor units + currency + exponent, all three from the
    /// response. An incomplete triplet yields no figure at all.
    MoneyMinor,
    /// A bare number, with an optional `unit_label` from the manifest.
    Number,
    /// The provider's own string, sanitised before display.
    Text,
}

/// `[balances.source]` — everything in a balance that is not an amount.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BalanceSourceConfig {
    /// JSON path to a percentage **the provider states**. There is
    /// deliberately no way to ask for a computed one: a percentage this app
    /// derived would be indistinguishable on screen from one the provider
    /// published.
    pub percent_path: Option<String>,
    /// JSON path to the provider's "a spending limit has been reached" flag.
    pub limit_reached_path: Option<String>,
    /// JSON path to the end of the calendar period.
    pub period_end_path: Option<String>,
    /// Format of the value at `period_end_path`.
    #[serde(default)]
    pub period_end_format: ResetsAtFormat,
}

impl AmountConfig {
    /// Whether this figure names every path its kind needs.
    fn missing_path(&self) -> Option<&'static str> {
        match self.kind {
            AmountKind::MoneyMinor => {
                match (&self.amount_path, &self.currency_path, &self.exponent_path) {
                    (Some(_), Some(_), Some(_)) => None,
                    (None, _, _) => Some("amount_path"),
                    (_, None, _) => Some("currency_path"),
                    (_, _, None) => Some("exponent_path"),
                }
            }
            AmountKind::Number | AmountKind::Text => match self.path {
                Some(_) => None,
                None => Some("path"),
            },
        }
    }
}

impl BalanceConfig {
    /// The `<entry>` half of this balance's key — the declared `id`, or the
    /// entry's position when it has none. Mirrors [`WindowConfig::entry_key`],
    /// with a `b` prefix so a balance and a window at the same index cannot
    /// produce the same string.
    pub fn entry_key(&self, index: usize) -> String {
        match self.id.is_empty() {
            true => format!("b{index}"),
            false => self.id.clone(),
        }
    }

    /// Whether this entry reads anything at all. An entry that names no source
    /// draws a label beside empty space.
    fn reads_nothing(&self) -> bool {
        self.used.is_none()
            && self.cap.is_none()
            && self.remaining.is_none()
            && self.source.percent_path.is_none()
            && self.source.limit_reached_path.is_none()
    }
}

// ── [status] ──────────────────────────────────────────────────────────────

/// `[status]` — where a provider states the standing of the **quota**, above
/// and independent of its windows.
///
/// This exists because the two are genuinely separate in the data, not as a
/// convenience. Codex's own schema makes `allowed` and `limit_reached`
/// non-optional fields of `rate_limit`, while `primary_window` and
/// `secondary_window` are both optional — so a quota can arrive blocked and
/// carrying no window at all. Read only off the windows, that state is
/// invisible: `window-presence` correctly emits no row for a window the
/// provider did not report, and the whole quota would then vanish from the
/// panel at the one moment it matters most.
///
/// Every path is optional on its own. A provider that says only "you are
/// blocked" without saying which kind of limit it hit is answered with what it
/// said, not with a guess.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusConfig {
    /// JSON path to a boolean: may this account currently spend at all.
    pub allowed_path: Option<String>,
    /// JSON path to a boolean: has a limit been reached.
    pub limit_reached_path: Option<String>,
    /// JSON path to a short string naming which limit was reached. Kept as the
    /// provider's own word rather than mapped onto an enum here — a vocabulary
    /// that grows on the server would otherwise turn into a silent "unknown"
    /// on ours (see `quota_notice` in `src/main.rs`, which prints this value
    /// unmapped for the same reason).
    pub reached_type_path: Option<String>,
}

impl StatusConfig {
    /// Whether this section states anything at all.
    fn is_empty(&self) -> bool {
        [
            &self.allowed_path,
            &self.limit_reached_path,
            &self.reached_type_path,
        ]
        .iter()
        .all(|p| p.as_ref().is_none_or(|s| s.trim().is_empty()))
    }
}

// ── [logfile] ─────────────────────────────────────────────────────────────

/// `[logfile]` — configuration for the `engine = "log-file"` reader.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct LogFileConfig {
    /// Env var that, if set, overrides the root directory.
    pub root_env: Option<String>,
    /// Subdirectory appended onto the `root_env` override, if set (e.g.
    /// `"sessions"` so `$CODEX_HOME` resolves to `$CODEX_HOME/sessions`).
    /// Ignored when `root_env` is unset or the env var itself isn't; has no
    /// effect on the plain `root` fallback, which is used verbatim.
    #[serde(default)]
    pub root_env_join: Option<String>,
    /// Root directory to search (subject to `root_env` override and `~`
    /// expansion — see [`crate::plugin::expand_home`]).
    pub root: String,
    /// Glob (relative to `root`) matching the provider's log files.
    pub glob: String,
    /// Log file format.
    #[serde(default = "default_logfile_format")]
    pub format: String,
    /// Which reading to keep when a file has more than one.
    #[serde(default = "default_logfile_select")]
    pub select: String,
    /// JSON key that wraps a window-bearing reading (e.g. `"rate_limits"`).
    pub container_key: String,
    /// Windows at most this many minutes long classify as "short"; used to
    /// resolve slot ambiguity when a provider doesn't fix window order.
    #[serde(default = "default_classify_threshold_minutes")]
    pub classify_threshold_minutes: u64,
    /// Name of an executable to look up on `PATH` when deciding whether the
    /// provider is "installed" at all (e.g. `"codex"`). Optional: when unset,
    /// a missing reading is always reported via `no_data_message` (or the
    /// engine's generic fallback) — matching this engine's pre-existing
    /// behaviour for third-party log-file plugins that have no notion of
    /// "not installed".
    #[serde(default)]
    pub detect_bin: Option<String>,
    /// Error message to show when no reading was found **and** the provider
    /// looks not installed (`detect_bin` set, not on `PATH`, and the root
    /// directory doesn't exist). Falls back to the engine's generic
    /// "No {name} usage data found yet." when unset.
    #[serde(default)]
    pub not_installed_message: Option<String>,
    /// Error message to show when no reading was found but the provider
    /// otherwise looks installed (or `detect_bin` isn't set). Falls back to
    /// the engine's generic "No {name} usage data found yet." when unset.
    #[serde(default)]
    pub no_data_message: Option<String>,
    /// Guard for a session tree shared by more than one account. Codex Desktop
    /// and the Codex CLI can be signed into *different* ChatGPT accounts yet
    /// both write into `~/.codex/sessions`, so the newest rollout line may
    /// belong to a different account than `[account]` names — showing that
    /// account's usage under this login's email (and its plan chip). When set,
    /// only a container whose `container_field` equals the value read from the
    /// `[account]` JWT at `auth_claim` is accepted, pinning the reading to the
    /// current login. Unset (or when the auth value can't be read) → no
    /// filtering, the pre-existing "newest reading wins" behaviour. See
    /// [`AccountMatchConfig`].
    #[serde(default)]
    pub account_match: Option<AccountMatchConfig>,
}

/// A [`LogFileConfig::account_match`] rule. Both halves are required: the
/// field to compare inside the matched container, and where to read the
/// expected value from the `[account]` JWT.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AccountMatchConfig {
    /// Field inside the matched container (the object carrying
    /// `primary`/`secondary`) to compare — e.g. Codex's `plan_type`. Resolved
    /// as a dotted JSON path, like `[tag] path`, so a nested field works too.
    pub container_field: String,
    /// Segment path to the expected value inside the decoded `[account]` JWT
    /// claims — reusing `[account]`'s `path`/`token_path` to locate the JWT. A
    /// list, not a dotted string, precisely because a segment may itself
    /// contain dots, e.g.
    /// `["https://api.openai.com/auth", "chatgpt_plan_type"]`.
    pub auth_claim: Vec<String>,
}

fn default_logfile_format() -> String {
    "jsonl".to_string()
}

fn default_logfile_select() -> String {
    "last".to_string()
}

fn default_classify_threshold_minutes() -> u64 {
    720
}

// ── [http] ────────────────────────────────────────────────────────────────

/// `[http]` — configuration for the `engine = "http-api"` reader.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct HttpConfig {
    /// `[[http.request]]` — one or more requests to issue (usually one).
    #[serde(default)]
    pub request: Vec<HttpRequestConfig>,
    /// `[http.version]` — optional source for the `{version}` substitution.
    pub version: Option<HttpVersionConfig>,
    /// `[[http.value]]` — named values read out of local files, substituted
    /// into header values as `{value.<name>}` (see [`HttpValueConfig`]).
    #[serde(default)]
    pub value: Vec<HttpValueConfig>,
    /// Smallest gap between two requests for one surface, however the fetch
    /// was triggered. The refresh timer is not the only caller — opening the
    /// panel, the Refresh button and the tray's "Refresh now" all fetch on
    /// demand — so without a floor a user clicking around turns into a burst
    /// against the provider's API. Keep it *below* `refresh_secs` or the
    /// scheduled refresh lands a hair early and gets skipped every other
    /// tick, halving the real cadence.
    #[serde(default = "default_min_interval_secs")]
    pub min_interval_secs: u64,
    /// First cool-off after a failed request, doubling per consecutive
    /// failure up to `backoff_max_secs`.
    #[serde(default = "default_backoff_start_secs")]
    pub backoff_start_secs: u64,
    /// Ceiling for the exponential backoff — a provider that is down must
    /// still be retried eventually, just rarely.
    #[serde(default = "default_backoff_max_secs")]
    pub backoff_max_secs: u64,
    /// How long an expired session stops the polling for.
    ///
    /// A 401 normally ends when the user signs in again, which changes the
    /// credentials and is noticed at once — that, not this, is the way out.
    /// But a 401 can also come from a gateway having a bad minute, and a
    /// stop that only credentials can lift would then last until the app is
    /// restarted. So the stop expires: rarely enough that a genuinely dead
    /// token is not retried on a loop, often enough that nothing is stuck
    /// forever.
    #[serde(default = "default_unauthorized_retry_secs")]
    pub unauthorized_retry_secs: u64,
}

/// One `[[http.value]]` — a named value read out of a local file and
/// substituted into request headers as `{value.<name>}`.
///
/// Codex needs this for its `chatgpt-account-id` header: the account the
/// bearer token belongs to is named in `~/.codex/auth.json`, not in the
/// request URL. Declaring it here keeps that provider-specific fact in the
/// manifest — the engine only knows "resolve names, substitute them".
///
/// Values are substituted into **header values only**, never into the URL —
/// the same rule `{token}` follows (see `engine_http::build_request`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct HttpValueConfig {
    /// Placeholder name: `{value.<name>}`. ASCII letters, digits and
    /// underscores only, unique within the manifest.
    pub name: String,
    /// Where to read it from.
    #[serde(rename = "type")]
    pub kind: HttpValueType,
    /// Path to the file holding the value (`~`/`{config_dir}`-expanded).
    pub path: Option<String>,
    /// `json-file`: dotted JSON path to the value inside that file.
    pub json_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpValueType {
    /// Read a plain JSON file and take the string at `json_path`.
    JsonFile,
}

fn default_min_interval_secs() -> u64 {
    55
}

fn default_backoff_start_secs() -> u64 {
    60
}

fn default_backoff_max_secs() -> u64 {
    900
}

fn default_unauthorized_retry_secs() -> u64 {
    3600
}

/// One `[[http.request]]` entry.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct HttpRequestConfig {
    pub url: String,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// GET (the default) or POST. Every provider through Grok answers a plain
    /// GET; Antigravity's `:retrieveUserQuotaSummary` follows Google's `:verb`
    /// HTTP-transcoding convention, which is POST-only — a manifest for it has
    /// no way to say so without this field. Defaulted rather than required so
    /// every manifest written before this field existed keeps reading exactly
    /// as it did.
    #[serde(default)]
    pub method: HttpMethod,
    /// Request body for `method = "post"`, substituted exactly like a header
    /// value (`{token}`/`{version}`/`{value.<name>}`/`{option.<key>}` — see
    /// `engine_http::substitute`). `None` (the default) sends an empty body,
    /// the only sensible default for a GET (which cannot carry one at all —
    /// see `validate`) and an entirely ordinary POST (a request whose payload
    /// is the URL and the credentials in its headers, which is exactly what
    /// Antigravity's endpoint reads).
    #[serde(default)]
    pub body: Option<String>,
    /// Header map; values may contain `{token}` / `{version}` placeholders.
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

fn default_timeout_secs() -> u64 {
    8
}

/// [`HttpRequestConfig::method`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpMethod {
    #[default]
    Get,
    Post,
}

/// `[http.version]` — where to read the `{version}` placeholder value from.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct HttpVersionConfig {
    /// Candidate files to read, tried in order.
    pub files: Vec<String>,
    /// JSON path to the version string inside whichever file matched.
    pub json_path: String,
    /// Value to use if none of `files` exist or parse.
    pub fallback: String,
}

// ── [[surface]] ───────────────────────────────────────────────────────────

/// One `[[surface]]` — a place this provider's usage can be read from (a
/// CLI install, a desktop app, …), each with its own credential chain.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SurfaceConfig {
    /// Stable identifier ("cli", "desktop").
    pub id: String,
    /// Display label ("CLI", "Desktop").
    pub label: String,
    /// Whether the surface is off unless the user explicitly enables it
    /// (e.g. a surface whose credential lookup needs a scary OS prompt).
    #[serde(default)]
    pub opt_in: bool,
    /// Whether this surface's readings show in the menu-bar pill/title.
    /// Defaults to true; popup-only surfaces (the Claude desktop account)
    /// set `in_menu_bar = false`.
    #[serde(default = "default_true")]
    pub in_menu_bar: bool,
    /// Hosts this surface's requests are allowed to reach (defence in depth
    /// for the http engine).
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// What to show when the whole auth chain came up empty — no credential
    /// store on this machine at all. Unset (the default) keeps the existing
    /// behaviour: the surface is treated as "not set up here" and its row is
    /// hidden from the popup entirely, which is right for a provider that may
    /// simply not be installed (`crate::plugin::auth::NO_CREDENTIALS`).
    ///
    /// A provider that *is* worth naming in that state sets a sentence here —
    /// Codex, whose "not signed in" is a step away from being useful and used
    /// to say so while its usage came from local logs.
    #[serde(default)]
    pub no_credentials_message: Option<String>,
    /// `[[surface.auth]]` — ordered credential lookup chain. Tried in order;
    /// each step is Present-ok (token found, use it), Present-err (the
    /// credential store exists but the token couldn't be read — surface much
    /// stop with an error), or Absent (store doesn't exist — try the next
    /// step, or conclude the surface isn't present if none are left).
    #[serde(default)]
    pub auth: Vec<AuthStep>,
}

/// One step of a `[[surface.auth]]` chain.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AuthStep {
    /// Which credential store this step reads from.
    #[serde(rename = "type")]
    pub kind: AuthType,

    /// `credentials-file` / `credentials-map`: path to the JSON file.
    pub path: Option<String>,
    /// `credentials-file` / `keychain` / `credentials-map`: JSON path(s) to
    /// the token inside the credential payload (for `credentials-map`, inside
    /// the *matched entry* — see `key_prefix`); `|`-separated fallback keys,
    /// tried in order (e.g. `"claudeAiOauth.accessToken|access_token"`) — see
    /// [`split_fallback_keys`].
    pub token_json_path: Option<String>,

    /// `keychain`: optional JSON path to an RFC3339 expiry beside the token.
    /// When set and the moment it names is in the past (with a small margin),
    /// the step resolves **Absent** rather than handing back the stale token —
    /// so a chain can fall through to a refresh step behind it. Without it a
    /// keychain step returns whatever token it finds, fresh or not (the
    /// behaviour every existing manifest relies on). Antigravity's item carries
    /// `token.expiry`; the CLI keeps it current while it runs, and this lets a
    /// build tell "signed in, current" from "signed in, but the token lapsed".
    /// Needs `requires_reader = ["keychain-expiry"]`.
    pub expiry_json_path: Option<String>,

    /// `credentials-map`: prefix an entry's key in the top-level JSON object
    /// at `path` must start with to be selected. Exists because some
    /// credential files are not a single record but a map of them, keyed by a
    /// string no manifest can spell in advance — Grok's `~/.grok/auth.json`
    /// keys each account's record `"https://auth.x.ai::<uuid>"`, a uuid
    /// unique to the install. Matched by prefix rather than by an exact key.
    pub key_prefix: Option<String>,

    /// `keychain`: service name to query.
    pub service: Option<String>,

    /// `env`: environment variable name holding the token.
    pub var: Option<String>,

    /// `electron-safe-storage`: path to the Electron config/state file that
    /// holds the encrypted blob.
    pub config_path: Option<String>,
    /// `electron-safe-storage`: `|`-separated fallback JSON paths to the
    /// blob inside `config_path`.
    pub blob_json_path: Option<String>,
    /// `electron-safe-storage` (macOS): Keychain service name holding the
    /// Safe Storage password. Ignored on Windows, where the blob is
    /// decrypted via DPAPI instead — no manifest field needed for that.
    pub macos_keychain_key: Option<String>,

    /// `win-credential`: Windows Credential Manager target names to try, in
    /// order.
    pub targets: Option<Vec<String>>,

    /// `reject-when`: dotted JSON path inside `path` whose presence means
    /// this surface cannot be read at all.
    pub json_path: Option<String>,
    /// `reject-when`: escape hatch — when this dotted path also resolves to a
    /// value, the rejection does *not* fire and the chain moves on. Lets a
    /// rule stay narrow ("an API key **and** no OAuth token") without the
    /// engine knowing what either field means.
    pub unless_json_path: Option<String>,
    /// `reject-when`: the message shown on the provider's row instead of
    /// windows.
    pub message: Option<String>,

    /// `oauth-refresh`: where to send the token exchange. Checked against this
    /// surface's `allowed_hosts` at fetch time — `auth::resolve_token` runs
    /// ahead of the engine's own `allowed_hosts` check on the main request, so
    /// a step that talks to the network on its own enforces the allow-list
    /// itself (see `auth::oauth_refresh_step`).
    pub token_url: Option<String>,
    /// `oauth-refresh`: the OAuth "installed application" client id, spelled
    /// out in the manifest. Public by construction — it identifies which
    /// client is asking, not who is asking on whose behalf — and published by
    /// the provider's own CLI/IDE, like `client_secret` below. Still supported
    /// for a manifest that would rather ship the pair directly than discover
    /// it (see `client` below, which the shipped Antigravity manifest uses
    /// instead); an `oauth-refresh` step needs one or the other.
    pub client_id: Option<String>,
    /// `oauth-refresh`: the matching "installed application" client secret.
    /// Despite the name, not confidential the way `refresh_token` is — an
    /// installed-app secret embedded in a distributed binary cannot be kept
    /// from anyone willing to extract it, which is why OAuth2 treats such
    /// clients as public. Still never logged or put in an error string here.
    pub client_secret: Option<String>,
    /// `oauth-refresh`: read `client_id`/`client_secret` from the installed
    /// client's own binaries at run time instead of carrying them in the
    /// manifest — see [`AuthClientDiscovery`] and `auth::resolve_client` for
    /// the resolution order (env vars, then `client_id`/`client_secret`
    /// above, then this). Needs `requires_reader =
    /// ["oauth-client-discovery"]`.
    pub client: Option<AuthClientDiscovery>,
}

/// `[[surface.auth]].client` — where to find the OAuth "installed
/// application" pair `oauth-refresh` needs, on a machine that has the
/// credential's own client installed, instead of shipping the pair in the
/// manifest. The pair is public by OAuth2's own definition (see
/// [`AuthStep::client_id`]), which is what makes reading it back out of the
/// client's own binary a legitimate substitute for typing it out — the
/// repository never carries a value that only ever lived in somebody's
/// installed app to begin with.
///
/// Resolution, in `auth::resolve_client`: both `id_env`/`secret_env` set and
/// non-blank wins outright; then the step's own literal `client_id`/
/// `client_secret`, if the manifest still carries them; then each of `files`
/// (after `~` expansion), then each of `bins` resolved on `PATH` and the
/// usual CLI install directories, scanned in order for the first match of
/// `id_pattern` and `secret_pattern` — both from the *same* file. Nothing
/// found resolves the step Absent, exactly like a missing credentials file.
///
/// `#[serde(deny_unknown_fields)]` — deliberately *not* this manifest
/// format's usual stance (see `PluginManifest`'s own doc: the schema at
/// large stays forward-compatible, an older build simply ignores a field it
/// doesn't know yet). This one table is the exception: `files`, `bins` and
/// `id_env` are exactly what `registry::analyze_trust`'s trust dialog shows
/// before installing anything, and a typo in one of them (`fils` for
/// `files`, say) would otherwise silently disable a candidate list or an
/// override rather than refuse to parse — a manifest author would see a
/// discovery config that never finds what it should, with nothing to point
/// at why. See `docs/PLUGIN-ARCHITECTURE.md`'s `[surface.auth.client]`
/// section for the same rule, stated for a reader who is not this source
/// file.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthClientDiscovery {
    /// Environment variable naming the client id. Checked first — an
    /// operator's own override always wins over whatever discovery would
    /// find, and is the only path that needs nothing installed at all.
    pub id_env: Option<String>,
    /// Environment variable naming the client secret. Both this and `id_env`
    /// have to be set, and non-blank, for the pair to come from the
    /// environment — one without the other falls through to discovery.
    pub secret_env: Option<String>,
    /// Regular expression (`regex` crate syntax) matched against a candidate
    /// file's bytes; the first match is the client id. Required.
    pub id_pattern: Option<String>,
    /// Same, for the client secret. Required.
    pub secret_pattern: Option<String>,
    /// Absolute paths (after `~` expansion) to scan first, in the order
    /// given. May be empty if `bins` names at least one candidate, or if
    /// `id_env`/`secret_env` are both set (nothing to search at all is then
    /// fine — the environment is always tried first).
    #[serde(default)]
    pub files: Vec<String>,
    /// Bare program names to resolve on `PATH` (and the install directories
    /// `main.rs`'s auto-ping already appends — see
    /// `crate::plugin::cli_install_dirs`), scanned after `files`. Same
    /// emptiness rule as `files`.
    #[serde(default)]
    pub bins: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthType {
    CredentialsFile,
    Keychain,
    Env,
    ElectronSafeStorage,
    WinCredential,
    /// The JSON object at `path` is a *map* of credential records, keyed by a
    /// string the manifest cannot predict, rather than a single record. Picks
    /// the one entry whose key starts with `key_prefix`, then reads
    /// `token_json_path` inside that entry — same grammar `credentials-file`
    /// already uses, applied one level deeper.
    ///
    /// The existing dotted-path grammar cannot reach such an entry at all:
    /// `json_path`/`token_json_path` split on `.` (see `json_path_str` /
    /// `credentials_file_step`), and `token_json_path`'s own fallback list
    /// splits on `|` (see `split_fallback_keys`) — neither can name a key that
    /// itself contains dots and colons, which is exactly what
    /// `"https://auth.x.ai::<uuid>"` is. More than one entry matching the
    /// prefix is refused rather than resolved by iteration order: which
    /// account's token that would pick is not something this app gets to
    /// guess (see `auth::credentials_map_step`).
    CredentialsMap,
    /// Not a credential store: a diagnostic step that turns a *known* dead
    /// end into a sentence the user can act on. When the field at `json_path`
    /// is present (and equal to `equals`, if given), the chain stops with
    /// `message`.
    ///
    /// Codex's case: signing in with an API key instead of a ChatGPT account
    /// leaves `OPENAI_API_KEY` set in `~/.codex/auth.json` and no OAuth
    /// token. Such an account has no subscription windows to report, so the
    /// honest answer is "an API key has no subscription limits", not the
    /// blank row a missing credential produces.
    ///
    /// Such a step belongs *before* the one that reads the real token, since
    /// a `credentials-file` step whose file exists but holds no token is
    /// Present-err and stops the chain on its own. `unless_json_path` is what
    /// keeps that ordering honest: the rejection stands down when the token
    /// it would have pre-empted is there after all.
    RejectWhen,
    /// Not a read: exchanges a stored `refresh_token` for a fresh
    /// `access_token` over the network, and hands back the latter — never
    /// written to disk (see `auth::oauth_refresh_step` for why, and why this
    /// step exists when every other one here follows "read, never renew").
    /// Google's Antigravity is the provider it exists for: the `access_token`
    /// on disk goes stale in hours whenever its IDE isn't running, so a step
    /// that only reads it would report "sign in again" almost all of the time —
    /// not a true statement about the account (measured, see the provider
    /// spec). Placed after an expiry-aware keychain step, it fires only when
    /// that token has lapsed.
    OauthRefresh,
}

/// [`AuthClientDiscovery::bins`]: a bare program name — no separator, no
/// `..` component, no drive prefix — the shape `auth::bin_candidates` joins
/// a directory onto. `files` has no equivalent rule: it is already a path,
/// by design (see the field's own doc).
fn is_bare_program_name(name: &str) -> bool {
    let has_drive_prefix =
        name.len() >= 2 && name.as_bytes()[0].is_ascii_alphabetic() && name.as_bytes()[1] == b':';
    !name.is_empty() && !name.contains(['/', '\\']) && !name.contains("..") && !has_drive_prefix
}

/// Whether `p` would be an absolute path on *some* platform this app runs
/// on, not merely the one validating it. `Path::is_absolute()` answers only
/// for the platform this binary happens to be compiled for: on Windows,
/// `/Applications/Antigravity.app/…` — an entirely ordinary POSIX absolute
/// path, and exactly what the shipped Antigravity manifest's `client.files`
/// names — is *not* absolute, because Windows requires a drive letter or a
/// UNC prefix. A plugin manifest is cross-platform data (the same
/// `antigravity.toml` ships to macOS and Windows installs alike); a
/// macOS-only candidate on a Windows machine is simply a file that will
/// never exist at discovery time, the same as any other candidate nothing
/// installed there — not a reason to refuse the *manifest* at load, on
/// every platform, for a path some other platform wrote. `starts_with('/')`
/// on the lossy string is the POSIX half this platform's own
/// `is_absolute()` may disagree with; `Path::is_absolute()` itself still
/// covers this platform's own notion (POSIX `/…` when validating on POSIX,
/// a drive letter or UNC prefix when validating on Windows).
fn is_absolute_on_any_platform(p: &Path) -> bool {
    p.is_absolute() || p.to_string_lossy().starts_with('/')
}

/// [`AuthClientDiscovery::id_env`]/`secret_env`: the POSIX/Windows
/// environment-variable charset — a leading letter or underscore, then
/// letters, digits or underscores. `std::env::var` would simply never find
/// anything for a name outside it, so refusing it here is a clearer answer
/// than a silent miss at every fetch.
fn is_valid_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The most bytes any match of `pattern` could ever return — `None` when
/// there is no such maximum (an unbounded repeat, e.g. `.*` or `[a-z]+`).
/// Parsed by `regex_syntax` directly rather than derived from a compiled
/// `regex::bytes::Regex` (which does not expose this): the same grammar
/// `regex::bytes::Regex` compiles, so a pattern this measures as unbounded is
/// exactly one that engine would have matched as unboundedly long.
///
/// `pub(crate)`, not private: `auth::compile_scan_pattern` reads this same
/// figure to decide whether a discovery pattern's match has already reached
/// its own maximum length (and so needs no deferral at a chunk boundary —
/// see `auth::accept_settled_match`'s own doc). One function, not two
/// independent copies of this parse, so validation's finite-maximum
/// requirement and the scanner's deferral rule can never disagree about
/// what a given pattern's maximum actually is.
pub(crate) fn regex_max_match_len(pattern: &str) -> Option<usize> {
    regex_syntax::Parser::new()
        .parse(pattern)
        .ok()?
        .properties()
        .maximum_len()
}

/// The fewest bytes any match of `pattern` could ever return — `0` for a
/// pattern that can match the empty string (e.g. `a*` or `(foo)?`). Paired
/// with [`regex_max_match_len`] against the same parse: an `id_pattern`/
/// `secret_pattern` that can match nothing is not "bounded", it is a
/// manifest bug that `discover_client` would otherwise turn into a client
/// id of `""` — a credential the OAuth exchange would then fail on with a
/// message naming no field a user wrote.
fn regex_min_match_len(pattern: &str) -> Option<usize> {
    regex_syntax::Parser::new()
        .parse(pattern)
        .ok()?
        .properties()
        .minimum_len()
}

/// A `[[surface.auth]].type` in its manifest spelling, for error messages.
fn auth_type_name(kind: AuthType) -> &'static str {
    match kind {
        AuthType::CredentialsFile => "credentials-file",
        AuthType::Keychain => "keychain",
        AuthType::Env => "env",
        AuthType::ElectronSafeStorage => "electron-safe-storage",
        AuthType::WinCredential => "win-credential",
        AuthType::CredentialsMap => "credentials-map",
        AuthType::RejectWhen => "reject-when",
        AuthType::OauthRefresh => "oauth-refresh",
    }
}

/// The first header-only placeholder found in a URL, if any — see the
/// validation that uses it.
fn url_placeholder(url: &str) -> Option<&'static str> {
    if url.contains("{token}") {
        return Some("`{token}`");
    }
    if url.contains("{version}") {
        return Some("`{version}`");
    }
    if url.contains("{value.") {
        return Some("`{value.<name>}`");
    }
    None
}

/// Split a `token_json_path`-style spec on `|` into its ordered fallback
/// keys, trimming surrounding whitespace off each. Used by the auth/http
/// engines when walking a JSON path that names more than one acceptable key
/// (e.g. `"claudeAiOauth.accessToken|access_token"` → try the camelCase key,
/// then the snake_case one).
pub fn split_fallback_keys(spec: &str) -> Vec<&str> {
    spec.split('|').map(str::trim).collect()
}

// ── [ping] ────────────────────────────────────────────────────────────────

/// `[ping]` — optional command run shortly after a window resets, to start a
/// fresh one (consumes a little quota, so plugins/users may opt out).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PingConfig {
    pub bin: String,
    #[serde(default)]
    pub args: Vec<String>,
}

// ── [[option]] ────────────────────────────────────────────────────────────

/// One `[[option]]` — a declarative bool option a plugin exposes, resolved by
/// `crate::config::plugin_option` and made available to the engines as the
/// `{option.<key>}` substitution (see [`crate::plugin::substitute_options`]).
/// A settings-sheet checkbox for these is a later phase (3b UI) — this
/// schema layer is UI-agnostic.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct OptionConfig {
    /// Stable identifier, unique within the plugin. Restricted to ASCII
    /// letters/digits/underscore (see [`PluginManifest::validate`]) so the
    /// `{option.<key>}` placeholder it drives is always unambiguous.
    pub key: String,
    /// Display label for the (future) checkbox.
    pub label: String,
    /// Value used until the user overrides it via config.
    #[serde(default)]
    pub default: bool,
}

// ── Directory loading ─────────────────────────────────────────────────────

/// Read every `*.toml` file directly inside `dir` as a [`PluginManifest`],
/// sorted by declared `order` (ties broken by `id`). Manifests that fail to
/// parse or validate are returned as `Err((path, message))` and sort after
/// every successfully-loaded manifest, keeping their directory-listing
/// relative order among themselves.
///
/// Returns an empty vec if `dir` doesn't exist or isn't readable — loading
/// plugin manifests is always best-effort at the call site.
pub fn load_dir(dir: &Path) -> Vec<Result<PluginManifest, (PathBuf, String)>> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("toml"))
        .collect();
    paths.sort();

    let mut results: Vec<Result<PluginManifest, (PathBuf, String)>> = paths
        .into_iter()
        .map(|path| load_one(&path).map_err(|e| (path.clone(), e)))
        .collect();

    results.sort_by(|a, b| match (a, b) {
        (Ok(a), Ok(b)) => a.order.cmp(&b.order).then_with(|| a.id.cmp(&b.id)),
        (Ok(_), Err(_)) => std::cmp::Ordering::Less,
        (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
        (Err(_), Err(_)) => std::cmp::Ordering::Equal,
    });
    results
}

fn load_one(path: &Path) -> Result<PluginManifest, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    PluginManifest::from_str(&text)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A Codex-like manifest: `engine = "log-file"`, one primary window
    /// classified `from_field`, one secondary window classified `assumed`.
    const CODEX_LIKE: &str = r#"
        id           = "codex"
        name         = "Codex"
        menu_label   = "Cx"
        order        = 10
        version      = "1.2.3"
        engine       = "log-file"
        refresh_secs = 15

        [tag]
        from = "field"
        path = "plan_type"
        transform = "uppercase"

        [account]
        type       = "jwt-file"
        path       = "~/.codex/auth.json"
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
        mode  = "assumed"
        assumed = 10080
        [windows.source]
        used_percent_path = "used_percent"
        resets_at_path    = "resets_at"
        min_period_minutes = 721

        [logfile]
        root_env      = "CODEX_HOME"
        root          = "~/.codex/sessions"
        glob          = "**/rollout-*.jsonl"
        container_key = "rate_limits"

        [ping]
        bin  = "codex"
        args = ["exec", "hello"]
    "#;

    /// A Claude-like manifest: `engine = "http-api"`, two surfaces, the CLI
    /// surface with a two-step auth chain.
    const CLAUDE_LIKE: &str = r#"
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
        url = "https://api.anthropic.com/api/oauth/usage"
        timeout_secs = 8
        [http.request.headers]
        Authorization    = "Bearer {token}"
        "anthropic-beta" = "oauth-2025-04-20"
        "User-Agent"     = "claude-code/{version}"

        [http.version]
        files = [
            "/usr/local/lib/node_modules/@anthropic-ai/claude-code/package.json",
            "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/package.json",
        ]
        json_path = "version"
        fallback  = "2.1.78"

        [[surface]]
        id     = "cli"
        label  = "CLI"
        opt_in = false
        allowed_hosts = ["api.anthropic.com"]
        [[surface.auth]]
        type = "credentials-file"
        path = "~/.claude/.credentials.json"
        token_json_path = "claudeAiOauth.accessToken|access_token"
        [[surface.auth]]
        type = "keychain"
        service = "Claude Code-credentials"
        token_json_path = "claudeAiOauth.accessToken|access_token"

        [[surface]]
        id     = "desktop"
        label  = "Desktop"
        allowed_hosts = ["example.com"]
        opt_in = true
        in_menu_bar = false
        [[surface.auth]]
        type = "electron-safe-storage"
        config_path = "{config_dir}/Claude/config.json"
        blob_json_path = "oauth:tokenCacheV2|oauth:tokenCache"
        macos_keychain_key = "Claude Safe Storage"
    "#;

    #[test]
    fn a_manifest_saved_with_a_byte_order_mark_still_parses() {
        // Notepad is what "Edit" opens a manifest in on Windows, and its
        // Save has historically written UTF-8 with a BOM — so a manifest the
        // app itself handed the user to edit used to come back unreadable,
        // reported as "invalid manifest TOML" at line 1.
        let with_bom = format!("\u{feff}{CODEX_LIKE}");
        let m =
            PluginManifest::from_str(&with_bom).expect("a BOM must not make a manifest invalid");
        assert_eq!(m.id, "codex");
    }

    #[test]
    fn parses_full_codex_like_log_file_manifest() {
        let m = PluginManifest::from_str(CODEX_LIKE).expect("valid manifest");

        assert_eq!(m.id, "codex");
        assert_eq!(m.name, "Codex");
        assert_eq!(m.menu_label, "Cx");
        assert_eq!(m.order, 10);
        assert_eq!(m.version, "1.2.3");
        assert_eq!(m.engine, EngineKind::LogFile);
        assert_eq!(m.refresh_secs, 15);
        assert!(m.enabled, "enabled defaults to true and stays true");

        assert_eq!(m.tag.from, TagFrom::Field);
        assert_eq!(m.tag.path.as_deref(), Some("plan_type"));
        assert_eq!(m.tag.transform, TagTransform::Uppercase);

        assert_eq!(m.account.kind, AccountType::JwtFile);
        assert_eq!(m.account.path.as_deref(), Some("~/.codex/auth.json"));
        assert_eq!(m.account.token_path.as_deref(), Some("tokens.id_token"));
        assert_eq!(m.account.claim.as_deref(), Some("email"));

        assert_eq!(m.windows.len(), 2);
        let five_h = &m.windows[0];
        assert_eq!(five_h.label, "5H");
        assert_eq!(five_h.role, Role::Primary);
        assert_eq!(five_h.period.mode, PeriodMode::FromField);
        assert_eq!(five_h.period.field.as_deref(), Some("window_minutes"));
        assert_eq!(
            five_h.source.used_percent_path.as_deref(),
            Some("used_percent")
        );
        assert_eq!(five_h.source.resets_at_path, "resets_at");
        assert_eq!(five_h.source.resets_at_format, ResetsAtFormat::Unix);
        assert_eq!(five_h.source.max_period_minutes, Some(720));

        let weekly = &m.windows[1];
        assert_eq!(weekly.role, Role::Secondary);
        assert_eq!(weekly.period.mode, PeriodMode::Assumed);
        assert_eq!(weekly.period.assumed, Some(10080));
        assert_eq!(weekly.source.min_period_minutes, Some(721));

        let lf = m.logfile.as_ref().expect("[logfile] section");
        assert_eq!(lf.root_env.as_deref(), Some("CODEX_HOME"));
        assert_eq!(lf.root, "~/.codex/sessions");
        assert_eq!(lf.glob, "**/rollout-*.jsonl");
        assert_eq!(lf.format, "jsonl", "format defaults to jsonl");
        assert_eq!(lf.select, "last", "select defaults to last");
        assert_eq!(lf.container_key, "rate_limits");
        assert_eq!(lf.classify_threshold_minutes, 720, "default threshold");

        assert!(m.http.is_none());

        let ping = m.ping.as_ref().expect("[ping] section");
        assert_eq!(ping.bin, "codex");
        assert_eq!(ping.args, vec!["exec".to_string(), "hello".to_string()]);

        // No [[surface]] declared → synthesized single opt-out default.
        assert_eq!(m.surface.len(), 1);
        assert_eq!(m.surface[0].id, "default");
        assert!(!m.surface[0].opt_in);
        assert!(m.surface[0].auth.is_empty());
    }

    #[test]
    fn parses_full_claude_like_http_api_manifest_with_two_surfaces() {
        let m = PluginManifest::from_str(CLAUDE_LIKE).expect("valid manifest");

        assert_eq!(m.engine, EngineKind::HttpApi);
        assert!(m.logfile.is_none());

        let http = m.http.as_ref().expect("[http] section");
        assert_eq!(http.request.len(), 1);
        let req = &http.request[0];
        assert_eq!(req.url, "https://api.anthropic.com/api/oauth/usage");
        assert_eq!(req.timeout_secs, 8);
        assert_eq!(
            req.headers.get("Authorization").map(String::as_str),
            Some("Bearer {token}")
        );
        assert_eq!(
            req.headers.get("anthropic-beta").map(String::as_str),
            Some("oauth-2025-04-20")
        );
        assert_eq!(
            req.headers.get("User-Agent").map(String::as_str),
            Some("claude-code/{version}")
        );

        let ver = http.version.as_ref().expect("[http.version] section");
        assert_eq!(ver.files.len(), 2);
        assert_eq!(ver.json_path, "version");
        assert_eq!(ver.fallback, "2.1.78");

        assert_eq!(
            m.surface.len(),
            2,
            "two declared surfaces, no synthesized default"
        );

        let cli = &m.surface[0];
        assert_eq!(cli.id, "cli");
        assert_eq!(cli.label, "CLI");
        assert!(!cli.opt_in);
        assert_eq!(cli.allowed_hosts, vec!["api.anthropic.com".to_string()]);
        assert_eq!(cli.auth.len(), 2, "two-step auth chain");
        assert_eq!(cli.auth[0].kind, AuthType::CredentialsFile);
        assert_eq!(
            cli.auth[0].path.as_deref(),
            Some("~/.claude/.credentials.json")
        );
        assert_eq!(
            cli.auth[0].token_json_path.as_deref(),
            Some("claudeAiOauth.accessToken|access_token")
        );
        assert_eq!(cli.auth[1].kind, AuthType::Keychain);
        assert_eq!(
            cli.auth[1].service.as_deref(),
            Some("Claude Code-credentials")
        );

        let desktop = &m.surface[1];
        assert_eq!(desktop.id, "desktop");
        assert!(desktop.opt_in);
        assert_eq!(desktop.auth.len(), 1);
        assert_eq!(desktop.auth[0].kind, AuthType::ElectronSafeStorage);
        assert_eq!(
            desktop.auth[0].config_path.as_deref(),
            Some("{config_dir}/Claude/config.json")
        );
        assert_eq!(
            desktop.auth[0].blob_json_path.as_deref(),
            Some("oauth:tokenCacheV2|oauth:tokenCache")
        );
        assert_eq!(
            desktop.auth[0].macos_keychain_key.as_deref(),
            Some("Claude Safe Storage")
        );
    }

    #[test]
    fn surface_in_menu_bar_defaults_true_and_parses_false() {
        let m = PluginManifest::from_str(CLAUDE_LIKE).expect("valid manifest");
        assert!(
            m.surface[0].in_menu_bar,
            "surface without the field defaults to in_menu_bar = true"
        );
        assert!(
            !m.surface[1].in_menu_bar,
            "in_menu_bar = false parses (popup-only desktop surface)"
        );
    }

    #[test]
    fn defaults_apply_when_omitted() {
        let minimal = r#"
            id         = "x"
            name       = "X"
            menu_label = "X"
            order      = 1
            engine     = "log-file"

            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode    = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "p"
            resets_at_path    = "r"

            [logfile]
            root          = "~/.x"
            glob          = "*.jsonl"
            container_key = "rate_limits"
        "#;
        let m = PluginManifest::from_str(minimal).expect("valid manifest");
        assert_eq!(m.refresh_secs, 60, "refresh_secs defaults to 60");
        assert_eq!(
            m.version, "",
            "version defaults to an empty string — a manifest predating the plugin registry \
             (no `version` field at all) must still parse, matching `#[serde(default)]`"
        );
        assert!(m.enabled, "enabled defaults to true");
        assert_eq!(m.tag.from, TagFrom::None, "tag.from defaults to none");
        assert_eq!(m.tag.transform, TagTransform::None);
        assert_eq!(
            m.account.kind,
            AccountType::None,
            "account.type defaults to none"
        );
        assert_eq!(m.windows[0].source.resets_at_format, ResetsAtFormat::Unix);
        assert_eq!(
            m.surface.len(),
            1,
            "a single default surface is synthesized"
        );
    }

    #[test]
    fn unknown_fields_are_ignored_not_rejected() {
        // `deny_unknown_fields` is deliberately not set (see module docs):
        // a manifest written for a newer version of this reader must still
        // load, ignoring fields this build doesn't know about yet.
        let with_extra_fields = r#"
            id             = "x"
            name           = "X"
            menu_label     = "X"
            order          = 1
            engine         = "log-file"
            future_field   = "some value from a newer schema version"

            [[windows]]
            label = "5H"
            role  = "primary"
            future_window_field = 123
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
            future_logfile_field = true
        "#;
        let m = PluginManifest::from_str(with_extra_fields)
            .expect("unknown fields must not break parsing");
        assert_eq!(m.id, "x");
    }

    #[test]
    fn rejects_blank_required_strings_not_just_missing_ones() {
        let blank_id = r#"
            id         = "   "
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
        let err = PluginManifest::from_str(blank_id).expect_err("blank id must be rejected");
        assert!(err.contains("id"), "error should mention id: {err}");

        let blank_name = blank_id.replacen(r#"id         = "   ""#, r#"id = "x""#, 1);
        let blank_name = blank_name.replacen(r#"name       = "X""#, r#"name = """#, 1);
        assert!(PluginManifest::from_str(&blank_name).is_err());
    }

    /// `id` is used as a filename stem and as a config-key segment
    /// (`plugin.<id>.*`) — see the charset check's own doc comment in
    /// `validate`. A path separator, a `..` component or whitespace must be
    /// rejected; letters, digits, `_` and `-` must still be accepted.
    #[test]
    fn rejects_ids_outside_the_safe_charset_but_accepts_hyphen_and_underscore() {
        let manifest_with_id = |id: &str| {
            format!(
                r#"
                id         = "{id}"
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
                "#
            )
        };

        for bad in [
            "../../evil",
            "/tmp/evil",
            "a/b",
            "has space",
            "plugin;rm -rf",
        ] {
            let toml = manifest_with_id(bad);
            let err = PluginManifest::from_str(&toml)
                .expect_err(&format!("id \"{bad}\" must be rejected"));
            assert!(
                err.contains(bad),
                "error should name the offending id: {err}"
            );
        }

        for good in ["codex", "claude", "my-plugin_2", "A1_b-2"] {
            let toml = manifest_with_id(good);
            assert!(
                PluginManifest::from_str(&toml).is_ok(),
                "id \"{good}\" must be accepted"
            );
        }
    }

    #[test]
    fn rejects_manifest_missing_required_fields() {
        // Missing `id`.
        let no_id = r#"
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
        assert!(PluginManifest::from_str(no_id).is_err());

        // Missing `engine`.
        let no_engine = r#"
            id         = "x"
            name       = "X"
            menu_label = "X"
            order      = 1
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "p"
            resets_at_path = "r"
        "#;
        assert!(PluginManifest::from_str(no_engine).is_err());

        // Missing `[[windows]]` entirely.
        let no_windows = r#"
            id         = "x"
            name       = "X"
            menu_label = "X"
            order      = 1
            engine     = "log-file"
            [logfile]
            root = "~/.x"
            glob = "*.jsonl"
            container_key = "rate_limits"
        "#;
        let err = PluginManifest::from_str(no_windows).expect_err("empty windows must be rejected");
        assert!(
            err.contains("windows"),
            "error should mention windows: {err}"
        );

        // engine = "log-file" but no [logfile] section.
        let no_logfile = r#"
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
        "#;
        let err =
            PluginManifest::from_str(no_logfile).expect_err("missing [logfile] must be rejected");
        assert!(
            err.contains("logfile"),
            "error should mention logfile: {err}"
        );
    }

    #[test]
    fn rejects_two_primary_windows() {
        let two_primary = r#"
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

            [[windows]]
            label = "WK"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 10080
            [windows.source]
            used_percent_path = "p2"
            resets_at_path = "r2"

            [logfile]
            root = "~/.x"
            glob = "*.jsonl"
            container_key = "rate_limits"
        "#;
        let err =
            PluginManifest::from_str(two_primary).expect_err("two primaries must be rejected");
        assert!(
            err.contains("primary"),
            "error should mention primary: {err}"
        );
    }

    #[test]
    fn rejects_zero_refresh_secs() {
        let zero_refresh = r#"
            id           = "x"
            name         = "X"
            menu_label   = "X"
            order        = 1
            engine       = "log-file"
            refresh_secs = 0
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
        let err =
            PluginManifest::from_str(zero_refresh).expect_err("refresh_secs = 0 must be rejected");
        assert!(
            err.contains("refresh_secs"),
            "error should mention refresh_secs: {err}"
        );
    }

    #[test]
    fn rejects_http_api_without_exactly_one_request() {
        let base = |http_section: &str| {
            format!(
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
                {http_section}
                "#
            )
        };

        let no_http = base("");
        let err = PluginManifest::from_str(&no_http).expect_err("missing [http] must be rejected");
        assert!(err.contains("http"), "error should mention http: {err}");

        let empty_requests = base("[http]");
        let err = PluginManifest::from_str(&empty_requests)
            .expect_err("[http] with zero [[http.request]] entries must be rejected");
        assert!(
            err.contains("http.request"),
            "error should mention http.request: {err}"
        );

        let two_requests = base(
            r#"
            [http]
            [[http.request]]
            url = "https://example.com/a"
            [[http.request]]
            url = "https://example.com/b"
            "#,
        );
        let err = PluginManifest::from_str(&two_requests)
            .expect_err("more than one [[http.request]] must be rejected");
        assert!(
            err.contains("http.request"),
            "error should mention http.request: {err}"
        );

        let one_request = base(
            r#"
            [http]
            [[http.request]]
            url = "https://example.com/a"
            "#,
        );
        assert!(
            PluginManifest::from_str(&one_request).is_ok(),
            "exactly one request is valid"
        );
    }

    #[test]
    fn rejects_period_mode_mismatched_with_its_field() {
        let base = |period: &str| {
            format!(
                r#"
                id         = "x"
                name       = "X"
                menu_label = "X"
                order      = 1
                engine     = "log-file"
                [[windows]]
                label = "5H"
                role  = "primary"
                {period}
                [windows.source]
                used_percent_path = "p"
                resets_at_path = "r"
                [logfile]
                root = "~/.x"
                glob = "*.jsonl"
                container_key = "rate_limits"
                "#
            )
        };

        let assumed_without_value = base("[windows.period]\nmode = \"assumed\"");
        assert!(PluginManifest::from_str(&assumed_without_value).is_err());

        let from_field_without_field = base("[windows.period]\nmode = \"from_field\"");
        assert!(PluginManifest::from_str(&from_field_without_field).is_err());

        let assumed_with_value = base("[windows.period]\nmode = \"assumed\"\nassumed = 300");
        assert!(PluginManifest::from_str(&assumed_with_value).is_ok());

        let from_field_with_field =
            base("[windows.period]\nmode = \"from_field\"\nfield = \"window_minutes\"");
        assert!(PluginManifest::from_str(&from_field_with_field).is_ok());
    }

    // ── [[option]] ───────────────────────────────────────────────────────

    /// A minimal valid manifest body shared by the `[[option]]` tests, with
    /// `{option_section}` spliced in.
    fn base_with_option_section(option_section: &str) -> String {
        format!(
            r#"
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
            {option_section}
            "#
        )
    }

    #[test]
    fn parses_two_options_with_defaults() {
        let toml = base_with_option_section(
            r#"
            [[option]]
            key     = "include_beta"
            label   = "Include beta usage"
            default = true

            [[option]]
            key   = "verbose_logging"
            label = "Verbose logging"
            "#,
        );
        let m = PluginManifest::from_str(&toml).expect("valid manifest");
        assert_eq!(m.option.len(), 2);
        assert_eq!(m.option[0].key, "include_beta");
        assert_eq!(m.option[0].label, "Include beta usage");
        assert!(m.option[0].default);
        assert_eq!(m.option[1].key, "verbose_logging");
        assert!(
            !m.option[1].default,
            "default defaults to false when omitted"
        );
    }

    #[test]
    fn manifest_without_option_section_yields_an_empty_vec() {
        // Backward compatibility: codex.toml/claude.toml declare no
        // `[[option]]` at all, and must parse exactly as before.
        let toml = base_with_option_section("");
        let m = PluginManifest::from_str(&toml).expect("valid manifest");
        assert!(m.option.is_empty());
    }

    #[test]
    fn rejects_blank_option_key() {
        let toml = base_with_option_section(
            r#"
            [[option]]
            key   = "   "
            label = "Blank key"
            "#,
        );
        let err = PluginManifest::from_str(&toml).expect_err("blank option key must be rejected");
        assert!(err.contains("key"), "error should mention key: {err}");
    }

    #[test]
    fn rejects_option_key_with_invalid_characters() {
        let toml = base_with_option_section(
            r#"
            [[option]]
            key   = "bad-key!"
            label = "Bad key"
            "#,
        );
        let err =
            PluginManifest::from_str(&toml).expect_err("non-alphanumeric key must be rejected");
        assert!(
            err.contains("bad-key!"),
            "error should name the offending key: {err}"
        );
    }

    #[test]
    fn rejects_blank_option_label() {
        let toml = base_with_option_section(
            r#"
            [[option]]
            key   = "opt"
            label = ""
            "#,
        );
        let err = PluginManifest::from_str(&toml).expect_err("blank option label must be rejected");
        assert!(err.contains("label"), "error should mention label: {err}");
    }

    #[test]
    fn rejects_duplicate_option_keys() {
        let toml = base_with_option_section(
            r#"
            [[option]]
            key   = "dup"
            label = "First"

            [[option]]
            key   = "dup"
            label = "Second"
            "#,
        );
        let err =
            PluginManifest::from_str(&toml).expect_err("duplicate option keys must be rejected");
        assert!(
            err.contains("dup"),
            "error should name the duplicated key: {err}"
        );
    }

    // ── http-api additions: containers, [[http.value]], reject-when ──────

    /// A minimal `http-api` manifest with `{extra}` spliced in before the
    /// `[http]` section and `{http_extra}` after it — enough to exercise the
    /// validation rules the Codex usage manifest depends on.
    fn http_manifest_with(window_source: &str, http_extra: &str, surface_extra: &str) -> String {
        format!(
            r#"
            id         = "http-test"
            name       = "HttpTest"
            menu_label = "Ht"
            order      = 1
            engine     = "http-api"

            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode  = "from_field"
            field = "limit_window_seconds"
            unit  = "seconds"
            [windows.source]
            {window_source}
            used_percent_path = "used_percent"
            resets_at_path    = "reset_at"

            [http]
            {http_extra}
            [[http.request]]
            url = "https://example.com/usage"
            {surface_extra}
            "#
        )
    }

    #[test]
    fn period_unit_defaults_to_minutes_and_reads_seconds_when_declared() {
        assert_eq!(PeriodUnit::default(), PeriodUnit::Minutes);
        assert_eq!(PeriodUnit::Minutes.to_minutes(10080), 10080);
        assert_eq!(PeriodUnit::Seconds.to_minutes(604800), 10080);
        assert_eq!(PeriodUnit::Seconds.to_minutes(18000), 300);
        assert_eq!(
            PeriodUnit::Seconds.to_minutes(30),
            0,
            "half a minute is not a minute"
        );
    }

    #[test]
    fn accepts_several_containers_when_the_period_comes_from_a_field() {
        let toml = http_manifest_with(
            r#"containers = ["rate_limit.primary_window", "rate_limit.secondary_window"]"#,
            "",
            "",
        );
        let m = PluginManifest::from_str(&toml).expect("valid manifest");
        assert_eq!(m.windows[0].source.containers.len(), 2);
        assert_eq!(m.windows[0].period.unit, PeriodUnit::Seconds);
    }

    #[test]
    fn rejects_several_containers_with_an_assumed_period() {
        // Nothing to tell the candidates apart by: caught at load, not at the
        // first network response.
        let toml = http_manifest_with(r#"containers = ["a", "b"]"#, "", "")
            .replace("mode  = \"from_field\"", "mode    = \"assumed\"")
            .replace("field = \"limit_window_seconds\"", "assumed = 300");
        let err = PluginManifest::from_str(&toml).expect_err("must be rejected");
        assert!(
            err.contains("from_field"),
            "error should say what is missing: {err}"
        );
    }

    #[test]
    fn containers_default_to_empty_so_existing_manifests_are_unchanged() {
        let m = PluginManifest::from_str(CLAUDE_LIKE).expect("valid manifest");
        assert!(m.windows.iter().all(|w| w.source.containers.is_empty()));
    }

    #[test]
    fn http_throttle_knobs_have_defaults_and_are_bounds_checked() {
        let m = PluginManifest::from_str(&http_manifest_with("", "", "")).expect("valid manifest");
        let http = m.http.as_ref().unwrap();
        assert_eq!(http.min_interval_secs, 55, "below the 60s default cadence");
        assert_eq!(http.backoff_start_secs, 60);
        assert_eq!(http.backoff_max_secs, 900);

        let bad = http_manifest_with("", "backoff_start_secs = 120\nbackoff_max_secs = 60", "");
        let err =
            PluginManifest::from_str(&bad).expect_err("a ceiling below the floor is nonsense");
        assert!(err.contains("backoff_max_secs"), "unexpected error: {err}");

        let zero = http_manifest_with("", "backoff_start_secs = 0", "");
        assert!(
            PluginManifest::from_str(&zero).is_err(),
            "a zero backoff is a retry storm"
        );
    }

    #[test]
    fn rejects_http_value_entries_that_cannot_be_resolved() {
        let missing_json_path = http_manifest_with(
            "",
            "[[http.value]]\nname = \"account_id\"\ntype = \"json-file\"\npath = \"~/.codex/auth.json\"",
            "",
        );
        let err = PluginManifest::from_str(&missing_json_path).expect_err("must be rejected");
        assert!(err.contains("json_path"), "unexpected error: {err}");

        let bad_name = http_manifest_with(
            "",
            "[[http.value]]\nname = \"acc-id\"\ntype = \"json-file\"\npath = \"p\"\njson_path = \"j\"",
            "",
        );
        let err = PluginManifest::from_str(&bad_name).expect_err("must be rejected");
        assert!(
            err.contains("acc-id"),
            "error should name the offending value: {err}"
        );

        let duplicate = http_manifest_with(
            "",
            "[[http.value]]\nname = \"a\"\ntype = \"json-file\"\npath = \"p\"\njson_path = \"j\"\n\
             [[http.value]]\nname = \"a\"\ntype = \"json-file\"\npath = \"p\"\njson_path = \"j\"",
            "",
        );
        let err = PluginManifest::from_str(&duplicate).expect_err("must be rejected");
        assert!(
            err.contains('a'),
            "error should name the duplicated value: {err}"
        );
    }

    #[test]
    fn rejects_a_reject_when_step_missing_its_required_fields() {
        let toml = http_manifest_with(
            "",
            "",
            "[[surface]]\nid = \"default\"\nlabel = \"Default\"\n\
             [[surface.auth]]\ntype = \"reject-when\"\npath = \"~/.codex/auth.json\"",
        );
        let err = PluginManifest::from_str(&toml).expect_err("must be rejected");
        assert!(err.contains("reject-when"), "unexpected error: {err}");
    }

    #[test]
    fn accepts_a_complete_reject_when_step() {
        let toml = http_manifest_with(
            "",
            "",
            "[[surface]]\nid = \"default\"\nlabel = \"Default\"\n\
             [[surface.auth]]\ntype = \"reject-when\"\npath = \"~/.codex/auth.json\"\n\
             json_path = \"OPENAI_API_KEY\"\nunless_json_path = \"tokens.access_token\"\n\
             message = \"an API key has no subscription limits\"",
        );
        let m = PluginManifest::from_str(&toml).expect("valid manifest");
        assert_eq!(m.surface[0].auth[0].kind, AuthType::RejectWhen);
        assert_eq!(
            m.surface[0].auth[0].unless_json_path.as_deref(),
            Some("tokens.access_token")
        );
    }

    #[test]
    fn a_placeholder_in_a_value_path_is_refused_even_without_a_request() {
        // The check walks every field a placeholder could be written into,
        // and `[[http.value]]`'s own `path` is one of them — read verbatim,
        // so a placeholder there is a directory name with braces in it. It
        // used to be collected inside the loop over `[[http.request]]`, which
        // meant a section that declares values but no request never had them
        // looked at. Nothing shipped is shaped that way; a third-party
        // manifest may be.
        let toml = format!(
            "{CODEX_LIKE}\n[http]\n[[http.value]]\nname = \"a\"\ntype = \"json-file\"\n\
             path = \"~/{{option.where}}/x.json\"\njson_path = \"a\"\n"
        );
        let err = PluginManifest::from_str(&toml).expect_err("a placeholder nothing substitutes");
        assert!(
            err.contains("nothing substitutes there"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn rejects_a_credential_surface_with_no_allowed_hosts() {
        // An empty allow-list means "no restriction", which is the wrong
        // default for a manifest that sends somebody's token somewhere.
        let toml = http_manifest_with(
            "",
            "",
            "[[surface]]\nid = \"cli\"\nlabel = \"CLI\"\n\
             [[surface.auth]]\ntype = \"env\"\nvar = \"TOK\"",
        );
        let err = PluginManifest::from_str(&toml).expect_err("must be rejected");
        assert!(err.contains("allowed_hosts"), "unexpected error: {err}");

        // A surface with no credentials to leak is left alone.
        let no_auth = http_manifest_with("", "", "[[surface]]\nid = \"cli\"\nlabel = \"CLI\"");
        assert!(PluginManifest::from_str(&no_auth).is_ok());
    }

    #[test]
    fn rejects_header_only_placeholders_in_a_url() {
        for (placeholder, expected) in [
            ("{token}", "{token}"),
            ("{version}", "{version}"),
            ("{value.account_id}", "{value.<name>}"),
        ] {
            let toml = http_manifest_with("", "", "").replace(
                "url = \"https://example.com/usage\"",
                &format!("url = \"https://example.com/{placeholder}\""),
            );
            let err = PluginManifest::from_str(&toml)
                .expect_err("a URL naming a header-only placeholder must be rejected");
            assert!(
                err.contains(expected),
                "unexpected error for {placeholder}: {err}"
            );
        }
        // `{option.<key>}` is substituted into URLs and stays allowed — when
        // the manifest declares the key. One that does not is a placeholder
        // nothing will ever replace, and is refused a few lines below.
        let ok = http_manifest_with("", "", "").replace(
            "url = \"https://example.com/usage\"",
            "url = \"https://example.com/{option.eu}\"",
        ) + "\n[[option]]\nkey = \"eu\"\nlabel = \"EU\"\ndefault = false\n";
        assert!(PluginManifest::from_str(&ok).is_ok());
    }

    #[test]
    fn splits_token_json_path_fallback_keys() {
        assert_eq!(
            split_fallback_keys("claudeAiOauth.accessToken|access_token"),
            vec!["claudeAiOauth.accessToken", "access_token"]
        );
        assert_eq!(split_fallback_keys("single.path"), vec!["single.path"]);
        assert_eq!(
            split_fallback_keys("a | b |c"),
            vec!["a", "b", "c"],
            "surrounding whitespace around `|` is trimmed"
        );
    }

    #[test]
    fn load_dir_sorts_by_order_then_id_and_reports_parse_errors_separately() {
        let dir = std::env::temp_dir().join(format!(
            "tickover-manifest-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");

        let write = |name: &str, body: &str| {
            std::fs::write(dir.join(name), body).expect("write fixture manifest");
        };

        let manifest_with = |id: &str, order: i64| {
            format!(
                r#"
                id         = "{id}"
                name       = "{id}"
                menu_label = "{id}"
                order      = {order}
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
                "#
            )
        };

        // Deliberately named so directory-listing order != declared order,
        // to prove load_dir sorts by `order`, not filename.
        write("b_second.toml", &manifest_with("bbb", 20));
        write("a_first.toml", &manifest_with("aaa", 10));
        write("c_broken.toml", "this is not [valid toml");
        write("not-a-manifest.txt", "ignored: wrong extension");
        // Tie on `order` with "aaa" — must break on `id`.
        write("d_tie.toml", &manifest_with("zzz", 10));

        let results = load_dir(&dir);
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(
            results.len(),
            4,
            "the .txt file must be ignored, the 4 .toml files kept"
        );

        let ok_ids: Vec<&str> = results
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|m| m.id.as_str())
            .collect();
        assert_eq!(
            ok_ids,
            vec!["aaa", "zzz", "bbb"],
            "ordered by `order`, ties by `id`"
        );

        let broken = results
            .iter()
            .find_map(|r| r.as_ref().err())
            .expect("the broken manifest should be reported as an error");
        assert!(broken.0.ends_with("c_broken.toml"));
    }

    // ── window identity ─────────────────────────────────────────────────

    /// A manifest with an explicit `id` and an anonymous entry beside it can
    /// collide without ever repeating an `id` — the anonymous one falls back
    /// to `w{index}`, and `w1` is a perfectly legal id for somebody else to
    /// have declared.
    ///
    /// Two voices found this independently, and it walks straight past a check
    /// that only compares declared ids to each other. It is the defect that
    /// check exists to stop: two windows, one identity, one registry entry
    /// between them.
    #[test]
    fn an_explicit_id_cannot_collide_with_the_position_another_entry_falls_back_to() {
        let manifest = |first_id: &str| {
            format!(
                r#"
                id         = "sample"
                name       = "Sample"
                menu_label = "Sa"
                order      = 1
                engine     = "log-file"
                requires_reader = ["window-identity"]

                [[windows]]
                id    = "{first_id}"
                label = "5H"
                role  = "primary"
                [windows.period]
                mode    = "assumed"
                assumed = 300
                [windows.source]
                used_percent_path = "used_percent"
                resets_at_path    = "resets_at"

                [[windows]]
                label = "WK"
                role  = "secondary"
                [windows.period]
                mode    = "assumed"
                assumed = 10080
                [windows.source]
                used_percent_path = "used_percent"
                resets_at_path    = "resets_at"

                [logfile]
                root          = "~/.sample"
                glob          = "*.jsonl"
                container_key = "rate_limits"
                "#
            )
        };

        // `w1` is what the second, anonymous entry resolves to.
        let err = PluginManifest::from_str(&manifest("w1"))
            .expect_err("two windows resolving to one identity must be refused");
        assert!(
            err.contains("same identity"),
            "the refusal must say what collided — {err}"
        );
        assert!(err.contains("w1"), "and name it — {err}");

        // Anything that does not collide is still fine.
        let ok = PluginManifest::from_str(&manifest("five-hour")).expect("no collision");
        assert_eq!(ok.windows[0].entry_key(0), "five-hour");
        assert_eq!(
            ok.windows[1].entry_key(1),
            "w1",
            "the anonymous entry keeps its position"
        );
    }

    /// `[status]` is read by one engine. Accepting it for the other would let a
    /// manifest declare a statement this app never reads — the shape of the
    /// bug where `required` was honoured in one engine and dead in the other.
    #[test]
    fn a_log_file_manifest_may_not_claim_a_status_section() {
        let toml = r#"
            id         = "sample"
            name       = "Sample"
            menu_label = "Sa"
            order      = 1
            engine     = "log-file"
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
            limit_reached_path = "rate_limit.limit_reached"

            [logfile]
            root          = "~/.sample"
            glob          = "*.jsonl"
            container_key = "rate_limits"
        "#;
        let err = PluginManifest::from_str(toml).expect_err("only http-api reads [status]");
        assert!(err.contains("http-api"), "{err}");
    }

    /// A provider that reports no window at all.
    ///
    /// This is not a hypothetical: Grok's billing endpoint carries no window
    /// key in either of the two shapes it answers with (measured against its
    /// live response), only a monthly period. Until this test passed, such a
    /// provider could not be written as a plugin — `validate` required a
    /// window — which is the one thing "every AI arrives as a plugin" rules
    /// out.
    const BALANCES_ONLY: &str = r#"
        id           = "sample"
        name         = "Sample"
        menu_label   = "Sa"
        order        = 30
        engine       = "http-api"
        requires_reader = ["reading-balances"]

        [[balances]]
        id    = "monthly"
        label = "Month"
        [balances.used]
        kind = "number"
        path = "config.used.val"
        unit_label = "credits"
        [balances.cap]
        kind = "number"
        path = "config.monthlyLimit.val"
        [balances.source]
        period_end_path   = "config.billingPeriodEnd"
        period_end_format = "iso8601"

        [http]
        [[http.request]]
        url = "https://example.com/billing"

        [[surface]]
        id            = "default"
        label         = "Default"
        allowed_hosts = ["example.com"]
        [[surface.auth]]
        type            = "credentials-file"
        path            = "~/.sample/auth.json"
        token_json_path = "token"
    "#;

    #[test]
    fn a_manifest_with_balances_and_no_windows_is_accepted() {
        let m = PluginManifest::from_str(BALANCES_ONLY).expect("balances alone are a provider");
        assert!(m.windows.is_empty());
        assert_eq!(m.balances.len(), 1);
        assert_eq!(m.balances[0].entry_key(0), "monthly");
        assert_eq!(
            m.balances[0].used.as_ref().unwrap().kind,
            AmountKind::Number
        );
        assert_eq!(
            m.balances[0].source.period_end_format,
            ResetsAtFormat::Iso8601
        );
    }

    #[test]
    fn balances_need_the_reader_capability_to_be_declared() {
        // Without the declaration an older build would load this manifest,
        // ignore the section it cannot read, and draw a provider that reported
        // nothing — while the provider was answering perfectly well. The
        // capability gate is what turns that into a refusal the author sees.
        let undeclared = BALANCES_ONLY.replace("requires_reader = [\"reading-balances\"]", "");
        let err = PluginManifest::from_str(&undeclared)
            .expect_err("a section this build reads has to be declared");
        assert!(err.contains("reading-balances"), "{err}");
    }

    #[test]
    fn an_entry_without_an_id_falls_back_to_a_position_that_cannot_collide_with_a_window() {
        let m = PluginManifest::from_str(&BALANCES_ONLY.replace("id    = \"monthly\"\n", ""))
            .expect("an id is optional");
        // `b0`, not `w0`: a balance and a window at the same index are two
        // different rows, and one registry key for both would file them
        // together the first time an entry drops its `id`.
        assert_eq!(m.balances[0].entry_key(0), "b0");
    }

    // ── http POST + body ────────────────────────────────────────────────

    /// A minimal `http-api` manifest, `method`/`body` left to their defaults
    /// — the base every test below edits one line of.
    const HTTP_POST_BASE: &str = r#"
        id         = "sample"
        name       = "Sample"
        menu_label = "Sa"
        order      = 1
        engine     = "http-api"
        requires_reader = ["http-post"]

        [[windows]]
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
        url = "https://example.com/v1internal:retrieveUserQuotaSummary"
        [http.request.headers]
        Authorization  = "Bearer {token}"
        "Content-Type" = "application/json"
    "#;

    #[test]
    fn parses_a_post_request_with_a_substituted_body() {
        // Google's `:verb` HTTP-transcoding convention (Antigravity's shape)
        // is POST-only, and the body carries the same placeholders a header
        // would. Not JSON-shaped on purpose: a body opening with `{` is a
        // separate rule (`a_body_naming_a_value_nothing_declares_is_refused`'s
        // neighbour below, `a_json_shaped_body_swallows_its_own_placeholder`)
        // — this test is about `method`/`body` parsing into the struct, not
        // about that one.
        let toml = HTTP_POST_BASE.replace(
            "url = \"https://example.com/v1internal:retrieveUserQuotaSummary\"",
            "url    = \"https://example.com/v1internal:retrieveUserQuotaSummary\"\n\
             method = \"post\"\n\
             body   = \"pluginType=gemini&auth=Bearer {token}\"",
        );
        let m = PluginManifest::from_str(&toml).expect("valid manifest");
        let req = &m.http.as_ref().unwrap().request[0];
        assert_eq!(req.method, HttpMethod::Post);
        assert_eq!(
            req.body.as_deref(),
            Some("pluginType=gemini&auth=Bearer {token}")
        );
    }

    #[test]
    fn method_defaults_to_get_and_body_defaults_to_none() {
        let m = PluginManifest::from_str(CLAUDE_LIKE).expect("valid manifest");
        let req = &m.http.as_ref().unwrap().request[0];
        assert_eq!(req.method, HttpMethod::Get);
        assert!(req.body.is_none());
    }

    #[test]
    fn a_get_request_may_not_declare_a_body() {
        let toml = HTTP_POST_BASE.replace(
            "url = \"https://example.com/v1internal:retrieveUserQuotaSummary\"",
            "url  = \"https://example.com/v1internal:retrieveUserQuotaSummary\"\nbody = \"x\"",
        );
        let err = PluginManifest::from_str(&toml).expect_err("a GET has nowhere to put a body");
        assert!(err.contains("method = \"post\""), "{err}");
    }

    #[test]
    fn a_post_request_with_no_body_is_a_complete_request() {
        // Not required to spell out `body = ""`: arguments in the URL and
        // credentials in the headers can be the whole request.
        let toml = HTTP_POST_BASE.replace(
            "url = \"https://example.com/v1internal:retrieveUserQuotaSummary\"",
            "url    = \"https://example.com/v1internal:retrieveUserQuotaSummary\"\nmethod = \"post\"",
        );
        let m = PluginManifest::from_str(&toml).expect("a POST with no body is legal");
        assert!(m.http.as_ref().unwrap().request[0].body.is_none());
    }

    #[test]
    fn a_body_naming_a_value_nothing_declares_is_refused() {
        // The same "undeclared placeholder" rule headers already obey — body
        // reuses the header-substitution set (`Substituted::ValuesAndOptions`)
        // rather than getting a rule of its own.
        let toml = HTTP_POST_BASE.replace(
            "url = \"https://example.com/v1internal:retrieveUserQuotaSummary\"",
            "url    = \"https://example.com/v1internal:retrieveUserQuotaSummary\"\n\
             method = \"post\"\n\
             body   = \"acc={value.account_id}\"",
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("an undeclared {value.…} in the body must be refused");
        assert!(err.contains("{value.account_id}"), "{err}");
    }

    #[test]
    fn a_json_shaped_body_swallows_its_own_placeholder() {
        // The failure this rule exists for: the body's own leading `{`
        // pairs, in the naive one-pass scan, with `{token}`'s closing brace
        // — not with the object's real, later end — so `{token}` is never
        // recognised as a placeholder at all and would be sent on the wire
        // exactly as written. Neither `method`/`body` parsing above nor the
        // undeclared-placeholder rule sees this; only `body_swallows_a_placeholder`
        // does (see its doc comment for why).
        let toml = HTTP_POST_BASE.replace(
            "url = \"https://example.com/v1internal:retrieveUserQuotaSummary\"",
            "url    = \"https://example.com/v1internal:retrieveUserQuotaSummary\"\n\
             method = \"post\"\n\
             body   = \"{\\\"auth\\\":\\\"{token}\\\"}\"",
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("a JSON-shaped body swallows its own placeholder");
        assert!(err.contains("{token}"), "{err}");
        assert!(
            err.contains("pairs with"),
            "the refusal must explain why — {err}"
        );
    }

    // ── remaining-fraction window ───────────────────────────────────────

    /// The base for the remaining-fraction rows: one http-api window whose
    /// figure comes from a remaining fraction, `remaining-fraction` declared.
    const REMAINING_BASE: &str = r#"
        id         = "sample"
        name       = "Sample"
        menu_label = "Sa"
        order      = 1
        engine     = "http-api"
        requires_reader = ["remaining-fraction"]

        [[windows]]
        label = "5H"
        role  = "primary"
        [windows.period]
        mode    = "assumed"
        assumed = 300
        [windows.source]
        remaining_fraction_path = "groups.0.buckets.0.remainingFraction"
        resets_at_path          = "groups.0.buckets.0.resetTime"
        resets_at_format        = "iso8601"

        [http]
        [[http.request]]
        url = "https://example.com/usage"
        [http.request.headers]
        Authorization = "Bearer {token}"
    "#;

    #[test]
    fn parses_a_window_that_states_a_remaining_fraction() {
        let m = PluginManifest::from_str(REMAINING_BASE).expect("valid manifest");
        let src = &m.windows[0].source;
        assert_eq!(
            src.remaining_fraction_path.as_deref(),
            Some("groups.0.buckets.0.remainingFraction")
        );
        assert!(src.used_percent_path.is_none());
    }

    #[test]
    fn a_window_may_not_state_both_a_used_percent_and_a_remaining_fraction() {
        let toml = REMAINING_BASE.replace(
            "remaining_fraction_path = \"groups.0.buckets.0.remainingFraction\"",
            "remaining_fraction_path = \"groups.0.buckets.0.remainingFraction\"\n\
             used_percent_path       = \"groups.0.buckets.0.used\"",
        );
        let err = PluginManifest::from_str(&toml).expect_err("two figure paths is ambiguous");
        assert!(err.contains("name only one"), "{err}");
    }

    #[test]
    fn an_http_window_that_states_no_figure_at_all_is_refused() {
        let toml = REMAINING_BASE
            .replace(
                "remaining_fraction_path = \"groups.0.buckets.0.remainingFraction\"\n",
                "",
            )
            .replace("requires_reader = [\"remaining-fraction\"]", "");
        let err =
            PluginManifest::from_str(&toml).expect_err("a window with no figure shows nothing");
        assert!(err.contains("no figure to show"), "{err}");
    }

    #[test]
    fn a_remaining_fraction_window_must_declare_the_reader() {
        let toml = REMAINING_BASE.replace("requires_reader = [\"remaining-fraction\"]", "");
        let err = PluginManifest::from_str(&toml)
            .expect_err("using remaining_fraction_path without declaring the reader is refused");
        assert!(err.contains("remaining-fraction"), "{err}");
    }

    // ── keychain-expiry ─────────────────────────────────────────────────

    /// A keychain auth step that names an expiry — the Antigravity hybrid's
    /// shape, `keychain-expiry` declared.
    const KEYCHAIN_EXPIRY_BASE: &str = r#"
        id         = "sample"
        name       = "Sample"
        menu_label = "Sa"
        order      = 1
        engine     = "http-api"
        requires_reader = ["keychain-expiry"]

        [[windows]]
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
        [http.request.headers]
        Authorization = "Bearer {token}"

        [[surface]]
        id            = "default"
        label         = "Default"
        allowed_hosts = ["example.com"]
        [[surface.auth]]
        type            = "keychain"
        service         = "gemini"
        token_json_path = "token.access_token"
        expiry_json_path = "token.expiry"
    "#;

    #[test]
    fn parses_a_keychain_step_with_an_expiry_path() {
        let m = PluginManifest::from_str(KEYCHAIN_EXPIRY_BASE).expect("valid manifest");
        assert_eq!(
            m.surface[0].auth[0].expiry_json_path.as_deref(),
            Some("token.expiry")
        );
    }

    #[test]
    fn a_keychain_expiry_step_must_declare_the_reader() {
        let toml = KEYCHAIN_EXPIRY_BASE.replace("requires_reader = [\"keychain-expiry\"]", "");
        let err = PluginManifest::from_str(&toml)
            .expect_err("using expiry_json_path without declaring the reader is refused");
        assert!(err.contains("keychain-expiry"), "{err}");
    }

    // ── oauth-refresh auth step ─────────────────────────────────────────

    /// A manifest with one `oauth-refresh` surface — the shape the Antigravity
    /// hybrid's fallback reads through.
    const OAUTH_REFRESH_BASE: &str = r#"
        id         = "sample"
        name       = "Sample"
        menu_label = "Sa"
        order      = 1
        engine     = "http-api"
        requires_reader = ["oauth-refresh"]

        [[windows]]
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
        [http.request.headers]
        Authorization = "Bearer {token}"

        [[surface]]
        id            = "default"
        label         = "Default"
        allowed_hosts = ["example.com", "oauth2.googleapis.com"]
        [[surface.auth]]
        type            = "oauth-refresh"
        path            = "~/.gemini/oauth_creds.json"
        token_json_path = "refresh_token"
        token_url       = "https://oauth2.googleapis.com/token"
        client_id       = "some-client-id.apps.googleusercontent.com"
        client_secret   = "some-client-secret"
    "#;

    #[test]
    fn parses_an_oauth_refresh_auth_step() {
        let m = PluginManifest::from_str(OAUTH_REFRESH_BASE).expect("valid manifest");
        let step = &m.surface[0].auth[0];
        assert_eq!(step.kind, AuthType::OauthRefresh);
        assert_eq!(step.path.as_deref(), Some("~/.gemini/oauth_creds.json"));
        assert_eq!(step.token_json_path.as_deref(), Some("refresh_token"));
        assert_eq!(
            step.token_url.as_deref(),
            Some("https://oauth2.googleapis.com/token")
        );
        assert_eq!(step.client_secret.as_deref(), Some("some-client-secret"));
    }

    #[test]
    fn an_oauth_refresh_step_declares_what_it_needs() {
        let toml = OAUTH_REFRESH_BASE.replace(
            "token_url       = \"https://oauth2.googleapis.com/token\"\n",
            "",
        );
        let err = PluginManifest::from_str(&toml).expect_err("token_url is required");
        assert!(err.contains("token_url"), "{err}");
    }

    #[test]
    fn an_oauth_refresh_field_present_and_blank_is_refused() {
        let toml = OAUTH_REFRESH_BASE.replace(
            "client_secret   = \"some-client-secret\"",
            "client_secret   = \"   \"",
        );
        let err = PluginManifest::from_str(&toml).expect_err("a blank client_secret is not one");
        assert!(err.contains("client_secret"), "{err}");
    }

    #[test]
    fn an_oauth_refresh_step_must_declare_the_reader() {
        let toml = OAUTH_REFRESH_BASE.replace("requires_reader = [\"oauth-refresh\"]", "");
        let err = PluginManifest::from_str(&toml)
            .expect_err("using oauth-refresh without declaring the reader is refused");
        assert!(err.contains("oauth-refresh"), "{err}");
    }

    #[test]
    fn an_oauth_refresh_step_without_either_the_literal_pair_or_a_client_table_is_refused() {
        // What the rule used to be, unconditionally: `client_id`/`client_secret`
        // were always required. Now it is "one or the other" — this is the
        // "neither" case, and the field named is still `client_id`, the first
        // one the missing-fields table checks.
        let toml = OAUTH_REFRESH_BASE
            .replace(
                "client_id       = \"some-client-id.apps.googleusercontent.com\"\n",
                "",
            )
            .replace("client_secret   = \"some-client-secret\"\n", "");
        let err = PluginManifest::from_str(&toml)
            .expect_err("neither a literal pair nor a client table is refused");
        assert!(err.contains("client_id"), "{err}");
    }

    // ── oauth-refresh's `[surface.auth.client]` discovery table ──────────

    /// [`OAUTH_REFRESH_BASE`] with the installed-app pair read from
    /// `[surface.auth.client]` discovery instead of the literal `client_id`/
    /// `client_secret` fields — the shape the shipped Antigravity manifest
    /// uses now.
    const OAUTH_REFRESH_CLIENT_BASE: &str = r#"
        id         = "sample"
        name       = "Sample"
        menu_label = "Sa"
        order      = 1
        engine     = "http-api"
        requires_reader = ["oauth-refresh", "oauth-client-discovery"]

        [[windows]]
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
        [http.request.headers]
        Authorization = "Bearer {token}"

        [[surface]]
        id            = "default"
        label         = "Default"
        allowed_hosts = ["example.com", "oauth2.googleapis.com"]
        [[surface.auth]]
        type            = "oauth-refresh"
        path            = "~/.gemini/oauth_creds.json"
        token_json_path = "refresh_token"
        token_url       = "https://oauth2.googleapis.com/token"
        [surface.auth.client]
        id_env         = "SAMPLE_CLIENT_ID"
        secret_env     = "SAMPLE_CLIENT_SECRET"
        id_pattern     = "[0-9]{1,20}-[a-z0-9]{1,40}\\.apps\\.googleusercontent\\.com"
        secret_pattern = "GOCSPX-[A-Za-z0-9_-]{28}"
        files          = ["~/.sample/client-binary"]
        bins           = ["sample-cli"]
    "#;

    #[test]
    fn parses_an_oauth_refresh_client_discovery_table() {
        let m = PluginManifest::from_str(OAUTH_REFRESH_CLIENT_BASE).expect("valid manifest");
        let step = &m.surface[0].auth[0];
        assert!(
            step.client_id.is_none() && step.client_secret.is_none(),
            "no literal pair needed"
        );
        let client = step.client.as_ref().expect("a client table");
        assert_eq!(client.id_env.as_deref(), Some("SAMPLE_CLIENT_ID"));
        assert_eq!(client.secret_env.as_deref(), Some("SAMPLE_CLIENT_SECRET"));
        assert_eq!(
            client.id_pattern.as_deref(),
            Some("[0-9]{1,20}-[a-z0-9]{1,40}\\.apps\\.googleusercontent\\.com")
        );
        assert_eq!(
            client.secret_pattern.as_deref(),
            Some("GOCSPX-[A-Za-z0-9_-]{28}")
        );
        assert_eq!(client.files, vec!["~/.sample/client-binary".to_string()]);
        assert_eq!(client.bins, vec!["sample-cli".to_string()]);
    }

    #[test]
    fn a_client_table_on_a_non_oauth_refresh_step_is_refused() {
        let toml = OAUTH_REFRESH_CLIENT_BASE.replace(
            "type            = \"oauth-refresh\"",
            "type            = \"env\"\n        var             = \"SAMPLE_TOKEN\"",
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("a client table only makes sense on an oauth-refresh step");
        assert!(err.contains("oauth-refresh"), "{err}");
    }

    #[test]
    fn a_client_pattern_that_does_not_compile_is_refused() {
        let toml = OAUTH_REFRESH_CLIENT_BASE.replace(
            r#"id_pattern     = "[0-9]{1,20}-[a-z0-9]{1,40}\\.apps\\.googleusercontent\\.com""#,
            r#"id_pattern     = "[0-9""#,
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("an id_pattern that does not compile as a regex is refused");
        assert!(err.contains("id_pattern"), "{err}");
    }

    #[test]
    fn a_client_files_entry_that_is_blank_is_refused() {
        let toml = OAUTH_REFRESH_CLIENT_BASE.replace(
            r#"files          = ["~/.sample/client-binary"]"#,
            r#"files          = ["   "]"#,
        );
        let err = PluginManifest::from_str(&toml).expect_err("a blank files entry is refused");
        assert!(err.contains("files"), "{err}");
    }

    #[test]
    fn a_client_table_naming_neither_files_nor_bins_and_no_env_pair_is_refused() {
        let toml = OAUTH_REFRESH_CLIENT_BASE
            .replace(
                "id_env         = \"SAMPLE_CLIENT_ID\"\n        secret_env     = \"SAMPLE_CLIENT_SECRET\"\n        ",
                "",
            )
            .replace(r#"files          = ["~/.sample/client-binary"]"#, "")
            .replace(r#"bins           = ["sample-cli"]"#, "");
        let err = PluginManifest::from_str(&toml)
            .expect_err("nothing to search and no env pair to skip searching for is refused");
        assert!(err.contains("files") && err.contains("bins"), "{err}");
    }

    #[test]
    fn an_oauth_refresh_client_fields_present_and_blank_is_refused() {
        let toml = OAUTH_REFRESH_CLIENT_BASE.replace(
            r#"id_pattern     = "[0-9]{1,20}-[a-z0-9]{1,40}\\.apps\\.googleusercontent\\.com""#,
            r#"id_pattern     = "   ""#,
        );
        let err = PluginManifest::from_str(&toml).expect_err("a blank id_pattern is not one");
        assert!(err.contains("client.id_pattern"), "{err}");
    }

    #[test]
    fn an_oauth_refresh_client_table_must_declare_the_reader() {
        let toml = OAUTH_REFRESH_CLIENT_BASE.replace(
            "requires_reader = [\"oauth-refresh\", \"oauth-client-discovery\"]",
            "requires_reader = [\"oauth-refresh\"]",
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("using a client table without declaring the reader is refused");
        assert!(err.contains("oauth-client-discovery"), "{err}");
    }

    #[test]
    fn a_client_bins_entry_shaped_like_a_path_is_refused() {
        for bad in [
            "/etc/passwd",
            "../../x",
            "sub/dir",
            "a\\b",
            "C:\\Windows\\System32\\cmd.exe",
        ] {
            let toml = OAUTH_REFRESH_CLIENT_BASE.replace(
                r#"bins           = ["sample-cli"]"#,
                &format!("bins           = [{bad:?}]"),
            );
            let err = PluginManifest::from_str(&toml).expect_err(&format!(
                "a bins entry shaped like a path must be refused: {bad:?}"
            ));
            assert!(err.contains(bad), "{err}");
        }
    }

    #[test]
    fn a_client_env_name_outside_the_variable_charset_is_refused() {
        let toml = OAUTH_REFRESH_CLIENT_BASE.replace(
            r#"id_env         = "SAMPLE_CLIENT_ID""#,
            r#"id_env         = "SAMPLE-CLIENT-ID""#,
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("a hyphen is not a valid environment variable name character");
        assert!(err.contains("client.id_env"), "{err}");
    }

    #[test]
    fn a_client_id_env_set_without_secret_env_is_refused() {
        let toml = OAUTH_REFRESH_CLIENT_BASE
            .replace("secret_env     = \"SAMPLE_CLIENT_SECRET\"\n        ", "");
        let err = PluginManifest::from_str(&toml)
            .expect_err("id_env without a matching secret_env is refused, not a partial override");
        assert!(err.contains("id_env"), "{err}");
    }

    #[test]
    fn a_client_secret_env_set_without_id_env_is_refused() {
        let toml = OAUTH_REFRESH_CLIENT_BASE
            .replace("id_env         = \"SAMPLE_CLIENT_ID\"\n        ", "");
        let err = PluginManifest::from_str(&toml)
            .expect_err("secret_env without a matching id_env is refused, not a partial override");
        assert!(err.contains("id_env"), "{err}");
    }

    #[test]
    fn a_client_files_entry_that_is_relative_is_refused() {
        let toml = OAUTH_REFRESH_CLIENT_BASE.replace(
            r#"files          = ["~/.sample/client-binary"]"#,
            r#"files          = ["relative/client-binary"]"#,
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("a relative files entry resolves against whatever directory this process happens to run from, which is refused");
        assert!(err.contains("client.files"), "{err}");
    }

    #[test]
    fn a_client_files_entry_shaped_like_a_posix_path_is_accepted_on_every_platform() {
        // The bug this fixes: the shipped Antigravity manifest's own
        // `/Applications/…` entry — this exact shape — used to be refused
        // by `Path::is_absolute()` on Windows, which wants a drive letter or
        // a UNC prefix instead. A macOS-only candidate on a Windows machine
        // should simply not exist at discovery time, not fail to load the
        // manifest — on every platform, not only the one that wrote it.
        let toml = OAUTH_REFRESH_CLIENT_BASE.replace(
            r#"files          = ["~/.sample/client-binary"]"#,
            r#"files          = ["/Applications/Sample.app/Contents/MacOS/sample"]"#,
        );
        PluginManifest::from_str(&toml)
            .expect("a POSIX absolute path must be accepted on every platform");
    }

    #[test]
    fn is_absolute_on_any_platform_accepts_posix_and_refuses_relative_regardless_of_the_running_platform(
    ) {
        assert!(is_absolute_on_any_platform(Path::new("/Applications/x")));
        assert!(!is_absolute_on_any_platform(Path::new("relative/x")));
        assert!(!is_absolute_on_any_platform(Path::new("x")));
    }

    #[test]
    fn a_client_table_with_an_unknown_field_is_refused_at_parse_time() {
        // Unlike the rest of this manifest format (deliberately
        // forward-compatible — see `PluginManifest`'s own doc), `client` is
        // `#[serde(deny_unknown_fields)]`: `files`, `bins` and `id_env` are
        // exactly what the trust dialog shows before installing anything,
        // and a typo here must not silently disable a candidate list or an
        // override.
        let toml = OAUTH_REFRESH_CLIENT_BASE.replace(
            r#"files          = ["~/.sample/client-binary"]"#,
            r#"fils           = ["~/.sample/client-binary"]"#,
        );
        PluginManifest::from_str(&toml)
            .expect_err("a typo'd field name in `client` must be refused, not silently ignored");
    }

    #[test]
    fn a_client_pattern_with_no_bound_on_its_match_length_is_refused() {
        let toml = OAUTH_REFRESH_CLIENT_BASE.replace(
            r#"id_pattern     = "[0-9]{1,20}-[a-z0-9]{1,40}\\.apps\\.googleusercontent\\.com""#,
            r#"id_pattern     = "(?s).*""#,
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("an unbounded pattern could read an unbounded slice of the file");
        assert!(err.contains("id_pattern"), "{err}");

        let toml = OAUTH_REFRESH_CLIENT_BASE.replace(
            r#"secret_pattern = "GOCSPX-[A-Za-z0-9_-]{28}""#,
            r#"secret_pattern = "GOCSPX-[A-Za-z0-9_-]+""#,
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("an unbounded quantifier is still unbounded");
        assert!(err.contains("secret_pattern"), "{err}");

        // And a pattern that *is* bounded, just too generously, is refused
        // the same way — the bound is on the match, not on whether the
        // author remembered a `{m,n}` at all.
        let toml = OAUTH_REFRESH_CLIENT_BASE.replace(
            r#"secret_pattern = "GOCSPX-[A-Za-z0-9_-]{28}""#,
            r#"secret_pattern = "GOCSPX-[A-Za-z0-9_-]{300}""#,
        );
        let err = PluginManifest::from_str(&toml).expect_err("300 bytes is still over the bound");
        assert!(err.contains("secret_pattern"), "{err}");
    }

    #[test]
    fn a_client_pattern_that_can_match_the_empty_string_is_refused() {
        // Bounded above (`{0,5}` is a finite, 5-byte match) is not bounded
        // below: it can also match zero bytes, which `auth::discover_client`
        // would otherwise hand to the OAuth exchange as a client id of `""`.
        let toml = OAUTH_REFRESH_CLIENT_BASE.replace(
            r#"id_pattern     = "[0-9]{1,20}-[a-z0-9]{1,40}\\.apps\\.googleusercontent\\.com""#,
            r#"id_pattern     = "[0-9]{0,5}""#,
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("a pattern that can match the empty string is refused");
        assert!(err.contains("id_pattern"), "{err}");
    }

    #[test]
    fn a_client_pattern_longer_than_the_text_limit_is_refused() {
        // A compact match bound (the previous test's `{0,5}` is 6 bytes of
        // source) says nothing about how long the pattern's own text is —
        // thousands of fixed-length alternatives could match well within
        // `CLIENT_PATTERN_MAX_MATCH_BYTES` while running to kilobytes of
        // source, which is exactly what the trust dialog would have to
        // render.
        let toml = OAUTH_REFRESH_CLIENT_BASE.replace(
            r#"id_pattern     = "[0-9]{1,20}-[a-z0-9]{1,40}\\.apps\\.googleusercontent\\.com""#,
            &format!(r#"id_pattern     = "{}""#, "1".repeat(520)),
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("520 bytes of pattern text is over the 512-byte limit");
        assert!(err.contains("id_pattern"), "{err}");
    }

    #[test]
    fn a_client_step_with_both_the_literal_pair_and_a_client_table_is_refused() {
        let toml = OAUTH_REFRESH_CLIENT_BASE.replace(
            "token_url       = \"https://oauth2.googleapis.com/token\"",
            "token_url       = \"https://oauth2.googleapis.com/token\"\n        client_id       = \"literal-id\"\n        client_secret   = \"literal-secret\"",
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("client_id/client_secret and a client table together is ambiguous");
        assert!(err.contains("client_id"), "{err}");
    }
}
