//! The provider plugin manifest: a per-provider TOML file that describes how
//! to read its usage windows without a dedicated Rust module.
//!
//! This schema is a **stable, additive contract**: the engines
//! ([`crate::plugin::engine_logfile`], [`crate::plugin::engine_http`]) and the
//! credential chain ([`crate::plugin::auth`]) are built against the types
//! here, and it grows only by adding new optional fields.
//! `#[serde(deny_unknown_fields)]` is deliberately **not** used, with one
//! exception ([`AuthClientDiscovery`], `[surface.auth.client]` — see its own
//! doc for why): a manifest field a future version of this reader doesn't
//! know about yet must be ignored, not rejected.
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
//! type       = "jwt-file"           # "none" (default) | "jwt-file" | "http" | "response-field"
//! path       = "~/.codex/auth.json"
//! token_path = "tokens.id_token"
//! claim      = "email"
//!
//! [[windows]]
//! label = "5H"
//! role  = "primary"                 # | "secondary" | "extra"
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
    /// this month). Empty for a provider that reports only windows — one of
    /// the five shipped manifests today (`antigravity`); the other four
    /// (`claude`, `codex`, `copilot`, `grok`) declare at least one, and
    /// `copilot` alone declares no `[[windows]]` at all.
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

/// Floor for `refresh_secs`, checked by `validate`. Below this a poll is not
/// "fresher", it is a loop against a local file or somebody else's API.
const MIN_REFRESH_SECS: u64 = 5;

/// Ceiling for `refresh_secs`. A day above the slowest shipped cadence
/// (Copilot's 300s), not a figure tuned to any one provider.
const MAX_REFRESH_SECS: u64 = 86_400;

/// Floor for a `[[windows]] period.assumed`, in minutes — `validate`'s own
/// call site explains why: the shortest real window shipped is 300 minutes,
/// and this only exists to stop a much smaller number reaching
/// `main.rs`'s ping arithmetic.
const MIN_ASSUMED_PERIOD_MINUTES: u64 = 5;

/// Ceiling shared by `[http] unauthorized_retry_secs` and
/// `[http] backoff_max_secs` — a week. Both are cool-offs after a failure,
/// and both fail the same way above this: a manifest naming a much larger
/// value (or the field's own unsigned maximum) turns "back off, then try
/// again" into "never try again", indistinguishable in practice from the
/// surface simply having stopped working.
const MAX_HTTP_COOLDOWN_SECS: u64 = 7 * 24 * 60 * 60;

/// Ceiling for `[[http.request]] timeout_secs` — two minutes, far past
/// anything a provider this app talks to has taken to answer. A manifest
/// asking for longer holds the fetch thread (and `main.rs`'s `FetchGuard`)
/// on one slow request instead of failing it and backing off.
const MAX_TIMEOUT_SECS: u64 = 120;

/// Cap on `name`, the popup's section header — plenty for "Antigravity", the
/// longest shipped, with room for a third party's longer one.
const NAME_MAX_CHARS: usize = 64;

/// Cap on `menu_label`, the menu-bar pill — every shipped one is two
/// characters ("Cx", "Cl", "Cp", "Gk", "Ag"); 16 is headroom, not a fit.
const MENU_LABEL_MAX_CHARS: usize = 16;

/// Cap on `windows[].label`, `balances[].label`, `surface[].label` and
/// `option[].label` — a row caption drawn on a card with `wrap: word-wrap`
/// (`ui/app.slint`), not a paragraph. Between [`MENU_LABEL_MAX_CHARS`] (a
/// pill, sized to a couple of characters) and [`NAME_MAX_CHARS`] (a section
/// header, 64): a row caption sits beside a figure rather than above a whole
/// section, so it gets more room than the pill and less than the header —
/// wide enough for a legitimate label in any of the four places while
/// bounding how far a hostile one can grow the card it lands in.
const LABEL_MAX_CHARS: usize = 120;

/// Cap on `[[balances]] used/cap/remaining unit_label` — appended after a
/// number (`credits`, `interactions`), not a caption of its own, so it gets
/// a quarter of [`LABEL_MAX_CHARS`] rather than the same room.
const UNIT_LABEL_MAX_CHARS: usize = 32;

// Count caps on every array a manifest can declare — none tuned to any one
// provider, all far past what one has ever needed (the largest shipped,
// Antigravity's four windows and two surfaces, sits well under every figure
// here). Two reasons to have them at all: `validate` walks several of these
// arrays against themselves looking for a colliding identity (an O(n²)
// comparison — see the `[[windows]]`/`[[balances]]` identity checks), and a
// third-party manifest with hundreds of entries in any of them is a
// manifest reporting a "quota" no real provider has, not a plugin author's
// honest mistake.
const WINDOWS_MAX_COUNT: usize = 32;
const BALANCES_MAX_COUNT: usize = 16;
const OPTIONS_MAX_COUNT: usize = 32;
const HTTP_VALUES_MAX_COUNT: usize = 32;
const SURFACES_MAX_COUNT: usize = 8;
const CLIENT_FILES_MAX_COUNT: usize = 16;
const CLIENT_BINS_MAX_COUNT: usize = 8;
const SOURCE_CONTAINERS_MAX_COUNT: usize = 8;

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
        // document being valid TOML; what the first pass cannot see is
        // whether the document's *shape* matches this struct — a field
        // holding a table where a string is expected, say — so a failure
        // here gets its own message rather than the syntax one above, which
        // would tell an author to look for a typo a syntax checker would
        // have caught, when what actually needs fixing is a field's type.
        let mut manifest: PluginManifest = toml::from_str(input)
            .map_err(|e| format!("manifest TOML has a field of the wrong shape or type: {e}"))?;
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
        // Each `validate_*` fn below covers one contiguous run of checks, in
        // the exact order they run in here — none of them reorders a single
        // check, so which error a given manifest gets back stays fixed
        // purely by this sequence. A few names cover more than their
        // label alone (`validate_windows` closes with `[status]`, since that
        // section sits between two runs of window checks in the original text;
        // `[tag]` sits between two runs of window-period checks and gets its
        // own fn rather than stretching either neighbour's name to cover it).
        self.validate_identity()?;
        self.validate_engine_sections()?;
        self.validate_windows()?;
        self.validate_balances()?;
        self.validate_window_period_mode()?;
        self.validate_tag()?;
        self.validate_window_period_bounds()?;
        self.validate_account_and_surface_auth()?;
        self.validate_http()?;
        self.validate_auth()?;
        self.validate_account_ping_options()?;
        self.validate_templates()?;
        Ok(())
    }

    fn validate_identity(&self) -> Result<(), String> {
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
        // The charset above admits every one of Windows's reserved device
        // names — none of `CON`, `NUL`, `COM1`, `LPT1`… uses a character
        // outside `[A-Za-z0-9_-]`. `<id>.toml` named exactly one of them
        // resolves to the device, not a file, on that platform, whatever
        // extension follows: `find_plugin_manifest_path` would seek a file
        // that can never be opened for writing, and a plugin manager on
        // Windows offering to create it would hang or fail on the device
        // instead.
        if is_windows_reserved_device_name(&self.id) {
            return Err(format!(
                "`id = \"{}\"` is a reserved device name on Windows (CON/PRN/AUX/NUL/COM1-9/LPT1-9) \
                 — `<id>.toml` would name the device, not a file, on that platform",
                self.id
            ));
        }
        if self.name.trim().is_empty() {
            return Err("`name` must not be empty".to_string());
        }
        // `name` is the popup's section header — sized to fit that role, not
        // to carry a sentence. Uncapped, a provider whose manifest is a
        // third-party (not necessarily malicious) mistake could size the
        // panel around one string.
        if self.name.chars().count() > NAME_MAX_CHARS {
            return Err(format!(
                "`name` is {} characters — {NAME_MAX_CHARS} is the cap for a section header",
                self.name.chars().count()
            ));
        }
        if self.menu_label.trim().is_empty() {
            return Err("`menu_label` must not be empty".to_string());
        }
        // `menu_label` sizes the menu-bar pill — every shipped one is two
        // characters ("Cx", "Cl", "Cp") — and that allocation, unlike
        // `name`'s, runs on `main.rs`'s own layout code every tick, not once
        // per open of the popup.
        if self.menu_label.chars().count() > MENU_LABEL_MAX_CHARS {
            return Err(format!(
                "`menu_label` is {} characters — {MENU_LABEL_MAX_CHARS} is the cap for the \
                 menu-bar pill",
                self.menu_label.chars().count()
            ));
        }

        // `[[surface]] id` becomes the reading id every engine builds a
        // `ProviderReading` from (`engine_http`/`engine_logfile`'s own
        // `surface_reading_id`: the plugin's own `id` verbatim for
        // `"default"`, `"{plugin.id}-{surface.id}"` otherwise) — the same
        // identity `throttle::key` paces by and `main.rs` files a panel row
        // under. The charset mirrors the plugin `id` check above, for the
        // same filename-stem/config-key reasons that one exists for
        // (`throttle::key` and a future per-surface config setting would
        // both make this a dotted-path segment); uniqueness matters more
        // here than there, since two surfaces sharing an id resolve to one
        // reading, with one silently standing in for two accounts.
        if self.surface.len() > SURFACES_MAX_COUNT {
            return Err(format!(
                "`[[surface]]` names {} entries — at most {SURFACES_MAX_COUNT}",
                self.surface.len()
            ));
        }
        let mut seen_surface_ids: std::collections::HashSet<&str> =
            std::collections::HashSet::new();
        for surface in &self.surface {
            if surface.id.trim().is_empty() {
                return Err("`[[surface]] id` must not be empty".to_string());
            }
            if !surface
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Err(format!(
                    "`[[surface]] id = \"{}\"` must contain only ASCII letters, digits, \
                     underscores and hyphens",
                    surface.id
                ));
            }
            if !seen_surface_ids.insert(surface.id.as_str()) {
                return Err(format!(
                    "`[[surface]]` id \"{}\" is declared more than once",
                    surface.id
                ));
            }
            // Every other label in the schema (`menu_label`, `[[windows]]
            // label`, `[[balances]] label`, `[[option]] label`) already
            // refuses blank; this one didn't, and `engine_http::resolve_tag`
            // hands a declared surface's own `label` straight to the tag
            // chip with no `.filter(|s| !s.is_empty())` the way its
            // `[tag] from = "field"` branch gets — a blank one loads clean
            // and draws an empty chip.
            if surface.label.trim().is_empty() {
                return Err(format!(
                    "`[[surface]]` id \"{}\": `label` must not be empty",
                    surface.id
                ));
            }
            // Same reasoning as `[[windows]] label`'s own cap: a row caption
            // on a card with `wrap: word-wrap`, not a paragraph.
            if surface.label.chars().count() > LABEL_MAX_CHARS {
                return Err(format!(
                    "`[[surface]]` id \"{}\": label is {} characters — {LABEL_MAX_CHARS} is the \
                     cap for a row caption",
                    surface.id,
                    surface.label.chars().count()
                ));
            }
        }

        if self.refresh_secs == 0 {
            return Err("`refresh_secs` must be greater than 0".to_string());
        }
        // A cadence under `MIN_REFRESH_SECS` is not "fresher", it is a poll
        // loop: the log-file engine would re-open and re-scan the same file
        // several times a second, and the http engine would burn through
        // `[http] min_interval_secs`'s floor before the timer had any real
        // gap to close. Every shipped manifest polls at 60s or slower.
        if self.refresh_secs < MIN_REFRESH_SECS {
            return Err(format!(
                "`refresh_secs = {}` is below the {MIN_REFRESH_SECS}-second floor — nothing this \
                 app reads changes fast enough to be worth polling more often than that",
                self.refresh_secs
            ));
        }
        // And a day is generous headroom above the slowest shipped cadence
        // (Copilot's monthly counter, polled every 300s) — a manifest asking
        // for less than once a day would leave a stale reading on screen for
        // a window that may have reset hours ago, with `main.rs`'s ping
        // logic never getting a fresh figure to arm on either.
        if self.refresh_secs > MAX_REFRESH_SECS {
            return Err(format!(
                "`refresh_secs = {}` is above the {MAX_REFRESH_SECS}-second (24h) ceiling",
                self.refresh_secs
            ));
        }
        Ok(())
    }

    fn validate_engine_sections(&self) -> Result<(), String> {
        match self.engine {
            EngineKind::LogFile if self.logfile.is_none() => {
                return Err("engine = \"log-file\" requires a [logfile] section".to_string());
            }
            // `[http]` describes the one request only `engine = "http-api"`
            // ever sends. Accepted on a log-file manifest, it would be a
            // whole section — a live `[[http.request]]` url, a
            // credential-bearing surface, backoff knobs — that this app
            // parses, validates and then never reads at all: exactly the
            // silent-misread shape the rest of this file exists to refuse,
            // just not gated by a capability because no older build is
            // involved, only a copied-and-edited third-party manifest.
            EngineKind::LogFile if self.http.is_some() => {
                return Err(
                    "engine = \"log-file\" does not read an [http] section — only \
                     engine = \"http-api\" does"
                        .to_string(),
                );
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
            // `root_env_join` is joined onto the env var's *value*
            // (`$CODEX_HOME` → `$CODEX_HOME/sessions`), never onto `root`
            // itself — it is a subdirectory name, not a path of its own, so
            // an absolute value would silently discard whatever the
            // environment named, and a `..` component would walk the search
            // outside whatever directory that env var pointed at.
            if let Some(join) = &lf.root_env_join {
                if is_absolute_on_any_platform(Path::new(join)) {
                    return Err(format!(
                        "`[logfile] root_env_join = \"{join}\"` must be a relative subdirectory \
                         — it is appended to `root_env`'s value, not used in its place"
                    ));
                }
                if has_dotdot_component(join) {
                    return Err(format!(
                        "`[logfile] root_env_join = \"{join}\"` must not contain a `..` \
                         component — it would search outside the directory `root_env` named"
                    ));
                }
            }
            // Both halves of `account_match` are required, and the same
            // "present but useless" gap the blank check above closes for
            // `root`/`glob`/`container_key` reaches this table too: a blank
            // `container_field` matches no container's field ever (the same
            // `json_path_get`-shaped miss `resets_at_path` above is refused
            // for), and an `auth_claim` with no segments, or with a blank one
            // among them, walks a `.get("")` that a real JWT claims object
            // never has a key for — `cur` stops resolving, `.as_str()` on
            // whatever it stopped at fails, and `resolve_account_match`
            // returns `None` on every call exactly as the empty-vec case
            // does. Either way the filter this table declares never actually
            // filters, silently defeating the reason a manifest author set
            // it at all (see `resolve_account_match` in `engine_logfile`).
            if let Some(am) = &lf.account_match {
                if am.container_field.trim().is_empty() {
                    return Err(
                        "`[logfile.account_match] container_field` must not be blank".to_string(),
                    );
                }
                if am.auth_claim.is_empty() || am.auth_claim.iter().any(|s| s.trim().is_empty()) {
                    return Err(
                        "`[logfile.account_match] auth_claim` must name at least one non-blank \
                         segment — empty, or a blank one among them, never matches"
                            .to_string(),
                    );
                }
            }
        }
        // Same for the one endpoint an http manifest calls: an empty URL is a
        // request that cannot be sent, and `allowed_hosts` has no host to
        // check it against either. Merged with the two checks below — all
        // three read `self.http` and nothing sits between them that does
        // not — rather than three separate `if let Some(http)`s over the
        // same reference.
        //
        // A GET has nowhere to put a body — `perform` only ever attaches one
        // to a POST — so `body` under the default `method = "get"` is a
        // request that cannot be sent as written, not a body silently
        // dropped. The reverse is not the same shape of mistake: `method =
        // "post"` with no `body` is a complete, sendable POST (its payload is
        // the URL and the credentials in its headers) — exactly what
        // Antigravity's `:retrieveUserQuotaSummary` needs — so it is legal
        // rather than required to spell out `body = ""`.
        //
        // A `{` earlier in a template than a real placeholder — most commonly
        // a JSON object's own opening brace in an http body, but nothing
        // about the shape is body-specific, or even http-specific: a header
        // value someone wrote a JSON fragment into, a URL whose query string
        // opens with an unrelated `{`, or a log-file `root`/`glob` that does
        // the same, swallows a later placeholder exactly the same way — can
        // pair that placeholder's own closing brace with the earlier `{`
        // before this app, or the engine, ever reads its name; see
        // `swallowed_placeholder` for the exact failure this catches. Checked
        // here, at load, rather than left to be discovered as a request sent
        // — or a directory searched — with a literal `{option.foo}` still in
        // it. One sweep over every `{option.<key>}`-substituted template in
        // the manifest (`crate::plugin::substitute_options`'s own doc names
        // every one of them: `[[http.request]]` url/headers/body,
        // `[logfile] root`/`root_env_join`/`glob`, and `[account] url`, which
        // gets the same substitution as an http request's own URL —
        // `engine_http::resolve_account_url`), the same shape as the
        // control-character and `..` sweeps below.
        let mut option_templates: Vec<(String, &str)> = Vec::new();
        if let Some(http) = &self.http {
            if http.request.iter().any(|r| r.url.trim().is_empty()) {
                return Err("`[[http.request]] url` must not be empty".to_string());
            }
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
            for req in &http.request {
                option_templates.push(("`[[http.request]] url`".to_string(), req.url.as_str()));
                for (header, value) in &req.headers {
                    option_templates.push((
                        format!("`[[http.request]]` header `{header}`"),
                        value.as_str(),
                    ));
                }
                if let Some(body) = &req.body {
                    option_templates.push(("`[[http.request]] body`".to_string(), body.as_str()));
                }
            }
        }
        if let Some(lf) = &self.logfile {
            option_templates.push(("`[logfile] root`".to_string(), lf.root.as_str()));
            if let Some(join) = &lf.root_env_join {
                option_templates.push(("`[logfile] root_env_join`".to_string(), join.as_str()));
            }
            option_templates.push(("`[logfile] glob`".to_string(), lf.glob.as_str()));
        }
        if let Some(url) = &self.account.url {
            option_templates.push(("`[account] url`".to_string(), url.as_str()));
        }
        if let Some((where_it_is, marker)) =
            option_templates.iter().find_map(|(where_it_is, text)| {
                swallowed_placeholder(text).map(|marker| (where_it_is, marker))
            })
        {
            return Err(format!(
                "{where_it_is} names {marker}, but an earlier `{{` — typically a JSON \
                 object's own opening brace — pairs with that placeholder's closing brace \
                 before its name is ever read, so it would be sent on the wire exactly as \
                 written"
            ));
        }
        Ok(())
    }

    fn validate_windows(&self) -> Result<(), String> {
        // A provider has to report *something*. Windows were the only shape
        // this could take until a provider whose response carries no window
        // key at all — only a calendar billing period — made "at least one
        // [[windows]]" a rule that left a whole class of provider unwritable
        // as a plugin. The rule is the same rule with the second shape added,
        // not a weaker one: a manifest that declares neither still cannot
        // draw a row.
        if self.windows.is_empty() && self.balances.is_empty() {
            return Err("at least one [[windows]] or [[balances]] section is required".to_string());
        }
        // Every identity check above and below this point (windows against
        // windows, balances against balances, `for_each` filters) is O(n²)
        // in the count of the section it walks — cheap at the size any real
        // provider has ever needed, and a manifest asking for hundreds of
        // entries is asking this app to do that on every load rather than
        // reporting an actual quota.
        if self.windows.len() > WINDOWS_MAX_COUNT {
            return Err(format!(
                "`[[windows]]` names {} entries — at most {WINDOWS_MAX_COUNT}",
                self.windows.len()
            ));
        }
        if self.balances.len() > BALANCES_MAX_COUNT {
            return Err(format!(
                "`[[balances]]` names {} entries — at most {BALANCES_MAX_COUNT}",
                self.balances.len()
            ));
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

        // A row caption, not a paragraph — the panel draws it on a card with
        // `wrap: word-wrap` (`ui/app.slint`), so a manifest with no cap of
        // its own grows that card to whatever length it names, the same
        // shape `name`/`menu_label`'s own caps exist to bound.
        for w in &self.windows {
            if w.label.chars().count() > LABEL_MAX_CHARS {
                return Err(format!(
                    "windows[label = \"{}\"]: label is {} characters — {LABEL_MAX_CHARS} is the \
                     cap for a row caption",
                    w.label,
                    w.label.chars().count()
                ));
            }
        }

        // `[[windows]] id` becomes the `<entry>` half of this window's
        // `crate::model::Window::key` (`window_key`, `WINDOW_ID_MAX_BYTES`'s
        // own doc says which registry it is not). That key is matched and
        // compared in-process every fetch — a `for_each` row is found again
        // by it, and a dedup check walks it — so the charset is a whitelist
        // for the same reason the plugin `id` above has one: legible without
        // decoding, even though `encode_key_part` would percent-encode
        // whatever this refusal didn't catch. The length cap keeps that
        // comparison, and every log line that quotes the id, cheap.
        for w in &self.windows {
            if w.id.is_empty() {
                continue;
            }
            check_entry_id(&w.id, &w.label, "windows")?;
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
            // A field present but blank (`Some("")`) is not a declaration,
            // and refusing it outright — rather than only excluding it from
            // "one of the two is named" below — matters here in a way it
            // would not for a field `build_window` reads on its own:
            // `engine_http::build_window` matches `(&used_percent_path,
            // &remaining_fraction_path)` on *`Some`-ness*, not on which one
            // actually resolves, so `used_percent_path = ""` beside a
            // perfectly good `remaining_fraction_path` would win that match
            // arm, read nothing at `json_path_get(v, "")`, and drop the
            // whole window — silently discarding a figure the manifest did
            // state, in a shape "the two fields disagree about which is
            // declared" would otherwise slip through as merely "the one
            // that lost". Same gap the `[status]` blank sweep closes for its
            // own paths.
            let blank_figure_paths = [
                ("used_percent_path", &w.source.used_percent_path),
                ("remaining_fraction_path", &w.source.remaining_fraction_path),
            ];
            if let Some((field, _)) = blank_figure_paths
                .iter()
                .find(|(_, p)| p.as_deref().is_some_and(|s| s.trim().is_empty()))
            {
                return Err(format!(
                    "windows[label = \"{}\"]: `{field}` is present but blank — a path that reads \
                     nothing is not a path",
                    w.label
                ));
            }
            let has_used = w
                .source
                .used_percent_path
                .as_deref()
                .is_some_and(|p| !p.trim().is_empty());
            let has_remaining = w
                .source
                .remaining_fraction_path
                .as_deref()
                .is_some_and(|p| !p.trim().is_empty());
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
            // `resets_at_path` is the one path in this table that is not
            // optional — every window states a reset time — so blank never
            // reads as "not declared" anywhere else the way the two above
            // do; it just resolves to nothing (`segments("")` = `[""]`) on
            // every fetch, and the panel silently stops showing a reset time
            // for this window.
            if w.source.resets_at_path.trim().is_empty() {
                return Err(format!(
                    "windows[label = \"{}\"]: `resets_at_path` must not be blank",
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
            // `is_empty()` above already refuses a *lone* blank path — it
            // treats absent and blank the same way, per-field. What it
            // cannot catch is one blank path sitting beside another that
            // genuinely has content: that combination reads as "not empty"
            // (the real path keeps the whole section from being refused
            // there), and the blank sibling then resolves to nothing at
            // fetch time with no error naming it — the same gap the
            // `[[balances]]` blank check below closes for its own paths.
            let blank_paths = [
                ("allowed_path", &status.allowed_path),
                ("limit_reached_path", &status.limit_reached_path),
                ("reached_type_path", &status.reached_type_path),
            ];
            if let Some((field, _)) = blank_paths
                .iter()
                .find(|(_, p)| p.as_deref().is_some_and(|s| s.trim().is_empty()))
            {
                return Err(format!(
                    "`[status] {field}` is present but blank — a path that reads nothing is not \
                     a path"
                ));
            }
        }
        Ok(())
    }

    fn validate_balances(&self) -> Result<(), String> {
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
            // Same reasoning as the `[[windows]] label` cap above: a row
            // caption on a card with `wrap: word-wrap`, not a paragraph.
            if b.label.chars().count() > LABEL_MAX_CHARS {
                return Err(format!(
                    "`[[balances]] label` = \"{}\" is {} characters — {LABEL_MAX_CHARS} is the \
                     cap for a row caption",
                    b.label,
                    b.label.chars().count()
                ));
            }
            // Same charset and cap as `[[windows]] id`, and for the same
            // reason: it becomes a segment of a dotted key on disk.
            if !b.id.is_empty() {
                check_entry_id(&b.id, &b.label, "balances")?;
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
            // Same blank-path gap, for `unlimited`/`when`'s own single
            // required field — a plain `String`, not an `Option`, so it
            // cannot be caught by the loop above.
            for (field, cfg_path) in [
                (
                    "unlimited.path",
                    b.unlimited.as_ref().map(|u| u.path.as_str()),
                ),
                ("when.path", b.when.as_ref().map(|w| w.path.as_str())),
            ] {
                if cfg_path.is_some_and(|p| p.trim().is_empty()) {
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
                    // Appended after a number, not a caption of its own — a
                    // quarter of a row caption's own room.
                    if label.chars().count() > UNIT_LABEL_MAX_CHARS {
                        return Err(format!(
                            "balances[label = \"{}\"].{field}: `unit_label` is {} characters — \
                             {UNIT_LABEL_MAX_CHARS} is the cap",
                            b.label,
                            label.chars().count()
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
                // The same restriction one step earlier, on the path fields
                // themselves: `path` is `number`/`text`'s own field
                // (`missing_path` above requires it for exactly those two),
                // and `amount_path`/`currency_path`/`exponent_path` are
                // `money-minor`'s own triplet — neither engine ever reads
                // either set for the other kind, so the wrong one present
                // loads clean and is silently ignored.
                if amount.kind == AmountKind::MoneyMinor && amount.path.is_some() {
                    return Err(format!(
                        "balances[label = \"{}\"].{field}: `path` belongs to `kind = \"number\"`/\
                         `\"text\"` — `kind = \"money-minor\"` reads `amount_path`/`currency_path`/\
                         `exponent_path` instead",
                        b.label
                    ));
                }
                if amount.kind != AmountKind::MoneyMinor {
                    let irrelevant: &[(&str, bool)] = &[
                        ("amount_path", amount.amount_path.is_some()),
                        ("currency_path", amount.currency_path.is_some()),
                        ("exponent_path", amount.exponent_path.is_some()),
                    ];
                    if let Some((name, _)) = irrelevant.iter().find(|(_, present)| *present) {
                        return Err(format!(
                            "balances[label = \"{}\"].{field}: `{name}` belongs to \
                             `kind = \"money-minor\"` only",
                            b.label
                        ));
                    }
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
        Ok(())
    }

    fn validate_window_period_mode(&self) -> Result<(), String> {
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
        Ok(())
    }

    fn validate_tag(&self) -> Result<(), String> {
        // The same `mode`/field cross-check as `[windows.period]` just
        // above, for `[tag]`: `resolve_tag` (`engine_http`/`engine_logfile`,
        // identically) reads `value` only on `from = "static"` and `path`
        // only on `from = "field"` — either without its own field loads
        // clean and then resolves to `None` on every fetch, drawing no chip
        // at all for a manifest that plainly declared one.
        match self.tag.from {
            TagFrom::Static if self.tag.value.is_none() => {
                return Err("`[tag] from = \"static\"` requires `value`".to_string());
            }
            TagFrom::Field if self.tag.path.is_none() => {
                return Err("`[tag] from = \"field\"` requires `path`".to_string());
            }
            _ => {}
        }
        Ok(())
    }

    fn validate_window_period_bounds(&self) -> Result<(), String> {
        // A window this short turns `main.rs`'s `ping_due` arithmetic —
        // `pinged_at + PING_GRACE_SECS < start` with `start = reset − period`
        // — into something that can fire on every one-second tick: a
        // `period.assumed` of 1 minute (or the field's own zero default were
        // it ever left unset) puts `start` in the past by design, and a
        // manifest making that number up gets to choose it. Real windows
        // measure in hours; `MIN_ASSUMED_PERIOD_MINUTES` is a floor far below
        // the shortest one shipped (Claude/Antigravity's five-hour window,
        // at 300), not a tight fit around it. `period.mode = "from_field"`
        // is exempt — that length comes from the provider's own response,
        // not from a number the manifest author picked.
        for w in &self.windows {
            if let (PeriodMode::Assumed, Some(assumed)) = (w.period.mode, w.period.assumed) {
                if assumed < MIN_ASSUMED_PERIOD_MINUTES {
                    return Err(format!(
                        "windows[label = \"{}\"]: period.assumed = {assumed} minutes is shorter \
                         than the {MIN_ASSUMED_PERIOD_MINUTES}-minute floor",
                        w.label
                    ));
                }
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
            if w.source.containers.len() > SOURCE_CONTAINERS_MAX_COUNT {
                return Err(format!(
                    "windows[label = \"{}\"]: source.containers lists {} candidates — at most \
                     {SOURCE_CONTAINERS_MAX_COUNT}",
                    w.label,
                    w.source.containers.len()
                ));
            }
        }

        // A classification bound only means something once there is a
        // length, read from the response, to measure it against — and on
        // `engine = "http-api"`, `period.mode = "assumed"` states the
        // window's own length outright (`period.assumed`), leaving nothing
        // for a bound to classify. `engine_http::select_container` treats a
        // bound exactly this way: it only ever consults
        // `min_period_minutes`/`max_period_minutes` when
        // `mode = "from_field"`, so on this engine a bound declared beside
        // `assumed` is not a stricter rule, it is dead weight — a number
        // nothing ever reads, which a manifest author would have every
        // reason to believe does something. The log-file engine is not the
        // same: `engine_logfile::classify_slot`/`effective_bounds` apply a
        // bound to a log record regardless of `period.mode`, and a
        // `role = "extra"` log-file window *needs* one (with neither bound
        // set it classifies to nothing and never draws — see
        // `classify_slot`'s own early return). So this refusal is scoped to
        // `http-api` only; the same manifest is legal for `log-file`.
        if self.engine == EngineKind::HttpApi {
            for w in &self.windows {
                if w.period.mode == PeriodMode::Assumed
                    && (w.source.min_period_minutes.is_some()
                        || w.source.max_period_minutes.is_some())
                {
                    return Err(format!(
                        "windows[label = \"{}\"]: min_period_minutes/max_period_minutes classify \
                         a candidate by length on engine = \"http-api\" — meaningless when \
                         period.mode = \"assumed\" already states the length outright",
                        w.label
                    ));
                }
            }
        }

        // A `min_period_minutes` greater than `max_period_minutes` bounds an
        // empty range — no length a response could ever report satisfies
        // both at once, so `engine_logfile::effective_bounds`/
        // `engine_http::select_container` never classify a candidate into
        // this window, and a `role = "extra"` window built this way silently
        // never draws.
        for w in &self.windows {
            if let (Some(min), Some(max)) =
                (w.source.min_period_minutes, w.source.max_period_minutes)
            {
                if min > max {
                    return Err(format!(
                        "windows[label = \"{}\"]: min_period_minutes ({min}) is greater than \
                         max_period_minutes ({max}) — nothing can ever classify into this window",
                        w.label
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_account_and_surface_auth(&self) -> Result<(), String> {
        // `[account] url`'s two checks used to sit inside `if let Some(http)`
        // below, which was never the right gate for them: `[account] type =
        // "http"` sends its own request whatever `self.engine` is (the
        // log-file engine simply has no use for it today —
        // `engine_logfile::resolve_account`'s own doc says so — which is a
        // reason for that engine to ignore the field, not a reason for this
        // file to stop checking it). A log-file manifest naming a header-only
        // placeholder or a plain `http://` account URL was loading clean and
        // would only ever have failed once some future engine read it.
        if let Some(url) = &self.account.url {
            if let Some(bad) = url_placeholder(url) {
                return Err(format!(
                    "`[account] url` may not contain {bad} — {{token}}, {{version}} and \
                     {{value.<name>}} are substituted into headers only"
                ));
            }
            if super::https_host(url).is_none() {
                return Err(format!(
                    "`[account] url` must be https — refusing to send a request over {url}"
                ));
            }
        }
        // A surface that carries a credential must say where it may go. An
        // empty `allowed_hosts` means "no restriction configured", which is
        // a fine default for a manifest that sends nothing — and exactly the
        // wrong one for a manifest that sends a token. Also moved out of
        // `if let Some(http)`: the rule is about what a *credential* may
        // reach, not about what `[http]` may reach, and a log-file manifest
        // can carry a `[[surface.auth]]` chain of its own (feeding `[account]
        // type = "http"`, or simply written ahead of an engine that will one
        // day read it) exactly as unguarded as an http-api one was before
        // this moved.
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
        Ok(())
    }

    fn validate_http(&self) -> Result<(), String> {
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
            // Every URL this engine ever sends a credential to must be
            // `https` — read by `super::https_host`, the same WHATWG parser
            // `ureq` builds the request through, so what is checked here is
            // what `perform` would actually dial. Caught at load rather than
            // left for `perform`'s own refusal (defence in depth, not the
            // only depth): a manifest that cannot be sent safely should
            // never reach a fetch to find that out. `token_url` carries the
            // same rule too — checked below, in the per-step loop over
            // `[[surface.auth]]`, since it lives on the step rather than on
            // `[http]` — and enforced again where it is spent
            // (`auth::oauth_refresh_step`), since a refresh token's exchange
            // has its own allow-list check to sit next to.
            for req in &http.request {
                if super::https_host(&req.url).is_none() {
                    return Err(format!(
                        "`[[http.request]] url` must be https — refusing to send a request over \
                         {}",
                        req.url
                    ));
                }
            }
            // `[http.version]` — the `files` candidates `resolve_version`
            // tries, in order, before falling back to `fallback`. Not gated
            // on `requires_reader`: an older build ignores the whole table
            // (there is no capability for it), so the risk this file guards
            // against elsewhere — a build that half-understands a section —
            // does not apply here. What does apply is the same shape of
            // mistake `[logfile]`'s blank check exists for: a manifest that
            // parses clean and then reads nothing every fetch, silently
            // falling back to `fallback` forever.
            if let Some(version) = &http.version {
                if version.files.len() > HTTP_VERSION_FILES_MAX_COUNT {
                    return Err(format!(
                        "`[http.version] files` names {} entries — at most \
                         {HTTP_VERSION_FILES_MAX_COUNT}",
                        version.files.len()
                    ));
                }
                if let Some(bad) = version.files.iter().find(|f| f.trim().is_empty()) {
                    return Err(format!(
                        "`[http.version] files` entry \"{bad}\" must not be blank"
                    ));
                }
                // Same rule and the same reasoning as `client.files` above:
                // a relative entry resolves against whatever directory this
                // process happens to be running from, never the intent of
                // naming an installed client's own version file, and
                // `is_absolute_on_any_platform` (not `Path::is_absolute`)
                // because this manifest ships to every platform this app
                // runs on, not only the one validating it.
                if let Some(bad) = version
                    .files
                    .iter()
                    .find(|f| !is_absolute_on_any_platform(&super::expand_home(f)))
                {
                    return Err(format!(
                        "`[http.version] files` entry \"{bad}\" must be an absolute path"
                    ));
                }
            }
            // `refresh_secs` paces the *scheduled* timer; `min_interval` is
            // the only thing standing between a person and a request on
            // every panel open, `Refresh` click and app start — the one
            // floor of the four in this table that was not already zero-
            // refused the way `backoff_start_secs`/`unauthorized_retry_secs`
            // are just below, even though `Limits::from_http` now clamps it
            // with the identical `.max(1)` those two already got. Caught
            // here rather than only at the clamp so the manifest author
            // sees why, not a request rate that quietly stopped matching
            // what `0` reads as.
            if http.min_interval_secs == 0 {
                return Err("`[http] min_interval_secs` must be greater than 0".to_string());
            }
            // `min_interval_secs`'s own doc states this: a floor at or above
            // the scheduled cadence skips every other tick (the timer lands
            // a hair early against the floor's own clock, so half its runs
            // are turned away), halving the real refresh rate for a manifest
            // whose author asked for the opposite of that.
            if http.min_interval_secs >= self.refresh_secs {
                return Err(format!(
                    "`[http] min_interval_secs` ({}) must be below `refresh_secs` ({}) — at or \
                     above it, the scheduled refresh is skipped every other tick",
                    http.min_interval_secs, self.refresh_secs
                ));
            }
            if http.backoff_start_secs == 0 {
                return Err("`[http] backoff_start_secs` must be greater than 0".to_string());
            }
            if http.unauthorized_retry_secs == 0 {
                return Err("`[http] unauthorized_retry_secs` must be greater than 0".to_string());
            }
            // Unbounded, a manifest naming a huge value (or the field's own
            // max — `u64::MAX` seconds is longer than this app, or its user,
            // will run) stops polling a surface after its first 401 forever:
            // nothing short of editing the manifest or reinstalling the
            // plugin would ever try it again, which is a worse failure mode
            // than the loop this field exists to prevent. A week is well
            // past any credential expiry this app has ever measured.
            if http.unauthorized_retry_secs > MAX_HTTP_COOLDOWN_SECS {
                return Err(format!(
                    "`[http] unauthorized_retry_secs` ({}) must be at most {MAX_HTTP_COOLDOWN_SECS} \
                     seconds (7 days) — longer than that is indistinguishable from never retrying",
                    http.unauthorized_retry_secs
                ));
            }
            if http.backoff_max_secs < http.backoff_start_secs {
                return Err(format!(
                    "`[http] backoff_max_secs` ({}) must be at least backoff_start_secs ({})",
                    http.backoff_max_secs, http.backoff_start_secs
                ));
            }
            // Same reasoning as `unauthorized_retry_secs` just above, for the
            // same failure shape: a backoff ceiling this high is a surface
            // that, once it has failed a handful of times, is retried on a
            // timescale nobody would recognise as "backing off" rather than
            // "given up".
            if http.backoff_max_secs > MAX_HTTP_COOLDOWN_SECS {
                return Err(format!(
                    "`[http] backoff_max_secs` ({}) must be at most {MAX_HTTP_COOLDOWN_SECS} \
                     seconds (7 days)",
                    http.backoff_max_secs
                ));
            }
            // A timeout of 0 is not "no timeout" (`ureq` has no such
            // setting to ask for) — it is a request that fails before it
            // could ever succeed, same as the two siblings above.
            for req in &http.request {
                if req.timeout_secs == 0 {
                    return Err(
                        "`[[http.request]] timeout_secs` must be greater than 0".to_string()
                    );
                }
            }
            // And a timeout above two minutes holds the fetch thread (and
            // whatever `FetchGuard` is waiting on it) far longer than any
            // provider this app talks to has ever taken to answer or fail —
            // a manifest asking for one is asking this app to wedge on a
            // single slow request instead of backing off and trying again.
            for req in &http.request {
                if req.timeout_secs > MAX_TIMEOUT_SECS {
                    return Err(format!(
                        "`[[http.request]] timeout_secs` ({}) must be at most {MAX_TIMEOUT_SECS} \
                         seconds",
                        req.timeout_secs
                    ));
                }
            }
            if http.value.len() > HTTP_VALUES_MAX_COUNT {
                return Err(format!(
                    "`[[http.value]]` names {} entries — at most {HTTP_VALUES_MAX_COUNT}",
                    http.value.len()
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
        Ok(())
    }

    fn validate_auth(&self) -> Result<(), String> {
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
                // A `token_url` that is not `https` would send the refresh
                // token — and the installed-app secret paired with it — to
                // whatever sits in front of that endpoint, in the clear.
                // Read the same way as `[[http.request]] url` and `[account]
                // url` above (`super::https_host`, the WHATWG parser `ureq`
                // builds the request through), so what is checked here is
                // what `auth::oauth_refresh_step` would actually dial.
                // `oauth_refresh_step` refuses the same thing again at run
                // time — its own `starts_with("https://")`, defence in
                // depth — but a manifest that can never refresh safely
                // should never reach a fetch to find that out. By this point
                // in the loop `token_url` is `Some` and non-blank (the
                // `missing`/`blank` checks above already returned otherwise),
                // so this only ever runs against text a manifest actually
                // wrote.
                if step.kind == AuthType::OauthRefresh {
                    let token_url = step.token_url.as_deref().unwrap_or_default();
                    if super::https_host(token_url).is_none() {
                        return Err(format!(
                            "surface \"{}\": an `oauth-refresh` auth step's `token_url` must be \
                             https — refusing to send a refresh token over {token_url}",
                            surface.id
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
                            // long (the shipped Antigravity ones measure 73
                            // and 35), so a pattern whose match has no
                            // ceiling — or one set too high — is refused
                            // here rather than left to `scan_candidate`'s own
                            // defensive `debug_assert` at scan time, which
                            // exists for a manifest that got past this check
                            // some other way, not as the primary guard.
                            let (max_len, min_len) = regex_len_bounds(pattern);
                            if !matches!(max_len, Some(len) if len <= super::CLIENT_PATTERN_MAX_MATCH_BYTES)
                            {
                                // `None` is not always "unbounded": `regex_syntax`'s
                                // own `maximum_len` also answers `None` for a
                                // pattern it simply cannot put a byte-length on —
                                // a purely Unicode-aware construct measured
                                // against raw bytes, say — where the match is
                                // not actually infinite, only unmeasurable by
                                // this analysis. Either way the refusal is the
                                // same (this check cannot tell "no ceiling"
                                // from "no answer" apart, and must refuse
                                // both), so the message says so rather than
                                // asserting a claim ("unbounded") this app
                                // cannot back up for the second case.
                                return Err(format!(
                                    "surface \"{}\": a `{}` auth step's `{field}` may match at most \
                                     {} bytes ({}) — a pattern with no measurable ceiling could read \
                                     an unbounded slice of the file it scans and call the slice the \
                                     client",
                                    surface.id,
                                    auth_type_name(step.kind),
                                    super::CLIENT_PATTERN_MAX_MATCH_BYTES,
                                    max_len
                                        .map(|n| n.to_string())
                                        .unwrap_or_else(|| "unbounded or unmeasurable".to_string())
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
                            // `Some(len)` failing this can only be
                            // `Some(0)` (`len` is a `usize`, so the only way
                            // `>= 1` fails on a value is for it to be zero);
                            // the other failing case is `None`, which is not
                            // the same claim, let alone a softer one —
                            // the minimum half of `regex_len_bounds` returns
                            // it exactly when the pattern can never match
                            // anything at all (an empty intersection like
                            // `[a&&b]`), so it is named separately rather
                            // than folded into a message that would call a
                            // pattern matching nothing "the empty string"
                            // too.
                            if !matches!(min_len, Some(len) if len >= 1) {
                                let why = match min_len {
                                    None => {
                                        "can never match anything, so it can never find a \
                                         client id or secret"
                                    }
                                    Some(_) => {
                                        "can match the empty string — every client id or secret \
                                         is at least one byte"
                                    }
                                };
                                return Err(format!(
                                    "surface \"{}\": a `{}` auth step's `{field}` {why}",
                                    surface.id,
                                    auth_type_name(step.kind)
                                ));
                            }
                        }
                    }
                    if client.files.len() > CLIENT_FILES_MAX_COUNT {
                        return Err(format!(
                            "surface \"{}\": a `{}` auth step's `client.files` names {} entries \
                             — at most {CLIENT_FILES_MAX_COUNT}",
                            surface.id,
                            auth_type_name(step.kind),
                            client.files.len()
                        ));
                    }
                    if client.bins.len() > CLIENT_BINS_MAX_COUNT {
                        return Err(format!(
                            "surface \"{}\": a `{}` auth step's `client.bins` names {} entries — \
                             at most {CLIENT_BINS_MAX_COUNT}",
                            surface.id,
                            auth_type_name(step.kind),
                            client.bins.len()
                        ));
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
            // `expiry_json_path` is honoured by the four step kinds whose
            // credential store hands back an expiry alongside the token:
            // `credentials-file`/`keychain`/`win-credential` share one JSON
            // blob holding both (`token_from_blob`), and `credentials-map`
            // reads it from the same matched entry its own token comes from
            // (`credentials_map_step`, via `stale_expiry_at`) — `env`,
            // `electron-safe-storage` and `oauth-refresh` never read the
            // field at all. Unrefused, a manifest that set it there anyway
            // would still trip `SurfaceConfig::declares_token_expiry` and
            // `auth::resolve_token`'s own `from_expiring_step` flag — both
            // just check the field's presence, not which step kind carries
            // it — so a `renews_token = true` surface could get a false
            // "token expired — renews on the next `<bin>` run" rewrite (and
            // a wasted ping) for a credential this app never actually
            // checked the age of.
            for (i, step) in surface.auth.iter().enumerate() {
                if step.expiry_json_path.is_some()
                    && !matches!(
                        step.kind,
                        AuthType::CredentialsFile
                            | AuthType::Keychain
                            | AuthType::WinCredential
                            | AuthType::CredentialsMap
                    )
                {
                    return Err(format!(
                        "surface \"{}\": auth step {i} (`{}`) sets `expiry_json_path`, which only \
                         `credentials-file`, `keychain`, `win-credential` and `credentials-map` \
                         steps honour",
                        surface.id,
                        auth_type_name(step.kind)
                    ));
                }
                // `macos_keychain_key` is read exactly once, by
                // `auth::electron_safe_storage_step` — the Keychain service
                // name that holds the Safe Storage password it hands to
                // `electron_decrypt`. Every other step kind never looks at
                // it, so a manifest setting it there would load clean and
                // never do anything, the same silent-no-op `expiry_json_path`
                // is refused above for.
                if step.macos_keychain_key.is_some() && step.kind != AuthType::ElectronSafeStorage {
                    return Err(format!(
                        "surface \"{}\": auth step {i} (`{}`) sets `macos_keychain_key`, which only \
                         `electron-safe-storage` steps honour",
                        surface.id,
                        auth_type_name(step.kind)
                    ));
                }
                // `unless_json_path` is `reject_when_step`'s own escape hatch
                // — read nowhere else. Same reasoning as the two checks
                // above: present on any other kind, it loads without
                // complaint and is never consulted.
                if step.unless_json_path.is_some() && step.kind != AuthType::RejectWhen {
                    return Err(format!(
                        "surface \"{}\": auth step {i} (`{}`) sets `unless_json_path`, which only \
                         `reject-when` steps honour",
                        surface.id,
                        auth_type_name(step.kind)
                    ));
                }
                // `path_env`/`path_env_join` are `credentials_file_step`'s
                // own fields (`auth::resolve_credentials_file_path`) —
                // every other step kind never reads either, same silent-
                // no-op reasoning as the three checks above.
                if (step.path_env.is_some() || step.path_env_join.is_some())
                    && step.kind != AuthType::CredentialsFile
                {
                    return Err(format!(
                        "surface \"{}\": auth step {i} (`{}`) sets `path_env`/`path_env_join`, \
                         which only `credentials-file` steps honour",
                        surface.id,
                        auth_type_name(step.kind)
                    ));
                }
                // Same shape as `[logfile] root_env_join`, and the same
                // reason: it is joined onto `path_env`'s *value*
                // (`$CLAUDE_CONFIG_DIR` → `$CLAUDE_CONFIG_DIR/.credentials.json`),
                // never onto `path` itself — an absolute value would
                // silently discard whatever the environment named, and a
                // `..` component would read a file outside the directory
                // that env var pointed at.
                if let Some(join) = &step.path_env_join {
                    if is_absolute_on_any_platform(Path::new(join)) {
                        return Err(format!(
                            "surface \"{}\": auth step {i} (`{}`) `path_env_join = \"{join}\"` \
                             must be a relative filename — it is appended to `path_env`'s value, \
                             not used in its place",
                            surface.id,
                            auth_type_name(step.kind)
                        ));
                    }
                    if has_dotdot_component(join) {
                        return Err(format!(
                            "surface \"{}\": auth step {i} (`{}`) `path_env_join = \"{join}\"` \
                             must not contain a `..` component — it would read outside the \
                             directory `path_env` named",
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
        Ok(())
    }

    fn validate_account_ping_options(&self) -> Result<(), String> {
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
            // `:` alone is a no-op on this platform's own charset check —
            // `contains('/')`/`contains('\\')` already refuse a Unix or
            // Windows separator — but on Windows `C:evil` is a **prefixed
            // relative** path (relative to whatever directory drive `C:` is
            // current on), not the bare name it looks like beside `/`/`\`.
            if ping.bin.contains(['/', '\\', ':']) {
                return Err(format!(
                    "`[ping] bin = \"{}\"` must be a bare program name, not a path",
                    ping.bin
                ));
            }
            // `[ping] args` reaches the install-time trust dialog verbatim
            // (`main.rs`'s `build_trust_message` renders the command line a
            // ping will run) before it is ever spawned as one — the bounds
            // below are for that dialog, not the spawn itself
            // (`std::process::Command::arg` takes arbitrary bytes safely
            // either way): an unbounded count or length lets a manifest push
            // the untrusted-host warning that dialog carries clean off the
            // bottom.
            if ping.args.len() > PING_ARGS_MAX_COUNT {
                return Err(format!(
                    "`[ping] args` names {} entries — a ping is a short, fixed command line, and \
                     {PING_ARGS_MAX_COUNT} is more than any real one needs",
                    ping.args.len()
                ));
            }
            if ping.args.iter().any(|a| a.is_empty()) {
                return Err(
                    "`[ping] args` entries must not be empty — an empty argument says nothing in \
                     the trust dialog and does nothing on the command line"
                        .to_string(),
                );
            }
            if let Some(bad) = ping.args.iter().find(|a| a.len() > PING_ARG_MAX_BYTES) {
                return Err(format!(
                    "`[ping] args` has an entry of {} bytes — the limit is {PING_ARG_MAX_BYTES}",
                    bad.len()
                ));
            }
        }

        if self.option.len() > OPTIONS_MAX_COUNT {
            return Err(format!(
                "`[[option]]` names {} entries — at most {OPTIONS_MAX_COUNT}",
                self.option.len()
            ));
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
            // Same reasoning as `[[windows]] label`'s own cap: a row caption
            // (the settings sheet's checkbox text), not a paragraph.
            if opt.label.chars().count() > LABEL_MAX_CHARS {
                return Err(format!(
                    "`[[option]] key = \"{}\"`: label is {} characters — {LABEL_MAX_CHARS} is \
                     the cap for a row caption",
                    opt.key,
                    opt.label.chars().count()
                ));
            }
            if !seen_option_keys.insert(opt.key.as_str()) {
                return Err(format!(
                    "`[[option]]` key \"{}\" is declared more than once",
                    opt.key
                ));
            }
        }
        Ok(())
    }

    fn validate_templates(&self) -> Result<(), String> {
        // A control character or a bidirectional override in any manifest
        // string reaches somewhere it can do real damage before this app
        // gets a chance to sanitise it for display: `[ping] args` and
        // `allowed_hosts` are rendered verbatim into the install-time trust
        // dialog (`main.rs::build_trust_message`), `message` and
        // `no_credentials_message` are drawn on the panel, and every one of
        // these can reach `diag::line`, which writes a manifest string to
        // the log file exactly as given. A `\n` splits a dialog's single
        // line in two; a `\r` overwrites what came before it; U+2028/U+2029
        // do what `\n` does to code that only checked for `\n`; and the bidi
        // marks/embeddings/overrides/isolates (U+200E/F, U+202A–E,
        // U+2066–9) can reorder what is printed after them, or hide where a
        // sentence actually ends, without a single character looking out of
        // place. `sanitize_provider_text` strips these from a *response*
        // before it reaches the screen; a manifest is data this app decided
        // to trust, not a response, so the right answer for it is to refuse
        // at load rather than launder at render time.
        //
        // Not every field here is checked the same way, though: a
        // [`CharClass::Narrow`] field is display text the app's own UI
        // renders after install — `name`, `menu_label`, a window/balance/
        // surface/option label, a panel message — where a legitimate emoji
        // sequence (👨‍💻 is a base character plus a zero-width joiner;
        // most emoji as an app actually renders them carry a trailing
        // variation selector) must not be refused just because it shares a
        // code point range with something that hides text. A
        // [`CharClass::Wide`] field is one that reaches the install-time
        // trust dialog before any of that is installed, or is resolved
        // directly against the filesystem or the network — see each field's
        // own tag below, and [`CharClass`]'s own doc for the reasoning.
        // Whichever class, one shared check
        // ([`control_char_field_is_disruptive`]) over every field named
        // above, rather than a copy of the same lines at each site.
        let seen_option_keys: std::collections::HashSet<&str> =
            self.option.iter().map(|o| o.key.as_str()).collect();
        let mut control_char_fields: Vec<(String, &str, CharClass)> = vec![
            ("`name`".to_string(), self.name.as_str(), CharClass::Narrow),
            (
                "`menu_label`".to_string(),
                self.menu_label.as_str(),
                CharClass::Narrow,
            ),
        ];
        if let Some(ping) = &self.ping {
            // `bin` is resolved on `PATH` and executed exactly like
            // `client.bins` below; `args` rides the same command line.
            control_char_fields.push((
                "`[ping] bin`".to_string(),
                ping.bin.as_str(),
                CharClass::Wide,
            ));
            for (i, arg) in ping.args.iter().enumerate() {
                control_char_fields.push((
                    format!("`[ping] args[{i}]`"),
                    arg.as_str(),
                    CharClass::Wide,
                ));
            }
        }
        for w in &self.windows {
            control_char_fields.push((
                format!("windows[label = \"{}\"]: `label`", w.label),
                w.label.as_str(),
                CharClass::Narrow,
            ));
        }
        for b in &self.balances {
            control_char_fields.push((
                format!("balances[label = \"{}\"]: `label`", b.label),
                b.label.as_str(),
                CharClass::Narrow,
            ));
        }
        if let Some(http) = &self.http {
            for (i, req) in http.request.iter().enumerate() {
                control_char_fields.push((
                    format!("`[[http.request]][{i}] url`"),
                    req.url.as_str(),
                    CharClass::Wide,
                ));
            }
            if let Some(version) = &http.version {
                for (i, f) in version.files.iter().enumerate() {
                    control_char_fields.push((
                        format!("`[http.version] files[{i}]`"),
                        f.as_str(),
                        CharClass::Wide,
                    ));
                }
            }
        }
        if let Some(url) = &self.account.url {
            control_char_fields.push((
                "`[account] url`".to_string(),
                url.as_str(),
                CharClass::Wide,
            ));
        }
        for surface in &self.surface {
            control_char_fields.push((
                format!("surface \"{}\": `label`", surface.id),
                surface.label.as_str(),
                CharClass::Narrow,
            ));
            for (i, host) in surface.allowed_hosts.iter().enumerate() {
                control_char_fields.push((
                    format!("surface \"{}\": `allowed_hosts[{i}]`", surface.id),
                    host.as_str(),
                    CharClass::Wide,
                ));
            }
            if let Some(msg) = &surface.no_credentials_message {
                control_char_fields.push((
                    format!("surface \"{}\": `no_credentials_message`", surface.id),
                    msg.as_str(),
                    CharClass::Narrow,
                ));
            }
            for step in &surface.auth {
                let step_name = auth_type_name(step.kind);
                if let Some(msg) = &step.message {
                    control_char_fields.push((
                        format!(
                            "surface \"{}\": a `{step_name}` auth step's `message`",
                            surface.id
                        ),
                        msg.as_str(),
                        CharClass::Narrow,
                    ));
                }
                // `service`/`targets` are technical identifiers, not prose —
                // and both reach the trust dialog through
                // `TrustDisclosure::credential_sources` (`"keychain
                // \"<service>\""`/`"credential manager \"<target>\""`),
                // which is exactly `CharClass::Wide`'s own criterion.
                if let Some(service) = &step.service {
                    control_char_fields.push((
                        format!(
                            "surface \"{}\": a `{step_name}` auth step's `service`",
                            surface.id
                        ),
                        service.as_str(),
                        CharClass::Wide,
                    ));
                }
                for (i, target) in step.targets.iter().flatten().enumerate() {
                    control_char_fields.push((
                        format!(
                            "surface \"{}\": a `{step_name}` auth step's `targets[{i}]`",
                            surface.id
                        ),
                        target.as_str(),
                        CharClass::Wide,
                    ));
                }
                if let Some(token_url) = &step.token_url {
                    control_char_fields.push((
                        format!(
                            "surface \"{}\": a `{step_name}` auth step's `token_url`",
                            surface.id
                        ),
                        token_url.as_str(),
                        CharClass::Wide,
                    ));
                }
                if let Some(client) = &step.client {
                    if let Some(id_env) = &client.id_env {
                        control_char_fields.push((
                            format!(
                                "surface \"{}\": a `{step_name}` auth step's `client.id_env`",
                                surface.id
                            ),
                            id_env.as_str(),
                            CharClass::Wide,
                        ));
                    }
                    if let Some(secret_env) = &client.secret_env {
                        control_char_fields.push((
                            format!(
                                "surface \"{}\": a `{step_name}` auth step's `client.secret_env`",
                                surface.id
                            ),
                            secret_env.as_str(),
                            CharClass::Wide,
                        ));
                    }
                    for (i, f) in client.files.iter().enumerate() {
                        control_char_fields.push((
                            format!(
                                "surface \"{}\": a `{step_name}` auth step's `client.files[{i}]`",
                                surface.id
                            ),
                            f.as_str(),
                            CharClass::Wide,
                        ));
                    }
                    // `bins`, `id_pattern` and `secret_pattern` reach the
                    // trust dialog exactly like `files` does —
                    // `registry::analyze_trust` folds every one of the three
                    // into `local_files` (a `bins` entry as the candidate
                    // name itself, the two patterns labelled
                    // `"id_pattern: …"`/`"secret_pattern: …"`) — so they need
                    // the same refusal `files` already gets, not a narrower
                    // one that leaves this one table's other fields able to
                    // rewrite what the dialog shows.
                    for (i, name) in client.bins.iter().enumerate() {
                        control_char_fields.push((
                            format!(
                                "surface \"{}\": a `{step_name}` auth step's `client.bins[{i}]`",
                                surface.id
                            ),
                            name.as_str(),
                            CharClass::Wide,
                        ));
                    }
                    if let Some(id_pattern) = &client.id_pattern {
                        control_char_fields.push((
                            format!(
                                "surface \"{}\": a `{step_name}` auth step's `client.id_pattern`",
                                surface.id
                            ),
                            id_pattern.as_str(),
                            CharClass::Wide,
                        ));
                    }
                    if let Some(secret_pattern) = &client.secret_pattern {
                        control_char_fields.push((
                            format!(
                                "surface \"{}\": a `{step_name}` auth step's `client.secret_pattern`",
                                surface.id
                            ),
                            secret_pattern.as_str(),
                            CharClass::Wide,
                        ));
                    }
                }
            }
        }
        for opt in &self.option {
            control_char_fields.push((
                format!("`[[option]] key = \"{}\"`: `label`", opt.key),
                opt.label.as_str(),
                CharClass::Narrow,
            ));
        }
        if let Some((where_it_is, _, _)) = control_char_fields
            .iter()
            .find(|(_, text, class)| control_char_field_is_disruptive(text, *class))
        {
            return Err(format!(
                "{where_it_is} contains a control character or a bidirectional override — refused \
                 before it can rewrite a trust dialog, a log line or the panel around it"
            ));
        }

        // A `..` component walks a path outside whatever directory this app
        // meant to confine the read to — `[account] path`/`[logfile] root`/
        // `client.files`/`[http.version] files` name a file to read, and
        // `[[surface.auth]] path`/`config_path` name a credential store to
        // read, none of which this app has any business reading past the
        // directory a manifest author actually named. `is_absolute_on_any_
        // platform` already lets an absolute value through on purpose (the
        // shipped Antigravity manifest's `client.files` names one) — this is
        // the narrower, purely relative escape a `~/.foo/../../.ssh/id_rsa`
        // shaped value would still get past that check. One shared sweep,
        // the same shape as the control-character one just above.
        let mut dotdot_fields: Vec<(String, &str)> = Vec::new();
        if let Some(path) = &self.account.path {
            dotdot_fields.push(("`[account] path`".to_string(), path.as_str()));
        }
        if let Some(lf) = &self.logfile {
            dotdot_fields.push(("`[logfile] root`".to_string(), lf.root.as_str()));
        }
        if let Some(http) = &self.http {
            for v in &http.value {
                if let Some(path) = &v.path {
                    dotdot_fields.push((
                        format!("`[[http.value]] name = \"{}\"` path", v.name),
                        path.as_str(),
                    ));
                }
            }
            if let Some(version) = &http.version {
                for (i, f) in version.files.iter().enumerate() {
                    dotdot_fields.push((format!("`[http.version] files[{i}]`"), f.as_str()));
                }
            }
        }
        for surface in &self.surface {
            for step in &surface.auth {
                let step_name = auth_type_name(step.kind);
                if let Some(path) = &step.path {
                    dotdot_fields.push((
                        format!(
                            "surface \"{}\": a `{step_name}` auth step's `path`",
                            surface.id
                        ),
                        path.as_str(),
                    ));
                }
                if let Some(config_path) = &step.config_path {
                    dotdot_fields.push((
                        format!(
                            "surface \"{}\": a `{step_name}` auth step's `config_path`",
                            surface.id
                        ),
                        config_path.as_str(),
                    ));
                }
                if let Some(client) = &step.client {
                    for (i, f) in client.files.iter().enumerate() {
                        dotdot_fields.push((
                            format!(
                                "surface \"{}\": a `{step_name}` auth step's `client.files[{i}]`",
                                surface.id
                            ),
                            f.as_str(),
                        ));
                    }
                }
            }
        }
        if let Some((where_it_is, _)) = dotdot_fields
            .iter()
            .find(|(_, text)| has_dotdot_component(text))
        {
            return Err(format!(
                "{where_it_is} contains a `..` component — refused before it can read outside \
                 the directory this app was meant to confine it to"
            ));
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
            // once for the one request an `http-api` manifest must declare
            // (`validate` refuses anything else), and only ever zero for a
            // manifest whose own engine never reads `[http]` at all and still
            // carries the section.
            for value in &http.value {
                templates.push((
                    format!("`[[http.value]] name = \"{}\"` path", value.name),
                    value.path.as_deref().unwrap_or(""),
                    Substituted::Nothing,
                ));
            }
            // `[http.version] files` — read verbatim by `resolve_version`,
            // the same as `client.files` below: nothing substitutes a
            // version file's own path, so a stray `{token}` in one would be
            // a directory name with braces in it, not a credential.
            if let Some(version) = &http.version {
                for (i, f) in version.files.iter().enumerate() {
                    templates.push((
                        format!("`[http.version] files[{i}]`"),
                        f.as_str(),
                        Substituted::Nothing,
                    ));
                }
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

/// Whether `text` contains a raw placeholder marker more times than
/// [`placeholders`] actually recognised out of it — the signature of one
/// having been swallowed.
///
/// [`placeholders`] (and `engine_http::substitute`, which it mirrors) pairs a
/// `{` with the *first* `}` that follows it, whatever text sits in between —
/// exactly right for the ordinary case, where nothing is ever written
/// starting with an unrelated `{`. A request body is the case that motivated
/// this — every JSON object opens with `{`, and that leading, purely
/// structural brace pairs with a real placeholder's own closing one before
/// either scanner ever reads the placeholder's name, so `{"auth":"{token}"}`
/// finds its first `}` closing `{token}`, not the (later, real) end of the
/// object, mailing it on the wire exactly as written — but nothing about the
/// shape is body-specific: a header value someone wrote a JSON fragment
/// into, or a URL whose query string opens with an unrelated `{`, swallow a
/// later placeholder the identical way, so this is checked against every
/// one of a request's texts (`validate`'s own call site), not the body
/// alone. The garbled "name" this produces starts with neither `value.` nor
/// `option.`, so the undeclared-placeholder loop in `validate` never sees it
/// either — this is the one shape that loop cannot catch, which is why it
/// gets a check of its own rather than folding into it.
///
/// Checked one marker at a time, and by raw-vs-recognised count rather than
/// by position, because the two counts can disagree in only one direction —
/// swallowed placeholders are always undercounted, never overcounted — and
/// because a text can swallow one marker while substituting another
/// correctly a few characters later (the case that found this: `{token}`
/// resolved fine while `{option.plugin}` earlier in the same string did
/// not).
/// The three placeholder markers checked in both [`swallowed_placeholder`]
/// and [`url_placeholder`] — everywhere a `{token}`/`{version}`/`{value.…}`
/// swallowed by an earlier, structural `{` gets caught. `{option.` is
/// deliberately not a fourth entry here: a `[plugin.<id>].option.<key>`
/// value substitutes fine anywhere in a URL, including its query string, so
/// [`url_placeholder`] leaves it out on purpose, not by omission —
/// [`swallowed_placeholder`] still checks it, on its own, after this list,
/// since a swallowed brace inside `{option.<key>}` breaks the same way
/// whichever text it lands in.
const HEADER_ONLY: [&str; 3] = ["{token}", "{version}", "{value."];

fn swallowed_placeholder(text: &str) -> Option<&'static str> {
    let names = placeholders(text);
    let raw = |marker: &str| text.matches(marker).count();
    let recognized_exact = |name: &str| names.iter().filter(|n| **n == name).count();
    let recognized_prefix = |prefix: &str| names.iter().filter(|n| n.starts_with(prefix)).count();
    let [token_marker, version_marker, value_marker] = HEADER_ONLY;
    if raw(token_marker) > recognized_exact("token") {
        return Some("{token}");
    }
    if raw(version_marker) > recognized_exact("version") {
        return Some("{version}");
    }
    if raw(value_marker) > recognized_prefix("value.") {
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
    if rest.contains('}') {
        Some("a `}` with no `{` before it")
    } else {
        None
    }
}

/// Cap on `[[windows]] id`, and, sharing the same constant, `[[balances]]
/// id` (see [`BalanceConfig::entry_key`]).
///
/// Both bound a string that is part of that entry's identity: fed through
/// [`crate::plugin::encode_key_part`] it becomes the `<entry>` half of
/// [`crate::model::Window::key`]/[`crate::model::Balance::key`]
/// (`crate::plugin::window_key`/`balance_key`), the identity this app
/// matches and dedupes readings by across fetches — not, despite an earlier
/// version of this comment, a segment `config::seen_key` writes: that
/// registry keys by *role* ("primary"/"secondary"), not by a window's
/// declared `id`, and never records an `Extra`-role window at all (see
/// `main.rs`'s `seen_role_key`). Capped here rather than left open, because a
/// manifest that already shipped with a 4 KB id would have to keep working.
pub(crate) const WINDOW_ID_MAX_BYTES: usize = 64;

/// The charset, length cap and "starts with a letter or digit" rule shared
/// by `[[windows]] id` and `[[balances]] id` — the same rule for the same
/// reason (see [`WINDOW_ID_MAX_BYTES`]'s own doc), written out identically
/// down to the message shape, with only the section name (`"windows"` or
/// `"balances"`) and the entry's own `label` differing. Callers still guard
/// an empty `id` themselves — an unset one falls back to the entry's
/// position, which this has nothing to say about — so an empty string never
/// reaches here.
fn check_entry_id(id: &str, label: &str, section: &str) -> Result<(), String> {
    let ok = id.len() <= WINDOW_ID_MAX_BYTES
        && id.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !ok {
        return Err(format!(
            "{section}[label = \"{label}\"]: `id = \"{id}\"` must be at most \
             {WINDOW_ID_MAX_BYTES} bytes of lowercase ASCII letters, digits and hyphens, \
             starting with a letter or digit"
        ));
    }
    Ok(())
}

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
    /// their registry entries across edits declares `id`; of the five shipped
    /// manifests, the four that declare any `[[windows]]` at all
    /// (`antigravity`, `claude`, `codex`, `grok`) declare `id` on every one —
    /// the remaining one (`copilot`) reports only `[[balances]]` and has no
    /// windows to give one to.
    pub fn entry_key(&self, index: usize) -> String {
        if self.id.is_empty() {
            format!("w{index}")
        } else {
            self.id.clone()
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
    /// Optional classification bound, read by both engines
    /// (`engine_logfile::classify_slot`, and `engine_http::select_container`
    /// for the `containers` case above): a window is this slot only if its
    /// period is at most this many minutes. Meaningless — and refused by
    /// `validate` — on a window whose `period.mode = "assumed"` already
    /// states the length outright.
    pub max_period_minutes: Option<u64>,
    /// Same as [`max_period_minutes`](Self::max_period_minutes), the other
    /// direction: a window is this slot only if its period is at least this
    /// many minutes.
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
/// are its contract, and a balance has neither to give. Copilot reports no
/// window at all — only a monthly premium-request allowance against a
/// calendar reset — which is why a manifest carrying balances and no windows
/// has to be legal (see [`PluginManifest::validate`]). Grok carries both: a
/// weekly usage-period window alongside two balances against the monthly
/// billing cycle.
///
/// Needs `requires_reader = ["reading-balances"]`: an older build has no notion
/// of a balance, and would show such a provider as one that reported nothing.
#[derive(Debug, Clone, PartialEq, Deserialize)]
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
    /// `[balances.unlimited]` — a boolean flag beside the amount paths above:
    /// when the path it names resolves to `true`, this entry draws as a
    /// single "Unlimited" caption instead of a used/cap/remaining pair (GitHub
    /// Copilot's premium bucket carries `unlimited = true` beside an
    /// `entitlement`/`remaining` pair that reads `0 / 0` for such an account —
    /// indistinguishable, without this, from an exhausted one). `false`,
    /// missing, or not a boolean falls through to the ordinary reading, the
    /// same fail-safe every other boolean-gated figure in this schema uses.
    /// Needs `requires_reader = ["balance-unlimited"]`.
    pub unlimited: Option<BalanceUnlimitedConfig>,
    /// `[balances.when]` — a boolean gate on the *whole entry*: when the path
    /// it names does not resolve to `true` (`false`, missing, or not a
    /// boolean), this entry draws no row at all, as if it named no figure —
    /// the same "no claim about a size nobody stated" rule presence already
    /// applies everywhere else. For a figure the response states only
    /// conditionally (Claude's `extra_usage`, off on most accounts, still
    /// sends the four fields this entry would otherwise read alongside its
    /// own `is_enabled`). Needs `requires_reader = ["balance-conditional"]`.
    pub when: Option<BalanceWhenConfig>,
}

/// `[balances.unlimited]` — see [`BalanceConfig::unlimited`]'s own doc.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct BalanceUnlimitedConfig {
    /// JSON path to the boolean.
    pub path: String,
}

/// `[balances.when]` — see [`BalanceConfig::when`]'s own doc.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct BalanceWhenConfig {
    /// JSON path to the boolean.
    pub path: String,
}

/// One figure inside a `[[balances]]` entry, and where to read it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
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
        if self.id.is_empty() {
            format!("b{index}")
        } else {
            self.id.clone()
        }
    }

    /// Whether this entry reads anything at all. An entry that names no source
    /// draws a label beside empty space. `when` is not counted: it gates
    /// whether the entry draws at all, but states no figure of its own, so an
    /// entry naming only `when` still reads nothing to draw when it passes.
    fn reads_nothing(&self) -> bool {
        self.used.is_none()
            && self.cap.is_none()
            && self.remaining.is_none()
            && self.source.percent_path.is_none()
            && self.source.limit_reached_path.is_none()
            && self.unlimited.is_none()
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
    /// Log file format — the one this engine's readers parse a line as. See
    /// [`LogFileFormat`].
    #[serde(default)]
    pub format: LogFileFormat,
    /// Which reading to keep when a file has more than one. See
    /// [`LogFileSelect`].
    #[serde(default)]
    pub select: LogFileSelect,
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

/// The shape this engine reads a matched line as. One variant today —
/// `engine_logfile::parse_file` matches on it at the point that parses each
/// line, so a manifest naming a format nothing here understands is refused at
/// load rather than read as `jsonl` regardless of what it asked for.
/// `engine_logfile::parse_file_groups` (the secondary-accounts path, reached
/// from `collect_plan_groups`) parses JSONL directly instead, without
/// consulting this field at all — a second variant would have to be threaded
/// there too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogFileFormat {
    /// One JSON object per line.
    #[default]
    Jsonl,
}

/// Which reading this engine keeps, *within one file*, when it holds more
/// than one matching line. One variant today — `engine_logfile::parse_file`
/// matches on it where it decides whether a newly parsed reading replaces the
/// one already kept, so a manifest naming a selection nothing here
/// understands is refused at load rather than read as `last` regardless of
/// what it asked for.
///
/// Choosing *between* the several files a `glob` matches is outside this
/// field's scope: that is `latest_reading`'s own newest-file-first fallback,
/// unconditional and not read from the manifest. `engine_logfile::
/// parse_file_groups` (the secondary-accounts path, reached from
/// `collect_plan_groups`) keeps the strictly-newer-by-timestamp line per
/// account group instead, without consulting this field either — a second
/// variant would have to be threaded there too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogFileSelect {
    /// The most recently written matching reading.
    #[default]
    Last,
}

fn default_classify_threshold_minutes() -> u64 {
    720
}

// ── [http] ────────────────────────────────────────────────────────────────

/// `[http]` — configuration for the `engine = "http-api"` reader.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct HttpConfig {
    /// `[[http.request]]` — the one request this surface issues. `validate`
    /// refuses an `[http]` section with none or with more than one.
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

/// [`HttpVersionConfig::files`]: how many candidates `validate` allows.
/// `resolve_version` tries each in turn until one exists and parses; the
/// shipped `claude.toml` names three (one per platform's npm prefix), so 16
/// is headroom for a provider installed in more places, not a figure any
/// real manifest is expected to approach.
const HTTP_VERSION_FILES_MAX_COUNT: usize = 16;

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
    /// credential store exists but the token couldn't be read — the surface
    /// must stop with an error), or Absent (store doesn't exist — try the next
    /// step, or conclude the surface isn't present if none are left).
    #[serde(default)]
    pub auth: Vec<AuthStep>,
}

impl SurfaceConfig {
    /// Whether this surface's own credential chain states a token lifetime
    /// at all — the manifest's own declaration that *this* surface's token
    /// is the CLI's, renewed by the CLI running, rather than some other
    /// credential (Claude's `desktop` surface reads Electron's
    /// safe-storage: its own separate token, with no `expiry_json_path` on
    /// any step, opt-in, and renewed by the desktop app itself). A plugin's
    /// `[ping] renews_token` names one binary; only a surface this returns
    /// `true` for is the one that binary's run actually renews, so it is
    /// the gate both halves of `[ping] renews_token` use before treating a
    /// surface's failure as renewable — a lapsed auth chain
    /// (`plugin::engine_http::fetch_surface`, which can only produce
    /// `lapsed_expiry: Some` from a step this same field governs, so it
    /// needs no separate check) and a bare HTTP 401
    /// (`plugin::engine_http::unauthorized_outcome`, which does).
    pub fn declares_token_expiry(&self) -> bool {
        self.auth.iter().any(|step| step.expiry_json_path.is_some())
    }
}

/// One step of a `[[surface.auth]]` chain.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AuthStep {
    /// Which credential store this step reads from.
    #[serde(rename = "type")]
    pub kind: AuthType,

    /// `credentials-file` / `credentials-map`: path to the JSON file.
    pub path: Option<String>,
    /// `credentials-file` only: env var that, if set to an absolute path,
    /// overrides `path`'s directory — the credential variant of
    /// `[logfile] root_env` (see that field's own doc), additionally
    /// ignoring an env value that is empty or relative, falling back to
    /// `path` exactly as if the variable were unset (a credential must never
    /// be read relative to this process's own working directory). For
    /// Claude, whose CLI honours `CLAUDE_CONFIG_DIR` for both its
    /// credentials file and its Keychain item name: this covers the file,
    /// naming the keychain item is out of scope (see the comment on
    /// claude.toml's own step). `false`/refused on any other step kind, the
    /// same rule `expiry_json_path` is refused under above. Needs
    /// `requires_reader = ["credentials-file-path-env"]`.
    #[serde(default)]
    pub path_env: Option<String>,
    /// Filename appended onto the `path_env` override, if set (e.g.
    /// `".credentials.json"` so `$CLAUDE_CONFIG_DIR` resolves to
    /// `$CLAUDE_CONFIG_DIR/.credentials.json`). Ignored when `path_env` is
    /// unset or the env var itself isn't; has no effect on the plain `path`
    /// fallback, which is used verbatim — mirrors `[logfile] root_env_join`
    /// exactly.
    #[serde(default)]
    pub path_env_join: Option<String>,
    /// `credentials-file` / `keychain` / `credentials-map`: JSON path(s) to
    /// the token inside the credential payload (for `credentials-map`, inside
    /// the *matched entry* — see `key_prefix`); `|`-separated fallback keys,
    /// tried in order (e.g. `"claudeAiOauth.accessToken|access_token"`) — see
    /// [`split_fallback_keys`].
    pub token_json_path: Option<String>,

    /// `keychain`, `credentials-file`, `win-credential`, `credentials-map`
    /// only — `validate` refuses it on any other step kind, naming the
    /// step's index and kind: the first three read one JSON blob holding
    /// both the token and its expiry directly (`auth::token_from_blob`);
    /// `credentials-map` reads it from the same *matched entry* its own
    /// token comes from (`auth::credentials_map_step`) — every other kind
    /// never reads this field at all. Optional JSON path to an expiry beside
    /// the token — an RFC3339 string, or a JSON number (or numeric string)
    /// read as epoch seconds or milliseconds (told apart by magnitude; see
    /// `auth::token_expiry_at`). When set and the moment it names is in the
    /// past (with a small margin), the step resolves **Absent** rather than
    /// handing back the stale token — so a chain can fall through to a
    /// refresh step behind it, or (with `[ping] renews_token`) let the
    /// engine ask for a renewal. Without it a step returns whatever token it
    /// finds, fresh or not (the behaviour every existing manifest relies
    /// on). Antigravity's keychain item carries `token.expiry` as RFC3339;
    /// Claude's credentials file carries `claudeAiOauth.expiresAt` as epoch
    /// milliseconds — this lets a build tell "signed in, current" from
    /// "signed in, but the token lapsed" from either shape. Needs
    /// `requires_reader = ["keychain-expiry"]`.
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
    /// is present, the chain stops with `message`.
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

/// Whether `spec` contains a `..` path component — split on both
/// separators (a manifest is cross-platform data, so a Windows-shaped value
/// on this platform's own `Path` still has to be caught), not searched for
/// as a substring, so a filename that merely contains two literal dots
/// without being a parent reference (`archive..bak`) is not refused for the
/// wrong reason.
fn has_dotdot_component(spec: &str) -> bool {
    spec.split(['/', '\\']).any(|segment| segment == "..")
}

/// Windows's reserved device names, compared case-insensitively against a
/// plugin `id` — `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`. A
/// file named exactly one of these, with or without an extension, opens the
/// device instead of a file on that platform: `registry.rs`'s own manifest-id
/// rule needs the identical list for the same reason (a registry entry's id
/// becomes the same `<id>.toml`), kept as a comment there rather than a
/// shared function across a module boundary this file does not own.
fn is_windows_reserved_device_name(name: &str) -> bool {
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    RESERVED
        .iter()
        .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

/// [`AuthClientDiscovery::bins`]: a bare program name — no separator, no
/// `..` component, no drive prefix — the shape `auth::bin_candidates` joins
/// a directory onto. `files` has no equivalent rule: it is already a path,
/// by design (see the field's own doc).
///
/// `name != ".."`, not `!name.contains("..")`: with no separator already
/// refused a line above, `name` joins onto a directory as a single path
/// component (`Path::join`), and only the exact string `".."` is that
/// component ever reading as a parent-directory reference — a name that
/// merely contains two dots without being that whole component
/// (`my..tool`) walks nowhere and was refused for no reason.
fn is_bare_program_name(name: &str) -> bool {
    let has_drive_prefix =
        name.len() >= 2 && name.as_bytes()[0].is_ascii_alphabetic() && name.as_bytes()[1] == b':';
    !name.is_empty() && !name.contains(['/', '\\']) && name != ".." && !has_drive_prefix
}

/// Whether `p` would be an absolute path on *some* platform this app runs
/// on, not merely the one validating it. `Path::is_absolute()` answers only
/// for the platform this binary happens to be compiled for: on Windows,
/// `/Applications/Antigravity.app/…` — an entirely ordinary POSIX absolute
/// path, and exactly what the shipped Antigravity manifest's `client.files`
/// names — is *not* absolute, because Windows requires a drive letter or a
/// UNC prefix; on macOS/Linux the reverse holds for `C:\Program Files\…` or
/// `\\server\share\…`, a client's own path on a Windows install. A plugin
/// manifest is cross-platform data (the same `antigravity.toml` ships to
/// macOS and Windows installs alike); a candidate written for one platform
/// is simply a file that will never exist at discovery time on another — not
/// a reason to refuse the *manifest* at load, on every platform, for a path
/// some other platform wrote. `Path::is_absolute()` still covers this
/// platform's own notion; the three prefix checks beside it — a leading
/// `/`, a drive letter (`C:\` or `C:/`), a UNC `\\` — cover every other
/// platform's, read off the lossy string rather than through whatever this
/// binary's own `Path` would parse them as.
fn is_absolute_on_any_platform(p: &Path) -> bool {
    let s = p.to_string_lossy();
    let has_drive_prefix = s.len() >= 3
        && s.as_bytes()[0].is_ascii_alphabetic()
        && s.as_bytes()[1] == b':'
        && matches!(s.as_bytes()[2], b'/' | b'\\');
    p.is_absolute() || s.starts_with('/') || has_drive_prefix || s.starts_with("\\\\")
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

/// Whether `text` carries a control character (`char::is_control` — ASCII
/// 0x00–0x1F, DEL, and the 0x80–0x9F Latin-1 range for free) or a character
/// that reorders or terminates a line without looking like it does: the
/// Unicode line/paragraph separators `is_control` does not cover (U+2028/
/// U+2029), and the bidi marks, embeddings/overrides and isolates (U+200E/F,
/// U+202A–E, U+2066–9) that can visually reorder whatever follows them or
/// hide where a message actually ends.
///
/// The [`CharClass::Narrow`] half of [`control_char_field_is_disruptive`] —
/// deliberately not [`super::is_invisible_or_directional`]: that one also
/// strips zero-width joiners, variation selectors and the soft hyphen, which
/// change how *rendered* text looks (an emoji sequence like "👨‍💻" is a base
/// character plus a zero-width joiner, and most emoji carry a trailing
/// variation selector) but do not split a line or reorder a dialog. A field
/// this narrow class covers is display text the app's own UI renders after
/// install — a section header, a menu-bar pill, a row caption, a panel
/// message — never an install-time trust dialog and never a file, a host or
/// a program name; refusing an emoji sequence there would reject an
/// otherwise harmless third-party manifest for no reason connected to the
/// hazard this check exists to catch.
fn has_disruptive_control_char(text: &str) -> bool {
    text.chars().any(|c| {
        c.is_control()
            || matches!(
                c,
                '\u{2028}' | '\u{2029}'
                    | '\u{200E}' | '\u{200F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2066}'..='\u{2069}'
            )
    })
}

/// Which class of "disruptive" character one of `validate`'s swept
/// `control_char_fields` is checked against — see
/// [`has_disruptive_control_char`] for the narrow class's own reasoning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CharClass {
    /// Display text the app's own UI renders after install — refused only
    /// for a control character or a bidi override, never for the zero-width
    /// class a legitimate emoji sequence uses.
    Narrow,
    /// A field that reaches `registry::analyze_trust`'s install-time trust
    /// dialog, or is resolved directly against the filesystem or the
    /// network (a program name, a file path, a host, a URL) — refused for
    /// [`super::is_invisible_or_directional`]'s full zero-width class too,
    /// on top of the narrow one: a zero-width character there could make two
    /// different disclosures, or two different destinations, render
    /// identically. The same predicate `main.rs::sanitize_trust_item` shares
    /// with `sanitize_provider_text`, checked here at load rather than
    /// laundered at render time so the manifest author sees why.
    Wide,
}

/// Dispatch to the class `text` was tagged with in `control_char_fields`.
fn control_char_field_is_disruptive(text: &str, class: CharClass) -> bool {
    match class {
        CharClass::Narrow => has_disruptive_control_char(text),
        CharClass::Wide => text
            .chars()
            .any(|c| c.is_control() || super::is_invisible_or_directional(c)),
    }
}

/// The bounds on how many bytes any match of `pattern` could ever return —
/// `.0` the most (`None` for an unbounded repeat like `.*`/`[a-z]+`, and
/// also, less obviously, whenever `regex_syntax` simply has no byte-length
/// answer for the pattern at all rather than a genuinely infinite one — its
/// own `Properties::maximum_len` does not distinguish the two, so neither
/// does this), `.1` the fewest (`0` for a pattern that can match the empty
/// string, e.g. `a*` or `(foo)?`; `None` when the parse fails —
/// unreachable at the one call site, which only ever runs a pattern
/// `regex::bytes::Regex::new` already compiled — or when `regex_syntax`
/// says the pattern can never match anything at all, an empty intersection
/// like `[a&&b]`, not merely an unmeasured minimum). `PluginManifest::validate`'s
/// call site needs both for the same pattern and names the two `None`s
/// differently in the messages it returns, so they stay separate `Option`s
/// rather than folding into one meaning — a ceiling this cannot compute is
/// refused like no ceiling, but a floor of `None` is not the same claim as a
/// floor of `Some(0)`, and only the latter is actually "matches the empty
/// string".
///
/// One `regex_syntax` parse for both, rather than two independent ones each
/// computing its own half: parsed directly rather than derived from a
/// compiled `regex::bytes::Regex` (which exposes neither), the same grammar
/// `regex::bytes::Regex` compiles, so a pattern this measures as unbounded
/// is exactly one that engine would have matched as unboundedly long.
fn regex_len_bounds(pattern: &str) -> (Option<usize>, Option<usize>) {
    let Ok(hir) = regex_syntax::Parser::new().parse(pattern) else {
        return (None, None);
    };
    let props = hir.properties();
    (props.maximum_len(), props.minimum_len())
}

/// The most bytes any match of `pattern` could ever return — see
/// [`regex_len_bounds`] for what `None` means here.
///
/// `pub(crate)`, not private: `auth::compile_scan_pattern` reads this same
/// figure to decide whether a discovery pattern's match has already reached
/// its own maximum length (and so needs no deferral at a chunk boundary —
/// see `auth::accept_settled_match`'s own doc). One function, not two
/// independent copies of this parse, so validation's finite-maximum
/// requirement and the scanner's deferral rule can never disagree about
/// what a given pattern's maximum actually is.
pub(crate) fn regex_max_match_len(pattern: &str) -> Option<usize> {
    regex_len_bounds(pattern).0
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
    let [token_marker, version_marker, value_marker] = HEADER_ONLY;
    if url.contains(token_marker) {
        return Some("`{token}`");
    }
    if url.contains(version_marker) {
        return Some("`{version}`");
    }
    if url.contains(value_marker) {
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
    /// Whether running this command also renews the provider's token, as a
    /// side effect the provider's own CLI has and this app does not (it never
    /// spends a provider's refresh token — see `plugin::throttle`'s module
    /// doc). A surface whose auth chain ends "lapsed" (see
    /// `plugin::auth::TOKEN_LAPSED`) is a token nothing here can renew on its
    /// own. With `renews_token = false` (the default, and the whole story
    /// for a manifest with no `[ping]` at all), a lapsed token still keeps
    /// its row on screen — reading `engine_http::LAPSED`'s text, "token
    /// expired — sign in again" — rather than being hidden the way an
    /// absent credential is by default (a surface's `no_credentials_message`
    /// keeps that row too); only the user's own next sign-in clears it.
    /// `renews_token = true` runs this command in that same spot instead,
    /// bounded by the same ten-minute floor the window ping shares. Default
    /// `false`: without it, this field simply does not exist for a manifest
    /// that predates it.
    #[serde(default)]
    pub renews_token: bool,
}

/// [`PingConfig::args`]: how many arguments `validate` allows. A ping is a
/// short, fixed command line (`codex exec hello`, three words) — not a
/// figure tuned to any one provider.
const PING_ARGS_MAX_COUNT: usize = 32;

/// [`PingConfig::args`]: how many bytes one argument may be. Bounded so a
/// single entry cannot push the untrusted-host clause off the bottom of the
/// install-time trust dialog that renders the whole command line.
const PING_ARG_MAX_BYTES: usize = 256;

// ── [[option]] ────────────────────────────────────────────────────────────

/// One `[[option]]` — a declarative bool option a plugin exposes, resolved by
/// `crate::config::plugin_option` and made available to the engines as the
/// `{option.<key>}` substitution (see [`crate::plugin::substitute_options`]).
/// Settings draws no checkbox for these yet; this schema layer is
/// UI-agnostic.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct OptionConfig {
    /// Stable identifier, unique within the plugin. Restricted to ASCII
    /// letters/digits/underscore (see [`PluginManifest::validate`]) so the
    /// `{option.<key>}` placeholder it drives is always unambiguous.
    pub key: String,
    /// Display label for the checkbox Settings does not yet draw.
    pub label: String,
    /// Value used until the user overrides it via config.
    #[serde(default)]
    pub default: bool,
}

// ── Directory loading ─────────────────────────────────────────────────────

/// Read every `*.toml` file directly inside `dir` as a [`PluginManifest`],
/// sorted by declared `order` (ties broken by `id`). Manifests that fail to
/// parse or validate are returned as `Err((path, message))` and sort after
/// every successfully-loaded manifest, keeping their lexicographic
/// (path-sorted) relative order among themselves — the paths are sorted
/// before `load_one` ever runs, and the final sort is stable, so a
/// directory-listing order this platform happened to hand back never leaks
/// through.
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
    // Plain `read_to_string` would block forever on a FIFO planted at this
    // path and has no size cap of its own — the same hazard
    // `read_regular_file`'s own doc describes for a credentials file, and
    // this one is read on every plugin-directory scan (a fresh install, a
    // Reset plugins, an "Add plugin"), not once at startup.
    let text = super::read_regular_file(path, super::SMALL_FILE_MAX_BYTES).ok_or_else(|| {
        "not a readable regular file, or larger than this app will read".to_string()
    })?;
    PluginManifest::from_str(&text)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A Codex-like manifest: `engine = "log-file"`, one primary window
    /// classified `from_field`, one secondary window classified `assumed`
    /// (a bound beside `assumed` is legal on this engine — see `validate`,
    /// which refuses that combination only on `engine = "http-api"`).
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
        assert_eq!(lf.format, LogFileFormat::Jsonl, "format defaults to jsonl");
        assert_eq!(lf.select, LogFileSelect::Last, "select defaults to last");
        assert_eq!(lf.container_key, "rate_limits");
        assert_eq!(lf.classify_threshold_minutes, 720, "default threshold");

        assert!(m.http.is_none());

        let ping = m.ping.as_ref().expect("[ping] section");
        assert_eq!(ping.bin, "codex");
        assert_eq!(ping.args, vec!["exec".to_string(), "hello".to_string()]);
        assert!(
            !ping.renews_token,
            "a manifest that never mentions the field must not renew a token"
        );

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

        // The same forward-compatibility rule holds for `[status]`
        // (`StatusConfig`) and every table inside `[[balances]]`
        // (`BalanceConfig`, `AmountConfig`, `BalanceSourceConfig`) — all four
        // `deny_unknown_fields` was mistakenly applied to and then removed
        // from (see the module doc and `AuthClientDiscovery`'s own doc for
        // the one table that keeps it). No windows here: `[[balances]]` is
        // legal without any (Grok ships exactly that shape), which also
        // keeps this manifest away from the http-api "exactly one window
        // figure" rules that windows would pull in for no reason this test
        // cares about.
        let with_extra_status_and_balance_fields = r#"
            id              = "y"
            name            = "Y"
            menu_label      = "Y"
            order           = 1
            engine          = "http-api"
            requires_reader = ["reading-status", "reading-balances"]

            [status]
            allowed_path       = "allowed"
            future_status_field = "some value from a newer schema version"

            [[balances]]
            label = "Credits"
            future_balance_field = "some value from a newer schema version"
            [balances.remaining]
            kind = "text"
            path = "credits.balance"
            future_amount_field = "some value from a newer schema version"
            [balances.source]
            percent_path = "credits.percent"
            future_source_field = "some value from a newer schema version"

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
            type            = "credentials-file"
            path            = "~/.y/auth.json"
            token_json_path = "token"
        "#;
        let m = PluginManifest::from_str(with_extra_status_and_balance_fields)
            .expect("unknown fields in [status]/[[balances]] must not break parsing either");
        assert_eq!(m.id, "y");
    }

    #[test]
    fn an_unsupported_logfile_format_or_select_is_refused_not_silently_ignored() {
        // `format`/`select` are typed enums with one variant each — the same
        // shape `engine` already is — so a value neither names is refused by
        // the typed parse itself, the way an unrecognized `engine` already
        // is, rather than loading and being read as whatever this build
        // happens to default to.
        for (field, bad) in [("format", "yaml"), ("select", "first")] {
            let manifest = format!(
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
                    root          = "~/.x"
                    glob          = "*.jsonl"
                    container_key = "rate_limits"
                    {field}        = "{bad}"
                "#
            );
            let err = PluginManifest::from_str(&manifest)
                .expect_err(&format!("`{field} = \"{bad}\"` must be refused"));
            assert!(
                err.contains(bad),
                "the refusal must name the unrecognized value — {err}"
            );
        }
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
        // Bare `is_err()` would pass just as well for a manifest refused for
        // an entirely different reason — this one also carries no `[logfile]`
        // and no `[http]`, either of which `validate` would refuse on its
        // own. Naming the field pins the refusal to the one this row is
        // actually about: `engine` itself, missing from the TOML, is what
        // `toml::from_str` reports before `validate` ever runs.
        let err = PluginManifest::from_str(no_engine).expect_err("must be rejected");
        assert!(err.contains("engine"), "unexpected error: {err}");

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
            "[[http.value]]\nname = \"dupval\"\ntype = \"json-file\"\npath = \"p\"\njson_path = \"j\"\n\
             [[http.value]]\nname = \"dupval\"\ntype = \"json-file\"\npath = \"p\"\njson_path = \"j\"",
            "",
        );
        let err = PluginManifest::from_str(&duplicate).expect_err("must be rejected");
        assert!(
            err.contains("dupval"),
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
        //
        // Built on `http_manifest_with` rather than spliced onto `CODEX_LIKE`
        // (an `engine = "log-file"` fixture): `engine = "log-file"` now
        // refuses an `[http]` section outright, so appending one would trip
        // that rule instead of the one this test means to exercise.
        let toml = http_manifest_with(
            "",
            "",
            "[[http.value]]\nname = \"a\"\ntype = \"json-file\"\n\
             path = \"~/{option.where}/x.json\"\njson_path = \"a\"",
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
    /// This is not a hypothetical: a provider's billing endpoint may carry no
    /// window key in any shape it answers with, only a calendar period. Until
    /// this test passed, such a provider could not be written as a plugin —
    /// `validate` required a window — which is the one thing "every AI
    /// arrives as a plugin" rules out.
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
    fn a_balance_unlimited_path_parses_and_needs_its_own_capability() {
        let toml = BALANCES_ONLY.replace(
            "[balances.source]",
            "[balances.unlimited]\n        path = \"config.unlimited\"\n        [balances.source]",
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("balances.unlimited.path without its own capability is refused");
        assert!(err.contains("balance-unlimited"), "{err}");

        let declared = toml.replace(
            "requires_reader = [\"reading-balances\"]",
            "requires_reader = [\"reading-balances\", \"balance-unlimited\"]",
        );
        let m = PluginManifest::from_str(&declared).expect("declared, the manifest parses");
        assert_eq!(
            m.balances[0].unlimited.as_ref().map(|u| u.path.as_str()),
            Some("config.unlimited")
        );
    }

    #[test]
    fn a_balance_when_path_parses_and_needs_its_own_capability() {
        let toml = BALANCES_ONLY.replace(
            "[balances.source]",
            "[balances.when]\n        path = \"config.enabled\"\n        [balances.source]",
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("balances.when.path without its own capability is refused");
        assert!(err.contains("balance-conditional"), "{err}");

        let declared = toml.replace(
            "requires_reader = [\"reading-balances\"]",
            "requires_reader = [\"reading-balances\", \"balance-conditional\"]",
        );
        let m = PluginManifest::from_str(&declared).expect("declared, the manifest parses");
        assert_eq!(
            m.balances[0].when.as_ref().map(|w| w.path.as_str()),
            Some("config.enabled")
        );
    }

    /// `when` alone, with no `used`/`cap`/`remaining`/`source.*`, is not a
    /// figure — `unlimited` alone is, since it is the figure itself. Pinned
    /// together so `reads_nothing`'s asymmetry between the two is a decision,
    /// not an accident.
    #[test]
    fn when_alone_reads_nothing_but_unlimited_alone_does() {
        let base = BALANCES_ONLY.replace(
            "[balances.used]\n        kind = \"number\"\n        path = \"config.used.val\"\n        \
             unit_label = \"credits\"\n        [balances.cap]\n        kind = \"number\"\n        \
             path = \"config.monthlyLimit.val\"\n        ",
            "",
        );

        let when_only = base
            .replace(
                "[balances.source]",
                "[balances.when]\n        path = \"config.enabled\"\n        [balances.source]",
            )
            .replace(
                "requires_reader = [\"reading-balances\"]",
                "requires_reader = [\"reading-balances\", \"balance-conditional\"]",
            );
        let err = PluginManifest::from_str(&when_only)
            .expect_err("when names no figure of its own — the entry still reads nothing");
        assert!(err.contains("names no figure"), "{err}");

        let unlimited_only = base
            .replace(
                "[balances.source]",
                "[balances.unlimited]\n        path = \"config.unlimited\"\n        [balances.source]",
            )
            .replace(
                "requires_reader = [\"reading-balances\"]",
                "requires_reader = [\"reading-balances\", \"balance-unlimited\"]",
            );
        PluginManifest::from_str(&unlimited_only)
            .expect("unlimited is itself a figure worth an entry");
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

    /// `path` is `number`/`text`'s own field — neither engine ever reads it
    /// for `money-minor`, which takes its figure from `amount_path`/
    /// `currency_path`/`exponent_path` instead.
    #[test]
    fn a_money_minor_amount_naming_path_is_refused() {
        let toml = BALANCES_ONLY.replace(
            "kind = \"number\"\n        path = \"config.used.val\"\n        unit_label = \"credits\"",
            "kind          = \"money-minor\"\n        path          = \"config.used.val\"\n        \
             amount_path   = \"config.used.val\"\n        currency_path = \"config.currency\"\n        \
             exponent_path = \"config.exponent\"",
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("path belongs to number/text, not money-minor");
        assert!(err.contains("`path` belongs to"), "{err}");
    }

    /// The mirror: `amount_path`/`currency_path`/`exponent_path` are
    /// `money-minor`'s own triplet — a `number` amount naming one loads
    /// clean and it is silently never read.
    #[test]
    fn a_number_amount_naming_a_money_minor_field_is_refused() {
        let toml = BALANCES_ONLY.replace(
            "kind = \"number\"\n        path = \"config.used.val\"\n        unit_label = \"credits\"",
            "kind = \"number\"\n        path = \"config.used.val\"\n        unit_label = \"credits\"\n        \
             amount_path = \"config.used.val\"",
        );
        let err =
            PluginManifest::from_str(&toml).expect_err("amount_path belongs to money-minor only");
        assert!(err.contains("amount_path"), "{err}");
        assert!(err.contains("money-minor"), "{err}");
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
        // undeclared-placeholder rule sees this; only `swallowed_placeholder`
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

    #[test]
    fn a_json_shaped_header_value_swallows_its_own_placeholder() {
        // Nothing about `swallowed_placeholder`'s scan is body-specific — a
        // header value someone wrote a JSON fragment into loses its
        // placeholder the identical way; this used to only be checked for
        // `body`.
        let toml = HTTP_POST_BASE.replace(
            "Authorization  = \"Bearer {token}\"",
            "Authorization  = \"{\\\"a\\\":\\\"{token}\\\"}\"",
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("a JSON-shaped header value swallows its own placeholder");
        assert!(err.contains("{token}"), "{err}");
        assert!(
            err.contains("header"),
            "the refusal must name the header — {err}"
        );
    }

    #[test]
    fn a_json_shaped_url_swallows_its_own_placeholder() {
        // And a URL whose query string opens with an unrelated `{` (not a
        // realistic URL, but a real string, and the scan does not know the
        // difference) swallows the same way.
        let toml = HTTP_POST_BASE.replace(
            "url = \"https://example.com/v1internal:retrieveUserQuotaSummary\"",
            "url = \"https://example.com/{\\\"a\\\":\\\"{option.deep}\\\"}\"",
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("a JSON-shaped URL swallows its own placeholder");
        assert!(err.contains("{option.<key>}"), "{err}");
        assert!(
            err.contains("`[[http.request]] url`"),
            "the refusal must name the url — {err}"
        );
    }

    /// Nothing about `swallowed_placeholder`'s scan is http-specific either —
    /// `[logfile] root` gets the same `{option.<key>}` substitution
    /// (`engine_logfile::resolve_root`) and loses a placeholder the same
    /// way; this used to only be checked for `[[http.request]]`'s own
    /// fields.
    #[test]
    fn a_logfile_root_swallows_its_own_placeholder() {
        let toml = CODEX_LIKE.replace(
            "root          = \"~/.codex/sessions\"",
            "root          = \"~/{\\\"a\\\":\\\"{option.deep}\\\"}\"",
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("a JSON-shaped root swallows its own placeholder");
        assert!(err.contains("{option.<key>}"), "{err}");
        assert!(err.contains("`[logfile] root`"), "{err}");
    }

    /// Same shape, for `glob` — substituted by the same `resolve_root`-
    /// adjacent code path (`fetch`'s own `substitute_options(&lf.glob, …)`).
    #[test]
    fn a_logfile_glob_swallows_its_own_placeholder() {
        let toml = CODEX_LIKE.replace(
            "glob          = \"**/rollout-*.jsonl\"",
            "glob          = \"{\\\"a\\\":\\\"{option.deep}\\\"}\"",
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("a JSON-shaped glob swallows its own placeholder");
        assert!(err.contains("{option.<key>}"), "{err}");
        assert!(err.contains("`[logfile] glob`"), "{err}");
    }

    /// And `root_env_join`, appended onto `root_env`'s own resolved value
    /// (`engine_logfile::resolve_root`) — the third and last field
    /// `substitute_options`'s own doc names for this engine.
    #[test]
    fn a_logfile_root_env_join_swallows_its_own_placeholder() {
        let toml = CODEX_LIKE.replace(
            "root          = \"~/.codex/sessions\"",
            "root          = \"~/.codex/sessions\"\n        \
             root_env_join = \"{\\\"a\\\":\\\"{option.deep}\\\"}\"",
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("a JSON-shaped root_env_join swallows its own placeholder");
        assert!(err.contains("{option.<key>}"), "{err}");
        assert!(err.contains("`[logfile] root_env_join`"), "{err}");
    }

    /// And `[account] url`, which `resolve_account_url` substitutes exactly
    /// like `[[http.request]] url` — the fourth field, and the only one
    /// outside `[logfile]`/`[[http.request]]` this sweep now covers.
    #[test]
    fn an_account_url_swallows_its_own_placeholder() {
        let toml = format!(
            "{HTTP_POST_BASE}\n[account]\ntype = \"http\"\n\
             url = \"https://example.com/{{\\\"a\\\":\\\"{{option.deep}}\\\"}}\"\n\
             json_path = \"email\""
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("a JSON-shaped account url swallows its own placeholder");
        assert!(err.contains("{option.<key>}"), "{err}");
        assert!(err.contains("`[account] url`"), "{err}");
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

    /// `Some("")` satisfies `is_some()` — present, and blank
    /// (`json_path_get` reads `segments("")` as `[""]`, matching nothing on
    /// a real response) — refused outright now, same as `[status]`'s own
    /// paths, rather than merely excluded from "one of the two is named".
    #[test]
    fn a_blank_remaining_fraction_path_is_refused() {
        let toml = REMAINING_BASE.replace(
            "remaining_fraction_path = \"groups.0.buckets.0.remainingFraction\"",
            "remaining_fraction_path = \"\"",
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("a blank remaining_fraction_path must be refused");
        assert!(err.contains("remaining_fraction_path"), "{err}");
        assert!(err.contains("present but blank"), "{err}");
    }

    /// The mirror, and the one that matters most: `engine_http::build_window`
    /// matches `(&used_percent_path, &remaining_fraction_path)` on
    /// *`Some`-ness*, not on which one actually resolves — a blank
    /// `used_percent_path` beside a perfectly good `remaining_fraction_path`
    /// would win that match arm, read nothing at `json_path_get(v, "")`, and
    /// silently drop the whole window at every fetch, even though the
    /// manifest plainly stated a real figure one field over. Refused
    /// outright, the same as the field above, closes that rather than only
    /// excluding it from "name only one" below.
    #[test]
    fn a_blank_used_percent_path_beside_a_real_remaining_fraction_path_is_refused() {
        let toml = REMAINING_BASE.replace(
            "remaining_fraction_path = \"groups.0.buckets.0.remainingFraction\"",
            "remaining_fraction_path = \"groups.0.buckets.0.remainingFraction\"\n\
             used_percent_path       = \"\"",
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("a blank used_percent_path must be refused even beside a real figure");
        assert!(err.contains("used_percent_path"), "{err}");
        assert!(err.contains("present but blank"), "{err}");
    }

    /// `resets_at_path` has no `Option` to be absent through — a manifest
    /// author can still leave it blank, and blank resolves to nothing on
    /// every fetch exactly like the two figure paths above.
    #[test]
    fn a_blank_resets_at_path_is_refused() {
        let toml = REMAINING_BASE.replace(
            "resets_at_path          = \"groups.0.buckets.0.resetTime\"",
            "resets_at_path          = \"\"",
        );
        let err =
            PluginManifest::from_str(&toml).expect_err("a blank resets_at_path must be refused");
        assert!(err.contains("resets_at_path"), "{err}");
        assert!(err.contains("must not be blank"), "{err}");
    }

    /// `min_period_minutes` greater than `max_period_minutes` bounds an
    /// empty range — nothing a response could report satisfies both, so
    /// this window would never classify a candidate on either engine.
    /// Built on [`CODEX_LIKE`] (log-file) rather than [`REMAINING_BASE`]
    /// (http-api): a bound beside `period.mode = "assumed"` on the http
    /// engine already trips a different, unrelated refusal, and this needs
    /// to isolate the one min/max is actually testing.
    #[test]
    fn min_period_minutes_greater_than_max_period_minutes_is_refused() {
        let toml = CODEX_LIKE.replace(
            "max_period_minutes = 720",
            "min_period_minutes = 900\n        max_period_minutes = 720",
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("min greater than max classifies nothing, ever");
        assert!(err.contains("min_period_minutes"), "{err}");
        assert!(err.contains("max_period_minutes"), "{err}");
    }

    /// A one-element `auth_claim` whose one segment is blank passes
    /// `is_empty()` (the vec has an element) just as surely as a wholesale
    /// empty vec would have — `resolve_account_match` still walks a
    /// `.get("")` no real JWT claims object ever has a key for, so this must
    /// be refused the same way.
    #[test]
    fn an_auth_claim_with_a_blank_segment_is_refused() {
        let toml = format!(
            "{CODEX_LIKE}\n[logfile.account_match]\ncontainer_field = \"plan_type\"\n\
             auth_claim = [\"\"]"
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("an auth_claim segment that is blank must be refused");
        assert!(err.contains("auth_claim"), "{err}");
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

    /// `expiry_json_path` is read only by `credentials_file_step`/
    /// `keychain_step`/`win_credential_step` (`auth::token_from_blob`,
    /// shared by all three) and `credentials_map_step` (its own matched
    /// entry, via `auth::stale_expiry_at`) — every other step kind never
    /// reads it at all, so a manifest setting it there would still trip
    /// `SurfaceConfig::declares_token_expiry`/`auth::resolve_token`'s
    /// `from_expiring_step` over a field the engine never actually checks.
    #[test]
    fn expiry_json_path_is_refused_on_a_step_kind_that_never_reads_it() {
        // Same shape as `KEYCHAIN_EXPIRY_BASE`, `keychain-expiry` still
        // declared, but the step itself turned into `env` — the reader
        // capability is present, so this reaches `validate`'s own check
        // rather than the backward-compat gate's.
        let toml = KEYCHAIN_EXPIRY_BASE.replace(
            "type            = \"keychain\"\n        service         = \"gemini\"\n        token_json_path = \"token.access_token\"",
            "type = \"env\"\n        var  = \"SAMPLE_TOKEN\"",
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("expiry_json_path on an env step must be refused");
        assert!(err.contains("expiry_json_path"), "{err}");
        assert!(err.contains("env"), "{err}");
        assert!(
            err.contains("auth step 0"),
            "names the step's own index: {err}"
        );
    }

    /// The mirror of the refusal above: each of the four step kinds that
    /// actually read `expiry_json_path` is accepted with it set —
    /// `KEYCHAIN_EXPIRY_BASE` itself already covers `keychain`
    /// (`parses_a_keychain_step_with_an_expiry_path`); this covers the other
    /// three.
    #[test]
    fn expiry_json_path_is_accepted_on_credentials_file_win_credential_and_credentials_map() {
        let credentials_file = KEYCHAIN_EXPIRY_BASE.replace(
            "type            = \"keychain\"\n        service         = \"gemini\"\n        token_json_path = \"token.access_token\"",
            "type             = \"credentials-file\"\n        path             = \"~/.sample/auth.json\"\n        token_json_path  = \"token.access_token\"",
        );
        PluginManifest::from_str(&credentials_file)
            .expect("expiry_json_path on a credentials-file step is accepted");

        let win_credential = KEYCHAIN_EXPIRY_BASE.replace(
            "type            = \"keychain\"\n        service         = \"gemini\"\n        token_json_path = \"token.access_token\"",
            "type             = \"win-credential\"\n        targets          = [\"Sample\"]\n        token_json_path  = \"token.access_token\"",
        );
        PluginManifest::from_str(&win_credential)
            .expect("expiry_json_path on a win-credential step is accepted");

        let credentials_map = KEYCHAIN_EXPIRY_BASE
            .replace(
                "type            = \"keychain\"\n        service         = \"gemini\"\n        token_json_path = \"token.access_token\"",
                "type             = \"credentials-map\"\n        path             = \"~/.sample/auth.json\"\n        key_prefix       = \"https://example.com::\"\n        token_json_path  = \"token.access_token\"",
            )
            .replace(
                "requires_reader = [\"keychain-expiry\"]",
                "requires_reader = [\"keychain-expiry\", \"credentials-map\"]",
            );
        PluginManifest::from_str(&credentials_map)
            .expect("expiry_json_path on a credentials-map step is accepted");
    }

    #[test]
    fn path_env_and_path_env_join_parse_on_a_credentials_file_step() {
        let toml = KEYCHAIN_EXPIRY_BASE
            .replace(
                "type            = \"keychain\"\n        service         = \"gemini\"\n        token_json_path = \"token.access_token\"",
                "type             = \"credentials-file\"\n        path             = \"~/.sample/.credentials.json\"\n        \
                 path_env         = \"SAMPLE_CONFIG_DIR\"\n        path_env_join    = \".credentials.json\"\n        \
                 token_json_path  = \"token.access_token\"",
            )
            .replace(
                "requires_reader = [\"keychain-expiry\"]",
                "requires_reader = [\"keychain-expiry\", \"credentials-file-path-env\"]",
            );
        let m = PluginManifest::from_str(&toml).expect("path_env/path_env_join are accepted");
        let step = &m.surface[0].auth[0];
        assert_eq!(step.path_env.as_deref(), Some("SAMPLE_CONFIG_DIR"));
        assert_eq!(step.path_env_join.as_deref(), Some(".credentials.json"));
    }

    #[test]
    fn path_env_needs_its_own_capability_declared() {
        let toml = KEYCHAIN_EXPIRY_BASE.replace(
            "type            = \"keychain\"\n        service         = \"gemini\"\n        token_json_path = \"token.access_token\"",
            "type             = \"credentials-file\"\n        path             = \"~/.sample/.credentials.json\"\n        \
             path_env         = \"SAMPLE_CONFIG_DIR\"\n        token_json_path  = \"token.access_token\"",
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("path_env without its own capability is refused");
        assert!(err.contains("credentials-file-path-env"), "{err}");
    }

    #[test]
    fn path_env_is_refused_on_a_step_kind_that_never_reads_it() {
        let toml = KEYCHAIN_EXPIRY_BASE
            .replace(
                "expiry_json_path = \"token.expiry\"",
                "path_env = \"SAMPLE_CONFIG_DIR\"",
            )
            .replace(
                "requires_reader = [\"keychain-expiry\"]",
                "requires_reader = [\"credentials-file-path-env\"]",
            );
        let err = PluginManifest::from_str(&toml)
            .expect_err("path_env on a keychain step must be refused");
        assert!(err.contains("path_env"), "{err}");
        assert!(err.contains("keychain"), "{err}");
    }

    #[test]
    fn path_env_join_must_be_a_relative_filename_with_no_dotdot_component() {
        let base = KEYCHAIN_EXPIRY_BASE
            .replace(
                "type            = \"keychain\"\n        service         = \"gemini\"\n        token_json_path = \"token.access_token\"",
                "type             = \"credentials-file\"\n        path             = \"~/.sample/.credentials.json\"\n        \
                 path_env         = \"SAMPLE_CONFIG_DIR\"\n        token_json_path  = \"token.access_token\"",
            )
            .replace(
                "requires_reader = [\"keychain-expiry\"]",
                "requires_reader = [\"keychain-expiry\", \"credentials-file-path-env\"]",
            );

        let absolute = base.replace(
            "path_env         = \"SAMPLE_CONFIG_DIR\"",
            "path_env         = \"SAMPLE_CONFIG_DIR\"\n        path_env_join    = \"/etc/passwd\"",
        );
        let err = PluginManifest::from_str(&absolute)
            .expect_err("an absolute path_env_join must be refused");
        assert!(err.contains("relative"), "{err}");

        let escaping = base.replace(
            "path_env         = \"SAMPLE_CONFIG_DIR\"",
            "path_env         = \"SAMPLE_CONFIG_DIR\"\n        path_env_join    = \"../escape\"",
        );
        let err = PluginManifest::from_str(&escaping)
            .expect_err("a `..` component in path_env_join must be refused");
        assert!(err.contains(".."), "{err}");
    }

    /// `macos_keychain_key` is `auth::electron_safe_storage_step`'s own
    /// field — every other step kind never reads it, same shape as
    /// `expiry_json_path` above.
    #[test]
    fn macos_keychain_key_is_refused_on_a_step_kind_that_never_reads_it() {
        let toml = KEYCHAIN_EXPIRY_BASE.replace(
            "expiry_json_path = \"token.expiry\"",
            "macos_keychain_key = \"Sample Safe Storage\"",
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("macos_keychain_key on a keychain step must be refused");
        assert!(err.contains("macos_keychain_key"), "{err}");
        assert!(err.contains("electron-safe-storage"), "{err}");
        assert!(
            err.contains("auth step 0"),
            "names the step's own index: {err}"
        );
    }

    /// `unless_json_path` is `auth::reject_when_step`'s own escape hatch —
    /// every other step kind never reads it, same shape as
    /// `expiry_json_path` above.
    #[test]
    fn unless_json_path_is_refused_on_a_step_kind_that_never_reads_it() {
        let toml = KEYCHAIN_EXPIRY_BASE.replace(
            "expiry_json_path = \"token.expiry\"",
            "unless_json_path = \"tokens.access_token\"",
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("unless_json_path on a keychain step must be refused");
        assert!(err.contains("unless_json_path"), "{err}");
        assert!(err.contains("reject-when"), "{err}");
        assert!(
            err.contains("auth step 0"),
            "names the step's own index: {err}"
        );
    }

    #[test]
    fn declares_token_expiry_is_true_only_for_a_surface_whose_chain_names_one() {
        let with_expiry = PluginManifest::from_str(KEYCHAIN_EXPIRY_BASE).expect("valid manifest");
        assert!(
            with_expiry.surface[0].declares_token_expiry(),
            "a step with expiry_json_path set makes the surface eligible"
        );

        // `CLAUDE_LIKE`'s `desktop` surface, like the shipped manifest's, has
        // no `expiry_json_path` on its one step at all.
        let two_surfaces = PluginManifest::from_str(CLAUDE_LIKE).expect("valid manifest");
        assert!(
            !two_surfaces.surface[1].declares_token_expiry(),
            "a surface whose chain never names an expiry is not renewal-eligible"
        );
    }

    #[test]
    fn ping_renews_token_parses_when_set() {
        let toml = CODEX_LIKE.replace(
            "        bin  = \"codex\"\n        args = [\"exec\", \"hello\"]\n",
            "        bin  = \"codex\"\n        args = [\"exec\", \"hello\"]\n        renews_token = true\n",
        );
        let m = PluginManifest::from_str(&toml).expect("valid manifest");
        let ping = m.ping.as_ref().expect("[ping] section");
        assert!(ping.renews_token);
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

    /// `client.bins`/`client.id_pattern`/`client.secret_pattern` reach the
    /// trust dialog exactly like `client.files` does
    /// (`registry::analyze_trust`), and the control-char/bidi sweep covers
    /// all three the same way — pinned here directly, since the corpus's one
    /// shared row for that sweep exercises `allowed_hosts`, not these.
    #[test]
    fn a_bidi_override_in_client_bins_is_refused() {
        let toml = OAUTH_REFRESH_CLIENT_BASE.replace("sample-cli", "sample\u{202E}cli");
        let err = PluginManifest::from_str(&toml)
            .expect_err("a bidi override in client.bins must be refused");
        assert!(err.contains("client.bins"), "{err}");
        assert!(err.contains("bidirectional override"), "{err}");
    }

    /// Same sweep, `client.id_pattern` — inserted mid-word rather than beside
    /// one of the pattern's own backslash escapes, so this stays a change to
    /// the regex source (still compiles: `regex` matches the zero-width
    /// space literally) rather than to TOML's own `\\` escaping.
    /// `client.id_pattern` is `CharClass::Wide` (reaches the trust dialog),
    /// so this keeps refusing even though a display-text field would not —
    /// see the mirror test on `windows[].label`.
    #[test]
    fn a_zero_width_space_in_client_id_pattern_is_refused() {
        let toml =
            OAUTH_REFRESH_CLIENT_BASE.replace("googleusercontent", "google\u{200B}usercontent");
        let err = PluginManifest::from_str(&toml)
            .expect_err("a zero-width space in client.id_pattern must be refused");
        assert!(err.contains("client.id_pattern"), "{err}");
        assert!(err.contains("bidirectional override"), "{err}");
    }

    /// The mirror of the test above, on a `CharClass::Narrow` field: a ZWJ
    /// emoji sequence ("👨‍💻" — a base character, a zero-width joiner
    /// U+200D, and a second base character) is exactly the kind of thing a
    /// legitimate manifest author puts in a caption. `windows[].label` never
    /// reaches the trust dialog and never names a file, a host or a program,
    /// so it must not be refused for a character class that only matters
    /// where one of those is at stake.
    #[test]
    fn a_zwj_emoji_sequence_in_a_window_label_is_accepted() {
        let toml = CODEX_LIKE.replace("label = \"5H\"", "label = \"👨\u{200D}💻 5H\"");
        let m = PluginManifest::from_str(&toml)
            .expect("a ZWJ emoji sequence in a display-text label must be accepted");
        assert_eq!(m.windows[0].label, "👨\u{200D}💻 5H");
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

    /// `is_bare_program_name` used to search for `".."` as a substring
    /// rather than compare the whole component to it — with no separator
    /// (already refused above), `name` joins onto a directory as a single
    /// path component, and only the component `".."` itself ever reads as
    /// "go up one directory"; `"my..tool"` never walks anywhere and was
    /// refused for no reason.
    #[test]
    fn a_client_bins_entry_that_merely_contains_two_dots_is_accepted() {
        let toml = OAUTH_REFRESH_CLIENT_BASE.replace(
            r#"bins           = ["sample-cli"]"#,
            r#"bins           = ["my..tool"]"#,
        );
        let m = PluginManifest::from_str(&toml)
            .expect("a bins entry that merely contains two dots is not a path escape");
        let client = m.surface[0].auth[0].client.as_ref().unwrap();
        assert_eq!(client.bins, vec!["my..tool".to_string()]);
    }

    /// The one shape that *is* still refused: the component being exactly
    /// `".."`, which really does join as "go up one directory".
    #[test]
    fn a_client_bins_entry_that_is_exactly_dotdot_is_refused() {
        let toml = OAUTH_REFRESH_CLIENT_BASE.replace(
            r#"bins           = ["sample-cli"]"#,
            r#"bins           = [".."]"#,
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("a bins entry that is exactly \"..\" must still be refused");
        assert!(err.contains("client.bins"), "{err}");
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
    fn is_absolute_on_any_platform_accepts_posix_and_windows_forms_and_refuses_relative_regardless_of_the_running_platform(
    ) {
        assert!(is_absolute_on_any_platform(Path::new("/Applications/x")));
        assert!(is_absolute_on_any_platform(Path::new(
            r"C:\Program Files\x"
        )));
        assert!(is_absolute_on_any_platform(Path::new("C:/Program Files/x")));
        assert!(is_absolute_on_any_platform(Path::new(r"\\server\share\x")));
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
        // `regex_len_bounds`'s own doc names `a*` and `(foo)?` as the
        // canonical empty-matching shapes; `?` is exercised here too, on top
        // of `{0,N}` — a bare `*` is not, on purpose: any `*`/`+` submatch
        // makes the pattern's *maximum* length unmeasurable as well as its
        // minimum zero, so it is always refused by the match-bound check
        // first (`a_client_pattern_with_no_bound_on_its_match_length_is_refused`
        // already covers that shape) and would never actually reach this
        // rule to prove it.
        for pattern in ["[0-9]{0,5}", "(?:[0-9]{1,3})?"] {
            let toml = OAUTH_REFRESH_CLIENT_BASE.replace(
                r#"id_pattern     = "[0-9]{1,20}-[a-z0-9]{1,40}\\.apps\\.googleusercontent\\.com""#,
                &format!(r#"id_pattern     = "{pattern}""#),
            );
            let err = PluginManifest::from_str(&toml).expect_err(&format!(
                "a pattern that can match the empty string is refused: {pattern}"
            ));
            assert!(err.contains("id_pattern"), "{pattern}: {err}");
            assert!(
                err.contains("empty string"),
                "must name the empty-match rule specifically, not the match-bound one — \
                 {pattern}: {err}"
            );
        }
    }

    #[test]
    fn a_client_pattern_longer_than_the_text_limit_is_refused() {
        // A compact match bound (the previous test's `{0,5}` is 6 bytes of
        // source) says nothing about how long the pattern's own text is —
        // thousands of fixed-length alternatives could match well within
        // `CLIENT_PATTERN_MAX_MATCH_BYTES` while running to kilobytes of
        // source, which is exactly what the trust dialog would have to
        // render.
        //
        // `"[0-9]{1,4}"` repeated 52 times is 520 bytes of source (over the
        // 512-byte cap here) whose match is bounded to 52–208 bytes — well
        // inside the 256-byte match bound and never empty, so this trips
        // *only* the text-length rule. A flat `"1".repeat(520)` (a 520-byte
        // literal) is incidentally over the match bound too, so the assertion
        // below would pass whichever of the two rules happened to fire first
        // — checking for "id_pattern" alone cannot tell them apart.
        let toml = OAUTH_REFRESH_CLIENT_BASE.replace(
            r#"id_pattern     = "[0-9]{1,20}-[a-z0-9]{1,40}\\.apps\\.googleusercontent\\.com""#,
            &format!(r#"id_pattern     = "{}""#, "[0-9]{1,4}".repeat(52)),
        );
        let err = PluginManifest::from_str(&toml)
            .expect_err("520 bytes of pattern text is over the 512-byte limit");
        assert!(err.contains("id_pattern"), "{err}");
        assert!(
            err.contains("bytes of pattern text"),
            "must name the text-length rule specifically, not any rule that mentions id_pattern — {err}"
        );
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
