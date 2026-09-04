//! Every rule a plugin manifest has to obey, as a list of manifests that
//! break exactly one rule each.
//!
//! A manifest can be installed from a third-party registry. That makes it
//! data this app trusts precisely as far as it has checked, and
//! `PluginManifest::validate` is where the checking happens — each rule is
//! stated once, in Rust, at the point that enforces it. Read as a whole,
//! "what does this app refuse to run" is not written down anywhere.
//!
//! Here it is, as a table. Each row is one rule, one manifest that trips it,
//! and the word the complaint must contain — because a rejection that does
//! not name the field is a rejection the author of the manifest cannot act
//! on. Beneath the table: the manifests that must be *accepted* (the built-in
//! ones, which would otherwise be the only thing proving the rules are not
//! simply too strict), and a generator that throws mutated manifests at
//! `from_str` to check it neither panics nor accepts something the engines
//! then cannot run.
//!
//! The count at the end is what keeps this honest. It reads the source of
//! `validate` and counts the places that refuse a manifest; if that number
//! and the number of rows here disagree, a rule was added without a line —
//! which is the way a list like this rots.

use tickover::plugin::manifest::{
    AmountKind, AuthType, EngineKind, HttpMethod, PluginManifest, ResetsAtFormat, Role,
};
use tickover::plugin::seed::DEFAULT_TEMPLATES;

// ── The two shapes a manifest comes in ───────────────────────────────────

/// A minimal manifest the log-file engine can run. Every rejection below is
/// this, or [`HTTP`], with one thing changed.
const LOGFILE: &str = r#"
id         = "sample"
name       = "Sample"
menu_label = "Sa"
order      = 1
engine     = "log-file"

[[windows]]
label = "5H"
role  = "primary"
[windows.period]
mode    = "assumed"
assumed = 300
[windows.source]
used_percent_path = "used_percent"
resets_at_path    = "resets_at"

[logfile]
root          = "~/.sample/sessions"
glob          = "*.jsonl"
container_key = "rate_limits"
"#;

/// A minimal manifest the HTTP engine can run, with one surface that carries
/// a credential.
const HTTP: &str = r#"
id         = "sample"
name       = "Sample"
menu_label = "Sa"
order      = 1
engine     = "http-api"

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
type            = "credentials-file"
path            = "~/.sample/auth.json"
token_json_path = "token"
"#;

/// [`HTTP`] declaring `requires_reader = <list>`, for the rules that live
/// inside a section an older build cannot read.
fn http_declaring(list: &str) -> String {
    changed(
        HTTP,
        "engine     = \"http-api\"",
        &format!("engine     = \"http-api\"\nrequires_reader = {list}"),
    )
}

/// [`http_declaring`] with its one `[[surface.auth]]` step turned into
/// `oauth-refresh` and a `[surface.auth.client]` discovery table attached —
/// the base every `client`-table rule below breaks exactly one field of.
/// `list` still has to name whatever capability the row is actually testing;
/// `oauth-refresh` and `oauth-client-discovery` are both already in use by
/// the base itself, so a row testing a *different* capability would need
/// them added too.
fn oauth_refresh_client_declaring(list: &str) -> String {
    let base = changed(
        &http_declaring(list),
        "[[surface.auth]]\ntype            = \"credentials-file\"\npath            = \"~/.sample/auth.json\"\ntoken_json_path = \"token\"",
        "[[surface.auth]]\n\
         type            = \"oauth-refresh\"\n\
         path            = \"~/.sample/oauth_creds.json\"\n\
         token_json_path = \"refresh_token\"\n\
         token_url       = \"https://oauth2.googleapis.com/token\"\n\
         [surface.auth.client]\n\
         id_env         = \"SAMPLE_CLIENT_ID\"\n\
         secret_env     = \"SAMPLE_CLIENT_SECRET\"\n\
         id_pattern     = \"[0-9]{1,20}-[a-z0-9]{1,40}\\\\.apps\\\\.googleusercontent\\\\.com\"\n\
         secret_pattern = \"GOCSPX-[A-Za-z0-9_-]{28}\"\n\
         files          = [\"~/.sample/client-binary\"]\n\
         bins           = [\"sample-cli\"]\n",
    );
    changed(
        &base,
        "allowed_hosts = [\"example.com\"]",
        "allowed_hosts = [\"example.com\", \"oauth2.googleapis.com\"]",
    )
}

/// [`HTTP`] with its one window turned into an enumerating entry (`for_each`).
/// `extra_keys` is written into the window, `role` replaces `primary` — an
/// enumerating entry may not be the menu bar's window, which is itself one of
/// the rules below.
fn http_enumerating(role: &str, extra_keys: &str) -> String {
    changed(
        &http_declaring(r#"["for-each-windows"]"#),
        "role  = \"primary\"",
        &format!("role  = \"{role}\"\n{extra_keys}"),
    )
}

/// A `[[balances]]` entry, appended to a manifest that declares
/// `reading-balances`. `body` is the entry minus its header line.
fn with_balance(body: &str) -> String {
    plus(
        &http_declaring(r#"["reading-balances"]"#),
        &format!("[[balances]]\n{body}"),
    )
}

/// One rule: what it is, a manifest that breaks it, and the text the
/// complaint has to carry.
struct Rule {
    /// The rule, in the words a manifest author would want to hear it in.
    says: &'static str,
    /// A manifest breaking that rule and nothing else.
    broken_by: String,
    /// What the refusal must name. Usually the field; never just "invalid".
    names: &'static str,
}

/// `base` with `find` replaced by `replace_with` — the mutation each row
/// applies. Panics when `find` is absent, so a row cannot silently stop
/// testing anything after an edit to the two manifests above.
fn changed(base: &str, find: &str, replace_with: &str) -> String {
    assert!(
        base.contains(find),
        "the corpus expects `{find}` to be in the base manifest"
    );
    base.replace(find, replace_with)
}

/// `base` with more TOML appended.
fn plus(base: &str, extra: &str) -> String {
    format!("{base}\n{extra}\n")
}

/// [`LOGFILE`] declaring `requires_reader = <list>`.
///
/// Written next to the other top-level fields rather than appended, because
/// `requires_reader` is one: appended, it would land inside whatever table
/// header the file ends with (`[logfile]`) and be read as a field of *that* —
/// silently, since unknown fields are ignored. The same trap is waiting for a
/// manifest author, and the backward half of the capability check is what
/// catches them: a declaration that went into the wrong table reads as no
/// declaration at all, and the first field they use refuses the manifest.
fn declaring(list: &str) -> String {
    changed(
        LOGFILE,
        "engine     = \"log-file\"",
        &format!("engine     = \"log-file\"\nrequires_reader = {list}"),
    )
}

fn rules() -> Vec<Rule> {
    vec![
        Rule {
            says: "a filter without an array to walk means nothing",
            broken_by: http_enumerating("extra", "for_each_where = \"kind=weekly\""),
            names: "`for_each_where`",
        },
        Rule {
            says: "an element identity without elements means nothing",
            broken_by: http_enumerating("extra", "element_id_path = \"id\""),
            names: "`element_id_path`",
        },
        Rule {
            says: "an unclosed placeholder in a label draws no row, on every element, in silence",
            broken_by: http_enumerating(
                "extra",
                "for_each = \"limits\"\nelement_id_path = \"id\"\nlabel_unused = 0",
            )
            .replace("label = \"5H\"", "label = \"{id weekly\""),
            names: "never closed",
        },
        Rule {
            says: "a label is a literal unless the entry expands, and then it may name its element",
            broken_by: changed(HTTP, "label = \"5H\"", "label = \"{model} weekly\""),
            names: "`for_each`",
        },
        Rule {
            says: "only the http engine has an array to expand over",
            broken_by: changed(
                &changed(
                    &declaring(r#"["for-each-windows"]"#),
                    "role  = \"primary\"",
                    "role  = \"extra\"\nfor_each = \"limits\"\nelement_id_path = \"id\"",
                ),
                "label = \"5H\"",
                "label = \"{id}\"",
            ),
            names: "engine = \"http-api\"",
        },
        Rule {
            says: "every row an expansion draws needs an identity of its own",
            broken_by: http_enumerating("extra", "for_each = \"limits\""),
            names: "`element_id_path`",
        },
        Rule {
            says: "an element filter is `field=value`, or it matches nothing forever",
            broken_by: http_enumerating(
                "extra",
                "for_each = \"limits\"\nelement_id_path = \"id\"\nfor_each_where = \"weekly\"",
            ),
            names: "`field=value`",
        },
        Rule {
            says: "the 5H and WK slots hold one window each, so an expanding entry fills neither",
            broken_by: http_enumerating(
                "primary",
                "for_each = \"limits\"\nelement_id_path = \"id\"",
            ),
            names: "must be `role = \"extra\"`",
        },
        Rule {
            says: "a manifest has an id",
            broken_by: changed(LOGFILE, r#"id         = "sample""#, r#"id = "  ""#),
            names: "`id`",
        },
        Rule {
            says: "an id is a filename stem and a config key, so it may hold no path",
            broken_by: changed(LOGFILE, r#"id         = "sample""#, r#"id = "../evil""#),
            names: "`id = \"../evil\"`",
        },
        Rule {
            says: "a manifest has a name",
            broken_by: changed(LOGFILE, r#"name       = "Sample""#, r#"name = """#),
            names: "`name`",
        },
        Rule {
            says: "a manifest has a menu-bar label",
            broken_by: changed(LOGFILE, r#"menu_label = "Sa""#, r#"menu_label = " ""#),
            names: "`menu_label`",
        },
        Rule {
            says: "a refresh interval of zero is not an interval",
            broken_by: changed(LOGFILE, "order      = 1", "order = 1\nrefresh_secs = 0"),
            names: "`refresh_secs`",
        },
        Rule {
            says: "the log-file engine needs a [logfile] section to read",
            broken_by: changed(LOGFILE, "[logfile]", "[unused]"),
            names: "[logfile]",
        },
        Rule {
            says: "the http engine needs an [http] section to call",
            broken_by: changed(LOGFILE, r#"engine     = "log-file""#, r#"engine = "http-api""#),
            names: "[http]",
        },
        Rule {
            says: "the http engine calls exactly one endpoint, not two",
            broken_by: plus(HTTP, "[[http.request]]\nurl = \"https://example.com/other\""),
            names: "[[http.request]]",
        },
        Rule {
            says: "a log-file section that names no glob matches nothing, forever",
            broken_by: changed(LOGFILE, r#"glob          = "*.jsonl""#, r#"glob = """#),
            names: "`[logfile] glob`",
        },
        Rule {
            says: "an endpoint with no URL is a request that cannot be sent",
            broken_by: changed(HTTP, "url = \"https://example.com/usage\"", "url = \"\""),
            names: "`[[http.request]] url`",
        },
        Rule {
            // Not a hand-rolled scheme check: a manifest whose URL can't be
            // read as `https` by `url::Url` — the parser `ureq` itself uses
            // — is refused the same way a plain `http://` one is.
            says: "an endpoint that isn't https would send its credential in the clear",
            broken_by: changed(
                HTTP,
                "url = \"https://example.com/usage\"",
                "url = \"http://example.com/usage\"",
            ),
            names: "`[[http.request]] url` must be https",
        },
        Rule {
            // A GET has nowhere to put a body — declared, so this trips the
            // body/method rule rather than the backward capability check
            // standing in front of it (same pattern as the window-id rows
            // below).
            says: "a GET request has nowhere to put a body — only a POST may declare one",
            broken_by: changed(
                &http_declaring(r#"["http-post"]"#),
                "url = \"https://example.com/usage\"",
                "url = \"https://example.com/usage\"\nbody = \"x\"",
            ),
            names: "requires `method = \"post\"`",
        },
        Rule {
            // A JSON object's own leading `{` pairs with the first `}` that
            // follows it, in the same naive one-pass scan `validate` and the
            // engine's own substitution both use — which is the
            // placeholder's own closing brace when the body wraps one.
            // Swallowed that way, `{token}` is never read as a placeholder
            // at all, and is sent on the wire exactly as written.
            says: "a body that opens with { cannot carry a placeholder — its own brace swallows it",
            broken_by: changed(
                &http_declaring(r#"["http-post"]"#),
                "url = \"https://example.com/usage\"",
                "url    = \"https://example.com/usage\"\nmethod = \"post\"\n\
                 body   = \"{\\\"auth\\\":\\\"{token}\\\"}\"",
            ),
            names: "{token}",
        },
        Rule {
            // A window states its consumed figure one way, not two: spent
            // (`used_percent_path`) or what is left (`remaining_fraction_path`),
            // never both at once, or the engine is left to pick.
            says: "a window names its figure one way, not both spent and remaining",
            broken_by: changed(
                &http_declaring(r#"["remaining-fraction"]"#),
                "used_percent_path = \"used_percent\"",
                "used_percent_path = \"used_percent\"\nremaining_fraction_path = \"f\"",
            ),
            names: "name only one",
        },
        Rule {
            // And an http-api window that names neither has no figure to show —
            // it would resolve to nothing on every fetch.
            says: "an http-api window with neither figure path resolves to nothing",
            broken_by: changed(HTTP, "used_percent_path = \"used_percent\"\n", ""),
            names: "it has no figure to show otherwise",
        },
        Rule {
            says: "a provider with no window has nothing to show",
            // Written out rather than cut from the base: removing the window
            // means removing four sections that refer to it, and a mutation
            // that leaves one behind tests the TOML parser instead of a rule.
            broken_by: r#"
                id         = "sample"
                name       = "Sample"
                menu_label = "Sa"
                order      = 1
                engine     = "log-file"
                [logfile]
                root          = "~/.sample"
                glob          = "*.jsonl"
                container_key = "rate_limits"
            "#
            .to_string(),
            names: "[[windows]] or [[balances]]",
        },
        Rule {
            // The log reader has nowhere to take a balance from, and a section
            // it silently ignores is the failure the capability mechanism
            // exists to turn into a refusal.
            says: "only the http engine reads balances",
            broken_by: plus(
                &declaring(r#"["reading-balances"]"#),
                "[[balances]]\nlabel = \"Credits\"\n[balances.remaining]\n\
                 kind = \"text\"\npath = \"credits.balance\"",
            ),
            names: "`[[balances]]` is read only by",
        },
        Rule {
            says: "a balance has a label",
            broken_by: with_balance(
                "label = \"  \"\n[balances.remaining]\nkind = \"text\"\npath = \"credits.balance\"",
            ),
            names: "`[[balances]] label`",
        },
        Rule {
            // Same rule as a window id, same reason: it becomes a segment of a
            // dotted key in the user's `config.json`.
            says: "a balance id is a key on disk, so it holds no dots or capitals",
            broken_by: with_balance(
                "id    = \"Credits.Left\"\nlabel = \"Credits\"\n\
                 [balances.remaining]\nkind = \"text\"\npath = \"credits.balance\"",
            ),
            names: "`id = \"Credits.Left\"`",
        },
        Rule {
            says: "a balance that names no figure is a caption beside empty space",
            broken_by: with_balance("label = \"Credits\""),
            names: "names no figure",
        },
        Rule {
            // Money is the triplet or it is nothing: an amount without its
            // currency and scale is a number whose meaning would have to be
            // guessed.
            says: "a money figure needs amount, currency and exponent",
            broken_by: with_balance(
                "label = \"Spend\"\n[balances.used]\nkind = \"money-minor\"\n\
                 amount_path = \"spend.used.amount_minor\"\ncurrency_path = \"spend.used.currency\"",
            ),
            names: "`exponent_path` is missing",
        },
        Rule {
            says: "a number figure needs a path to the number",
            broken_by: with_balance("label = \"Credits\"\n[balances.cap]\nkind = \"number\""),
            names: "requires `path`",
        },
        Rule {
            // A unit label on money would compete with the currency the
            // response states.
            says: "only a bare number takes a unit label from the manifest",
            broken_by: with_balance(
                "label = \"Spend\"\n[balances.used]\nkind = \"money-minor\"\n\
                 amount_path = \"a\"\ncurrency_path = \"c\"\nexponent_path = \"e\"\n\
                 unit_label = \"credits\"",
            ),
            names: "`unit_label` belongs to",
        },
        Rule {
            // `is_none()` is false for `path = "  "`, so the manifest loads and
            // then reads nothing on every fetch — accepted, and silently inert.
            says: "a balance path can be present and still be blank",
            broken_by: with_balance(
                "label = \"Credits\"\n[balances.remaining]\nkind = \"text\"\npath = \"   \"",
            ),
            names: "present but blank",
        },
        Rule {
            // The label is the one key in an amount table the panel prints, so
            // a blank one is accepted and then quietly changes what pairs with
            // what — two rows where the author wrote a pair.
            says: "a unit label can be present and still print nothing",
            broken_by: with_balance(
                "label = \"Credits\"\n[balances.cap]\nkind = \"number\"\npath = \"c\"\n\
                 unit_label = \"   \"",
            ),
            names: "nothing printable",
        },
        Rule {
            says: "two balances cannot share an id",
            broken_by: plus(
                &with_balance(
                    "id    = \"same\"\nlabel = \"A\"\n[balances.remaining]\n\
                     kind = \"text\"\npath = \"a\"",
                ),
                "[[balances]]\nid = \"same\"\nlabel = \"B\"\n\
                 [balances.remaining]\nkind = \"text\"\npath = \"b\"",
            ),
            names: "resolve to the same identity",
        },
        Rule {
            says: "only one window can be the primary one",
            broken_by: plus(
                LOGFILE,
                "[[windows]]\nlabel = \"WK\"\nrole = \"primary\"\n\
                 [windows.period]\nmode = \"assumed\"\nassumed = 10080\n\
                 [windows.source]\nused_percent_path = \"u\"\nresets_at_path = \"r\"",
            ),
            names: "at most one window",
        },
        Rule {
            // A window id becomes a segment of a dotted key in the user's
            // `config.json`, so a `.` in it would split the path and grow a
            // neighbouring table in their config rather than a key in ours.
            says: "a window id is a key on disk, so it holds no dots or capitals",
            // Declared, so this trips the id rule rather than the backward
            // capability check standing in front of it.
            broken_by: changed(
                &declaring(r#"["window-identity"]"#),
                "label = \"5H\"",
                "id    = \"five.hour\"\nlabel = \"5H\"",
            ),
            names: "`id = \"five.hour\"`",
        },
        Rule {
            // Two entries with one id are two rows with one identity, and
            // identity is what the registry, the row reconciler and the ping's
            // target all address a window by. Left to the engine it would
            // surface as one row quietly inheriting another's boundary.
            says: "two windows cannot share an id",
            broken_by: plus(
                changed(
                    &declaring(r#"["window-identity"]"#),
                    "label = \"5H\"",
                    "id    = \"same\"\nlabel = \"5H\"",
                )
                .as_str(),
                "[[windows]]\nid = \"same\"\nlabel = \"WK\"\nrole = \"secondary\"\n\
                 [windows.period]\nmode = \"assumed\"\nassumed = 10080\n\
                 [windows.source]\nused_percent_path = \"u\"\nresets_at_path = \"r\"",
            ),
            names: "resolve to the same identity",
        },
        Rule {
            // A section that names no path cannot answer the question it
            // exists for, and everything upstream would read it as "this
            // provider states a status".
            says: "a [status] section that names no path states nothing",
            // From the HTTP base, since `[status]` is an http-api section and
            // the log-file one would trip the rule below instead.
            broken_by: plus(
                &changed(
                    HTTP,
                    "engine     = \"http-api\"",
                    "engine     = \"http-api\"\nrequires_reader = [\"reading-status\"]",
                ),
                "[status]",
            ),
            names: "`[status]`",
        },
        Rule {
            // Only the HTTP engine reads it. A log line records what one
            // session saw, not the standing of the account — so accepting the
            // section here would let a manifest state a guarantee this app
            // does not keep, which is what a dead `required` once cost.
            says: "[status] is an http-api section, and a log-file manifest may not claim one",
            broken_by: plus(
                &declaring(r#"["reading-status"]"#),
                "[status]\nlimit_reached_path = \"rate_limit.limit_reached\"",
            ),
            names: "http-api",
        },
        Rule {
            // `is_empty()` only asks whether every path is absent — a blank
            // one beside a real one passes it and then reads nothing at
            // fetch time, the same gap the `[[balances]]` blank check closes
            // for its own paths.
            says: "a status path can be present and still be blank",
            broken_by: plus(
                &http_declaring(r#"["reading-status"]"#),
                "[status]\nallowed_path = \"rate_limit.allowed\"\nlimit_reached_path = \"   \"",
            ),
            names: "present but blank",
        },
        Rule {
            says: "an assumed period has to say what it assumes",
            broken_by: changed(LOGFILE, "assumed = 300", ""),
            names: "period.assumed",
        },
        Rule {
            says: "a period read from a field has to say which field",
            broken_by: changed(
                LOGFILE,
                "mode    = \"assumed\"\nassumed = 300",
                "mode = \"from_field\"",
            ),
            names: "period.field",
        },
        Rule {
            says: "several candidate containers can only be told apart by length",
            broken_by: changed(
                LOGFILE,
                "used_percent_path = \"used_percent\"",
                "containers = [\"a\", \"b\"]\nused_percent_path = \"used_percent\"",
            ),
            names: "from_field",
        },
        Rule {
            // `mode = "assumed"` already states the window's length outright
            // — there is no candidate left for a bound to measure, so
            // `engine_http::select_container` never even asks it whether a
            // candidate fits. `http-api` only: the log-file engine's own
            // `classify_slot` applies a bound to a record regardless of
            // `period.mode`, and a `role = "extra"` log-file window needs
            // one — so the same manifest, on `engine = "log-file"`, is
            // legal (see `CODEX_LIKE` in `src/plugin/manifest.rs`, which
            // pairs `mode = "assumed"` with `min_period_minutes` on purpose).
            says: "a classification bound on a window whose length is assumed reads air on http-api",
            broken_by: changed(
                HTTP,
                "used_percent_path = \"used_percent\"",
                "min_period_minutes = 60\nused_percent_path = \"used_percent\"",
            ),
            names: "min_period_minutes",
        },
        Rule {
            says: "a credential never goes in a URL, where whatever fronts the endpoint logs it",
            broken_by: changed(
                HTTP,
                "url = \"https://example.com/usage\"",
                "url = \"https://example.com/usage?t={token}\"",
            ),
            names: "{token}",
        },
        Rule {
            says: "and not in the profile URL either",
            broken_by: plus(
                HTTP,
                "[account]\ntype = \"http\"\nurl = \"https://example.com/me?t={token}\"\njson_path = \"email\"",
            ),
            names: "`[account] url`",
        },
        Rule {
            says: "nor is the profile URL exempt from https",
            broken_by: plus(
                HTTP,
                "[account]\ntype = \"http\"\nurl = \"http://example.com/me\"\njson_path = \"email\"",
            ),
            names: "`[account] url` must be https",
        },
        Rule {
            says: "a surface that carries a token has to say where the token may go",
            broken_by: changed(HTTP, "allowed_hosts = [\"example.com\"]", "allowed_hosts = []"),
            names: "allowed_hosts",
        },
        Rule {
            says: "a cool-off that starts at zero is a retry loop",
            broken_by: changed(HTTP, "[http]\n", "[http]\nbackoff_start_secs = 0\n"),
            names: "backoff_start_secs",
        },
        Rule {
            says: "so is an expired-session wait of zero",
            broken_by: changed(HTTP, "[http]\n", "[http]\nunauthorized_retry_secs = 0\n"),
            names: "unauthorized_retry_secs",
        },
        Rule {
            says: "a cool-off cannot be capped below where it starts",
            broken_by: changed(
                HTTP,
                "[http]\n",
                "[http]\nbackoff_start_secs = 600\nbackoff_max_secs = 60\n",
            ),
            names: "backoff_max_secs",
        },
        Rule {
            says: "a request timeout of zero would fail before it could ever succeed",
            broken_by: changed(
                HTTP,
                "url = \"https://example.com/usage\"",
                "url = \"https://example.com/usage\"\ntimeout_secs = 0",
            ),
            names: "timeout_secs",
        },
        Rule {
            says: "a header value read from a file has a name",
            broken_by: plus(
                HTTP,
                "[[http.value]]\nname = \" \"\ntype = \"json-file\"\npath = \"~/x.json\"\njson_path = \"a\"",
            ),
            names: "`name`",
        },
        Rule {
            says: "and that name is what a placeholder spells, so it is spellable",
            broken_by: plus(
                HTTP,
                "[[http.value]]\nname = \"acc-id\"\ntype = \"json-file\"\npath = \"~/x.json\"\njson_path = \"a\"",
            ),
            names: "name = \"acc-id\"",
        },
        Rule {
            says: "two values cannot answer to the same placeholder",
            broken_by: plus(
                HTTP,
                "[[http.value]]\nname = \"a\"\ntype = \"json-file\"\npath = \"~/x.json\"\njson_path = \"a\"\n\
                 [[http.value]]\nname = \"a\"\ntype = \"json-file\"\npath = \"~/y.json\"\njson_path = \"a\"",
            ),
            names: "declared more than once",
        },
        Rule {
            says: "a value read from a JSON file needs the file and the path inside it",
            broken_by: plus(HTTP, "[[http.value]]\nname = \"a\"\ntype = \"json-file\""),
            names: "`path` and `json_path`",
        },
        Rule {
            says: "an auth step declares what its own kind needs",
            broken_by: changed(HTTP, "token_json_path = \"token\"", ""),
            names: "token_json_path",
        },
        Rule {
            says: "hosts are matched exactly, so a wildcard matches nothing",
            broken_by: changed(HTTP, "allowed_hosts = [\"example.com\"]", "allowed_hosts = [\"*\"]"),
            names: "wildcards",
        },
        Rule {
            says: "an [account] declares what its own kind needs",
            broken_by: plus(LOGFILE, "[account]\ntype = \"jwt-file\"\npath = \"~/auth.json\""),
            names: "`token_path`",
        },
        Rule {
            says: "a ping that runs nothing is not a ping",
            broken_by: plus(LOGFILE, "[ping]\nbin = \"\"\nargs = []"),
            names: "`[ping] bin`",
        },
        Rule {
            says: "a ping runs a program by name; a path is a worse sentence to put in a trust dialog",
            broken_by: plus(LOGFILE, "[ping]\nbin = \"/usr/local/bin/thing\"\nargs = []"),
            names: "bare program name",
        },
        Rule {
            says: "an option has a key",
            broken_by: plus(LOGFILE, "[[option]]\nkey = \"\"\nlabel = \"L\""),
            names: "`key`",
        },
        Rule {
            says: "and that key is what a placeholder spells",
            broken_by: plus(LOGFILE, "[[option]]\nkey = \"no spaces\"\nlabel = \"L\""),
            names: "key = \"no spaces\"",
        },
        Rule {
            says: "an option is offered to a person, so it has something to read",
            broken_by: plus(LOGFILE, "[[option]]\nkey = \"k\"\nlabel = \"\""),
            names: "`label`",
        },
        Rule {
            says: "two options cannot answer to the same key",
            broken_by: plus(
                LOGFILE,
                "[[option]]\nkey = \"k\"\nlabel = \"A\"\n[[option]]\nkey = \"k\"\nlabel = \"B\"",
            ),
            names: "declared more than once",
        },
        Rule {
            says: "a placeholder only works where something substitutes it, and the log engine has no values",
            broken_by: changed(
                LOGFILE,
                r#"root          = "~/.sample/sessions""#,
                r#"root = "~/.sample/{value.account_id}""#,
            ),
            names: "nothing substitutes there",
        },
        Rule {
            says: "a header naming a value nothing declares would be sent with the braces in it",
            broken_by: changed(
                HTTP,
                "Authorization = \"Bearer {token}\"",
                "Authorization = \"Bearer {value.account_id}\"",
            ),
            names: "{value.account_id}",
        },
        Rule {
            says: "and an option nothing declares is never substituted either",
            broken_by: changed(
                LOGFILE,
                "glob          = \"*.jsonl\"",
                "glob = \"{option.deep}/*.jsonl\"",
            ),
            names: "{option.deep}",
        },
        Rule {
            // `is_none()` (the table above) is true for a field left out
            // entirely, and false for `key_prefix = "   "` — present, and
            // useless. Without this a manifest like that loads fine and then
            // fails on every fetch, with an error naming a field the row
            // gives the user no way to see.
            says: "a `credentials-map` step's fields can be present and still say nothing",
            broken_by: plus(
                &http_declaring(r#"["credentials-map"]"#),
                "[[surface.auth]]\ntype = \"credentials-map\"\n\
                 path = \"~/.sample/other-auth.json\"\nkey_prefix = \"   \"\n\
                 token_json_path = \"key\"",
            ),
            names: "key_prefix",
        },
        Rule {
            // `[surface.auth.client]` is `oauth-refresh`'s own sub-table; a
            // manifest that wrote it under a `credentials-file` step is not
            // asking for anything this app knows how to do with it.
            says: "a `client` table only makes sense on an oauth-refresh step",
            broken_by: plus(
                &http_declaring(r#"["oauth-client-discovery"]"#),
                "[surface.auth.client]\nid_pattern = \"a\"\nsecret_pattern = \"b\"\n\
                 files = [\"~/.sample/client-binary\"]",
            ),
            names: "oauth-refresh",
        },
        Rule {
            // A pattern that never compiles as a regex would fail on every
            // single discovery attempt, with an error naming the manifest's
            // own field rather than one the user can see from the row.
            says: "a client pattern has to compile as a regular expression",
            broken_by: changed(
                &oauth_refresh_client_declaring(r#"["oauth-refresh", "oauth-client-discovery"]"#),
                r#"id_pattern     = "[0-9]{1,20}-[a-z0-9]{1,40}\\.apps\\.googleusercontent\\.com""#,
                r#"id_pattern     = "[0-9""#,
            ),
            names: "id_pattern",
        },
        Rule {
            says: "a client `files`/`bins` entry can be present and still say nothing",
            broken_by: changed(
                &oauth_refresh_client_declaring(r#"["oauth-refresh", "oauth-client-discovery"]"#),
                r#"files          = ["~/.sample/client-binary"]"#,
                r#"files          = ["   "]"#,
            ),
            names: "client.files",
        },
        Rule {
            // Neither list to search, and no `id_env`/`secret_env` pair to
            // excuse that — `auth::discover_client` would then have nothing
            // to look at and nothing to fall back to, which is a manifest
            // that can never resolve this step. All four fields the base
            // fixture sets have to go, not just `files`: the base also
            // names an env pair and a `bins` entry now, either of which
            // alone would satisfy the rule this row means to break.
            says: "a client table needs something to search, or an env pair to skip searching for",
            broken_by: {
                let base = oauth_refresh_client_declaring(r#"["oauth-refresh", "oauth-client-discovery"]"#);
                let base = changed(&base, "id_env         = \"SAMPLE_CLIENT_ID\"\n", "");
                let base = changed(&base, "secret_env     = \"SAMPLE_CLIENT_SECRET\"\n", "");
                let base = changed(&base, r#"files          = ["~/.sample/client-binary"]"#, "");
                changed(&base, r#"bins           = ["sample-cli"]"#, "")
            },
            names: "`bins`",
        },
        Rule {
            // `bins` resolves on `PATH` by joining a directory onto whatever
            // is written here — a `/`, a `..` component or a drive prefix
            // would turn that join into an absolute or escaping path, i.e. a
            // manifest naming any file it likes rather than a program name
            // to look up.
            says: "a client bins entry is a bare program name, not a path",
            broken_by: changed(
                &oauth_refresh_client_declaring(r#"["oauth-refresh", "oauth-client-discovery"]"#),
                r#"bins           = ["sample-cli"]"#,
                r#"bins           = ["/etc/passwd"]"#,
            ),
            names: "client.bins",
        },
        Rule {
            // `files` is a path, not a program name — a relative one
            // resolves against whatever directory this process happens to
            // be running from, never the intent of naming an installed
            // client's binary. Checked after `~` expansion, so this row
            // uses a plain relative entry rather than a `~`-prefixed one
            // (which is exactly what the accepted fixture already uses).
            says: "a client files entry has to be an absolute path",
            broken_by: changed(
                &oauth_refresh_client_declaring(r#"["oauth-refresh", "oauth-client-discovery"]"#),
                r#"files          = ["~/.sample/client-binary"]"#,
                r#"files          = ["relative/client-binary"]"#,
            ),
            names: "client.files",
        },
        Rule {
            // A client id or secret is never remotely long enough to need
            // an unbounded pattern — one that could match arbitrarily far
            // into the file would turn "scan for a short id" into "read an
            // unbounded slice of it and call the slice the client".
            says: "a client pattern's match has to be bounded",
            broken_by: changed(
                &oauth_refresh_client_declaring(r#"["oauth-refresh", "oauth-client-discovery"]"#),
                r#"secret_pattern = "GOCSPX-[A-Za-z0-9_-]{28}""#,
                r#"secret_pattern = "GOCSPX-[A-Za-z0-9_-]+""#,
            ),
            names: "secret_pattern",
        },
        Rule {
            // Bounded above is not bounded below: `[0-9]{0,5}` is a finite
            // (5-byte) match, and can also match zero bytes — a client id
            // of `""`, which `auth::discover_client` would otherwise hand
            // straight to the OAuth exchange.
            says: "a client pattern must not be able to match the empty string",
            broken_by: changed(
                &oauth_refresh_client_declaring(r#"["oauth-refresh", "oauth-client-discovery"]"#),
                r#"id_pattern     = "[0-9]{1,20}-[a-z0-9]{1,40}\\.apps\\.googleusercontent\\.com""#,
                r#"id_pattern     = "[0-9]{0,5}""#,
            ),
            names: "id_pattern",
        },
        Rule {
            // A compact match bound says nothing about the pattern's own
            // source text — thousands of fixed-length alternatives could
            // all match well within the 256-byte match bound while the
            // pattern itself runs to kilobytes, and that source text is
            // exactly what the trust dialog renders before installing
            // anything.
            says: "a client pattern's own source text has a length limit, separate from what it can match",
            broken_by: changed(
                &oauth_refresh_client_declaring(r#"["oauth-refresh", "oauth-client-discovery"]"#),
                r#"id_pattern     = "[0-9]{1,20}-[a-z0-9]{1,40}\\.apps\\.googleusercontent\\.com""#,
                &format!(r#"id_pattern     = "{}""#, "1".repeat(520)),
            ),
            names: "id_pattern",
        },
        Rule {
            // `std::env::var` would simply never find anything for a name
            // outside the POSIX/Windows charset, which is a worse answer
            // than refusing it here — "never set" reads exactly like "not
            // using the override", when the manifest plainly meant to.
            says: "a client env name has to be a valid environment variable name",
            broken_by: changed(
                &oauth_refresh_client_declaring(r#"["oauth-refresh", "oauth-client-discovery"]"#),
                r#"id_env         = "SAMPLE_CLIENT_ID""#,
                r#"id_env         = "SAMPLE-CLIENT-ID""#,
            ),
            names: "client.id_env",
        },
        Rule {
            // Half a pair can never resolve anything by itself
            // (`auth::client_env_pair` only returns an override when both
            // are set) — left unrefused, it would fall through to discovery
            // every fetch while queuing a diagnostic nobody asked to read,
            // hiding what is almost certainly a manifest typo.
            says: "a client's id_env/secret_env must be set together or not at all",
            broken_by: changed(
                &oauth_refresh_client_declaring(r#"["oauth-refresh", "oauth-client-discovery"]"#),
                "secret_env     = \"SAMPLE_CLIENT_SECRET\"\n",
                "",
            ),
            names: "id_env",
        },
        Rule {
            // A step naming both the literal pair and a `client` table
            // cannot say which one it means — `auth::resolve_client` would
            // otherwise try the literal fields as a fallback rung between
            // the env override and discovery, an ambiguity refused outright
            // rather than resolved by picking an order silently.
            says: "an oauth-refresh step may not set both the literal pair and a client table",
            broken_by: changed(
                &oauth_refresh_client_declaring(r#"["oauth-refresh", "oauth-client-discovery"]"#),
                "token_url       = \"https://oauth2.googleapis.com/token\"",
                "token_url       = \"https://oauth2.googleapis.com/token\"\n\
                 client_id       = \"literal-id\"\n\
                 client_secret   = \"literal-secret\"",
            ),
            names: "client_id",
        },
        Rule {
            // Same rule `[[http.request]] url` and `[account] url` carry
            // above, read the same way (`super::https_host`) — refused
            // before `auth::oauth_refresh_step` would ever dial it with the
            // refresh token in tow.
            says: "nor is a refresh token's own exchange exempt from https",
            broken_by: changed(
                &oauth_refresh_client_declaring(r#"["oauth-refresh", "oauth-client-discovery"]"#),
                "token_url       = \"https://oauth2.googleapis.com/token\"",
                "token_url       = \"http://oauth2.googleapis.com/token\"",
            ),
            names: "`token_url` must be https",
        },
        // ── `requires_reader` (src/plugin/capability.rs) ──────────────────
        //
        // These five are refused before validation runs at all, by the
        // capability gate in `PluginManifest::from_str`. They are here for the
        // same reason as the rest: this file is "what does this app refuse to
        // run", and where in the front door the refusal happens is an
        // implementation detail of the door.
        Rule {
            says: "a declared capability is a name, not blank space",
            broken_by: declaring(r#"["  "]"#),
            names: "`requires_reader`",
        },
        Rule {
            says: "a capability is declared once",
            broken_by: declaring(r#"["window-presence", "window-presence"]"#),
            names: "more than once",
        },
        Rule {
            says: "a declared capability is one this build has heard of",
            broken_by: declaring(r#"["windwo-presence"]"#),
            names: "\"windwo-presence\"",
        },
        Rule {
            // Names whichever capability is still unimplemented — which is the
            // one thing about this row that will keep changing. When
            // `window-presence` shipped, this row stopped refusing anything and
            // said so loudly, which is how the corpus is meant to behave.
            says: "a declared capability is one this build actually implements",
            broken_by: declaring(r#"["window-severity"]"#),
            names: "does not implement",
        },
        Rule {
            says: "a manifest that uses a capability's fields has to declare it",
            broken_by: changed(
                LOGFILE,
                "role  = \"primary\"",
                "role  = \"primary\"\nrequired = true",
            ),
            names: "`windows.required`",
        },
    ]
}

#[test]
fn every_rule_refuses_its_manifest_and_says_which_field() {
    // Each row's complaint, so the check below can see two rows that turned
    // out to trip the same rule.
    let mut heard: Vec<(&'static str, String)> = Vec::new();
    for rule in rules() {
        let outcome = PluginManifest::from_str(&rule.broken_by);
        let complaint = match outcome {
            Ok(_) => panic!(
                "accepted a manifest that breaks a rule — {}\n{}",
                rule.says, rule.broken_by
            ),
            Err(message) => message,
        };
        if let Some((other, _)) = heard.iter().find(|(_, said)| *said == complaint) {
            panic!(
                "two rows trip the same rule, so one of them tests nothing:\n  {other}\n  {}\n  both said: {complaint}",
                rule.says
            );
        }
        heard.push((rule.says, complaint.clone()));
        assert!(
            complaint.contains(rule.names),
            "the refusal has to name `{}` so the author knows where to look — {}\n  said: {complaint}",
            rule.names,
            rule.says
        );
    }
}

// ── The other half: what must be accepted ────────────────────────────────

#[test]
fn the_shipped_manifests_and_the_smallest_valid_ones_are_accepted() {
    // Iterated rather than named one by one, so a third built-in added later
    // is covered without anybody remembering to add it here.
    for (name, contents) in DEFAULT_TEMPLATES {
        PluginManifest::from_str(contents)
            .unwrap_or_else(|e| panic!("the shipped {name} must be valid: {e}"));
    }
    for (shape, base) in [("log-file", LOGFILE), ("http-api", HTTP)] {
        PluginManifest::from_str(base)
            .unwrap_or_else(|e| panic!("the smallest valid {shape} manifest must be valid: {e}"));
    }
}

/// Three things no single manifest can check about itself, and nothing else
/// checks at all: two built-ins claiming the same `id` (one silently replaces
/// the other in the registry), the same `menu_label` (two identical pills in
/// the menu bar), or the same `order` (a tie broken on `id`, so the panel
/// reorders itself when a provider is renamed). Each is a mistake a new
/// manifest makes by copying an existing one, which is how every one of them
/// was written.
#[test]
fn no_two_shipped_manifests_share_an_id_a_menu_label_or_a_sort_order() {
    let shipped: Vec<PluginManifest> = DEFAULT_TEMPLATES
        .iter()
        .map(|(name, contents)| {
            PluginManifest::from_str(contents).unwrap_or_else(|e| panic!("{name}: {e}"))
        })
        .collect();

    for (what, keys) in [
        (
            "id",
            shipped.iter().map(|m| m.id.clone()).collect::<Vec<_>>(),
        ),
        (
            "menu_label",
            shipped.iter().map(|m| m.menu_label.clone()).collect(),
        ),
        (
            "order",
            shipped.iter().map(|m| m.order.to_string()).collect(),
        ),
    ] {
        // Reported as "which value, held by whom" rather than as two counts:
        // a failure that says `4 != 5` over a deduplicated list names neither
        // the colliding value nor the pair of manifests that collided, which
        // is the entire content of the answer.
        for (i, key) in keys.iter().enumerate() {
            if let Some(j) = keys
                .iter()
                .position(|other| other == key)
                .filter(|j| *j < i)
            {
                panic!(
                    "{} and {} share a {what} ({key:?})",
                    shipped[j].id, shipped[i].id,
                );
            }
        }
    }
}

/// `grok.toml` on its own, read straight off disk rather than through
/// [`DEFAULT_TEMPLATES`] — wiring a manifest into that constant is
/// `plugin::seed`'s job, a separate change from writing the manifest itself.
#[test]
fn the_shipped_grok_manifest_is_accepted() {
    let text = include_str!("../plugins/grok.toml");
    let m =
        PluginManifest::from_str(text).unwrap_or_else(|e| panic!("grok.toml must be valid: {e}"));
    assert_eq!(m.id, "grok");
    // The whole reason [[balances]] exists: Grok states no window length, no
    // percentage and no reset moment — only two figures against a monthly
    // billing period.
    assert!(
        m.windows.is_empty(),
        "Grok reports no windows, only balances"
    );
    assert!(
        m.status.is_none(),
        "Grok states nothing about the quota as a whole"
    );

    // The golden half: a manifest that parses is not a manifest that reads the
    // right fields. Every path this provider depends on is asserted, because a
    // typo in one of them is accepted by every check above and then silently
    // reads nothing at all.
    let http = m.http.as_ref().expect("grok.toml declares [http]");
    let req = http.request.first().expect("one request");
    assert_eq!(
        req.url,
        "https://cli-chat-proxy.grok.com/v1/billing?format=credits"
    );
    assert_eq!(
        req.headers.get("Authorization").map(String::as_str),
        Some("Bearer {token}"),
        "the token has to reach the request"
    );
    let surface = m.surface.first().expect("one surface");
    assert_eq!(
        surface.allowed_hosts,
        vec!["cli-chat-proxy.grok.com".to_string()]
    );
    let step = surface.auth.first().expect("one auth step");
    assert_eq!(step.kind, AuthType::CredentialsMap);
    assert_eq!(step.path.as_deref(), Some("~/.grok/auth.json"));
    assert_eq!(
        step.key_prefix.as_deref(),
        Some("https://auth.x.ai::"),
        "the entry is selected by this prefix — a wrong one finds no credential at all"
    );
    assert_eq!(step.token_json_path.as_deref(), Some("key"));

    assert_eq!(m.balances.len(), 2);
    let prepaid = &m.balances[0];
    assert_eq!(prepaid.id, "prepaid");
    let remaining = prepaid.remaining.as_ref().expect("prepaid is a remainder");
    assert_eq!(remaining.kind, AmountKind::Number);
    assert_eq!(remaining.path.as_deref(), Some("config.prepaidBalance.val"));
    assert!(
        remaining.unit_label.is_none(),
        "the response states no scale for these figures, so the manifest names no unit"
    );
    assert_eq!(
        prepaid.source.period_end_path.as_deref(),
        Some("config.billingPeriodEnd")
    );
    assert_eq!(prepaid.source.period_end_format, ResetsAtFormat::Iso8601);

    assert!(
        prepaid.used.is_none() && prepaid.cap.is_none(),
        "prepaid is a remainder, not a pair"
    );

    let on_demand = &m.balances[1];
    assert_eq!(on_demand.id, "on-demand");
    let used = on_demand
        .used
        .as_ref()
        .expect("pay-as-you-go states what was spent");
    let cap = on_demand.cap.as_ref().expect("and its ceiling");
    assert_eq!(used.kind, AmountKind::Number);
    assert_eq!(cap.kind, AmountKind::Number);
    assert_eq!(used.path.as_deref(), Some("config.onDemandUsed.val"));
    assert_eq!(cap.path.as_deref(), Some("config.onDemandCap.val"));
    // Both, not just the first: a unit on one side and none on the other stops
    // them pairing, and the panel would show two rows where one was meant.
    assert!(used.unit_label.is_none() && cap.unit_label.is_none());
    assert!(
        on_demand.remaining.is_none(),
        "this row is a pair, not a remainder"
    );
    assert_eq!(
        on_demand.source.period_end_path.as_deref(),
        Some("config.billingPeriodEnd")
    );
    assert_eq!(on_demand.source.period_end_format, ResetsAtFormat::Iso8601);
    assert!(
        on_demand.source.percent_path.is_none(),
        "Grok states no percentage, and one computed from these two would be invented"
    );
}

#[test]
fn the_shipped_antigravity_manifest_is_accepted() {
    let text = include_str!("../plugins/antigravity.toml");
    let m = PluginManifest::from_str(text)
        .unwrap_or_else(|e| panic!("antigravity.toml must be valid: {e}"));
    assert_eq!(m.id, "antigravity");

    // The golden half: every path this provider depends on, asserted — a typo
    // in one is accepted by every check above and then silently reads nothing.
    // The request is a POST with an empty JSON body, gated on the client's own
    // User-Agent (a request without it is answered 403 "no license").
    let http = m.http.as_ref().expect("antigravity.toml declares [http]");
    let req = http.request.first().expect("one request");
    assert_eq!(
        req.url,
        "https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary"
    );
    assert_eq!(
        req.method,
        HttpMethod::Post,
        "Google's :verb transcoding is POST-only"
    );
    assert_eq!(
        req.body.as_deref(),
        Some("{}"),
        "the endpoint parses the body and wants {{}}"
    );
    assert_eq!(
        req.headers.get("Authorization").map(String::as_str),
        Some("Bearer {token}")
    );
    assert_eq!(
        req.headers.get("User-Agent").map(String::as_str),
        Some("antigravity/cli/1.1.17"),
        "the server gates on this exact agent string — without it, 403"
    );
    assert_eq!(
        req.headers.get("Content-Type").map(String::as_str),
        Some("application/json")
    );

    let surface = m.surface.first().expect("one surface");
    assert_eq!(
        surface.allowed_hosts,
        vec![
            "daily-cloudcode-pa.googleapis.com".to_string(),
            "oauth2.googleapis.com".to_string()
        ],
        "the refresh step needs Google's OAuth host allowed alongside the quota host"
    );
    // Hybrid auth: an expiry-aware keychain step first, an oauth-refresh
    // fallback second — the fresh token while Antigravity runs, a refresh when
    // it has lapsed. Order matters: a keychain step that could not stand aside
    // would stop the chain before the refresh ever ran.
    assert_eq!(surface.auth.len(), 2, "keychain then oauth-refresh");
    let keychain = &surface.auth[0];
    assert_eq!(keychain.kind, AuthType::Keychain);
    assert_eq!(keychain.service.as_deref(), Some("gemini"));
    assert_eq!(
        keychain.token_json_path.as_deref(),
        Some("token.access_token")
    );
    assert_eq!(
        keychain.expiry_json_path.as_deref(),
        Some("token.expiry"),
        "without an expiry path the keychain step cannot fall through to the refresh"
    );
    let refresh = &surface.auth[1];
    assert_eq!(refresh.kind, AuthType::OauthRefresh);
    assert_eq!(
        refresh.path.as_deref(),
        Some("~/.gemini/antigravity-cli/antigravity-oauth-token")
    );
    assert_eq!(
        refresh.token_json_path.as_deref(),
        Some("token.refresh_token")
    );
    assert_eq!(
        refresh.token_url.as_deref(),
        Some("https://oauth2.googleapis.com/token")
    );
    // The installed-app pair is discovered, not shipped: this repository
    // carries no literal `client_id`/`client_secret` for it (that pair used
    // to be typed out here, and going public is exactly why it no longer
    // is), only where to look and what shape to look for. Every field below
    // is asserted exactly — a typo in any of them is invisible otherwise,
    // since it would still parse as a perfectly good, wrong, discovery
    // config.
    assert!(
        refresh.client_id.is_none() && refresh.client_secret.is_none(),
        "the literal pair must not be here — that is the whole point of this change"
    );
    let client = refresh
        .client
        .as_ref()
        .expect("an oauth-refresh step with a client table");
    assert_eq!(
        client.id_env.as_deref(),
        Some("TICKOVER_ANTIGRAVITY_CLIENT_ID")
    );
    assert_eq!(
        client.secret_env.as_deref(),
        Some("TICKOVER_ANTIGRAVITY_CLIENT_SECRET")
    );
    // Exact, not merely bounded, the same reason `secret_pattern` below is —
    // `{12}`/`{32}` are the digit and alnum run lengths measured against a
    // real installed client, not a generous cap above them. A bounded-but-
    // not-exact count (the shape this used to be) still lets a stray digit
    // right before the real id get swallowed into a longer, wrong match;
    // an exact count cannot match that longer run at all (see
    // `scan_candidate_with_the_shipped_exact_id_pattern_does_not_swallow_a_leading_digit`
    // in `src/plugin/auth.rs`) — well short of the 256-byte ceiling
    // `manifest::validate` enforces on both patterns either way.
    assert_eq!(
        client.id_pattern.as_deref(),
        Some(r"[0-9]{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com")
    );
    // Exact, not open-ended: measured against a real installed copy of both
    // `language_server` and `agy`, the character class the format allows
    // keeps matching well past the secret's own end, so an unbounded count
    // silently pulls in trailing bytes that are not part of it. `{28}` is
    // Google's own fixed length for this secret shape, confirmed by the
    // measurement, not assumed from it.
    assert_eq!(
        client.secret_pattern.as_deref(),
        Some("GOCSPX-[A-Za-z0-9_-]{28}")
    );
    assert_eq!(
        client.files,
        vec![
            "/Applications/Antigravity.app/Contents/Resources/bin/language_server".to_string(),
            "~/Applications/Antigravity.app/Contents/Resources/bin/language_server".to_string(),
        ]
    );
    assert_eq!(client.bins, vec!["agy".to_string()]);
    for capability in [
        "keychain-expiry",
        "oauth-refresh",
        "oauth-client-discovery",
        "http-post",
        "remaining-fraction",
        "window-identity",
    ] {
        assert!(
            m.requires_reader.iter().any(|c| c == capability),
            "{capability} is load-bearing here"
        );
    }
    assert_eq!(m.requires_reader.len(), 6, "and nothing else is claimed");

    // Four windows, each addressed by its stable bucketId — a typo in a
    // selector reads nothing and the row silently vanishes.
    assert_eq!(m.windows.len(), 4);
    let by_id = |id: &str| {
        m.windows
            .iter()
            .find(|w| w.id == id)
            .unwrap_or_else(|| panic!("{id}"))
    };
    for (id, role, period, bucket, group) in [
        ("gemini-5h", Role::Primary, 300u64, "gemini-5h", 0),
        ("gemini-wk", Role::Secondary, 10080, "gemini-weekly", 0),
        ("3p-5h", Role::Extra, 300, "3p-5h", 1),
        ("3p-wk", Role::Extra, 10080, "3p-weekly", 1),
    ] {
        let w = by_id(id);
        assert_eq!(w.role, role, "{id} role");
        assert!(
            !w.required,
            "{id} is absent-tolerant: proto3 drops a zero fraction, and that silence is not an error"
        );
        assert_eq!(w.period.assumed, Some(period), "{id} period");
        assert!(
            w.source.used_percent_path.is_none(),
            "{id} states a remaining fraction, not spent"
        );
        assert_eq!(
            w.source.remaining_fraction_path.as_deref(),
            Some(format!("groups[{group}].buckets[bucketId={bucket}].remainingFraction").as_str()),
            "{id} figure path"
        );
        assert_eq!(
            w.source.resets_at_path,
            format!("groups[{group}].buckets[bucketId={bucket}].resetTime"),
            "{id} reset path"
        );
        assert_eq!(
            w.source.resets_at_format,
            ResetsAtFormat::Iso8601,
            "{id} reset format"
        );
    }
    assert_eq!(
        m.windows.iter().filter(|w| w.role == Role::Primary).count(),
        1,
        "exactly one window rides the menu bar"
    );
}

#[test]
fn the_shipped_copilot_manifest_is_accepted() {
    let text = include_str!("../plugins/copilot.toml");
    let m = PluginManifest::from_str(text)
        .unwrap_or_else(|e| panic!("copilot.toml must be valid: {e}"));
    assert_eq!(m.id, "copilot");
    // Like Grok and unlike everything else shipped: a monthly allowance, no
    // rolling window anywhere in the response, and nothing stated about the
    // standing of the quota as a whole.
    assert!(
        m.windows.is_empty(),
        "Copilot reports no window, only a monthly allowance"
    );
    assert!(
        m.status.is_none(),
        "Copilot states no standing above its buckets"
    );
    assert_eq!(
        m.refresh_secs, 300,
        "a monthly counter is polled at the client's own cadence, not once a minute"
    );
    // Asserted because nothing else would notice their loss: a manifest that
    // stops declaring these still parses, and an older build then reads a
    // provider it cannot understand as one that reported nothing.
    // Membership, not order: the list is a set, and a manifest that swaps two
    // lines has changed nothing a reader cares about.
    for capability in ["reading-balances", "credentials-map"] {
        assert!(
            m.requires_reader.iter().any(|c| c == capability),
            "{capability} is load-bearing here — without it an older build reads this manifest \
             as one that states nothing"
        );
    }
    assert_eq!(m.requires_reader.len(), 2, "and nothing else is claimed");
    assert_eq!(m.menu_label, "Cp");
    assert_eq!(m.order, 50, "after the four that shipped before it");

    // The golden half: every path this provider depends on, asserted — a typo
    // in one is accepted by every check above and then silently reads nothing.
    let http = m.http.as_ref().expect("copilot.toml declares [http]");
    let req = http.request.first().expect("one request");
    assert_eq!(req.url, "https://api.github.com/copilot_internal/user");
    assert_eq!(req.method, HttpMethod::Get);
    assert_eq!(
        req.headers.get("Authorization").map(String::as_str),
        Some("Bearer {token}"),
        "the token has to reach the request"
    );
    assert_eq!(
        req.headers.get("X-GitHub-Api-Version").map(String::as_str),
        Some("2025-05-01"),
        "the version pin the client sends — what keeps a default-version change from reshaping this"
    );
    assert!(
        !req.headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("Editor-Version")),
        "measured: auth alone answers 200, so this app claims no editor identity it does not have"
    );

    let surface = m.surface.first().expect("one surface");
    assert_eq!(surface.allowed_hosts, vec!["api.github.com".to_string()]);
    let step = surface.auth.first().expect("one auth step");
    assert_eq!(surface.auth.len(), 1);
    assert_eq!(step.kind, AuthType::CredentialsMap);
    assert_eq!(
        step.path.as_deref(),
        Some("~/.config/github-copilot/apps.json")
    );
    assert_eq!(
        step.key_prefix.as_deref(),
        Some("github.com:"),
        "keys are `<host>:<app-id>` and the app id differs per editor, so the prefix stops at the host"
    );
    assert_eq!(step.token_json_path.as_deref(), Some("oauth_token"));

    // Three rows, and the split matters: one for the bucket a paid plan meters,
    // two for the fields a free plan is metered through instead. Neither set of
    // paths exists in the other plan's response, so each draws only where it
    // applies.
    assert_eq!(m.balances.len(), 3);
    let premium = &m.balances[0];
    assert_eq!(premium.id, "premium");
    let remaining = premium.remaining.as_ref().expect("what is left");
    let cap = premium.cap.as_ref().expect("and its ceiling");
    assert_eq!(remaining.kind, AmountKind::Number);
    assert_eq!(cap.kind, AmountKind::Number);
    assert_eq!(
        remaining.path.as_deref(),
        Some("quota_snapshots.premium_interactions.quota_remaining"),
        "the fractional figure the provider's own percentage is computed from, not its floored twin"
    );
    assert_eq!(
        cap.path.as_deref(),
        Some("quota_snapshots.premium_interactions.entitlement")
    );
    // Both, not just one: a unit on one side and none on the other stops them
    // pairing, and the panel would show two rows where one was meant.
    assert_eq!(remaining.unit_label.as_deref(), Some("interactions"));
    assert_eq!(cap.unit_label.as_deref(), Some("interactions"));
    assert!(
        premium.used.is_none(),
        "no spent figure is stated, and one derived here would be ours"
    );
    assert_eq!(
        premium.source.period_end_path.as_deref(),
        Some("quota_reset_date_utc")
    );
    assert_eq!(premium.source.period_end_format, ResetsAtFormat::Iso8601);
    assert!(
        premium.source.percent_path.is_none(),
        "the stated percentage is a *remaining* one, and the panel prints a stated percent as used"
    );

    // The free-plan pair, per bucket. Which path is the remainder and which is
    // the ceiling is the one thing here that cannot be guessed: the client
    // divides `limited_user_quotas` by `monthly_quotas` to get what is left, so
    // swapping them would draw a whole month's allowance as the remainder.
    for (i, id, label, bucket) in [
        (1, "free-chat", "Chat", "chat"),
        (2, "free-completions", "Completions", "completions"),
    ] {
        let b = &m.balances[i];
        assert_eq!(b.id, id);
        assert_eq!(b.label, label);
        let remaining = b
            .remaining
            .as_ref()
            .unwrap_or_else(|| panic!("{id} states what is left"));
        let cap = b
            .cap
            .as_ref()
            .unwrap_or_else(|| panic!("{id} states a ceiling"));
        assert_eq!(
            remaining.path.as_deref(),
            Some(format!("limited_user_quotas.{bucket}").as_str())
        );
        assert_eq!(
            cap.path.as_deref(),
            Some(format!("monthly_quotas.{bucket}").as_str())
        );
        // No unit: the row label names what is counted, and "20 chat / 50 chat"
        // reads worse than "20 / 50".
        assert!(remaining.unit_label.is_none() && cap.unit_label.is_none());
        assert!(
            b.used.is_none(),
            "no spent figure is stated on this plan either"
        );
        assert_eq!(
            b.source.period_end_path.as_deref(),
            Some("limited_user_reset_date")
        );
    }
}

/// The panel draws `remaining` and `cap` as one pair when a balance states no
/// `used` — a rendering branch added for Copilot. Which other shipped rows it
/// reaches is a question about the manifests, so it is answered here: none.
/// Claude declares no balances at all, Codex's is a lone remainder, and Grok's
/// two are a lone remainder and a used/cap pair.
#[test]
fn only_copilot_declares_the_remainder_pair_the_panel_draws_as_one_line() {
    for (name, contents) in DEFAULT_TEMPLATES {
        let m = PluginManifest::from_str(contents).unwrap_or_else(|e| panic!("{name}: {e}"));
        for b in &m.balances {
            let remainder_pair = b.used.is_none() && b.cap.is_some() && b.remaining.is_some();
            assert_eq!(
                remainder_pair,
                m.id == "copilot",
                "{name}: balance `{}` — this shape is Copilot's alone today, and a second one \
                 arriving unnoticed is how a rendering change reaches a card nobody looked at",
                b.id
            );
        }
    }
}

// ── Garbage in ───────────────────────────────────────────────────────────

/// xorshift64, seeded per case: a failure names a seed that reproduces it.
struct Rng(u64);

impl Rng {
    fn seeded(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Damage a manifest at random. Mutations rather than random bytes on
/// purpose: random bytes die in the TOML parser and prove only that the TOML
/// parser works, while a manifest with one field emptied, one type swapped or
/// one stray character inserted reaches `validate`, which is where the
/// interesting answers are.
fn mangled(rng: &mut Rng, base: &str) -> String {
    let mut lines: Vec<String> = base.lines().map(str::to_string).collect();
    if lines.is_empty() {
        return String::new();
    }
    for _ in 0..1 + rng.below(3) {
        let which = rng.below(lines.len() as u64) as usize;
        let line = lines[which].clone();
        lines[which] = match rng.below(10) {
            0 => String::new(),                     // delete it
            1 => line.replacen('=', "= \"\" #", 1), // empty the value
            2 => line.replacen('=', "= 0 #", 1),    // wrong type, or zero
            3 => format!("{line}{line}"),           // duplicate it in place
            4 => line.replace('"', ""),             // unquote
            5 => format!("{{{line}"),               // stray brace
            6 => match rng.below(2) {
                // an undeclared placeholder
                0 => line.replacen('=', "= \"{value.nope}\" #", 1),
                _ => line.replacen('=', "= \"{option.nope}\" #", 1),
            },
            7 => line.replace(['a', 'e', 'i'], "*"), // wildcards, typos, bad chars
            // Point the manifest at the other engine, leaving the section for
            // the one it came from — the mismatch a copied-and-edited
            // third-party manifest arrives as.
            8 => match line.trim().starts_with("engine") {
                true => "engine = \"http-api\"".to_string(),
                false => format!("{line}\nengine = \"log-file\""),
            },
            _ => format!("{line}\n[[surface]]\nid = \"extra\"\nlabel = \"Extra\""),
        };
    }
    lines.join("\n")
}

#[test]
fn no_damaged_manifest_is_ever_accepted_as_one_an_engine_could_run() {
    for seed in 1..=20_000u64 {
        let mut rng = Rng::seeded(seed);
        let base = if seed % 2 == 0 { LOGFILE } else { HTTP };
        let input = mangled(&mut rng, base);

        // Whatever comes back, it comes back: `from_str` is the front door
        // for a file a third party wrote, and a panic there is a crash on
        // somebody else's typo.
        let Ok(m) = PluginManifest::from_str(&input) else {
            continue;
        };

        // Accepted. Then it has to be a manifest an engine can actually run —
        // these are the things `engine_http::fetch_surface` and
        // `engine_logfile::fetch` assume without checking, asked here rather
        // than by re-running the validation that just said yes.
        let why = |what: &str| format!("accepted at seed {seed} but {what}:\n{input}");
        assert!(!m.windows.is_empty(), "{}", why("has no window to fill"));
        assert!(!m.id.is_empty(), "{}", why("has no id to file it under"));

        // Every placeholder, everywhere either engine reads one, names
        // something declared — the check that motivated this test, because
        // both engines substitute what they know and leave the rest visible,
        // which turns a typo into a request (or a path) with braces in it.
        let values: Vec<&str> = m
            .http
            .iter()
            .flat_map(|h| h.value.iter().map(|v| v.name.as_str()))
            .collect();
        let options: Vec<&str> = m.option.iter().map(|o| o.key.as_str()).collect();
        let mut substituted: Vec<&str> = Vec::new();
        if let Some(http) = &m.http {
            for req in &http.request {
                substituted.push(req.url.as_str());
                substituted.extend(req.headers.values().map(String::as_str));
            }
        }
        if let Some(lf) = &m.logfile {
            substituted.extend([lf.root.as_str(), lf.glob.as_str()]);
        }
        substituted.extend(m.account.url.as_deref());
        for text in substituted {
            for name in text.split("{value.").skip(1) {
                let name = name.split('}').next().unwrap_or_default();
                assert!(
                    values.contains(&name),
                    "{}",
                    why(&format!("names {{value.{name}}}"))
                );
            }
            for key in text.split("{option.").skip(1) {
                let key = key.split('}').next().unwrap_or_default();
                assert!(
                    options.contains(&key),
                    "{}",
                    why(&format!("names {{option.{key}}}"))
                );
            }
        }
        match m.engine {
            EngineKind::LogFile => {
                let lf = m
                    .logfile
                    .as_ref()
                    .unwrap_or_else(|| panic!("{}", why("has no [logfile]")));
                assert!(
                    !lf.glob.is_empty(),
                    "{}",
                    why("would match every file or none")
                );
            }
            EngineKind::HttpApi => {
                let http = m
                    .http
                    .as_ref()
                    .unwrap_or_else(|| panic!("{}", why("has no [http]")));
                assert_eq!(
                    http.request.len(),
                    1,
                    "{}",
                    why("does not call exactly one endpoint")
                );
                assert!(
                    http.backoff_start_secs > 0,
                    "{}",
                    why("would retry without pausing")
                );

                for req in &http.request {
                    assert!(!req.url.trim().is_empty(), "{}", why("has no URL to call"));
                }
            }
        }
    }
}

// ── The thing that keeps this list from rotting ──────────────────────────

#[test]
fn the_corpus_has_a_line_for_every_rule_the_validator_enforces() {
    // Counted from the source rather than kept in a constant, because a
    // constant is one more thing to forget. If this fails, `validate` gained
    // or lost a refusal: add the row that describes it (or delete the row
    // that described what is gone), and the two numbers agree again.
    //
    // What it is: a grep, and it reads like one. It cannot see a rule folded
    // into a refusal that already exists — another entry in one of the
    // "which field is missing" tables raises no count — and it will need
    // adjusting if `validate` is ever refactored to return through `?`. Both
    // are worth living with: a mechanism that catches the common case loudly
    // beats a comment asking people to remember, and neither failure mode is
    // silent for long, because the row you would have to delete to satisfy it
    // is the one that describes the rule you just wrote.
    // Two functions refuse manifests, not one: `validate` for the schema's own
    // invariants, and the capability gate for what a manifest asks this build
    // to be able to *do*. Counting only the first would let every rule the
    // second gains go unwritten — which is the rot this test exists to stop.
    let refusals_in = |source: &str, signature: &str, ends_with: &str| -> usize {
        let start = source.find(signature).unwrap_or_else(|| {
            panic!("`{signature}` was renamed — point this at whatever refuses manifests now")
        });
        let end = source[start..].find(ends_with).unwrap_or_else(|| {
            panic!("`{signature}` no longer ends with `Ok(())` where this expects — update the locator")
        });
        // Comment lines don't count. A grep this literal is otherwise inflated
        // by a comment that quotes the thing it is counting — which happened
        // the first time a comment explained why one refusal carries two
        // messages, and cost a red build to notice.
        source[start..start + end]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .map(|line| line.matches("return Err(").count())
            .sum()
    };

    let enforced = refusals_in(
        include_str!("../src/plugin/manifest.rs"),
        "pub fn validate(&self)",
        "\n        Ok(())\n    }\n}",
    ) + refusals_in(
        include_str!("../src/plugin/capability.rs"),
        "pub fn check_against(",
        "\n    Ok(())\n}",
    );

    assert_eq!(
        rules().len(),
        enforced,
        "a manifest is refused in {enforced} places and this corpus describes {} of them",
        rules().len()
    );
}
