//! Reader capabilities — what a manifest may ask this build of the reader to
//! do, declared by name in `requires_reader`.
//!
//! The manifest schema grows. `#[serde(deny_unknown_fields)]` is deliberately
//! off (see [`crate::plugin::manifest`]), so a build that predates a field
//! ignores it — which is right for a cosmetic addition and badly wrong for one
//! that changes what a number *means*. The shape of that failure is the reason
//! this module exists: a manifest that says "the used figure is in this field
//! now" is read by an older build as "that field does not exist", and the
//! older build then finds the legacy field beside it and draws a confident,
//! wrong number. Nothing is missing from the screen, so nothing looks broken.
//!
//! So a manifest names the capabilities it needs, and the check runs **both
//! ways**:
//!
//! * **Forward** — a name this build does not implement is refused. That is
//!   the half that makes the declaration worth writing: an older reader stops
//!   instead of guessing.
//! * **Backward** — a manifest that *uses* a capability's fields without
//!   naming it is refused too. Without this half the forward check protects
//!   only the authors who remember to opt in, which is the ones who did not
//!   need protecting.
//!
//! ## Why the backward check reads raw TOML
//!
//! Detection is by manifest key ([`Capability::keys`]), resolved against the
//! parsed TOML rather than against [`crate::plugin::manifest::PluginManifest`].
//! That is what lets this build refuse a manifest written for a *newer* schema
//! than its own struct has fields for: the key is a string, and a string can be
//! recognised by a build that has nowhere to put the value. Struct-based
//! detection would only ever see fields this build already implements, which
//! closes the hole one release later than it can be closed.
//!
//! That is also why [`Capability::implemented`] exists, and why a capability is
//! listed here *before* it is implemented: listed-and-unimplemented is
//! precisely the state in which a manifest from the future gets a loud,
//! accurate refusal rather than a quiet misreading.
//!
//! ## Keeping the key lists honest
//!
//! A [`Capability::keys`] entry is a promise about a spelling. Get one wrong —
//! list `windows.required` when the field ships as `windows.source.required` —
//! and the backward check silently passes the manifest it exists to catch. Two
//! rules keep them true:
//!
//! 1. **Adding a manifest field adds that field's spelling here, in the same
//!    change**, and re-checks the ones already listed against what it
//!    actually wrote. Where the home of a field is still an open question,
//!    list every plausible one: `keys` is an "any of these" list, and a spare
//!    spelling costs only the chance that somebody else's manifest uses that
//!    exact path for something of their own.
//! 2. **A capability's semantics are introduced by a new key — never by
//!    widening the grammar of an existing value.** This one is a project
//!    constraint, not an observation, and it is load-bearing: detection reads
//!    keys, so it is blind to a new syntax *inside* a value. This manifest
//!    language already grows that way —
//!    `containers = ["additional_rate_limits[limit_name=…]"]` puts a selector
//!    inside a string — so a future capability would walk into it by default. A
//!    `containers = ["…[*]"]` meaning "one row per element" would add no key,
//!    trip nothing here, and be read by an older build as the single empty row
//!    this whole module exists to prevent. If a future capability genuinely
//!    needs value-shaped detection, [`Capability`] has to grow a predicate;
//!    until then, new key.
//!
//! ## What this costs
//!
//! Detection cannot tell our field from somebody else's field of the same
//! name at the same depth. A third-party manifest that already carries, say,
//! its own `severity_path` under `[windows.source]` loaded fine before this
//! and is refused now. That is a deliberate breaking change, and the right way
//! round: the alternative is to keep loading it and, once the capability is
//! implemented, read their field as ours.

use std::collections::HashSet;

/// One reader capability: a name a manifest may declare, and the manifest keys
/// whose presence means it is being used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Capability {
    /// The name as written in `requires_reader`. Kebab-case, and a shipped
    /// contract once published — a manifest in somebody else's registry spells
    /// it, so it is renamed only by adding the new name beside the old.
    pub name: &'static str,
    /// Whether **this** build implements it. A capability is listed here from
    /// the moment its name and key spellings are known, and flips to `true` in
    /// the change that implements it — see the module docs for why the
    /// listed-but-unimplemented state is the useful one.
    pub implemented: bool,
    /// Manifest key paths that mean this capability is in use — any one of
    /// them is enough. Dotted from the document root; an array of tables on
    /// the way (`windows`) is walked through, so `windows.required` means "a
    /// `required` key in any `[[windows]]` table". A `*` segment matches any
    /// key of a table, so `status.*` means "a `[status]` table with something
    /// in it" — which is how to name a section whose own field names are not
    /// settled yet without guessing at them.
    pub keys: &'static [&'static str],
}

/// Every capability this build knows the name of.
///
/// These are the vocabulary of the dynamic-limits work: the number of rows in
/// the panel comes from what a provider actually reports, and each one
/// changes what a manifest field means rather than only adding one.
/// `implemented` is the per-capability bit — see the module docs.
pub(crate) const CAPABILITIES: &[Capability] = &[
    // Window presence. A window whose paths do not resolve in a successfully
    // parsed response stops being emitted at all, instead of being emitted
    // blank, and `required` marks the windows whose absence is the provider's
    // error rather than a plan that simply has no such limit. A build without
    // this draws an empty row where the newer one draws nothing, and reads a
    // `required` it does not know as "there is no such field".
    //
    // The spare spelling is gone: the field shipped on `[[windows]]` itself,
    // beside `label` and `role`, because it says what the row *is* rather than
    // where to read it from. Re-checking that against what was actually
    // written — and deleting the home that turned out not to be one — is rule
    // 1 of the module docs being followed rather than quoted.
    Capability {
        name: "window-presence",
        implemented: true,
        keys: &["windows.required"],
    },
    // Quota status. The standing of the quota itself (`allowed` / `limit_reached` /
    // `reached_type`), which a provider states above its windows and can state
    // when it reports no window at all. A build that ignores `[status]` shows
    // an account as fine while the provider is refusing it.
    //
    // `status.*` rather than `status`: the field names inside that section were
    // not settled when the name shipped, and a bare `status` would also match a
    // scalar — somebody else's `status = "beta"` annotation, which this build
    // ignores today and would start refusing with advice ("update the app")
    // that does not help, because no version of the app will ever read their
    // string as our section. The wildcard stays now that the fields *are*
    // settled: it costs nothing and it keeps that scalar passing.
    Capability {
        name: "reading-status",
        implemented: true,
        keys: &["status.*"],
    },
    // Window identity. `[[windows]] id` — the stable half of a window's key. A build
    // that ignores it keys the window by position instead, so the same window
    // is filed under two different registry keys depending on which build wrote
    // it, and the auto-ping loses the boundary it was working from.
    Capability {
        name: "window-identity",
        implemented: true,
        keys: &["windows.id"],
    },
    // Copilot. A `[[balances]]` entry's own `used`/`cap`/`remaining` read as
    // an ordinary numeric pair by default — right for a metered bucket, wrong
    // for one the response has marked `unlimited = true`, which an older
    // build would draw as `0 / 0`, indistinguishable from an exhausted quota
    // rather than one with no ceiling at all.
    //
    // Listed *before* `reading-balances` below, not just alongside it: its
    // own key nests inside `balances.*`, which `reading-balances`' own
    // wildcard also matches, and the backward check below reports whichever
    // capability it reaches first in this array — after `reading-balances`,
    // a document setting only `balances.unlimited.path` would be refused in
    // that capability's name instead of this one's, and
    // `every_key_in_the_shipped_table_reaches_its_own_capability` catches
    // exactly that shadowing.
    Capability {
        name: "balance-unlimited",
        implemented: true,
        keys: &["balances.unlimited.path"],
    },
    // Claude's `extra_usage`, which the response states whether or not the
    // account has it enabled — an older build has no notion of drawing an
    // entry conditionally, so it would show a disabled account's own zeroed
    // (`null`) figures as a real, empty balance rather than no row at all.
    // Ordered before `reading-balances` for the same shadowing reason as
    // `balance-unlimited` just above.
    Capability {
        name: "balance-conditional",
        implemented: true,
        keys: &["balances.when.path"],
    },
    // Balances. Figures against a calendar period — credits left, spent this
    // month — which a provider may report instead of, not only beside, its
    // windows. A build without this ignores `[[balances]]` entirely, and for a
    // provider whose manifest declares no `[[windows]]` at all that is a
    // section header with nothing under it: the app would say the account
    // reported no usage while the provider was answering fine.
    //
    // `balances.*` rather than `balances`: the whole section is new, so every
    // key inside it is unreadable to an older build, and naming them one by one
    // would mean amending this list for each figure a later addition reads.
    Capability {
        name: "reading-balances",
        implemented: true,
        keys: &["balances.*"],
    },
    // Window severity. The server's own per-window severity. Split out of
    // `reading-status`, which it shipped inside: `reading-status` covers the
    // quota's status but *not* this, and leaving the two under one name would
    // have let a manifest declare `reading-status`, write `severity_path`, and
    // be accepted by a build that then ignores the field — the exact silent
    // misreading this whole mechanism exists to refuse.
    //
    // Measured rather than assumed: Claude states `severity` only inside
    // `limits[]` elements, which needs an entry that can enumerate an array
    // (`for-each-windows`, implemented separately) to reach at all — and this
    // capability itself is not implemented yet.
    Capability {
        name: "window-severity",
        implemented: false,
        keys: &["windows.severity_path", "windows.source.severity_path"],
    },
    // Enumerating windows. One `[[windows]]` entry expands into a row per
    // element of an array in the response. A build that ignores `for_each`
    // reads the entry as a single window and resolves its paths against the
    // array itself — one row where there should be several, filled with
    // nothing.
    // The spare spelling is gone, like `window-presence`'s was: the keys
    // shipped on `[[windows]]` itself, beside `label` and `role`, because they
    // say what the *entry* is (one row or many) rather than where a figure is
    // read from. `for_each_where` and `element_id_path` are named here for the
    // same reason `for_each` is — an older build ignores each of them
    // separately, and ignoring the filter alone would draw a row for every
    // element of an array the manifest meant to select three from.
    Capability {
        name: "for-each-windows",
        implemented: true,
        keys: &[
            "windows.for_each",
            "windows.for_each_where",
            "windows.element_id_path",
        ],
    },
    // Grok. `[[surface.auth]]`'s dotted-path grammar cannot select a
    // credential keyed by `"https://auth.x.ai::<client-id>"` — the part
    // after `::` is xAI's own OAuth client id, a fixed value this login flow
    // always uses, not one that varies by install: `json_path` and
    // `token_json_path` split on `.`, and `token_json_path`'s own fallback
    // list splits on `|` on top of that — neither can name a key that itself
    // holds dots and colons. `credentials-map` reads the top-level object at
    // `path` as a map of records and selects the one entry whose key starts
    // with `key_prefix`, so `key_prefix` is the field spelling here — the new
    // key rule 2 in the module docs calls for, since `type =
    // "credentials-map"` is a value the detector cannot see.
    //
    // What a build without this capability actually does with such a
    // manifest is not the usual silent-misread this mechanism exists to
    // catch: `AuthType` is a closed enum, so an unrecognized `type` fails the
    // *whole document's* typed parse rather than being ignored field-by-field
    // the way an unknown `bool` would be. Either way — declared or not — that
    // build cannot run the manifest, and `load_plugins_from` skips a manifest
    // that fails to load exactly like one that was never dropped in the
    // plugins directory: a `diag::line`, the provider simply absent from the
    // panel, nothing said to the user. What the declaration changes is which
    // message lands in that log line: the forward check on `requires_reader`
    // runs *before* the typed parse ever reaches the unknown variant, and
    // answers by name — "update the app" — instead of a raw `unknown variant
    // credentials-map` a human did not write for another human to read.
    Capability {
        name: "credentials-map",
        implemented: true,
        keys: &["surface.auth.key_prefix"],
    },
    // Antigravity. Every provider through Grok answers a plain GET;
    // Antigravity's `:retrieveUserQuotaSummary` follows Google's `:verb`
    // HTTP-transcoding convention, which is POST-only. A build without this
    // capability sends the GET such a manifest never asked for, gets back a
    // 404/405, and shows the provider as broken rather than "update the app".
    //
    // Two keys, not one: `method` alone is not enough, because a manifest
    // could in principle write `method = "post"` with no `body` and an older
    // build's silent-GET behaviour would already be wrong for it — the
    // capability has to cover whichever field the manifest actually used.
    Capability {
        name: "http-post",
        implemented: true,
        keys: &["http.request.method", "http.request.body"],
    },
    // Antigravity, continued. It states a *remaining* fraction, not a spent
    // percent; the engine complements it into the consumed-percent a window
    // holds. A build without this reader has no notion of the key, so a window
    // stating only `remaining_fraction_path` would read as one stating nothing
    // — the row would vanish rather than say "update the app". Named by the
    // key only this form writes.
    Capability {
        name: "remaining-fraction",
        implemented: true,
        keys: &["windows.source.remaining_fraction_path"],
    },
    // Grok. A window's own length read off the response's stated bounds
    // (`start_path`/`end_path`, an RFC3339 pair) rather than a number typed
    // into the manifest or read directly out of one field — for a provider
    // that states its period as "from here to there" instead of a duration.
    // What a build without this capability actually does is the same shape
    // `credentials-map`'s own comment walks through: `PeriodMode` is a closed
    // enum, so `mode = "from_bounds"` fails the whole document's typed parse
    // rather than being ignored field-by-field, and the declaration only
    // changes which message that build gives for it.
    Capability {
        name: "window-period-bounds",
        implemented: true,
        keys: &["windows.period.start_path", "windows.period.end_path"],
    },
    // Antigravity's hybrid auth. A `keychain`/`credentials-file`/
    // `win-credential` step that names an expiry resolves Absent when the
    // token has lapsed, so a refresh step behind it fires (or, with
    // `[ping] renews_token`, a renewal ping) — an older build has no notion
    // of the field and would return the stale token instead, silently
    // defeating the fall-through. Named by the one key only this behaviour
    // writes.
    Capability {
        name: "keychain-expiry",
        implemented: true,
        keys: &["surface.auth.expiry_json_path"],
    },
    // Claude's CLI honours `CLAUDE_CONFIG_DIR` for where it keeps
    // `.credentials.json`; a `credentials-file` step reading the fixed
    // `~/.claude/...` path unconditionally misses that override entirely —
    // not merely a stale figure, but the wrong file (or none) once the
    // account has ever set it. An older build has no notion of `path_env`/
    // `path_env_join` at all, so it would keep reading the un-overridden
    // path and report the surface as signed out.
    Capability {
        name: "credentials-file-path-env",
        implemented: true,
        keys: &["surface.auth.path_env", "surface.auth.path_env_join"],
    },
    // Codex's CLI honours `CODEX_HOME` for where it keeps `auth.json`, and a
    // `[[http.value]]` `json-file` read that ignores the override reads the
    // default `~/.codex/auth.json` — the wrong file, or none, on an account
    // that has ever set it. `surface.auth.path_env` is a *different* spelling
    // already covered by `credentials-file-path-env`; this one is new, so it
    // gets a name no older build knows — a manifest that uses it is refused
    // rather than quietly read from the un-overridden path.
    Capability {
        name: "http-value-path-env",
        implemented: true,
        keys: &["http.value.path_env", "http.value.path_env_join"],
    },
    // Claude's CLI, continued: `CLAUDE_CONFIG_DIR` also renames the Keychain
    // item it writes, not only the credentials file `credentials-file-path-env`
    // above covers — a `keychain` step that always queries the fixed default
    // service reads nothing on an account that has ever set the variable. An
    // older build has no notion of `service_env`/`service_env_suffix` at all,
    // so it would keep querying the un-rekeyed service name and report the
    // surface as signed out.
    Capability {
        name: "keychain-service-env",
        implemented: true,
        keys: &[
            "surface.auth.service_env",
            "surface.auth.service_env_suffix",
        ],
    },
    // Antigravity's hybrid, continued. `oauth-refresh` is the one auth step
    // that spends a credential instead of only reading one; an older build has
    // no notion of it. `surface.auth.token_url` rather than `type`: `AuthType`
    // is a closed enum, so an unrecognized `type = "oauth-refresh"` already
    // fails the whole document's typed parse in a build that lacks the variant
    // — the detector needs a key only this step writes, and `token_url` is it.
    Capability {
        name: "oauth-refresh",
        implemented: true,
        keys: &["surface.auth.token_url"],
    },
    // Antigravity's hybrid, continued once more. The repository cannot ship
    // `oauth-refresh`'s installed-app pair in plain text (it is the client's
    // own secret, and GitHub's push protection refuses the commit either
    // way), so `[surface.auth.client]` reads it back out of the installed
    // client's own binary at run time instead. An older build has no notion
    // of the table at all — it would simply never resolve a client id/secret
    // for such a step, which for `oauth-refresh` is silently indistinguishable
    // from "not signed in": the surface goes missing rather than saying
    // "update the app". `surface.auth.client.*`, matching `status.*`'s
    // wildcard: every field inside the table is new, so naming the section
    // rather than each field covers the whole table in one entry.
    Capability {
        name: "oauth-client-discovery",
        implemented: true,
        keys: &["surface.auth.client.*"],
    },
];

/// Check a manifest's `requires_reader` against this build, both ways.
///
/// `raw` is the manifest's parsed TOML, not the deserialized
/// [`crate::plugin::manifest::PluginManifest`] — including the `requires_reader`
/// list itself, which is read straight out of the document. That is not
/// tidiness: this check has to answer *before* the document is fitted into
/// this build's struct, or it never gets asked at all in the case that matters
/// most. A manifest from the future does not only add fields; it also changes
/// the type of one that already exists (a `label` that becomes a table, say),
/// and typed deserialization refuses that with a TOML type error while the
/// `requires_reader` line naming the capability sits unread three lines above.
pub fn check(raw: &toml::Value) -> Result<(), String> {
    check_against(CAPABILITIES, raw)
}

/// The `requires_reader` list as the document spells it.
///
/// A value of the wrong shape reads as *less* than it says here — a bare
/// string declares nothing, a non-string entry is skipped — and never as more,
/// so nothing gets past the check by being mistyped. What the difference costs
/// is only which complaint arrives first: `["window-severity", 7]` is refused
/// here for the name (a capability this build knows but does not implement),
/// and the `7` is never mentioned, where deserializing into `Vec<String>`
/// would have named it.
fn declared_in(raw: &toml::Value) -> Vec<&str> {
    raw.get("requires_reader")
        .and_then(toml::Value::as_array)
        .map(|entries| entries.iter().filter_map(toml::Value::as_str).collect())
        .unwrap_or_default()
}

/// [`check`] against an arbitrary capability table.
///
/// Split out for the tests: a synthetic table keeps both sides of
/// `implemented` reachable and deterministic, independent of which
/// capabilities the shipped table happens to have flipped to `true`.
pub(crate) fn check_against(table: &[Capability], raw: &toml::Value) -> Result<(), String> {
    let declared = declared_in(raw);
    // Two passes, and the split matters: a list that is malformed as a *list*
    // is said so whatever this build happens to implement. Folded into one
    // pass, "you wrote it twice" would be reachable only for a name that got
    // past the lookup — which, in a build that implements none of them yet, is
    // no name at all.
    let mut seen: HashSet<&str> = HashSet::new();
    for entry in &declared {
        let name = entry.trim();
        if name.is_empty() {
            return Err("`requires_reader` entries must not be blank".to_string());
        }
        if !seen.insert(name) {
            return Err(format!("`requires_reader` names \"{name}\" more than once"));
        }
    }

    // Forward: everything declared has to be a name this build can honour.
    for entry in &declared {
        let name = entry.trim();
        match table.iter().find(|c| c.name == name) {
            Some(c) if c.implemented => {}
            // Known by name, not implemented here. Worth its own message: the
            // author's manifest is fine and the app is the old half, which is a
            // different thing to do about it than a typo.
            Some(_) => {
                return Err(format!(
                    "`requires_reader` names \"{name}\", a reader capability this version of \
                     Tickover knows about but does not implement — update the app to use \
                     this plugin"
                ));
            }
            None => {
                return Err(format!(
                    "`requires_reader` names \"{name}\", which is not a reader capability this \
                     build knows about — check the spelling, or update the app if the plugin was \
                     written for a newer one"
                ));
            }
        }
    }

    // Backward speaks only for a document that claims to be one of our
    // manifests at all. `id` is the field that makes that claim: it has no
    // default, it names the file on disk, and no manifest of any vintage
    // reaches this app without it.
    //
    // Without this line the reordering that put the check ahead of the typed
    // parse would answer for somebody else's TOML too — a notes file with a
    // `[status]` section in it would be told to update the app, advice that
    // can never come true because that file is not going to become a manifest
    // in any version. The forward half needs no such guard: it fires only on a
    // document that wrote `requires_reader` itself.
    if raw.get("id").is_none() {
        return Ok(());
    }

    // Backward: everything used has to have been declared.
    for cap in table {
        let Some(key) = cap.keys.iter().find(|key| has_key_path(raw, key)) else {
            continue;
        };
        if seen.contains(cap.name) {
            continue;
        }
        // One rule — "a capability you use, you declare" — with the sentence
        // that fits the case. The manifest is equally refused either way; what
        // differs is whether the fix is a line in the manifest or a newer app.
        //
        // One refusal and two texts, which the corpus counter in
        // `tests/manifest_corpus.rs` sees as one rule — it counts early
        // returns, so this comment carefully does not spell one. The corpus
        // row ("a manifest that uses a capability's fields has to declare
        // it") exercises the `true` branch: `windows.required` belongs to
        // `window-presence`, implemented since that capability shipped —
        // `using_an_implemented_capability_without_declaring_it_is_refused`
        // covers the same branch again, against a synthetic table, so it
        // stays reachable however the shipped one changes. The `false`
        // branch is covered here in this file instead, against a capability
        // this build genuinely does not implement yet:
        // `window_severity_is_named_but_not_implemented_so_its_field_is_refused`
        // (the shipped table) and the second half of
        // `a_capability_this_build_does_not_implement_is_refused_either_way`
        // (a synthetic one).
        return Err(if cap.implemented {
            format!(
                "this plugin sets `{key}`, which needs the reader capability \"{}\" — declare it \
                 with `requires_reader = [\"{}\"]`",
                cap.name, cap.name
            )
        } else {
            format!(
                "this plugin sets `{key}`, which needs the reader capability \"{}\" that this \
                 version of Tickover does not implement — update the app to use this plugin",
                cap.name
            )
        });
    }

    Ok(())
}

/// Whether `path` names a key that exists in `raw`, at exactly that depth.
///
/// Segments are separated by `.`; an array on the way is walked through
/// element-wise, so `windows.required` matches a `required` key in any
/// `[[windows]]` table. A `*` segment matches any key of a table.
///
/// Depth is exact on purpose: a bare "is there a key called `required`
/// anywhere in this document" would refuse a third-party manifest for a field
/// of its own that happens to share a name with one of ours. Exactness is also
/// what makes the last segment's *value* irrelevant — reaching it is the
/// answer, so a scalar where our schema expects a table stops the walk one
/// segment short and is left alone.
fn has_key_path(raw: &toml::Value, path: &str) -> bool {
    // `segments: impl Iterator<Item = &str> + Clone` rather than a collected
    // `Vec<&str>` — this runs at every manifest load, and every path here is
    // a handful of dotted words, so the allocation bought nothing `Split`
    // (already `Clone`) didn't already have for free. `segments` itself is
    // never advanced directly — only a clone of it is (`peek`, below) — so
    // every recursive call still has the same concrete iterator type to
    // pass on, whichever branch it takes.
    fn walk<'a>(value: &toml::Value, segments: impl Iterator<Item = &'a str> + Clone) -> bool {
        let mut peek = segments.clone();
        let Some(head) = peek.next() else {
            // Every segment matched, so the key named by the last one exists —
            // whatever its value is. Presence is the question; a `required =
            // false` uses the capability exactly as much as a `true` does.
            return true;
        };
        match value {
            toml::Value::Table(table) => match head {
                "*" => table.values().any(|v| walk(v, peek.clone())),
                key => table.get(key).is_some_and(|v| walk(v, peek.clone())),
            },
            // Not a step of its own: `[[windows]]` is spelled `windows` in a
            // path, and the elements are what the next segment applies to —
            // `segments`, not `peek`, so `head` is still there for every
            // element to match against in turn.
            toml::Value::Array(items) => items.iter().any(|v| walk(v, segments.clone())),
            _ => false,
        }
    }
    walk(raw, path.split('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A table with one capability in each state, so both sides of
    /// `implemented` are reachable regardless of what the shipped table
    /// currently holds.
    const TABLE: &[Capability] = &[
        Capability {
            name: "done",
            implemented: true,
            keys: &["windows.required"],
        },
        Capability {
            name: "not-yet",
            implemented: false,
            keys: &["status.*", "windows.source.severity_path"],
        },
    ];

    fn toml_of(text: &str) -> toml::Value {
        toml::from_str(text).expect("test TOML must parse")
    }

    const PLAIN: &str = r#"
        id = "sample"
        [[windows]]
        label = "5H"
        [windows.source]
        used_percent_path = "used_percent"
    "#;

    /// `PLAIN` with `line` added to the `[[windows]]` table itself — which is
    /// not the same as appending to the end of the file, where the last
    /// `[windows.source]` header is still open and would swallow it.
    fn in_window(line: &str) -> String {
        PLAIN.replace("label = \"5H\"", &format!("label = \"5H\"\n        {line}"))
    }

    /// `text` declaring `requires_reader = <list>`, written at the document
    /// root — where, for the same reason as `in_window`, appending would not
    /// put it.
    fn declaring(text: &str, list: &str) -> String {
        text.replace(
            "id = \"sample\"",
            &format!("id = \"sample\"\n        requires_reader = {list}"),
        )
    }

    #[test]
    fn a_manifest_that_declares_and_uses_nothing_passes() {
        assert_eq!(check_against(TABLE, &toml_of(PLAIN)), Ok(()));
    }

    #[test]
    fn an_empty_list_is_the_same_as_no_list_at_all() {
        // `requires_reader = []` is what an absent field defaults to, so the
        // two have to be indistinguishable — otherwise writing the field out
        // explicitly would be a way to fail.
        let absent = check_against(TABLE, &toml_of(PLAIN));
        let empty = check_against(TABLE, &toml_of(&declaring(PLAIN, "[]")));
        assert_eq!(absent, empty);
        assert_eq!(empty, Ok(()));
    }

    #[test]
    fn a_list_of_the_wrong_shape_declares_nothing_rather_than_exploding() {
        // `requires_reader = "done"` is a type error, and the place that says
        // so properly is deserialization into `Vec<String>`, a step later. Here
        // it simply declares nothing — which is the safe reading, since the
        // backward check then refuses anything the manifest actually uses.
        let mistyped = declaring(&in_window("required = true"), "\"done\"");
        let err = check_against(TABLE, &toml_of(&mistyped))
            .expect_err("a declaration that isn't a list declares nothing");
        assert!(err.contains("windows.required"), "{err}");
    }

    #[test]
    fn declaring_a_capability_without_using_it_is_allowed() {
        // Declaring defensively is a manifest saying "I am written for a reader
        // that has this", which is true whether or not this particular file
        // reaches for the field today. Refusing it would punish the careful.
        assert_eq!(
            check_against(TABLE, &toml_of(&declaring(PLAIN, "[\"done\"]"))),
            Ok(())
        );
    }

    #[test]
    fn using_an_implemented_capability_without_declaring_it_is_refused() {
        let err = check_against(TABLE, &toml_of(&in_window("required = true")))
            .expect_err("an undeclared capability must be refused");
        assert!(
            err.contains("windows.required"),
            "the refusal must name the key — {err}"
        );
        assert!(
            err.contains("done"),
            "the refusal must name the capability — {err}"
        );
        assert!(
            err.contains("requires_reader"),
            "the refusal must say how to fix it — {err}"
        );
    }

    #[test]
    fn using_an_implemented_capability_after_declaring_it_is_allowed() {
        let used = declaring(&in_window("required = true"), "[\"done\"]");
        assert_eq!(check_against(TABLE, &toml_of(&used)), Ok(()));
    }

    /// The negative half for each key `window-identity` and `reading-status`
    /// add, against the **shipped** table rather than the synthetic one.
    ///
    /// A test walking every listed key proves a path is reachable, never that
    /// it matches the schema somebody actually wrote — it builds its document
    /// out of the key string, so a typo travels into the document with it. The
    /// only real protection is the rule that the change adding a field spells
    /// it in the same change, and these are that rule, checked: they name the
    /// keys the way a manifest does.
    #[test]
    fn a_manifest_using_a_capabilitys_keys_without_declaring_it_is_refused() {
        // The key as the *table* spells it, which is what the refusal quotes:
        // `status.*` is one entry covering every field of that section, so the
        // message names the pattern rather than the field that tripped it.
        for (document, key, capability) in [
            (
                in_window("id = \"five-hour\""),
                "windows.id",
                "window-identity",
            ),
            (
                format!("{PLAIN}\n[status]\nlimit_reached_path = \"rate_limit.limit_reached\"\n"),
                "status.*",
                "reading-status",
            ),
        ] {
            let err = check_against(CAPABILITIES, &toml_of(&document))
                .expect_err("using a capability's field without declaring it must be refused");
            assert!(err.contains(key), "the refusal must name the key — {err}");
            assert!(
                err.contains(capability),
                "and the capability to declare — {err}"
            );
        }
    }

    /// And the same documents pass once declared, so the refusal above is the
    /// declaration being missing rather than the field being unknown.
    #[test]
    fn declaring_the_capabilities_lets_their_fields_through() {
        let with_id = declaring(&in_window("id = \"five-hour\""), "[\"window-identity\"]");
        assert_eq!(check_against(CAPABILITIES, &toml_of(&with_id)), Ok(()));

        let with_status = declaring(
            &format!("{PLAIN}\n[status]\nlimit_reached_path = \"rate_limit.limit_reached\"\n"),
            "[\"reading-status\"]",
        );
        assert_eq!(check_against(CAPABILITIES, &toml_of(&with_status)), Ok(()));
    }

    /// Severity ships as a *name* ahead of its semantics, which is the whole
    /// point of the mechanism — and it must not ride in on `reading-status`,
    /// which is implemented. A manifest writing `severity_path` is told to
    /// update the app rather than quietly having the field ignored.
    #[test]
    fn window_severity_is_named_but_not_implemented_so_its_field_is_refused() {
        let used = declaring(
            &in_window("severity_path = \"severity\""),
            "[\"window-severity\"]",
        );
        let err = check_against(CAPABILITIES, &toml_of(&used))
            .expect_err("a capability this build does not implement must be refused");
        assert!(err.contains("does not implement"), "{err}");
    }

    #[test]
    fn a_capability_is_used_by_writing_its_key_at_all_not_by_setting_it_true() {
        // `required = false` is a manifest written against the newer schema
        // just as much as `required = true` is: it says "this window's absence
        // is not an error", which an older build has no way to honour because
        // it has no notion of a window being absent at all.
        let err = check_against(TABLE, &toml_of(&in_window("required = false")))
            .expect_err("presence of the key is what counts, not its value");
        assert!(err.contains("windows.required"), "{err}");
    }

    #[test]
    fn a_capability_this_build_does_not_implement_is_refused_either_way() {
        // Declared: the app is behind the manifest.
        let declared = check_against(TABLE, &toml_of(&declaring(PLAIN, "[\"not-yet\"]")))
            .expect_err("an unimplemented capability must be refused when declared");
        assert!(declared.contains("update the app"), "{declared}");

        // Used without declaring: same conclusion, reached from the key. This
        // is the case struct-based detection cannot see at all — there is no
        // field on this build to notice.
        let used = check_against(
            TABLE,
            &toml_of(&format!(
                "{PLAIN}\n        [status]\n        allowed_path = \"a\"\n"
            )),
        )
        .expect_err("an unimplemented capability must be refused when used");
        assert!(
            used.contains("status"),
            "the refusal must name the key — {used}"
        );
        assert!(used.contains("update the app"), "{used}");
    }

    #[test]
    fn an_unknown_name_is_refused_as_a_typo_not_as_an_old_app() {
        let err = check_against(TABLE, &toml_of(&declaring(PLAIN, "[\"dnoe\"]")))
            .expect_err("an unknown capability must be refused");
        assert!(
            err.contains("dnoe"),
            "the refusal must quote what was written — {err}"
        );
        assert!(
            err.contains("spelling"),
            "an unknown name is more likely a typo than a time machine — {err}"
        );
    }

    #[test]
    fn blank_and_duplicate_entries_are_refused() {
        let blank = check_against(TABLE, &toml_of(&declaring(PLAIN, "[\"  \"]")))
            .expect_err("a blank entry must be refused");
        assert!(blank.contains("blank"), "{blank}");

        let dup = check_against(TABLE, &toml_of(&declaring(PLAIN, "[\"done\", \"done\"]")))
            .expect_err("a repeated entry must be refused");
        assert!(dup.contains("more than once"), "{dup}");

        // Also for a name the table has but this build does not implement —
        // the malformed-list rules answer before the lookup does, so they stay
        // reachable in a build that implements nothing yet.
        let dup_unimplemented = check_against(
            TABLE,
            &toml_of(&declaring(PLAIN, "[\"not-yet\", \"not-yet\"]")),
        )
        .expect_err("a repeated entry must be refused whatever it names");
        assert!(
            dup_unimplemented.contains("more than once"),
            "{dup_unimplemented}"
        );
    }

    #[test]
    fn a_declaration_is_matched_after_trimming() {
        // Not cosmetic: the gate trims, so this passes — and anything later
        // that asks "did you declare it" has to trim too, which is why
        // `apply_defaults` normalizes the stored list.
        let padded = declaring(&in_window("required = true"), "[\"  done \"]");
        assert_eq!(check_against(TABLE, &toml_of(&padded)), Ok(()));
    }

    #[test]
    fn any_one_of_a_capabilitys_keys_triggers_it() {
        // Two unrelated spellings, either of which is the capability being
        // used. This one also proves the walk goes through `[[windows]]` into
        // `[windows.source]`.
        let nested = format!("{PLAIN}\n        severity_path = \"severity\"\n");
        let err = check_against(TABLE, &toml_of(&nested))
            .expect_err("the nested key must trigger its capability");
        assert!(err.contains("windows.source.severity_path"), "{err}");
    }

    #[test]
    fn a_document_that_is_not_a_manifest_is_not_ours_to_complain_about() {
        // The cost of checking before the typed parse, paid back. Somebody
        // else's TOML in the plugins folder — a notes file with a `[status]`
        // section — used to be told "missing field `id`", which is true and
        // fixable. Answering for it here would say "update the app" instead,
        // about a file that will not become a manifest in any version.
        let foreign = "name = \"notes\"\n[status]\nstate = \"active\"\n";
        assert_eq!(check_against(TABLE, &toml_of(foreign)), Ok(()));

        // The same document once it claims to be a manifest: `id` is the claim,
        // and every manifest of every vintage carries one.
        let ours = format!("id = \"notes\"\n{foreign}");
        let err = check_against(TABLE, &toml_of(&ours))
            .expect_err("a document claiming to be a manifest is ours to check");
        assert!(err.contains("status.*"), "{err}");

        // The forward half needs no such guard — it only fires on a document
        // that wrote `requires_reader` itself, which no foreign file does.
        let declared_without_id = "name = \"notes\"\nrequires_reader = [\"not-yet\"]\n";
        let err = check_against(TABLE, &toml_of(declared_without_id))
            .expect_err("a document that declares a capability has asked to be checked");
        assert!(err.contains("update the app"), "{err}");
    }

    #[test]
    fn a_key_at_the_wrong_depth_is_not_this_capability() {
        // A third-party manifest with a `required` of its own, somewhere that
        // is not a `[[windows]]` table. Matching on the bare name would refuse
        // a file that never touched our field.
        let elsewhere = format!("{PLAIN}\n        [logfile]\n        required = true\n");
        assert_eq!(check_against(TABLE, &toml_of(&elsewhere)), Ok(()));
    }

    #[test]
    fn a_star_segment_needs_a_table_with_something_in_it() {
        // What `status.*` buys over a bare `status`: somebody else's scalar
        // annotation is left alone. No version of this app will ever read
        // their string as our section, so "update the app" would be advice
        // that cannot come true.
        let scalar = PLAIN.replace(
            "id = \"sample\"",
            "id = \"sample\"\n        status = \"beta\"",
        );
        assert_eq!(check_against(TABLE, &toml_of(&scalar)), Ok(()));

        // An empty section reaches for nothing either.
        let empty_section = format!("{PLAIN}\n        [status]\n");
        assert_eq!(check_against(TABLE, &toml_of(&empty_section)), Ok(()));

        // A section with any field in it is the capability, whatever the field
        // is called — which is the point: `[status]`'s field names are not
        // settled, and this does not have to guess them.
        let populated =
            format!("{PLAIN}\n        [status]\n        whatever_it_ends_up_called = 1\n");
        let err = check_against(TABLE, &toml_of(&populated))
            .expect_err("a populated section is the capability being used");
        assert!(err.contains("status.*"), "{err}");
    }

    /// A minimal document that sets `key`, with the first segment as an array
    /// of tables (`[[windows]]` — the shape a real manifest uses, and the one
    /// whose traversal is worth exercising) and the rest as nested tables.
    ///
    /// Not necessarily the shape an author would write: `status.*` comes out
    /// as `[[status]]`, where the real section will be `[status]`. Both match,
    /// and the plain-table form is exercised by
    /// `a_star_segment_needs_a_table_with_something_in_it`.
    fn document_setting(key: &str) -> String {
        let segments: Vec<&str> = key.split('.').collect();
        let (field, tables) = segments
            .split_last()
            .expect("a key has at least one segment");
        // `*` is "any field of that table"; a document has to name one.
        let field = if *field == "*" { "anything" } else { field };
        // `id` first: the backward check only speaks for a document claiming
        // to be a manifest, and these have to be checkable.
        let mut out = String::from("id = \"probe\"\n");
        if let Some((first, rest)) = tables.split_first() {
            out.push_str(&format!("[[{first}]]\n"));
            if !rest.is_empty() {
                out.push_str(&format!("[{first}.{}]\n", rest.join(".")));
            }
        }
        out.push_str(&format!("{field} = \"x\"\n"));
        out
    }

    #[test]
    fn every_key_in_the_shipped_table_reaches_its_own_capability() {
        // What this does and does not prove, because the difference matters.
        //
        // It builds each document *from the key string*, so it cannot tell a
        // right spelling from a wrong one: rename `windows.required` to
        // `windwos.required` and this still passes, because the document is
        // built to match. Nothing can test a spelling against a schema that has
        // not been written — the only real protection is rule 1 in the module
        // docs, that the change adding a field fixes the spelling with it.
        //
        // What it does prove is that every listed key is *reachable*: it
        // resolves through the walk to a refusal, and to its own capability
        // rather than to a collision with another one's key. A path that can
        // never match anything — a segment that walks into a scalar, a
        // capability shadowed by an earlier entry — fails here rather than
        // going unnoticed until the capability ships.
        for cap in CAPABILITIES {
            for key in cap.keys {
                let document = toml_of(&document_setting(key));
                let Err(err) = check_against(CAPABILITIES, &document) else {
                    panic!("`{key}` is listed for \"{}\" but refuses nothing", cap.name)
                };
                assert!(
                    err.contains(key),
                    "a document setting `{key}` was refused for something else — {err}"
                );
                assert!(
                    err.contains(cap.name),
                    "`{key}` refused a document without naming \"{}\" — {err}",
                    cap.name
                );
            }
        }
    }

    #[test]
    fn the_shipped_table_has_no_duplicate_names_and_no_malformed_keys() {
        // A capability with no keys is a backward check that never fires — the
        // way this mechanism would rot into the forward-only check the module
        // docs warn about.
        let mut seen: HashSet<&str> = HashSet::new();
        for cap in CAPABILITIES {
            assert!(
                seen.insert(cap.name),
                "capability \"{}\" is listed twice",
                cap.name
            );
            assert!(!cap.name.trim().is_empty(), "a capability must have a name");
            assert!(
                !cap.keys.is_empty(),
                "capability \"{}\" names no key, so nothing can be caught using it",
                cap.name
            );
            for key in cap.keys {
                // An empty segment — a leading, trailing or doubled dot — walks
                // to a key no TOML document can have, so the path silently
                // matches nothing.
                assert!(
                    !key.is_empty() && key.split('.').all(|s| !s.trim().is_empty()),
                    "capability \"{}\" has a malformed key \"{key}\"",
                    cap.name
                );
            }
        }
    }
}
