# Plugin architecture

Every provider this app reads (Codex, Claude, and anything added later) is
read through a declarative **TOML manifest** plus a small, fixed set of
generic engines, instead of a dedicated Rust module per provider.

**Source of truth.** The manifest schema is frozen in
[`src/plugin/manifest.rs`](../src/plugin/manifest.rs) (types, field docs,
defaults, `PluginManifest::validate`). If anything below and that file ever
disagree, `manifest.rs` wins — this document explains and motivates the
schema, it doesn't own it. Directory loading (`load_dir`) and path expansion
(`expand_home`) live in [`src/plugin/mod.rs`](../src/plugin/mod.rs). The two
readers that consume a parsed manifest are `src/plugin/engine_logfile.rs`
(`engine = "log-file"`) and `src/plugin/engine_http.rs`
(`engine = "http-api"`); the credential chain is `src/plugin/auth.rs`. The
sections on engine and auth-chain *behavior* below describe the contract
those modules implement — for the exact wire format of what they consume,
always check `manifest.rs`.

## Plugin folder & seeding

The **only** source of truth for which providers exist is:

```
<config-dir>/tickover/plugins/*.toml
```

(`dirs::config_dir()` — `~/Library/Application Support` on macOS, `%APPDATA%`
on Windows). There is no provider baked into the binary. Every `.toml` file
directly inside that folder (non-recursive) is read as a `PluginManifest`,
sorted by declared `order` (ties break on `id`); files that fail to parse or
validate are reported individually and don't block the rest of the folder
from loading (see `manifest::load_dir`).

On first run, or whenever the folder is empty, it is **seeded** from the
templates checked into the repo at `plugins/*.toml` (today `codex.toml`,
`claude.toml`, `grok.toml`, `antigravity.toml` and `copilot.toml`). Seeding
only ever adds the shipped defaults — it never touches or deletes a manifest
it didn't write, so a hand-edited or third-party manifest survives a reseed.
A shipped manifest that first appeared after an install already had a
plugins folder is delivered on a later launch too, when no file of that name
exists (`deliver_if_absent` in `seed.rs`, set on the manifests that shipped
after the first two); a file that does exist is never overwritten by that
path, whatever it contains.

Settings has a **"Reset plugins"** button that re-runs this seeding step
on demand: it restores/rewrites every shipped manifest from its template,
still without touching any other file in the folder. This is the recovery path
if you've broken one of the built-in manifests while editing it, or want to
pick up a newer shipped default.

Because the manifest is just a TOML file, "installing a plugin" is: drop a
`.toml` file into that folder. There is no code to compile, sign, or review by
this app — which means installing a manifest is an act of trust in whoever
wrote it, comparable to installing a browser extension or a Cargo crate: the
app will do exactly what the manifest says, including reading whatever
credential source and calling whatever host it declares. See
[Security](#security) for what that trust actually covers.

## Manifest format

### Top-level fields

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `id` | string | yes | — | stable identifier (`"codex"`, `"claude"`); ASCII `[A-Za-z0-9_-]+` only, and not one of Windows's reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, compared case-insensitively) — it names the on-disk `<id>.toml` and must be a safe filename component on every platform this ships to |
| `name` | string | yes | — | display name for the popup section header; must not be blank, and at most 64 characters |
| `menu_label` | string | yes | — | short label for the menu-bar pill/title (`"Cx"` / `"Cl"`); must not be blank, and at most 16 characters |
| `order` | integer | yes | — | sort key across providers; ties break on `id` |
| `engine` | `"log-file"` \| `"http-api"` | yes | — | which engine reads this provider's usage data; a `log-file` manifest may not also declare `[http]` |
| `refresh_secs` | integer | no | `60` | poll interval, seconds; from 5 to 86 400 (a day) inclusive |
| `enabled` | bool | no | `true` | whether the plugin is active at all |
| `requires_reader` | array of strings | no | `[]` | reader capabilities this manifest needs — see [Reader capabilities](#reader-capabilities-requires_reader) |
| `version` | string | no | — | this manifest's own version. The registry's update check compares it against the index, and the built-in upgrade step records it in `config.json` once a shipped copy is replaced — see [Registry](#registry) |
| `[tag]` | table | no | all fields empty/none | see [`[tag]`](#tag) |
| `[account]` | table | no | `type = "none"` | see [`[account]`](#account) |
| `[[windows]]` | array of tables | conditional | — | at least one `[[windows]]` **or** one `[[balances]]` entry, enforced by validation rather than by a schema default — see [`[[windows]]`](#windows) |
| `[[balances]]` | array of tables | conditional | empty | figures against a calendar period, for a provider that reports one instead of (or beside) a rolling window — see [`[[balances]]`](#balances) |
| `[status]` | table | no | absent = nothing stated | what the provider says about the quota *as a whole*, above its windows — see [`[status]`](#status) |
| `[logfile]` | table | conditional | — | required when `engine = "log-file"` |
| `[http]` | table | conditional | — | required when `engine = "http-api"` |
| `[[surface]]` | array of tables | no | one synthesized `"default"` surface | see [`[[surface]]`](#surface) |
| `[ping]` | table | no | absent = no auto-ping | see [`[ping]`](#ping) |

Values for enum-typed fields (`engine`, `role`, `from`, `transform`, `type`,
`mode`, `resets_at_format`) are lower-case, hyphenated (`"log-file"`,
`"credentials-file"`) — **except** `[windows.period].mode`, whose two values
are `"assumed"` and `"from_field"` (underscore, not hyphen). Get that one
wrong and the manifest fails to parse.

**Unknown fields are ignored, not rejected.** The manifest type deliberately
does not use `#[serde(deny_unknown_fields)]`: a manifest written for (or by) a
future version of this reader must still load, ignoring fields this build
doesn't understand yet. This matters for the registry (below) —
plugins can advertise a newer schema version without breaking older installs.

One table breaks that rule: [`[surface.auth.client]`](#surfaceauthclient) is
`#[serde(deny_unknown_fields)]`. `files`, `bins` and `id_env` are exactly what
the install-time trust dialog shows before anything is written to disk (see
[Trust model](#trust-model)) — a typo there (`fils` for `files`, say) would
otherwise silently disable a candidate list or an override rather than refuse
to parse, and a manifest author would see a discovery config that never finds
what it should, with nothing in the error to point at why. This is a
narrower, stricter table than the manifest at large on purpose; it does not
change the forward-compatibility rule for everything else in this document.

That rule is right for a field that only *adds* something, and dangerous for a
field that changes what an existing number means — which is what
`requires_reader` is for.

### Reader capabilities (`requires_reader`)

A manifest names the reader capabilities it needs:

```toml
requires_reader = ["window-presence"]
```

Absent means `[]`. Every manifest written before this field existed asks for
nothing, so nothing about them changes.

**Why it exists.** "Ignore what you don't understand" fails silently in one
specific way: a manifest says "the used figure lives in this new field now",
an older build has no such field, ignores it, finds the legacy field beside it
and draws a number that is confidently wrong. Nothing is missing from the
screen, so nothing looks broken. A declared capability turns that into a
refusal with a sentence in it.

**The check runs both ways**, and both halves are load-bearing:

* **Forward** — a capability this build does not implement is refused:
  *"`requires_reader` names "window-presence", a reader capability this version
  of Tickover knows about but does not implement — update the app to use
  this plugin."* This is the half that makes declaring worth the trouble.
* **Backward** — a manifest that *uses* a capability's fields without naming it
  is refused too: *"this plugin sets `windows.required`, which needs the reader
  capability "window-presence" — declare it with `requires_reader =
  ["window-presence"]`."* Without this half, the forward check protects only
  the authors who remembered to opt in, which is the ones who did not need
  protecting.

The backward half detects use by **manifest key**, read from the raw TOML
rather than from the parsed struct (`src/plugin/capability.rs`). That is what
lets a build refuse a manifest written for a schema newer than its own: a key
is a string, and a string can be recognised by a build with nowhere to put the
value. Keys are matched at exact depth, so a third-party manifest with a
`required` of its own somewhere else is not refused for a field it never
touched. A `*` segment matches any key of a table, which is how a section
whose own field names aren't settled yet (`status.*`) is named without
guessing at them — and it also means a scalar `status = "beta"` of somebody
else's is left alone, since the walk stops where a table was expected.

**The check runs before the manifest is parsed into the reader's own struct**,
which is where its value is. A manifest from the future doesn't only *add*
fields; it changes the type of one that already exists. Deserialization
answers a `label` that became a table with a TOML type error, while the
`requires_reader` line naming the capability sits unread a few lines above.
Checked first, that same file hears "update the app".

The backward half is skipped for a document with no `id`. That is the price of
running early, paid back: `id` is what makes a file claim to be one of these
manifests at all, and without the guard somebody else's TOML in the plugins
folder — a notes file with a `[status]` section — would be told to update the
app rather than that it is missing an `id`. The forward half needs no guard: it
only fires on a document that wrote `requires_reader` itself.

**What it costs.** Detection can't tell our field from somebody else's field
of the same name at the same depth. A third-party manifest already carrying,
say, its own `severity_path` under `[windows.source]` loaded before this and
is refused now. That is a deliberate breaking change and the right way round:
the alternative is to keep loading it and then, once the capability ships,
read their field as ours.

One consequence worth knowing: `requires_reader` is a **top-level** field, and
TOML puts an appended line inside whatever table header precedes it. Written
after a `[logfile]` or `[http]` section it becomes a field of *that* table and
is silently ignored — but the manifest is not silently misread, because the
backward check then sees the capability used and undeclared, and refuses it.

**Capabilities are listed before they are implemented.** `CAPABILITIES` in
`src/plugin/capability.rs` carries an `implemented` flag per entry, and an
entry appears there as soon as its name and key spellings are known — with
`implemented = false` until the change that implements it. Listed-but-
unimplemented is the useful state: it is what lets a build refuse a manifest
from the future loudly instead of misreading it quietly. A capability nobody
has listed yet is the one hole this mechanism cannot close, which is why new
capability *names* ship ahead of the semantics that use them.

Two rules keep the key lists true:

1. **The change that adds a manifest field adds that field's spelling to its
   capability's `keys`, in the same change.** A wrong spelling there is a
   backward check that passes exactly the manifest it exists to catch. Where a
   field's home is still open, list every plausible one — `keys` is an
   "any of these" list. This rule is the *only* protection against a wrong
   spelling: a test walks every listed key and fails if it reaches no refusal,
   but it builds its document from the key string, so it proves a path is
   reachable and unshadowed — never that it matches a schema nobody has
   written yet.
2. **A capability's semantics arrive as a new key, never as a wider grammar
   inside an existing value.** Detection reads keys, so it is blind to new
   syntax *within* a value — and this language already grows that way
   (`containers = ["additional_rate_limits[limit_name=…]"]` holds a selector
   inside a string). A `containers = ["…[*]"]` meaning "a row per element"
   would add no key, trip nothing, and be read by an older build as the single
   empty row this mechanism exists to prevent.

| Capability | Implemented | What it covers |
|---|---|---|
| `window-presence` | **yes** | a window whose paths don't resolve is not emitted at all (rather than emitted blank), and `required` marks the ones whose absence is the provider's error — see [Presence](#presence-a-window-that-isnt-there) |
| `window-identity` | **yes** | `[[windows]] id` — the stable half of a window's key, so a row is filed under the same registry entry whichever slot it arrived in |
| `reading-status` | **yes** | the quota's own standing (`[status]`: `allowed` / `limit_reached` / `reached_type`), which a provider can state while reporting no window at all |
| `reading-balances` | **yes** | `[[balances]]` — figures against a calendar period, which a provider may report *instead of* windows — see [`[[balances]]`](#balances) |
| `window-severity` | not yet | the server's own per-window severity, split out of `reading-status` because that stage implements the quota's standing and not this |
| `for-each-windows` | **yes** | one `[[windows]]` entry expanding into a row per element of an array in the response — see [Enumerating entries](#enumerating-entries--for_each-http-api-only) |
| `credentials-map` | **yes** | `[[surface.auth]]` `type = "credentials-map"` + `key_prefix` — a credential file that is a *map* of records keyed by a string no manifest can spell in advance |
| `http-post` | **yes** | `[[http.request]]` `method` / `body` — an endpoint that answers only a POST, where every provider before it answered a plain GET |
| `remaining-fraction` | **yes** | `[windows.source]` `remaining_fraction_path` — a provider that states what is *left* rather than what is spent |
| `keychain-expiry` | **yes** | `[[surface.auth]]` `expiry_json_path` — a `keychain`/`credentials-file`/`win-credential` step that resolves Absent on a lapsed token, so a step behind it can fire (or, with `[ping] renews_token`, a renewal ping) |
| `oauth-refresh` | **yes** | `[[surface.auth]]` `type = "oauth-refresh"` + `token_url` — the one auth step that *spends* a credential instead of only reading one |
| `oauth-client-discovery` | **yes** | `[surface.auth.client]` — reads an `oauth-refresh` step's installed-app client id/secret back out of the credential's own installed client at run time, instead of shipping the pair in the manifest — see [`[surface.auth.client]`](#surfaceauthclient) |

`window-severity` is listed without being implemented, and that is the useful
state, not an oversight: the name ships ahead of the semantics so the build
that first meets a manifest using the field refuses the file out loud instead
of ignoring the number. What it is waiting on is not code but a measurement —
whether a provider's own severity words say anything the panel's colour bands
do not already say.

### `[tag]`

The small chip shown next to the provider name in the popup (e.g. `PROLITE`,
`CLI`, `Desktop`).

| Field | Type | Default | Notes |
|---|---|---|---|
| `from` | `"static"` \| `"field"` \| `"none"` | `"none"` | where the tag text comes from |
| `value` | string | — | literal tag text, used when `from = "static"` |
| `path` | string | — | dotted JSON path to the tag text, used when `from = "field"` |
| `transform` | `"none"` \| `"uppercase"` | `"none"` | text transform applied to the resolved tag |

### `[account]`

Where the account email shown next to the tag comes from.

| Field | Type | Default | Notes |
|---|---|---|---|
| `type` | `"none"` \| `"jwt-file"` \| `"http"` \| `"response-field"` | `"none"` | lookup strategy |
| `path` | string | — | `jwt-file`: path to the file holding the token |
| `token_path` | string | — | `jwt-file`: dotted JSON path to the JWT string inside that file |
| `claim` | string | — | `jwt-file`: claim name read out of the decoded JWT (e.g. `"email"`) |
| `url` | string | — | `http`: URL to fetch the account profile from; must be `https` |
| `json_path` | string | — | `http`: dotted JSON path to the email in the response body; `response-field`: the same path, read out of the **usage** response |

`type = "response-field"` costs no request at all: the address is taken from
the usage response the engine has just parsed. Prefer it whenever a provider
states the account in that response (Codex's `/wham/usage` returns `email`,
`account_id` and `plan_type` next to the windows) — a profile endpoint that
repeats what you already hold doubles the provider's request count for
nothing.

For `type = "http"` there is **no separate header/auth configuration** —
the request reuses whichever surface/token is currently active (the same
credential chain and header substitutions as the provider's `[http]`
section), so an account-profile fetch never needs its own auth block.

### `[[windows]]`

One entry per quota window the provider reports (Codex: 5-hour + weekly;
Claude: same). At most one window may have `role = "primary"` — the
manifest fails validation with 2+. A manifest may declare at most 32
`[[windows]]` entries.

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | string | no (default empty) | stable identity of this window — the `<entry>` half of its `Window::key`, matched across fetches (and, for an enumerating entry, the base a per-element row's key is built from); at most 64 bytes of lowercase ASCII letters, digits and hyphens, starting with a letter or digit. Empty means the entry's position stands in (`wN`) — and a caption is deliberately *not* used as identity, since a label is expected to change freely. Not a `config.json` key: the seen-window registry keys by *role* (`"primary"`/`"secondary"`) and never records an `Extra`-role window at all. Needs `requires_reader = ["window-identity"]` |
| `label` | string | yes | short row label shown in the popup (`"5H"`, `"WK"`) |
| `role` | `"primary"` \| `"secondary"` \| `"extra"` | yes | UI slot this window fills; primary drives the auto-ping and the pill's first mini-bar. `extra` fills neither slot: it is a row in the panel and nothing else — see below |
| `required` | bool | no (default `false`) | whether this provider *always* reports this window, so its absence is the provider's error rather than a fact about the account — see [Presence](#presence-a-window-that-isnt-there). Needs `requires_reader = ["window-presence"]` |
| `for_each`, `for_each_where`, `element_id_path` | strings | no | one row per element of an array in the response, instead of one row per entry — see [Enumerating entries](#enumerating-entries--for_each-http-api-only) |
| `[windows.period]` | table | yes | how long the window nominally is |
| `[windows.source]` | table | yes | where the window's numbers live in a raw reading |

#### `[windows.period]`

| Field | Type | Required | Notes |
|---|---|---|---|
| `mode` | `"assumed"` \| `"from_field"` | yes | how the period length is determined |
| `assumed` | integer (minutes) | when `mode = "assumed"` | fixed period length; at least 5 — a manifest-stated period shorter than that reaches `main.rs`'s auto-ping arithmetic as a window that has effectively always just started |
| `field` | string | when `mode = "from_field"` | dotted JSON path to the period length, read from the reading itself |
| `unit` | `"minutes"` \| `"seconds"` | no (default `"minutes"`) | unit of the value at `field`; the stored length is always minutes (seconds round down). Codex states `window_minutes` in its logs and `limit_window_seconds` in its API |

#### Presence: a window that isn't there

**A window the reading does not report is not emitted at all.** Not as a row
with every field empty — that shape said "this window exists and we know
nothing about it", which is a different sentence from the one the provider
spoke, and every consumer upstream of the panel's filter believed the first
one. The auto-ping in particular used to find its window by asking the reading
for a primary row, and told "we could not read this provider" from "this
provider reports no 5-hour window right now" purely by whether a blank row had
been emitted.

Three states, kept apart:

| The provider... | What the reading says | What the panel draws |
|---|---|---|
| reported the window | a `Window` with a percentage | the row |
| reported no such window | no `Window` for it | no row (and the header alone if that was the only one) |
| could not be read at all | `error` set, no windows | the error message |

The third is never the second. A request that failed, a token that expired, a
body that would not parse — none of them is evidence that a quota does not
exist, and drawing them as "no such limit" is how a broken reader looks
exactly like a generous plan.

`required` is how a manifest tells the first two apart *for its own provider*,
because only it knows. Codex's 5-hour window is legitimately absent — a plan
without one reports none, and an empty one stops being reported until
something is spent. Codex's weekly window is not: every subscription has one,
so a response without it has changed shape. The reader used to guess at this
with a single rule — "not one window resolved" meant a broken response — which
called a 5-hour-less plan broken and said nothing at all about a response that
had lost half its shape.

A missing `required` window refuses the whole reading, with a message naming
it. Deliberately stricter than showing the rest: half a response drawn
confidently is a row that reads as "nothing used". Both engines share the rule
(`plugin::collect_windows`) — it is about the manifest, not about JSON or log
lines, and an engine that implemented it separately would make `required` mean
two things. One of them once did: the log-file engine ignored the field
entirely, so a manifest could state a guarantee the app did not keep.

**A reading with no windows at all is not refused.** The obvious rule —
"nothing resolved, so the response must be broken" — was tried here and taken
out again, because it is false for Codex. That provider reports an empty
window by not reporting it, and an account can have *both* windows empty at
once: in the hours after a weekly reset, with nothing spent since. The body
then holds two nulls, which is byte-for-byte what a broken endpoint sends, so
no rule can tell them apart. Refusing it costs the whole provider — an error
in place of the account, the menu-bar entry gone, and the auto-ping silenced in
exactly the state it exists to end. Reporting no windows costs a section
saying "no usage reported yet", which is true.

So mark a window `required` only where the provider genuinely always sends it,
and expect no safety net where you don't. Neither of Codex's windows is
marked. Both of Claude's are — Anthropic sends both for every account, so a
response with half of them has changed shape.

#### The seen-window registry: a row that doesn't blink out

A window vanishing from the response is a *fact about the account*, but drawing
it as one row fewer means the panel's shape changes every time a window empties
— the 5-hour row disappears the moment Codex has nothing to report and comes
back on the first request the user makes. So a window this app has seen the
provider state keeps a faint row saying **not started**, until it is stale
enough that the likelier explanation is a plan that no longer has it.

What is remembered, in `config.json` under
`plugin.<id>.seen.<reading id>.<role>`: the newest reset the provider stated
(`at`) and how long it said the window was (`period_minutes`). Keyed by reading
and role rather than by plugin, because a plugin can report several accounts
whose windows empty independently. Recorded for every plugin that produces a
reading — not only ones with a `[ping]` section, which is where this bookkeeping
used to live and where every third-party manifest silently missed out.

- **The length is remembered, not looked up.** The manifest is only a fallback:
  the windows that vanish are exactly the ones whose length arrives in the
  response (`period.mode = "from_field"`), so by the time it is needed there is
  nothing in the manifest to read.
- **Only `primary` and `secondary`.** An `extra` quota is a row the provider may
  withdraw at any time (see `role = "extra"`), so remembering it would both
  contradict that and let keys pile up for every model that ever appeared.
- **Forwards only**, so a stale or cached reading can't move a boundary back
  onto a window the auto-ping has already dealt with.
- **A reading with an `error` records nothing.** A provider we could not read
  has said nothing about its quota.

The row appears only when the remembered window has *ended* (`now >= at`) and
less than **two of its own periods** have passed since. Before its end, the
provider going quiet says nothing about the next window, and "not started" over a
window that was being spent would be a lie.

The second of those two periods is *slack*, and it is capped at three days,
because two periods scales with the window while the confidence behind it does
not: two periods of a *weekly* window would show "Weekly limit — not started" for
a fortnight to an account that had just lost its weekly allowance. The cap never
touches the first period — the window the row is actually talking about, whose
boundary and length the provider itself gave us. While that window is still
running, an empty one explains the silence completely and there is nothing stale
to bound. So a 5-hour window gets ten hours (unchanged, and the case this was
written for), a weekly window one week rather than two, and nothing under 36
hours is affected at all.

Only a window the provider did not report **at all** can carry the row, and only
from a reading that is not in error. A window reported without a usable
percentage draws no row — there is no figure to draw — but it is not therefore
called empty: that would state as fact the very thing the response failed to say.

Two manifests can spell the same reading id (a plugin *named* `claude-cli`
against plugin `claude`'s `cli` surface). Neither then gets an answer, because
guessing would file one provider's windows under the other's plugin key — but
that costs both of them their hysteresis row *and* their auto-ping boundary, so
the collision is written to the log at load time rather than degrading quietly.

The row is a `WindowData` and never a `Window`: a synthesized window at 0% would
be picked up by `primary_window()` and printed by the menu bar as a `0` where it
now shows nothing, which is the confident-but-invented number this whole section
exists to avoid.

The registry entry itself **never expires**, and the difference is deliberate.
The auto-ping projects the next boundary from it a period at a time, and
dropping the entry would take that retry with it. One remembered fact, two
decisions: a stale row is a limit the user believes they have, while a stale
boundary costs an unattended `hello` the user opted into. What the single
registry guarantees is that the panel and the ping can never disagree about
whether a window was *ever seen* — not that they must act alike once it is gone.

Be precise about the ping's side of that, because it is not free: for an account
whose plan has genuinely dropped the window, the projection keeps coming due
once per period **indefinitely**, long after the row has left the panel. That is
the projection's existing behaviour (the alternative it replaced was a ping that
stopped forever after one failure), but the asymmetry is open and belongs with
the ping's own pacing rather than here.

### Enumerating entries — `for_each` (http-api only)

One `[[windows]]` entry normally draws one row. With `for_each` it draws a row
**per element** of an array in the response, and every path in
`[windows.source]` (and `period.field`) is then read *inside the element*.

```toml
[[windows]]
label           = "{scope.model.display_name} weekly"   # template, this entry only
role            = "extra"
for_each        = "limits"                # the array
for_each_where  = "kind=weekly_scoped"    # keep only these elements
element_id_path = "scope.model.display_name"   # identity of one row
```

Needs `requires_reader = ["for-each-windows"]`.

What it is for: a provider that scopes a limit to a model and does not say in
advance how many such limits there are. Anthropic reports its session and
weekly windows in fixed fields *and* repeats them inside `limits[]`, which also
carries a weekly allowance scoped to one model. A path selector
(`limits[kind=weekly_scoped]`) picks **one** element and would silently drop the
rest; a literal caption could not say which model the figure is about.

| Key | Meaning |
|---|---|
| `for_each` | dotted path to the array. Anything that is not an array yields no rows — `required` decides whether that is an error |
| `for_each_where` | `field=value`, both halves trimmed. Reads **one key** of the element (not a path), the way a selector does; a `.` in the field is refused at load |
| `element_id_path` | path inside the element to the row's identity. **Required** — position is not an identity, since no provider promises the order of an array |
| `label` | may carry `{path}` placeholders, resolved against the element and sanitised. The one place a caption comes from the response |

Rules worth knowing before writing one:

* **`role` must be `extra`.** The 5H and WK slots hold one window each (the menu
  bar reads the primary, and the "not started" placeholder is keyed by role),
  while an expansion draws as many rows as the provider sent.
* **Rows are ordered by identity, not by the array's order**, and two elements
  resolving to the same identity collapse into one row — a key is a path in the
  user's config, and two rows writing it would overwrite each other.
* **The identity is the raw text**, percent-encoded into the key; only the
  caption is sanitised. Sanitising is lossy, and two names differing by an
  invisible character would otherwise share one config path.
* **An element that cannot be named draws no row** — the same rule as a figure
  that does not resolve.
* Eight refusals guard the shapes that would otherwise fail in silence (a
  filter or an identity without an array, a template off an enumerating entry,
  an expansion on the log engine, an expansion without an identity, a malformed
  filter, an unclosed placeholder, a non-`extra` role). Each has a line in
  `tests/manifest_corpus.rs`.

### `[windows.source]`

Where a window's numbers live in the provider's raw reading (a JSONL line for
`log-file`, a JSON response body for `http-api`). Paths are dot-separated
object keys (e.g. `"five_hour.utilization"`).

A segment may also select one element of an array, either by position —
`"list[0].used"` — or by a field of the element's own:
`"additional_rate_limits[limit_name=GPT-5.3-Codex-Spark].rate_limit"`. The
second form is what a list of quotas needs, because a provider that answers
with an array of them fixes neither their order nor their number; "the one
that calls itself this" is a thing a manifest can mean, and "the second one"
is not. Dots inside the brackets belong to the value, not to the path — model
names have dots in them. A selector that matches nothing reads as a missing
field, so the window it feeds reports no percentage and the panel simply
doesn't draw that row. A segment that is not a well-formed selector is tried
as a literal key, so a provider may still have a field called `counts[daily]`.

Two things the syntax deliberately cannot say: selectors do not chain
(`grid[0][0]` finds nothing), and a value containing the sequence `].` is cut
short at it — a plain `]` is fine, since the closing bracket is the last one.
No escaping is offered rather than invented. No wildcards.

| Field | Type | Default | Notes |
|---|---|---|---|
| `containers` | array of strings | empty | `http-api`: candidate objects this window may live in, each a dotted path into the response (e.g. `["rate_limit.primary_window", "rate_limit.secondary_window"]`); at most 8. The other paths in this section are then read *relative to* the candidate that classifies as this window. Empty = read from the response root, the pre-existing behaviour |
| `used_percent_path` | string | — (one of two, required) | dotted JSON path to the consumed-percent number, 0–100 |
| `remaining_fraction_path` | string | — (the other) | dotted JSON path to a **remaining** fraction, 0..1, for a provider that states what is left rather than what is spent (Antigravity's `remainingFraction`). Mutually exclusive with `used_percent_path`; needs `requires_reader = ["remaining-fraction"]` |
| `resets_at_path` | string | — (required) | dotted JSON path to the absolute reset timestamp |
| `resets_at_format` | `"unix"` \| `"iso8601"` | `"unix"` | format of the value at `resets_at_path` |
| `max_period_minutes` | integer | — (optional) | classification bound: this slot only if the period is ≤ this many minutes. On `http-api`, needs `period.mode = "from_field"` — refused alongside `mode = "assumed"`, which already states the length and leaves the bound nothing to classify; [`log-file`'s own classification](#engine--log-file) applies it either way |
| `min_period_minutes` | integer | — (optional) | classification bound: this slot only if the period is ≥ this many minutes. Same `http-api`-only `period.mode = "from_field"` requirement as `max_period_minutes` |

An `http-api` window states its figure through **exactly one** of
`used_percent_path` and `remaining_fraction_path`; naming both, or neither, is
refused at load rather than left to resolve to nothing on every fetch. (The
`log-file` engine reads neither — it takes `used_percent` from the log
record's own fields, so `[windows.source]` there carries only the
classification bounds.)

A remaining fraction is turned into the consumed percent a window holds —
`(1 − fraction)·100`, clamped. That is a change of units of a number the
provider stated: reversible, information-preserving, and the only licence of
its kind here. A percentage *computed* from something the provider did not
state is not allowed anywhere in this app, and no manifest key offers one.

Declare `containers` when a provider does **not** fix which slot a given
window arrives in. Codex sends its weekly window as `primary_window` with
`secondary_window` null whenever the 5-hour window has nothing to report, so
reading "primary" as "the 5-hour window" would print a weekly figure on the 5H
row. With bounds declared, each window takes the first candidate whose own
length (`period.field`, converted by `period.unit`) falls inside its
`min_period_minutes`/`max_period_minutes` — the same first-match rule
`log-file` uses for its `primary`/`secondary` pair. Declaring neither bound is
also legal with several candidates: the first one that resolves to a value at
all (skipping `null`) wins, in the order `containers` names them. On this
engine, either bound only means something once `period.mode = "from_field"`
gives a length to measure it against — `mode = "assumed"` states the
window's length outright, so a bound declared beside it would never be read
here, and `validate` refuses that combination on `http-api`. The same
manifest is legal on `log-file`: its own [classification](#engine--log-file)
applies a bound to a candidate's length regardless of `period.mode`, and a
`role = "extra"` log-file window needs one — with neither bound set, it
classifies to nothing and never draws.

#### `role = "extra"`

A provider may report quotas that are not its subscription: a per-model
allowance, a credit pool, a code-review budget. Those are worth a row and must
never be mistaken for the headline number. `extra` is how a manifest says so.

Only `primary` and `secondary` fill the 5H/WK slots, and everything that reads
a provider's headline figure — the menu-bar pill, the compact tray title, the
auto-ping's reset time — goes through `ProviderReading::primary_window()` /
`secondary_window()`, which select by role. An `extra` window is therefore
unreachable from any of them; it appears in the panel, titled by its own
`label` rather than by its length (so a per-model *weekly* allowance does not
render as a second row saying "Weekly limit"), and nowhere else.

This is not a stylistic preference. Codex's rollout logs interleave quota
families, and a reader that took the newest one showed a model-specific 0%
where the subscription's weekly window stood at 69%. Keeping the two in
different roles is what makes showing both safe.

One rule covers every shape: a length the **response states** is checked
against the bounds the manifest declares, and nothing else is checked. So a
declared bound holds over several candidates (what it is for), over a single
one, and over the response root — a window declared to be at least a week long
never shows a five-hour figure, however few objects were on offer. A window
whose period is `assumed` has no stated length to check, so it classifies
nothing and takes its candidate as declared. A window that matches no
candidate is still emitted, with every field blank; a manifest listing more
than one candidate without `period.mode = "from_field"` fails validation,
since nothing would tell the candidates apart.

### `[[balances]]`

Figures against a **calendar period** — credits left, spent this month —
as opposed to a `[[windows]]` percentage against a rolling one. Needs
`requires_reader = ["reading-balances"]`, and `engine = "http-api"`: a log line
records the windows one session saw, so the log reader has nowhere to take a
balance from, and the section is refused there rather than ignored.

**A manifest needs at least one `[[windows]]` entry or at least one
`[[balances]]` entry** — one that declares neither is still refused, because it
still cannot draw a row. The second shape exists because a provider need not
report a window at all: Grok's billing endpoint states a monthly period and no
window key of any kind, and the old "at least one window" rule made that
provider unwritable as a plugin.

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | string | no | stable identity, same charset and cap as `[[windows]] id` (it becomes the `<entry>` half of this balance's `Balance::key`, matched across fetches — no `config.json` registry keys a balance by it; balances have no seen-window-style persistence at all today). Without one the entry falls back to `bN` — never `wN`, so a balance and a window at the same index cannot share an identity |
| `label` | string | yes | row label, a **literal**; never a template, so provider text cannot reach a caption this app vouches for |
| `[balances.used]` | table | no | what has been spent |
| `[balances.cap]` | table | no | the ceiling, when the provider states one |
| `[balances.remaining]` | table | no | what is left, for providers that report the remainder instead of a used/cap pair |
| `[balances.source]` | table | no | the non-amount figures |

An entry must name at least one of `used`, `cap`, `remaining`,
`source.percent_path` or `source.limit_reached_path` — an entry that reads
nothing is a caption beside empty space. A manifest may declare at most 16
`[[balances]]` entries.

#### Amount tables (`used` / `cap` / `remaining`)

| Field | Type | Required | Notes |
|---|---|---|---|
| `kind` | `"money-minor"` \| `"number"` \| `"text"` | yes | the form the provider states the figure in |
| `path` | string | `number`, `text` | dotted JSON path to the value |
| `amount_path` | string | `money-minor` | path to the amount in **minor units** |
| `currency_path` | string | `money-minor` | path to the currency code |
| `exponent_path` | string | `money-minor` | path to the scale (minor units per major one, as a power of ten) |
| `unit_label` | string | no, `number` only | what the number counts, as a manifest literal |

Three kinds and no more, because three are what live providers were observed to
fill; a fourth would be a branch nothing can test.

**A money figure is the whole triplet or it is no figure at all.** An amount
without its currency and scale is not a smaller truth, it is a different one —
`1999` of what, at what scale — so an incomplete triplet emits nothing rather
than a bare number. The scale comes from the response for the same reason:
"cents have two digits" holds until the first currency for which it does not.

`unit_label` belongs to `number` alone: money carries the currency the response
states, and text is already the provider's own wording. A `number` without a
label is drawn bare, which is the honest rendering when the provider names no
unit (Grok states none).

#### `[balances.source]`

| Field | Type | Required | Notes |
|---|---|---|---|
| `percent_path` | string | no | a percentage **the provider stated** |
| `limit_reached_path` | string | no | the provider's "a spending limit has been reached" flag |
| `period_end_path` | string | no | end of the calendar period |
| `period_end_format` | `"unix"` \| `"iso8601"` | no (default `"unix"`) | format of the value at `period_end_path` |

**There is deliberately no key that asks for a computed percentage.** A
percentage this app derived from `used` and `cap` would be indistinguishable on
screen from one the provider published, and the rule that no number appears
unless somebody stated it is what the rest of the panel's credibility rests on.

The period is stored as the **date it ends**, never as a length: a billing month
is 28–31 days, so a length would be a fiction and classifying by it — the way
windows classify — would be meaningless.

**Zero is not read as a ceiling.** No provider documents what a zero in a cap
means, and none was found that distinguishes "no cap is set" from "the cap is
zero" in a way a single account can observe, so a zero yields no ratio and no
"exhausted" — and equally no claim that the cap is absent.

`limit_reached` stays on the balance rather than folding into `[status]`,
because a provider may state one and not the other: Claude declares no
`[status]` at all, so for it this is the only channel a refusal arrives
through. Not repeating a refusal the quota level already stated is a rendering
rule, not a reason to drop the field.

### `[status]`

What the provider says about the quota **as a whole**, above its windows.
Optional; needs `requires_reader = ["reading-status"]`. Read only by
`engine = "http-api"` — a `log-file` manifest carrying it is refused, since a
log line records what one session saw, not the standing of the account. The
table must name at least one of its three paths — an empty `[status]` is
refused at load, and so is any of the three that is present but blank.

| Field | Type | Notes |
|---|---|---|
| `allowed_path` | string | JSON path to a boolean: may this account spend against the quota at all |
| `limit_reached_path` | string | JSON path to a boolean: has a limit been reached |
| `reached_type_path` | string | JSON path to a short string naming *which* limit was reached, kept in the provider's own words |

Every field is optional on its own (the table as a whole names at least
one), and that is the point: the app answers
with what the provider stated, and `None` means "did not say" — never "no".
The section exists because a refusal can arrive with no window attached to it.
Codex's schema makes `allowed` and `limit_reached` required fields of
`rate_limit` while both window slots are optional, so a blocked account with
nothing running answers with a status and no windows at all — and
[presence](#presence-a-window-that-isnt-there) correctly draws no row for a
window nobody reported, which would leave the panel showing an account with
nothing wrong with it at the one moment something is.

Two statements count as a refusal outright: `limit_reached = true` and
`allowed = false`. Silence is not one. Naming which limit was reached counts
as a third, but only when neither boolean was set — Codex sends
`rate_limit_reached_type` solely on a refusal, so a body carrying that and no
booleans is one; a provider that fills the same field in the ordinary case
(`"type": "none"`) is not turned into a refusal by it, because any explicit
statement wins over the inference.

`reached_type` is not mapped onto an enum of this app's own. A vocabulary that
grows on the server would otherwise arrive here as a silent "unknown", and the
provider's own word is the thing worth showing.

### `[logfile]`

Required when `engine = "log-file"`.

| Field | Type | Default | Notes |
|---|---|---|---|
| `root_env` | string | — (optional) | name of an env var that, if set in the process environment, overrides where the engine searches (mirrors the existing `CODEX_HOME` override) |
| `root_env_join` | string | — (optional) | subdirectory appended onto `root_env`'s value when it is set (`"sessions"` so `$CODEX_HOME` resolves to `$CODEX_HOME/sessions`); ignored otherwise. Must be a relative path with no `..` component — it is joined onto the env var's value, never used in its place |
| `root` | string | — (required) | root directory to search; `~` and `{config_dir}` expand (see [Path expansion](#path-expansion)); no `..` component |
| `glob` | string | — (required) | glob, relative to `root`, matching the provider's log files (e.g. `"**/rollout-*.jsonl"`) |
| `format` | string | `"jsonl"` | log file format — currently the only supported value |
| `select` | string | `"last"` | which reading to keep when a file has more than one — currently the only supported value |
| `container_key` | string | — (required) | JSON key wrapping a window-bearing reading (e.g. `"rate_limits"`) |
| `classify_threshold_minutes` | integer | `720` | default boundary used to classify a found window as "short" vs "long" when it doesn't declare its own `max_period_minutes`/`min_period_minutes` |

### `[http]`

Required when `engine = "http-api"`.

| Field | Type | Default | Notes |
|---|---|---|---|
| `[[http.request]]` | array of tables | — (required) | the request to issue — exactly one; validation refuses a `[http]` with none and one with two or more |
| `[http.version]` | table | — (optional) | source for the `{version}` header substitution |
| `[[http.value]]` | array of tables | empty | named values read from local files, substituted into headers as `{value.<name>}`; at most 32 entries |
| `min_interval_secs` | integer | `55` | smallest gap between two requests for one surface, however the fetch was triggered — see [Request pacing](#request-pacing); must be below `refresh_secs`, or the scheduled refresh is skipped every other tick |
| `backoff_start_secs` | integer | `60` | first cool-off after a failed request; must be greater than 0 |
| `backoff_max_secs` | integer | `900` | ceiling the doubling cool-off stops at; at least `backoff_start_secs`, at most 7 days |
| `unauthorized_retry_secs` | integer | `3600` | how long an expired session stops the polling for, before one more attempt; from 1 second to 7 days |

`engine = "log-file"` may not declare `[http]` at all — the section describes
a request only the http-api engine ever sends.

#### `[[http.request]]`

| Field | Type | Default | Notes |
|---|---|---|---|
| `url` | string | — (required) | request URL; must be `https` |
| `timeout_secs` | integer | `8` | request timeout, seconds; from 1 to 120 |
| `method` | `"get"` \| `"post"` | `"get"` | HTTP verb. Needs `requires_reader = ["http-post"]` |
| `body` | string | — (optional) | request body for `method = "post"`, substituted exactly like a header value. A GET carrying one fails validation. Needs `requires_reader = ["http-post"]` |
| `headers` | map<string,string> | empty | header map; values may contain `{token}` / `{version}` / `{option.<key>}` / `{value.<name>}` placeholders |

`method` exists because not every usage endpoint answers a GET: Antigravity's
`:retrieveUserQuotaSummary` follows Google's `:verb` HTTP-transcoding
convention, which is POST-only, and a GET to it comes back 404/405 — the
provider would show as broken rather than as "update the app". Both keys carry
the capability, not just `method`: a manifest could write `method = "post"`
with no body at all, and an older build's silent GET would already be wrong
for it.

A `body` is substituted from the same placeholder set as a header value, which
means a manifest **can** put `{token}` in it. That is a property of the engine
rather than of any shipped manifest (Antigravity's body is the literal `{}`),
and it is deliberate: a provider that expects its credential in the payload is
not this app's to refuse. `allowed_hosts` still governs where the request may
go.

#### `[[http.value]]`

A named string read out of a local JSON file and substituted into **header
values** as `{value.<name>}` — never into the URL, the same rule `{token}`
follows. Codex needs it for `chatgpt-account-id`: the account its bearer token
speaks for is named in `~/.codex/auth.json`, not in the URL.

| Field | Type | Notes |
|---|---|---|
| `name` | string | placeholder name; ASCII letters, digits and underscores, unique within the manifest |
| `type` | `"json-file"` | where to read it from |
| `path` | string | file to read (`~` / `{config_dir}` expanded) |
| `json_path` | string | dotted JSON path to a non-empty string inside that file |

A value that can't be resolved is an error on the provider's row, and **no
request is made** — a request carrying an unresolved placeholder would be
answered wrongly, or refused in a way that reads like an auth failure.

#### `[http.version]`

Resolves the `{version}` placeholder (Claude's User-Agent needs a real
`claude-code/<ver>` string or gets aggressively rate-limited).

| Field | Type | Notes |
|---|---|---|
| `files` | array of strings | candidate files, tried in order; at most 16, each non-blank, each an absolute path (`~`, `/`, a drive letter or a UNC prefix — the same rule `[surface.auth.client] files` uses, since a relative one would resolve against whatever directory this process happens to run from) and free of a `..` component. Read verbatim, like `[account] path` and `client.files`: naming `{value.<name>}` or `{option.<key>}` in it is refused (nothing substitutes into it), the same "undeclared/never-substituted placeholder" rule every such field carries |
| `json_path` | string | dotted JSON path to the version string inside whichever file matched |
| `fallback` | string | value used if none of `files` exist or parse |

### `[[surface]]`

A place this provider's usage can be read from — a CLI install, a desktop
app, a second account — each with its own credential chain. A provider may
declare zero, one, or several surfaces.

| Field | Type | Default | Notes |
|---|---|---|---|
| `id` | string | — (required) | stable identifier (`"cli"`, `"desktop"`); ASCII `[A-Za-z0-9_-]+` only, unique within the manifest — it becomes the reading id (`"<plugin id>-<surface id>"`, or the plugin id verbatim for `"default"`) and a throttle key |
| `label` | string | — (required) | display label (`"CLI"`, `"Desktop"`) |
| `opt_in` | bool | `false` | if `true`, the surface is off unless the user explicitly enables it (for a credential lookup that needs a scary OS prompt) |
| `in_menu_bar` | bool | `true` | whether this surface's readings show in the menu-bar pill/title; `false` for popup-only surfaces (e.g. the Claude desktop account) |
| `allowed_hosts` | array of strings | empty | hosts this surface's requests are allowed to reach — see [Security](#security). Required, and refused when empty, on any surface whose auth chain has a step other than `reject-when` — regardless of `engine`, since a credential chain can exist ahead of an engine that reads it — an empty list would let its token be sent anywhere |
| `no_credentials_message` | string | — (optional) | what to show when the whole auth chain came up empty. Unset, that state hides the provider's row entirely (right for a provider that may simply not be installed); set, the row stays and says this instead (Codex: `"Not signed in — run: codex login"`) |
| `[[surface.auth]]` | array of tables | empty | ordered credential lookup chain — see [Auth chain](#auth-chain-semantics) |

A manifest may declare at most 8 `[[surface]]` entries.

**If `[[surface]]` is omitted entirely**, one is synthesized:
`id = "default"`, `label = "Default"`, `opt_in = false`, `in_menu_bar = true`,
`allowed_hosts = []`, `auth = []` — i.e. a single always-present surface with
no credential chain at all — the shape a log-file manifest normally has,
since a log reader authenticates nothing of its own.

#### `[[surface.auth]]`

One step of the ordered credential-lookup chain. All fields below live on the
same struct regardless of `type` — the schema doesn't statically pair a
field with a type, the engine reads whichever fields its declared `type`
needs and ignores the rest.

| Field | Type | Used by | Notes |
|---|---|---|---|
| `type` | `"credentials-file"` \| `"credentials-map"` \| `"keychain"` \| `"env"` \| `"electron-safe-storage"` \| `"win-credential"` \| `"reject-when"` \| `"oauth-refresh"` | all | which credential store this step reads from (`reject-when` reads none, `oauth-refresh` reads one and spends it — see below) |
| `path` | string | `credentials-file`, `credentials-map`, `oauth-refresh` | path to the JSON file |
| `token_json_path` | string | `credentials-file`, `credentials-map`, `keychain`, `win-credential`, `oauth-refresh`; optional on `electron-safe-storage` (default `"claudeAiOauth.accessToken\|access_token"`) | `\|`-separated fallback JSON paths to the token (e.g. `"claudeAiOauth.accessToken\|access_token"` — try camelCase, then snake_case). For `credentials-map` it is read inside the *matched entry*; for `oauth-refresh` it names the **refresh** token |
| `key_prefix` | string | `credentials-map` | prefix the entry's key in the top-level object at `path` must start with. Needs `requires_reader = ["credentials-map"]` |
| `service` | string | `keychain` | Keychain service name to query |
| `expiry_json_path` | string | `keychain`, `credentials-file`, `win-credential` — refused on any other step kind (the error names the step's own index and kind) | JSON path to an expiry beside the token — an RFC3339 string, or a JSON number/numeric string read as epoch seconds or milliseconds (told apart by magnitude); a lapsed one makes the step **Absent** instead of handing back a stale token. Needs `requires_reader = ["keychain-expiry"]` |
| `var` | string | `env` | environment variable name holding the token |
| `config_path` | string | `electron-safe-storage` | path to the Electron config/state file holding the encrypted blob |
| `blob_json_path` | string | `electron-safe-storage` | `\|`-separated fallback JSON paths to the blob inside `config_path` |
| `macos_keychain_key` | string | `electron-safe-storage` (macOS only) | Keychain service name holding the Safe Storage password; ignored on Windows, where the blob is decrypted via DPAPI instead — no manifest field needed there |
| `targets` | array of strings | `win-credential` | Windows Credential Manager target names, tried in order |
| `json_path` | string | `reject-when` | dotted path inside `path` whose presence means this surface cannot be read |
| `unless_json_path` | string | `reject-when` | when this path also resolves, the rejection stands down and the chain continues |
| `message` | string | `reject-when` | the sentence shown on the row instead of windows |
| `token_url` | string | `oauth-refresh` | where to send the token exchange; must be `https` and must be inside this surface's `allowed_hosts`. Needs `requires_reader = ["oauth-refresh"]` |
| `client_id` | string | `oauth-refresh` | the OAuth *installed application* client id, spelled out literally. Still supported for a manifest that would rather ship the pair directly than discover it (see `client` below); an `oauth-refresh` step needs one or the other, and may not set both |
| `client_secret` | string | `oauth-refresh` | the matching installed-app secret. Public by construction — an installed-app secret shipped inside a distributed binary cannot be kept from anyone willing to extract it, which is why OAuth2 treats such clients as public — but still never logged or put in an error string here |
| `client` | table | `oauth-refresh` | read `client_id`/`client_secret` from the installed client's own binaries at run time instead of shipping them — see [`[surface.auth.client]`](#surfaceauthclient) below. Needs `requires_reader = ["oauth-client-discovery"]`; may not be set alongside the literal `client_id`/`client_secret` above |

`credentials-map` is `credentials-file` applied one level deeper: the JSON
object at `path` is a **map** of credential records rather than one record,
and the step picks the single entry whose key starts with `key_prefix`, then
reads `token_json_path` inside it. It exists because the dotted-path grammar
cannot name such an entry at all — `token_json_path` splits on `.` and its
fallback list splits on `|`, and neither can spell a key that itself contains
dots and colons, which is what Grok's `"https://auth.x.ai::<uuid>"` (a uuid
unique to the install) is. Copilot's `apps.json` is keyed `"github.com:<...>"`
for the same reason. More than one entry matching the prefix is an **error**,
not a coin toss: which account's token to send is not something this app gets
to guess.

`oauth-refresh` is the one step that does not merely read a credential. It
loads a stored refresh token from `path`/`token_json_path`, exchanges it at
`token_url` for a fresh access token, and hands that back — held in memory
only, never written to disk, so the provider's own client keeps the copy it is
holding. It exists for a store whose *access* token is stale most of the time:
Antigravity's goes off in hours whenever its IDE is not running, so a chain
that could only read it would report "sign in again" about an account that is
signed in fine. Placed behind a `keychain` step carrying `expiry_json_path`,
it fires only when the fast path has actually lapsed.

Because that step sends a credential of its own — before the engine's own
`allowed_hosts` check on the main request ever runs — it enforces the rules
itself: `token_url` must be `https` (refused at load by `validate`, the same
as `[[http.request]].url` and `[account].url` above, and refused again where
the exchange is actually sent — defence in depth, not the only depth), and an
**empty** `allowed_hosts` is refused outright rather than read as "no
restriction" the way it is everywhere else. Successful exchanges are cached
in memory by expiry, and a failed one backs off, so a one-minute poll does
not become a one-minute token exchange.

The cache is read by `(token_url, refresh_token)` **before** the installed-app
pair (`client_id`/`client_secret`, literal or discovered) is ever resolved —
a still-valid cached access token is served without touching `client`
discovery at all, so a transient discovery hiccup this tick (the miss-cache
backoff active, a candidate that failed to read, …) can never discard a token
that is still perfectly good. The one place the pair is still relevant to an
already-cached entry is a *backoff*: that entry remembers which `client_id`
it failed with, and if the pair now resolves to a different one, the backoff
is bypassed and retried immediately — a rotated or corrected pair is not
punished for a different pair's recent failure. A fresh, unexpired access
token carries no such comparison; it is served purely by expiry.

##### `[surface.auth.client]`

`oauth-refresh`'s installed-app pair is public by OAuth2's own definition
(above), but "public" is not "safe to commit" — it is *this app's* repository
that would be carrying somebody else's client's secret, in plain text,
forever, and GitHub's push protection agrees. `client` is the alternative to
typing the pair out: it reads `client_id`/`client_secret` back out of the
credential's own installed client, on whichever machine is running, instead
of shipping them. A step may set `client` *or* the literal `client_id`/
`client_secret` fields, never both — the combination is ambiguous about
which one is meant, and is refused at load rather than resolved by picking
an order silently.

| Field | Type | Required | Notes |
|---|---|---|---|
| `id_env` | string | no | environment variable naming the client id; must match `^[A-Za-z_][A-Za-z0-9_]*$` |
| `secret_env` | string | no | environment variable naming the client secret; same charset |
| `id_pattern` | string | **yes** | regular expression (`regex` crate syntax, compiled as `regex::bytes::Regex` — the engine the scan actually uses) matched against a candidate file's bytes; the first match is the client id |
| `secret_pattern` | string | **yes** | same, for the client secret |
| `files` | array of strings | no\* | absolute paths (`~` expanded), with no `..` component, to scan first, in order — at most 16 |
| `bins` | array of strings | no\* | bare program names — no `/`, `\`, `..` component or drive prefix — to resolve on `PATH` (and the usual CLI install directories) and scan next, in order — at most 8 |

\* `files` and `bins` may each be empty, but not both — unless `id_env` and
`secret_env` are both set, in which case there is nothing that must be
searched at all. `id_env` and `secret_env` must themselves be set together or
not at all — half a pair can never resolve anything, and is refused at load
rather than treated as a partial override. Blank strings are refused anywhere
in the table, and a `files` entry must be an absolute path *after* `~`
expansion (a relative one would resolve against whatever directory this
process happens to be running from). `id_pattern`/`secret_pattern` must each
compile, must not be able to match the empty string (`regex_syntax`'s parsed
`minimum_len` at least 1 — otherwise a matched-but-empty id or secret would
reach the OAuth exchange as `""`), and must have a bounded maximum match
length (`maximum_len`) no greater than 256 bytes — a client id or secret is
never remotely that long, and an unbounded pattern (`.*`, `[a-z]+`) would turn
"scan a file for a short id" into "read an unbounded slice of it and call the
slice the client". A *bounded-but-not-exact* pattern (`{1,20}` where the real
value is always exactly 13 digits, say) is not itself refused, but is worth
avoiding: the same character class that lets it match the real value at all
usually keeps matching past its actual end, so a stray byte adjacent to the
real value in the file gets pulled into the match — a wrong, corrupted id or
secret every candidate would match, not a missing one, and a harder failure
to notice than a load-time refusal (see the shipped Antigravity manifest's
own `id_pattern` and its comment for a measured example). The scan enforces
the same 256-byte ceiling defensively at read time, on top of refusing the
manifest at load.

That 256-byte ceiling bounds what a pattern can *match* — it says nothing
about how long the pattern's own *source text* is: thousands of
fixed-length alternatives could all match well within it while the pattern
itself runs to kilobytes. A separate cap, 512 bytes of source text, is
refused at load for exactly that reason — and matters beyond the file size
alone, since that source text is what the install-time trust dialog shows
(next). The dialog itself truncates each pattern to 120 bytes plus `…`,
shorter still: a dialog line is meant to be read at a glance, not merely
bounded enough not to be a denial-of-service.

**Resolution order**, tried once per `oauth-refresh` fetch
(`auth::resolve_client`), and only *after* the step's refresh-token file has
already been found and read — a client with a `files`/`bins` candidate
hundreds of megabytes long costs nothing for the common case of someone who
has never signed in to this surface at all:

1. Both `id_env` and `secret_env` set and non-blank in the environment — used
   outright, no file ever touched. An operator's own override always wins.
   For a manifest that passed validation, `id_env`/`secret_env` are always
   either both set or both absent (see above), so "exactly one set" cannot
   actually happen here; `auth::client_env_pair` still handles it — queuing a
   diagnostic line, once per process, and falling through to the next rung —
   for a hand-built step that reached this some other way, in this reader's
   own tests.
2. Discovery: each of `files`, then each of `bins` resolved on this machine,
   in order — the **first** candidate that carries a match of both
   `id_pattern` and `secret_pattern`, **from the same file**, matched
   independently (the first match of one need not be anywhere near the
   first match of the other). A pair split across two files does not count;
   a candidate that doesn't exist, or exists but doesn't carry the shape, is
   skipped, not an error. A candidate that exists but can't be *read* (a
   permission error, say) queues its own diagnostic and is likewise skipped,
   but is still tracked separately from a genuine miss below. A candidate
   whose read was cut short by the per-file or whole-pass byte budget — not
   fully read, so "not found" is a claim it cannot make either — is tracked
   as a third state, `Truncated`, and queues its own diagnostic too.
3. Nothing found anywhere — the step resolves **Absent**, exactly like a
   missing credentials file. For Antigravity specifically, the `keychain`
   step ahead of it in the chain still covers the common case (the IDE
   actually running); only the fallback loses its own fallback. One line is
   written to this app's diagnostic log per process, per plugin, naming the
   env vars — a client that hasn't been installed yet is retried at most once
   every ten minutes, so installing it mid-session is picked up without a
   restart. That ten-minute backoff is not reserved for a genuine miss: a
   read error also earns it (a permanently unreadable candidate must not be
   rescanned in full on every fetch), and it always comes with the read-error
   diagnostic rather than the "not found" one, so the two are never confused.
   A truncated pass earns a *shorter* backoff — two minutes, not ten — since
   it was never a completed attempt and must not be mistaken for one, but a
   candidate set that is *always* truncated (an oversized `bins` match, say)
   still must not be re-read in full on every single tick.

(The literal `client_id`/`client_secret` fields are not part of this
resolution order at all — `resolve_client` never reads them.
`auth::oauth_refresh_step` reads them directly, before ever calling
`resolve_client`, and only when the step carries no `client` table; the two
are mutually exclusive by the rule above, so a manifest that passed
validation is always in exactly one of the two shapes.)

A found pair is cached in memory for the life of the process, keyed by
*(the discovery config, the file it was found in)* — so the *same* installed
binary is never scanned twice for the same config, which matters when it is
Antigravity's ~180 MB `agy`, while two different configs sharing a candidate
never share a match. The cache is re-validated by the candidate's length and
modification time on every lookup, not by a clock — a found entry has no
expiry of its own, so a client reinstalled with a new secret at the same
path is rescanned because its length/modification time changed, not because
some interval passed; without that check it would be served indefinitely,
for as long as the file at that path keeps the same identity. It is also
evicted outright on an `invalid_client` response from the token exchange, so
a rotated pair is retried on the very next attempt rather than replayed
until its identity happens to change some other way. Eviction clears the
found pair and the miss backoff, but
**not** the once-per-process "not found"/"half-set env" notifications — those
are about a *config* an operator has already been told about, not about the
credential that just went stale, and eviction must not make them reappear.
The file itself is read in bounded chunks (a total budget across every
candidate in one pass, not merely per file) with a small overlap carried
across each chunk boundary, never loaded whole, so a match split across a
boundary is still found.

The install-time trust dialog ([Trust model](#trust-model)) discloses a
`client` table's `files`, `bins`, `id_env`/`secret_env` **and**
`id_pattern`/`secret_pattern` — both patterns are bounded to 256 bytes by the
rule above, so always short enough to render, and without them the dialog
would show only *where* a step looks, never *what shape* it pulls out of
there.

`reject-when` is not a credential store: it turns a *known* dead end into
something the user can act on, using the chain's existing Present-err outcome.
Codex's case is an API-key sign-in — `OPENAI_API_KEY` set in
`~/.codex/auth.json`, no OAuth token, and therefore no subscription windows to
report. Such a step goes **before** the one reading the real token, because a
credentials file that exists without a token is itself Present-err and would
stop the chain first; `unless_json_path` is what keeps it from firing for an
account that does have a token. A file that is missing or unparsable makes the
step Absent — a rule that can't be evaluated must never block a credential
that might be there.

### `[[option]]`

A declarative boolean a plugin exposes, one entry per option. Its current
value reaches the engines as the `{option.<key>}` substitution (`"true"` /
`"false"`) in `[http]` headers and URLs and in `[logfile]` `root`,
`root_env_join` and `glob`; the user's choice is stored in `config.json` under
`plugin.<id>.option.<key>` and falls back to `default` until set. The schema,
validation and substitution are in place; no shipped manifest declares an
option yet, and Settings draws no checkbox for them yet.

| Field | Type | Required | Notes |
|---|---|---|---|
| `key` | string | yes | ASCII letters, digits and underscores only; unique within the plugin — it spells the `{option.<key>}` placeholder |
| `label` | string | yes | display label for the (future) checkbox; must not be blank |
| `default` | bool | no (default `false`) | value used until the user overrides it |

A template that spells `{option.<key>}` for a key no `[[option]]` declares is
refused at load (see [Validation](#validation--forward-compatibility)); a key
declared twice is refused too. A manifest may declare at most 32
`[[option]]` entries.

### `[ping]`

Optional command run shortly after the **primary** window resets, to start a
fresh window (consumes a little quota — opt-in per plugin/user). With
`renews_token`, the same command also runs whenever a surface's token has
lapsed — see [Renewing a lapsed token](#renewing-a-lapsed-token) below.

| Field | Type | Default | Notes |
|---|---|---|---|
| `bin` | string | — (required) | binary to run; a bare program name, not a path — no `/`, `\` or `:` (the last rules out a Windows prefixed-relative path like `C:evil`, which has neither of the other two) |
| `args` | array of strings | empty | arguments; at most 32, each non-empty and at most 256 bytes — the install-time trust dialog renders the whole command line, and these bounds keep one argument from pushing its untrusted-host warning off the bottom |
| `renews_token` | bool | `false` | whether running this command also renews the provider's token, as a side effect the provider's own CLI has and this app does not (it never spends a provider's refresh token). A surface whose auth chain ends "lapsed" (a credential found, past its `expiry_json_path`, with no working step behind it) runs this command instead of only waiting for the user to sign in again — bounded by the same ten-minute floor as the window ping above |

No argument, label, hostname, message, or other manifest-supplied string
listed in this document may contain a control character (C0, DEL) or a
bidirectional override (U+200E/F, U+202A–E, U+2066–9, or the Unicode line/
paragraph separators U+2028/9) — refused at load, for the same reason: one of
these can rewrite a trust dialog, a log line, or the panel around it without
a single visible character looking wrong.

### Path expansion

`~` (home directory) and `{config_dir}` (OS config directory — `~/Library/
Application Support` on macOS, `%APPDATA%` on Windows) are recognised only at
the very start of a path spec (`root`, surface auth paths, etc.) and expanded
by `plugin::expand_home`. Anything else is a literal path; if the
corresponding directory can't be resolved, the original spec is returned
unchanged rather than panicking.

### Validation & forward compatibility

`PluginManifest::from_str` parses the file as a TOML document, checks
capabilities (`plugin::capability::check` — see [Reader
capabilities](#reader-capabilities-requires_reader)), *then* parses it into
`PluginManifest`, defaults, and validates (`PluginManifest::validate`).
Capabilities go first — ahead of the typed parse, not merely ahead of
validation — so that a manifest written for a newer reader hears "update the
app" even when what's new about it is the type of a field that already
existed. Failures for one manifest never break the others in the folder (see
[Plugin folder & seeding](#plugin-folder--seeding)).

Note the split: the capability check reads the raw TOML and therefore lives in
`from_str` alone, while `validate` works on the parsed struct and can be
re-run by anything holding one. Anything that ever starts accepting manifests
by a route other than `from_str` has to call the capability check itself.

**The complete list of what is refused lives in `tests/manifest_corpus.rs`** —
one row per rule, each with a manifest that breaks exactly that rule and the
field the complaint has to name. It is the list rather than a sample: a test
in that file counts the refusals in `validate` and fails if the two numbers
disagree, so a rule added without a row is caught where it happens. Prose
here would be a copy that drifts; the corpus is checked on every build.

Broadly, the rules cover: `requires_reader` naming capabilities that exist,
are implemented here, and are declared by every manifest that uses their
fields; the fields every manifest needs and the charset an
`id` may use (it becomes a filename and a config key, and may not be one of
Windows's reserved device names); each engine having the section it reads,
and only that section — a `log-file` manifest may not carry `[http]` — and
that section being usable rather than merely present; one primary window, and
a period that supplies what its own mode needs, with `period.assumed` at
least five minutes; every timing knob (`refresh_secs`, `min_interval_secs`,
the backoff pair, `unauthorized_retry_secs`, `timeout_secs`) bounded above
and below, and `min_interval_secs` kept under `refresh_secs`; every
credential-carrying surface declaring where its token may go, regardless of
which engine reads it; credentials never appearing in a URL; every auth step
and `[account]` type carrying its own required fields; `[ping]` naming a
program rather than a path, with its argument list bounded in count and
length; every array a manifest can declare (`[[windows]]`, `[[balances]]`,
`[[option]]`, `[[http.value]]`, `[[surface]]`, `[http.version] files`,
`source.containers`, `client.files`/`client.bins`) capped in size; no `..`
component in a path a manifest names (`[account] path`, `[logfile] root`,
`[[http.value]] path`, `[http.version] files`, an auth step's `path`/
`config_path`, `client.files`); no control character or bidirectional
override in a string this app renders or logs; and every `{value.<name>}` or
`{option.<key>}` a template spells being declared somewhere in the same file
— an undeclared one is not substituted at runtime, so the request would go
out with the braces still in it.

Everything else is optional/defaulted, and — per the "unknown fields
ignored" rule above — a manifest can carry extra fields a given build
doesn't understand without failing to load.

## Engines

Both engines turn a `[[windows]]` list plus a raw reading (a JSONL line, or
an HTTP response body) into the neutral `crate::model` shape the UI renders.
This section describes the target read algorithm each engine implements
against the frozen schema above.

### `engine = "log-file"`

1. Expand `[logfile].root` (`root_env` override, then `~`/`{config_dir}`),
   and glob for files matching `[logfile].glob` under it.
2. Order candidate files **newest-first by mtime** (not by any timestamp
   in the filename — an actively-written file is the freshest source even
   if its name is older).
3. Within a file, walk its lines and, for each, **depth-first search** the
   parsed JSON for an object keyed `[logfile].container_key` (e.g.
   `"rate_limits"`) — tolerant of how deeply it's nested inside the line,
   so a provider that wraps its reading in extra envelope fields doesn't
   need a different manifest shape.
4. Once a container is found, its immediate object-valued children are
   candidate windows — the engine does **not** need to know their key
   names (`"primary"`/`"secondary"` or anything else a provider calls
   them). Each candidate is matched against a declared `[[windows]]` entry
   by **period length**: its length is computed per that window's
   `[windows.period]` (`assumed`, or read via `field`), then compared
   against that window's `source.max_period_minutes` /
   `min_period_minutes` if given, else against the provider-wide
   `[logfile].classify_threshold_minutes` (default 720 — windows this long
   or shorter classify as "short"). This mirrors the existing Codex
   reader's length-based classification (`SHORT_WINDOW_MAX_MINUTES = 720`),
   generalized so windows aren't required to appear in a fixed position —
   Codex has been observed reporting the weekly window alone in the
   `primary` slot right after a 5-hour reset.
5. Per `[logfile].select` (`"last"`, the only supported value today): keep
   the last matching reading found across the file, falling back across
   files if the newest one has none yet (a session that only just started
   can legitimately contain zero readings so far).
6. For each matched window, read the slot's own `used_percent` and
   `resets_at` fields (with the spelling tolerance listed at the top of
   `engine_logfile.rs`: `used_percent` / `usedPercent` / `percent_used`,
   `resets_at` / `resetsAt` / `reset_at`), then parse `resets_at` per that
   window's `resets_at_format`. `used_percent_path` / `resets_at_path` are
   `http-api` fields and play no part here.

Two caps bound the cost of one fetch regardless of how large the session
tree under `root` has grown, so a plugin whose glob has matched years'
worth of files pays a fixed price rather than one proportional to what it
matched: at most 200 files (`LOG_WALK_MAX_FILES`) are ever opened and read
— the newest by mtime kept whenever a glob matches more, since both the
primary lookup and the secondary-accounts lookup already read newest-first
and only need the freshest handful — and at most 64 MiB total
(`FETCH_BYTE_BUDGET`) is read out of them, the primary lookup and the
secondary-accounts lookup each paying this budget separately rather than
sharing one.

### `engine = "http-api"`

1. For each active surface (its auth chain resolved to a token — see
   below), issue every `[[http.request]]`, substituting `{token}` with
   that surface's resolved credential and `{version}` with
   `[http.version]`'s resolved value (or its `fallback`) in header values.
2. Before sending, the resolved request host — the one named in the
   manifest's own `[[http.request]].url`, before any redirect — is checked
   against that same surface's own `allowed_hosts`; a mismatch refuses the
   request rather than sending it. The client does not follow redirects, so a
   3xx response from an allowed host can't retarget the request to a host
   outside that list either. This check is a guard against a *trusted*
   manifest's own mistakes (a typo'd host, an open redirect on its declared
   endpoint) — not a sandbox against a manifest that deliberately declares a
   hostile host, since the manifest is the one supplying both the URL and the
   allow-list it's checked against (see [Security](#security)).
3. Parse the JSON response body and read each `[[windows]]` entry's
   `used_percent_path` / `resets_at_path`, honoring `resets_at_format`.
   Those paths are read from the response root (Claude's
   `"five_hour.utilization"`) unless the window declares
   `source.containers`, in which case they are relative to whichever
   candidate classified as this window — see
   [`[windows.source]`](#windowssource).
4. A window whose paths resolve to nothing is still emitted, with every
   field blank. A reading whose windows are *all* blank renders as a
   message ("no usage reported yet"), never as an empty card.

Pacing, backoff and the stop-on-expired-session rule apply to every request
this engine makes, including the `[account] type = "http"` profile lookup —
see [Request pacing](#request-pacing).

## Request pacing

`refresh_secs` paces the timer. It does not pace the panel opening, the
Refresh button, the tray's "Refresh now", enabling a plugin, or app start —
all of which fetch. Against a local log file that costs nothing; against an
API, a user opening and closing the panel ten times a minute would have made
ten requests. `src/plugin/throttle.rs` holds one state machine per surface:

- **A floor between requests** (`min_interval_secs`), served from the last
  reading in between. Keep it *below* `refresh_secs`: at or above it, the
  scheduled refresh lands a hair early, gets served from cache, and the real
  cadence silently halves.
- **A doubling cool-off after a failure** (`backoff_start_secs` →
  `backoff_max_secs`), then steady at the ceiling. A provider that is down is
  polled rarely, never never. While backing off, the row keeps showing the
  last good reading if there is one, else the failure.
- **A stop on HTTP 401.** This app never spends a provider's refresh token —
  that would invalidate the copy the provider's own CLI holds — so an expired
  token cannot come back on its own, and retrying it on the refresh cadence is
  a request that can only fail.

That last rule is only safe because of what lifts it. Every decision is keyed
on a fingerprint of the token plus the `{value.<name>}` headers derived from
it: sign in again and the fingerprint changes, which lifts the stop at once
and drops the cached reading — so one account is never answered out of
another's cache. And because a 401 can also be a gateway having a bad minute,
with the credentials never changing, the stop additionally expires after
`unauthorized_retry_secs` and one more attempt is made — otherwise that
surface would stay silent until the app was restarted.

Timing is monotonic, so a clock moved backwards can't stretch a cool-off into
hours. The state is per-process: restarting the app is always worth one
request per surface, by design.

### A fetch that never comes back

Pacing decides when to *start* a fetch. Separately, the app keeps one
in-flight mark per plugin so two fetches for the same provider can't overlap,
and that mark is cleared by the result arriving. A fetch that panics still
sends one (`FetchGuard`); a fetch that never gets a thread never sets the mark.
A fetch that **hangs** did neither: the mark stayed up for the life of the
process and the plugin was never polled again — a row that quietly stopped
changing, with no error to show for it. A credential step waiting on an
unanswered OS keychain prompt is the realistic way in.

A thread can't be killed, so what happens instead is that the app stops
waiting. After `FETCH_PATIENCE` (10 minutes — generous, because that keychain
prompt is a legitimate reason to be slow and asking again would mean prompting
again) the next scheduled refresh starts a fresh fetch and says so in the log.
The abandoned one may still return, so each fetch carries a generation and a
result whose generation is no longer the current one is dropped: it must not
clear the mark belonging to its replacement, nor overwrite that replacement's
newer reading with an older one.

## Auth chain semantics

A surface's `[[surface.auth]]` list is tried **in order**. Each step
resolves to one of three outcomes:

- **Present-ok** — the credential store exists and a token was read from
  it. Stop here; use this token.
- **Present-err** — the credential store exists, but the token couldn't be
  read (e.g. a Keychain access prompt was denied). Stop the whole chain
  with an error; do **not** fall through to the next step (a denied
  Keychain read isn't "absent", it's a real failure the user should see and
  can act on).
- **Absent** — the store doesn't exist on this machine at all. Try the
  next step; if none remain, the surface itself is considered absent
  (its section is simply not shown — this is how "no Claude desktop
  install on this machine" differs from "Claude desktop is installed but
  denied Keychain access").

For Claude this chain runs credentials file, then Keychain, then Windows
Credential Manager — expressed as a declarative, ordered list any plugin can
configure, not hardcoded to that one provider.

## Surfaces & accounts

A single provider can have more than one account-bearing surface — Claude
ships two: `cli` (the CLI/VS Code login) and `desktop` (the Electron app,
which may be signed into a different account). Each surface:

- Runs its own auth chain independently — one surface being absent or
  denied doesn't affect another.
- Can be `opt_in` (default `false`): a surface whose credential lookup
  needs a scary OS prompt (the Claude desktop app's Safe Storage key) stays
  off until the user explicitly turns it on, so no surprise Keychain dialog
  appears on first launch.
- Can be excluded from the menu-bar pill/title via `in_menu_bar = false`
  while still appearing in the popup (the desktop surface's default).

## Windows & period classification

`role = "primary"` marks the window that drives the automatic refresh
timer and fills the first mini-bar in the menu-bar pill when a provider has
more than one window; `role = "secondary"` is everything else. A manifest
with two or more `primary` windows fails validation — there's exactly one
"main" window per provider.

`period.mode` says whether a window's nominal length is a fixed constant
(`"assumed"`, e.g. Claude's 5-hour/weekly windows, which the API doesn't
report a length for) or read out of the reading itself (`"from_field"`,
e.g. Codex's `window_minutes`, since Codex can and does report a window
whose stated period differs from the "usual" 5h/weekly split). See
[log-file classification](#engine--log-file) for how a read period length
maps back to a declared window when the raw data doesn't name its windows
positionally.

## Ping (auto-refresh nudge)

`[ping]` is optional. If present, `bin`/`args` are run once per **primary**
window, on the tick that first sees that window sitting empty. This nudges the
provider's CLI to start a fresh usage window immediately rather than waiting
for the user's next real request, at the cost of a small amount of quota,
which is why it's an explicit per-provider, user-toggleable feature (see
`auto_ping_codex` / `auto_ping_claude` in `src/config.rs`), not something a
manifest can force silently on.

**Empty, not just-reset** — the condition is a state, not an edge, and the
difference is the whole point (`main.rs::ping_due`). Firing on the reset
*instant* only works for a process awake at that instant: a Mac asleep at the
boundary, or an app launched a minute later, missed that window's ping for
good, with no catch-up. Asking instead whether the current window is empty is
a question that is still answerable afterwards, so the ping goes out late
rather than not at all.

A window counts as empty when the provider reports it with no usage at all —
`used_percent` absent, or `0`. A figure that is neither (a NaN) counts as
busy: a number that can't be read must not spend quota.

**De-duplicated by time, not by window id.** Two pieces of state in
`config.json` survive restarts and sleeps:

| Key | Meaning |
|---|---|
| `plugin.<id>.pinged_at` | when the last ping fired. A ping is due only if that is *older than the start of the window on screen* — a ping from inside the current window has already done its job |
| `plugin.<id>.seen.<reading id>.<role>.at` / `.period_minutes` | the seen-window registry (below): the newest reset the provider has *stated* for one window, and how long it said that window was |

The pre-registry key `plugin.<id>.seen_window` — one value per plugin, meaning
this plugin's primary window on its first surface — is still read as a fallback
for exactly that window and never written again, so an install upgrading into
the registry doesn't lose the boundary its ping is working from.

A timestamp rather than a window id because **the same window is named
differently before and after the provider starts reporting it**. Codex reports
nothing while empty, so the ping's own `hello` is what makes it report a window
again — arriving rounded to `0%` used and looking, to an id-based rule, like a
second empty window to ping. `window_start` is the reset minus the period when
the provider states one, and the last stated reset (projected forward a period
at a time) when it doesn't.

That projection is what keeps a failed ping from being permanent. A ping that
doesn't start a window leaves the provider silent, so its boundary would stay
frozen at a value already recorded as pinged — and the retry would never come.
Projected, the boundary moves on one period later and the ping is owed again:
at worst one attempt per window, never zero.

Consequences worth knowing:

- Enabling the toggle while the current window is empty pings once, right
  away, rather than waiting up to five hours for the next boundary.
- A provider in the vanished-window case gets no ping until it has stated a reset
  at least once — there is otherwise no boundary to compare against, and
  inventing one would ping on a schedule nobody declared.
- The edge rule also bounded *staleness*: armed only within 120 seconds of the
  reset, it could not act on an old reading. The state rule can, and the case
  is real — while a surface is backing off (or stopped on a 401) the panel
  keeps showing its last good reading. The cost is bounded to one ping per
  window by `pinged_at`, and judged the better trade: a ping that occasionally
  goes out one window late costs a few tokens, while the boundary a sleeping
  Mac swallowed cost the whole window.

### Renewing a lapsed token

A second, independent trigger for the same command: `[ping] renews_token =
true` means running `bin`/`args` also renews the provider's token, as a side
effect the provider's own CLI has and this app does not — it never spends a
provider's refresh token (see [Auth chain semantics](#auth-chain-semantics)
and `plugin::throttle`'s module doc). Claude's CLI keeps its 8-hour access
token current only when it itself makes a request; while the app is otherwise
idle, that token can lapse with nothing here to renew it until the next
window boundary happens to fire the ordinary ping — a gap of up to two hours.

Only a surface whose own auth chain declares a token lifetime is even
*consulted* by the tick — `SurfaceConfig::declares_token_expiry`, true iff
some `[[surface.auth]]` step on it sets `expiry_json_path`. Claude's `cli`
surface does (all three of its steps carry `expiry_json_path`); its
`desktop` surface does not (`electron-safe-storage`, its own separate
token, opt-in, renewed by the desktop app itself) — so a lapsed or 401'd
`desktop` reading is never rewritten and never triggers a ping, even though
the plugin's `[ping] renews_token` is true: that ping's binary renews the
CLI's token, not the desktop app's, and rewriting or pinging on its behalf
would be false.

A `keychain`/`credentials-file`/`win-credential` step carrying
`expiry_json_path` already resolves **Absent** on a lapsed token so a step
behind it (an `oauth-refresh`, say) gets its turn. When nothing is behind it,
the chain reports "lapsed" rather than "no credentials at all" — a fact
distinct enough to act on — and, with `renews_token` set, the surface's row
reads `token expired — renews on the next <bin> run` instead of "session
expired — sign in again". The same rewrite happens on an HTTP 401 the token
still managed to reach the network with — gated more precisely there, by
*which step actually produced the token that 401'd*
(`auth::resolve_token`'s own `from_expiring_step`), not by the surface as a
whole: a surface whose chain mixes an expiry-declaring step with a plain
fallback behind it (an `env` var behind a lapsed `credentials-file`, say)
can still 401 on a token the fallback step produced, and that token's own
lifetime was never declared — rewriting that 401 would promise a renewal
`[ping]`'s binary cannot deliver. The lapsed-chain rewrite needs no
separate check of its own here: it can only ever fire from a step
`declares_token_expiry` already required to exist.

Every tick, a plugin whose `[ping] renews_token` is true has every eligible
surface's current reading checked — not just the first with a signal, since
two independent surfaces can lapse on their own separate schedules — and the
first one found due is offered the same treatment [`ping_due`] gives the
window ping: no more than once every ten minutes
(`PING_MIN_INTERVAL_SECS`), the floor shared with the window ping — a
renewal spends this tick's one allowed ping, same as a window ping would.
A renewal merely on cooldown never blocks a *later* eligible surface's own
renewal from being checked, nor that tick's ordinary window ping — only a
renewal that actually spawned a run skips the window ping. It is otherwise
the same command, the same auto-ping toggle, and the same sandboxed working
directory as the window ping below — and that toggle is what decides
whether *this app* runs the command at all; the row text itself (above)
appears either way, since it states what the next run of that command does,
regardless of who starts it.

**Bounded to once per token, not once per floor.** A lapsed auth chain
carries the expiry it declared (`auth::token_expiry`, epoch seconds). A bare
401 carries no such expiry — nothing here ever parsed the credential that
produced it — so it is keyed on the token itself instead: a hash of the
bearer token and the request's other credential-derived values
(`plugin::throttle::fingerprint`, already computed for the throttle's own
purposes and reused here rather than hashed twice; never the token itself,
never persisted or logged). `main.rs` remembers, per *surface* (keyed by the
same surface reading id the panel and the registry already use, e.g.
`"claude-cli"`) and in memory only, which key the last renewal ping actually
fired for, and a reading naming that same key again is not due again — only
a *different* key (the CLI renewed, then the token lapsed again; or, after a
401, the credential changed) is due. Keyed per surface rather than per
plugin so that two renewal-eligible surfaces on one plugin, each lapsing on
its own schedule, each get their own "once per token" bound instead of one
surface's renewal overwriting — and so silently re-arming — the other's.
Without this, a token the CLI cannot renew either — its own refresh token
has expired too, say, and it now needs an interactive login — would
otherwise be pinged every ten minutes forever, uselessly, for as long as the
app runs. The credit is provisional until the command is actually running:
recorded once the background thread that would run it starts, and undone if
the OS then refuses to start the process itself (an existing but
unexecutable binary — permission denied, wrong architecture) — a run that
never happened must not read as "already tried".

### Where the ping's command runs

Not in the home directory. These CLIs read the directory they start in —
`codex exec` picks up an `AGENTS.md` there as instructions — and the ping is a
model run on a timer that nobody watches and whose output is discarded, which
is the ideal setting for a prompt injection. It runs in an empty directory this
app owns instead (`main.rs::ping_cwd`, beside the plugins folder), so there is
nothing there to read.

Its `PATH` is the inherited one with the usual CLI install directories
**appended** (`main.rs::cli_path_env`). A bundled app inherits launchd's
minimal `/usr/bin:/bin:/usr/sbin:/sbin`, which is not enough to start a CLI
that is a wrapper script — `~/.npm-global/bin/codex` is a symlink to
`codex.js`, whose `#!/usr/bin/env node` finds no `node` there, and the run dies
before it begins. Appended rather than prepended, because every one of those
directories is user-writable and this command runs unattended: adding places to
look is the point, letting them shadow the `git` or `curl` the CLI shells out
to is not.

Every attempt is recorded — the command as it was run, then how it ended, with
the command's own stderr quoted on failure. That quoted line ("Not inside a
trusted directory…") is the one that made the last such failure diagnosable at
all. It goes to `tickover.log` beside `config.json` as well as to stderr,
because stderr is exactly the place a Finder-launched `.app` doesn't have (see
`src/diag.rs`):

```
2026-08-20T12:57:25+03:00 auto-ping: running /Users/…/codex exec --skip-git-repo-check --sandbox read-only hello
2026-08-20T12:57:30+03:00 auto-ping: /Users/…/codex finished
```

The run is waited on in a thread of its own, with a **10-minute deadline**
after which the command is killed and the kill recorded. The deadline bounds a
hang — a CLI waiting on a read that never returns would otherwise hold a
thread and a process for as long as the app lives — and is set far above any
healthy answer (the real thing takes seconds), because killing a slow but
living run would be worse than the hang it prevents. The command's stderr is
drained on a second thread rather than after the wait, since a command chatty
enough to fill the pipe would otherwise block writing to it while we block
waiting for it to exit.

## Ordering & the menu-bar pill

Providers are ordered by `order` (Codex ships at `10`, Claude at `20`; ties
break on `id`). When only one provider is currently visible in the
menu-bar pill, that provider's `menu_label` prefix is omitted — a single
visible provider doesn't need a label to disambiguate it from anything, so
the pill just shows its numbers (e.g. `▂▂ 91/68` rather than
`Cx ▂▂ 91/68`). Add a second visible provider and both labels reappear.

## Prior art: what the neighbours do, and what was taken from them

Four codebases were read while this format was designed. Two are the *clients
whose endpoints this app reads*, so they are the authority on those response
shapes; two are apps solving an adjacent problem. Recorded with what each one
settled, because the same questions come back every stage.

**The Codex CLI source.** Its generated
OpenAPI models (`codex-rs/codex-backend-openapi-models/src/models/`) are the
schema for `chatgpt.com/backend-api/wham/usage`, i.e. the contract
`plugins/codex.toml` is written against:

* `rate_limit` (the subscription) carries `allowed`, `limit_reached` and
  **exactly two** window slots — `primary_window`, `secondary_window`. There is
  no array of arbitrary windows; a window snapshot is `used_percent`,
  `limit_window_seconds`, `reset_after_seconds`, `reset_at`. So *how many*
  windows a quota has is fixed by the provider, and only their **length** is
  data. That is why windows are classified by length here and never by slot.
* `additional_rate_limits[]` **is** an array, and each element is
  self-describing: `limit_name` (display, carries the model version),
  `metered_feature` (stable key), and a full `rate_limit` of its own — meaning
  its own `allowed` and its own two windows.
* `credits` is a separate quota family (`has_credits`, `unlimited`, `balance`)
  that this app does not read at all.
* `rate_limit_reached_type` and `plan_type` are closed enums *with an explicit
  `unknown` catch-all variant*. The official client treats an unrecognised
  value as unknown rather than as a state — the same rule this app applies to a
  severity it does not know.

**The Claude Code CLI source.**
`src/services/api/usage.ts` calls `/api/oauth/usage` and types the answer as
`five_hour`, `seven_day`, `seven_day_oauth_apps`, `seven_day_opus`,
`seven_day_sonnet`, `extra_usage`. Two things worth keeping in mind: model
names are **baked into the type**, so a model Anthropic adds does not appear
until that file changes — which is the failure mode a `for_each` over the
response's own `limits[]` exists to avoid; and `extra_usage`
(`monthly_limit`, `used_credits`) is a *monthly* quota, so "a period we have no
name for" is not hypothetical.

**[uginy/keySwitcher](https://github.com/uginy/keySwitcher)** — the nearest
neighbour: a macOS menu-bar app with live quota monitoring for multiple Codex
accounts *and* Google Antigravity, in Swift/SwiftUI over a Python engine
(`engine/keyswitcher.py`, `engine/antigravity.py`). It reads the same Codex
endpoint this app does, and reaches Antigravity through
`cloudcode-pa.googleapis.com (loadCodeAssist)`, with tokens out of
`~/.codex/accounts/auth_*.json`, the macOS Keychain and SQLite. Reading it is
where three items in this project's backlog came from: that `rate_limit.allowed`
is the only hard "blocked" bit and was not being read; that a suspicious drop in
`used_percent` deserves a second request; and the shape of the Antigravity
credential problem — a token in a SQLite row, base64-wrapped, which is what
`[[surface.auth]]`'s planned `sqlite-row`/`base64`/`command` steps are for.

**[get-bb/bb](https://github.com/get-bb/bb)** — an agentic IDE (TypeScript,
Electron) that deliberately owns none of this: it "uses the provider CLI you
already have authenticated", names models by hand, and tracks no quotas at
all. Useful as the opposite pole: it shows what is left when a tool declines
to model limits — a fallback model and nothing to show the user about why the
first one stopped answering.

## Security

### Trust model

**Installing a manifest is trusting it, the same way installing a browser
extension or a Cargo crate is — this app does not, and cannot, sandbox a
manifest against its own author.** A manifest is plain, unsigned TOML; it
declares its own credential source *and* its own destination host, so nothing
in the schema stops a manifest that is deliberately hostile (not just
careless) from doing the following, with no confirmation dialog beyond
installing the plugin and, for an `opt_in` surface, ticking one checkbox:

- **Read any credential source it declares.** A `credentials-file` or `env`
  auth step reads silently — no OS prompt of any kind. A `keychain` step
  reading a *pre-existing* item another app created does trigger a macOS
  keychain-ACL prompt the first time (the OS, not this app, is asking "allow
  `tickover` to access this item?") — a real, if user-dismissible,
  speed bump; but a `service` name is just a string the manifest supplies, so
  this only helps if the user actually reads and declines that prompt.
- **Send whatever it read to any host it wants**, because the destination
  isn't fixed by this app — it's the manifest's own `[[http.request]].url`,
  and `allowed_hosts` is a list the *same* manifest also supplies (see
  [below](#what-allowed_hosts-does-and-doesnt-protect-against)). A manifest
  with `engine = "http-api"`, a `credentials-file`/`keychain` auth step, and
  `allowed_hosts = ["evil.example"]` exfiltrates whatever that credential
  store holds, to `evil.example`, by design, not by bypassing anything.
- **Do this automatically, with no request the user has to trigger.** Any
  surface with `opt_in = false` (the default) is fetched on its normal
  `refresh_secs` schedule starting right after the app launches — there is no
  "click to fetch" step standing between installing/enabling a hostile
  manifest and its first outbound request.
- **Run an arbitrary local command on a timer**, via `[ping]`'s `bin`/`args` —
  gated by the auto-ping toggle (`auto_ping_codex` / `auto_ping_claude` in
  `src/config.rs`), which defaults to **off**, so this one does require the
  user to opt in explicitly; once on, `bin` can be anything, not only the
  provider's own CLI.

None of this is a bug to fix in this app — it's what "the manifest folder is
the only source of truth for which providers exist" (above) necessarily
means once a manifest can name an arbitrary host and command. **The actual
mitigation is social, not technical: only install plugin manifests from
sources you trust**, the same way you'd vet a browser extension before
installing it. The manifests this app ships and seeds by default (`codex.toml`,
`claude.toml`, `grok.toml`, `antigravity.toml`, `copilot.toml` — see [Plugin
folder & seeding](#plugin-folder--seeding))
are trusted because they're reviewed and versioned in this repo; a manifest
you or someone else drops into the plugins folder afterwards is exactly as
trusted as whoever wrote it.

### What `allowed_hosts` does and doesn't protect against

`allowed_hosts` is real, but it is a guard against a *trusted* manifest's own
mistakes, not a sandbox against a hostile author — the manifest supplies both
the request URL and the list it's checked against, so an author who wants to
exfiltrate a credential simply writes a consistent `url` /
`allowed_hosts` pair naming their own host, and the check passes. A host is
read out of a URL by `url::Url` — the same parser `ureq` builds the request
through, not a hand-rolled split on the URL's punctuation, so what is checked
here is what the request actually dials — and every URL this app attaches a
credential to must be `https`, refused at load if it isn't. What it does buy
you, for a manifest you already trust:

- **Defense against a typo or a stale copy-paste.** If a future edit to
  `[[http.request]].url` (by you, or a well-meaning upstream manifest update)
  ever pointed at the wrong host by accident, the mismatch is caught and the
  request is refused rather than silently sent somewhere unintended.
- **Defense against an open redirect on the manifest's own declared
  endpoint.** The host check runs against the URL as written in the
  manifest, before any redirect, and the HTTP client does not follow
  redirects — so if the manifest's own declared host ever issued a 3xx to
  somewhere else (a misconfiguration on that service's side, not the
  manifest author's), the credential still can't leave via that redirect.

Reviewing a third-party manifest's `auth` steps against its
`[[http.request]].url` / `allowed_hosts` together is still worth doing before
installing it — but what you're checking is "does this manifest, read
honestly, send my credential somewhere I'd expect", not "can this manifest be
tricked into sending it somewhere it doesn't intend to". A manifest that
intends to exfiltrate reads exactly as consistent as one that doesn't.

### `[ping]` executes an arbitrary local binary

It's meant for a provider's own CLI (`codex exec hello`, `claude -p hello`),
but the manifest format doesn't restrict `bin`/`args` beyond that convention
— treat a plugin's `[ping]` section with the same scrutiny you'd give any
script you're about to let run automatically on a timer. It's gated by the
auto-ping toggle, off by default (see [Trust model](#trust-model) above), but
turning that toggle on for an untrusted manifest is exactly as risky as
running any other command that manifest could name.

`renews_token` is a second trigger for the same command — a lapsed auth chain
or an HTTP 401, not only a resting window — bounded by the same ten-minute
floor either way (see [Renewing a lapsed
token](#renewing-a-lapsed-token)); it names no new binary and reaches no new
scrutiny beyond what the toggle above already covers.

### Secrets aren't persisted or logged by this app

A resolved token lives in memory only for the duration of the request that
needs it; it is never logged, never written to disk by this app (it's only
ever *read* from a store something else — Keychain, the CLI's own
credentials file, Electron Safe Storage — already wrote), and the app's own
persisted config (`config.json`) never contains one. This is a real
guarantee about this app's own code paths — it says nothing about where a
manifest's *own* declared `[[http.request]].url` sends that token once
resolved, which is the manifest author's choice, not this app's (see
[Trust model](#trust-model)).

The manifest format has no code-execution surface of its own beyond
`[ping]` — everything else is declarative JSON-path reads through a fixed,
reviewed set of engines and credential-store readers. "Declarative" bounds
*how* a manifest can act, not *what* it's allowed to target.

The pair `[surface.auth.client]` discovers is a secret in exactly this same
sense, kept to the same rule: never logged, never written anywhere. It lives
in two process-only, in-memory caches (one keyed by the file it was found in,
one recording a miss) that die with the process, the same as the refresh
token cache above it in the chain.

## Full example: `codex.toml` (http-api)

Shipped verbatim as `plugins/codex.toml`. Up to version 1.0.0 this was
a `log-file` manifest reading `~/.codex/sessions/**/rollout-*.jsonl`; the
comments below say why it isn't any more.

```toml
# Built-in plugin manifest — OpenAI Codex CLI.
#
# Codex usage is read from the same endpoint the Codex CLI itself calls,
# `chatgpt.com/backend-api/wham/usage`, with the CLI's own credentials. It is
# unofficial and undocumented — if its shape changes, update this file, not
# Rust code.
#
# Until version 2.0.0 this read `~/.codex/sessions/**/rollout-*.jsonl` instead,
# via `engine = "log-file"`. Two reasons that had to go:
#
#   * A log says what the last session wrote, not what is true now. Leave Codex
#     unused for a day and the panel quietly shows yesterday.
#   * A log line carries no identity. It names a plan tier and nothing else, so
#     an account's address had to be *guessed* from a remembered "tier ->
#     address" map — a guess that once deleted a live account's row as a
#     duplicate of itself. The API answers with `email` and `account_id` in the
#     response, so there is nothing left to guess.
#
# A third reason showed up while writing this: rollout logs interleave quota
# families. A `codex exec` run writes a `rate_limits` container for the
# GPT-5.3-Codex-Spark limit, which the log reader — newest line wins — showed
# as *the* Codex quota. The panel read 0% used while the real weekly window sat
# at 69%. Here, the main quota is `rate_limit` and the side quotas are
# elsewhere (see `additional_rate_limits` below), so they cannot be confused.
#
# The log-file engine itself stays: it is a general mechanism any third-party
# manifest can use, and `docs/PLUGIN-ARCHITECTURE.md` specifies it.

id           = "codex"
name         = "Codex"
menu_label   = "Cx"
order        = 10
# `required` below needs a reader that knows a window can be absent rather than
# blank; `[[windows]] id` needs one that keys a window by identity rather than
# by position; `[status]` needs one that reads the quota's own standing. See
# docs/PLUGIN-ARCHITECTURE.md, "Reader capabilities".
requires_reader = ["window-presence", "window-identity", "reading-status", "reading-balances"]
version      = "2.5.1"
engine       = "http-api"
# One request a minute, matching Claude. The log-file reader polled every 15s
# because re-reading a local file is free; four requests a minute at somebody
# else's undocumented endpoint, forever, is not. Nothing here needs to be
# fresher: the shortest window Codex reports is five hours, so a minute-old
# figure is at worst 0.3% of a window stale.
refresh_secs = 60

# What Codex says about the quota itself, above its windows.
#
# This is not a nicer way of reading the windows: `allowed` and `limit_reached`
# are required fields of `rate_limit` in Codex's own schema, while both window
# slots are optional. So a blocked account with nothing running answers with a
# status and no windows at all — and presence (correctly) emits no row for a
# window nobody reported, which would leave the panel showing an account with
# nothing wrong with it at the one moment something is.
#
# `rate_limit_reached_type` sits at the root rather than inside `rate_limit`,
# and names its kind in a nested `type`.
[status]
allowed_path       = "rate_limit.allowed"
limit_reached_path = "rate_limit.limit_reached"
reached_type_path  = "rate_limit_reached_type.type"

# The plan chip next to "Codex" ("PRO", …), read from the usage response.
[tag]
from      = "field"
path      = "plan_type"
transform = "uppercase"

# Account email. The usage response already carries it, so this costs no
# request at all (unlike Claude, whose usage and profile live at separate
# endpoints).
[account]
type      = "response-field"
json_path = "email"

# 5-hour window. Codex does not fix slot order: when the 5-hour window has
# nothing to report it sends the *weekly* window as `primary_window` with
# `secondary_window` null — observed live, and the reason both windows list
# both slots as candidates and are told apart by `limit_window_seconds` rather
# than by position. Windows up to 720 minutes are the short slot, from 721 the
# weekly one — the same split the log-file manifest used.
#
# Deliberately not `required`: this window is legitimately absent. A plan with
# no 5-hour allowance reports none, and an empty one stops being reported at
# all until something is spent — the state the auto-ping exists to end. Marking
# it required would call both of those a broken response.
[[windows]]
# Identity, and deliberately not the label: a caption may be reworded, and this
# string is a segment of a key in the user's config.
id    = "codex-5h"
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
resets_at_format   = "unix"
max_period_minutes = 720

# Weekly window, same pair of candidates, the other side of the split.
#
# Also not `required`, for the same reason as the 5-hour window above and one
# more. A weekly window resets too, and this provider is the one observed to
# stop reporting a window while it is empty — so an account in the hours after
# its weekly reset may well send neither. Marking this required would turn that
# into an error covering the whole provider, hiding the 5-hour figure that did
# arrive and silencing the auto-ping for as long as it lasted. With neither
# window `required`, a body with two empty slots and a body whose keys have
# been renamed read the same here — an account with nothing to show, not an
# error. That is the deliberate price of not refusing the empty state, and
# `[status]` (`allowed` / `limit_reached`) is what still speaks for a blocked
# account in that case.
[[windows]]
id    = "codex-wk"
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
resets_at_format   = "unix"
min_period_minutes = 721

# A per-model allowance, from the same response — no extra request. Codex
# reports these in `additional_rate_limits[]`, an array whose order it does not
# fix and adds to over time, so this names the one it wants rather than
# counting: `[limit_name=…]` selects the element that calls itself that. If
# Codex renames or withdraws the model, nothing matches and this row simply
# does not appear.
#
# `role = "extra"` is what keeps it out of the way. Only `primary` and
# `secondary` fill the 5H/WK slots and reach the menu-bar pill; an extra quota
# is a row in the panel and nothing else. That separation is the whole reason
# this is safe to show: reading a model-specific quota as *the* Codex quota is
# the bug that had the panel saying 0% while the real weekly window sat at 69%.
#
# The response also carries `code_review_rate_limit`, `credits` and
# `spend_control`. Same mechanism if they are ever worth a row.
[[windows]]
id    = "codex-spark"
label = "GPT-5.3-Codex-Spark"
role  = "extra"
[windows.period]
mode  = "from_field"
field = "limit_window_seconds"
unit  = "seconds"
[windows.source]
# Both slots, for the same reason the subscription windows list both: Codex
# does not fix which one a window arrives in, and a model allowance that moved
# to the other slot would simply stop being reported.
containers = [
  "additional_rate_limits[limit_name=GPT-5.3-Codex-Spark].rate_limit.primary_window",
  "additional_rate_limits[limit_name=GPT-5.3-Codex-Spark].rate_limit.secondary_window",
]
used_percent_path = "used_percent"
resets_at_path    = "reset_at"
resets_at_format  = "unix"

# Credits — what is left to work with once the subscription quota is spent.
#
# This is the state the panel was blind to: when `rate_limit` is exhausted, the
# question "can I still work" is answered by `credits`, not by a window, and a
# panel showing a full quota bar said nothing about it. Codex answers the same
# request that carries the windows, so this costs no extra call.
#
# `kind = "text"` is not a shortcut. Codex's own schema types this field as a
# string (`CreditStatusDetails.balance`, `Option<Option<String>>` in
# codex-backend-openapi-models), so it is the provider's own wording — read it,
# sanitise it, print it. Parsing a number back out of it would mean deciding
# what its currency and scale are, which the response does not say.
#
# What is deliberately NOT read here, though the live response carries it:
# `spend_control.individual_limit` and `rate_limit_reset_credits.*` are absent
# from the vendored schema, so their meaning would be a reading of their names
# rather than something a contract states — and a figure this app cannot
# explain has no business on a panel about limits. Neither is `has_credits`:
# whether an account is cut off already arrives through `[status]` above
# (`rate_limit_reached_type` has `workspace_owner_credits_depleted` in its
# vocabulary), and saying it twice is the repetition the balance level was
# told not to add.
#
# No period end: Codex states none for credits, and a calendar period this app
# invented would be a date nobody promised.
[[balances]]
id    = "codex-credits"
label = "Credits"
[balances.remaining]
kind = "text"
path = "credits.balance"

[http]
# Pacing. `refresh_secs` above only paces the timer; the panel opening, the
# Refresh button, "Refresh now" and app start all fetch too. 55s sits just
# below the 60s cadence so a scheduled refresh is never the thing that gets
# throttled, while a user clicking Refresh repeatedly gets the cached reading.
# See `src/plugin/throttle.rs`.
min_interval_secs  = 55
backoff_start_secs = 60
backoff_max_secs   = 900

[[http.request]]
url          = "https://chatgpt.com/backend-api/wham/usage"
# Well above the ~0.6s observed, well below the one-minute cadence.
timeout_secs = 10
[http.request.headers]
Authorization        = "Bearer {token}"
# Which ChatGPT account the token speaks for. The endpoint needs it as a
# header, hence [[http.value]] below.
"chatgpt-account-id" = "{value.account_id}"
# What the Codex CLI itself sends. The endpoint is the CLI's, and identifying
# as something else invites being treated as something else.
originator           = "codex_cli_rs"
Accept               = "application/json"

# The account id for the header above, read out of the CLI's own credentials
# file. `tokens.account_id` is written there in plain sight; the same value is
# also a claim inside `tokens.id_token`, but reading the plain field means one
# less thing that breaks if the CLI stops storing an id token it does not need.
[[http.value]]
name      = "account_id"
type      = "json-file"
path      = "~/.codex/auth.json"
json_path = "tokens.account_id"

# One surface, deliberately named "default": that keeps this provider's reading
# id "codex" (rather than "codex-cli"), which is what config keys, the menu-bar
# pill and the auto-ping already refer to, and keeps the chip above showing the
# plan rather than a surface label.
[[surface]]
id            = "default"
label         = "Default"
opt_in        = false
in_menu_bar   = true
allowed_hosts = ["chatgpt.com"]
# Shown instead of hiding the provider outright when no credentials are found
# at all — an installed-but-not-signed-in Codex used to say so, and should
# still.
no_credentials_message = "Not signed in — run: codex login"

# Signed in with an API key rather than a ChatGPT account: there is no
# subscription behind it and therefore no window to report. Say that instead of
# leaving a blank row. This step is first because a credentials file that
# exists without a token stops the chain on its own — `unless_json_path` keeps
# it from firing for an account that does have a token.
[[surface.auth]]
type             = "reject-when"
path             = "~/.codex/auth.json"
json_path        = "OPENAI_API_KEY"
unless_json_path = "tokens.access_token"
message          = "API-key sign-in has no subscription limits"

# The bearer token: the CLI's own OAuth access token, read but never renewed.
# Refreshing it would hand back a new refresh token and invalidate the copy the
# Codex CLI is holding — this app would be logging the user's CLI out to draw a
# progress bar. An expired token stops the polling until the user signs in
# again (see `src/plugin/throttle.rs`).
[[surface.auth]]
type            = "credentials-file"
path            = "~/.codex/auth.json"
token_json_path = "tokens.access_token"

# `codex exec hello` — run while the 5-hour window sits empty, to start a
# fresh one (src/main.rs `ping_due` / `send_ping`, gated by
# `config::auto_ping_codex`).
#
# `--skip-git-repo-check` is not optional here. Without it `codex exec` refuses
# to start outside a git repository at all: "Not inside a trusted directory and
# --skip-git-repo-check was not specified." — exit 1, before any request. Its
# output was discarded, so up to version 2.1.0 this feature failed silently
# every single time.
#
# What that flag gives up is bounded elsewhere rather than here. The app runs
# the ping in an empty directory it owns (`main.rs::ping_cwd`), not in $HOME,
# so this unattended model run reads no `AGENTS.md` of the user's as
# instructions. `--sandbox read-only` is the other half: whatever the user's
# own `~/.codex/config.toml` sets for their interactive work, a run nobody is
# watching cannot write to disk.
[ping]
bin  = "codex"
args = ["exec", "--skip-git-repo-check", "--sandbox", "read-only", "hello"]
```

### When an upgrade replaces an installed manifest

Manifests live on disk (`<config dir>/tickover/plugins/`) and the copy
there wins. An upgrade (`plugin::seed::BUILTIN_UPGRADES`) replaces one only
when it is byte-identical to something this app shipped before (sha256), and
it makes that decision once per shipped version, recording it in `config.json`
(`plugin.<id>.builtin_migrated`). Edit a built-in and it is yours: the upgrade
records the decision and leaves the file alone.

That marker is load-bearing, not bookkeeping. Restoring an earlier built-in by
hand produces a file that *is* byte-identical to something this app shipped —
indistinguishable, by hash alone, from an install that never migrated. Without
the marker the next launch would replace it again and quietly undo what the
user just did; with it, the decision was already made once and stands. "Reset plugins" in Settings *does* overwrite it
with the current built-in — that is what it is for.

Writing a `log-file` manifest is still entirely possible — the engine is a
general mechanism and this document specifies it — but no shipped manifest
uses it, and no copy of the retired Codex one is kept in the tree.

## Full example: `claude.toml` (http-api, two surfaces)

Shipped verbatim as `plugins/claude.toml`.

```toml
# Built-in plugin manifest — Claude Code CLI + Claude desktop app.
#
# Claude's quota is read from the `/api/oauth/usage` endpoint. It is
# unofficial and undocumented — if Anthropic changes its shape, update this
# file, not Rust code.

id           = "claude"
name         = "Claude"
menu_label   = "Cl"
order        = 20
# `required` below needs a reader that knows a window can be absent rather than
# blank; `keychain-expiry` is what lets the auth steps below tell a stale
# token from a working one — see docs/PLUGIN-ARCHITECTURE.md, "Reader
# capabilities".
requires_reader = ["window-presence", "window-identity", "for-each-windows", "keychain-expiry"]
version      = "1.4.3"
engine       = "http-api"
# Re-fetched every 60 s.
refresh_secs = 60

# Claude reports no window lengths of its own, so the nominal periods (5h =
# 300 min, weekly = 10080 min) are assumed here. This is the mirror image of
# Codex, whose windows carry their own `window_minutes`.
# Both windows are `required`: Anthropic reports both for every account, so a
# response missing one has changed shape under us. That is worth saying out
# loud — the alternative is a panel drawing whichever half still parsed, where
# a missing row is indistinguishable from a quota nothing has been spent
# against.
[[windows]]
id       = "claude-5h"
label    = "5H"
role     = "primary"
required = true
[windows.period]
mode    = "assumed"
assumed = 300
[windows.source]
used_percent_path = "five_hour.utilization"
resets_at_path    = "five_hour.resets_at"
resets_at_format  = "iso8601"

[[windows]]
id       = "claude-wk"
label    = "WK"
role     = "secondary"
required = true
[windows.period]
mode    = "assumed"
assumed = 10080
[windows.source]
used_percent_path = "seven_day.utilization"
resets_at_path    = "seven_day.resets_at"
resets_at_format  = "iso8601"

# The third kind of window Anthropic reports, and the one no fixed entry can
# describe: a weekly allowance scoped to a single model. It does not live in a
# field of its own — `seven_day_opus` and friends are present in the response
# and null — but inside the `limits[]` array, as an element whose `kind` says
# `weekly_scoped` and whose `scope.model.display_name` names the model. On the
# account this was measured against there is one such element, for Fable,
# which Anthropic's own usage page draws.
#
# So this entry enumerates rather than points at a fixed path (`for_each`):
#  * `limits[]` also carries the session and weekly-all windows — the two the
#    fixed entries above already draw from `five_hour`/`seven_day` — so the
#    filter is what keeps this from drawing them a second time under a
#    different caption. Its `kind` is the provider's own word for the
#    distinction.
#  * the caption comes from the element, because a per-model row that cannot
#    say which model is worse than no row (`label`'s own docs carry the
#    exception; the text is sanitised on the way in like any provider string).
#  * `role = "extra"` keeps it out of the menu bar and out of the 5H/WK slots,
#    and makes the panel title it by the manifest's caption instead of by its
#    length — otherwise a per-model weekly row would sit under the
#    subscription's weekly row saying the same two words about a different
#    number (`window_title_of` in src/main.rs).
#  * the identity is the model's *display name*, and that is a compromise worth
#    stating: `scope.model.id` exists in the response and is null on the account
#    this was measured against, so keying on it would resolve to nothing and
#    draw no row at all. A display name is a caption Anthropic may reword, and
#    the day it does, the row's registry entry is orphaned and comes back as a
#    new row. Switch this to `scope.model.id` the moment that field is filled.
#  * not `required`: an account whose plan scopes nothing reports no such
#    element, and that is a plan without the limit rather than a response that
#    changed shape.
[[windows]]
id              = "claude-wk-model"
label           = "{scope.model.display_name} weekly"
role            = "extra"
for_each        = "limits"
for_each_where  = "kind=weekly_scoped"
element_id_path = "scope.model.display_name"
[windows.period]
mode    = "assumed"
assumed = 10080
[windows.source]
used_percent_path = "percent"
resets_at_path    = "resets_at"
resets_at_format  = "iso8601"

# GET .../oauth/usage with the OAuth bearer token, the `oauth-2025-04-20` beta
# header, and a `claude-code/<version>` User-Agent (required — Anthropic 429s
# aggressively without it).
[http]
[[http.request]]
url          = "https://api.anthropic.com/api/oauth/usage"
timeout_secs = 8
[http.request.headers]
Authorization    = "Bearer {token}"
"anthropic-beta" = "oauth-2025-04-20"
"User-Agent"     = "claude-code/{version}"

# `{version}` substitution reads the installed CLI's own package.json,
# falling back to a recent constant.
#
# The third is Windows: npm's global prefix is per-user there, under %APPDATA%
# rather than a system directory. Spelled `~/AppData/Roaming` rather than
# `{config_dir}` so the path says which platform it is for — `{config_dir}` is
# ~/Library/Application Support on macOS, where it could never match anything.
# A winget install has no package.json at all (it ships one self-contained
# .exe), so that one takes the fallback below — which is what a fallback is
# for, and costs only a slightly stale version in a User-Agent.
[http.version]
files = [
    "/usr/local/lib/node_modules/@anthropic-ai/claude-code/package.json",
    "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/package.json",
    "~/AppData/Roaming/npm/node_modules/@anthropic-ai/claude-code/package.json",
]
json_path = "version"
fallback  = "2.1.78"

# Account email — GET .../oauth/profile with the same headers/auth as [http],
# then `account.email` in the response body.
[account]
type      = "http"
url       = "https://api.anthropic.com/api/oauth/profile"
json_path = "account.email"

# CLI surface — always on.
[[surface]]
id            = "cli"
label         = "CLI"
opt_in        = false
in_menu_bar   = true
allowed_hosts = ["api.anthropic.com"]

# Plaintext credentials file first, then the OS secure store per platform.
# Every step decodes the same JSON shape, hence the same `token_json_path`
# fallback throughout: nested
# `claudeAiOauth.accessToken`/`claudeAiOauth.access_token`, else flat
# `accessToken`/`access_token` at the root.
[[surface.auth]]
type             = "credentials-file"
path             = "~/.claude/.credentials.json"
token_json_path  = "claudeAiOauth.accessToken|claudeAiOauth.access_token|accessToken|access_token"
# expiresAt is epoch milliseconds.
expiry_json_path = "claudeAiOauth.expiresAt"

[[surface.auth]]
type             = "keychain"
service          = "Claude Code-credentials"
token_json_path  = "claudeAiOauth.accessToken|claudeAiOauth.access_token|accessToken|access_token"
# expiresAt is epoch milliseconds.
expiry_json_path = "claudeAiOauth.expiresAt"

[[surface.auth]]
type             = "win-credential"
targets          = ["Claude Code-credentials", "Claude Code"]
token_json_path  = "claudeAiOauth.accessToken|claudeAiOauth.access_token|accessToken|access_token"
# expiresAt is epoch milliseconds.
expiry_json_path = "claudeAiOauth.expiresAt"

# Desktop surface — opt-in (its token needs a one-time Keychain/DPAPI grant),
# popup-only (`in_menu_bar = false`).
[[surface]]
id            = "desktop"
label         = "Desktop"
opt_in        = true
in_menu_bar   = false
allowed_hosts = ["api.anthropic.com"]

# `{config_dir}/Claude/config.json` → `oauth:tokenCacheV2` (falling back to
# `oauth:tokenCache`) → an Electron Safe Storage blob, decrypted via the macOS
# Keychain key "Claude Safe Storage" (or Windows DPAPI, which needs no
# manifest field). The decrypted payload is the same `claudeAiOauth`-wrapped
# shape as the CLI's, hence the same `token_json_path` fallback.
[[surface.auth]]
type               = "electron-safe-storage"
config_path        = "{config_dir}/Claude/config.json"
blob_json_path     = "oauth:tokenCacheV2|oauth:tokenCache"
token_json_path    = "claudeAiOauth.accessToken|claudeAiOauth.access_token|accessToken|access_token"
macos_keychain_key = "Claude Safe Storage"

# `claude -p hello` — run while the 5-hour window sits empty, to start a
# fresh one (src/main.rs `ping_due` / `send_ping`, gated by
# `config::auto_ping_claude`).
[ping]
bin  = "claude"
args = ["-p", "hello"]
# The CLI renews its own token only when it runs.
renews_token = true
```

## Registry

The registry lets the user discover and install/update manifests from a
git-hosted `index.toml`, without this app baking in a fixed list of known
providers. The default
registry is this repository's own [`plugins/index.toml`](../plugins/index.toml),
read over raw HTTPS from `main` (`DEFAULT_REGISTRY_URL` in `src/main.rs`);
it lists the five shipped manifests, so *Check updates* can deliver a
manifest fix between releases, and `tests/registry_index.rs` fails the
suite if a manifest changes without its index entry. The format is not
specific to that location — any repository whose root holds an
`index.toml` of this shape is a registry. All the pure logic — parsing/validating `index.toml`, resolving
a relative manifest path against the index's own URL, semver comparison,
sha256 verification, the on-disk lockfile, and the installed-vs-registry
state machine — lives in
[`src/plugin/registry.rs`](../src/plugin/registry.rs) and is unit-tested
with zero network access.

**Source of truth, same rule as the manifest schema above:** if anything
below and `registry.rs` ever disagree, `registry.rs` wins. The **only**
network calls in that module are `fetch_text` (the index) and `fetch_bytes`
(a manifest, as raw bytes); everything downstream of a
download — writing the verified bytes to disk, driving the trust-
disclosure UI, enforcing the mandatory approval gate, calling the clock
for `installed_at` — is orchestration `registry.rs` deliberately leaves to
its caller (`src/main.rs`). `registry.rs` never writes a plugin manifest
to disk itself. Where this section describes that caller-side behavior,
it's bounded to the contract `registry.rs`'s own doc comments make about
what the caller does with its return values — the settings-sheet UI
itself is out of scope for this document.

### `index.toml` format

A registry is a directory in a plain git repository that holds `index.toml`
beside (or above) the manifests it lists, consumed over raw HTTPS (e.g. a
`raw.githubusercontent.com`-style URL) — this app never clones the
repository. In the shipped index the manifests sit next to it, so each
`manifest` path is a bare file name:

```toml
schema_version = 1                               # optional, default 1

[[plugin]]
id          = "some-provider"                    # ^[A-Za-z0-9_-]+$
name        = "Some Provider"
version     = "1.0.0"                             # non-empty
description = "Some Provider usage indicator"     # optional
manifest    = "manifests/some-provider.toml"      # relative, no scheme, no ..
sha256      = "…"                                 # 64 lowercase hex chars
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `schema_version` | integer | no, default `1` | reserved for a future incompatible schema change; not currently branched on by this reader |
| `[[plugin]]` | array of tables | no, default empty | every plugin the registry publishes; an index with zero entries is valid, and one listing more than 500 (`MAX_INDEX_ENTRIES`) is rejected wholesale, the same as any other malformed index — no real registry comes close, but a 10 MiB index paid for in short ids rather than useful content could otherwise still hand the UI thread on the order of a hundred thousand rows to sort, diff and draw |

Per `[[plugin]]` entry:

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | string | yes | same charset rule as a manifest's own `id` (`^[A-Za-z0-9_-]+$`, see [Top-level fields](#top-level-fields)) — it becomes the installed manifest's `<id>.toml` filename stem |
| `name` | string | yes | display name; must not be blank |
| `version` | string | yes | must not be blank; compared with `version_cmp` (see [Installed-vs-registry state machine](#installed-vs-registry-state-machine)) |
| `description` | string | no | one-line description shown before install |
| `manifest` | string | yes | path to the manifest file, **relative to the index's own directory** — never a full URL (resolved by `resolve_manifest_url`, see [Install / update process](#install--update-process)) |
| `sha256` | string | yes | expected sha256 of the manifest file's raw bytes — exactly 64 **lowercase** hex characters |

Like [`PluginManifest`](#manifest-format), `RegistryIndex` doesn't use
`#[serde(deny_unknown_fields)]` — an unrecognized top-level or per-entry
field is ignored, not rejected, so a registry can publish an index newer
than this build understands without breaking it.

`RegistryIndex::from_str` parses, then validates the whole index at once —
a malformed or dishonest index is **rejected wholesale**, not partially
trusted:

- `id`: non-blank, restricted to `[A-Za-z0-9_-]+` — same rule, and the
  same reason, as a manifest's own `id`: it becomes a filename.
- `name` / `version`: non-blank.
- `sha256`: exactly 64 characters, every one a lowercase hex digit;
  uppercase is **rejected outright, not normalized**, keeping every
  stored/compared hash in one canonical form.
- `manifest`: rejected if it contains a URL scheme (`://`), starts with a
  path separator (an absolute path), or has any `..` path component
  (directory traversal). This is what closes off a compromised index
  pointing the installer at a manifest hosted on a different host, or at a
  file outside the registry's own tree.
- `id` must be unique across the index; a duplicate id fails the whole
  parse.

### Manifest `version` field

Every plugin manifest now carries an optional top-level `version` field
(`#[serde(default)]`, defaulting to `""`) — free-form text, compared with
a small hand-rolled SemVer-style ordering: the `major.minor.patch` base is
compared numerically, a build-metadata suffix (`+…`) is ignored, and a
pre-release suffix (`-…`) sorts *below* the same base without one
(`1.0.0-alpha` < `1.0.0`), pre-release identifiers compared dot-segment by
dot-segment (numeric segments numerically). If either side doesn't parse
that way it falls back to a plain string compare, so the comparison is
always total and never panics. Defaulting to an **empty string, not
`Option<String>`**, keeps registry comparisons unwrap-free: a manifest
predating the registry (no `version` field at all) still parses exactly
as before, and its blank version simply loses every comparison it's
involved in — see the no-lockfile branch of the
[state machine](#installed-vs-registry-state-machine) below — rather than
needing special-casing.

### Publisher signature

The index is signed, and the signature is checked **before the index is
parsed**. This is a different question from the per-manifest `sha256`: that
hash arrives in the same `index.toml` as the link it describes, from the same
host, so it proves the manifest bytes were not altered in transit and says
nothing whatever about who served them. Anyone able to serve a different
`index.toml` serves matching hashes with it.

- **Format:** [minisign](https://jedisct1.github.io/minisign/), detached, at
  the index's own URL with `.minisig` appended — which is where
  `minisign -Sm index.toml` writes it. Both signatures in the file are
  verified, the one over the index and the one over the trusted comment;
  unverified, a "trusted" comment is exactly as forgeable as an untrusted one.
- **Algorithm:** both of minisign's — `Ed` over the file, `ED` over a
  Blake2b-512 hash of it. Which one the signing tool writes depends on its
  version and its flags, and a publisher whose correct signature was refused
  by name would have no way to tell that from a compromised index.
- **The index is fetched as bytes, not text.** A signature is over the bytes a
  server sent; verifying a decoded form would check a signature over something
  the publisher never signed. The decode happens after verification, and a body
  that is not UTF-8 is refused there.
- **A missing signature and an unfetchable one are different answers.** A 404
  is the registry saying it publishes none — with a key pinned, a refusal.
  Any other fetch failure is reported as the network error it is, so nobody
  who can drop a single request can make an honest registry look corrupt.
- **Key:** ed25519, public half compiled into the binary
  (`plugin::signature::REGISTRY_PUBLIC_KEY`). The verification is `ring`'s,
  which was already linked in through `ureq`'s TLS, so this adds no new
  cryptographic code to the build.
- **Policy:** with a key pinned, an index carrying no valid signature by that
  key is refused outright — not warned about. A trust dialog can be clicked
  through; this cannot.
- **Until a key is pinned** the constant is `None`, verification is impossible,
  and the code says so in its own type (`Verification::Unverifiable`, which a
  caller must handle separately from `Signed`) and on stderr at every check.
  A security check that is switched off is only safe while it is visible that
  it is switched off.

Signing is not a substitute for anything downstream. The per-manifest
`sha256`, the entry-id/manifest-id match, `allowed_hosts`, the refusal to
write through a symlink and the trust dialog all still happen, unchanged and
afterwards.

### Transport

- **HTTPS-only.** A plain `http://` URL is refused before any connection
  is attempted — the registry's entire trust story rests on verified
  sha256 *and* a non-tampered transport, so plaintext isn't an option even
  for a read-only index fetch.
- **No redirects** (`ureq::AgentBuilder::redirects(0)`) — a `3xx` response
  is treated as an error rather than followed, so a compromised or
  misconfigured CDN in front of the registry can't silently hand back
  content from a different host than the one the user actually approved.
- **~8 second timeout** per request — the same default as a plugin's own
  `[[http.request]]` (`timeout_secs`).

`fetch_text` itself is transport-agnostic: it takes whatever URL it's
given and doesn't hardcode a registry location — that's app-level wiring,
not this module's concern. The app is expected to point Settings' manual
**"Check updates"** button at exactly one official default registry URL
(a `DEFAULT_REGISTRY_URL` constant belongs in `src/main.rs` — caller-side
wiring, not part of `registry.rs`). There is no autoscan of third-party
registries, no automatic downloading, and no background polling: **"Check
updates" is a manual, user-triggered action**, not something that runs on
`refresh_secs` or on app launch — the same "no automatic downloading,
ever" rule the rest of this document already applies to `[ping]` and to
opt-in surfaces.

### Install / update process

`registry.rs` provides the verification primitives; the caller
(`src/main.rs`) sequences them and performs the actual filesystem write.
The contract the module's own doc comments make with that caller:

1. Fetch `index.toml` via `fetch_text`, parse it with
   `RegistryIndex::from_str`.
2. For a plugin the user chooses to install or update, resolve its
   `manifest` path against the index's own URL with
   `resolve_manifest_url`: it strips a trailing `index.toml` off the base
   URL (or just the trailing slash) and appends the relative path, then
   re-checks that the resolved URL's host still matches the index's own
   host as a second, independent guard against a hostile relative path —
   belt-and-braces, since a path that's already been validated as relative
   (no scheme, no leading separator) can't actually change host through
   string concatenation alone, but this is the one place that would notice
   if it somehow did.
3. Fetch the manifest's raw bytes from that resolved URL via `fetch_bytes`
   (raw `Vec<u8>`, **not** the UTF-8-decoding `fetch_text` used for the
   index — the hash must be over the exact transport bytes, and the reader
   is capped at 10 MB before buffering so a hostile unbounded response
   can't exhaust memory before the hash gate runs).
4. Call `verify_and_prepare` with those exact bytes and the index entry's
   `sha256`: it hashes the bytes and compares against the expected hash
   **before ever attempting to parse**, then — only on a match — parses
   the bytes as a `PluginManifest`, purely as a gate ("does this even
   parse"), not as the source of what gets written to disk. A hash
   mismatch is rejected before parsing is even attempted.
4b. Reject the install if the parsed manifest's `id` doesn't equal the
   index entry's `id` the user clicked. A registry is trusted, but this
   catches an honest-but-mistaken index (or a swapped file) before anything
   is written — the install/update always targets the clicked id, never the
   id the downloaded file happens to declare.
5. Run `analyze_trust` on the parsed manifest and show the caller's
   trust-disclosure UI, blocking on the mandatory approval gate when it
   applies — see [Registry trust model](#registry-trust-model) below.
6. **Write the original, unmodified raw bytes to disk — never a
   re-serialization of the parsed `PluginManifest`.** TOML
   re-serialization isn't guaranteed byte-identical to the source, and the
   entire point of verifying sha256 is that the bytes that land on disk
   are the exact bytes that were hashed; writing anything else would
   silently break every later "is this pristine" check (see the
   [state machine](#installed-vs-registry-state-machine) below, which
   hashes the on-disk file the same way).
7. Record the plugin's provenance in the lockfile — `origin_registry_url`,
   `origin_version`, the hash `verify_and_prepare` returned, and
   `installed_at` (the caller's clock; `registry.rs` never reads it) — via
   `RegistryLockState::set` and `save_lockfile`. See
   [Lockfile](#lockfile-registry-statejson) below.

This is a fetch → verify → disclose → write sequence, always triggered by
an explicit per-plugin user approval; nothing in it runs on a timer or at
app launch.

### Lockfile (`registry-state.json`)

The registry's provenance record lives at
`<config-dir>/tickover/registry-state.json` — **outside** the
`<config-dir>/tickover/plugins/` folder, deliberately: that folder is
non-recursively globbed for `*.toml` by `manifest::load_dir` and reseeded
by the plugin-seeding step (see
[Plugin folder & seeding](#plugin-folder--seeding)), so a JSON lockfile
sitting next to the manifests would either be silently ignored today
(wrong extension) or, worse, invite a future change to accidentally treat
it as plugin data. Keeping it in the parent `tickover` directory — the
same base directory `config.json` already lives in — sidesteps that
entirely.

Shape (`RegistryLockState`):

```json
{
  "plugins": {
    "<id>": {
      "origin_registry_url": "https://raw.githubusercontent.com/.../index.toml",
      "origin_version": "1.0.0",
      "origin_sha256": "e3b0c4...",
      "installed_at": 1800000000
    }
  }
}
```

| Field | Notes |
|---|---|
| `origin_registry_url` | the index URL this plugin was installed/updated from |
| `origin_version` | the registry `version` at install/update time |
| `origin_sha256` | sha256 of the exact bytes written to disk at install/update time |
| `installed_at` | Unix seconds, set by the caller — `registry.rs` never reads the clock |

Loading is best-effort, matching `crate::config`'s own `load`: a missing
file, an unreadable file, or corrupt JSON all quietly resolve to an empty
`RegistryLockState` rather than an error, so a missing/corrupt lockfile
never blocks reading or installing plugins — it only degrades the "was
this locally modified" check below to the no-record branch.

The lockfile's whole role is **provenance for the diff, not enforcement**:
it's what lets the state machine below tell "the registry published a new
version and the local file is untouched" apart from "the user hand-edited
this file since it was installed" — a distinction a bare version number
alone can't make.

### Installed-vs-registry state machine

`diff_installed` compares every plugin the index lists against what's
actually on disk and returns one `RegistryPluginState` per index entry
(`New` / `UpToDate` / `UpdateAvailable`), driving the "Check updates" UI.
**sha256 is the ground truth the decision is made on; `version` is
display-only**, except in the one branch below with no provenance at all,
where it's the best-effort fallback.

The caller supplies, for every plugin manifest currently on disk,
`(id, current_file_sha256, installed_version)`. **`current_file_sha256`
must be the sha256 of the manifest file's raw on-disk bytes**
(`std::fs::read`, never `read_to_string` followed by a round-trip through
`PluginManifest`/`toml::to_string`) — the same byte-exactness the write
side requires (above): hashing a re-serialized manifest would almost
never match `origin_sha256`, making every installed plugin spuriously
look locally-modified/unsafe-to-overwrite. A manifest file on disk whose
id isn't in the index is never visited — the index drives iteration, not
the disk.

Per plugin, the decision looks up a lockfile record and then, if one
exists, compares two independent sha256 equalities: does the local file's
hash still match `origin_sha256` (`local_matches_origin`), and does the
index's *current* `sha256` still match `origin_sha256`
(`index_matches_origin`):

| local file | lockfile record | local == origin | index == origin | state |
|---|---|---|---|---|
| absent | — | — | — | `New` — offer install |
| present | yes | yes | yes | `UpToDate { locally_modified: false }` — nothing to do |
| present | yes | yes | no | `UpdateAvailable { overwrite_safe: true, warning: None }` — the registry moved, the local file is still pristine, safe to overwrite |
| present | yes | no | yes | `UpToDate { locally_modified: true }` — the user edited the file; the registry hasn't changed, so there's nothing to offer an update to |
| present | yes | no | no | `UpdateAvailable { overwrite_safe: false, warning: Some(...) }` — both the local file and the registry have diverged from the recorded origin; updating would overwrite the user's edits |
| present | **no** | — | best-effort: `update_available(installed_version, entry.version)` | `UpdateAvailable { overwrite_safe: false, warning: Some(...) }` if the index version is newer, else `UpToDate { locally_modified: false }` |

Two things the table alone doesn't make obvious:

- **The no-lockfile row never returns `overwrite_safe: true`.** A plugin
  with no install record (installed before the registry existed, or
  hand-dropped into the plugins folder) has no proof either way about
  local edits, so *whenever* it does offer an update, that update is
  always flagged unsafe-with-a-warning — it isn't that this row always
  warns unconditionally: a same-or-older version still resolves quietly to
  `UpToDate { locally_modified: false }`, with no update offered and no
  warning shown.
- **`locally_modified: false` means "no evidence of local edits found,"
  not "provably pristine."** It's the value for both the genuinely
  provenance-backed pristine case (row 2) and the no-lockfile case where
  the file's origin is simply unknown — that's the strongest claim that
  can honestly be made without a hash to compare against, not a stronger
  guarantee.

### Registry trust model

**The registry does not change the [trust model](#trust-model) above — it
changes how a manifest is *discovered and downloaded*, not how much it's
*reviewed*.** `sha256` in `index.toml` is verified against the downloaded
manifest's raw bytes purely as a **transport-integrity** check — it proves
the bytes that landed on disk are the same bytes the registry published at
that URL, and nothing more:

- It says nothing about the manifest author's intent. A compromised (or
  simply malicious) registry can publish a hostile manifest whose
  `sha256` is perfectly, honestly self-consistent — the entry passes
  every check in `RegistryIndex::validate` and `verify_and_prepare`
  because both are checking "did the bytes arrive intact," not "is this a
  trustworthy manifest." Verifying sha256 **does not catch this, by
  construction**: the hash is computed over whatever bytes the registry
  chose to publish; there is no independent reference-good version to
  compare against.
- Installing a plugin from the registry is still an act of trust in
  whoever wrote (and whoever hosts) it — the same trust boundary as
  installing a hand-dropped third-party manifest, the same as installing
  a Cargo crate. Verified sha256 makes sure the bytes you approved are the
  bytes you get; it doesn't vouch for what's in them.

**Trust disclosure at install time.** Before a downloaded manifest is
written to disk, the caller runs `analyze_trust` on the parsed
`PluginManifest` and is expected to show the result to the user
(`TrustDisclosure`):

| Field | Discloses |
|---|---|
| `engine` | `log-file` or `http-api` |
| `auth_types` | every distinct `[[surface.auth]].type` used by any surface, across every surface, in first-seen order — every auth-source type the manifest declares, not just the ones that trigger the mandatory gate below |
| `dest_hosts` | every distinct destination host the manifest could reach: every `[[http.request]].url` host, `[account].url`'s host when `type = "http"`, and every `oauth-refresh` step's `token_url` host — each URL's `{option.<key>}` placeholders substituted at the manifest's own `[[option]]` defaults *before* the host is read off, so a host spelled `{option.beta}.example` discloses the destination it actually resolves to, not the placeholder text — case-insensitively de-duplicated, in first-seen order |
| `untrusted_hosts` | the subset of `dest_hosts` outside the caller's `trusted_hosts` set — disclosure only, see below for why it doesn't gate `requires_approval` |
| `local_files` | every local file, or file-*shaped* source, the manifest reads: an auth step's own credential file (`credentials-file`/`credentials-map`/`reject-when`/`oauth-refresh`'s `path`), `[[http.value]] path`, `[http.version] files`, an `oauth-refresh` step's `[surface.auth.client]` discovery (`files`, `bins` labelled by name rather than a path, `id_env`/`secret_env` labelled as an environment variable, `id_pattern`/`secret_pattern` labelled and length-capped), an `electron-safe-storage` step's `config_path`, `engine = "log-file"`'s own `root`/`glob` read scope (one `"<root>/<glob>"` entry, `root` shown literally — `~` included, unexpanded — unless `root_env` is set, in which case it's `"$<root_env>"`, joined with `root_env_join` when the manifest sets one), and `[account] path` (a `jwt-file` lookup's own token file) |
| `credential_sources` | every `env`/`keychain`/`win-credential`/`electron-safe-storage` auth step's *own* source, named specifically — `"env $VAR"`, `"keychain \"service\""`, one `"credential manager \"target\""` per target tried, `"electron safe storage <config_path> (key \"...\")"` — rather than just the step *kind* `auth_types` already carries; `credentials-file`/`credentials-map` don't repeat here since their file is already in `local_files` |
| `ping` | the command this manifest runs after a window resets, if it declares one — with a trailing note that it also runs when its token has expired or is no longer accepted, when `renews_token` is set (see [Renewing a lapsed token](#renewing-a-lapsed-token)) |
| `requires_approval` | see below |

**Mandatory approval gate.** `requires_approval` is `true` when *any* of the
following hold:

1. At least one auth step is **store-backed** — `credentials-file`,
   `keychain`, `electron-safe-storage`, `win-credential`, `credentials-map`,
   or `oauth-refresh` (i.e. it reads a secret out of some OS-/app-managed
   store, or sends one to the network on its own) — **and** `engine =
   "http-api"`, i.e. the manifest can actually send something somewhere,
   unlike `log-file`, which never touches the network on its own account.
   A plain `env` step is excluded from "store-backed" here: a var is
   something the user set themselves, not a store this manifest goes
   digging in (it can still trip condition 4 below, just not this one).
2. It declares `[ping]` — an arbitrary local command is worth stopping for
   whatever the engine.
3. `local_files` is non-empty — a manifest reading a local file of its own
   choosing (including `engine = "log-file"`'s own read scope) is the same
   "something on this machine leaves it, or a manifest picks what a request
   carries off this machine" shape as a stored credential, whatever the
   engine.
4. `credential_sources` is non-empty — naming a specific `env`/`keychain`/
   `win-credential`/`electron-safe-storage` source is worth a look whatever
   the engine: a `log-file` manifest whose one auth step reads
   `AWS_SECRET_ACCESS_KEY` is exactly as much this app's business as an
   `http-api` one that reads it and sends it on, since nothing stops a later
   update from adding the sending half once the reading half already
   installed unseen.

Condition 1 is the only one still narrowed to `engine = "http-api"`; the
other three fire whatever the engine declares. Reading a real credential
store out of a third-party manifest is itself the thing worth a
confirmation — the manifest author controls the URL, so a plugin that reads
your Claude token and today posts it to `api.anthropic.com` could post it
elsewhere tomorrow, and the approval was granted against the "safe" version.
Everything that comes through the registry install flow is third-party by
definition (the bundled `codex`/`claude` are *seeded*, never installed
through this path), so condition 1 fires for any registry plugin that reads
a secret over `http-api`, regardless of where it currently sends it — and
the destination host is deliberately not a condition of its own, for any of
the four.

The destination host still matters for **disclosure**, just not for the
gate: `analyze_trust` also returns `untrusted_hosts` — the subset of
`dest_hosts` not in the caller's `trusted_hosts` set (default
`TRUSTED_HOSTS = ["api.anthropic.com", "chatgpt.com"]`, passed as a
parameter, not hardcoded in the function). The confirmation dialog
highlights those hosts so the user sees which destinations are unfamiliar,
but the dialog appears whether or not any host is untrusted.

`requires_approval` is a **computed disclosure flag**, not an enforced
gate, by itself — `analyze_trust` only tells the caller whether the
stronger confirmation is required; the caller (`src/main.rs`) is the one
that actually blocks the install pending that confirmation.

**Signing is a known, explicit gap — future hardening, not something
silently deferred.** Manifest signing (as opposed to today's plain
sha256, which only proves transport integrity, never provenance) needs
key-management infrastructure this app doesn't have yet: publishing and
rotating a signing key, and something on the client side to verify
against. Until that infrastructure exists, the only mitigation for a
registry that turns hostile — or a registry entry that was always
hostile — is the same one that already applies to a hand-dropped
manifest: **only add a registry whose publisher you trust**. This is
listed as future hardening, not a bug in what's shipped: the registry's
actual job — making discovery easy, and making sure a verified download
matches what you approved — is fully implemented; provenance beyond
"this registry vouches for it, and the bytes weren't tampered with in
transit" is not.

### Bundled plugins and Reset plugins

The shipped manifests aren't special-cased anywhere in the registry:
nothing stops a registry from publishing an entry with `id = "codex"` (or
any other shipped id), and nothing in `registry.rs` refuses to overwrite a
bundled manifest with a registry-sourced one that shares its id. If a
registry update is installed over a bundled manifest, Settings'
**"Reset plugins"** button will overwrite it right back to the shipped
default the next time it's pressed — the same as it would for any other
hand-edit to a shipped file (see
[Plugin folder & seeding](#plugin-folder--seeding)). That's expected, not
a bug to special-case around: "Reset plugins" only ever rewrites the
shipped templates (five today); it has no notion of "this file used to come
from the registry."
