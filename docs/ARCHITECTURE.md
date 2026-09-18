# Architecture

A guided tour for a reader who wants to judge the engineering rather than
use the app. Claims name the file they live in; the manifest reference
([`PLUGIN-ARCHITECTURE.md`](PLUGIN-ARCHITECTURE.md)) and the development
notes ([`DEVELOPMENT.md`](DEVELOPMENT.md)) carry the detail.

## The shape

```
plugins/*.toml         five provider manifests + the registry index      (data)
src/lib.rs             the library crate root: `plugin`, `model`, `menubar`
src/plugin/            the library: manifest → capability gate → engine  (no UI)
src/model.rs           one provider-neutral reading every consumer draws from
src/main.rs            the binary: tray, panel, timers, dialogs, auto-ping (Slint)
src/menubar.rs         rasterises the tray reading (pill on macOS, badge on Windows)
src/platform.rs        accessory policy, single instance, dock mode
src/config.rs          persisted settings (JSON under the OS config dir)
src/autostart.rs       the launch-at-login toggle
src/diag.rs            the trimmed local diagnostics log (`tickover.log`)
ui/*.slint             the panel, declared
```

Two decisions shape everything else. **A provider is data, not code**: the
Rust knows how to read *a* manifest, never *the* Codex manifest, so when an
undocumented endpoint changes shape the fix is a text edit and the binary
is untouched. And **the app never prints a figure the provider did not
state** — no estimates from logs, no derived percentages, one licensed unit
change (a stated *remaining* fraction into the used percent). Both rules
are written down in [`../CONTRIBUTING.md`](../CONTRIBUTING.md) and most design
questions below were decided by them.

The library under `src/plugin/` has no UI dependency and is exercised by
the whole test suite; the binary's `main.rs` is the largest file in the
tree because it holds the platform glue — tray, window, timers, native
dialogs — and the auto-ping, and it consumes the library through
`model.rs`, apart from one documented legacy seam: a few settings toggles
are still keyed to the `codex` and `claude` ids for backward compatibility
of the settings file.

## Reading a manifest without trusting it

- **Schema and validation** — `src/plugin/manifest.rs`. Every way a manifest
  can be refused is a `return Err` with a sentence a person can act on; a
  plugin `id` is a file name and is restricted to `[A-Za-z0-9_-]+`, which
  closes path traversal through an imported manifest at the point of parsing.
- **The capability gate** — `src/plugin/capability.rs`. A manifest lists the
  reader capabilities it needs (`requires_reader = ["window-presence",
  "window-identity", …]`) and every capability owns the manifest keys it
  introduced. An older build meeting a manifest from the future refuses it
  *out loud* instead of misreading it quietly. The discipline that makes
  this work: a new key ships in the same change as its capability entry, a
  negative test and a golden.
- **The corpus** — `tests/manifest_corpus.rs`. One row per refusal, with the
  word the complaint must contain, and a count of the `return Err` sites in
  both refusing functions checked against the row count. A refusal added
  without a row fails the suite. It is a grep and says so.

## Getting a token without keeping it

`src/plugin/auth.rs` runs an ordered credential chain per surface: a
credentials file, the macOS Keychain, Windows Credential Manager, an
environment variable, Electron Safe Storage (AES-CBC under a PBKDF2 key on
macOS, DPAPI on Windows), or a keyed map for CLIs that store several logins
under ids no manifest can spell in advance. Each step answers Present-ok,
Present-err or Absent, and the chain stops at the first Present — so
"item not found" hides the row while "access denied" is reported, two
states the code refuses to collapse.

A `credentials-file`, `keychain` or `win-credential` step that declares
`expiry_json_path` folds a fourth outcome into that same three-way answer:
a token past its own stated expiry resolves Absent too, exactly like no
token at all, so a step behind it in the chain still gets its turn. With
nothing behind it to catch that, the chain reports the token as lapsed
rather than merely missing — the distinction that drives both the row's
"token expired — renews on the next `<bin>` run" text and the renewal ping
(`[ping] renews_token`). Without a renewing ping — no `[ping]` at all, or
`renews_token` left `false` — a lapsed token still keeps its row on screen,
reading "token expired — sign in again" instead; only a credential that
resolves Absent with nothing behind it to catch it hides a row.

Tokens live in memory for the request that uses them and are never written
to disk. The one step that spends a credential, `oauth-refresh`, exists
because Antigravity's access token lapses within hours; it exchanges the
stored refresh token, caches the result in memory until the provider's own
expiry, refuses non-`https` and an empty `allowed_hosts` outright, and
writes nothing back to the other client's file. The OAuth client id and
secret that exchange needs are not in this repository: the manifest
declares where the installed client keeps them (its own binaries) and
what shape they have, and the step reads them at run time — the same
pair the client itself sends, discovered rather than copied. Every request is `ureq` with redirects disabled; a provider
request is also checked against its manifest's `allowed_hosts`
(`host_allowed`), and a registry download against the host the index came
from. That protects a trusted manifest from typos and open redirects — and
is documented as exactly that, not as a sandbox
([`../SECURITY.md`](../SECURITY.md)).

## Asking a provider politely

`src/plugin/throttle.rs` is a pure state machine on a monotonic clock: a
floor between requests to one surface, doubling backoff after a failure,
and a full stop on 401 that only a change of credential fingerprint lifts.
It is tested without sleeping. It exists because the refresh timer is not
the only thing that asks for a fetch — opening the panel, the Refresh
button, enabling a plugin and starting the app all do — and the floor is
what turns ten panel openings in a minute into a redraw of the last reading
rather than ten requests at somebody else's undocumented endpoint.
`src/plugin/scheduler.rs` decides which surface is due and when.

## The engines

- **`http-api`** (`src/plugin/engine_http.rs`, every shipped provider):
  substitutes `{token}`, `{version}`, `{value.<name>}` and `{option.<key>}`
  into headers, URL and body; expands one `[[windows]]` entry into a row per
  array element (`for_each`) for limits a provider enumerates at runtime,
  such as Claude's per-model weekly caps; reads `[[balances]]` for
  calendar-period figures and `[status]` for "limit reached", which a
  blocked account can report with no windows at all.
- **`log-file`** (`src/plugin/engine_logfile.rs`): tails local JSONL, finds
  the `rate_limits` container by depth-first search with spelling
  tolerance, classifies windows by period length. No shipped manifest uses
  it any more (the reasons are in [`PROVIDERS.md`](PROVIDERS.md)); it stays
  because it is a general mechanism and is fully specified.

Both engines produce the same `ProviderReading` (`src/model.rs`); the panel,
the tray pill, the badge and the auto-ping consume that and nothing else.

## Starting the next window: the auto-ping

The feature the project exists for is a small piece of state logic in
`main.rs` (`ping_due`, `ping_cwd`, `cli_path_env`). The question asked once a
second is not "did the window just reset" but "is the window *empty*" — a
state, not an edge — so a machine asleep at the boundary pings when it
wakes instead of losing the window for good. One ping per window is
enforced by a timestamp (`pinged_at`) compared against the window's start,
because the same window is named differently by the provider before and
after the ping makes it report again. Two guards sit on top of that
arithmetic, because the reset time comes from the provider: a ping is never
due before the window has actually begun, and never twice within ten
minutes, whatever a response says about its reset. A window whose ping
failed has its boundary projected forward one period, so the retry is owed
at most once per window and never zero. The command runs in a fresh,
uniquely named temporary directory created for that one run and removed
afterwards (nothing there for a prompt injection to read, and nothing under
the home directory for a CLI to walk up into), with the Codex sandbox set to
read-only, and with the usual CLI install directories *appended* to `PATH`
rather than prepended, because every one of them is user-writable and this
command runs unattended.

A second trigger fires that same command: a manifest whose `[ping]` sets
`renews_token` (Claude's does) also runs it the moment a surface whose auth
chain declares a token expiry finds that token lapsed or refused. That
decision is `renewal_ping_due`, and `classify_renewal_across_surfaces`
applies it across every renewal-eligible surface a plugin reports, since two
surfaces on one plugin can lapse on independent schedules. It shares the
window trigger's ten-minute floor, plus a bound of its own: a
per-surface `LAST_RENEWED_FOR` table stops a token the CLI cannot itself
renew from being pinged again every ten minutes forever, so a renewal fires
once per distinct token per surface when the run succeeds, and up to three
attempts, ten minutes apart, when it keeps ending without success.

## Keeping the folder honest

`src/plugin/seed.rs` seeds the plugins folder from the embedded manifests on
first run, and thereafter upgrades a shipped manifest once per version it
ships in — but only while the file on disk still hashes to a copy this app
wrote. An edited manifest is yours and stays. A marker that says "this
install has had its say" with no file beside it is *explained in the log*,
not repaired, because deleting a manifest is a legitimate act.

`src/plugin/registry.rs` is "Check updates": one `index.toml`, sha256 over
the downloaded bytes *before* parsing, the downloaded id checked against
the clicked entry, install with `create_new` under a containment check,
update by writing a temporary neighbour and renaming over the target. The
ed25519 verification in `src/plugin/signature.rs` runs on the same path but
no key is pinned yet, and the UI says "unverifiable" rather than pretending
— the gap is named in `SECURITY.md`, not hidden. A manifest that combines a
store-backed secret with `http-api`, or declares a `[ping]`, or reads local
files of its own choosing, or names a specific credential source — an
`env` variable, the Keychain, Credential Manager, Electron Safe Storage —
cannot be installed without a native confirmation showing exactly what it
will do (`analyze_trust`, `requires_approval`). The same dialog gates a
manifest picked from disk through *Add plugin*, not only one installed from
the registry (`src/main.rs`'s import path calls `analyze_trust` too).

## One process, two desktops

`src/platform.rs` takes an OS-level lock on a file beside `config.json`; a
second launch — a `cargo run` beside the installed bundle, a login item
beside a manual start — leaves a `show-panel` note and exits, and the running
copy opens its panel. The lock dies with the process, so there is nothing
stale to clean up. On macOS the app flips itself to the accessory policy at
runtime; when the menu bar is full and macOS silently drops the status item,
dock mode turns the panel into an ordinary window
([`DOCK-MODE.md`](DOCK-MODE.md)) — a switch, because macOS does not say when
an item was dropped. The Windows port shares the tree: DPAPI and Credential
Manager in the auth chain, native message boxes and the common file picker
for the plugin manager, a flyout placed on whichever side of the tray has
room, the tray reading drawn *inside* the icon at the tray's own icon size
by `src/menubar.rs`.

## Things that were learned the hard way, and kept

- The bar tooltip is drawn by the window, not the bar: Slint has no z-index,
  painting order is declaration order, and a bubble inside a bar is painted
  under the next row. The invariant is written down where the next person
  will look (`DEVELOPMENT.md`).
- Tests run under a substituted `HOME`, because a run under the real one
  once wrote a "manifest already delivered" marker into a live install.
  `config::path()` is sandboxed under `cfg(test)` since; the folder around
  it is not, and the notes say so.
- A window the provider once stated does not blink out of the panel when
  the provider goes quiet: the seen-window registry in `config.json` keeps
  the last stated reset, and the reader projects it forward.
- Every diagnostic goes to a trimmed local log that never carries a token,
  because a bundled app launched from Finder has no stderr anywhere and a
  feature failing silently on every attempt looked like a feature that had
  never run.

## Numbers

About 47,000 lines of Rust (roughly half of it tests), three Slint files,
some 800 test functions, a release binary of about 8 MB per architecture
(the macOS binary is universal, so twice that on disk; the zip is about
8 MB). CI builds and tests on macOS and Windows,
with clippy at `-D warnings` on macOS — the half that can be reproduced on
the machine this is developed on — actions pinned by commit, and the
checkout token not persisted. A release run repeats the suite on both
platforms before packaging.
