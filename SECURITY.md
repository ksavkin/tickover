# Security

This app reads credentials that other tools left on your machine. That is its
whole job, so the interesting question is not whether it touches secrets but
what it does with them — and what it refuses to do.

## What it touches, and what it never does

- **It reads tokens from the stores your own CLIs wrote** — a credentials file,
  the macOS Keychain, an environment variable, Windows Credential Manager,
  Electron Safe Storage — as named by a plugin manifest's `[[surface.auth]]`
  chain.
- **A token is held in memory, never on disk.** This app writes no token
  anywhere and puts none in its log; `tickover.log` is trimmed local
  diagnostics and has never carried one. Most tokens live only for the request
  they are used in. The exception is the one this app obtains itself: an
  `oauth-refresh` result is kept in a process-global in-memory cache
  (`src/plugin/auth.rs`, a `Mutex` over a map) until 60 seconds before the
  moment the provider said it expires, after which it is not used again — an
  expired entry reads as a miss and the next exchange overwrites it. (It is
  not scrubbed at that moment; if that distinction matters to you, the map is
  `REFRESH_CACHE` and it dies with the process.) Without the cache a
  one-minute poll would mean a token exchange a minute, which is both rude to
  the provider and a way to get an account rate-limited.
- **It does not refresh a provider's token** — with one named exception below.
  Renewing an OAuth token hands back a new refresh token and invalidates the
  copy the provider's own CLI is holding, which would break the tool you
  actually work in. An expired session is reported, not repaired.
- **The exception is `oauth-refresh`**, an auth step a manifest must ask for by
  name (Antigravity uses it, because its stored access token goes stale within
  hours whenever its IDE is not running). It exchanges a stored refresh token
  for an access token, keeps the result in memory, and writes nothing back to
  the other client's file. It refuses to send anything unless the token URL is
  `https` and its host is in that surface's `allowed_hosts` — an empty
  allow-list is refused outright there, rather than read as "no restriction".
  The OAuth client id and secret the exchange needs are not shipped with
  this app; see the gap list below for where they come from.

## What leaves the machine

### Requests this app makes

Four call sites, all of them `ureq` with redirects disabled — `grep -n ureq -r src`
finds every one — carrying five kinds of request between them, since the
registry's byte fetch serves both the index and a manifest file. All four are `https`-only, each enforced where it is sent: the usage
endpoint's URL is refused at load (`PluginManifest::validate`) and refused
again by the generic HTTP engine right before it would open a connection; the
`oauth-refresh` token exchange refuses a non-`https` `token_url` of its own
accord before dialing it; and the registry's `index.toml`/signature/manifest
fetches carry the same gate at their own call site.

1. **The provider's own usage endpoint**, per manifest, to a host that
   manifest pins in `allowed_hosts`. This is the one on a timer.
2. **An OAuth token exchange**, only for a manifest that declares
   `oauth-refresh`, under the rules above. Unattended, but not on a clock of
   its own: it happens inside a scheduled fetch, and only when the token that
   fetch needs has lapsed — which the in-memory cache above makes rare.
3. **One `index.toml`**, and only when you press "Check updates" in Settings.
4. **That index's signature file**, `index.toml.minisig`, fetched right after
   and only on the same trigger — minisign's own convention keeps it at a
   fixed name beside the index, and it is what the trust check in the gap
   list below verifies (or, until a key is pinned, fails to).
5. **A manifest file named by that index**, and only when you then choose to
   install or update one of the plugins it lists. Its bytes are checked
   against the sha256 the index stated before anything is parsed or written —
   see the gap about provenance below.

Every response this app reads is bounded before it is buffered into memory,
not read until the connection closes: a provider's usage response is capped
at 4 MB (`engine_http::MAX_PROVIDER_RESPONSE_BYTES`), an index or manifest
download at 10 MB and the signature file at 8 KB (`registry::fetch_bytes`'s
and `fetch_text`'s own caps) — so a compromised or merely broken host cannot
exhaust memory by answering at length instead of answering correctly. A
response shaped to make one manifest enumerate an unbounded number of rows
through `for_each` is capped the same way, at 64 elements considered
(`engine_http::FOR_EACH_MAX_ELEMENTS`); past that point the rest of the array
is simply not read, and a line in the log says so once for the life of the
process, not once per plugin or per tick.

The same principle bounds what is read off disk and how long this process
will wait on anything. A `log-file` plugin's session-tree glob opens at
most 200 matched files per fetch (`engine_logfile::LOG_WALK_MAX_FILES`, the
newest by mtime kept when a glob matches more) and reads at most 64 MiB out
of them per lookup (`engine_logfile::FETCH_BYTE_BUDGET`; the primary
lookup and the secondary-accounts lookup each get their own), so years of
session history cost a fixed amount of work rather than one proportional
to how much has piled up. The `[surface.auth.client]` discovery scan reads
at most 512 MiB of any one candidate binary and 1 GiB across one whole pass
(`auth::CLIENT_DISCOVERY_MAX_SCAN_BYTES`,
`auth::CLIENT_DISCOVERY_PASS_BUDGET_BYTES`); an OAuth token-exchange
response is capped at 1 MiB (`auth::OAUTH_RESPONSE_MAX_BYTES`), and a
credential file read off disk at 4 MB (`plugin::SMALL_FILE_MAX_BYTES`). A
registry index listing more than 500 plugins
(`registry::MAX_INDEX_ENTRIES`) is rejected wholesale rather than handed to
the install UI to sort and draw. A refreshed OAuth token is never cached as
living longer than 24 hours (`auth::EXPIRES_IN_MAX_SECS`), whatever a token
endpoint's own `expires_in` claims. And a macOS Keychain read that hangs —
a wedged daemon, or a first-run access prompt nobody is there to answer —
is killed and reported as a timeout after 30 seconds
(`auth::KEYCHAIN_DEADLINE`), rather than blocking that surface, and the
throttle gate behind it, forever.

### A request this app makes something *else* make

`[ping]` is the sixth way traffic leaves because of this app, and it is not an
HTTP call of its own: it runs a local command the manifest names, shortly after
that provider's window resets — and, for a manifest that also sets
`renews_token`, again the moment a surface whose auth chain declares a token
expiry finds that token lapsed or refused outright — and that command talks
to its own provider. The shipped example is `codex exec … hello` — a real
prompt, spending a little real quota, which is why it exists and why it is
**off until you switch it on** per plugin. Once on, it is unattended: it
fires on a window reset or a lapsed token, not on a click. What it sends is
between that CLI and its provider; this app neither sees nor logs it.

Antigravity's manifest declares no `[ping]` at all, deliberately. Google has
confirmed banning accounts for third-party tools and proxies driving
Antigravity's underlying quota, with the ban reported to cascade to Gemini
CLI / Code Assist on the same account — see this
[gemini-cli discussion](https://github.com/google-gemini/gemini-cli/discussions/20632) —
a risk none of the bounds above (the toggle, the floor, the confirmation
dialog) actually removes, since they all assume the provider tolerates being
pinged at all.

### Neither list contains

No telemetry, no crash reporting, no analytics, and nothing on a timer against
a host this project controls. The usage endpoints are the providers' own,
undocumented and unofficial; if one changes shape, the fix is a manifest, not a
release.

## The trust model, stated plainly

**Installing a plugin manifest is an act of trust in whoever wrote it**, the
way installing a browser extension or a Cargo crate is. A manifest declares
both where a secret is read *and* where it is sent, and this app does what the
manifest says.

`allowed_hosts`, the `redirects(0)` on every request, and the refusal to put a
token in a URL protect a *trusted* manifest from typos and open redirects.
They are not a sandbox against a hostile author. A manifest you did not read is
a program you did not read.

**And one part of it is a program in the ordinary sense.** A manifest may
declare `[ping]` — a binary and its arguments — which this app runs shortly
after that provider's window resets, to start a fresh one, and which a
manifest that also sets `renews_token` runs again the moment a surface's
own token has lapsed or been refused outright. That is an arbitrary local
command with your user's privileges. Four things bound it: the toggle is
**off unless you turn it on**, per plugin, in Settings; the window trigger
never fires before the window it targets has actually started, and neither
trigger fires more than once every ten minutes regardless of what a
manifest's own numbers claim — a renewal is bound tighter still: once per
distinct token per surface when the run succeeds, up to three attempts,
ten minutes apart, when it keeps failing — which is what stops a
misconfigured or malicious manifest from turning this into a loop; it runs
in a directory created fresh for that one command, normally under the OS
temp directory and removed once the command exits, so there is nothing
already on disk for it to read; and a manifest that declares `[ping]` at
all cannot be installed from a registry without the confirmation dialog,
which shows the exact command line — appending " — also run when its token
has expired or is no longer accepted" when that ping renews a token.

The manifests that ship with the app (`plugins/*.toml`) are versioned in
this repository, and are seeded rather than installed — they never go
through the registry path.

Details, including what each auth step does and why: `docs/PLUGIN-ARCHITECTURE.md`,
sections "Auth chain semantics" and "Security".

## Known gaps, named rather than left to be found

- **The registry index is not signature-verified in practice.** The check
  exists (`src/plugin/signature.rs`, ed25519) and runs on the install path, but
  no public key is pinned (`REGISTRY_PUBLIC_KEY = None`), so it answers
  "unverifiable" and says so in the UI. The sha256 a manifest is checked
  against comes from the same index, over the same connection, so it is
  transport integrity — not provenance. Until a key is pinned, treat installing
  from the registry as trusting the host that served the index.
- **The confirmation before a registry install is a prompt, not a proof.**
  The same gate runs for a manifest picked off disk through "Add plugin" —
  a file you chose yourself is exactly as third-party as one the registry
  would have downloaded, and nothing here special-cases it. It fires on any
  of four things (`registry::analyze_trust`): reading a secret
  out of an OS/app store while calling an endpoint, declaring `[ping]`,
  reading local files of its own choosing into a request, or naming a
  specific `env`/keychain/Credential Manager/Electron Safe Storage source to
  read a credential from — whatever the engine, so a `log-file` manifest
  reading an environment variable asks exactly as loudly as an `http-api`
  one does. It shows the hosts (each URL's option placeholders substituted
  at the manifest's own defaults first, so a host is never shown as raw
  `{option.…}` text when it names a real destination), the files (including
  a `log-file` manifest's own read scope and a `jwt-file` account lookup's
  token file, not just a credential store's own path), the specific
  credential source named above, and the ping command line — and then a
  person decides, which is the part no code here can do for them.
- **The Windows Credential Manager and DPAPI steps are unexercised against a
  real credential.** On Windows 11 (x86_64, MSVC) Antigravity's Credential
  Manager (`CredRead`, `gemini:antigravity`) step and Claude Desktop's
  DPAPI-decrypted Safe Storage step compile and are reached, but neither has
  run against an item actually sitting in either store. Claude's own CLI
  surface declares no Credential Manager step on Windows — the CLI writes
  only `%USERPROFILE%\.claude\.credentials.json` there, and that file is
  where its chain stops.
- **The Antigravity token exchange needs an OAuth client id and secret, and
  this repository does not carry them.** The manifest declares where the
  installed Antigravity client keeps its own pair (the `language_server`
  binary inside `Antigravity.app`, the `agy` CLI on `PATH`) and what shape
  the two strings have, and the `oauth-refresh` step reads them from there
  at run time, or from `TICKOVER_ANTIGRAVITY_CLIENT_ID` /
  `TICKOVER_ANTIGRAVITY_CLIENT_SECRET` if you set both. Without either, the
  step stands aside and an expired session is simply reported. The pair is
  held in memory like a token and never logged. What this does *not* do is
  make the pair secret — an installed-app secret is public by construction,
  which is why reading it from the client that already holds it is
  acceptable and shipping it in a public repository is not. The gap that
  remains: the discovery reads whatever files a manifest names, by pattern.
  For the shipped manifest that is two known binaries; for a manifest from a
  registry the files it would read are shown in the confirmation dialog
  before anything is installed.

## Reporting something

Open a GitHub security advisory on the repository (Security → Report a
vulnerability). If that tab is not there — private reporting is a setting, and
it may not be switched on — open an ordinary issue saying only that you have
something to report, and it can move somewhere private from there. An issue is
also the right place outright if it is not sensitive. Please include what a
malicious manifest, endpoint, or local file would have to look like to trigger
it — this project's whole attack surface is "somebody else's data, read by a
declarative rule", and a reproduction in that shape is the fastest fix.

Do not include a real token in a report.
