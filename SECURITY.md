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
  (`src/plugin/auth.rs`, a `Mutex` over a map) until the moment the provider
  said it expires, after which it is not used again — an expired entry reads
  as a miss and the next exchange overwrites it. (It is not scrubbed at the
  moment it expires; if that distinction matters to you, the map is
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
finds every one:

1. **The provider's own usage endpoint**, per manifest, to a host that
   manifest pins in `allowed_hosts`. This is the one on a timer.
2. **An OAuth token exchange**, only for a manifest that declares
   `oauth-refresh`, under the rules above. Unattended, but not on a clock of
   its own: it happens inside a scheduled fetch, and only when the token that
   fetch needs has lapsed — which the in-memory cache above makes rare.
3. **One `index.toml`**, and only when you press "Check updates" in Settings.
4. **A manifest file named by that index**, and only when you then choose to
   install or update one of the plugins it lists. Its bytes are checked
   against the sha256 the index stated before anything is parsed or written —
   see the gap about provenance below.

### A request this app makes something *else* make

`[ping]` is the fifth way traffic leaves because of this app, and it is not an
HTTP call of its own: it runs a local command the manifest names, shortly after
that provider's window resets, and that command talks to its own provider. The
shipped example is `codex exec … hello` — a real prompt, spending a little real
quota, which is why it exists and why it is **off until you switch it on** per
plugin. Once on, it is unattended: it fires on a reset, not on a click. What it
sends is between that CLI and its provider; this app neither sees nor logs it.

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
after that provider's window resets, to start a fresh one. That is an
arbitrary local command with your user's privileges. Three things bound it:
the toggle is **off unless you turn it on**, per plugin, in Settings; it fires
at most once per window reset; and a manifest that declares `[ping]` at all
cannot be installed from a registry without the confirmation dialog, which
shows the exact command line.

The manifests that ship with the app (`plugins/*.toml`) are reviewed and
versioned in this repository, and are seeded rather than installed — they never
go through the registry path.

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
- **The confirmation before a registry install is a prompt, not a proof.** It
  fires on any of three things (`registry::analyze_trust`): reading a secret
  out of an OS/app store while calling an endpoint, declaring `[ping]`, or
  reading local files of its own choosing into a request. It shows the hosts,
  the files and the ping command line — and then a person decides, which is
  the part no code here can do for them.
- **The Windows credential paths have been built and run, but not against a
  real item.** The app has since been built and run on Windows 11 (x86_64,
  MSVC); the Credential Manager (`CredRead`) and DPAPI desktop-token steps
  compile and are reached, but the machine this was checked on had nothing in
  either store for them to find. The gap that remains is narrower than "never
  compiled": these paths are unexercised against a real credential, not
  unbuilt.
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
