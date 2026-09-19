# Providers

Five providers ship as manifests in [`plugins/`](../plugins). Each one is a
TOML file the app reads at runtime — nothing about a provider is written in
Rust. This page is the user's view: what each row shows, which login it
reuses, and the rough edges. The manifest format itself is specified in
[`PLUGIN-ARCHITECTURE.md`](PLUGIN-ARCHITECTURE.md).

## What is read, and from where

| Provider | What the panel shows | The login it reuses | Refresh | Host pinned in the manifest |
|---|---|---|---|---|
| **OpenAI Codex CLI** | 5-hour and weekly windows; model-specific windows as extra rows; the account's credit balance, email and plan; a "limit reached" notice when Codex says so | `~/.codex/auth.json` — the access token and account id, sent to the same usage endpoint the CLI calls | 60 s | `chatgpt.com` (`/backend-api/wham/usage`) |
| **Claude** | 5-hour and weekly windows per login found — Claude Code CLI / VS Code, and (opt-in) the desktop app, which may be a different account; per-model weekly limits as extra rows | `~/.claude/.credentials.json`, else the Keychain item `Claude Code-credentials` on macOS — on Windows that same file is the only store the CLI writes; the desktop app's token from Electron Safe Storage | 60 s | `api.anthropic.com` (`/api/oauth/usage`, `/api/oauth/profile` for the address) |
| **Grok** | credits used in the current usage period, plus a prepaid credit balance and pay-as-you-go spend | the record in `~/.grok/auth.json` whose key starts with the x.ai auth host (the rest of the key is xAI's own OAuth client id — fixed, not one that varies by install — matched by prefix rather than spelled out in full) | 60 s | `cli-chat-proxy.grok.com` |
| **Antigravity** | 5-hour and weekly allowances for Gemini and for third-party models | the access token in the Keychain item its CLI writes, or the same token from Windows Credential Manager (`gemini:antigravity`); once that has lapsed, the refresh token in `~/.gemini/antigravity-cli/antigravity-oauth-token`, exchanged with the OAuth client pair read from the installed Antigravity app or `agy` binary (never shipped with this app; `TICKOVER_ANTIGRAVITY_CLIENT_ID`/`_SECRET` override) | 60 s | `daily-cloudcode-pa.googleapis.com`; `oauth2.googleapis.com` for the token exchange |
| **GitHub Copilot** | the month's premium-request allowance and its reset; chat and completion rows on the free tier | the `github.com` entry of `~/.config/github-copilot/apps.json` | 300 s | `api.github.com` |

Every one of these endpoints is the provider's own — undocumented and
unofficial. When one changes shape, the fix is an edit to the manifest, not a
release; until then the affected row says what went wrong.

The refresh cadence is a manifest field (`refresh_secs`). There is no
setting for it: a minute is already generous for a window five hours long,
and Copilot's allowance is monthly. Each provider is asked less often while
it is failing, and opening the panel redraws the last reading rather than
firing a request.

## Auto-ping

Two of the five manifests declare a `[ping]` — Codex
(`codex exec --skip-git-repo-check --sandbox read-only hello`) and Claude
(`claude -p hello --model haiku` — the CLI's own alias for its current
cheapest model, not a dated snapshot id, does the same job of starting the
window and renewing the token). When that provider's 5-hour window sits
empty, the command runs once so the new window starts counting
immediately. Copilot and Grok have no rolling window a ping could start — a
monthly allowance, and a credit period with balances. Neither this
ping nor a renewal one (below) is ever launched while the provider's own
host does not resolve — the tick simply tries again once it does.

Antigravity, which does have a rolling window, deliberately has no `[ping]`.
Google has confirmed banning accounts over third-party tools and proxies
driving Antigravity's underlying quota, with reports of the ban cascading to
Gemini CLI / Code Assist on the same account — see this
[gemini-cli discussion](https://github.com/google-gemini/gemini-cli/discussions/20632).
[`leonidlouis/antigravity-quota-refresher`](https://github.com/leonidlouis/antigravity-quota-refresher),
a tool built for exactly the job `[ping]` does for Codex and Claude, is marked deprecated for this reason —
its users got banned. Nothing here second-guesses that: Antigravity stays
read-only, however tempting an empty window is to nudge.

The mechanism, its bounds and where the command runs are in
the README and in
[`PLUGIN-ARCHITECTURE.md`](PLUGIN-ARCHITECTURE.md#ping-auto-refresh-nudge).

## Rows, notices and what can be missing

- **Extra rows.** Limits a provider reports beside its main windows —
  Claude's per-model weekly limit, Codex's model-specific windows — are
  shown in a role that cannot reach the headline 5H/WK slots or the tray.
- **Balances.** Providers that report a calendar period instead of a
  rolling window get a balance row: Grok's credit and spend, Codex's
  credits, Copilot's premium requests.
- **A notice above the rows** appears when the provider says the account is
  blocked. A blocked account may report no window at all, and the bars alone
  would then show nothing wrong.
- **Only Codex announces a missing login** ("Not signed in — run: codex
  login"). Whether a row says so is a manifest field
  (`no_credentials_message`), and Codex is the only shipped manifest that
  sets one. The other four hide their row entirely — right for a tool you
  never installed, a rough edge for one you did.
- **Signing in to Codex with an API key** rather than a ChatGPT account gets
  a sentence of its own: an API key has no subscription window to report.
- **A row that disappears because its credential went away** (signed out,
  file deleted, keychain item removed) is explained in `tickover.log` at the
  moment it happens. A token that is merely no longer accepted is a
  different state: the request comes back 401 and the row stays, reading
  "session expired — sign in again" — unless the provider's ping can renew
  it (`[ping] renews_token`) *and* the step that actually produced the
  token this 401 named declares that token's expiry (a surface with its own
  separate, undeclared credential, like Claude's Desktop below, never gets
  the rewrite; nor does a token from an undeclared fallback step behind a
  declared one), in which case the row reads "token expired — renews on the
  next `<bin>` run" instead. That text appears regardless of whether
  auto-ping is on — the next time that command runs, by whatever hand runs
  it, it renews the token — but *this app* only runs it for you when
  auto-ping is switched on for that plugin: per-plugin opt-in, off by
  default.
- **Grok checks its own token's expiry before ever asking the endpoint.**
  `~/.grok/auth.json` states an `expires_at` beside the matched entry's key,
  and past it the row reads "token expired — sign in again" without a
  request going out — Grok declares no `[ping]`, so there is no renewal to
  key the "token expired — renews on the next `<bin>` run" text on the way
  Claude's row does above; only the user's own next `grok` login clears it.

## Claude: two surfaces

`claude.toml` declares two `[[surface]]` entries, `cli` and `desktop`, each
with its own credential chain, and any login found gets a section of its
own.

- **CLI / VS Code** reads `~/.claude/.credentials.json` first; only when
  that file is absent does it ask the Keychain, which is when macOS shows
  its prompt. *Don't Allow* leaves the section empty until you relaunch and
  allow it. An account with `CLAUDE_CONFIG_DIR` set reads
  `$CLAUDE_CONFIG_DIR/.credentials.json` instead — this app follows the same
  override for the file, and for the Keychain item name the CLI also renames
  under that variable.
- **Desktop app** is an opt-in in Settings. The desktop app locks its
  Safe-Storage key to itself, so the first read shows a Keychain prompt for
  `Claude Safe Storage` — *Always Allow* and the account populates. On
  Windows the same token is read through DPAPI.
- **A lapsed CLI access token renews itself the next time the CLI runs —
  including a run this app triggers itself, if auto-ping is on for Claude**
  (off by default, like every plugin's ping). `claudeAiOauth.expiresAt`
  (epoch milliseconds) is checked on both the credentials-file and Keychain
  steps; past it, the chain reports the token lapsed rather than handing
  back one that will 401. Because `[ping] renews_token = true`, the
  row reads "token expired — renews on the next claude run" regardless of
  whether auto-ping is on — that text names what the *next* `claude` run
  does, by whoever runs it. With auto-ping on, the app also runs
  `claude -p hello --model haiku` itself, on the same ten-minute floor as
  the window ping, so the CLI renews its own token sooner than the next
  window boundary would otherwise trigger it.
  **This is the CLI row's behavior only.** The Desktop row's own chain
  (`electron-safe-storage`) declares no expiry, so a lapsed or 401'd Desktop
  token is never rewritten and never pings — it keeps the plain "session
  expired — sign in again", because the desktop app renews its own token
  itself, not by way of this app's ping.

The weekly bucket is reported as `seven_day` but in practice resets sooner;
the countdown follows the reset time the provider states, not the name.

**Extra usage** — a separate, pay-as-you-go pool beyond the plan's own
windows — draws its own "Extra usage" row, but only for an account that has
turned it on: the response states `extra_usage.is_enabled` directly, and an
account without it carries every other field in that object as `null`, so
the row simply does not appear rather than showing an empty pair.

## Codex: why it stopped reading logs

Until manifest version 2.0.0, Codex was read from the CLI's rollout logs
(`~/.codex/sessions/**/rollout-*.jsonl`). Three things were wrong with
that, and all three are why it changed:

- A log says what the last session wrote. Leave Codex unused for a day and
  the panel quietly showed yesterday's figures as current.
- A log line carries no identity — a plan tier and nothing else — so the
  address on a row had to be guessed. The endpoint states the address.
- Logs interleave quota families: a `codex exec` run writes a
  `rate_limits` container for a model-specific limit, and "newest line wins"
  showed it as *the* Codex quota — 0 % used while the real weekly window sat
  at 69 %.

The header comment of [`plugins/codex.toml`](../plugins/codex.toml) carries
the same reasoning. The `log-file` engine itself is still shipped and fully
specified for any third-party manifest that wants it.

## Copilot: one caveat

- **The free-tier rows are the one thing written from a client's source
  rather than from an observed response.** With no free account to check
  against, they are either right or draw nothing; they cannot be wrong
  loudly.

An unlimited premium allowance draws "Unlimited", not `cap 0 / remaining 0`:
the response's own `unlimited` flag (a zero `entitlement` beside it) is read
through `[balances.unlimited]`.

## Adding a provider

A sixth provider is a TOML file dropped into the plugins folder — see
[`PLUGIN-ARCHITECTURE.md`](PLUGIN-ARCHITECTURE.md) for the field reference and
[`../CONTRIBUTING.md`](../CONTRIBUTING.md) for the two rules that decide most
questions: the app never prints a figure the provider did not state, and a
mechanism with no consumer is not shipped.
