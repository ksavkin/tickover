# Configuration, files and switches

There is nothing to configure before first use: the app reads the logins
your CLIs already hold. This page is for when you want to know where its
files are, what each one holds, and which switches exist.

## Where its files live

Apart from the launch-at-login entry, everything the app writes for itself
lives in one folder:

| Platform | Folder |
|---|---|
| macOS | `~/Library/Application Support/tickover/` |
| Windows | `%APPDATA%\tickover\` |

| File | What it is |
|---|---|
| `config.json` | preferences and per-plugin toggles (`plugin.<id>.enabled`, `.ping`, `.surface.<sid>`, `.option.<key>`) — except that for `codex` and `claude` the ping toggle lives under the top-level `auto_ping_codex` / `auto_ping_claude` keys instead, and Claude's desktop surface under `monitor_desktop`, kept for settings-file compatibility; `plugin.codex.ping` itself is never read — plus two derived facts the auto-ping works from: when a stated window is due to reset and when a ping last fired. No percentage, no balance, no token. |
| `plugins/*.toml` | the provider manifests — seeded from the shipped copies on first run, yours to edit or add to afterwards |
| `tickover.log` | timestamped diagnostics, trimmed to its last ~32 KB once it passes 64 KB; never carries a token |
| `registry-state.json` | origin URL, version and sha256 of anything installed from a registry — provenance, and how a local edit is detected |
| `instance.lock` | held by the running copy, so a second launch opens the first one's panel and exits; released however the process ends, so there is no stale file to clean up |
| `show-panel` | the hand-off a second launch leaves for the running copy; removed as soon as it is acted on |
| `ping-workdir/` | present only when the OS temp directory can't be used for a ping's working directory. Each ping still gets its own fresh, empty, owner-only subdirectory in here, removed once the command exits — this folder itself is not, so an empty one can persist. The normal case runs the ping from the OS's own temp directory instead, never from here |

`config.json` and the manifests are plain text and safe to edit by hand
while the app is not running. On Windows, save them as UTF-8
**without** a byte-order mark if your editor offers the choice: the app
strips one if it finds it, other tools reading the same files may not. A
hand-edit that leaves `config.json` unparsable, or turns it into JSON that
parses but isn't an object (an array, a bare string, a number, `null`), is
not fatal: the app moves the broken file aside to `config.json.corrupt-<unix
time>` (or a `-<n>`-suffixed sibling, on the rare chance that name is already
taken) and starts fresh with defaults rather than silently overwriting your
edit the next time a setting is saved — the renamed copy is yours to recover
values from by hand.

An install of the app under its previous name (a `codex-limits` folder in
the same place) is renamed to `tickover` on the first launch, with its
settings and plugins intact.

## Settings

The gear in the panel's header opens the settings sheet: launch at login,
the tray reading, and then one row per installed manifest with the engine
it declares, an enable switch, and whatever toggles it exposes — the
auto-ping, an opt-in surface such as the Claude desktop app, or a boolean
`[[option]]` of its own. Nothing in the sheet is written for a specific
provider; a manifest you add gets the same row.

*Reset plugins* re-seeds just the shipped manifests without touching
anything else you have dropped into the folder. *Check updates* fetches the
registry index and offers to install or update what it lists — see
[`PLUGIN-ARCHITECTURE.md`](PLUGIN-ARCHITECTURE.md) for what is verified and
what is not.

The refresh cadence is not a setting: it is a manifest field
(`refresh_secs`), a minute for four of the shipped manifests and five for
Copilot, whose allowance is monthly.

## Environment variables

| Variable | Effect |
|---|---|
| `TICKOVER_DOCK=1` / `=0` | keep the panel on screen as an ordinary window, reachable from the Dock or the taskbar and no longer dismissed by a click outside it. Writes the setting, so it sticks; `=0` clears it. See [`DOCK-MODE.md`](DOCK-MODE.md). |
| `TICKOVER_SHOW_ON_START=1` | open the panel immediately on launch |
| `TICKOVER_SNAPSHOT=out.png` | render the panel to a PNG and exit — not on Windows; add `TICKOVER_SNAPSHOT_SETTINGS=1` for the settings sheet |
| `TICKOVER_THEME=light` / `=dark` | force the tray pill's palette instead of following the system appearance |
| `TICKOVER_DEMO_ACCOUNT=you@example.com` | show this in place of the real account label — for screenshots; it rewrites the label only, never the reading or the token |
| `CODEX_HOME=/path` | honoured by the `log-file` engine's `root_env`; the shipped Codex manifest no longer uses it |
| `TICKOVER_ANTIGRAVITY_CLIENT_ID` / `TICKOVER_ANTIGRAVITY_CLIENT_SECRET` | override the OAuth client pair the Antigravity manifest otherwise reads from the installed Antigravity app or `agy` binary; set both or neither |
| `SLINT_BACKEND` | Slint toolkit variable, honoured as-is — the app only defaults it to `winit` when unset; set it yourself to override the UI backend |

## When something goes wrong

Read `tickover.log`. It exists because an app launched from Finder has no
stderr anywhere — not in Console, not in the unified log — and the auto-ping
once failed on every attempt, said so each time, and still looked like a
feature that had never run.

```
2026-08-20T12:57:25+03:00 auto-ping: running /Users/…/codex exec --skip-git-repo-check --sandbox read-only hello
2026-08-20T12:57:30+03:00 auto-ping: /Users/…/codex finished
```

It says two things the panel deliberately does not: that a shipped manifest
is missing because you deleted it (which holds — *Reset plugins* restores
it), and that a provider's row vanished because its credential is gone. A
token that is merely no longer accepted is a different state: the row stays
and reads "session expired — sign in again" — unless the provider's own
`[ping]` can renew it (Claude's does), in which case the row instead reads
"token expired — renews on the next claude run". That text appears
regardless of whether auto-ping is switched on: the next time that command
runs, by whatever hand runs it, it renews the token as a side effect, and
the row states that plainly either way. That rewrite applies to the CLI row
only: Claude's Desktop row keeps "session expired — sign in again", because
the desktop app renews its own token itself, not by way of this app's ping.
Whether *this app* also runs that command itself, outside its usual
schedule, is the separate question the toggle actually answers: like the
window ping it shares a schedule with, that part is per-plugin opt-in and
off by default — with it off, the row still names the command that renews
the token, but nothing runs it on your behalf.

## Uninstalling

Switch *Launch at login* off first (macOS keeps it as a login item, Windows
as a `…\CurrentVersion\Run` entry), quit, then delete the app and the folder
above. Your CLIs' own credentials are untouched — this app never wrote them.
