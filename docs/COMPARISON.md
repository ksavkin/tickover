# Compared with the neighbours

There are a dozen or so menu-bar meters for these quotas. Four of the
better-documented ones, side by side with Tickover. Every cell comes from
that project's README as read on 2 September 2026; `?` means the README
does not say, and everything here will drift — these projects ship weekly.
Corrections welcome.

| | **Tickover** | [CodexBar](https://github.com/steipete/CodexBar) | [ClaudeBar](https://github.com/tddworks/ClaudeBar) | [usage](https://github.com/aqua5230/usage) | [AI Usage](https://github.com/burakgon/ai-usage-menubar) |
|---|---|---|---|---|---|
| Starts the next window for you (pre-warm) | yes — per provider, off by default | — | — | — | — |
| Platforms | macOS, Windows — one codebase | macOS 14+ (Windows is a separate project; Linux via community ports) | macOS 15+ | macOS 12+, Windows 10/11 | macOS 26+ |
| Built with | Rust + Slint, about 8 MB per architecture | Swift | Swift 6.2 | Python | Swift 6 / SwiftUI |
| Providers shipped | 5 | 68+ | 13 | 4 | 7 |
| Where a quota comes from | the provider's usage API, with the login your CLI holds; host pinned per manifest | provider configs, local logs, browser cookies (opt-in) | probes the CLIs; APIs; browser cookies for one | local log files (Claude, Codex); Google's endpoint (Antigravity) | first-party endpoints with existing credentials |
| Adding a provider | a TOML file, no rebuild | ? | a Swift probe | ? | ? |
| Cost / token accounting | none, by rule | spend charts, dashboards | ? | cost reports, burn rate | ? |
| Notifications | none | incident badges | system notifications | service-status alerts | ? |
| Install | zip from Releases, or build from source | Homebrew, releases, AUR | Homebrew, signed DMG | Homebrew, `uvx`, Windows binary | signed DMG |
| Signed release | not yet | ? | yes | yes (SignPath) | yes |
| License | MIT or Apache-2.0 | MIT | MIT | AGPL-3.0 | MIT |

The first row is the one this project exists for. Nobody else's README
describes starting a window automatically; people do it by hand with a cron
job or a scheduled routine that fires a prompt at a fixed hour. Tickover
does it on the condition that matters — the window is empty — for every
provider whose manifest declares a ping, and never more than once per
window.

Where this project is behind: no installer or package-manager install, no
signed release yet, no notifications, a dark-only panel, and five providers
against thirteen or sixty-eight. Where it is not: a provider is a text file, both desktops ship
from one tree, and the list of what leaves the machine fits in five lines
([`../SECURITY.md`](../SECURITY.md)).

Also in the niche, not tabulated:
[claude-codex-limits](https://github.com/ArrivaRUS/claude-codex-limits)
(Claude + Codex, one Swift file),
[ModelDeck](https://github.com/timharris707/modeldeck) (multi-account
switching, noncommercial licence),
[Usage4Claude](https://github.com/f-is-h/usage4claude) (browser-login auth).
