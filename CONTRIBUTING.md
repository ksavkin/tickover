# Contributing

The most useful contribution to this project usually contains no Rust at all.

## Adding a provider is writing a TOML file

Providers are not modules. Each one is a manifest — where the token lives, what
endpoint to call, which numbers in the answer are which — and the engine reads
it. Five ship in `plugins/`; a sixth is a file you drop into the plugins
folder. Start from `docs/PLUGIN-ARCHITECTURE.md`, which is the reference for
every field, and from the shipped manifests, which are commented with why each
path is the path it is.

Each shipped manifest also has an entry in `plugins/index.toml`, the registry
"Check updates" reads — editing a shipped manifest without bumping that
entry's `version` and `sha256` breaks the download for everyone reading the
stale hash against the new bytes; `tests/registry_index.rs` fails the build
over exactly that mismatch.

Two rules decide most questions before they are asked:

- **The app never prints a figure the provider did not state.** A percentage
  computed from something else is out, and so is a number scraped from a web
  page or estimated from local logs. The one licensed conversion is
  complementing a stated *remaining* fraction into the consumed percent a
  window holds — a change of units, reversible, information-preserving.
- **A mechanism with no consumer is not shipped.** If a manifest key would have
  nothing to read on any account anyone here can see, it waits.

## Building and running

```bash
cargo build --release          # rust-toolchain.toml asks for stable
./packaging/macos/make-app.sh  # bundles dist/Tickover.app (macOS)
cargo run                      # dev run, tray glyph in the menu bar
```

`docs/DEVELOPMENT.md` carries the rest: the pinned `tray-icon` version and why,
how to take a headless screenshot, what the plugin modules are.

## Tests: run them under a substituted `HOME`

```bash
REAL_HOME="$HOME"; FH=$(mktemp -d)
HOME="$FH" CARGO_HOME="$REAL_HOME/.cargo" RUSTUP_HOME="$REAL_HOME/.rustup" cargo test
```

Parts of the suite resolve the plugins folder and this app's config directory
from the real `HOME`. Today nothing writes there, but that is a measurement
rather than something the code enforces: a test run must never touch the
live install, since writing a "this manifest was already delivered" marker
into it would keep a shipped provider out of the panel for good.
`docs/DEVELOPMENT.md` has the whole story.

## What a change is expected to carry

- **`cargo clippy --all-targets` stays silent.** It is silent today. If a lint
  is wrong for a specific line, `#[allow]` it *with the reason on the line* —
  there are three such allows in the tree and each says what breaks otherwise.
- **A new manifest key ships with four things in the same change:** its
  spelling in the matching `CAPABILITIES` entry's `keys` (`src/plugin/capability.rs`),
  a row in `tests/manifest_corpus.rs` if it adds a way to refuse a manifest, a
  negative test, and a golden. The capability list is what lets an older build
  refuse a manifest from the future *out loud* instead of misreading it
  quietly, and a key missing from it defeats exactly that.
- **A test that watches behaviour, not a method.** The suite has several tests
  whose whole point is that a plausible-looking simplification breaks
  something; `a_selector_matches_a_number_or_a_boolean_by_the_text_it_prints`
  exists because a clippy suggestion would otherwise have passed the suite
  while breaking every non-string selector.

**`cargo fmt --check` is a CI gate**, run on the macOS job only — formatting
is platform-independent, so one job saying so is enough. Run
`cargo fmt` before you push; a formatting pass on a tree that was already
formatted with it does not bury the history of files whose comments carry
most of the reasoning, but running it on your own diff up front is cheaper
than a red build. Match the surrounding style for everything the tool
itself does not decide (naming, comment density, doc-comment shape).

## CI

`.github/workflows/ci.yml` builds and tests on macOS and Windows on every
push to `main` or `dev` and on every pull request; a change that only
touches documentation is skipped. It can also be run by hand
(`gh workflow run CI --ref <branch>`) — do that before merging anything that
touches the Windows halves of `auth.rs`, `config.rs`, `seed.rs` or
`engine_logfile.rs`, none of which can be compiled on a Mac. Releases are a
separate workflow, described in `docs/RELEASING.md`.

## Security-relevant changes

Read `SECURITY.md` first. A change that widens what a manifest can reach — a
new credential store, a new place a token may be substituted into, a relaxation
of `allowed_hosts` — is a trust-model change and should say so in its commit
message, whatever its size.
