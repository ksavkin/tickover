# Releasing

A release is a tag. Pushing one is the only thing that makes
`.github/workflows/release.yml` publish anything; a manual run of the same
workflow builds without releasing, for rehearsal.

## Cutting one

```bash
# 1. Bump the version and let the lockfile follow it.
$EDITOR Cargo.toml   # [package] version = "X.Y.Z"
cargo build          # rewrites Cargo.lock's own version entry to match

# 2. Commit and tag, on main.
git switch main && git pull
git commit -am "Release vX.Y.Z"
git tag vX.Y.Z
git push origin main vX.Y.Z
```

The tag has to match `Cargo.toml`: an early step, before either platform
compiles, checks for the exact line `version = "X.Y.Z"` and fails if the
bump was forgotten, or the build that refreshes `Cargo.lock` was. The
build job then runs the whole test suite on both platforms before
packaging — a tag can land on a commit that CI skipped (documentation-only
pushes are), and the release must not be the first build that skips the
tests.

`workflow_dispatch` runs the same build jobs against a branch, so a change to
the steps can be rehearsed before it runs unattended on a real tag. A
dispatch run never drafts a release — there is no version to name one after
— but it leaves the zips and their checksums as a run artifact to inspect.

## What comes out

Three files, attached to a **draft** release named after the tag:

- `Tickover-vX.Y.Z-macos-universal.zip` — `Tickover.app`, built for both
  `aarch64` and `x86_64` on one `macos-latest` runner and joined with `lipo`,
  so one download runs on Apple silicon and Intel alike.
- `tickover-vX.Y.Z-windows-x86_64.zip` — the bare `tickover.exe`.
- `SHA256SUMS.txt` — checksums for both zips.

Draft, not published: nothing downloads it until a human opens the page,
reads the generated notes, and presses Publish — the point where a bad build
gets caught before anyone outside this repository sees it.

## Signing

Neither binary is signed by an identity a system trusts yet. The macOS `.app`
is ad-hoc signed by `make-app.sh` and the workflow verifies that signature
before zipping — enough for Gatekeeper to run it locally, not enough to skip
its warning on a download. Expect:

- **macOS:** "Apple could not verify this app is free of malware." Right-click
  the app → Open, or System Settings → Privacy & Security → Open Anyway; or
  strip the quarantine flag: `xattr -d com.apple.quarantine Tickover.app`.
- **Windows:** SmartScreen's "Windows protected your PC" / unknown publisher.
  More info → Run anyway.

The plan is to remove both warnings, not document them forever: **SignPath
Foundation** signs Windows builds for open-source projects for free, once a
project is public, OSI-licensed, and already shipping releases in the form it
would sign — true here once the repository is public (it is still private)
and a release has been published, not merely tagged. Apple's side needs a paid
Developer ID (**$99/year**) and `notarytool` in CI — a later step, once
downloads justify it.
