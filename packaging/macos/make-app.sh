#!/usr/bin/env bash
# Assemble a distributable "Tickover.app" from a release build.
#
#   cargo build --release
#   ./packaging/macos/make-app.sh
#
# Produces ./dist/Tickover.app  (a menu-bar accessory — LSUIElement).
#
# Takes the binary to bundle as an optional first argument, defaulting to the
# release build's own path — a caller assembling a cross-compiled or
# otherwise differently-located binary can point this at it directly instead
# of relying on `cargo build --release` having just run.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP="$ROOT/dist/Tickover.app"
BIN="${1:-$ROOT/target/release/tickover}"

if [[ ! -x "$BIN" ]]; then
  echo "Release binary not found at $BIN. Run: cargo build --release" >&2
  exit 1
fi

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cp "$BIN"                              "$APP/Contents/MacOS/tickover"
cp "$ROOT/packaging/macos/Info.plist"  "$APP/Contents/Info.plist"
cp "$ROOT/assets/app.icns"             "$APP/Contents/Resources/app.icns"

# The plist in the tree carries whatever version it was last edited to say —
# `Cargo.toml`'s `[package]` line is the one place this build actually states
# its own version, so the copy (never the source plist) is stamped from it
# here, and the bundle can never ship a stale one by omission. `head -1`
# picks the package's own `version =`, the only one that starts a line —
# every dependency's sits inside an inline table further right.
VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -1)"
if [[ -z "$VERSION" ]]; then
  echo "Could not read [package] version from Cargo.toml" >&2
  exit 1
fi
sed -i '' \
  -e "/<key>CFBundleVersion<\/key>/{n;s#<string>.*</string>#<string>$VERSION</string>#;}" \
  -e "/<key>CFBundleShortVersionString<\/key>/{n;s#<string>.*</string>#<string>$VERSION</string>#;}" \
  "$APP/Contents/Info.plist"

# Ad-hoc sign so Gatekeeper lets a local build run. Only a missing
# `codesign` is tolerated here — a checkout with no Developer Tools has
# nothing to sign with and no need to. If it is present and signing (or the
# verification after it) fails, that is a real problem with this build, not
# an optional step, so the script stops and shows codesign's own stderr
# rather than shrugging past it the way the missing-tool case does.
if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign - "$APP"
  codesign --verify --deep --strict "$APP"
else
  echo "note: codesign not found — skipping ad-hoc signing (optional for local use)"
fi

echo "Built: $APP"
echo "Run:   open \"$APP\"   (or drag it to /Applications)"
