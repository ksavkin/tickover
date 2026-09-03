//! Keeps `plugins/index.toml` honest against the manifests it sits beside.
//!
//! The index is the one thing "Check updates" trusts before it downloads
//! anything: it names each shipped manifest's `id`/`version` and pins a
//! sha256 the download is checked against *before* the bytes are parsed (see
//! `src/plugin/registry.rs`'s module docs). Nothing re-derives the index from
//! the manifests at build time, so an editor who bumps `codex.toml`'s
//! `version` and forgets the matching entry here ships a registry that either
//! offers an update to a plugin already installed, or refuses every download
//! with a sha256 mismatch — silently, until someone hits it. This test is
//! the thing that hits it first.
//!
//! Read straight off disk (`include_str!`/`fs::read`) rather than through
//! `plugin::seed::DEFAULT_TEMPLATES`: the index is registry data, published
//! at a URL, and is checked against the files it actually points at — not
//! against whatever the seeding step happens to embed.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use tickover::plugin::manifest::PluginManifest;
use tickover::plugin::registry::{sha256_hex, RegistryIndex};

const INDEX: &str = include_str!("../plugins/index.toml");

fn plugins_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("plugins")
}

fn parsed_index() -> RegistryIndex {
    RegistryIndex::from_str(INDEX).unwrap_or_else(|e| panic!("plugins/index.toml: {e}"))
}

#[test]
fn the_index_parses_and_validates() {
    // `RegistryIndex::from_str` runs the same TOML-shape and per-entry
    // checks (id charset, non-empty name/version, 64 lowercase hex sha256, a
    // relative `manifest` path, no duplicate id) a downloaded index would be
    // put through — a shipped index that failed this would mean the app
    // ships something it would itself refuse to fetch.
    let index = parsed_index();
    assert!(
        !index.plugins.is_empty(),
        "plugins/index.toml lists no plugins"
    );
}

#[test]
fn every_entrys_manifest_is_a_bare_filename_next_to_the_index() {
    // `manifest` is resolved against the index's own URL at fetch time
    // (`registry::resolve_manifest_url`); here it doubles as a relative path
    // on disk, and this repo only ever ships the manifest beside the index,
    // one directory deep — a `/` in the field would mean something more
    // elaborate is going on than a shipped provider.
    for entry in &parsed_index().plugins {
        assert!(
            !entry.manifest.contains('/') && !entry.manifest.contains('\\'),
            "plugin \"{}\": `manifest = \"{}\"` must be a bare filename",
            entry.id,
            entry.manifest,
        );
        let path = plugins_dir().join(&entry.manifest);
        assert!(
            path.is_file(),
            "plugin \"{}\": `manifest = \"{}\"` names a file that does not exist ({})",
            entry.id,
            entry.manifest,
            path.display(),
        );
    }
}

#[test]
fn every_entrys_sha256_matches_the_manifest_bytes_on_disk() {
    // Byte-exact, the same way `verify_and_prepare` checks a download: read
    // as raw bytes, never through a `String` (a re-encoded manifest would
    // still hash the same content but is not what this guards — a hand-typed
    // hex string that no longer matches the file is).
    for entry in &parsed_index().plugins {
        let path = plugins_dir().join(&entry.manifest);
        let bytes = fs::read(&path)
            .unwrap_or_else(|e| panic!("plugin \"{}\": reading {}: {e}", entry.id, path.display()));
        let actual = sha256_hex(&bytes);
        assert_eq!(
            actual, entry.sha256,
            "plugin \"{}\": plugins/index.toml's sha256 is stale — `{}` was edited without \
             re-running `shasum -a 256 plugins/{}` and updating the entry",
            entry.id, entry.manifest, entry.manifest,
        );
    }
}

#[test]
fn every_entrys_manifest_parses_and_its_id_and_version_match_the_index() {
    for entry in &parsed_index().plugins {
        let path = plugins_dir().join(&entry.manifest);
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("plugin \"{}\": reading {}: {e}", entry.id, path.display()));
        let manifest = PluginManifest::from_str(&contents).unwrap_or_else(|e| {
            panic!(
                "plugin \"{}\": {} does not parse: {e}",
                entry.id, entry.manifest
            )
        });
        assert_eq!(
            manifest.id, entry.id,
            "plugins/index.toml's id for {} (\"{}\") does not match the manifest's own id (\"{}\")",
            entry.manifest, entry.id, manifest.id,
        );
        assert_eq!(
            manifest.version, entry.version,
            "plugins/index.toml's version for \"{}\" (\"{}\") does not match {}'s own version \
             (\"{}\") — bump one or the other",
            entry.id, entry.version, entry.manifest, manifest.version,
        );
    }
}

#[test]
fn every_shipped_manifest_is_listed_in_the_index_exactly_once() {
    // The other direction from the tests above: not just "does every entry
    // point at a real file" but "does every file have an entry" — the check
    // that catches a sixth manifest dropped into `plugins/` and never added
    // to the index, which would ship silently with no way for "Check
    // updates" to ever offer it.
    let on_disk: Vec<String> = fs::read_dir(plugins_dir())
        .expect("plugins/ directory must exist")
        .map(|entry| {
            entry
                .expect("reading plugins/ entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.ends_with(".toml") && name != "index.toml")
        .collect();
    assert!(
        !on_disk.is_empty(),
        "plugins/ has no shipped manifests to check the index against"
    );

    let index = parsed_index();
    let listed: Vec<String> = index.plugins.iter().map(|e| e.manifest.clone()).collect();

    for name in &on_disk {
        let occurrences = listed.iter().filter(|m| *m == name).count();
        assert_eq!(
            occurrences, 1,
            "plugins/{name} is listed {occurrences} times in plugins/index.toml (expected exactly 1)",
        );
    }

    let on_disk_set: HashSet<&str> = on_disk.iter().map(String::as_str).collect();
    for name in &listed {
        assert!(
            on_disk_set.contains(name.as_str()),
            "plugins/index.toml lists \"{name}\", which is not a file in plugins/",
        );
    }
}
