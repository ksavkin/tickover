//! Hermetic regression test for the generic log-file engine
//! ([`tickover::plugin::engine_logfile`]), driven by a Codex-like manifest.
//!
//! Uses a checked-in fixture so it never touches `$HOME`. The fixture contains
//! two `rate_limits` lines; the reader must return the **last** one, and its
//! numbers must match the ground truth captured from a real Codex session.

use std::path::PathBuf;

use tickover::plugin::engine_logfile;
use tickover::plugin::manifest::PluginManifest;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// A private, one-off copy of the oracle fixture, nested one level under a
/// fresh temp directory — for the "recursive walk from a parent directory"
/// test below, which needs a `root` whose fixture is *not* directly inside
/// it. `collect_log_files` walks every file under `root` and matches by
/// basename alone (`engine_logfile::glob_matches` only looks at the part of
/// `glob` after its last path separator), so pointing that test at the real,
/// checked-in `tests/` directory — the fixture's own parent's parent — would
/// let any other `rollout-*.jsonl` fixture ever placed anywhere else under
/// `tests/` change what "exactly one reading" there actually proves. A
/// private nested copy has nothing else under it to find.
fn isolated_nested_fixture() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "tickover-reader-nested-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let nested = root.join("nested");
    std::fs::create_dir_all(&nested).expect("create a nested temp dir");
    std::fs::copy(
        fixtures_dir().join("rollout-sample.jsonl"),
        nested.join("rollout-sample.jsonl"),
    )
    .expect("copy the oracle fixture into it");
    root
}

/// A Codex-like manifest whose `[logfile].root` is the fixture directory
/// itself (an absolute, literal path — `expand_home` leaves it unchanged).
/// No `root_env` is set, so the test never touches a real environment
/// variable.
///
/// The root is escaped for the TOML basic string it lands in: on Windows it
/// arrives as `D:\a\tickover\…`, and TOML reads a backslash there as the
/// start of an escape sequence rather than as a path separator.
fn codex_like_manifest(root: &std::path::Path, glob: &str) -> PluginManifest {
    let root = root
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let toml = format!(
        r#"
        id           = "codex"
        name         = "Codex"
        menu_label   = "Cx"
        order        = 10
        engine       = "log-file"

        [tag]
        from = "field"
        path = "plan_type"
        transform = "uppercase"

        [[windows]]
        label = "5H"
        role  = "primary"
        [windows.period]
        mode  = "from_field"
        field = "window_minutes"
        [windows.source]
        used_percent_path  = "used_percent"
        resets_at_path     = "resets_at"
        max_period_minutes = 720

        [[windows]]
        label = "WK"
        role  = "secondary"
        [windows.period]
        mode  = "from_field"
        field = "window_minutes"
        [windows.source]
        used_percent_path  = "used_percent"
        resets_at_path     = "resets_at"
        min_period_minutes = 721

        [logfile]
        root          = "{root}"
        glob          = "{glob}"
        container_key = "rate_limits"
        "#,
    );
    PluginManifest::from_str(&toml).expect("valid test manifest")
}

#[test]
fn parses_last_reading_matching_oracle() {
    let m = codex_like_manifest(&fixtures_dir(), "**/rollout-*.jsonl");
    let readings = engine_logfile::fetch(&m, &[], &std::collections::BTreeMap::new());
    assert_eq!(
        readings.len(),
        1,
        "one reading for this single-surface manifest"
    );
    let reading = &readings[0];
    assert!(
        reading.error.is_none(),
        "the fixture has rate_limits lines to find"
    );

    let primary = reading.primary_window().expect("primary (5h) window");
    let secondary = reading
        .secondary_window()
        .expect("secondary (weekly) window");

    // Ground truth captured from the live session via the Python reference.
    assert_eq!(
        primary.used_percent,
        Some(11.0),
        "must take the LAST reading, not 3%"
    );
    assert_eq!(primary.resets_at, Some(1783216497));
    assert_eq!(primary.period_minutes, Some(300));

    assert_eq!(
        secondary.used_percent,
        Some(72.0),
        "must take the LAST reading, not 50%"
    );
    assert_eq!(secondary.resets_at, Some(1783614509));
    assert_eq!(secondary.period_minutes, Some(10080));

    assert_eq!(reading.tag.as_deref(), Some("PROLITE"));
}

#[test]
fn fetch_falls_back_across_files_when_pointed_at_a_parent_directory() {
    // The fixture lives one level down from `root` here too (a private copy,
    // not `tests/fixtures/rollout-sample.jsonl` itself — see
    // `isolated_nested_fixture`'s own doc for why): pointing the manifest's
    // root at its parent proves the engine's glob walk is recursive, not a
    // flat listing of `root` itself.
    let root = isolated_nested_fixture();
    let m = codex_like_manifest(&root, "rollout-*.jsonl");
    let readings = engine_logfile::fetch(&m, &[], &std::collections::BTreeMap::new());

    assert_eq!(readings.len(), 1);
    assert!(
        readings[0].error.is_none(),
        "should find a reading via the recursive glob walk"
    );
    assert_eq!(
        readings[0].primary_window().unwrap().used_percent,
        Some(11.0)
    );
    std::fs::remove_dir_all(&root).ok();
}
