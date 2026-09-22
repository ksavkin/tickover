//! End-to-end history pipeline against fixture directories — the suite's
//! proof that scanning real-shaped provider files lands in the store and
//! that nothing but usage metadata ever does.
//!
//! The privacy sentinel test is the load-bearing one: fixture transcripts
//! carry a marker string inside `message.content` (a prompt) and the test
//! asserts it appears nowhere in `state.json`, `days.jsonl`, or the
//! rendered HTML report. If an extractor ever started persisting message
//! bodies, this is the test that would catch it.

#![cfg(feature = "history")]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use tickover::history::{query, report, scan_tick, store::HistoryStore};
use tickover::plugin::manifest::PluginManifest;

const SENTINEL: &str = "SENTINEL-PROMPT-9f3ac7b2";

fn tmpdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tickover-e2e-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn manifest(id: &str, format: &str, root: &std::path::Path, glob: &str) -> PluginManifest {
    let text = format!(
        r#"
id         = "{id}"
name       = "Sample"
menu_label = "Sa"
order      = 1
engine     = "log-file"
requires_reader = ["reading-history"]

[[windows]]
label = "5H"
role  = "primary"
[windows.period]
mode    = "assumed"
assumed = 300
[windows.source]
used_percent_path = "used_percent"
resets_at_path    = "resets_at"

[logfile]
root          = "{root}"
glob          = "*.jsonl"
container_key = "rate_limits"

[history]
format = "{format}"
root   = "{root}"
glob   = "{glob}"
"#,
        root = root.display()
    );
    PluginManifest::from_str(&text).unwrap_or_else(|e| panic!("fixture manifest: {e}"))
}

/// A Claude transcript: one assistant usage line, one sidechain (skipped),
/// one user line carrying the sentinel prompt.
fn claude_fixture() -> String {
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S.000Z");
    [
        format!(
            r#"{{"type":"user","timestamp":"{now}","sessionId":"sess-1","cwd":"/work/proj-a","message":{{"role":"user","content":"{SENTINEL}"}}}}"#
        ),
        format!(
            r#"{{"type":"assistant","timestamp":"{now}","sessionId":"sess-1","cwd":"/work/proj-a","message":{{"id":"msg-1","model":"claude-opus-4","usage":{{"input_tokens":1000,"output_tokens":200,"cache_read_input_tokens":5000,"cache_creation_input_tokens":300}}}}}}"#
        ),
        format!(
            r#"{{"type":"assistant","timestamp":"{now}","sessionId":"sess-1","isSidechain":true,"cwd":"/work/proj-a","message":{{"id":"msg-side","model":"claude-opus-4","usage":{{"input_tokens":999999,"output_tokens":1}}}}}}"#
        ),
        format!(r#"{{"type":"assistant","timestamp":"{now}","sessionId":"sess-1","cwd":"/work/proj-a","message":{{"id":"msg-1","model":"claude-opus-4","usage":{{"input_tokens":1000,"output_tokens":200,"cache_read_input_tokens":5000,"cache_creation_input_tokens":300}}}}}}"#),
    ]
    .join("\n")
        + "\n"
}

/// A Codex rollout: session_meta + turn_context + two token_count events
/// (cumulative — the diff must be taken), one user line with the sentinel.
fn codex_fixture() -> String {
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S.000Z");
    [
        format!(
            r#"{{"type":"session_meta","timestamp":"{now}","payload":{{"type":"session_meta","id":"codex-s1","cwd":"/work/proj-b"}}}}"#
        ),
        format!(
            r#"{{"type":"user_message","timestamp":"{now}","payload":{{"type":"user_message","message":"{SENTINEL}"}}}}"#
        ),
        format!(
            r#"{{"type":"turn_context","timestamp":"{now}","payload":{{"type":"turn_context","cwd":"/work/proj-b","model":"gpt-5.2-codex"}}}}"#
        ),
        format!(
            r#"{{"type":"event_msg","timestamp":"{now}","ordinal":1,"payload":{{"type":"token_count","info":{{"total_token_usage":{{"input_tokens":4000,"cached_input_tokens":1500,"output_tokens":300,"reasoning_output_tokens":50}},"last_token_usage":{{"input_tokens":4000,"cached_input_tokens":1500,"output_tokens":300,"reasoning_output_tokens":50}}}}}}}}"#
        ),
        format!(
            r#"{{"type":"event_msg","timestamp":"{now}","ordinal":2,"payload":{{"type":"token_count","info":{{"total_token_usage":{{"input_tokens":9000,"cached_input_tokens":3000,"output_tokens":800,"reasoning_output_tokens":120}},"last_token_usage":{{"input_tokens":5000,"cached_input_tokens":1500,"output_tokens":500,"reasoning_output_tokens":70}}}}}}}}"#
        ),
    ]
    .join("\n")
        + "\n"
}

#[test]
fn scan_then_query_matches_the_fixture() {
    let store_dir = tmpdir("store");
    let claude_root = tmpdir("claude");
    let codex_root = tmpdir("codex");
    fs::create_dir_all(claude_root.join("proj-a")).unwrap();
    fs::write(
        claude_root.join("proj-a/sess-1.jsonl"),
        claude_fixture(),
    )
    .unwrap();
    fs::write(codex_root.join("rollout-1.jsonl"), codex_fixture()).unwrap();

    let manifests = vec![
        manifest("claude", "claude-transcripts", &claude_root, "**/*.jsonl"),
        manifest("codex", "codex-rollouts", &codex_root, "rollout-*.jsonl"),
    ];
        let mut store = HistoryStore::open(&store_dir).unwrap();

    let scans = scan_tick(&mut store, &manifests, &|_| BTreeMap::new());
    assert_eq!(scans.len(), 2, "both providers scanned");
    for s in &scans {
        assert!(!s.root_missing, "{} fixture root missing", s.provider);
    }

    let st = query::compute(&store, 30);
    // Claude: msg-1 counted once (the duplicate line dedups on message id),
    // the sidechain's 999999 tokens never land.
    let cl = &st.by_provider["claude"];
    assert_eq!(cl.input, 1000);
    assert_eq!(cl.output, 200);
    assert_eq!(cl.cache_read, 5000);
    assert_eq!(cl.cache_write, 300);
    assert_eq!(cl.messages, 1);
    assert_eq!(st.projects.len(), 2, "proj-a + proj-b");
    // Codex: cumulative 4000→9000 input diffs to 9000 total, of which the
    // 3000 cached subset lands in cache_read — `input` is the uncached
    // remainder (Codex's input_tokens includes the cached part).
    let cx = &st.by_provider["codex"];
    assert_eq!(cx.input, 6000);
    // …and output_tokens carries the reasoning subset the same way:
    // 800 total = 680 ordinary + 120 thinking.
    assert_eq!(cx.output, 680);
    assert_eq!(cx.thinking, 120);
    assert_eq!(cx.cache_read, 3000);

    // A second tick rescans nothing new and counts nothing twice.
    let scans = scan_tick(&mut store, &manifests, &|_| BTreeMap::new());
    for s in &scans {
        assert!(!s.root_missing);
    }
    let st2 = query::compute(&store, 30);
    assert_eq!(st2.by_provider["claude"].input, 1000);
    assert_eq!(st2.by_provider["codex"].input, 6000);

    for d in [&store_dir, &claude_root, &codex_root] {
        let _ = fs::remove_dir_all(d);
    }
}

#[test]
fn nothing_but_usage_metadata_leaves_the_extractor() {
    let store_dir = tmpdir("priv-store");
    let root = tmpdir("priv-claude");
    fs::create_dir_all(root.join("p")).unwrap();
    fs::write(root.join("p/s.jsonl"), claude_fixture()).unwrap();
    fs::write(root.join("rollout-r.jsonl"), codex_fixture()).unwrap();

    let manifests = vec![
        manifest("claude", "claude-transcripts", &root, "**/*.jsonl"),
        manifest("codex", "codex-rollouts", &root, "rollout-*.jsonl"),
    ];
    let mut store = HistoryStore::open(&store_dir).unwrap();
    let _ = scan_tick(&mut store, &manifests, &|_| BTreeMap::new());
    store.commit().unwrap();

    // The sentinel prompt is in the fixture twice (a user line per format);
    // it must be in neither persistent file nor the report.
    let state = fs::read_to_string(store_dir.join("state.json")).unwrap();
    let days = fs::read_to_string(store_dir.join("days.jsonl")).unwrap();
    for (name, content) in [("state.json", &state), ("days.jsonl", &days)] {
        assert!(
            !content.contains(SENTINEL),
            "{name} persisted prompt content"
        );
    }

    let st = query::compute(&store, 30);
    let report_path = store_dir.join("report.html");
    let written = report::write(&st, Some(report_path.clone()), false, &[], &[]).unwrap();
    let html = fs::read_to_string(&written).unwrap();
    assert!(!html.contains(SENTINEL), "report leaked prompt content");

    // The report file is created owner-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&written).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "report must be mode 0600, got {mode:o}");
    }

    for d in [&store_dir, &root] {
        let _ = fs::remove_dir_all(d);
    }
}
