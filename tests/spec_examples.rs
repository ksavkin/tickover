//! Keeps the two full manifest listings in `docs/PLUGIN-ARCHITECTURE.md`
//! honest against the files they claim to reproduce.
//!
//! The "Full example" sections for `codex.toml` and `claude.toml` each say
//! "Shipped verbatim as `plugins/<name>.toml`" and paste the manifest in full.
//! Nothing regenerates that paste from the shipped file, so an editor who
//! touches `plugins/codex.toml` and not the doc ships two copies that
//! silently disagree — which is how the embedded copies drifted before this
//! test existed: a stale version, a missing `[status]`, a ping command that
//! never worked, and a claude.toml example that did not even validate.
//! Byte comparison, not TOML parsing: the doc has to read exactly what ships.

use std::fs;
use std::path::PathBuf;

const DOC: &str = include_str!("../docs/PLUGIN-ARCHITECTURE.md");
const CODEX_HEADING: &str = "## Full example: `codex.toml` (http-api)";
const CLAUDE_HEADING: &str = "## Full example: `claude.toml` (http-api, two surfaces)";

fn plugins_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("plugins")
}

/// A heading, and the shipped file its first fenced block after it must
/// match byte-for-byte.
fn examples() -> [(&'static str, &'static str); 2] {
    [
        (CODEX_HEADING, "codex.toml"),
        (CLAUDE_HEADING, "claude.toml"),
    ]
}

#[test]
fn each_full_example_heading_appears_exactly_once() {
    // A duplicated heading would make "the first fenced block after it"
    // ambiguous — this is what the extraction below relies on.
    for (heading, _) in examples() {
        let count = DOC.lines().filter(|line| *line == heading).count();
        assert_eq!(
            count, 1,
            "docs/PLUGIN-ARCHITECTURE.md must have exactly one `{heading}` heading, found {count}",
        );
    }
}

#[test]
fn the_full_examples_match_the_shipped_manifests_byte_for_byte() {
    for (heading, filename) in examples() {
        let block = first_toml_block_after(DOC, heading);
        let path = plugins_dir().join(filename);
        let shipped =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        assert_blocks_match(block, &shipped, filename);
    }
}

/// The first fenced block (` ```toml ` up to the next bare ` ``` `) after the
/// exact heading line `heading`. Panics naming what is missing — an absent
/// heading or an unclosed fence is a doc bug, not a case for the caller.
fn first_toml_block_after<'a>(doc: &'a str, heading: &str) -> &'a str {
    // The `\n` on each side pins this to a line matching `heading` exactly,
    // not merely a document that mentions it in passing — text such as
    // "see ## Full example: ... below" would otherwise satisfy `find` too.
    let heading_line = format!("\n{heading}\n");
    let heading_at = doc.find(&heading_line).unwrap_or_else(|| {
        panic!("docs/PLUGIN-ARCHITECTURE.md is missing the heading `{heading}`")
    }) + 1;
    let after_heading = &doc[heading_at..];
    let fence_marker = "\n```toml\n";
    let open = after_heading
        .find(fence_marker)
        .unwrap_or_else(|| panic!("no ```toml fence found after `{heading}`"));
    let content_start = heading_at + open + fence_marker.len();
    let rest = &doc[content_start..];
    let close = rest.find("\n```\n").unwrap_or_else(|| {
        panic!("the ```toml fence after `{heading}` is never closed with a bare ``` line")
    });
    &doc[content_start..content_start + close + 1]
}

/// Byte-exact, modulo a trailing newline either side may or may not have —
/// that is not the drift this test means to catch. On mismatch, names the
/// first differing line rather than leaving a maintainer to diff by hand.
fn assert_blocks_match(doc_block: &str, shipped: &str, filename: &str) {
    fn trim_nl(s: &str) -> &str {
        s.strip_suffix('\n').unwrap_or(s)
    }
    let (doc_norm, shipped_norm) = (trim_nl(doc_block), trim_nl(shipped));
    if doc_norm == shipped_norm {
        return;
    }
    let doc_lines: Vec<&str> = doc_norm.lines().collect();
    let shipped_lines: Vec<&str> = shipped_norm.lines().collect();
    let first_diff = doc_lines
        .iter()
        .zip(shipped_lines.iter())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| doc_lines.len().min(shipped_lines.len()));
    panic!(
        "docs/PLUGIN-ARCHITECTURE.md's embedded copy of plugins/{filename} has drifted from the \
         shipped file — first differs at line {} (1-based):\n  doc:     {}\n  plugins: {}",
        first_diff + 1,
        doc_lines
            .get(first_diff)
            .copied()
            .unwrap_or("<end of embedded block>"),
        shipped_lines
            .get(first_diff)
            .copied()
            .unwrap_or("<end of shipped file>"),
    );
}
