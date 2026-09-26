//! `claude-transcripts` — `~/.claude/projects/**/​*.jsonl`.
//!
//! One JSON object per line; only `type = "assistant"` lines carry
//! `message.usage`. Two rules keep the count honest:
//!
//! * **`isSidechain` lines count only from a `subagents/` transcript.** A
//!   sub-agent's turn is written to its own file,
//!   `<project>/<session>/subagents/agent-<id>.jsonl`, and every line
//!   there is flagged `isSidechain` — it is that file's only record of
//!   the spend, so it counts. The same flag turning up inside a *parent*
//!   session's own transcript is a different thing: that turn is already
//!   counted through the parent's ordinary lines, so a sidechain line
//!   there really would double it, and stays skipped. The rule is which
//!   file the line came from, not the flag alone.
//! * **`message.id` dedups.** The same assistant message can be written
//!   more than once (streamed progress, a session re-opened after a
//!   crash); the scanner's pass set and per-file ring drop the copies.
//!
//! Cache tokens stay split: `cache_read_input_tokens` is billed at the
//! cheap read rate, `cache_creation_input_tokens` (and the newer
//! `ephemeral_5m/1h` breakdowns inside `cache_creation`) at the write
//! premium — folding them together would understate the cost either way.

use std::io;
use std::path::Path;
use std::time::Instant;

use serde::Deserialize;

use crate::history::formats::{project_basename, read_new_lines, Extraction, HistoryExtractor};
use crate::history::UsageRecord;

/// A single JSONL line is refused past this size — a transcript line holds
/// a message, and a message that needs more than this is not one we parse.
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

pub struct ClaudeExtractor;

#[derive(Debug, Default, Deserialize)]
struct Line {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default, rename = "sessionId")]
    session_id: Option<String>,
    /// Sub-agent turn marker — see the module doc for when it is skipped.
    #[serde(default, rename = "isSidechain")]
    is_sidechain: bool,
    #[serde(default)]
    message: Option<Message>,
}

#[derive(Debug, Default, Deserialize)]
struct Message {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    usage: Option<Usage>,
}

#[derive(Debug, Default, Deserialize)]
struct Usage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
    /// Flat form: total cache-write tokens.
    #[serde(default)]
    cache_creation_input_tokens: u64,
    /// Newer nested form: the same total split by TTL.
    #[serde(default)]
    cache_creation: Option<CacheCreation>,
}

#[derive(Debug, Default, Deserialize)]
struct CacheCreation {
    #[serde(default)]
    ephemeral_5m_input_tokens: u64,
    #[serde(default)]
    ephemeral_1h_input_tokens: u64,
}

impl Usage {
    /// Cache-write tokens, whichever shape the line carried. The nested
    /// `cache_creation` object (when present) already includes the flat
    /// `cache_creation_input_tokens` figure, so it wins when both exist.
    fn cache_write(&self) -> u64 {
        match &self.cache_creation {
            Some(cc) if cc.ephemeral_5m_input_tokens + cc.ephemeral_1h_input_tokens > 0 => {
                cc.ephemeral_5m_input_tokens + cc.ephemeral_1h_input_tokens
            }
            _ => self.cache_creation_input_tokens,
        }
    }
}

impl HistoryExtractor for ClaudeExtractor {
    fn extract(
        &self,
        path: &Path,
        root: &Path,
        st: &mut crate::history::store::FileState,
        byte_cap: u64,
        _deadline: Instant,
    ) -> io::Result<Extraction> {
        let resume_from = st.cursor;
        let (buf, cursor, eof) = read_new_lines(path, resume_from, byte_cap)?;
        let mut out = Extraction {
            cursor,
            complete: eof,
            ..Default::default()
        };
        // Whether this file sits somewhere under a `subagents/` directory
        // — decided once per file, not per line, since a transcript never
        // changes which kind of file it is mid-stream. The documented
        // layout puts the file directly in that directory, but a further
        // subdirectory below it is allowed too, so every directory
        // component counts, not just the immediate parent — restricted to
        // the part of the path *below* the manifest's own scanned root,
        // and to `path`'s directory components rather than its own file
        // name, or a directory named that way above the root (a project
        // can be called anything, including "subagents") or a file whose
        // own name happens to match would misclassify an ordinary parent
        // transcript. `Path::components` compares path segments, not raw
        // bytes, so `/` vs `\` is not a concern here.
        let in_subagent_file = path
            .strip_prefix(root)
            .ok()
            .and_then(|rel| rel.parent())
            .is_some_and(|dirs| dirs.components().any(|c| c.as_os_str() == "subagents"));
        let mut offset_in_buf = 0u64;
        for raw in buf.split(|&b| b == b'\n') {
            let line_start = resume_from + offset_in_buf;
            offset_in_buf += raw.len() as u64 + 1;
            if raw.is_empty() || raw.len() > MAX_LINE_BYTES {
                continue;
            }
            let line: Line = match serde_json::from_slice(raw) {
                Ok(l) => l,
                // Not every line is a message — summaries, snapshots and
                // user turns parse fine but carry no usage; a JSON syntax
                // error mid-file is the drift case that counts.
                Err(_) => {
                    out.skipped_unparsed += 1;
                    continue;
                }
            };
            if line.kind != "assistant" || (line.is_sidechain && !in_subagent_file) {
                continue;
            }
            let Some(msg) = line.message.as_ref() else {
                continue;
            };
            let Some(usage) = msg.usage.as_ref() else {
                continue;
            };
            let ts = line
                .timestamp
                .as_deref()
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                .map(|t| t.with_timezone(&chrono::Utc));
            let Some(ts) = ts else {
                out.skipped_unparsed += 1;
                continue;
            };
            out.records.push(UsageRecord {
                ts,
                provider: String::new(), // stamped by the scanner
                project: project_basename(line.cwd.as_deref()),
                session_id: line.session_id.clone().unwrap_or_default(),
                model: msg.model.clone().unwrap_or_else(|| "unknown".into()),
                input: usage.input_tokens,
                output: usage.output_tokens,
                cache_read: usage.cache_read_input_tokens,
                cache_write: usage.cache_write(),
                thinking: 0,
                // Globally unique per assistant message; a fallback to the
                // byte position keeps keyless lines still dedupable.
                dedup_key: msg
                    .id
                    .clone()
                    .unwrap_or_else(|| format!("{}:{line_start}", path.display())),
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::formats::testutil::TmpDir;
    use crate::history::store::FileState;
    use std::time::Duration;

    fn fresh() -> FileState {
        FileState::fresh(String::new(), 0, 0)
    }

    fn line(id: &str, input: u64, output: u64, sidechain: bool) -> String {
        format!(
            r#"{{"type":"assistant","isSidechain":{sidechain},"sessionId":"s1","cwd":"/u/proj","timestamp":"2026-09-22T14:30:00.000Z","message":{{"id":"{id}","model":"claude-sonnet-4","usage":{{"input_tokens":{input},"output_tokens":{output},"cache_read_input_tokens":0,"cache_creation_input_tokens":0}}}}}}"#
        )
    }

    fn later() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    #[test]
    fn extracts_usage_and_skips_sidechains() {
        let tmp = TmpDir::new("claude-basic");
        let p = tmp.write(
            "t.jsonl",
            &([
                line("m1", 100, 50, false),
                line("m2", 999, 999, true),
                r#"{"type":"user","timestamp":"2026-09-22T14:31:00.000Z"}"#.to_string(),
            ]
            .join("\n")
                + "\n"),
        );
        let ex = ClaudeExtractor
            .extract(&p, tmp.as_ref(), &mut fresh(), u64::MAX, later())
            .unwrap();
        assert_eq!(ex.records.len(), 1);
        let r = &ex.records[0];
        assert_eq!((r.input, r.output), (100, 50));
        assert_eq!(r.project, "proj");
        assert_eq!(r.dedup_key, "m1");
        assert_eq!(r.model, "claude-sonnet-4");
    }

    #[test]
    fn torn_tail_stays_unconfirmed() {
        let tmp = TmpDir::new("claude-torn");
        let good = line("m1", 1, 2, false) + "\n";
        let p = tmp.write(
            "t.jsonl",
            &(good.clone() + r#"{"type":"assistant","isSidechain":false,"time"#),
        );
        let ex = ClaudeExtractor
            .extract(&p, tmp.as_ref(), &mut fresh(), u64::MAX, later())
            .unwrap();
        assert_eq!(ex.records.len(), 1);
        assert_eq!(
            ex.cursor,
            good.len() as u64,
            "cursor stops at the last newline"
        );
    }

    #[test]
    fn resume_reads_only_new_bytes() {
        let tmp = TmpDir::new("claude-resume");
        let l1 = line("m1", 1, 1, false) + "\n";
        let p = tmp.write("t.jsonl", &l1);
        let first = ClaudeExtractor
            .extract(&p, tmp.as_ref(), &mut fresh(), u64::MAX, later())
            .unwrap();
        assert_eq!(first.records.len(), 1);
        let l2 = line("m2", 2, 2, false) + "\n";
        tmp.write("t.jsonl", &(l1 + &l2));
        let mut resumed = fresh();
        resumed.cursor = first.cursor;
        let second = ClaudeExtractor
            .extract(&p, tmp.as_ref(), &mut resumed, u64::MAX, later())
            .unwrap();
        assert_eq!(second.records.len(), 1);
        assert_eq!(second.records[0].dedup_key, "m2");
    }

    #[test]
    fn a_subagent_transcript_counts_its_sidechain_lines() {
        // Sub-agent turns are written to their own file under a
        // `subagents/` directory, every line flagged `isSidechain` — the
        // parent transcript never carries them at all, so skipping them
        // here would drop the sub-agent's entire spend.
        let tmp = TmpDir::new("claude-subagent");
        let p = tmp.write(
            "proj/sess/subagents/agent-x.jsonl",
            &(line("sub1", 40, 20, true) + "\n"),
        );
        let ex = ClaudeExtractor
            .extract(&p, tmp.as_ref(), &mut fresh(), u64::MAX, later())
            .unwrap();
        assert_eq!(ex.records.len(), 1, "the sub-agent's own turn counts");
        assert_eq!((ex.records[0].input, ex.records[0].output), (40, 20));
    }

    #[test]
    fn a_sidechain_line_inside_a_parent_transcript_still_skips() {
        // The same flag inside the *parent's* own transcript is still the
        // duplicate it always was — only the file's location changes what
        // the flag means.
        let tmp = TmpDir::new("claude-parent-sidechain");
        let p = tmp.write(
            "proj/sess/session.jsonl",
            &(line("m1", 40, 20, true) + "\n"),
        );
        let ex = ClaudeExtractor
            .extract(&p, tmp.as_ref(), &mut fresh(), u64::MAX, later())
            .unwrap();
        assert_eq!(
            ex.records.len(),
            0,
            "a parent-file sidechain stays a duplicate"
        );
    }

    #[test]
    fn a_nested_subdirectory_under_subagents_still_counts() {
        // The provider allows a further subdirectory below `subagents/`
        // (a per-agent transcript subdir); every directory component below
        // the scanned root must be searched, not just the immediate
        // parent, or this layout would wrongly read as a parent file.
        let tmp = TmpDir::new("claude-subagent-nested");
        let p = tmp.write(
            "proj/sess/subagents/subdir/agent-x.jsonl",
            &(line("sub1", 40, 20, true) + "\n"),
        );
        let ex = ClaudeExtractor
            .extract(&p, tmp.as_ref(), &mut fresh(), u64::MAX, later())
            .unwrap();
        assert_eq!(
            ex.records.len(),
            1,
            "a subdirectory below subagents/ is still the sub-agent's own file"
        );
    }

    #[test]
    fn an_ancestor_named_subagents_above_the_scanned_root_does_not_count() {
        // A project directory can itself be named "subagents" — the search
        // must be confined to the part of the path below the manifest's
        // own scanned root, or a directory happening to have that name
        // above it would turn every ordinary parent transcript under it
        // into a sub-agent file.
        let tmp = TmpDir::new("claude-ancestor-subagents");
        let root = tmp.write("subagents/actual-root/.keep", "");
        let root = root.parent().unwrap();
        let p = tmp.write(
            "subagents/actual-root/sess/session.jsonl",
            &(line("m1", 40, 20, true) + "\n"),
        );
        let ex = ClaudeExtractor
            .extract(&p, root, &mut fresh(), u64::MAX, later())
            .unwrap();
        assert_eq!(
            ex.records.len(),
            0,
            "\"subagents\" above the scanned root is not this file's own directory"
        );
    }

    #[test]
    fn cache_creation_breakdown_is_cache_write() {
        let tmp = TmpDir::new("claude-cache");
        let l = r#"{"type":"assistant","isSidechain":false,"sessionId":"s","cwd":"/u/p","timestamp":"2026-09-22T14:30:00.000Z","message":{"id":"mx","model":"m","usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":7,"cache_creation":{"ephemeral_5m_input_tokens":30,"ephemeral_1h_input_tokens":40}}}}"#;
        let p = tmp.write("t.jsonl", &(l.to_string() + "\n"));
        let ex = ClaudeExtractor
            .extract(&p, tmp.as_ref(), &mut fresh(), u64::MAX, later())
            .unwrap();
        assert_eq!(ex.records[0].cache_write, 70);
        assert_eq!(ex.records[0].cache_read, 7);
    }
}
