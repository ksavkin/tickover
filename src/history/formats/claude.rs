//! `claude-transcripts` — `~/.claude/projects/**/​*.jsonl`.
//!
//! One JSON object per line; only `type = "assistant"` lines carry
//! `message.usage`. Two rules keep the count honest:
//!
//! * **`isSidechain` lines are skipped.** A sub-agent's turn is written
//!   into the same transcript with its own `message.usage`; the parent
//!   session's usage already accounts for it, so counting both doubles
//!   the real spend.
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
    /// Sub-agent turn marker — skipped, see the module doc.
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
            if line.kind != "assistant" || line.is_sidechain {
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
            .extract(&p, &mut fresh(), u64::MAX, later())
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
            .extract(&p, &mut fresh(), u64::MAX, later())
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
            .extract(&p, &mut fresh(), u64::MAX, later())
            .unwrap();
        assert_eq!(first.records.len(), 1);
        let l2 = line("m2", 2, 2, false) + "\n";
        tmp.write("t.jsonl", &(l1 + &l2));
        let mut resumed = fresh();
        resumed.cursor = first.cursor;
        let second = ClaudeExtractor
            .extract(&p, &mut resumed, u64::MAX, later())
            .unwrap();
        assert_eq!(second.records.len(), 1);
        assert_eq!(second.records[0].dedup_key, "m2");
    }

    #[test]
    fn cache_creation_breakdown_is_cache_write() {
        let tmp = TmpDir::new("claude-cache");
        let l = r#"{"type":"assistant","isSidechain":false,"sessionId":"s","cwd":"/u/p","timestamp":"2026-09-22T14:30:00.000Z","message":{"id":"mx","model":"m","usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":7,"cache_creation":{"ephemeral_5m_input_tokens":30,"ephemeral_1h_input_tokens":40}}}}"#;
        let p = tmp.write("t.jsonl", &(l.to_string() + "\n"));
        let ex = ClaudeExtractor
            .extract(&p, &mut fresh(), u64::MAX, later())
            .unwrap();
        assert_eq!(ex.records[0].cache_write, 70);
        assert_eq!(ex.records[0].cache_read, 7);
    }
}
