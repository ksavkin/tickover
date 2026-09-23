//! `codex-rollouts` — `~/.codex/sessions/**/*.jsonl` +
//! `~/.codex/archived_sessions/*.jsonl`.
//!
//! One JSON object per line, `ordinal`-numbered. The shapes that matter:
//!
//! * `type = "session_meta"` — `payload.session_id`, `payload.cwd`, the
//!   session's own timestamp.
//! * `type = "turn_context"` — `payload.model`/`payload.cwd`, re-emitted
//!   when the user switches model mid-session, so the latest seen wins.
//! * `type = "event_msg"` with `payload.type = "token_count"` —
//!   `info.last_token_usage` is the per-turn delta (preferred), while
//!   `info.total_token_usage` is cumulative per session and needs diffing
//!   against the baseline kept in `FileState.aux`. `info` can be `null`.
//!
//! Token classes map as: `cached_input_tokens` → `cache_read`,
//! `cache_write_input_tokens` → `cache_write`, `reasoning_output_tokens`
//! → `thinking`. Codex follows the OpenAI Responses convention where the
//! parent count *includes* the detailed subset — `input_tokens` contains
//! `cached_input_tokens`, `output_tokens` contains
//! `reasoning_output_tokens` (checked against real rollouts:
//! `total_tokens` equals `input + output` exactly, and each subset never
//! exceeds its parent) — so the uncached remainder and the non-reasoning
//! output are the differences, not the raw fields.

use std::io;
use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::history::formats::{project_basename, read_new_lines, Extraction, HistoryExtractor};
use crate::history::store::FileState;
use crate::history::UsageRecord;

const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

/// `FileState.aux` keys for the cumulative baseline, one per counter.
const AUX_INPUT: &str = "ti";
const AUX_CACHED: &str = "tc";
const AUX_CACHE_WRITE: &str = "tw";
const AUX_OUTPUT: &str = "to";
const AUX_THINKING: &str = "tt";

pub struct CodexExtractor;

#[derive(Debug, Default, Deserialize)]
struct Line {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    ordinal: Option<u64>,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    payload: Option<Payload>,
}

#[derive(Debug, Default, Deserialize)]
struct Payload {
    #[serde(rename = "type", default)]
    kind: String,
    // session_meta
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    id: Option<String>,
    // session_meta + turn_context
    #[serde(default)]
    cwd: Option<String>,
    // turn_context
    #[serde(default)]
    model: Option<String>,
    // token_count
    #[serde(default)]
    info: Option<TokenInfo>,
}

#[derive(Debug, Default, Deserialize)]
struct TokenInfo {
    #[serde(default)]
    total_token_usage: Option<TokenUsage>,
    #[serde(default)]
    last_token_usage: Option<TokenUsage>,
}

#[derive(Debug, Default, Clone, Copy, Deserialize)]
struct TokenUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    cached_input_tokens: u64,
    #[serde(default)]
    cache_write_input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    reasoning_output_tokens: u64,
}

impl TokenUsage {
    /// This reading minus the baseline in `aux`, which is then advanced.
    /// A counter that moved backwards (session compaction, restart) is
    /// reset: the delta is the new value itself rather than a wrapped
    /// negative.
    fn delta(&self, aux: &mut std::collections::BTreeMap<String, serde_json::Value>) -> TokenUsage {
        fn diff(
            aux: &mut std::collections::BTreeMap<String, serde_json::Value>,
            key: &str,
            now: u64,
        ) -> u64 {
            let prev = aux
                .insert(key.to_string(), now.into())
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            // Counter moved backwards → compaction/restart, not a wrap:
            // the new value is the delta itself.
            if now >= prev {
                now - prev
            } else {
                now
            }
        }
        TokenUsage {
            input_tokens: diff(aux, AUX_INPUT, self.input_tokens),
            cached_input_tokens: diff(aux, AUX_CACHED, self.cached_input_tokens),
            cache_write_input_tokens: diff(aux, AUX_CACHE_WRITE, self.cache_write_input_tokens),
            output_tokens: diff(aux, AUX_OUTPUT, self.output_tokens),
            reasoning_output_tokens: diff(aux, AUX_THINKING, self.reasoning_output_tokens),
        }
    }

    /// Advance the baseline without emitting a delta — for events that
    /// carry `last_token_usage` beside the cumulative figures. A later
    /// total-only event must diff against *this* reading, not the last
    /// time the total alone was seen, or every earlier token counts twice.
    fn advance(&self, aux: &mut std::collections::BTreeMap<String, serde_json::Value>) {
        aux.insert(AUX_INPUT.to_string(), self.input_tokens.into());
        aux.insert(AUX_CACHED.to_string(), self.cached_input_tokens.into());
        aux.insert(
            AUX_CACHE_WRITE.to_string(),
            self.cache_write_input_tokens.into(),
        );
        aux.insert(AUX_OUTPUT.to_string(), self.output_tokens.into());
        aux.insert(
            AUX_THINKING.to_string(),
            self.reasoning_output_tokens.into(),
        );
    }
}

/// Per-file session context — `session_meta` sits at the top, `turn_context`
/// refreshes model/cwd as the session goes. Persisted in `FileState.aux`
/// under `ctx`: a resumed read starts mid-file, past both line kinds, so
/// without it every post-first-pass record would lose id, cwd and model.
#[derive(Default, Serialize, Deserialize)]
struct SessionCtx {
    #[serde(default)]
    id: String,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    model: Option<String>,
}

impl HistoryExtractor for CodexExtractor {
    fn extract(
        &self,
        path: &Path,
        st: &mut FileState,
        byte_cap: u64,
        _deadline: Instant,
    ) -> io::Result<Extraction> {
        let resume_from = st.cursor;
        let (buf, cursor) = read_new_lines(path, resume_from, byte_cap)?;
        let mut out = Extraction {
            cursor,
            ..Default::default()
        };
        // A resumed read starts mid-file, past `session_meta` — restore the
        // session context persisted last pass, falling back to the file
        // name's trailing uuid (`rollout-<ts>-<uuid>.jsonl`, 36 chars).
        let mut ctx: SessionCtx = st
            .aux
            .get("ctx")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        if ctx.id.is_empty() {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                let tail = &stem[stem.len().saturating_sub(36)..];
                if tail.len() == 36 {
                    ctx.id = tail.to_string();
                }
            }
        }
        let mut offset_in_buf = resume_from;
        for raw in buf.split(|&b| b == b'\n') {
            let line_start = offset_in_buf;
            offset_in_buf += raw.len() as u64 + 1;
            if raw.is_empty() || raw.len() > MAX_LINE_BYTES {
                continue;
            }
            let line: Line = match serde_json::from_slice(raw) {
                Ok(l) => l,
                Err(_) => {
                    out.skipped_unparsed += 1;
                    continue;
                }
            };
            let Some(payload) = line.payload else {
                continue;
            };
            match (line.kind.as_str(), payload.kind.as_str()) {
                ("session_meta", _) => {
                    ctx.id = payload
                        .session_id
                        .clone()
                        .or(payload.id.clone())
                        .unwrap_or(ctx.id);
                    if payload.cwd.is_some() {
                        ctx.cwd = payload.cwd.clone();
                    }
                }
                ("turn_context", _) => {
                    if payload.model.is_some() {
                        ctx.model = payload.model.clone();
                    }
                    if payload.cwd.is_some() {
                        ctx.cwd = payload.cwd.clone();
                    }
                }
                ("event_msg", "token_count") => {
                    let Some(info) = payload.info else { continue };
                    // `last_token_usage` is the delta outright; a total-only
                    // `info` needs the cumulative diff. Either way the
                    // baseline advances to this event's total, so a later
                    // total-only event diffs against the right watermark.
                    let usage = match (info.last_token_usage, info.total_token_usage) {
                        (Some(u), Some(t)) => {
                            t.advance(&mut st.aux);
                            u
                        }
                        (Some(u), None) => u,
                        (None, Some(t)) => t.delta(&mut st.aux),
                        (None, None) => continue,
                    };
                    let Some(ts) = line
                        .timestamp
                        .as_deref()
                        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                        .map(|t| t.with_timezone(&chrono::Utc))
                    else {
                        out.skipped_unparsed += 1;
                        continue;
                    };
                    let ordinal = line.ordinal.unwrap_or(line_start);
                    out.records.push(UsageRecord {
                        ts,
                        provider: String::new(),
                        project: project_basename(ctx.cwd.as_deref()),
                        session_id: ctx.id.clone(),
                        model: ctx.model.clone().unwrap_or_else(|| "unknown".into()),
                        input: usage.input_tokens.saturating_sub(usage.cached_input_tokens),
                        output: usage
                            .output_tokens
                            .saturating_sub(usage.reasoning_output_tokens),
                        cache_read: usage.cached_input_tokens,
                        cache_write: usage.cache_write_input_tokens,
                        thinking: usage.reasoning_output_tokens,
                        dedup_key: format!("{}:{ordinal}", ctx.id),
                    });
                }
                _ => {}
            }
        }
        // Persist the session context so a resumed pass reads records with
        // the same attribution the first pass saw.
        st.aux.insert(
            "ctx".to_string(),
            serde_json::to_value(&ctx).unwrap_or_default(),
        );
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::formats::testutil::TmpDir;
    use std::time::Duration;

    fn fresh() -> FileState {
        FileState::fresh(String::new(), 0, 0)
    }

    fn later() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    fn meta(session: &str, cwd: &str) -> String {
        format!(
            r#"{{"timestamp":"2026-09-22T10:00:00.000Z","ordinal":0,"type":"session_meta","payload":{{"session_id":"{session}","id":"{session}","cwd":"{cwd}","model_provider":"openai"}}}}"#
        )
    }

    fn turn_ctx(model: &str) -> String {
        format!(
            r#"{{"timestamp":"2026-09-22T10:00:01.000Z","ordinal":1,"type":"turn_context","payload":{{"cwd":"/u/proj","model":"{model}"}}}}"#
        )
    }

    fn token_count(ordinal: u64, input: u64, cached: u64, output: u64) -> String {
        format!(
            r#"{{"timestamp":"2026-09-22T10:01:0{o}.000Z","ordinal":{o},"type":"event_msg","payload":{{"type":"token_count","info":{{"total_token_usage":{{"input_tokens":{input},"cached_input_tokens":{cached},"cache_write_input_tokens":0,"output_tokens":{output},"reasoning_output_tokens":0,"total_tokens":0}},"last_token_usage":{{"input_tokens":{input},"cached_input_tokens":{cached},"cache_write_input_tokens":0,"output_tokens":{output},"reasoning_output_tokens":0,"total_tokens":0}}}},"rate_limits":null}}}}"#,
            o = ordinal
        )
    }

    #[test]
    fn last_token_usage_is_the_delta() {
        let tmp = TmpDir::new("codex-basic");
        let p = tmp.write(
            "rollout-x-sess1.jsonl",
            &([
                meta("sess1", "/u/proj"),
                turn_ctx("gpt-5.2-codex"),
                token_count(2, 100, 40, 30),
            ]
            .join("\n")
                + "\n"),
        );
        let ex = CodexExtractor
            .extract(&p, &mut fresh(), u64::MAX, later())
            .unwrap();
        assert_eq!(ex.records.len(), 1);
        let r = &ex.records[0];
        // input_tokens includes the cached part, so `input` is the
        // uncached remainder; `cache_read` holds the cached share.
        assert_eq!((r.input, r.cache_read, r.output), (60, 40, 30));
        assert_eq!(r.project, "proj");
        assert_eq!(r.model, "gpt-5.2-codex");
        assert_eq!(r.session_id, "sess1");
        assert_eq!(r.dedup_key, "sess1:2");
    }

    #[test]
    fn reasoning_is_split_out_of_output_not_doubled() {
        // Real-rollout semantics: `output_tokens` already contains
        // `reasoning_output_tokens` (total = input + output exactly), so
        // reporting both raw would count reasoning twice.
        let tmp = TmpDir::new("codex-reasoning");
        let p = tmp.write(
            "rollout-r.jsonl",
            &(meta("s1", "/u/p")
                + "\n"
                + &turn_ctx("gpt-5.2-codex")
                + "\n"
                + r#"{"timestamp":"2026-09-22T10:01:00.000Z","ordinal":2,"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":103036,"cached_input_tokens":96000,"cache_write_input_tokens":0,"output_tokens":331,"reasoning_output_tokens":209,"total_tokens":103367},"last_token_usage":{"input_tokens":103036,"cached_input_tokens":96000,"cache_write_input_tokens":0,"output_tokens":331,"reasoning_output_tokens":209,"total_tokens":103367}},"rate_limits":null}}"#
                + "\n"),
        );
        let ex = CodexExtractor
            .extract(&p, &mut fresh(), u64::MAX, later())
            .unwrap();
        let r = &ex.records[0];
        assert_eq!(
            (r.input, r.cache_read, r.output, r.thinking),
            (7036, 96000, 122, 209)
        );
    }

    #[test]
    fn cumulative_totals_are_diffed_when_last_is_absent() {
        let tmp = TmpDir::new("codex-cumul");
        let tc = |ord: u64, ti: u64| {
            format!(
                r#"{{"timestamp":"2026-09-22T10:0{ord}:00.000Z","ordinal":{ord},"type":"event_msg","payload":{{"type":"token_count","info":{{"total_token_usage":{{"input_tokens":{ti},"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":0,"reasoning_output_tokens":0,"total_tokens":{ti}}}}},"rate_limits":null}}}}"#
            )
        };
        let p = tmp.write(
            "r.jsonl",
            &([meta("s", "/u/p"), tc(5, 1000), tc(6, 2500)].join("\n") + "\n"),
        );
        let ex = CodexExtractor
            .extract(&p, &mut fresh(), u64::MAX, later())
            .unwrap();
        assert_eq!(
            ex.records.iter().map(|r| r.input).collect::<Vec<_>>(),
            vec![1000, 1500],
            "deltas: 1000 first, then 2500-1000"
        );
    }

    #[test]
    fn a_counter_reset_emits_the_new_value() {
        let tmp = TmpDir::new("codex-reset");
        let tc = |ord: u64, ti: u64| {
            format!(
                r#"{{"timestamp":"2026-09-22T10:0{ord}:00.000Z","ordinal":{ord},"type":"event_msg","payload":{{"type":"token_count","info":{{"total_token_usage":{{"input_tokens":{ti},"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":0,"reasoning_output_tokens":0,"total_tokens":{ti}}}}},"rate_limits":null}}}}"#
            )
        };
        // Compaction drops the counter; delta is the post-reset value.
        let p = tmp.write(
            "r.jsonl",
            &([meta("s", "/u/p"), tc(5, 5000), tc(6, 800)].join("\n") + "\n"),
        );
        let ex = CodexExtractor
            .extract(&p, &mut fresh(), u64::MAX, later())
            .unwrap();
        assert_eq!(ex.records[1].input, 800);
    }

    #[test]
    fn last_usage_still_advances_the_cumulative_baseline() {
        // A `last_token_usage` event followed by a totals-only event: the
        // second must diff against the first's total, not zero — otherwise
        // the whole session re-counts.
        let tmp = TmpDir::new("codex-mixed");
        let both = r#"{"timestamp":"2026-09-22T10:01:00.000Z","ordinal":2,"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":1000,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":0,"reasoning_output_tokens":0,"total_tokens":1000},"last_token_usage":{"input_tokens":1000,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":0,"reasoning_output_tokens":0,"total_tokens":1000}},"rate_limits":null}}"#;
        let total_only = r#"{"timestamp":"2026-09-22T10:02:00.000Z","ordinal":3,"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":1500,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":0,"reasoning_output_tokens":0,"total_tokens":1500}},"rate_limits":null}}"#;
        let p = tmp.write(
            "r.jsonl",
            &([meta("s", "/u/p"), both.to_string(), total_only.to_string()].join("\n") + "\n"),
        );
        let ex = CodexExtractor
            .extract(&p, &mut fresh(), u64::MAX, later())
            .unwrap();
        assert_eq!(
            ex.records.iter().map(|r| r.input).collect::<Vec<_>>(),
            vec![1000, 500],
            "the totals-only event diffs against 1000, not 0"
        );
    }

    #[test]
    fn a_resumed_pass_keeps_the_persisted_session_context() {
        // Two passes over one file through the same FileState: the second
        // pass's bytes carry no session_meta, so attribution must come
        // from aux — otherwise everything past the first scan lands under
        // "unknown".
        let tmp = TmpDir::new("codex-resume");
        let p = tmp.write(
            "rollout-x-sess1.jsonl",
            &(meta("sess1", "/u/proj") + "\n" + &turn_ctx("gpt-5.2-codex") + "\n"),
        );
        let mut st = fresh();
        let first = CodexExtractor
            .extract(&p, &mut st, u64::MAX, later())
            .unwrap();
        assert!(first.records.is_empty());
        st.cursor = first.cursor;
        // The session's first token_count arrives in a later append.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&p)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all((token_count(7, 100, 40, 30) + "\n").as_bytes())
            })
            .unwrap();
        let second = CodexExtractor
            .extract(&p, &mut st, u64::MAX, later())
            .unwrap();
        assert_eq!(second.records.len(), 1);
        assert_eq!(second.records[0].project, "proj");
        assert_eq!(second.records[0].model, "gpt-5.2-codex");
        assert_eq!(second.records[0].session_id, "sess1");
    }

    #[test]
    fn null_info_is_skipped_not_counted() {
        let tmp = TmpDir::new("codex-null");
        let l = r#"{"timestamp":"2026-09-22T10:00:00.000Z","ordinal":9,"type":"event_msg","payload":{"type":"token_count","info":null,"rate_limits":null}}"#;
        let p = tmp.write(
            "r.jsonl",
            &([meta("s", "/u/p"), l.to_string()].join("\n") + "\n"),
        );
        let ex = CodexExtractor
            .extract(&p, &mut fresh(), u64::MAX, later())
            .unwrap();
        assert!(ex.records.is_empty());
        assert_eq!(ex.skipped_unparsed, 0);
    }
}
