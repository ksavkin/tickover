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
//! → `thinking`, `output_tokens` → `output`, and `input_tokens` here
//! already excludes the cached part (Codex counts it separately, unlike
//! Claude whose `input_tokens` is the uncached remainder by convention).

use std::io;
use std::path::Path;
use std::time::Instant;

use serde::Deserialize;

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
    fn delta(&self, aux: &mut std::collections::BTreeMap<String, u64>) -> TokenUsage {
        fn diff(aux: &mut std::collections::BTreeMap<String, u64>, key: &str, now: u64) -> u64 {
            let prev = aux.insert(key.to_string(), now).unwrap_or(0);
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
}

/// Per-file session context, rebuilt within a pass from the lines
/// themselves — `session_meta` sits at the top, `turn_context` refreshes
/// model/cwd as the session goes.
#[derive(Default)]
struct SessionCtx {
    id: String,
    cwd: Option<String>,
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
        // A resumed read starts mid-file with no session_meta — recover the
        // session id from the file name (`rollout-<ts>-<uuid>.jsonl` ends
        // with the uuid) so records still dedup and group correctly.
        let mut ctx = SessionCtx {
            id: path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.rsplit('-').next())
                .unwrap_or_default()
                .to_string(),
            ..Default::default()
        };
        let mut offset_in_buf = resume_from;
        for raw in buf.split(|&b| b == b'\n') {
            let line_start = offset_in_buf;
            offset_in_buf += raw.len() as u64 + 1;
            if raw.is_empty() || raw.len() > MAX_LINE_BYTES {
                continue;
            }
            let line: Line = match serde_json::from_slice(raw) {
                Ok(l) => l,
                Err(_) => continue,
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
                    // `last_token_usage` is the delta outright; only a
                    // total-only `info` needs the cumulative diff.
                    let usage = match info.last_token_usage {
                        Some(u) => u,
                        None => match info.total_token_usage {
                            Some(t) => t.delta(&mut st.aux),
                            None => continue,
                        },
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
                        input: usage.input_tokens,
                        output: usage.output_tokens,
                        cache_read: usage.cached_input_tokens,
                        cache_write: usage.cache_write_input_tokens,
                        thinking: usage.reasoning_output_tokens,
                        dedup_key: format!("{}:{ordinal}", ctx.id),
                    });
                }
                _ => {}
            }
        }
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
        assert_eq!((r.input, r.cache_read, r.output), (100, 40, 30));
        assert_eq!(r.project, "proj");
        assert_eq!(r.model, "gpt-5.2-codex");
        assert_eq!(r.session_id, "sess1");
        assert_eq!(r.dedup_key, "sess1:2");
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
