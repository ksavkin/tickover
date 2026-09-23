//! `grok-unified` — `~/.grok/logs/unified.jsonl`.
//!
//! Grok's shell logs every model call as a `shell.turn.inference_done`
//! event: top-level `sid` (session id) and `ts`, and a `ctx` carrying
//! `prompt_tokens`, `cached_prompt_tokens`, `completion_tokens` and
//! `reasoning_tokens`. Two sibling events supply attribution the usage
//! event itself lacks: `session created` carries `ctx.cwd`, and
//! `model changed` carries `ctx.model` — both keyed by the same `sid`, so
//! they are collected into a per-pass map and joined onto the records.
//!
//! Mapping to the shared record: `prompt_tokens` → `input`,
//! `cached_prompt_tokens` → `cache_read`, `completion_tokens` → `output`,
//! `reasoning_tokens` → `thinking`. Grok reports no cache-write class.

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::history::formats::{project_basename, read_new_lines, Extraction, HistoryExtractor};
use crate::history::store::FileState;
use crate::history::UsageRecord;

const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

pub struct GrokExtractor;

#[derive(Debug, Default, Deserialize)]
struct Line {
    #[serde(default)]
    ts: Option<String>,
    #[serde(default)]
    msg: Option<String>,
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    ctx: Option<Ctx>,
}

#[derive(Debug, Default, Deserialize)]
struct Ctx {
    // inference_done
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    cached_prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
    #[serde(default)]
    reasoning_tokens: u64,
    #[serde(default)]
    loop_index: Option<u64>,
    // session created
    #[serde(default)]
    cwd: Option<String>,
    // model changed
    #[serde(default)]
    model: Option<String>,
    // some events name it session_id instead of a top-level sid
    #[serde(default)]
    session_id: Option<String>,
}

/// Attribution collected from non-usage events, joined onto inference
/// records by `sid`. Persisted in `FileState.aux` between passes —
/// `session created`/`model changed` are written once near session start,
/// so a resumed read mid-file would otherwise attribute every later turn
/// to "unknown".
#[derive(Debug, Default, Serialize, Deserialize)]
struct SessionInfo {
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    model: Option<String>,
}

impl HistoryExtractor for GrokExtractor {
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
        // Two passes over the same buffer: `session created`/`model
        // changed` can appear lines after the inference they describe, so
        // attribution is collected file-wide before records are built.
        // The map is seeded from `aux` — events already consumed by earlier
        // passes are behind the cursor and won't be re-read here.
        let mut sessions: HashMap<String, SessionInfo> = st
            .aux
            .get("sess")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        for raw in buf.split(|&b| b == b'\n') {
            if raw.is_empty() || raw.len() > MAX_LINE_BYTES {
                continue;
            }
            let Ok(line) = serde_json::from_slice::<Line>(raw) else {
                continue;
            };
            let Some(ctx) = line.ctx.as_ref() else {
                continue;
            };
            let sid = line
                .sid
                .clone()
                .or_else(|| ctx.session_id.clone())
                .unwrap_or_default();
            if sid.is_empty() {
                continue;
            }
            match line.msg.as_deref() {
                Some("session created") if ctx.cwd.is_some() => {
                    sessions.entry(sid).or_default().cwd = ctx.cwd.clone();
                }
                Some(m) if m.contains("model") && ctx.model.is_some() => {
                    // "model changed", "model catalog: …", "backend_search:
                    // model switch" — any event carrying a model name.
                    sessions.entry(sid).or_default().model = ctx.model.clone();
                }
                _ => {}
            }
        }
        let mut offset_in_buf = resume_from;
        for raw in buf.split(|&b| b == b'\n') {
            let line_start = offset_in_buf;
            offset_in_buf += raw.len() as u64 + 1;
            if raw.is_empty() || raw.len() > MAX_LINE_BYTES {
                continue;
            }
            let Ok(line) = serde_json::from_slice::<Line>(raw) else {
                out.skipped_unparsed += 1;
                continue;
            };
            if line.msg.as_deref() != Some("shell.turn.inference_done") {
                continue;
            }
            let Some(ctx) = line.ctx else { continue };
            let Some(ts) = line
                .ts
                .as_deref()
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                .map(|t| t.with_timezone(&chrono::Utc))
            else {
                out.skipped_unparsed += 1;
                continue;
            };
            let sid = line
                .sid
                .clone()
                .or_else(|| ctx.session_id.clone())
                .unwrap_or_default();
            let info = sessions.get(&sid);
            out.records.push(UsageRecord {
                ts,
                provider: String::new(),
                project: project_basename(info.and_then(|i| i.cwd.as_deref())),
                session_id: sid.clone(),
                model: info
                    .and_then(|i| i.model.clone())
                    .unwrap_or_else(|| "unknown".into()),
                input: ctx.prompt_tokens,
                output: ctx.completion_tokens,
                cache_read: ctx.cached_prompt_tokens,
                cache_write: 0,
                thinking: ctx.reasoning_tokens,
                dedup_key: format!(
                    "grok:{sid}:{}:{}",
                    line.ts.unwrap_or_default(),
                    ctx.loop_index.unwrap_or(line_start)
                ),
            });
        }
        // Persist attribution for the next pass — the events that produced
        // it sit behind the cursor by then. The map is bounded: `unified.
        // jsonl` accumulates a sid per session indefinitely, so past a cap
        // a share is evicted (an evicted sid degrades to "unknown"
        // attribution, never to dropped tokens).
        const SESS_CAP: usize = 16_384;
        if sessions.len() > SESS_CAP {
            let drop: Vec<String> = sessions
                .keys()
                .take(sessions.len() - SESS_CAP * 3 / 4)
                .cloned()
                .collect();
            for k in drop {
                sessions.remove(&k);
            }
        }
        st.aux.insert(
            "sess".to_string(),
            serde_json::to_value(&sessions).unwrap_or_default(),
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

    #[test]
    fn inference_done_extracts_with_attribution() {
        let tmp = TmpDir::new("grok-basic");
        let content = concat!(
            r#"{"ts":"2026-09-22T10:00:00.000Z","src":"shell","sid":"s1","msg":"session created","ctx":{"cwd":"/u/proj"}}"#,
            "\n",
            r#"{"ts":"2026-09-22T10:00:01.000Z","src":"shell","sid":"s1","msg":"model changed","ctx":{"model":"grok-4.5"}}"#,
            "\n",
            r#"{"ts":"2026-09-22T10:05:00.000Z","src":"shell","sid":"s1","msg":"shell.turn.inference_done","ctx":{"loop_index":1,"prompt_tokens":1000,"cached_prompt_tokens":600,"completion_tokens":200,"reasoning_tokens":50}}"#,
            "\n",
            // unrelated noise
            r#"{"ts":"2026-09-22T10:05:01.000Z","src":"shell","msg":"auth: ok","ctx":{}}"#,
            "\n"
        );
        let p = tmp.write("unified.jsonl", content);
        let ex = GrokExtractor
            .extract(&p, &mut fresh(), u64::MAX, later())
            .unwrap();
        assert_eq!(ex.records.len(), 1);
        let r = &ex.records[0];
        assert_eq!(
            (r.input, r.cache_read, r.output, r.thinking),
            (1000, 600, 200, 50)
        );
        assert_eq!(r.project, "proj");
        assert_eq!(r.model, "grok-4.5");
        assert_eq!(r.session_id, "s1");
    }

    #[test]
    fn a_resumed_pass_keeps_attribution_from_aux() {
        // unified.jsonl is append-only; the `session created` line is read
        // once. The next pass must still attribute later turns — from the
        // persisted sessions map, not "unknown".
        let tmp = TmpDir::new("grok-resume");
        let head = concat!(
            r#"{"ts":"2026-09-22T10:00:00.000Z","sid":"s1","msg":"session created","ctx":{"cwd":"/u/proj"}}"#,
            "\n",
            r#"{"ts":"2026-09-22T10:00:01.000Z","sid":"s1","msg":"model changed","ctx":{"model":"grok-4.5"}}"#,
            "\n",
        );
        let p = tmp.write("unified.jsonl", head);
        let mut st = fresh();
        let first = GrokExtractor
            .extract(&p, &mut st, u64::MAX, later())
            .unwrap();
        assert!(first.records.is_empty());
        st.cursor = first.cursor;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&p)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(concat!(
                    r#"{"ts":"2026-09-22T10:05:00.000Z","sid":"s1","msg":"shell.turn.inference_done","ctx":{"loop_index":1,"prompt_tokens":100,"completion_tokens":20}}"#,
                    "\n"
                ).as_bytes())
            })
            .unwrap();
        let second = GrokExtractor
            .extract(&p, &mut st, u64::MAX, later())
            .unwrap();
        assert_eq!(second.records.len(), 1);
        assert_eq!(second.records[0].project, "proj");
        assert_eq!(second.records[0].model, "grok-4.5");
        assert_eq!(second.records[0].session_id, "s1");
    }
}
