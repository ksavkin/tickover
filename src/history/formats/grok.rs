//! `grok-unified` — `~/.grok/logs/unified.jsonl`.
//!
//! Grok's shell logs every model call as a `shell.turn.inference_done`
//! event: top-level `sid` (session id) and `ts`, and a `ctx` carrying
//! `prompt_tokens`, `cached_prompt_tokens`, `completion_tokens` and
//! `reasoning_tokens`. Two sibling events supply attribution the usage
//! event itself lacks: `session created` carries `ctx.cwd`, and
//! `model changed` carries `ctx.model` — both keyed by the same `sid`,
//! applied to the turns that follow them.
//!
//! Mapping to the shared record: `prompt_tokens`/`completion_tokens` are
//! *assumed* to be Chat-Completions-style supersets that already include
//! their `cached_prompt_tokens`/`reasoning_tokens` shares — the same
//! convention Codex's `input_tokens`/`output_tokens` follow, which Codex
//! could verify against real rollouts (`total_tokens` equals
//! `input + output` exactly there). Grok's own payload carries no such
//! total to check itself against, and no captured Grok log exists in
//! this repository to verify the assumption against either, so it stays
//! an assumption rather than a checked fact. What would falsify it: a
//! line where `cached_prompt_tokens > prompt_tokens` or
//! `reasoning_tokens > completion_tokens` — the "subset" reading larger
//! than its own parent. That line is counted as drift rather than
//! silently clamped to zero, so the day the assumption breaks is visible
//! instead of hidden. `input` is `prompt_tokens` minus
//! `cached_prompt_tokens`; `output` is `completion_tokens` minus
//! `reasoning_tokens`; `cached_prompt_tokens` → `cache_read`,
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
        _root: &Path,
        st: &mut FileState,
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
        // Single pass, map-as-of-that-line: `model changed` marks a
        // switch, so an inference logged *before* the event ran on the
        // old model — collecting attribution file-wide first would stamp
        // it with the new one. `session created` precedes its session's
        // turns by definition, and the map is seeded from `aux` — events
        // already consumed by earlier passes sit behind the cursor and
        // won't be re-read here.
        let mut sessions: HashMap<String, SessionInfo> = st
            .aux
            .get("sess")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
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
            let Some(ctx) = line.ctx.as_ref() else {
                continue;
            };
            let sid = line
                .sid
                .clone()
                .or_else(|| ctx.session_id.clone())
                .unwrap_or_default();
            match line.msg.as_deref() {
                Some("session created") if ctx.cwd.is_some() && !sid.is_empty() => {
                    sessions.entry(sid).or_default().cwd = ctx.cwd.clone();
                }
                Some("model changed") if ctx.model.is_some() && !sid.is_empty() => {
                    sessions.entry(sid).or_default().model = ctx.model.clone();
                }
                Some("shell.turn.inference_done") => {
                    let Some(ts) = line
                        .ts
                        .as_deref()
                        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                        .map(|t| t.with_timezone(&chrono::Utc))
                    else {
                        out.skipped_unparsed += 1;
                        continue;
                    };
                    // A subset reading larger than its own parent is the
                    // exact shape that would disprove the superset
                    // assumption (see the module doc) — `saturating_sub`
                    // would clamp it to zero and hide it. Counted as
                    // drift instead of emitted as a wrong record.
                    if ctx.cached_prompt_tokens > ctx.prompt_tokens
                        || ctx.reasoning_tokens > ctx.completion_tokens
                    {
                        out.skipped_unparsed += 1;
                        continue;
                    }
                    let info = sessions.get(&sid);
                    out.records.push(UsageRecord {
                        ts,
                        provider: String::new(),
                        project: project_basename(info.and_then(|i| i.cwd.as_deref())),
                        session_id: sid.clone(),
                        // An inference that carries its own model wins over
                        // the session map — today's log never writes one,
                        // but a future format that does must not be
                        // flattened to the remembered value.
                        model: ctx
                            .model
                            .clone()
                            .or_else(|| info.and_then(|i| i.model.clone()))
                            .unwrap_or_else(|| "unknown".into()),
                        input: ctx.prompt_tokens - ctx.cached_prompt_tokens,
                        output: ctx.completion_tokens - ctx.reasoning_tokens,
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
                // A msg we don't know that still carries a model name is
                // format drift worth counting — silently stamping "unknown"
                // would hide the day Grok renames the event.
                Some(_) if ctx.model.is_some() && !sid.is_empty() => {
                    out.skipped_unparsed += 1;
                }
                _ => {}
            }
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
            .extract(&p, tmp.as_ref(), &mut fresh(), u64::MAX, later())
            .unwrap();
        assert_eq!(ex.records.len(), 1);
        let r = &ex.records[0];
        // Both parents are assumed supersets: input = 1000 - 600 = 400,
        // output = 200 - 50 = 150.
        assert_eq!(
            (r.input, r.cache_read, r.output, r.thinking),
            (400, 600, 150, 50)
        );
        assert_eq!(r.project, "proj");
        assert_eq!(r.model, "grok-4.5");
        assert_eq!(r.session_id, "s1");
    }

    #[test]
    fn reasoning_tokens_are_not_double_counted_in_output() {
        // `completion_tokens` is assumed to already include the reasoning
        // share — a wholly-reasoning turn must show zero fresh output,
        // not the full completion size again on top of `thinking`.
        let tmp = TmpDir::new("grok-reasoning-superset");
        let content = concat!(
            r#"{"ts":"2026-09-22T10:00:00.000Z","sid":"s1","msg":"shell.turn.inference_done","ctx":{"loop_index":1,"prompt_tokens":100,"completion_tokens":50,"reasoning_tokens":50}}"#,
            "\n"
        );
        let p = tmp.write("unified.jsonl", content);
        let ex = GrokExtractor
            .extract(&p, tmp.as_ref(), &mut fresh(), u64::MAX, later())
            .unwrap();
        assert_eq!(ex.records.len(), 1);
        let r = &ex.records[0];
        assert_eq!((r.output, r.thinking), (0, 50));
    }

    #[test]
    fn a_subset_larger_than_its_parent_counts_as_drift_not_a_clamp() {
        // `saturating_sub` would silently clamp a broken assumption to
        // zero; the line must be dropped and counted instead, so the day
        // the superset assumption breaks is visible, not hidden.
        let tmp = TmpDir::new("grok-broken-assumption");
        let bad_cache = concat!(
            r#"{"ts":"2026-09-22T10:00:00.000Z","sid":"s1","msg":"shell.turn.inference_done","ctx":{"loop_index":1,"prompt_tokens":100,"cached_prompt_tokens":200,"completion_tokens":10}}"#,
            "\n"
        );
        let p = tmp.write("unified.jsonl", bad_cache);
        let ex = GrokExtractor
            .extract(&p, tmp.as_ref(), &mut fresh(), u64::MAX, later())
            .unwrap();
        assert!(
            ex.records.is_empty(),
            "cached_prompt_tokens > prompt_tokens must not emit"
        );
        assert_eq!(ex.skipped_unparsed, 1);

        let bad_reasoning = concat!(
            r#"{"ts":"2026-09-22T10:00:00.000Z","sid":"s1","msg":"shell.turn.inference_done","ctx":{"loop_index":1,"prompt_tokens":100,"completion_tokens":10,"reasoning_tokens":20}}"#,
            "\n"
        );
        let p2 = tmp.write("unified2.jsonl", bad_reasoning);
        let ex2 = GrokExtractor
            .extract(&p2, tmp.as_ref(), &mut fresh(), u64::MAX, later())
            .unwrap();
        assert!(
            ex2.records.is_empty(),
            "reasoning_tokens > completion_tokens must not emit"
        );
        assert_eq!(ex2.skipped_unparsed, 1);
    }

    #[test]
    fn cached_prompt_tokens_are_not_double_counted_in_input() {
        // `prompt_tokens` is a superset that already includes the cached
        // share (the OpenAI Responses convention Codex also follows) — a
        // wholly-cached turn must show zero fresh input, not the full
        // prompt size again on top of `cache_read`.
        let tmp = TmpDir::new("grok-cache-superset");
        let content = concat!(
            r#"{"ts":"2026-09-22T10:00:00.000Z","sid":"s1","msg":"shell.turn.inference_done","ctx":{"loop_index":1,"prompt_tokens":800,"cached_prompt_tokens":800,"completion_tokens":50}}"#,
            "\n"
        );
        let p = tmp.write("unified.jsonl", content);
        let ex = GrokExtractor
            .extract(&p, tmp.as_ref(), &mut fresh(), u64::MAX, later())
            .unwrap();
        assert_eq!(ex.records.len(), 1);
        let r = &ex.records[0];
        assert_eq!((r.input, r.cache_read), (0, 800));
    }

    #[test]
    fn a_model_change_does_not_relabel_the_turn_before_it() {
        // The model switch is logged at the switch: the inference above
        // it ran on the old model, the one below on the new.
        let tmp = TmpDir::new("grok-switch");
        let content = concat!(
            r#"{"ts":"2026-09-22T10:00:00.000Z","sid":"s1","msg":"session created","ctx":{"cwd":"/u/proj"}}"#,
            "\n",
            r#"{"ts":"2026-09-22T10:00:01.000Z","sid":"s1","msg":"model changed","ctx":{"model":"grok-4"}}"#,
            "\n",
            r#"{"ts":"2026-09-22T10:05:00.000Z","sid":"s1","msg":"shell.turn.inference_done","ctx":{"loop_index":1,"prompt_tokens":100,"completion_tokens":20}}"#,
            "\n",
            r#"{"ts":"2026-09-22T10:06:00.000Z","sid":"s1","msg":"model changed","ctx":{"model":"grok-4.5"}}"#,
            "\n",
            r#"{"ts":"2026-09-22T10:07:00.000Z","sid":"s1","msg":"shell.turn.inference_done","ctx":{"loop_index":2,"prompt_tokens":200,"completion_tokens":40}}"#,
            "\n"
        );
        let p = tmp.write("unified.jsonl", content);
        let ex = GrokExtractor
            .extract(&p, tmp.as_ref(), &mut fresh(), u64::MAX, later())
            .unwrap();
        assert_eq!(ex.records.len(), 2);
        assert_eq!(ex.records[0].model, "grok-4");
        assert_eq!(ex.records[1].model, "grok-4.5");
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
            .extract(&p, tmp.as_ref(), &mut st, u64::MAX, later())
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
            .extract(&p, tmp.as_ref(), &mut st, u64::MAX, later())
            .unwrap();
        assert_eq!(second.records.len(), 1);
        assert_eq!(second.records[0].project, "proj");
        assert_eq!(second.records[0].model, "grok-4.5");
        assert_eq!(second.records[0].session_id, "s1");
    }
}
