//! `antigravity-sqlite` — `~/.gemini/antigravity-cli/conversations/*.db`.
//!
//! Each conversation is a SQLite database (WAL-mode, live while the CLI
//! runs). Per-generation usage sits in `gen_metadata.data` as a protobuf
//! blob; the message shape observed in the wild and mirrored by the
//! `usage` app's loader is:
//!
//! ```text
//! gen_metadata.data
//!   └─ field 1 (LEN)  chat_model
//!        ├─ field 4 (LEN)  usage
//!        │    ├─ field 1  varint  system tokens
//!        │    ├─ field 2  varint  new input tokens   (input = 1 + 2)
//!        │    ├─ field 5  varint  cache-read tokens
//!        │    ├─ field 9  varint  output tokens
//!        │    ├─ field 10 varint  thinking tokens
//!        │    └─ field 11 string dedup key (required — no key, no record)
//!        ├─ field 9 (LEN)  → field 4 (LEN) → google.protobuf.Timestamp
//!        │                                        {1: seconds, 2: nanos}
//!        └─ field 19 string model name
//! ```
//!
//! Attribution comes from `trajectory_metadata_blob`: field 2 is the
//! session Timestamp, field 18 the workspace name used as the project.
//! The session id is the database filename's UUID stem.
//!
//! The database is opened read-only (`mode=ro`, `query_only`); a busy or
//! locked database yields zero records this tick instead of blocking —
//! the next scan picks it up. `aux["max_idx"]` watermarks the
//! `gen_metadata` primary key so reopened files only emit new rows.

use std::io;
use std::path::Path;
use std::time::Instant;

use rusqlite::{Connection, OpenFlags};

use crate::history::formats::{Extraction, HistoryExtractor};
use crate::history::store::FileState;
use crate::history::UsageRecord;

pub struct AntigravityExtractor;

impl HistoryExtractor for AntigravityExtractor {
    fn extract(
        &self,
        path: &Path,
        st: &mut FileState,
        _byte_cap: u64,
        deadline: Instant,
    ) -> io::Result<Extraction> {
        let mut out = Extraction::default();
        let uri = format!("file:{}?mode=ro", uri_encode(&path.to_string_lossy()));
        let conn = match Connection::open_with_flags(
            &uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        ) {
            Ok(c) => c,
            // A locked/unreadable db is not an error — next tick retries.
            Err(_) => return Ok(out),
        };
        let _ = conn.pragma_update(None, "query_only", true);
        let _ = conn.busy_timeout(std::time::Duration::from_millis(500));

        let session_ts = session_timestamp(&conn).unwrap_or(st.mtime.max(0));
        let project = session_project(&conn);
        let session_id = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();

        let watermark = st.aux.get("max_idx").and_then(|v| v.as_u64()).unwrap_or(0) as i64;
        let mut stmt =
            match conn.prepare("SELECT idx, data FROM gen_metadata WHERE idx > ?1 ORDER BY idx") {
                Ok(s) => s,
                Err(_) => return Ok(out), // schema drift — skip the db entirely
            };
        let Ok(rows) = stmt.query_map([watermark], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
        }) else {
            return Ok(out);
        };
        let mut max_idx = watermark;
        let mut completed = true;
        let mut seen_keys = std::collections::HashSet::new();
        for row in rows.flatten() {
            // Honour the pass deadline mid-scan: `max_idx` only covers the
            // rows already emitted, so an early stop resumes correctly —
            // but only because the cursor below stays short of `size`.
            if Instant::now() >= deadline {
                completed = false;
                break;
            }
            let (idx, blob) = row;
            if idx > max_idx {
                max_idx = idx;
            }
            match parse_generation(&blob) {
                Gen::Record {
                    usage,
                    model,
                    ts,
                    dedup,
                } => {
                    if !dedup.is_empty() && seen_keys.insert(dedup.clone()) {
                        out.records.push(UsageRecord {
                            ts: ts.unwrap_or_else(|| {
                                chrono::DateTime::from_timestamp(session_ts, 0).unwrap_or_default()
                            }),
                            provider: String::new(),
                            project: project.clone(),
                            session_id: session_id.clone(),
                            model,
                            input: usage.0,
                            output: usage.1,
                            cache_read: usage.2,
                            cache_write: 0,
                            thinking: usage.3,
                            dedup_key: format!("agy:{session_id}:{dedup}"),
                        });
                    }
                }
                Gen::NoDedupKey => out.skipped_unparsed += 1,
                Gen::NoUsage => {}
            }
        }
        st.aux.insert("max_idx".into(), (max_idx as u64).into());
        // A deadline-truncated pass must NOT report the file consumed:
        // `cursor >= size` is the scanner's "unchanged" check, and a db
        // that never changes again would keep its tail rows unread
        // forever. The `max_idx` watermark does the real resuming.
        out.cursor = if completed { st.size } else { 0 };
        Ok(out)
    }
}

/// What one `gen_metadata` blob decoded to.
enum Gen {
    /// (input, output, cache_read, thinking), model, timestamp, dedup key.
    Record {
        usage: (u64, u64, u64, u64),
        model: String,
        ts: Option<chrono::DateTime<chrono::Utc>>,
        dedup: String,
    },
    /// Usage-shaped but missing the dedup key — counted as drift.
    NoDedupKey,
    /// Not a usage-bearing generation.
    NoUsage,
}

fn parse_generation(blob: &[u8]) -> Gen {
    let Some(chat_model) = message_field(blob, 1) else {
        return Gen::NoUsage;
    };
    let Some(usage) = message_field(chat_model, 4) else {
        return Gen::NoUsage;
    };
    let system = varint_field(usage, 1).unwrap_or(0);
    let new_input = varint_field(usage, 2).unwrap_or(0);
    let cache_read = varint_field(usage, 5).unwrap_or(0);
    let output = varint_field(usage, 9).unwrap_or(0);
    let thinking = varint_field(usage, 10).unwrap_or(0);
    if system + new_input + cache_read + output + thinking == 0 {
        return Gen::NoUsage;
    }
    let dedup = string_field(usage, 11).unwrap_or_default();
    if dedup.trim().is_empty() {
        return Gen::NoDedupKey;
    }
    let ts = message_field(chat_model, 9)
        .and_then(|m| message_field(m, 4))
        .and_then(timestamp_field);
    let model = string_field(chat_model, 19).unwrap_or_else(|| "unknown".into());
    Gen::Record {
        usage: (system + new_input, output, cache_read, thinking),
        model,
        ts,
        dedup,
    }
}

/// `trajectory_metadata_blob` field 2 is a Timestamp for the session;
/// fall back to the file's own mtime.
fn session_timestamp(conn: &Connection) -> Option<i64> {
    let blob: Vec<u8> = conn
        .query_row(
            "SELECT data FROM trajectory_metadata_blob LIMIT 1",
            [],
            |r| r.get(0),
        )
        .ok()?;
    message_field(&blob, 2)
        .and_then(timestamp_field)
        .map(|t| t.timestamp())
}

/// The workspace name lives in `trajectory_metadata_blob` field 18 of the
/// `id='main'` row — the conversation's own statement of which project it
/// ran in. (The `steps.step_payload` `"Cwd"` fragment an earlier build
/// looked for is unreachable anyway: the column is a BLOB and SQLite
/// `LIKE` never matches a blob, and on current builds it names agent
/// scratch dirs rather than the workspace.)
fn session_project(conn: &Connection) -> String {
    conn.query_row(
        "SELECT data FROM trajectory_metadata_blob WHERE id = 'main' LIMIT 1",
        [],
        |r| r.get::<_, Vec<u8>>(0),
    )
    .ok()
    .and_then(|blob| string_field(&blob, 18))
    .filter(|s| !s.is_empty())
    .unwrap_or_else(|| "unknown".into())
}

// ---- minimal protobuf wire decoder -------------------------------------

/// Iterate a blob's fields as `(field_number, wire_type, value)` — varint
/// fields yield the decoded u64, length-delimited fields yield the bytes;
/// fixed32/64 are skipped over. Decoding stops at the first malformed tag.
fn fields(blob: &[u8]) -> Vec<(u64, u8, Field<'_>)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < blob.len() {
        let Some((tag, p)) = read_varint(blob, pos) else {
            break;
        };
        pos = p;
        let (field, wire) = (tag >> 3, (tag & 7) as u8);
        if field == 0 {
            break;
        }
        match wire {
            0 => match read_varint(blob, pos) {
                Some((v, p)) => {
                    out.push((field, wire, Field::Varint(v)));
                    pos = p;
                }
                None => break,
            },
            1 if pos + 8 <= blob.len() => pos += 8,
            2 => match read_varint(blob, pos) {
                Some((len, p)) => {
                    let (start, end) = (p, p.saturating_add(len as usize));
                    if end > blob.len() {
                        break;
                    }
                    out.push((field, wire, Field::Bytes(&blob[start..end])));
                    pos = end;
                }
                None => break,
            },
            5 if pos + 4 <= blob.len() => pos += 4,
            _ => break,
        }
    }
    out
}

enum Field<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

fn read_varint(blob: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *blob.get(pos)?;
        pos += 1;
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, pos));
        }
    }
    None
}

fn varint_field(blob: &[u8], target: u64) -> Option<u64> {
    fields(blob)
        .into_iter()
        .find_map(|(f, w, v)| match (f == target, w, v) {
            (true, 0, Field::Varint(v)) => Some(v),
            _ => None,
        })
}

fn message_field(blob: &[u8], target: u64) -> Option<&[u8]> {
    fields(blob)
        .into_iter()
        .find_map(|(f, w, v)| match (f == target, w, v) {
            (true, 2, Field::Bytes(b)) => Some(b),
            _ => None,
        })
}

fn string_field(blob: &[u8], target: u64) -> Option<String> {
    message_field(blob, target).and_then(|b| String::from_utf8(b.to_vec()).ok())
}

/// `file:` URI path escaping — `?`, `#` and `%` would corrupt the query
/// string; everything else passes through as UTF-8.
fn uri_encode(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'.' | b'-' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Decode a `google.protobuf.Timestamp` (fields 1/2: seconds/nanos).
fn timestamp_field(blob: &[u8]) -> Option<chrono::DateTime<chrono::Utc>> {
    let secs = varint_field(blob, 1)?;
    let nanos = varint_field(blob, 2).unwrap_or(0);
    if nanos > 999_999_999 || secs > i64::MAX as u64 {
        return None;
    }
    chrono::DateTime::from_timestamp(secs as i64, nanos as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-encode a protobuf blob: `[(field, wire, bytes_or_varint)]`.
    fn proto(fields: &[(u64, u8, ProtoVal)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (f, w, v) in fields {
            let tag = (f << 3) | *w as u64;
            push_varint(&mut out, tag);
            match (w, v) {
                (0, ProtoVal::V(x)) => push_varint(&mut out, *x),
                (2, ProtoVal::B(b)) => {
                    push_varint(&mut out, b.len() as u64);
                    out.extend_from_slice(b);
                }
                _ => unreachable!(),
            }
        }
        out
    }

    enum ProtoVal<'a> {
        V(u64),
        B(&'a [u8]),
    }
    use ProtoVal::*;

    fn push_varint(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                break;
            }
            out.push(b | 0x80);
        }
    }

    fn generation_blob() -> Vec<u8> {
        let ts = proto(&[(1, 0, V(1_758_500_000)), (2, 0, V(0))]);
        let reply_meta = proto(&[(4, 2, B(&ts))]);
        let usage = proto(&[
            (1, 0, V(100)),         // system
            (2, 0, V(50)),          // new input
            (5, 0, V(400)),         // cache read
            (9, 0, V(30)),          // output
            (10, 0, V(7)),          // thinking
            (11, 2, B(b"dedup-1")), // dedup key
        ]);
        proto(&[(
            1,
            2,
            B(&{
                let mut cm = Vec::new();
                cm.extend_from_slice(&proto(&[(4, 2, B(&usage))]));
                cm.extend_from_slice(&proto(&[(9, 2, B(&reply_meta))]));
                cm.extend_from_slice(&proto(&[(19, 2, B(b"gemini-3-pro"))]));
                cm
            }),
        )])
    }

    #[test]
    fn decodes_usage_and_metadata() {
        match parse_generation(&generation_blob()) {
            Gen::Record {
                usage,
                model,
                ts,
                dedup,
            } => {
                assert_eq!(usage, (150, 30, 400, 7)); // input = system + new
                assert_eq!(model, "gemini-3-pro");
                assert_eq!(dedup, "dedup-1");
                assert_eq!(ts.unwrap().timestamp(), 1_758_500_000);
            }
            _ => panic!("expected a record"),
        }
    }

    #[test]
    fn missing_dedup_key_counts_as_drift() {
        let usage = proto(&[(1, 0, V(5)), (9, 0, V(3))]);
        let blob = proto(&[(1, 2, B(&proto(&[(4, 2, B(&usage))])))]);
        assert!(matches!(parse_generation(&blob), Gen::NoDedupKey));
    }

    #[test]
    fn malformed_wire_stops_cleanly() {
        assert!(matches!(parse_generation(&[0xff, 0xff]), Gen::NoUsage));
        // Truncated length-delimited field
        assert!(matches!(
            parse_generation(&[0x0a, 0x7f, 0x01]),
            Gen::NoUsage
        ));
    }
}
