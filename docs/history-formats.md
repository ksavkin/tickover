# History formats

The wire details of each provider's local usage log, as implemented by the
extractors in `src/history/formats/`. This page exists so the formats can be
reviewed — or reimplemented elsewhere — without reading Rust. Everything
here was derived from observing the files the CLIs write on a real machine
(clean-room: no provider source was read), and cross-checked against the
`usage` app's loaders where they exist.

Every format reduces to the same record: timestamp, provider, project,
session, model, and five token classes — `input`, `output`, `cache_read`,
`cache_write`, `thinking`. What an extractor must never emit: prompt or
message text, file contents, credentials.

## `claude-transcripts`

**Files:** `~/.claude/projects/**/*.jsonl` (honours `CLAUDE_CONFIG_DIR` —
the root becomes `$CLAUDE_CONFIG_DIR/projects`).

One JSON object per line. Only `type = "assistant"` lines carry usage, in
`message.usage`. The session id is `sessionId`, the project is `cwd`'s
basename, the model is `message.model`, the timestamp is the line's own
`timestamp` (RFC 3339).

Usage fields: `input_tokens`, `output_tokens`,
`cache_read_input_tokens`, `cache_creation_input_tokens` → input, output,
cache-read, cache-write. Cache classes stay split — read is billed at the
cheap rate, creation at the write premium; newer lines may break creation
down into `ephemeral_5m` / `ephemeral_1h`, which are summed into
cache-write.

Two rules keep the count honest:

- **`isSidechain` lines are skipped.** A sub-agent's turn lands in the same
  transcript with its own `message.usage`, and the parent session's usage
  already accounts for it — counting both doubles the spend.
- **`message.id` dedups.** The same assistant message can be written more
  than once (streamed progress, a session re-opened after a crash); copies
  are dropped.

## `codex-rollouts`

**Files:** `~/.codex/sessions/**/rollout-*.jsonl` plus
`~/.codex/archived_sessions/*.jsonl` (honours `CODEX_HOME`).

One JSON object per line, `ordinal`-numbered. The shapes that matter:

- `type = "session_meta"` — `payload.id`, `payload.cwd`, the session's own
  timestamp.
- `type = "turn_context"` — `payload.model` and `payload.cwd`, re-emitted
  when the user switches model mid-session; the latest seen wins.
- `type = "event_msg"` with `payload.type = "token_count"` —
  `info.last_token_usage` is the per-turn delta (preferred when present),
  `info.total_token_usage` is cumulative per session and is differenced
  against a per-file baseline held in scanner state. `info` can be `null`.

Counter subsets follow the OpenAI Responses convention: `input_tokens`
*includes* `cached_input_tokens`, and `output_tokens` includes
`reasoning_output_tokens` (verified against real rollouts:
`total_tokens` equals `input + output` exactly, and a subset never exceeds
its parent). So the stored `input` is the uncached remainder and `output`
the non-reasoning remainder; `cached_input_tokens` → `cache_read`,
`cache_write_input_tokens` → `cache_write`, `reasoning_output_tokens` →
`thinking`. Miscounting this is the difference between 5.4B and 38.7B
lifetime tokens on a real corpus.

## `grok-unified`

**Files:** `~/.grok/logs/unified.jsonl`.

Every model call is a `shell.turn.inference_done` event: top-level `sid`
(session id) and `ts`, and a `ctx` carrying `prompt_tokens`,
`cached_prompt_tokens`, `completion_tokens`, `reasoning_tokens`.

Attribution comes from sibling events keyed by the same `sid`, because the
usage event itself lacks them: `session created` carries `ctx.cwd`, and
`model changed` carries `ctx.model`. The extractor collects both into a
per-pass map and joins them onto the records.

Mapping: `prompt_tokens` → `input`, `cached_prompt_tokens` → `cache_read`,
`completion_tokens` → `output`, `reasoning_tokens` → `thinking`. Grok
reports no cache-write class; `sessions/*/updates.jsonl` is a session
protocol log and carries no token counts.

## `antigravity-sqlite`

**Files:** `~/.gemini/antigravity-cli/conversations/*.db`.

Each conversation is a WAL-mode SQLite database, live while the CLI runs.
The file is opened read-only (`mode=ro` — deliberately not `immutable=1`,
which would hide rows still sitting in the WAL); a busy or locked
database yields zero records for the tick rather than blocking — the next
scan picks it up. Nothing is ever written to a provider database.
Because fresh writes land in `<db>-wal` while the `.db`'s own size and
mtime stay frozen until a checkpoint, the scanner folds the sibling's
signature into its unchanged check — a live conversation is never
skipped as "unchanged".

Per-generation usage sits in `gen_metadata.data` as a protobuf blob:

```text
gen_metadata.data
  └─ field 1 (LEN)  chat_model
       ├─ field 4 (LEN)  usage
       │    ├─ field 1  varint  system tokens
       │    ├─ field 2  varint  new input tokens   (input = 1 + 2)
       │    ├─ field 5  varint  cache-read tokens
       │    ├─ field 9  varint  output tokens
       │    ├─ field 10 varint  thinking tokens
       │    └─ field 11 string dedup key (required — no key, no record)
       ├─ field 9 (LEN) → field 4 (LEN) → google.protobuf.Timestamp
       │                                        {1: seconds, 2: nanos}
       └─ field 19 string model name
```

Two more fields of `trajectory_metadata_blob` (the `id='main'` row)
supply attribution: field 2 is the session `Timestamp`, field 18 the
workspace name used as the project. (The `steps.step_payload` `"Cwd"`
fragment an earlier build looked for is unreachable: that column is a
BLOB, which SQLite `LIKE` never matches.) The session id is the database
filename's UUID stem. A `max_idx` watermark in scanner state makes
re-opened databases emit only new rows.

## The shared invariants

Whatever the format, the same rules apply at the store boundary:

- **Dedup keys are per-provider-format.** Claude dedups on `message.id`,
  Codex on the session's cumulative counters, Antigravity on the
  protobuf's dedup key, Grok on event identity. A record with no key
  counts toward the file's drift tally instead of being guessed at.
- **Rewritten files are rescanned whole.** A changed prefix digest marks
  the file's generation; the store replaces its derived records rather
  than adding to them.
- **A torn tail is deferred, not dropped.** A final line without its
  newline is a write in flight; the cursor holds so the next pass reads
  it complete. The same rule applied to the store's own `days.jsonl`: a
  crash mid-append leaves a fragment that, left in place, would glue
  itself to the retry's first line — so the open path cuts the file back
  to its last newline before parsing (under the lock, so the fragment is
  always a crash leftover, never a write in flight).

## The store

Aggregates land in `<config>/tickover/history/` as two files, both
created `0600`:

- `days.jsonl` — append-only bucket lines: hour, provider, project,
  model, session, the five token classes, message count, the source
  file's generation, and the byte range `[lo, hi)` the bucket was
  aggregated from. The range is what makes a crash between append and
  commit safe: at load, a line whose range overlaps an earlier line in
  the same bucket supersedes it, so a re-parse replaces instead of
  double-counting — while identical aggregates at disjoint ranges
  legitimately sum.
- `state.json` — per-file cursor, size/mtime, prefix digest (with the
  span it covered), owning provider, generation, a recent dedup ring,
  the extractor's persisted `aux` (Grok's session map, Codex's turn
  context and cumulative baseline, Antigravity's `max_idx` watermark and
  WAL signature), plus a global dedup ring for ids that can appear in
  more than one file. The per-file rings persist across commits on
  purpose: a provider can re-log an id at a later byte offset (Claude
  rewrites an assistant message as it streams), and the ring is the only
  thing that recognizes the repeat on a later pass.

The whole open→scan→commit sequence runs under a `flock` on a `lock`
file in the same directory, so the tray app and `tickover stats` can
never interleave writes. Entries under none of the active history roots
are pruned after each scan — their day lines stay counted, and a path
that re-enters a root rescans into place via range supersession.
