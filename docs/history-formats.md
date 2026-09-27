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

- **`isSidechain` lines count only from a `subagents/` transcript.** A
  sub-agent's turn is written to its own file,
  `<project>/<session>/subagents/agent-<id>.jsonl`, every line flagged
  `isSidechain` — that file is the turn's only record, so it counts. The
  same flag inside a *parent* session's own transcript marks a turn
  already counted through the parent's ordinary lines; there it stays
  skipped, or counting both would double the spend.
- **`message.id` dedups.** The same assistant message can be written more
  than once (streamed progress, a session re-opened after a crash); copies
  are dropped.

## `codex-rollouts`

**Files:** the shipped manifest's `root` is `~/.codex` and its `glob` is
`rollout-*.jsonl`, matched against a file's basename anywhere under that
root — which is what actually reaches both `sessions/**/` and
`archived_sessions/`, but only a file whose name still starts with
`rollout-`; nothing here asserts what Codex itself names an archived file.
`CODEX_HOME` relocates the whole root.

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

Mapping: like Codex's OpenAI Responses shape, `prompt_tokens` is a
superset that already includes the cached share, so the stored `input` is
the uncached remainder (`prompt_tokens` minus `cached_prompt_tokens`);
`cached_prompt_tokens` → `cache_read`, `completion_tokens` → `output`,
`reasoning_tokens` → `thinking`. Grok reports no cache-write class;
`sessions/*/updates.jsonl` is a session protocol log and carries no token
counts.

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
re-opened databases emit only new rows. A row whose `idx` decodes but
whose blob does not is skipped permanently — the watermark steps over
it, because the committed bytes will not change and retrying the same
row forever would starve every row after it.

## The shared invariants

Whatever the format, the same rules apply at the store boundary:

- **Dedup keys are per-provider-format.** Claude dedups on `message.id`,
  Codex on the session's cumulative counters, Antigravity on the
  protobuf's dedup key, Grok on event identity. A record with no key
  counts toward the file's drift tally instead of being guessed at.
- **A record's year must fit four digits.** A garbled timestamp past
  year 9999 would format a bucket key the query layer can never parse
  back; it is dropped and counted toward the file's drift tally instead
  of silently vanishing from every total. The JSONL formats already
  refuse a timestamp string RFC 3339 can't parse; a raw numeric
  timestamp (Antigravity's protobuf seconds) is the one path that still
  needs this check.
- **The cross-file dedup ring is bounded, not absolute.** Past its
  capacity the oldest untouched id ages out; a record for it arriving
  through a second file afterward is indistinguishable from a genuinely
  new one and counts again.
- **Rewritten files are rescanned whole.** A changed prefix digest marks
  the file's generation; the store replaces its derived records rather
  than adding to them. The reset also drops the file's global-ring
  ownership — otherwise the second pass of a large rescan, resumed from
  mid-file, would mistake the file's own re-derived records for
  ring-evicted repeats and skip them all.
- **A torn tail is deferred, not dropped.** A final line without its
  newline is a write in flight; the cursor holds so the next pass reads
  it complete. The same rule applied to the store's own `days.jsonl`: a
  crash mid-append leaves a fragment that, left in place, would glue
  itself to the retry's first line — so the open path cuts the file back
  to its last newline before parsing (under the lock, so the fragment is
  always a crash leftover, never a write in flight).

## The store

Aggregates land in `<config>/tickover/history/` as two files, both
created `0600` on macOS (Windows has no code-level equivalent for either),
beside a third file in the same directory, `lock`, which carries no data of
its own and exists only for the flock below:

- `days.jsonl` — append-only bucket lines: hour, provider, project,
  model, session, the five token classes, message count, the source
  file's generation, the source range `[lo, hi)` the bucket was
  aggregated from (bytes for JSONL, row indices for SQLite), a `full`
  seal flag, and a `b` batch id. The range is what makes a crash
  between append and commit safe: at load, a line whose range overlaps
  an earlier line in the same bucket supersedes it, so a re-parse
  replaces instead of double-counting — while identical aggregates at
  disjoint ranges legitimately sum. A `full` line goes further: its
  pass reached the end of the source, so it supersedes every older
  line of the same `(file, gen)` — including ranges written in a
  different coordinate space by an older schema, and lines drifted
  into other buckets — except its own batch-mates and the live
  prefix chain. Mates are matched on the full `(b, lo, hi)` shape,
  not `b` alone: one append emits one range, so equal shape is the
  best proxy for "same append" among legacy lines, which all
  deserialize with `b = 0`. The chain is a *disjoint* cover of the
  prefix — honest passes resume where the last cursor stopped, so
  their ranges never overlap, though a span that produced only
  deduped or non-usage records leaves a gap. Overlapping candidates
  are stale artifacts of a pass that appended but never committed;
  the freshest step wins, where freshness is `(b, append position)`
  — the batch id, then the line's place in `days.jsonl`, which is
  the only ordering legacy `b = 0` lines still carry. A kept step
  keeps every line of its `(range, batch)`: one pass emits a line
  per bucket, all sharing the pass's range and batch. A truncated
  pass's line supersedes only what it actually re-read, and a
  complete pass over a source with no records *and no skipped ones*
  writes a `full` tombstone so the seal still fires — a source
  whose every record failed to parse is not empty; its older lines
  hold the only copy of that usage.
- `state.json` — per-file cursor, size/mtime, prefix digest (with the
  span it covered), owning provider, generation, the highest generation
  ever sealed by a `full` line, a recent dedup ring that remembers the
  usage each id last carried, the extractor's persisted `aux` (Grok's
  session map, Codex's turn context and cumulative baseline, Antigravity's
  `max_idx` watermark) plus the scanner's own WAL signature kept under the
  same map, a global dedup ring for ids that can appear in more than one
  file, plus one entry per pruned path recording the generation its
  figure had already resolved
  to (not the raw tracked generation, which would discard whatever the
  sealed-generation mark was holding it back to) at the moment its
  cursor entry was removed — see the pruning paragraph below. Nothing
  expires this map: a path that is deleted and never comes back keeps
  its entry forever, the same way `state.files` would have kept a
  cursor forever without pruning, just at the cost of one integer
  instead of a whole cursor. The sealed-generation mark is what lets a
  later reopen still know a generation was once sealed even after the
  specific line that recorded it has been superseded and dropped from
  memory — re-deriving it fresh from `days.jsonl` alone cannot survive
  that reopen. The two marks differ in one more way: a build without
  them that opens a state file carrying both and then commits drops
  both silently (its own `FileState`/`ScannerState` shapes have nowhere
  to put them) — but the sealed-generation mark self-heals the next
  time a build that knows it reopens, re-derived from whatever `full`
  lines `days.jsonl` still holds, while the pruned-path mark does not:
  once it is gone, the ambiguity it existed to resolve is back. The
  per-file rings persist across commits on purpose:
  a provider can re-log an id at a later byte offset (Claude rewrites an
  assistant message as it streams), and the ring is the only thing that
  recognizes the repeat on a later pass. A re-emission that carries a
  larger count emits only its growth — totals converge on the high-water
  mark of the id *within its owning file* (a regressed snapshot never
  lowers the baseline, and a duplicate sighted by a second file is
  skipped outright rather than delta'd). A path's owning provider is a
  claim against every id the registry has, not only the ones enabled
  this run: if a second manifest's root also reaches the same path (no
  shipped pair overlaps, but a user's own manifest can), the walk that
  finds the path already owned skips it outright rather than taking
  over its cursor — the two providers would otherwise share one cursor,
  and whichever scanned last would silently attribute the file's whole
  history to itself. This holds even while the owner is disabled: a
  provider toggled off for one run keeps its claim, so re-enabling it
  later hands the file straight back rather than finding some other
  provider quietly took it over the run it was off. Only an owner whose
  id the registry no longer has at all (renamed or actually removed) is
  stale, and only then does the walk that reaches the path take it over
  instead of leaving it orphaned forever. A `state.json` written by
  a *newer* build is a downgrade, not corruption: it is left exactly
  where it is and this run starts empty instead, so the newer build
  finds its own file intact next time — this run remembers nothing
  across restarts, and skips compacting `days.jsonl` too (a compacting
  rewrite would write it from this run's memory, which never holds the
  newer build's own lines), until the machine is upgraded back to the
  version that owns both files. An older or unreadable file is
  quarantined to `state.corrupt-<epoch>.json`, keeping only the most
  recent handful so repeated incidents don't accumulate one file per
  run forever.

The whole open→scan→commit sequence runs under a `flock` on a `lock`
file in the same directory, so the tray app and `tickover stats` can
never interleave writes. After each scan, an entry leaves `state.json`
once `stat`ing its exact path confirms `NotFound` — never merely
because no root this process resolved reached it this tick. The panel
and `tickover stats` can resolve the same provider's root differently
(a different `CODEX_HOME` or `CLAUDE_CONFIG_DIR` in one environment),
and pruning by "no active root reaches this path" let one process's
tick drop state the other still needed; confirming against the
filesystem itself needs no notion of roots, and both processes agree on
what it says. A path a symlink has replaced (dangling or not) counts as
gone too — a successful `stat` reporting anything other than a regular
file removes the entry exactly the same way, since the scan never
follows symlinks and never re-offers one, so leaving its entry in place
would strand it exactly like a deletion would. Any other outcome — the
path exists as a regular file, or `stat` fails some other way (an
unreadable root, an unmounted volume, a permission failure) — keeps the
entry. Their day lines stay counted regardless, at the generation the
path was tracked at when it was pruned (recorded into `state.json`
rather than re-derived, since a later, unrelated generation can sit
higher in `days.jsonl` without being more recent), and a path that is
recreated later rescans into place via range supersession. The sweep
itself runs at most once per store instance, not once per scan tick —
the same eight-tick loop that resumes a cold scan
would otherwise pay a `stat` per tracked entry up to eight times over for
no new answer.

Several edges are accepted rather than chased:

- **A path claimed by one provider is invisible to a second, for as
  long as the claim stays live.** No shipped pair of manifests has
  overlapping roots, but a user's own manifest can, or an unset
  `CLAUDE_CONFIG_DIR` resolving to the current directory can. Whichever
  provider's walk reaches a path first owns it — disabling it for a run
  does not release the claim (see the `state.json` bullet above) — and
  a second provider whose root also reaches it reads nothing from that
  path, not zero-then-recovering but zero for as long as the first
  provider's id stays in the registry. The claim does move, two ways:
  if that id is later renamed or actually removed, the next walk to
  reach the path takes it over; or the path itself is deleted and
  recreated (see the delete-and-recreate bullet below) — that drops the
  `FileState` the claim was stamped on, and whichever provider's walk
  reaches the recreated path first claims it fresh, live competitor or
  not, since there is no owner left on record to weigh it against.
  Bounded to the pathological case of two enabled manifests actually
  sharing a root.
- **A file outside every enabled root, but not yet deleted, keeps its
  cursor.** Pruning confirms deletion against the filesystem rather
  than a resolved root list, so a manifest edit that narrows a
  provider's search (`~/.grok` → `~/.grok/logs`) no longer drops the
  file it stopped walking — the entry sits in `state.json`,
  unreachable, until the file itself is actually deleted. The cost is
  one stale cursor per abandoned path, not a miscount.
- **A provider whose log only ever grows is not size-bounded.**
  Compaction rewrites `days.jsonl` past a size threshold, but only
  lines a *later, sealed* generation has actually superseded ever
  leave. A provider that never rewrites its own log — new hours,
  sessions or models, never a stale generation — has nothing to drop,
  and the file keeps growing past the threshold on every future check.
- **A recreated file's stale sealed generation is retained forever,
  until re-sealed past.** Delete-and-recreate, a `SCHEMA_VERSION`
  rebuild, or a downgrade can hand a file a fresh life at a generation
  *lower* than one it had already sealed. The old sealed line is
  neither live (the current, lower generation is what counts) nor
  droppable (nothing has sealed a generation *past* it — the lower
  current one doesn't count): compaction keeps it, doing nothing,
  until the file's fresh life reaches and reseals past it in turn.
  It does not contribute to any total while the path stays tracked, or
  once it is pruned by `prune_missing_files` (which records the path's
  *resolved* generation at removal for exactly this reason, not the
  raw tracked one). Bounded to one retained generation per such
  incident, but not to zero cost: that generation's lines are never
  compacted away either, for as long as this file's fresh life hasn't
  sealed past them — a permanent, if small, amount of disk space paid
  per incident, not nothing. The protection needs a `files` entry or a
  `pruned_generations` one to hang off; a path with neither — the
  `SCHEMA_VERSION` rebuild or downgrade named above empties `files`
  wholesale rather than one path at a time, and neither writes a
  `pruned_generations` entry for what it empties — falls back to the
  newest surviving generation `days.jsonl` happens to contain, stale or
  not, same as data from before either field existed.
- **A generation's seal survives the line that recorded it.** Sealing
  is a fact about a generation reaching the end of its source, not
  about the one line that happened to say so — a later same-bucket
  line can still supersede that specific line by the ordinary overlap
  rule (a crash-then-deadline retry re-reads the same bytes and
  legitimately wins), but the generation itself is remembered as sealed
  regardless, on the tracked `FileState` itself
  (`sealed_through`), not only re-derived from whatever `days.jsonl`
  still holds: a fact re-derived fresh on every call cannot survive a
  reopen landing right after the seal's own line dies, because the
  load path drops a dead row from memory before anything gets to read
  `full` off it. What the generation *counts* is only whatever
  currently survives at it, so the superseded seal's own tokens are
  gone with it — narrow, and bounded to that one crash-plus-truncated-
  retry sequence — but no amount of this can send a live figure back to
  a generation compaction has already dropped, which is the property
  this exists to hold. The mark is capped at the file's own current
  generation the moment it is written, not only when it is read: `open`
  parses `state.json` before it folds a single line of `days.jsonl`, so
  a file is already tracked by the time the load loop reaches a relic
  line from an unrelated earlier life, and without that cap the relic
  would be absorbed into the persisted mark on every single reopen —
  not once, the way appending it live would cost, but permanently.
- **A file deleted and recreated at the same path can seal away its own
  previous life's held figure.** `begin_file` always starts a
  rediscovered path at generation 0, the same number its previous life
  started at — nothing here reads `pruned_generations` to pick a
  number the old life never used. So when the new life's first pass
  reaches the end of the (new, unrelated) file and writes its own `full`
  line at generation 0, that line's from-origin seal reaches every older
  line of `(file, 0)` it does not recognize as its own prefix chain —
  which includes the previous life's generation-0 lines, since their
  byte range has nothing to do with the new file's. They are marked
  dead in the same pass, and the figure `pruned_generations` was holding
  for them is gone the moment that seal lands. Pre-existing — the same
  `(path, generation)` identity that lets an honest rescan supersede its
  own prior pass is what a delete-and-recreate collides with — and not
  addressed here: fixing it would mean `begin_file` consulting
  `pruned_generations` to start a recreated path above its previous
  life's held generation instead of at 0, which is a real change to a
  function several other passages here depend on staying simple.
- **Owner-rewrite loses a shared id.** If a dedup id lives in two
  files, the first file to see it owns it; if that file is later
  rewritten without it, the second file has already moved past the
  id and never re-emits it. Releasing ownership on rewrite is what
  makes the owner's own rescan correct, and no mechanism can know
  which *other* file held the copy. Bounded to cross-file
  duplicates whose owning file loses the content on rewrite.
- **A file vanished from `state.json` counts only its latest live
  generation.** With the state entry gone nothing marks superseded
  generations stale, so `live_days` uses the file's newest
  surviving gen as the remembered watermark — a rewritten-then-
  deleted file keeps its final readings, not every generation it
  ever had.
- **A crash artifact in a drifted bucket outlives a deleted file.**
  A pass that appended but never committed leaves a stale duplicate;
  the retry's same-range lines kill it in-bucket, and the next seal
  kills it anywhere. If the retry attributed the re-derived records to
  a *different* bucket and the file leaves every root before a
  completing pass runs, nothing ever folds the stale copy away — the
  overlap counts twice, permanently. Narrow: needs crash, drifted
  attribution, and removal before a clean pass.
- **A rescan that partially fails to parse still seals what it read.**
  `skipped_unparsed` doubles as the drift counter — it also counts
  records that parsed fine but carry no usable usage (a Grok event of
  an unknown kind, an Antigravity row with no dedup key) — so it
  cannot gate `full` without freezing seals for ordinary drifted
  files. The tombstone gate is the narrow exception: an extraction
  that produced *zero* records while skipping some is treated as
  unreadable, not empty.
