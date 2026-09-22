//! Per-format extractors, selected by `[history] format` in the manifest.
//!
//! Each extractor turns raw bytes from a provider's local history files
//! into [`UsageRecord`]s. Format-specific correctness rules (dedup keys,
//! cumulative-counter diffing, sub-agent filtering) live here and only
//! here — the scanner feeds bytes, the store keeps aggregates, and the
//! manifest names the format; none of them knows what a line looks like.

use crate::history::UsageRecord;

/// What one parse of a byte slice produced.
#[derive(Debug, Default)]
pub struct ParseOutcome {
    /// Usage records found, in file order.
    pub records: Vec<UsageRecord>,
    /// Bytes consumed up to and including the last complete line the
    /// extractor accepted — the scanner commits this as the confirmed
    /// offset. A torn tail stays unconfirmed for the next pass.
    pub consumed_to: u64,
    /// Lines that looked like they should carry usage but did not parse —
    /// the format-drift observability counter, surfaced in `stats`.
    pub skipped_unparsed: u64,
}
