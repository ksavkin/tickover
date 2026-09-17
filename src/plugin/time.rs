//! Timestamp parsing, and the one substantive rule around it, shared by
//! [`crate::plugin::engine_http`] and [`crate::plugin::engine_logfile`].
//!
//! Both engines used to carry their own copy of the same two things: an
//! RFC3339 parser for `resets_at_format = "iso8601"` ([`parse_iso8601`]), and
//! a Unix-seconds reader tolerant of a provider that quotes its numbers
//! ([`read_unix_timestamp`]), for `resets_at_format = "unix"`. One copy,
//! here, called directly from `engine_http` and, from `engine_logfile`,
//! through a small private wrapper of the same name the tests already
//! pinned to (`engine_logfile::resets_at_for`) — no `pub use` re-exports it
//! into either module.
//!
//! [`resets_at`] adds the rule neither copy enforced on its own:
//! `plausible_resets_at` refuses a parsed value more than ten years from
//! now rather than let it through. The shape this exists for is a provider
//! sending milliseconds where the manifest declares `resets_at_format =
//! "unix"` (seconds) — a reset half an hour away then reads as one some
//! 30,000 years out — but it also catches a saturated float-to-int cast
//! without a separate range check on the float that produced it: `1e30 as
//! u64` is `u64::MAX`, comfortably past the line whenever "now" is.
//! [`plausible_period_minutes`] states the same idea for a window's own
//! *length* rather than a point in time.

use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::plugin::manifest::ResetsAtFormat;

/// Parse an RFC3339 / ISO-8601 timestamp to Unix seconds. Negative
/// (pre-1970) results clamp to 0 rather than wrap — `chrono` accepts years
/// this app has no business trusting either way, which is what
/// `plausible_resets_at` is for; this function only speaks RFC3339, not
/// "sane".
pub fn parse_iso8601(s: &str) -> Option<u64> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.timestamp().max(0) as u64)
}

/// One JSON value read as a Unix-seconds timestamp: a number, or — because
/// providers do quote their numbers sometimes — a numeric string. Both
/// engines accepted the quoted form for the same reason before this module
/// existed: a reset time is too useful to drop over the difference between
/// `1787207494` and `"1787207494"`. A fractional number truncates toward
/// zero, same as the network sending whole seconds with `.0` appended.
pub fn read_unix_timestamp(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| {
            v.as_f64()
                .filter(|f| f.is_finite() && *f >= 0.0)
                .map(|f| f as u64)
        })
        .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
}

/// How far past "now" a `resets_at` may plausibly sit and still be trusted:
/// ten years. Long past any real quota window, and short of the distance a
/// seconds/milliseconds mixup produces.
const MAX_RESETS_AT_SECS_AHEAD: u64 = 10 * 365 * 24 * 60 * 60;

/// Whether `secs` (Unix seconds) is close enough to now to show.
pub(crate) fn plausible_resets_at(secs: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    secs <= now.saturating_add(MAX_RESETS_AT_SECS_AHEAD)
}

/// The longest window length either engine will trust, in minutes — the same
/// ten years, restated as a duration rather than a horizon. A raw field this
/// large is a response that drifted units (seconds misread as minutes, say)
/// far more plausibly than an actual quota window; treating it as absent is
/// safer than showing a bar that will not move again in this app's lifetime.
const MAX_PLAUSIBLE_PERIOD_MINUTES: u64 = 10 * 365 * 24 * 60;

/// Whether `minutes` is a window length either engine will trust.
pub fn plausible_period_minutes(minutes: u64) -> bool {
    minutes <= MAX_PLAUSIBLE_PERIOD_MINUTES
}

/// `v` read as `format` says, refused outright when the result is not
/// `plausible_resets_at` — the one rule both engines need after parsing,
/// enforced here once rather than however many times it would otherwise get
/// copied.
pub fn resets_at(v: &Value, format: ResetsAtFormat) -> Option<u64> {
    let raw = match format {
        ResetsAtFormat::Unix => read_unix_timestamp(v),
        ResetsAtFormat::Iso8601 => v.as_str().and_then(parse_iso8601),
    }?;
    if plausible_resets_at(raw) {
        Some(raw)
    } else {
        queue_implausible_resets_at_diag();
        None
    }
}

/// Diagnostics this module produced that only the binary can write —
/// `crate::diag` lives in `main.rs`'s binary crate, not this library one
/// (see `crate::plugin::auth`'s own `PENDING_DIAGNOSTICS` for the identical
/// split, and its own doc for why this crate does not reach into either
/// directly). Queued here, meant to be drained once per fetch pass by
/// `main.rs` via [`take_pending_diagnostics`], the same shape as `auth`'s.
static PENDING_DIAGNOSTICS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Whether the one diagnostic this module ever queues has already gone out,
/// this process. A single flag rather than a per-value key on purpose,
/// mirroring `auth::expires_in_clamped_key`'s own fixed-key diagnostic and
/// for the same reason stated there: a provider sending one implausible
/// `resets_at` tonight and a different implausible one tomorrow does not
/// need two lines saying essentially the same thing, and the common shape
/// here — a millisecond value, which keeps advancing — would otherwise queue
/// a fresh line on every tick forever, with nothing here ever draining it.
static IMPLAUSIBLE_RESETS_AT_LOGGED: AtomicBool = AtomicBool::new(false);

fn queue_implausible_resets_at_diag() {
    if !IMPLAUSIBLE_RESETS_AT_LOGGED.swap(true, Ordering::SeqCst) {
        PENDING_DIAGNOSTICS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(
                "a resets_at value more than ten years from now was treated as absent \
                 (seconds vs. milliseconds?)"
                    .to_string(),
            );
    }
}

/// Every diagnostic line queued since the last call, removing them.
pub fn take_pending_diagnostics() -> Vec<String> {
    let mut guard = PENDING_DIAGNOSTICS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    std::mem::take(&mut *guard)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_iso8601_reads_rfc3339_and_refuses_nonsense() {
        assert_eq!(parse_iso8601("2026-01-01T00:00:00Z"), Some(1_767_225_600));
        assert_eq!(
            parse_iso8601("1969-12-31T23:59:00Z"),
            Some(0),
            "pre-epoch clamps to 0 rather than wrapping"
        );
        assert_eq!(parse_iso8601("yesterday"), None);
    }

    #[test]
    fn read_unix_timestamp_accepts_a_number_or_its_quoted_twin() {
        assert_eq!(
            read_unix_timestamp(&json!(1_787_207_494u64)),
            Some(1_787_207_494)
        );
        assert_eq!(
            read_unix_timestamp(&json!("1787207494")),
            Some(1_787_207_494),
            "a provider that quotes its numbers is still readable"
        );
        assert_eq!(read_unix_timestamp(&json!(-5)), None);
        assert_eq!(read_unix_timestamp(&json!("not a number")), None);
        assert_eq!(read_unix_timestamp(&json!(null)), None);
    }

    #[test]
    fn plausible_resets_at_draws_the_line_at_ten_years() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(plausible_resets_at(now + 60), "a minute away is fine");
        assert!(
            !plausible_resets_at(now + MAX_RESETS_AT_SECS_AHEAD + 1),
            "a hair past ten years out is not"
        );
        // The saturated cast a wildly out-of-range float produces
        // (`1e30 as u64`), caught without a separate check on the float.
        assert!(!plausible_resets_at(u64::MAX));
    }

    #[test]
    fn plausible_period_minutes_draws_the_same_line_as_a_duration() {
        assert!(
            plausible_period_minutes(10_080),
            "a week is an ordinary window"
        );
        assert!(!plausible_period_minutes(MAX_PLAUSIBLE_PERIOD_MINUTES + 1));
    }

    #[test]
    fn resets_at_treats_an_implausible_value_as_absent_in_both_formats() {
        let far_future_unix = json!(9_999_999_999_999u64); // ~year 318857
        assert_eq!(resets_at(&far_future_unix, ResetsAtFormat::Unix), None);

        let far_future_iso = json!("9999-01-01T00:00:00Z");
        assert_eq!(resets_at(&far_future_iso, ResetsAtFormat::Iso8601), None);

        // An ordinary value in either format still reads through.
        assert_eq!(
            resets_at(&json!("2026-01-01T00:00:00Z"), ResetsAtFormat::Iso8601),
            Some(1_767_225_600)
        );
        assert_eq!(
            resets_at(&json!(1_787_207_494u64), ResetsAtFormat::Unix),
            Some(1_787_207_494)
        );
    }
}
