//! Request pacing for the HTTP engine: a floor under how often one surface
//! may be asked, an exponential cool-off after a failure, and a full stop on
//! the one failure retrying cannot fix.
//!
//! The refresh timer is not the only reason a fetch happens. Opening the
//! panel fetches, the Refresh button fetches, the tray's "Refresh now"
//! fetches, enabling a plugin fetches, and starting the app fetches. Reading
//! a local log file that often costs nothing; asking a provider's API that
//! often is a burst nobody asked for — a user opening and closing the panel
//! ten times in a minute would have made ten requests. `refresh_secs` paces
//! the schedule; this module caps everything else.
//!
//! Three rules, in the order [`decide`] applies them:
//!
//! 1. **Credentials decide whose state this is.** Every decision is keyed on
//!    a fingerprint of the token and the header values derived from it. Sign
//!    out and back in as somebody else and the fingerprint changes, which
//!    drops the cached reading (it belongs to the previous account, and
//!    showing one account's usage under another's name is the very defect
//!    this provider's migration set out to fix) and lifts any stop. The same
//!    rule read the other way: a request that left under the previous login
//!    and reports back after the change reports about nobody, and changes
//!    nothing here.
//! 2. **One schedule, and it only ever moves later.** A failure sets the
//!    earliest next attempt; a second failure may push that out further, and
//!    can never pull it in. Ordinary failures — 429, 5xx, a refused
//!    connection, a 400 from a changed API — double the wait from
//!    `backoff_start_secs` up to `backoff_max_secs` and keep retrying at that
//!    ceiling: a provider that is down is polled rarely, never never.
//! 3. **An expired session waits far longer.** HTTP 401 means the token is
//!    dead, and this app never spends a provider's refresh token — doing so
//!    can invalidate the copy the provider's own CLI is holding — so retrying
//!    on the refresh cadence is a request that cannot succeed. It waits
//!    `unauthorized_retry_secs` instead. Rule 1 is the real way out (signing
//!    in again is noticed at once); the wait is for the 401 that came from a
//!    gateway having a bad minute, where nothing about the credentials ever
//!    changes. Because the schedule only grows, a network error landing in
//!    between cannot shorten that hour — and because it is a wait rather than
//!    a stop, polling cannot be silenced for good, which this project has
//!    been bitten by from that side too.
//!
//! The state machine ([`State`]) is pure: every method that needs to know
//! *when* this is happening takes the current [`Instant`] as an argument —
//! [`State::decide`], [`State::attempt`], [`State::failure`] — so the tests
//! drive time by hand and nothing here sleeps. [`State::success`] is the one
//! exception, deliberately: recording a good answer doesn't depend on when
//! it arrived, only on the fact that it did. Only [`decide`],
//! [`record_success`], [`record_failure`] and [`remembered_account`] touch
//! the process-wide map, and they are thin. Timing is monotonic on purpose —
//! a wall clock moved backwards (a timezone change, an NTP correction) would
//! otherwise stretch a cool-off into hours.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::model::ProviderReading;
use crate::plugin::manifest::HttpConfig;

/// The pacing knobs of one `[http]` section, resolved to durations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Smallest gap between two requests for one surface, whatever triggered
    /// them.
    pub min_interval: Duration,
    /// Cool-off after the first failure.
    pub backoff_start: Duration,
    /// Ceiling the doubling cool-off stops at.
    pub backoff_max: Duration,
    /// How long an expired session stops the polling for, before one more
    /// attempt is allowed.
    pub unauthorized_retry: Duration,
}

impl Limits {
    pub fn from_http(http: &HttpConfig) -> Self {
        Limits {
            min_interval: Duration::from_secs(http.min_interval_secs),
            backoff_start: Duration::from_secs(http.backoff_start_secs.max(1)),
            backoff_max: Duration::from_secs(http.backoff_max_secs.max(1)),
            unauthorized_retry: Duration::from_secs(http.unauthorized_retry_secs.max(1)),
        }
    }
}

/// What the engine should do with a request it is about to make.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// Make the request.
    Fetch,
    /// Don't: hand back the last reading this surface produced.
    Serve(Box<ProviderReading>),
    /// Don't: there is nothing to show, only this error.
    Blocked(String),
}

/// One surface's pacing state. Public for the tests that drive it directly;
/// the engine goes through [`decide`] and the two `record_*` functions.
#[derive(Debug, Default)]
pub struct State {
    /// Fingerprint of the credentials the rest of this state belongs to.
    /// `None` until the first decision — an `Option` rather than a bare `0`
    /// so a hash that happens to be zero isn't read as "never adopted",
    /// which would reset the pacing on every fetch.
    fingerprint: Option<u64>,
    /// When the last request was *started* (not finished) — pacing measured
    /// from completion would let a slow provider drift the schedule.
    last_attempt: Option<Instant>,
    /// Earliest next attempt while backing off.
    next_allowed: Option<Instant>,
    /// Consecutive failures, driving the doubling.
    failures: u32,
    /// The last failure's message, shown while waiting when there is no
    /// earlier reading to show instead.
    last_error: Option<String>,
    /// The account these credentials resolved to, for providers that name it
    /// at a second endpoint (see [`State::account`]).
    account: Option<String>,
    /// The last reading a successful fetch produced.
    cached: Option<ProviderReading>,
}

impl State {
    /// Whether `fingerprint` still describes the credentials this state was
    /// built from — and, when it doesn't, reset to a clean state for the new
    /// ones. A cached reading, a cool-off and a stop are all statements about
    /// one account; none of them survives the account changing.
    fn adopt(&mut self, fingerprint: u64) {
        if self.fingerprint != Some(fingerprint) {
            *self = State {
                fingerprint: Some(fingerprint),
                ..State::default()
            };
        }
    }

    /// The pacing decision for a request at `now`.
    ///
    /// One schedule, one gate. `next_allowed` is the only thing that can hold
    /// a request back, and it only ever moves *later* — a failure of one kind
    /// can never shorten the wait another kind has already set. That is what
    /// keeps an expired session at one attempt an hour even when ordinary
    /// network errors land in between it and the retry.
    pub fn decide(&self, now: Instant, limits: Limits) -> Decision {
        if self.next_allowed.is_some_and(|next| now < next) {
            return self.hold();
        }
        // The floor applies to every attempt, including one a cool-off just
        // released and one after an attempt that never reported back at all (a
        // fetch thread that died). Two requests closer together than
        // `min_interval`, *for the same credentials*, must not be reachable
        // by any path — a fingerprint change is the one path that resets
        // this on purpose (see `State::adopt`): a new login is a new
        // question, and it is asked at once rather than waiting out the
        // previous one's floor.
        if self
            .last_attempt
            .is_some_and(|last| now.saturating_duration_since(last) < limits.min_interval)
        {
            return self.hold();
        }
        Decision::Fetch
    }

    /// What to show while a request is being held back: the last good reading
    /// if there is one — it still describes the last thing the provider said,
    /// and the row keeps its own countdown — else whatever went wrong.
    fn hold(&self) -> Decision {
        match &self.cached {
            Some(reading) => Decision::Serve(Box::new(reading.clone())),
            None => Decision::Blocked(
                self.last_error
                    .clone()
                    .unwrap_or_else(|| "no reading yet".to_string()),
            ),
        }
    }

    /// Record that a request is being made right now. Clears the cool-off it
    /// was released by: the attempt it was holding back has now happened, and
    /// leaving a stale `next_allowed` in the past would make every later
    /// decision take the "cool-off is over" path.
    pub fn attempt(&mut self, now: Instant) {
        self.last_attempt = Some(now);
        self.next_allowed = None;
    }

    /// Record a reading a request actually produced, and the account it names
    /// (`None` leaves whatever was already known — a profile lookup that
    /// failed this time doesn't unname the row). One good answer means the
    /// provider is answering again, so the cool-off goes with it.
    pub fn success(&mut self, reading: ProviderReading, account: Option<String>) {
        self.failures = 0;
        self.next_allowed = None;
        self.last_error = None;
        if account.is_some() {
            self.account = account;
        }
        self.cached = Some(reading);
    }

    /// The account this surface's credentials resolved to, if it has been
    /// looked up since they last changed. Lets a provider whose address lives
    /// behind a second endpoint be asked once rather than once a minute — the
    /// answer cannot change without the credentials changing, and that resets
    /// this state anyway.
    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }

    /// Record a failed request.
    ///
    /// `terminal` marks the failure retrying cannot fix — an expired session,
    /// which this app will not renew on the user's behalf — and schedules the
    /// long `unauthorized_retry` wait instead of the doubling one. Either way
    /// the wait can only grow: a network error a minute after a 401 must not
    /// pull the next attempt forward into the hour that 401 bought.
    pub fn failure(&mut self, now: Instant, message: &str, terminal: bool, limits: Limits) {
        self.last_error = Some(message.to_string());
        let wait = if terminal {
            // Nothing may be served from before the session died: the row must
            // say the session is over, not keep drawing yesterday's numbers as
            // if they were current.
            self.cached = None;
            self.failures = 0;
            limits.unauthorized_retry
        } else {
            self.failures = self.failures.saturating_add(1);
            backoff_delay(self.failures, limits)
        };
        let at = deadline(now, wait);
        self.next_allowed = Some(match self.next_allowed {
            Some(existing) => existing.max(at),
            None => at,
        });
    }
}

/// `now + wait`, or — for a manifest whose numbers are large enough that the
/// clock can't express the result — as far out as the clock will go, halving
/// `wait` until the addition fits. `now` itself is returned only as the last
/// resort of that loop: if even a zero-length wait can't be added without
/// overflowing, the boundary `Instant` type's own range would already have
/// to be exhausted, which nothing observed here has ever done — but the loop
/// still has to terminate rather than spin, so `now` (not "no deadline at
/// all") is the one answer left once `wait` reaches zero.
fn deadline(now: Instant, wait: Duration) -> Instant {
    let mut wait = wait;
    loop {
        if let Some(at) = now.checked_add(wait) {
            return at;
        }
        wait /= 2;
        if wait.is_zero() {
            return now;
        }
    }
}

/// The cool-off after `failures` consecutive failures: `backoff_start`
/// doubled once per failure, capped at `backoff_max`. Saturating, so a long
/// outage can't overflow the shift into a tiny (or enormous) delay.
fn backoff_delay(failures: u32, limits: Limits) -> Duration {
    let doublings = failures.saturating_sub(1).min(32);
    let scaled = limits
        .backoff_start
        .checked_mul(1u32.checked_shl(doublings).unwrap_or(u32::MAX))
        .unwrap_or(limits.backoff_max);
    scaled.min(limits.backoff_max)
}

/// A fingerprint of the credentials a request would carry: the bearer token
/// and every header value derived from local files (Codex's account id). Not
/// a secret in itself and never persisted or logged — it exists only so a
/// changed login is noticed. A plain hash is enough: the question asked of it
/// is "same as last time?", never "what was it?".
/// Takes a `BTreeMap` rather than any iterator on purpose: hashing depends on
/// the order values arrive in, and a `HashMap`'s order varies per process and
/// per insertion. A fingerprint that changed on its own would reset this
/// state on every fetch, quietly turning the pacing off.
pub fn fingerprint(token: &str, values: &BTreeMap<String, String>) -> u64 {
    let mut hasher = DefaultHasher::new();
    token.hash(&mut hasher);
    for (name, value) in values {
        name.hash(&mut hasher);
        value.hash(&mut hasher);
    }
    hasher.finish()
}

/// The map key for one surface of one plugin. `\u{1}` because a plugin id may
/// contain hyphens and underscores (see `PluginManifest::validate`) but not a
/// control character, so no two pairs can collide.
pub fn key(plugin_id: &str, surface_id: &str) -> String {
    format!("{plugin_id}\u{1}{surface_id}")
}

static STATES: Mutex<Option<HashMap<String, State>>> = Mutex::new(None);

/// Run `f` against one surface's state, creating it on first use and adopting
/// `fingerprint` as whose it now is. A poisoned lock is recovered rather than
/// propagated: a panic in some other thread must not be what stops this app
/// from ever polling again.
///
/// Only [`decide`] goes through here, because deciding is the moment the
/// credentials in use are established. Everything else reports *about* a
/// decision already made and goes through [`with_state_of`].
fn with_state<R>(key: &str, fingerprint: u64, f: impl FnOnce(&mut State) -> R) -> R {
    let mut guard = STATES.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    let state = map.entry(key.to_string()).or_default();
    state.adopt(fingerprint);
    f(state)
}

/// Run `f` against one surface's state only while it still belongs to
/// `fingerprint`; `None` when it does not, and nothing is touched.
///
/// A request carries the credentials it left with, and reports back whenever
/// it reports back — the engine hands the fingerprint it captured before the
/// request to `record_success`/`record_failure` after it
/// (`engine_http::fetch_surface`). Sign out and in as somebody else while one
/// is in the air and its answer is news about an account nobody is looking
/// at. Adopting it would do worse than store the wrong thing: it would reset
/// the state the *current* credentials had already built, and a state with no
/// last attempt in it allows a request immediately — so every late reply
/// bought one free request straight through the floor. Generated sequences
/// found that; it is what invariant "no two requests closer than
/// `min_interval`, by any path" means by *any*.
fn with_state_of<R>(key: &str, fingerprint: u64, f: impl FnOnce(&mut State) -> R) -> Option<R> {
    let mut guard = STATES.lock().unwrap_or_else(|e| e.into_inner());
    let state = guard.as_mut()?.get_mut(key)?;
    (state.fingerprint == Some(fingerprint)).then(|| f(state))
}

/// The pacing decision for a surface, and — when it is [`Decision::Fetch`] —
/// the record that the attempt is happening. One call, so the interval is
/// measured even for a request that never comes back.
pub fn decide(key: &str, fingerprint: u64, limits: Limits, now: Instant) -> Decision {
    with_state(key, fingerprint, |state| {
        let decision = state.decide(now, limits);
        if decision == Decision::Fetch {
            state.attempt(now);
        }
        decision
    })
}

pub fn record_success(
    key: &str,
    fingerprint: u64,
    reading: ProviderReading,
    account: Option<String>,
) {
    with_state_of(key, fingerprint, |state| state.success(reading, account));
}

/// The account remembered for these credentials, if one has been resolved
/// since they last changed. See [`State::account`].
pub fn remembered_account(key: &str, fingerprint: u64) -> Option<String> {
    with_state_of(key, fingerprint, |state| state.account().map(str::to_owned)).flatten()
}

pub fn record_failure(
    key: &str,
    fingerprint: u64,
    message: &str,
    terminal: bool,
    limits: Limits,
    now: Instant,
) {
    with_state_of(key, fingerprint, |state| {
        state.failure(now, message, terminal, limits)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Role, TokenRenewal};

    fn limits() -> Limits {
        Limits {
            min_interval: Duration::from_secs(55),
            backoff_start: Duration::from_secs(60),
            backoff_max: Duration::from_secs(900),
            unauthorized_retry: Duration::from_secs(3600),
        }
    }

    fn reading(percent: f64) -> ProviderReading {
        ProviderReading {
            id: "codex".to_string(),
            name: "Codex".to_string(),
            short: "Cx".to_string(),
            tag: Some("PRO".to_string()),
            account: Some("you@example.com".to_string()),
            balances: Vec::new(),
            windows: vec![crate::model::Window {
                key: "codex-wk:".to_string(),
                label: "WK".to_string(),
                role: Role::Secondary,
                used_percent: Some(percent),
                resets_at: Some(1_787_207_494),
                period_minutes: Some(10080),
            }],
            error: None,
            token_renewal: TokenRenewal::No,
            quota_status: None,
            in_menu_bar: true,
            bare_when_sole: false,
        }
    }

    fn served(decision: &Decision) -> Option<&ProviderReading> {
        match decision {
            Decision::Serve(reading) => Some(reading),
            _ => None,
        }
    }

    #[test]
    fn the_first_request_of_a_surface_goes_through() {
        let state = State::default();
        assert_eq!(state.decide(Instant::now(), limits()), Decision::Fetch);
    }

    /// A refusal has to survive the cache, or it disappears for as long as the
    /// minimum interval — a minute in which the panel shows an account as fine
    /// while the provider is turning it away.
    ///
    /// Carried today by cloning the whole reading, which is why this holds
    /// without anything here doing it on purpose. The test is against the
    /// version of this code that stops cloning and starts assembling the
    /// served reading field by field, which is where a field gets forgotten.
    #[test]
    fn a_served_reading_still_carries_the_refusal_the_fetched_one_did() {
        let t0 = Instant::now();
        let mut state = State::default();
        state.attempt(t0);

        let mut blocked = reading(0.0);
        blocked.quota_status = Some(crate::model::QuotaStatus {
            allowed: Some(false),
            limit_reached: Some(true),
            reached_type: Some("rate_limit_reached".to_string()),
        });
        state.success(blocked, None);

        let decision = state.decide(t0 + Duration::from_secs(1), limits());
        let served = served(&decision).expect("inside the minimum interval, this is served");
        let status = served
            .quota_status
            .as_ref()
            .expect("the refusal survives the cache");
        assert!(status.is_blocked());
        assert_eq!(status.reached_type.as_deref(), Some("rate_limit_reached"));
    }

    #[test]
    fn a_burst_inside_the_minimum_interval_is_served_from_the_last_reading() {
        // The panel opened, then opened again nine seconds later, then again:
        // one request, three answers.
        let t0 = Instant::now();
        let mut state = State::default();
        state.attempt(t0);
        state.success(reading(69.0), None);

        for offset in [1, 9, 54] {
            let decision = state.decide(t0 + Duration::from_secs(offset), limits());
            assert_eq!(
                served(&decision).and_then(|r| r.windows[0].used_percent),
                Some(69.0),
                "a fetch {offset}s after the last one must be served from cache"
            );
        }
        assert_eq!(
            state.decide(t0 + Duration::from_secs(55), limits()),
            Decision::Fetch,
            "once the interval has passed, the next request goes through"
        );
    }

    #[test]
    fn the_scheduled_cadence_is_never_the_thing_that_gets_throttled() {
        // The shipped pairing: refresh_secs = 60, min_interval = 55. Ticks
        // land 60s apart, so every scheduled refresh must go through — a
        // floor at or above the cadence would silently halve it.
        let t0 = Instant::now();
        let mut state = State::default();
        for tick in 0..5 {
            let now = t0 + Duration::from_secs(60 * tick);
            assert_eq!(state.decide(now, limits()), Decision::Fetch, "tick {tick}");
            state.attempt(now);
            state.success(reading(69.0), None);
        }
    }

    #[test]
    fn failures_back_off_by_doubling_and_stop_at_the_ceiling() {
        let t0 = Instant::now();
        let mut state = State::default();

        let expected = [60, 120, 240, 480, 900, 900];
        for (i, wait) in expected.into_iter().enumerate() {
            state.failure(t0, "network error", false, limits());
            assert_eq!(
                state.decide(t0 + Duration::from_secs(wait - 1), limits()),
                Decision::Blocked("network error".to_string()),
                "failure {} must still be waiting a second before {wait}s",
                i + 1
            );
            assert_eq!(
                state.decide(t0 + Duration::from_secs(wait), limits()),
                Decision::Fetch,
                "failure {} must retry after {wait}s",
                i + 1
            );
        }
    }

    #[test]
    fn the_floor_holds_even_when_an_attempt_never_reports_back() {
        // A fetch that neither succeeded nor failed — the thread died, the
        // process was interrupted mid-request. Nothing recorded an outcome,
        // so the only thing standing between the next panel open and a live
        // request is that the attempt itself was recorded.
        let t0 = Instant::now();
        let mut state = State::default();
        assert_eq!(state.decide(t0, limits()), Decision::Fetch);
        state.attempt(t0);

        assert!(
            matches!(
                state.decide(t0 + Duration::from_secs(1), limits()),
                Decision::Blocked(_)
            ),
            "a second request one second later must not go out"
        );
        assert_eq!(
            state.decide(t0 + Duration::from_secs(55), limits()),
            Decision::Fetch
        );
    }

    #[test]
    fn a_released_cool_off_still_respects_the_floor() {
        // A short backoff (a manifest may set one) must not become a way
        // around the minimum interval: the attempt the cool-off releases is
        // still an attempt.
        let short = Limits {
            backoff_start: Duration::from_secs(5),
            ..limits()
        };
        let t0 = Instant::now();
        let mut state = State::default();
        state.attempt(t0);
        state.success(reading(69.0), None);
        state.failure(t0 + Duration::from_secs(1), "HTTP 500", false, short);

        // Cool-off is over at t0+6, but only 6s have passed since the request.
        assert!(
            matches!(
                state.decide(t0 + Duration::from_secs(6), short),
                Decision::Serve(_)
            ),
            "the 55s floor outlives a 5s cool-off"
        );
        assert_eq!(
            state.decide(t0 + Duration::from_secs(55), short),
            Decision::Fetch
        );
    }

    #[test]
    fn a_provider_that_comes_back_resets_the_backoff() {
        let t0 = Instant::now();
        let mut state = State::default();
        state.failure(t0, "HTTP 500", false, limits());
        state.failure(t0, "HTTP 500", false, limits());

        let recovered = t0 + Duration::from_secs(240);
        assert_eq!(state.decide(recovered, limits()), Decision::Fetch);
        state.attempt(recovered);
        state.success(reading(70.0), None);

        state.failure(recovered, "HTTP 500", false, limits());
        assert_eq!(
            state.decide(recovered + Duration::from_secs(60), limits()),
            Decision::Fetch,
            "after a success the next failure waits the *first* backoff again (60s), not the third (240s)"
        );
    }

    #[test]
    fn a_backoff_serves_the_last_good_reading_rather_than_a_blank_row() {
        let t0 = Instant::now();
        let mut state = State::default();
        state.attempt(t0);
        state.success(reading(69.0), None);
        state.failure(
            t0 + Duration::from_secs(60),
            "network error",
            false,
            limits(),
        );

        let decision = state.decide(t0 + Duration::from_secs(70), limits());
        assert_eq!(
            served(&decision).and_then(|r| r.windows[0].used_percent),
            Some(69.0)
        );
    }

    #[test]
    fn an_expired_session_stops_polling_and_never_shows_stale_numbers() {
        let t0 = Instant::now();
        let mut state = State::default();
        state.attempt(t0);
        state.success(reading(69.0), None);
        state.failure(t0, crate::plugin::engine_http::UNAUTHORIZED, true, limits());

        for minutes in [1, 5, 30, 59] {
            assert_eq!(
                state.decide(t0 + Duration::from_secs(60 * minutes), limits()),
                Decision::Blocked(crate::plugin::engine_http::UNAUTHORIZED.to_string()),
                "a dead token must not be retried on the refresh cadence ({minutes}m later)"
            );
        }
    }

    #[test]
    fn a_stop_expires_so_nothing_is_ever_stuck_for_good() {
        // The other side of the same rule: a 401 can come from a gateway
        // having a bad minute, with the credentials never changing. If only
        // new credentials could lift the stop, that surface would be silent
        // until the app was restarted — which is the failure this project has
        // already had once, from the other direction.
        let t0 = Instant::now();
        let mut state = State::default();
        state.failure(t0, crate::plugin::engine_http::UNAUTHORIZED, true, limits());

        assert!(matches!(
            state.decide(t0 + Duration::from_secs(3599), limits()),
            Decision::Blocked(_)
        ));
        assert_eq!(
            state.decide(t0 + Duration::from_secs(3600), limits()),
            Decision::Fetch,
            "after the stop expires, exactly one more attempt is allowed"
        );

        // And if that attempt succeeds, nothing about the stop lingers.
        state.attempt(t0 + Duration::from_secs(3600));
        state.success(reading(69.0), None);
        assert!(
            matches!(
                state.decide(t0 + Duration::from_secs(3630), limits()),
                Decision::Serve(_)
            ),
            "the surface is back to ordinary pacing, with a reading to serve"
        );
    }

    #[test]
    fn an_ordinary_failure_can_never_shorten_the_wait_an_expired_session_bought() {
        // The seam to guard here: clearing the session wait on the next
        // ordinary failure would let a provider that alternates 401 and 500
        // be polled every minute instead of every hour.
        let t0 = Instant::now();
        let mut state = State::default();
        state.attempt(t0);
        state.failure(t0, crate::plugin::engine_http::UNAUTHORIZED, true, limits());
        state.failure(
            t0 + Duration::from_secs(1),
            "network error",
            false,
            limits(),
        );

        assert!(
            matches!(
                state.decide(t0 + Duration::from_secs(120), limits()),
                Decision::Blocked(_)
            ),
            "two minutes in, the hour the 401 bought is still running"
        );
        assert_eq!(
            state.decide(t0 + Duration::from_secs(3600), limits()),
            Decision::Fetch
        );
    }

    #[test]
    fn an_expired_stop_does_not_hand_out_a_request_of_its_own() {
        // The expiry lifts a block; it is not a licence to skip the floor.
        // With a manifest whose stop is shorter than its minimum interval,
        // the floor is what still holds.
        let short_stop = Limits {
            unauthorized_retry: Duration::from_secs(5),
            ..limits()
        };
        let t0 = Instant::now();
        let mut state = State::default();
        state.attempt(t0);
        state.failure(
            t0,
            crate::plugin::engine_http::UNAUTHORIZED,
            true,
            short_stop,
        );

        assert!(
            matches!(
                state.decide(t0 + Duration::from_secs(6), short_stop),
                Decision::Blocked(_)
            ),
            "the stop expired, but only 6 of the 55 seconds have passed"
        );
        assert_eq!(
            state.decide(t0 + Duration::from_secs(55), short_stop),
            Decision::Fetch
        );
    }

    #[test]
    fn a_still_dead_token_stops_again_rather_than_retrying_on_the_cadence() {
        let t0 = Instant::now();
        let mut state = State::default();
        state.failure(t0, crate::plugin::engine_http::UNAUTHORIZED, true, limits());
        let retry = t0 + Duration::from_secs(3600);
        assert_eq!(state.decide(retry, limits()), Decision::Fetch);

        state.attempt(retry);
        state.failure(
            retry,
            crate::plugin::engine_http::UNAUTHORIZED,
            true,
            limits(),
        );
        assert!(
            matches!(
                state.decide(retry + Duration::from_secs(60), limits()),
                Decision::Blocked(_)
            ),
            "a token that is genuinely dead is asked about once an hour, not once a minute"
        );
    }

    #[test]
    fn signing_in_again_lifts_the_stop() {
        // The other half of the rule above, and the one this project has been
        // burned by: a stop that outlives the reason for it is a provider
        // that never reports again.
        let t0 = Instant::now();
        let mut state = State::default();
        state.adopt(fingerprint("old-token", &BTreeMap::new()));
        state.failure(t0, "session expired", true, limits());
        assert!(matches!(state.decide(t0, limits()), Decision::Blocked(_)));

        state.adopt(fingerprint("new-token", &BTreeMap::new()));
        assert_eq!(
            state.decide(t0, limits()),
            Decision::Fetch,
            "a new token is a new question, and it must be asked at once"
        );
    }

    #[test]
    fn new_credentials_drop_the_previous_accounts_reading() {
        let t0 = Instant::now();
        let mut state = State::default();
        state.adopt(fingerprint("token-a", &BTreeMap::new()));
        state.attempt(t0);
        state.success(reading(69.0), None);

        state.adopt(fingerprint("token-b", &BTreeMap::new()));
        assert_eq!(
            state.decide(t0, limits()),
            Decision::Fetch,
            "serving the previous login's usage under a new one is the defect this migration is about"
        );
    }

    #[test]
    fn a_changed_header_value_counts_as_changed_credentials() {
        let same_token = "tok";
        let account_a: BTreeMap<String, String> = [("account_id".to_string(), "acc-a".to_string())]
            .into_iter()
            .collect();
        let account_b: BTreeMap<String, String> = [("account_id".to_string(), "acc-b".to_string())]
            .into_iter()
            .collect();
        assert_ne!(
            fingerprint(same_token, &account_a),
            fingerprint(same_token, &account_b),
            "the same token pointed at another account is another account"
        );
        assert_eq!(
            fingerprint(same_token, &account_a),
            fingerprint(same_token, &account_a),
            "and the same credentials must fingerprint the same, or nothing is ever cached"
        );
        // Insertion order must not matter either: two values are hashed by
        // key order, not by how they were collected.
        let two_ways = |pairs: [(&str, &str); 2]| -> u64 {
            fingerprint(
                same_token,
                &pairs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            )
        };
        assert_eq!(
            two_ways([("a", "1"), ("b", "2")]),
            two_ways([("b", "2"), ("a", "1")]),
        );
    }

    #[test]
    fn keys_of_different_surfaces_never_collide() {
        assert_ne!(key("claude", "cli"), key("claude", "desktop"));
        assert_ne!(key("a-b", "c"), key("a", "b-c"));
    }

    #[test]
    fn limits_come_from_the_manifest() {
        let http = crate::plugin::manifest::PluginManifest::from_str(
            r#"
            id         = "l"
            name       = "L"
            menu_label = "Ll"
            order      = 1
            engine     = "http-api"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode    = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "u"
            resets_at_path    = "r"
            [http]
            min_interval_secs  = 30
            backoff_start_secs = 10
            backoff_max_secs   = 100
            [[http.request]]
            url = "https://example.com/usage"
            "#,
        )
        .expect("valid manifest")
        .http
        .expect("[http] section");

        assert_eq!(
            Limits::from_http(&http),
            Limits {
                min_interval: Duration::from_secs(30),
                backoff_start: Duration::from_secs(10),
                backoff_max: Duration::from_secs(100),
                unauthorized_retry: Duration::from_secs(3600),
            }
        );
    }

    #[test]
    fn one_good_answer_lifts_the_wait_an_expired_session_bought() {
        // The one exception to "an expired session waits the full hour", and
        // it is deliberate. Two requests were in the air; one came back 401
        // and bought the hour, the other came back with an answer — carrying
        // the same token. "This token is dead" is the entire reason for the
        // hour, and a 200 holding that token says otherwise, so the wait goes
        // with it. An ordinary *failure* never does this: a network error is
        // evidence of nothing working, and the test below says so.
        let t0 = Instant::now();
        let mut state = State::default();
        state.attempt(t0);
        state.failure(t0, crate::plugin::engine_http::UNAUTHORIZED, true, limits());
        assert!(matches!(
            state.decide(t0 + Duration::from_secs(60), limits()),
            Decision::Blocked(_)
        ));

        state.success(reading(69.0), None);
        assert_eq!(
            state.decide(t0 + Duration::from_secs(60), limits()),
            Decision::Fetch,
            "the token demonstrably works, so nothing is waiting on it being dead"
        );
    }

    #[test]
    fn a_reply_from_a_login_that_has_been_replaced_changes_nothing() {
        // A request carries the credentials it left with and reports back
        // whenever it reports back. Sign in as somebody else while one is in
        // the air and its answer arrives about an account nobody is looking
        // at any more. It used to be adopted anyway, which reset the state
        // the new login had already built — and a state with no last attempt
        // in it lets the very next ask through, whatever the floor says. One
        // free request per late reply.
        //
        // Found by the generated sequences below, at seed 2.
        let now = Instant::now();
        let (old, new) = (
            fingerprint("token-before", &BTreeMap::new()),
            fingerprint("token-after", &BTreeMap::new()),
        );
        let surface = key("test-late-reply", "default");

        assert_eq!(
            decide(&surface, old, limits(), now),
            Decision::Fetch,
            "a request goes out"
        );
        assert_eq!(
            decide(&surface, new, limits(), now),
            Decision::Fetch,
            "then a new login, asked at once as it should be"
        );

        // The first request finally answers, still speaking for the old login.
        record_failure(&surface, old, "network error", false, limits(), now);
        record_success(&surface, old, reading_of(old), None);

        assert!(
            matches!(decide(&surface, new, limits(), now), Decision::Blocked(_)),
            "the new login's own floor is still standing, and it has nothing of its own to show"
        );
    }

    // ── Generated sequences ──────────────────────────────────────────────
    //
    // Every test above closes one seam in this state machine — an expired
    // stop handing out a request past both the floor and the cool-off, a
    // lapsed deadline doing the same, an ordinary failure cancelling the hour
    // a 401 had bought. Each was closed by a test that describes exactly the
    // path that produced it, and none of those tests would have found either
    // of the others.
    //
    // What follows says the rules instead of the paths: throw random
    // sequences of everything that can happen at the surface the engine
    // actually uses, and check the four things that must be true of every
    // one of them. The generator is a plain xorshift with the sequence
    // number for a seed — a failure names the seed and prints what led to
    // it, so it can be replayed. No dependency for this: a few thousand
    // sequences of a few dozen events each is arithmetic, and this project
    // does not add a crate to do arithmetic.

    /// xorshift64. Not a good random number generator; a perfectly good
    /// deterministic one, which is what a reproducible failure needs.
    struct Rng(u64);

    impl Rng {
        fn seeded(seed: u64) -> Self {
            // Odd, non-zero, and spread out: xorshift stays at zero forever
            // if it ever reaches it, and neighbouring seeds otherwise open
            // with suspiciously similar sequences.
            Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
        }

        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }

        fn pick(&mut self, from: &[u64]) -> u64 {
            from[self.below(from.len() as u64) as usize]
        }
    }

    /// Pacing knobs drawn from the plausible and the awkward alike: a floor
    /// of zero, a cool-off ceiling below its own starting point, a session
    /// wait shorter than the floor. A manifest may declare any of these, and
    /// the seams this module has already had came from exactly such corners.
    fn generated_limits(rng: &mut Rng) -> Limits {
        Limits {
            min_interval: Duration::from_secs(rng.pick(&[0, 1, 55, 300])),
            backoff_start: Duration::from_secs(rng.pick(&[1, 5, 60])),
            backoff_max: Duration::from_secs(rng.pick(&[1, 60, 900])),
            unauthorized_retry: Duration::from_secs(rng.pick(&[5, 600, 3600])),
        }
    }

    /// The wait the documented rule calls for after `streak` ordinary
    /// failures in a row: `backoff_start` doubled once per failure, never
    /// past `backoff_max`. Written from the sentence at the top of this file
    /// rather than by calling [`backoff_delay`] — an oracle that calls the
    /// thing it is checking agrees with it about everything, including being
    /// wrong.
    fn backoff_of(streak: u32, limits: Limits) -> u64 {
        limits
            .backoff_start
            .as_secs()
            .saturating_mul(
                1u64.checked_shl(streak.saturating_sub(1))
                    .unwrap_or(u64::MAX),
            )
            .min(limits.backoff_max.as_secs())
    }

    /// A reading that says whose it is, so serving one account's numbers
    /// under another's login is a visible difference rather than a matter of
    /// trusting the reset.
    fn reading_of(fingerprint: u64) -> ProviderReading {
        ProviderReading {
            account: Some(format!("acct-{fingerprint}")),
            ..reading(42.0)
        }
    }

    #[test]
    fn generated_sequences_keep_every_pacing_rule_whatever_the_order() {
        for seed in 1..=3_000u64 {
            if let Err(broken) = run_generated_sequence(seed) {
                panic!("{broken}");
            }
        }
    }

    /// One generated sequence. `Err` carries the rule that broke, the seed
    /// that produced it and every event up to it.
    fn run_generated_sequence(seed: u64) -> Result<(), String> {
        let mut rng = Rng::seeded(seed);
        let limits = generated_limits(&mut rng);
        // A key of its own: the map these calls go through is process-wide,
        // and a sequence that inherited another's state would be neither
        // reproducible nor about anything.
        let surface = key("generated-throttle", &format!("seq-{seed}"));
        let t0 = Instant::now();

        let mut at = 0u64; // seconds since t0; monotonic, like the clock
        let mut logins = 0u64;
        let mut fingerprint_now = fingerprint("token-0", &BTreeMap::new());
        let mut trail: Vec<String> = Vec::new();

        // What the rules say, tracked beside the machine that has to obey.
        let mut last_fetch: Option<u64> = None;
        // The earliest a fetch may happen, as bought by failures since the
        // last success. Deliberately a *lower bound* on the wait rather than
        // a copy of `backoff_delay`: a test that recomputes the formula
        // agrees with a wrong formula.
        let mut earliest = 0u64;
        // Ordinary failures in a row since the last success, terminal failure
        // or change of login — the three things that put the doubling back to
        // the start. Mirrors the rule this module documents ("double the wait
        // from `backoff_start` up to `backoff_max`") rather than calling
        // `backoff_delay`, so a cool-off that stopped doubling is a failure
        // here and not an agreement.
        let mut streak = 0u32;
        // A surface nothing has asked yet owes an answer to the first ask,
        // the same way a surface whose login just changed does.
        let mut owed_a_fetch = true;
        // Requests that have gone out and not yet reported back, each
        // remembering the credentials it left with — which is what the engine
        // does (`engine_http::fetch_surface` captures the fingerprint before
        // the request and hands it to `record_success`/`record_failure`
        // afterwards). Replies arrive as their own events, in any order and
        // however much later: a request is a thread, and the outcome of two
        // overlapping ones is not the order they were sent in.
        let mut in_flight: Vec<u64> = Vec::new();

        let fail = |rule: &str, trail: &[String]| -> String {
            format!(
                "{rule}\n  seed {seed}, limits {limits:?}\n  events:\n    {}",
                trail.join("\n    ")
            )
        };

        for _ in 0..48 {
            match rng.below(10) {
                // A moment passes. Nothing here sleeps; the clock is an
                // argument, which is why it can leap an hour in a test.
                0 | 1 => {
                    // Weighted small. A step drawn flat from two hours would
                    // clear every floor and every cool-off almost every time,
                    // and the interesting moments are the ones just before
                    // and just after a deadline, not an hour past it.
                    at += match rng.below(4) {
                        0 => 0,
                        1 => rng.below(120),
                        2 => rng.below(1_200),
                        _ => rng.below(7_200),
                    };
                    trail.push(format!("{at}s: clock moved"));
                }
                // Signed out and back in as somebody else.
                2 => {
                    logins += 1;
                    fingerprint_now = fingerprint(&format!("token-{logins}"), &BTreeMap::new());
                    last_fetch = None;
                    earliest = 0;
                    streak = 0;
                    owed_a_fetch = true;
                    trail.push(format!("{at}s: new credentials (#{logins})"));
                }
                // A request that went out earlier reports back — possibly
                // after the login it was made under has been replaced.
                3 | 4 if !in_flight.is_empty() => {
                    let which = rng.below(in_flight.len() as u64) as usize;
                    let whose = in_flight.remove(which);
                    let now = t0 + Duration::from_secs(at);
                    let current = whose == fingerprint_now;
                    let mine = if current {
                        ""
                    } else {
                        " (from a previous login)"
                    };

                    match rng.below(3) {
                        0 => {
                            record_success(&surface, whose, reading_of(whose), None);
                            if current {
                                earliest = 0;
                                streak = 0;
                            }
                            trail.push(format!("{at}s: reply{mine}: answered"));
                        }
                        1 => {
                            record_failure(
                                &surface,
                                whose,
                                crate::plugin::engine_http::UNAUTHORIZED,
                                true,
                                limits,
                                now,
                            );
                            if current {
                                earliest = earliest.max(at + limits.unauthorized_retry.as_secs());
                                streak = 0;
                            }
                            trail.push(format!("{at}s: reply{mine}: session expired"));
                        }
                        _ => {
                            record_failure(&surface, whose, "network error", false, limits, now);
                            if current {
                                streak += 1;
                                earliest = earliest.max(at + backoff_of(streak, limits));
                            }
                            trail.push(format!("{at}s: reply{mine}: failed"));
                        }
                    }
                }
                // …and a request that never reports back at all: the thread
                // died, the process was interrupted mid-request. Nothing
                // records an outcome; the floor is the only thing left
                // holding.
                5 if !in_flight.is_empty() => {
                    let which = rng.below(in_flight.len() as u64) as usize;
                    in_flight.remove(which);
                    trail.push(format!("{at}s: a request never came back"));
                }
                // Something asked this surface for a reading: the timer, the
                // panel opening, a Refresh button, the app starting.
                _ => {
                    let now = t0 + Duration::from_secs(at);
                    let decision = decide(&surface, fingerprint_now, limits, now);

                    match &decision {
                        Decision::Fetch => {
                            trail.push(format!("{at}s: asked -> fetch"));
                            if let Some(last) = last_fetch {
                                if at - last < limits.min_interval.as_secs() {
                                    return Err(fail(
                                        &format!(
                                            "two requests {}s apart, under the {}s floor",
                                            at - last,
                                            limits.min_interval.as_secs()
                                        ),
                                        &trail,
                                    ));
                                }
                            }
                            if at < earliest {
                                return Err(fail(
                                    &format!(
                                        "a request at {at}s, inside a wait that runs to {earliest}s"
                                    ),
                                    &trail,
                                ));
                            }
                            last_fetch = Some(at);
                            owed_a_fetch = false;
                            in_flight.push(fingerprint_now);
                        }
                        Decision::Serve(served) => {
                            trail.push(format!("{at}s: asked -> served from cache"));
                            if owed_a_fetch {
                                return Err(fail(
                                    "a new login was served the previous one's cache instead of \
                                     being asked at once",
                                    &trail,
                                ));
                            }
                            let whose = format!("acct-{fingerprint_now}");
                            if served.account.as_deref() != Some(whose.as_str()) {
                                return Err(fail(
                                    &format!(
                                        "served {:?} while signed in as {whose}",
                                        served.account
                                    ),
                                    &trail,
                                ));
                            }
                        }
                        Decision::Blocked(_) => {
                            trail.push(format!("{at}s: asked -> held"));
                            if owed_a_fetch {
                                return Err(fail(
                                    "a new login was held back rather than asked at once",
                                    &trail,
                                ));
                            }
                        }
                    }
                }
            }
        }

        // And the other half of every rule above, which they do not state:
        // that the holding ever ends. Each invariant so far says a request
        // must not go out too early, and a surface that never fetches again
        // satisfies all of them — which is not a hypothetical here. A 401
        // that stopped the polling outright, lifted only by signing in again,
        // is a defect this project has already shipped once. So: wait past
        // every deadline any of these limits can name, and ask.
        let quiet = limits
            .min_interval
            .max(limits.backoff_max)
            .max(limits.unauthorized_retry)
            .as_secs()
            + 1;
        at += quiet;
        let woken = decide(
            &surface,
            fingerprint_now,
            limits,
            t0 + Duration::from_secs(at),
        );
        if woken != Decision::Fetch {
            trail.push(format!("{at}s: asked after {quiet}s of quiet -> {woken:?}"));
            return Err(fail(
                "nothing was asked again even after every wait these limits can name had passed",
                &trail,
            ));
        }
        Ok(())
    }

    #[test]
    fn the_process_wide_map_keeps_surfaces_apart() {
        let now = Instant::now();
        let fp = fingerprint("tok", &BTreeMap::new());
        let (a, b) = (
            key("test-throttle-a", "default"),
            key("test-throttle-b", "default"),
        );

        assert_eq!(decide(&a, fp, limits(), now), Decision::Fetch);
        record_success(&a, fp, reading(1.0), None);
        assert!(
            matches!(decide(&a, fp, limits(), now), Decision::Serve(_)),
            "the surface that just fetched is paced"
        );
        assert_eq!(
            decide(&b, fp, limits(), now),
            Decision::Fetch,
            "another surface's pacing is its own"
        );
    }
}
