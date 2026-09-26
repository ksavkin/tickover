//! Read-side aggregation over the append-only bucket log.
//!
//! Buckets are stored per UTC hour; every local-day view is resolved here
//! at query time through [`chrono::Local`], so DST's 23/25-hour days fall
//! out of the conversion instead of needing their own handling.
//!
//! The one rule that shapes every method: **a provider with no `[history]`
//! data contributes nothing, and is never averaged into a total that
//! implies coverage.** Views that would lie — like a blended cache-hit
//! ratio across providers where only some report cache classes — expose
//! their ingredients so the caller can label partial coverage honestly.

use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Datelike, Duration, Local, NaiveDate, TimeZone, Timelike, Utc};

use crate::history::store::{DayLine, HistoryStore};

/// Token-class counters shared by every grouping.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Totals {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub thinking: u64,
    /// Requests/turns folded in — the count behind the tokens.
    pub messages: u64,
}

impl Totals {
    pub fn add(&mut self, d: &DayLine) {
        self.input += d.input;
        self.output += d.output;
        self.cache_read += d.cache_read;
        self.cache_write += d.cache_write;
        self.thinking += d.thinking;
        self.messages += u64::from(d.messages);
    }
    pub fn sum(&self) -> u64 {
        self.input + self.output + self.cache_read + self.cache_write + self.thinking
    }
    /// Tokens that had to be generated — everything except cache reads.
    /// The panel's "burn" figure; counting cache reads would let a resent
    /// context mark a light user as heavy forever.
    pub fn active(&self) -> u64 {
        self.input + self.output + self.cache_write + self.thinking
    }
    /// Cache-hit ratio over read-or-fresh input, `None` when there is no
    /// input traffic at all (a 0/0 ratio is meaningless, not 0%).
    pub fn cache_hit_pct(&self) -> Option<f64> {
        let denom = self.cache_read + self.input;
        (denom > 0).then(|| self.cache_read as f64 * 100.0 / denom as f64)
    }
}

/// One session's roll-up — the report's "top sessions" and the panel's
/// session counter share this shape.
#[derive(Debug, Clone)]
pub struct SessionStat {
    pub session: String,
    pub provider: String,
    pub project: String,
    pub model: String,
    pub first_hour: String,
    pub last_hour: String,
    pub totals: Totals,
}

/// The whole query surface, computed once from `live_days()`.
pub struct Stats {
    /// Providers that contributed at least one live bucket.
    pub providers: Vec<String>,
    /// All-time and ranged totals.
    pub total: Totals,
    pub today: Totals,
    pub week: Totals,
    pub month: Totals,
    /// Per-provider totals, all-time.
    pub by_provider: BTreeMap<String, Totals>,
    /// Today only, per provider — the panel's provider rows.
    pub today_by_provider: BTreeMap<String, Totals>,
    /// Projects sorted by total desc (all-time).
    pub projects: Vec<(String, Totals)>,
    /// Models sorted by total desc.
    pub models: Vec<(String, Totals)>,
    /// Per-provider model split — pricing needs it: a provider's cost is
    /// the sum over its models, never a blend priced at one rate.
    pub by_provider_model: BTreeMap<String, Vec<(String, Totals)>>,
    /// Local calendar day → totals, ascending, covering the last `days`
    /// days (sparse days absent).
    pub daily: BTreeMap<NaiveDate, Totals>,
    /// Last 52 weeks of daily totals for the heatmap — dense, zeros kept,
    /// oldest first, aligned to weeks (each entry is a Sunday-start week
    /// of 7 `(date, total)` pairs).
    pub heatmap: Vec<Vec<(NaiveDate, u64)>>,
    /// Token volume by local hour-of-day, all-time — the report's
    /// "active hours" strip.
    pub active_hours: [u64; 24],
    /// Sessions sorted by total desc.
    pub sessions: Vec<SessionStat>,
    /// Consecutive local days ending today (or yesterday, if today has no
    /// usage yet) with nonzero totals.
    pub streak_days: u32,
    /// All-time count of days with any usage — `daily` is bounded by the
    /// `days` argument, so the report's all-time cards need this instead.
    pub active_days: u64,
    /// Cumulative unparsed-line count across all tracked files.
    pub skipped_unparsed: u64,
}

/// Compute everything [`Stats`] exposes over the store's live buckets.
/// `days` bounds `daily`/`heatmap` lookback; all-time groupings ignore it.
/// `enabled` is the providers the user hasn't disabled — a disabled
/// provider's stored buckets stay on disk but drop out of every figure,
/// matching what its hidden quota card already implies.
pub fn compute(
    store: &HistoryStore,
    days: u32,
    enabled: &std::collections::HashSet<String>,
) -> Stats {
    let now = Local::now();
    let today = now.date_naive();
    let week_start = today - Duration::days(today.weekday().num_days_from_monday() as i64);
    let month_start = today.with_day(1).unwrap_or(today);
    let daily_floor = today - Duration::days(i64::from(days));

    let mut st = Stats {
        providers: Vec::new(),
        total: Totals::default(),
        today: Totals::default(),
        week: Totals::default(),
        month: Totals::default(),
        by_provider: BTreeMap::new(),
        today_by_provider: BTreeMap::new(),
        projects: Vec::new(),
        models: Vec::new(),
        by_provider_model: BTreeMap::new(),
        daily: BTreeMap::new(),
        heatmap: Vec::new(),
        active_hours: [0; 24],
        sessions: Vec::new(),
        streak_days: 0,
        active_days: 0,
        skipped_unparsed: store
            .state()
            .files
            .values()
            .filter(|f| enabled.contains(&f.provider))
            .map(|f| f.skipped_unparsed)
            .sum(),
    };

    let mut projects: HashMap<String, Totals> = HashMap::new();
    let mut models: HashMap<String, Totals> = HashMap::new();
    let mut provider_models: HashMap<String, HashMap<String, Totals>> = HashMap::new();
    let mut sessions: HashMap<String, SessionStat> = HashMap::new();
    // Day-total map feeding both `daily` (bounded) and `heatmap` (52 wk).
    let mut day_totals: BTreeMap<NaiveDate, u64> = BTreeMap::new();

    for d in store.live_days() {
        if !enabled.contains(&d.provider) {
            continue;
        }
        // Bucket hour is UTC `"YYYY-MM-DDTHH"` — convert to the local
        // instant, then take the local date/hour for day-level views.
        let Some(hour_utc) = parse_bucket_hour(&d.hour) else {
            continue;
        };
        let local: DateTime<Local> = hour_utc.with_timezone(&Local);
        let day = local.date_naive();

        st.total.add(d);
        if day == today {
            st.today.add(d);
        }
        if day >= week_start {
            st.week.add(d);
        }
        if day >= month_start {
            st.month.add(d);
        }
        st.active_hours[local.hour() as usize] += d.sum();

        // A line that records no tokens and no messages did not happen on
        // any day, isn't a session, and isn't a provider/project/model the
        // user actually used — a coverage tombstone always looks like
        // this, but so would any other bucket that genuinely summed to
        // zero, and both must drop out the same way: what matters is what
        // the line records, not why. `total`/`today`/`week`/`month` and
        // `active_hours` above are the exception: they describe coverage
        // (bytes the scanner has read), not activity, so a tombstone's
        // zero folds into them exactly as it always did.
        if !d.has_activity() {
            continue;
        }
        st.by_provider.entry(d.provider.clone()).or_default().add(d);
        if day == today {
            st.today_by_provider
                .entry(d.provider.clone())
                .or_default()
                .add(d);
        }
        projects.entry(d.project.clone()).or_default().add(d);
        models.entry(d.model.clone()).or_default().add(d);
        provider_models
            .entry(d.provider.clone())
            .or_default()
            .entry(d.model.clone())
            .or_default()
            .add(d);
        *day_totals.entry(day).or_default() += d.sum();
        if day >= daily_floor {
            st.daily.entry(day).or_default().add(d);
        }

        let sess = sessions
            .entry(format!("{}:{}", d.provider, d.session))
            .or_insert_with(|| SessionStat {
                session: d.session.clone(),
                provider: d.provider.clone(),
                project: d.project.clone(),
                model: d.model.clone(),
                first_hour: d.hour.clone(),
                last_hour: d.hour.clone(),
                totals: Totals::default(),
            });
        sess.totals.add(d);
        if d.hour < sess.first_hour {
            sess.first_hour = d.hour.clone();
        }
        if d.hour > sess.last_hour {
            sess.last_hour = d.hour.clone();
        }
    }

    st.providers = st.by_provider.keys().cloned().collect();
    st.projects = sorted_desc(projects);
    st.models = sorted_desc(models);
    st.by_provider_model = provider_models
        .into_iter()
        .map(|(p, m)| (p, sorted_desc(m)))
        .collect();
    st.sessions = {
        let mut v: Vec<SessionStat> = sessions.into_values().collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.totals.sum()));
        v
    };
    st.streak_days = streak(&day_totals, today);
    st.active_days = day_totals.len() as u64;
    st.heatmap = heatmap(&day_totals, today);
    st
}

/// `"YYYY-MM-DDTHH"` (UTC) → the hour as a `DateTime<Utc>`.
fn parse_bucket_hour(hour: &str) -> Option<DateTime<Utc>> {
    let date = NaiveDate::parse_from_str(hour.get(..10)?, "%Y-%m-%d").ok()?;
    let h: u32 = hour.get(11..)?.parse().ok()?;
    Some(Utc.from_utc_datetime(&date.and_hms_opt(h, 0, 0)?))
}

/// Consecutive days with usage, ending today if today has any, else
/// ending yesterday (a day not yet over still counts as "in progress" —
/// the streak dies only after a fully-past empty day).
fn streak(day_totals: &BTreeMap<NaiveDate, u64>, today: NaiveDate) -> u32 {
    let mut end = today;
    if !day_totals.contains_key(&today) {
        end = today - Duration::days(1);
    }
    let mut n = 0;
    while day_totals.contains_key(&end) {
        n += 1;
        end -= Duration::days(1);
    }
    n
}

/// The most recent completed streak — the run of active days that ended
/// before the live one (or before today, when the live one is empty). The
/// empty-range state prints it as "streak ended at Nd"; a run that could
/// still grow is not "ended", so a live streak never counts here.
fn ended_streak(day_totals: &BTreeMap<NaiveDate, u64>, today: NaiveDate, current: u32) -> u32 {
    // Where the live streak is anchored — `streak` counts from yesterday
    // when today has no activity yet.
    let cur_end = if day_totals.contains_key(&today) {
        today
    } else {
        today - Duration::days(1)
    };
    // One day before the live run started; when the live run is empty this
    // is two days back, and the quiet tail is skipped to the last active
    // day either way.
    let mut end = cur_end - Duration::days(current as i64 + 1);
    if let Some(&first) = day_totals.keys().next() {
        while end >= first && !day_totals.contains_key(&end) {
            end -= Duration::days(1);
        }
    } else {
        return 0;
    }
    let mut n = 0;
    while day_totals.contains_key(&end) {
        n += 1;
        end -= Duration::days(1);
    }
    n
}

/// 52 Sunday-aligned weeks ending this week, each a 7-day row of
/// `(date, total)` — zeros included so the renderer can stay dumb.
fn heatmap(day_totals: &BTreeMap<NaiveDate, u64>, today: NaiveDate) -> Vec<Vec<(NaiveDate, u64)>> {
    let this_week_sun = today - Duration::days(today.weekday().num_days_from_sunday() as i64);
    let first_sun = this_week_sun - Duration::weeks(51);
    (0..52)
        .map(|w| {
            let start = first_sun + Duration::weeks(w);
            (0..7)
                .map(|d| {
                    let date = start + Duration::days(d);
                    (date, day_totals.get(&date).copied().unwrap_or(0))
                })
                .collect()
        })
        .collect()
}

fn sorted_desc(map: HashMap<String, Totals>) -> Vec<(String, Totals)> {
    let mut v: Vec<_> = map.into_iter().collect();
    v.sort_by(|a, b| b.1.sum().cmp(&a.1.sum()).then(a.0.cmp(&b.0)));
    v
}

impl Stats {
    /// This provider's per-model totals — the input `pricing` needs for a
    /// provider-level estimate.
    pub fn provider_models(&self, provider: &str) -> Vec<(String, Totals)> {
        self.by_provider_model
            .get(provider)
            .cloned()
            .unwrap_or_default()
    }
}

// ── Panel summary ───────────────────────────────────────────────────────────

/// The Activity card's range toggle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelRange {
    /// Last 24 hours, hourly bars.
    Day,
    /// Last 7 local days, daily bars.
    Week,
    /// Last 30 local days, daily bars.
    Month,
}

/// Which face the Activity card shows — the design's three panel states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PanelState {
    /// Store has never seen a record: ghosted sparkline, explainer copy.
    #[default]
    FirstRun,
    /// History exists, but the selected range is empty: `0`, quiet copy,
    /// the last-seen session named.
    EmptyRange,
    /// Ordinary populated card.
    Data,
}

/// Everything the Activity card draws, computed in one pass. Strings the
/// card shows verbatim are formatted by the caller (`stats_cli`/`main`),
/// not here — this struct stays numeric so the UI stays dumb.
#[derive(Debug, Default)]
pub struct PanelSummary {
    pub state: PanelState,
    /// Total tokens inside the range (every class — the headline).
    pub headline: u64,
    /// Range total vs. the comparison baseline, e.g. +0.38. `None` when the
    /// baseline is zero (a percentage against nothing would lie).
    pub delta: Option<f64>,
    /// Bar heights 0..=1 over the range's buckets — 24 for [`PanelRange::Day`]
    /// (hours), 7 or 30 for the others (days). `spark.len()-1` is the
    /// current bucket, drawn in the accent.
    pub spark: Vec<f32>,
    /// Token-class shares of the range total: `[cache_read, cache_write,
    /// input, output]` — the order the four-segment bar draws them.
    pub segments: [f32; 4],
    /// `cache_read / (cache_read + input)` over the range.
    pub cache_hit_pct: Option<f64>,
    /// Range totals the legend names: `in`/`out` token counts and an
    /// optional estimated cost (set only when the user opted in).
    pub in_tokens: u64,
    pub out_tokens: u64,
    pub est_cost: Option<f64>,
    /// Top 2 projects in range: `(name, share 0..=1, tokens)`.
    pub projects: Vec<(String, f32, u64)>,
    /// All-time streak and the range's session count — the footer pair.
    pub streak_days: u32,
    /// The most recent *completed* streak — what "streak ended at Nd" names
    /// in the empty-range state. `0` when there is no completed run at all.
    pub streak_ended: u32,
    pub sessions: u64,
    /// For the empty-range state: when and where usage last happened —
    /// "yesterday 23:14 on codewiki" as `(timestamp, project)`.
    pub last_seen: Option<(DateTime<Local>, String)>,
    /// Enabled providers with no `[history]` section at all — named so the
    /// card can say "N counted, X not counted" (design §6: the not-counted
    /// mark is for providers that *cannot* publish local history, not for
    /// ones that merely saw no usage in the range).
    pub not_counted: Vec<String>,
}

/// What [`panel`] takes to price a `(provider, model, Totals)` triple —
/// `None` disables cost estimation entirely (the config's opt-in).
pub type CostFn<'a> = Option<&'a dyn Fn(&str, &str, &Totals) -> Option<f64>>;

/// Compute the Activity card's data for `range`.
///
/// `quota_only` is the enabled providers with no `[history]` section: they
/// land in `not_counted` so the card can mark partial coverage instead of
/// implying it.
pub fn panel(
    store: &HistoryStore,
    range: PanelRange,
    quota_only: &[String],
    enabled: &std::collections::HashSet<String>,
    cost_fn: CostFn,
) -> PanelSummary {
    let now = Local::now();
    let today = now.date_naive();
    let mut out = PanelSummary {
        last_seen: last_seen(store, enabled),
        ..Default::default()
    };

    // Range bounds as local-day / UTC-hour windows. Day is an hourly view
    // (buckets are already UTC hours); Week/Month aggregate whole local days.
    let range_start_hour: Option<DateTime<Utc>> = match range {
        PanelRange::Day => Some(now.with_timezone(&Utc) - Duration::hours(24)),
        _ => None,
    };
    let day_floor = match range {
        PanelRange::Day => today,
        PanelRange::Week => today - Duration::days(6),
        PanelRange::Month => today - Duration::days(29),
    };

    // Buckets for the sparkline: hour slots for Day, day slots otherwise —
    // dense, so a quiet stretch draws a flat run instead of missing bars.
    let mut slots: Vec<u64> = match range {
        PanelRange::Day => vec![0; 24],
        PanelRange::Week => vec![0; 7],
        PanelRange::Month => vec![0; 30],
    };
    // Slot index per bucket, computed per line.
    let slot_of = |d: &DayLine| -> Option<usize> {
        let hour_utc = parse_bucket_hour(&d.hour)?;
        let local: DateTime<Local> = hour_utc.with_timezone(&Local);
        match range {
            PanelRange::Day => {
                let start = *range_start_hour.as_ref().unwrap();
                if hour_utc >= start && hour_utc <= now.with_timezone(&Utc) {
                    Some((hour_utc - start).num_hours().clamp(0, 23) as usize)
                } else {
                    None
                }
            }
            _ => {
                let day = local.date_naive();
                if day < day_floor || day > today {
                    return None;
                }
                Some((day - day_floor).num_days() as usize)
            }
        }
    };

    // For the delta baseline: the previous window of equal length.
    // 24h compares against the mean of the preceding 7 days (the design's
    // "vs 7d avg"); 7d/30d against the window immediately before.
    let (base_lo, base_hi): (NaiveDate, NaiveDate) = match range {
        PanelRange::Day => (today - Duration::days(7), today - Duration::days(1)),
        PanelRange::Week => (day_floor - Duration::days(7), day_floor - Duration::days(1)),
        PanelRange::Month => (
            day_floor - Duration::days(30),
            day_floor - Duration::days(1),
        ),
    };
    // The window's own length, in days — fixed by `base_lo`/`base_hi`
    // regardless of which of those days actually saw usage. A day with no
    // data is still a day: it still occupies a slot in the average, or the
    // same total spread over fewer days would look bigger than it is.
    let base_days_span = (base_hi - base_lo).num_days() + 1;
    let mut base_total = 0u64;

    let mut class_totals = Totals::default();
    let mut projects: HashMap<String, Totals> = HashMap::new();
    let mut sessions: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut range_total = 0u64;
    let mut any_history = false;
    // (provider, model) totals inside the range — priced per pair.
    let mut price_units: HashMap<(String, String), Totals> = HashMap::new();

    for d in store.live_days() {
        if !enabled.contains(&d.provider) {
            continue;
        }
        any_history = true;
        let Some(hour_utc) = parse_bucket_hour(&d.hour) else {
            continue;
        };
        let local: DateTime<Local> = hour_utc.with_timezone(&Local);
        let day = local.date_naive();
        if day >= base_lo && day <= base_hi {
            base_total += d.sum();
        }
        let Some(slot) = slot_of(d) else { continue };
        slots[slot] += d.sum();
        range_total += d.sum();
        class_totals.add(d);
        // See `compute`'s identical guard: a line recording nothing is not
        // a project or a (provider, model) pair the user actually used,
        // and not a session either — the totals above describe coverage,
        // not activity, so they alone stay unconditional.
        if d.has_activity() {
            projects.entry(d.project.clone()).or_default().add(d);
            sessions.insert(format!("{}:{}", d.provider, d.session));
            price_units
                .entry((d.provider.clone(), d.model.clone()))
                .or_default()
                .add(d);
        }
    }

    out.headline = range_total;
    let peak = slots.iter().copied().max().unwrap_or(0);
    out.spark = if peak == 0 {
        // Flat ghost row: a quiet range draws dashes of track, not bumps.
        slots.iter().map(|_| 0.0f32).collect()
    } else {
        slots.iter().map(|&v| v as f32 / peak as f32).collect()
    };

    out.delta = match range {
        // Mean daily total over the whole 7-day baseline window, never
        // over just how much of it happened to carry data — the window's
        // own length (`base_days_span`) is fixed, unlike the count of
        // days with data.
        PanelRange::Day => Some(base_total as f64 / base_days_span as f64),
        // Week/Month compare `range_total` against `base_total` directly:
        // both are sums over windows of the same length (7 or 30 days),
        // so no division is needed — a per-day average and a ratio of the
        // two totals agree once the lengths already match.
        _ => (base_total > 0).then_some(base_total as f64),
    }
    .filter(|b| *b > 0.0)
    .map(|b| (range_total as f64 - b) / b);

    let denom = range_total.max(1) as f32;
    // `thinking` folds into the output segment, matching the report's
    // mix bar — providers that report reasoning separately would otherwise
    // leave that share of the range unaccounted in the bar.
    out.segments = [
        class_totals.cache_read as f32 / denom,
        class_totals.cache_write as f32 / denom,
        class_totals.input as f32 / denom,
        (class_totals.output + class_totals.thinking) as f32 / denom,
    ];
    out.cache_hit_pct = class_totals.cache_hit_pct();
    out.in_tokens = class_totals.input;
    out.out_tokens = class_totals.output + class_totals.thinking;
    out.est_cost = cost_fn.and_then(|f| {
        let mut sum = 0.0;
        let mut any = false;
        for ((p, m), t) in &price_units {
            if let Some(c) = f(p, m, t) {
                sum += c;
                any = true;
            }
        }
        any.then_some(sum)
    });
    out.projects = sorted_desc(projects)
        .into_iter()
        .take(2)
        .map(|(name, t)| (name, t.sum() as f32 / range_total.max(1) as f32, t.sum()))
        .collect();
    out.sessions = sessions.len() as u64;
    let day_totals = store
        .live_days()
        .filter(|d| enabled.contains(&d.provider) && d.has_activity())
        .filter_map(|d| {
            let h = parse_bucket_hour(&d.hour)?;
            let local: DateTime<Local> = h.with_timezone(&Local);
            Some((local.date_naive(), d.sum()))
        })
        .fold(BTreeMap::new(), |mut m, (day, s)| {
            *m.entry(day).or_insert(0) += s;
            m
        });
    out.streak_days = streak(&day_totals, today);
    // "Ended" names the most recent *completed* run — the live run is
    // skipped whether it is anchored at today or yesterday, since a run
    // that could still grow has not ended.
    out.streak_ended = ended_streak(&day_totals, today, out.streak_days);
    out.not_counted = quota_only.to_vec();

    out.state = if !any_history {
        PanelState::FirstRun
    } else if range_total == 0 {
        PanelState::EmptyRange
    } else {
        PanelState::Data
    };
    out
}

/// Most recent bucket with any usage — the empty state's "last session
/// was …" line.
fn last_seen(
    store: &HistoryStore,
    enabled: &std::collections::HashSet<String>,
) -> Option<(DateTime<Local>, String)> {
    store
        .live_days()
        .filter(|d| enabled.contains(&d.provider) && d.has_activity())
        .filter_map(|d| {
            parse_bucket_hour(&d.hour).map(|h| (h, d.project.clone(), d.session.clone()))
        })
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(h, project, _)| (h.with_timezone(&Local), project))
}

/// Whether `hour` has exactly the shape every bucket the scanner writes
/// has — `"YYYY-MM-DDTHH"`, fixed-width, zero-padded, *and* a real calendar
/// hour (scanner.rs stamps each one with `DateTime::format("%Y-%m-%dT%H")`,
/// which can never emit `"2026-02-30"` or an hour past 23). Calendar
/// validity is not optional here: `parse_bucket_hour` rejects an impossible
/// date or `h >= 24`, and a shape check that only looked at digit
/// placement would accept one of those and then compare it lexicographically
/// instead of dropping it — counting a bucket the parser, and `compute`'s
/// own load path, never would. Still O(1): four small digit folds and one
/// calendar lookup (leap years included), never a full
/// `NaiveDate::parse_from_str`. `parse_bucket_hour` stays looser on
/// purpose — it also accepts an unpadded hour like `"...T7"` — so anything
/// this check can't vouch for falls back to it rather than being treated
/// as malformed outright.
fn bucket_hour_well_formed(hour: &str) -> bool {
    let b = hour.as_bytes();
    if b.len() != 13 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
        return false;
    }
    let is_digits = |s: &[u8]| s.iter().all(u8::is_ascii_digit);
    if !is_digits(&b[..4])
        || !is_digits(&b[5..7])
        || !is_digits(&b[8..10])
        || !is_digits(&b[11..13])
    {
        return false;
    }
    // Every byte here already passed the digit check above, so a plain
    // base-10 fold is exact — no `Result` either field could still fail.
    let field = |s: &[u8]| s.iter().fold(0u32, |acc, &d| acc * 10 + (d - b'0') as u32);
    let (y, m, d, h) = (
        field(&b[..4]),
        field(&b[5..7]),
        field(&b[8..10]),
        field(&b[11..13]),
    );
    h < 24 && NaiveDate::from_ymd_opt(y as i32, m, d).is_some()
}

/// Whether an hour bucket falls inside a window that started at `since`:
/// buckets are hour-granular, so the hour containing `since` counts whole —
/// equivalent to `parse_bucket_hour(hour) + 1h > since` for every
/// well-formed bucket, since both `since_hour` and a well-formed `hour` are
/// zero-padded to the same width, so string order and chronological order
/// of the truncated hour agree (see `window_tokens`'s test for the worked
/// cases). `since_hour` is `since` floored to its hour and formatted the
/// same way, computed once by the caller rather than per bucket.
fn bucket_counts(hour: &str, since: DateTime<Utc>, since_hour: &str) -> bool {
    if bucket_hour_well_formed(hour) {
        hour >= since_hour
    } else {
        parse_bucket_hour(hour).is_some_and(|h| h + Duration::hours(1) > since)
    }
}

/// Tokens a provider spent inside a quota window, from `since` (unix
/// seconds) — the store-touching half of a burn figure, split out from the
/// elapsed-hours half a caller pairs it with. A caller that asks the same
/// `(provider, since)` again — every tick, for an open window — can cache
/// this and only redo the elapsed-hours half, which needs nothing from the
/// store.
pub fn window_tokens(store: &HistoryStore, provider: &str, since_unix: u64) -> Option<u64> {
    let since = Utc.timestamp_opt(since_unix as i64, 0).single()?;
    if since >= Utc::now() {
        return None;
    }
    let since_hour = since.format("%Y-%m-%dT%H").to_string();
    let tokens: u64 = store
        .live_days()
        .filter(|d| d.provider == provider)
        .filter(|d| bucket_counts(&d.hour, since, &since_hour))
        // Burn excludes cache reads — a resent context is not fresh spend.
        .map(|d| d.active())
        .sum();
    (tokens > 0).then_some(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::store::FileState;
    use crate::history::store::SCHEMA_VERSION;
    use std::fs;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tickover-qry-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Test lines belong to `claude`/`codex` — the enabled set the
    /// filtering API expects.
    fn enabled_all() -> std::collections::HashSet<String> {
        ["claude", "codex", "grok", "antigravity"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn line(hour: &str, provider: &str, project: &str, input: u64) -> DayLine {
        DayLine {
            v: SCHEMA_VERSION,
            hour: hour.into(),
            provider: provider.into(),
            project: project.into(),
            model: "m".into(),
            session: format!("s-{provider}"),
            file: "/f".into(),
            gen: 0,
            lo: 0,
            hi: 0,
            full: false,
            b: 0,
            input,
            output: input / 4,
            cache_read: input * 2,
            cache_write: 0,
            thinking: 0,
            messages: 1,
        }
    }

    /// The shape `scan_root` writes for a source with no usage at all —
    /// coverage-only, no project/model/session, all counts zero.
    fn tombstone(hour: &str, provider: &str) -> DayLine {
        DayLine {
            v: SCHEMA_VERSION,
            hour: hour.into(),
            provider: provider.into(),
            project: String::new(),
            model: String::new(),
            session: String::new(),
            file: "/tomb".into(),
            gen: 0,
            lo: 0,
            hi: 0,
            full: true,
            b: 0,
            input: 0,
            output: 0,
            cache_read: 0,
            cache_write: 0,
            thinking: 0,
            messages: 0,
        }
    }

    #[test]
    fn a_store_of_only_tombstones_reports_no_activity() {
        // A source that has never carried usage still gets a coverage
        // line so the seal chain tiles — but it must not read as a day
        // the user was active, a streak, a session, or a "last seen".
        let dir = tmpdir("tombstones-only");
        let mut store = HistoryStore::open(&dir).unwrap();
        let today = Local::now().date_naive();
        let yesterday_hour = (Utc::now() - Duration::days(1))
            .format("%Y-%m-%dT%H")
            .to_string();
        let today_hour = Utc::now().format("%Y-%m-%dT%H").to_string();
        store
            .append_days(&[
                tombstone(&yesterday_hour, "claude"),
                tombstone(&today_hour, "claude"),
            ])
            .unwrap();
        store.commit().unwrap();
        let store = HistoryStore::open(&dir).unwrap();

        let enabled = enabled_all();
        let st = compute(&store, 30, &enabled);
        assert_eq!(st.active_days, 0, "no day actually saw usage");
        assert_eq!(st.streak_days, 0);
        assert!(
            st.sessions.is_empty(),
            "the tombstone's empty session id must not appear"
        );
        assert!(!st.daily.contains_key(&today));
        assert!(st.providers.is_empty(), "no provider was ever used");
        assert!(st.by_provider.is_empty());
        assert!(
            st.projects.is_empty(),
            "the tombstone's blank project must not appear"
        );
        assert!(
            st.models.is_empty(),
            "the tombstone's blank model must not appear"
        );
        assert!(st.by_provider_model.is_empty());

        let panel_sum = panel(&store, PanelRange::Day, &[], &enabled, None);
        assert_eq!(panel_sum.streak_days, 0);
        assert_eq!(panel_sum.sessions, 0);
        assert!(panel_sum.last_seen.is_none(), "nothing was ever seen");
        assert!(panel_sum.projects.is_empty(), "no project row to show");
        assert_eq!(
            panel_sum.state,
            PanelState::EmptyRange,
            "coverage lines still mean the source has been scanned"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn one_real_bucket_among_tombstones_counts_exactly_one_day() {
        let dir = tmpdir("tombstones-mixed");
        let mut store = HistoryStore::open(&dir).unwrap();
        let real_hour = Utc::now().format("%Y-%m-%dT%H").to_string();
        let other_hour = (Utc::now() - Duration::days(3))
            .format("%Y-%m-%dT%H")
            .to_string();
        store
            .append_days(&[
                line(&real_hour, "claude", "proj", 50),
                tombstone(&real_hour, "codex"),
                tombstone(&other_hour, "claude"),
                tombstone(&other_hour, "codex"),
            ])
            .unwrap();
        store.commit().unwrap();
        let store = HistoryStore::open(&dir).unwrap();

        let enabled = enabled_all();
        let st = compute(&store, 30, &enabled);
        assert_eq!(st.active_days, 1);
        assert_eq!(st.sessions.len(), 1);
        assert_eq!(
            st.providers,
            vec!["claude".to_string()],
            "codex never had real usage"
        );
        assert_eq!(st.projects.len(), 1);
        assert_eq!(st.models.len(), 1);
        assert_eq!(st.by_provider_model.len(), 1);

        let panel_sum = panel(&store, PanelRange::Week, &[], &enabled, None);
        assert_eq!(panel_sum.projects.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn day_range_delta_divides_by_the_whole_baseline_window() {
        // One real day's usage sits inside the 7-day baseline window; the
        // other six days are empty. The baseline average must still be
        // spread over all seven days, not just the one that has data —
        // dividing by the days-with-data instead inflates a sparse week
        // into a much heavier trend, sign included.
        let dir = tmpdir("day-delta-sparse-baseline");
        let mut store = HistoryStore::open(&dir).unwrap();
        let baseline_hour = (Utc::now() - Duration::days(4))
            .format("%Y-%m-%dT%H")
            .to_string();
        let today_hour = Utc::now().format("%Y-%m-%dT%H").to_string();
        let baseline_line = line(&baseline_hour, "claude", "p", 100);
        let today_line = line(&today_hour, "claude", "p", 50);
        let expected_baseline_avg = baseline_line.sum() as f64 / 7.0;
        let expected_range_total = today_line.sum() as f64;
        let expected_delta = (expected_range_total - expected_baseline_avg) / expected_baseline_avg;
        store.append_days(&[baseline_line, today_line]).unwrap();
        store.commit().unwrap();
        let store = HistoryStore::open(&dir).unwrap();

        let sum = panel(&store, PanelRange::Day, &[], &enabled_all(), None);
        let got = sum.delta.expect("a nonzero baseline must produce a delta");
        assert!(
            (got - expected_delta).abs() < 1e-9,
            "got={got} expected={expected_delta}"
        );
        assert!(
            got > 0.0,
            "spreading the lone baseline day over the full week must not flip the sign"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn utc_hours_group_into_local_days() {
        let dir = tmpdir("days");
        let mut store = HistoryStore::open(&dir).unwrap();
        // An hour that is "today" in UTC terms; whatever the local offset,
        // the bucket lands in some local day and must appear exactly once.
        let utc_now = Utc::now();
        let hour = utc_now.format("%Y-%m-%dT%H").to_string();
        store
            .append_days(&[line(&hour, "claude", "p1", 100)])
            .unwrap();
        store.commit().unwrap();
        let store = HistoryStore::open(&dir).unwrap();
        let st = compute(&store, 30, &enabled_all());
        assert_eq!(st.total.input, 100);
        assert_eq!(st.providers, vec!["claude".to_string()]);
        assert_eq!(st.by_provider["claude"].cache_read, 200);
        // cache-hit = read / (read + fresh) = 200/300
        assert!((st.by_provider["claude"].cache_hit_pct().unwrap() - 66.66).abs() < 0.1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_store_computes_to_zeros_not_a_crash() {
        let dir = tmpdir("empty");
        let store = HistoryStore::open(&dir).unwrap();
        let st = compute(&store, 30, &enabled_all());
        assert_eq!(st.total.sum(), 0);
        assert!(st.providers.is_empty());
        assert_eq!(st.heatmap.len(), 52);
        assert_eq!(st.streak_days, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disabled_providers_drop_out_of_every_total() {
        // A provider the user disabled keeps its lines on disk — but no
        // figure may count them, or the panel/report imply coverage they
        // don't have.
        let dir = tmpdir("disabled");
        let mut store = HistoryStore::open(&dir).unwrap();
        let utc_now = Utc::now();
        let hour = utc_now.format("%Y-%m-%dT%H").to_string();
        store
            .append_days(&[
                line(&hour, "claude", "p1", 100),
                line(&hour, "codex", "p2", 900),
            ])
            .unwrap();
        store.commit().unwrap();
        let store = HistoryStore::open(&dir).unwrap();

        let enabled: std::collections::HashSet<String> =
            ["claude".to_string()].into_iter().collect();
        let st = compute(&store, 30, &enabled);
        assert_eq!(st.total.input, 100, "codex's 900 must not count");
        assert_eq!(st.providers, vec!["claude".to_string()]);
        assert!(!st.by_provider.contains_key("codex"));

        let sum = panel(&store, PanelRange::Day, &[], &enabled, None);
        assert_eq!(sum.headline, 325); // 100 in + 25 out + 200 cache_read
        assert!(!sum.segments.iter().any(|s| s.is_nan())); // shape intact
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn skipped_unparsed_counts_enabled_providers_only() {
        // Drift counts are provider-owned: a disabled provider's parse
        // failures must not inflate the warning the user sees.
        let dir = tmpdir("skipped");
        let mut store = HistoryStore::open(&dir).unwrap();
        for (path, provider, n) in [("/a", "claude", 3u64), ("/b", "codex", 5u64)] {
            let mut st = FileState::fresh("d".into(), 1, 1);
            st.provider = provider.to_string();
            st.skipped_unparsed = n;
            store.state_mut().files.insert(path.to_string(), st);
        }
        let enabled: std::collections::HashSet<String> =
            ["claude".to_string()].into_iter().collect();
        let st = compute(&store, 30, &enabled);
        assert_eq!(st.skipped_unparsed, 3);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bucket_counts_matches_the_old_parse_and_compare_at_every_edge() {
        // The old rule was `parse_bucket_hour(hour) + 1h > since`; the new
        // one is a lexicographic compare of `hour` against `since`'s own
        // hour string. Prove they agree at the hour-of-`since`, the hour
        // before, and the hour after — with `since` both on an hour
        // boundary and mid-hour — and that a malformed hour still falls
        // back to the exact old expression instead of being skipped
        // outright or compared as if it were well-formed.
        for since in [
            Utc.with_ymd_and_hms(2026, 9, 22, 14, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 9, 22, 14, 30, 0).unwrap(),
        ] {
            let since_hour = since.format("%Y-%m-%dT%H").to_string();
            for hour in ["2026-09-22T14", "2026-09-22T13", "2026-09-22T15"] {
                let old = parse_bucket_hour(hour).is_some_and(|h| h + Duration::hours(1) > since);
                let new = bucket_counts(hour, since, &since_hour);
                assert_eq!(new, old, "hour={hour} since={since}");
            }
            for malformed in [
                "2026-09-22T7",
                "not-an-hour",
                "2026-09-22",
                // Digit-shaped but not a calendar hour at all — the shape
                // check alone would have waved these through and compared
                // them lexicographically; `parse_bucket_hour` drops every
                // one, and so must the fast path.
                "2026-13-01T00", // month 13
                "2026-09-32T00", // day 32
                "2026-09-22T24", // hour 24
                "2026-02-30T00", // February has no 30th, leap year or not
            ] {
                let old =
                    parse_bucket_hour(malformed).is_some_and(|h| h + Duration::hours(1) > since);
                assert!(!old, "parse_bucket_hour must reject {malformed}");
                let new = bucket_counts(malformed, since, &since_hour);
                assert_eq!(new, old, "malformed hour={malformed} since={since}");
            }
        }
    }

    #[test]
    fn window_tokens_matches_the_old_expression_over_a_real_store() {
        // Same edges as above, but through `window_tokens` against buckets
        // actually appended to a store — the fast path's provider filter
        // and `live_days()` plumbing included, not just the hour compare.
        for since in [
            Utc.with_ymd_and_hms(2026, 9, 22, 14, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 9, 22, 14, 30, 0).unwrap(),
        ] {
            let dir = tmpdir("window-tokens");
            let mut store = HistoryStore::open(&dir).unwrap();
            let lines = [
                line("2026-09-22T14", "claude", "p", 100), // hour of `since`
                line("2026-09-22T13", "claude", "p", 200), // one hour before
                line("2026-09-22T15", "claude", "p", 300), // one hour after
                line("2026-09-22T7", "claude", "p", 400),  // malformed (unpadded)
                line("2026-09-22T15", "codex", "p", 999),  // different provider
            ];
            let old: u64 = lines
                .iter()
                .filter(|d| d.provider == "claude")
                .filter_map(|d| parse_bucket_hour(&d.hour).map(|h| (h, d.active())))
                .filter(|(h, _)| *h + Duration::hours(1) > since)
                .map(|(_, s)| s)
                .sum();
            store.append_days(&lines).unwrap();
            let new = window_tokens(&store, "claude", since.timestamp() as u64).unwrap_or(0);
            assert_eq!(new, old, "since={since}");
            let _ = fs::remove_dir_all(&dir);
        }
    }
}
