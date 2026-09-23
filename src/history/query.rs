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
            .state
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
        st.by_provider.entry(d.provider.clone()).or_default().add(d);
        if day == today {
            st.today.add(d);
            st.today_by_provider
                .entry(d.provider.clone())
                .or_default()
                .add(d);
        }
        if day >= week_start {
            st.week.add(d);
        }
        if day >= month_start {
            st.month.add(d);
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
        st.active_hours[local.hour() as usize] += d.sum();

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
    let mut base_total = 0u64;
    // The 24h baseline is a mean *daily* total over the window — bucket
    // rows are per (hour × provider × project × model × session), so the
    // denominator must be the window's day count, not the row count.
    let mut base_days: std::collections::HashSet<NaiveDate> = std::collections::HashSet::new();

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
            base_days.insert(day);
        }
        let Some(slot) = slot_of(d) else { continue };
        slots[slot] += d.sum();
        range_total += d.sum();
        class_totals.add(d);
        projects.entry(d.project.clone()).or_default().add(d);
        sessions.insert(format!("{}:{}", d.provider, d.session));
        price_units
            .entry((d.provider.clone(), d.model.clone()))
            .or_default()
            .add(d);
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
        PanelRange::Day => {
            // Mean daily total over the baseline days that had any data.
            (!base_days.is_empty()).then(|| base_total as f64 / base_days.len() as f64)
        }
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
        .filter(|d| enabled.contains(&d.provider))
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
        .filter(|d| enabled.contains(&d.provider))
        .filter_map(|d| {
            parse_bucket_hour(&d.hour).map(|h| (h, d.project.clone(), d.session.clone()))
        })
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(h, project, _)| (h.with_timezone(&Local), project))
}

/// Tokens a provider spent inside a quota window, for the projection hatch:
/// `since` is the window's start (unix seconds). Returns `(tokens, hours
/// elapsed)` — `None` when nothing was counted, so the caller can omit the
/// burn figure rather than draw a fabricated one.
pub fn window_burn(store: &HistoryStore, provider: &str, since_unix: u64) -> Option<(u64, f64)> {
    let since = Utc.timestamp_opt(since_unix as i64, 0).single()?;
    let now = Utc::now();
    if since >= now {
        return None;
    }
    let tokens: u64 = store
        .live_days()
        .filter(|d| d.provider == provider)
        // Burn excludes cache reads — a resent context is not fresh spend.
        .filter_map(|d| parse_bucket_hour(&d.hour).map(|h| (h, d.active())))
        // Buckets are hour-granular: the hour containing `since` counts
        // whole — dropping it would zero out any window shorter than an
        // hour or one that starts mid-hour.
        .filter(|(h, _)| *h + Duration::hours(1) > since)
        .map(|(_, s)| s)
        .sum();
    (tokens > 0).then(|| (tokens, (now - since).num_seconds().max(1) as f64 / 3600.0))
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
            input,
            output: input / 4,
            cache_read: input * 2,
            cache_write: 0,
            thinking: 0,
            messages: 1,
        }
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
            store.state.files.insert(path.to_string(), st);
        }
        let enabled: std::collections::HashSet<String> =
            ["claude".to_string()].into_iter().collect();
        let st = compute(&store, 30, &enabled);
        assert_eq!(st.skipped_unparsed, 3);
        let _ = fs::remove_dir_all(&dir);
    }
}
