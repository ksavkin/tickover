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
    /// Cumulative unparsed-line count across all tracked files.
    pub skipped_unparsed: u64,
}

/// Compute everything [`Stats`] exposes over the store's live buckets.
/// `days` bounds `daily`/`heatmap` lookback; all-time groupings ignore it.
pub fn compute(store: &HistoryStore, days: u32) -> Stats {
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
        skipped_unparsed: store.state.files.values().map(|f| f.skipped_unparsed).sum(),
    };

    let mut projects: HashMap<String, Totals> = HashMap::new();
    let mut models: HashMap<String, Totals> = HashMap::new();
    let mut provider_models: HashMap<String, HashMap<String, Totals>> = HashMap::new();
    let mut sessions: HashMap<String, SessionStat> = HashMap::new();
    // Day-total map feeding both `daily` (bounded) and `heatmap` (52 wk).
    let mut day_totals: BTreeMap<NaiveDate, u64> = BTreeMap::new();

    for d in store.live_days() {
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
            .or_insert_with(HashMap::new)
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
        v.sort_by(|a, b| b.totals.sum().cmp(&a.totals.sum()));
        v
    };
    st.streak_days = streak(&day_totals, today);
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

#[cfg(test)]
mod tests {
    use super::*;
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
        let st = compute(&store, 30);
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
        let st = compute(&store, 30);
        assert_eq!(st.total.sum(), 0);
        assert!(st.providers.is_empty());
        assert_eq!(st.heatmap.len(), 52);
        assert_eq!(st.streak_days, 0);
        let _ = fs::remove_dir_all(&dir);
    }
}
