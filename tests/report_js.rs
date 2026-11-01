//! `report.js` adds up in the browser what `query::compute` adds up here. The
//! two cannot share code, so this runs the shipped script under `node` and
//! holds its answer against `compute`'s: over all of history, and over a
//! period, where the reference is `compute` on a store holding only that
//! period's lines. No period filter exists in Rust for the two to share a bug
//! with.
#![cfg(feature = "history")]

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::{DateTime, Local, NaiveDate, Utc};
use serde_json::{json, Value};
use tickover::history::pricing;
use tickover::history::query::{self, Stats, Totals};
use tickover::history::report::{self, REPORT_JS};
use tickover::history::report_data::{self, ReportData};
use tickover::history::store::{DayLine, HistoryStore, SCHEMA_VERSION};

fn tmpdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tickover-report-js-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `node`, or a skip message. Skipping is for a machine without it: on CI a
/// missing `node` would silently retire the only check on this arithmetic.
fn node_or_skip() -> bool {
    let found = Command::new("node").arg("--version").output().is_ok();
    assert!(
        found || std::env::var_os("CI").is_none(),
        "CI must have node: tests/report_js.rs is the parity check"
    );
    if !found {
        eprintln!("skipping: no node on PATH");
    }
    found
}

fn run_node(dir: &Path, data: &ReportData, program: &str) -> Value {
    let script = dir.join("report.js");
    std::fs::write(&script, REPORT_JS).unwrap();
    let payload = dir.join("data.json");
    std::fs::write(&payload, report_data::embed_json(data).unwrap()).unwrap();
    let wrapper = format!(
        "const r = require({script:?}); const data = JSON.parse(require('fs').readFileSync({payload:?}, 'utf8')); console.log(JSON.stringify({program}));",
        script = script.display().to_string(),
        payload = payload.display().to_string(),
    );
    let out = Command::new("node")
        .arg("-e")
        .arg(wrapper)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

fn line(hour: &str, provider: &str, project: &str, model: &str, session: &str, n: u64) -> DayLine {
    DayLine {
        v: SCHEMA_VERSION,
        hour: hour.into(),
        provider: provider.into(),
        project: project.into(),
        model: model.into(),
        session: session.into(),
        file: format!("/{provider}/{session}/{hour}/{model}/{project}"),
        gen: 0,
        lo: 0,
        hi: 0,
        full: false,
        b: 0,
        input: n * 1000,
        output: n * 300,
        cache_read: n * 7000,
        cache_write: n * 11,
        thinking: n * 5,
        messages: n as u32,
    }
}

fn store_of(dir: &Path, lines: &[DayLine]) -> HistoryStore {
    let mut store = HistoryStore::open(dir).unwrap();
    store.append_days(lines).unwrap();
    store.commit().unwrap();
    HistoryStore::open(dir).unwrap()
}

fn enabled() -> HashSet<String> {
    ["claude", "codex"].iter().map(|s| s.to_string()).collect()
}

fn local_date(hour: &str) -> NaiveDate {
    let at = format!("{hour}:00:00Z").parse::<DateTime<Utc>>().unwrap();
    at.with_timezone(&Local).date_naive()
}

fn utc_hour(hour: &str) -> i64 {
    query::parse_bucket_hour(hour).unwrap().timestamp() / 3600
}

fn totals(t: &Totals) -> Value {
    json!({
        "input": t.input, "output": t.output, "cache_read": t.cache_read,
        "cache_write": t.cache_write, "thinking": t.thinking, "messages": t.messages,
    })
}

/// A cost pair as `report.js` states it. Rows round to 1e-7 of a dollar, so
/// the figures compare at a tenth of a cent, past anything the page prints.
fn cost(models: &[(String, Totals)]) -> Value {
    let (v, partial) = pricing::cost_summary(models);
    json!({ "cost": v.map(|c| (c * 1000.0).round() / 1000.0), "partial": partial })
}

fn rounded(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

/// Every week from the first to the last, zero where nothing happened.
fn dense_weeks(weeks: &BTreeMap<NaiveDate, u64>) -> Vec<Value> {
    let mut out = Vec::new();
    if let (Some(first), Some(last)) = (weeks.keys().next(), weeks.keys().next_back()) {
        let mut week = *first;
        while week <= *last {
            let total = weeks.get(&week).copied().unwrap_or(0);
            out.push(json!([week.to_string(), total]));
            week += chrono::Duration::weeks(1);
        }
    }
    out
}

fn round_cost(v: &Value) -> Value {
    let c = v["cost"].as_f64().map(rounded);
    json!({ "cost": c, "partial": v["partial"] })
}

/// The reference figures, in the shape `aggregate` answers in, with the
/// orderings that are incidental (session ties) taken out on both sides.
fn expected(st: &Stats) -> Value {
    let ranked = |list: &[(String, Totals)]| -> Value {
        list.iter()
            .map(|(n, t)| json!([n, totals(t)]))
            .collect::<Vec<_>>()
            .into()
    };
    let mut sessions: Vec<Value> = st
        .sessions
        .iter()
        .map(|s| {
            let models: Vec<(String, Totals)> =
                s.models.iter().map(|(m, t)| (m.clone(), *t)).collect();
            json!({
                "provider": s.provider, "project": s.project, "totals": totals(&s.totals),
                "cost": cost(&models),
                "first": utc_hour(&s.first_hour), "last": utc_hour(&s.last_hour),
                "first_day": local_date(&s.first_hour).to_string(),
            })
        })
        .collect();
    sessions.sort_by_key(Value::to_string);
    let by_provider: BTreeMap<&String, Value> =
        st.by_provider.iter().map(|(p, t)| (p, totals(t))).collect();
    let provider_costs: BTreeMap<&String, Value> = st
        .by_provider
        .keys()
        .map(|p| (p, cost(&st.provider_models(p))))
        .collect();
    let (saved, saved_partial) = report::cache_saved(&st.models);
    let mut weeks: BTreeMap<NaiveDate, u64> = BTreeMap::new();
    for (d, t) in &st.daily {
        let monday =
            *d - chrono::Duration::days(chrono::Datelike::weekday(d).num_days_from_monday() as i64);
        *weeks.entry(monday).or_default() += t.sum();
    }
    let busiest = st
        .daily
        .iter()
        .max_by_key(|(_, t)| t.sum())
        .map(|(d, t)| json!([d.to_string(), t.sum()]));
    json!({
        "total": totals(&st.total),
        "by_provider": by_provider,
        "provider_costs": provider_costs,
        "models": ranked(&st.models),
        "projects": ranked(&st.projects),
        "sessions": sessions,
        "active_hours": st.active_hours.to_vec(),
        "active_days": st.active_days,
        "busiest": busiest,
        "weeks": dense_weeks(&weeks),
        "cost": cost(&st.models),
        "saved": rounded(saved),
        "saved_partial": saved_partial,
        "hit": st.total.cache_hit_pct().map(rounded),
    })
}

/// `aggregate`'s answer, reduced to what [`expected`] states.
fn normalized(a: &Value) -> Value {
    let mut sessions: Vec<Value> = a["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            json!({
                "provider": s["provider"], "project": s["project"], "totals": s["totals"],
                "cost": round_cost(s),
                "first": s["first"], "last": s["last"], "first_day": s["first_day"],
            })
        })
        .collect();
    sessions.sort_by_key(Value::to_string);
    let provider_costs: BTreeMap<String, Value> = a["provider_costs"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(p, c)| (p.clone(), round_cost(c)))
        .collect();
    json!({
        "total": a["total"],
        "by_provider": a["by_provider"],
        "provider_costs": provider_costs,
        "models": a["models"],
        "projects": a["projects"],
        "sessions": sessions,
        "active_hours": a["active_hours"],
        "active_days": a["active_days"],
        "busiest": a["busiest"],
        "weeks": a["weeks"],
        "cost": round_cost(a),
        "saved": rounded(a["saved"].as_f64().unwrap()),
        "hit": a["hit"].as_f64().map(rounded),
        "saved_partial": a["saved_partial"],
    })
}

fn stats(store: &HistoryStore) -> Stats {
    query::compute(store, query::ALL_DAYS, &enabled())
}

fn payload(store: &HistoryStore, st: &Stats, cost_on: bool) -> ReportData {
    report_data::build(store, st, &enabled(), cost_on)
}

/// The check itself: `aggregate` over `from..=to` of everything against
/// `compute` over only the lines of `from..=to`.
fn assert_period(lines: &[DayLine], from: Option<NaiveDate>, to: Option<NaiveDate>, tag: &str) {
    let whole_dir = tmpdir(&format!("{tag}-whole"));
    let part_dir = tmpdir(&format!("{tag}-part"));
    let whole = store_of(&whole_dir, lines);
    let inside: Vec<DayLine> = lines
        .iter()
        .filter(|d| {
            let day = local_date(&d.hour);
            from.is_none_or(|f| day >= f) && to.is_none_or(|t| day <= t)
        })
        .cloned()
        .collect();
    let part = store_of(&part_dir, &inside);
    let data = payload(&whole, &stats(&whole), true);
    let quote =
        |d: Option<NaiveDate>| d.map_or("null".to_string(), |d| format!("{:?}", d.to_string()));
    let answer = run_node(
        &whole_dir,
        &data,
        &format!(
            "(a => Object.assign(a, {{hit: r.cacheHit(a.total)}}))(r.aggregate(data, {}, {}))",
            quote(from),
            quote(to)
        ),
    );
    assert_eq!(normalized(&answer), expected(&stats(&part)), "{tag}");
    let _ = std::fs::remove_dir_all(&whole_dir);
    let _ = std::fs::remove_dir_all(&part_dir);
}

/// Three days around local midnights, a session crossing the middle boundary,
/// one provider it shares a project with, a model with no price, and a line
/// recording nothing.
fn history() -> Vec<DayLine> {
    let mut lines = vec![
        line(
            "2026-09-20T10",
            "claude",
            "alpha",
            "claude-sonnet-4",
            "s1",
            3,
        ),
        line(
            "2026-09-20T23",
            "claude",
            "alpha",
            "claude-sonnet-4",
            "s1",
            5,
        ),
        line(
            "2026-09-21T00",
            "claude",
            "alpha",
            "mystery-model-x",
            "s1",
            7,
        ),
        line("2026-09-21T01", "codex", "alpha", "gpt-5", "s2", 2),
        line("2026-09-21T12", "codex", "beta", "gpt-5", "s2", 9),
        line(
            "2026-09-22T12",
            "claude",
            "beta",
            "mystery-model-x",
            "s3",
            4,
        ),
        line(
            "2026-09-22T13",
            "claude",
            "gamma",
            "claude-sonnet-4",
            "s4",
            1,
        ),
    ];
    // Weeks of nothing before the fixture's busy days: the trail must show
    // them flat, not close them up.
    lines.push(line("2026-08-20T10", "codex", "alpha", "gpt-5", "s0", 1));
    let mut nothing = line("2026-09-22T14", "claude", "", "", "", 0);
    nothing.file = "/tombstone".into();
    lines.push(nothing);
    lines
}

#[test]
fn all_of_history_adds_up_the_same() {
    if node_or_skip() {
        assert_period(&history(), None, None, "all");
    }
}

#[test]
fn every_period_of_the_fixture_adds_up_the_same() {
    if !node_or_skip() {
        return;
    }
    let days: Vec<NaiveDate> = (19..=23)
        .map(|d| NaiveDate::from_ymd_opt(2026, 9, d).unwrap())
        .collect();
    for (i, from) in days.iter().enumerate() {
        for to in &days[i..] {
            assert_period(&history(), Some(*from), Some(*to), &format!("{from}-{to}"));
        }
    }
}

#[test]
fn an_open_ended_period_and_an_empty_one_add_up_the_same() {
    if !node_or_skip() {
        return;
    }
    let day = |d| NaiveDate::from_ymd_opt(2026, 9, d);
    assert_period(&history(), day(21), None, "open-end");
    assert_period(&history(), None, day(21), "open-start");
    assert_period(&history(), day(1), day(2), "empty");
}

/// Two clock changes, each with a bucket on the far side, on either side of a
/// local midnight. The child inherits this test with `TZ` set before anything
/// reads it, so `Local` here and in the payload both see that zone.
#[cfg(unix)]
#[test]
fn a_clock_change_adds_up_the_same() {
    const CHILD: &str = "TICKOVER_REPORT_JS_DST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        for tz in ["America/New_York", "Australia/Lord_Howe", "Asia/Kolkata"] {
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "a_clock_change_adds_up_the_same"])
                .env(CHILD, "1")
                .env("TZ", tz)
                .status()
                .unwrap();
            assert!(status.success(), "{tz}");
        }
        return;
    }
    if !node_or_skip() {
        return;
    }
    let lines: Vec<DayLine> = [
        "2026-03-08T04",
        "2026-03-08T05",
        "2026-03-08T06",
        "2026-03-08T07",
        "2026-11-01T03",
        "2026-11-01T04",
        "2026-11-01T05",
        "2026-11-01T06",
        "2026-11-02T04",
        "2026-11-02T05",
    ]
    .iter()
    .enumerate()
    .map(|(i, h)| line(h, "claude", "alpha", "claude-sonnet-4", "s1", i as u64 + 1))
    .collect();
    let mut days: Vec<NaiveDate> = lines.iter().map(|d| local_date(&d.hour)).collect();
    days.dedup();
    assert_period(&lines, None, None, "dst-all");
    for day in days {
        assert_period(&lines, Some(day), Some(day), &format!("dst-{day}"));
    }
}

#[test]
fn the_script_prints_numbers_the_way_the_page_does() {
    if !node_or_skip() {
        return;
    }
    let dir = tmpdir("formats");
    let store = store_of(&dir, &history());
    let data = payload(&store, &stats(&store), true);
    let tokens = [
        1250u64,
        1350,
        2500,
        0,
        7,
        999,
        1000,
        1049,
        1050,
        999_949,
        999_950,
        1_000_000,
        2_500_000_000,
    ];
    let usd = [
        0.125, 0.375, 2.125, 2.135, 2.5, 3.5, 0.0, 0.0005, 0.25, 0.9995, 1.0, 99.994, 99.995,
        100.0, 1234.5,
    ];
    let spans = [(0, 0), (5, 3), (0, 1), (0, 22), (0, 23), (0, 24), (0, 50)];
    let list = |v: Vec<String>| format!("[{}]", v.join(","));
    let answer = run_node(
        &dir,
        &data,
        &format!(
            "{{tokens: {t}.map(r.fmtTokens), ints: {t}.map(r.fmtInt), usd: {u}.map(r.fmtUsd), headline: {u}.map(r.fmtHeadlineUsd), none: r.fmtUsd(null), spans: {s}.map(p => r.fmtSpan(p[0], p[1])), day: r.fmtDay('2026-03-08'), active: [0, 1, 2].map(r.fmtActiveDays)}}",
            t = list(tokens.iter().map(u64::to_string).collect()),
            u = list(usd.iter().map(f64::to_string).collect()),
            s = list(spans.iter().map(|(a, b)| format!("[{a},{b}]")).collect()),
        ),
    );
    let hour = |h: i64| {
        (DateTime::UNIX_EPOCH + chrono::Duration::hours(h))
            .format("%Y-%m-%dT%H")
            .to_string()
    };
    let want = json!({
        "tokens": tokens.iter().map(|n| report::fmt_tokens(*n)).collect::<Vec<_>>(),
        "ints": tokens.iter().map(|n| report::fmt_int(*n)).collect::<Vec<_>>(),
        "usd": usd.iter().map(|v| report::fmt_usd(Some(*v))).collect::<Vec<_>>(),
        "headline": usd.iter().map(|v| report::fmt_headline_usd(*v)).collect::<Vec<_>>(),
        "none": report::fmt_usd(None),
        "spans": spans.iter().map(|(a, b)| report::session_span(&hour(*a), &hour(*b))).collect::<Vec<_>>(),
        "day": NaiveDate::from_ymd_opt(2026, 3, 8).unwrap().format("%d %b %Y").to_string(),
        "active": (0u64..3).map(report::active_days_label).collect::<Vec<_>>(),
    });
    assert_eq!(answer, want);
    let _ = std::fs::remove_dir_all(&dir);
}
