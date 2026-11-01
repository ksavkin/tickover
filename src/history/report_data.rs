//! What the HTML report carries for its period picker — every live bucket,
//! grouped by local hour, ready for `report.js` to filter and sum.
//!
//! The split is deliberate: everything that takes knowledge lives here, on the
//! Rust side, once (which lines are live, the local date of a UTC hour, what a
//! model costs), and the browser only ever adds rows up. A price or a timezone
//! rule in JavaScript would be a second copy to keep true.
//!
//! The local date and hour are the generating machine's, fixed into the file:
//! a report means the same days wherever it is opened.

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Local, Timelike};
use serde::Serialize;

use crate::history::pricing;
use crate::history::query::{self, Stats, Totals};
use crate::history::report;
use crate::history::store::{DayLine, HistoryStore};

/// `(day, hour, utc_hour, provider, model, project, session, input, output,
/// cache_read, cache_write, thinking, messages, cost)`. Indices point into
/// [`ReportData`]'s dictionaries; `utc_hour` is hours since the epoch, what a
/// session's length is measured in across a clock change.
type Row = (
    u32,
    u32,
    i64,
    u32,
    u32,
    u32,
    u32,
    u64,
    u64,
    u64,
    u64,
    u64,
    u64,
    Option<f64>,
);

/// Bumped when `report.js` could no longer read an older shape — the two ship
/// in one file, so this only documents the format, nothing negotiates it.
const DATA_VERSION: u32 = 1;

/// A row's identity before it is summed: `(day, hour, utc_hour, provider,
/// model, project, session)`, the day still a date so the rows sort by it.
type RowKey = (String, u32, i64, u32, u32, u32, u32);

/// One provider, with what the report draws it as.
#[derive(Debug, Serialize)]
pub struct ProviderEntry {
    pub id: String,
    pub name: String,
    pub color: String,
}

/// One model. `saved_per_mtok` is what a million cache-read tokens saved
/// against the full input price; `None` for a model with no list price.
#[derive(Debug, Serialize)]
pub struct ModelEntry {
    pub name: String,
    pub saved_per_mtok: Option<f64>,
}

/// The JSON embedded in the report.
#[derive(Serialize)]
pub struct ReportData {
    pub v: u32,
    /// Local date the report was generated — what the presets count back
    /// from, so a report opened next week still says what it said.
    pub generated: String,
    /// The generating machine's UTC offset when it wrote this, for the label.
    pub tz: String,
    pub cost_on: bool,
    /// Ascending local dates with any activity.
    pub days: Vec<String>,
    pub providers: Vec<ProviderEntry>,
    pub models: Vec<ModelEntry>,
    /// Ordered by all-time total, so `project-N` means the same here as in a
    /// masked file.
    pub projects: Vec<String>,
    /// `(provider, project)` per session. The index is all that identifies
    /// one: the provider's own session id stays out of the file.
    pub sessions: Vec<(u32, u32)>,
    pub rows: Vec<Row>,
}

/// Index of `key` in a dictionary being built, adding it if new.
fn intern(map: &mut HashMap<String, u32>, key: &str) -> u32 {
    let next = map.len() as u32;
    *map.entry(key.to_string()).or_insert(next)
}

fn saved_per_mtok(model: &str) -> Option<f64> {
    let tokens = |input, cache_read| Totals {
        input,
        cache_read,
        ..Totals::default()
    };
    let as_input = pricing::cost_usd(model, &tokens(1_000_000, 0))?;
    let as_cache = pricing::cost_usd(model, &tokens(0, 1_000_000))?;
    Some(as_input - as_cache)
}

/// Build the payload from the same lines `st` was computed from. `st` only
/// supplies the order of the project dictionary; the figures come from the
/// store, line by line, the way [`query::compute`] reads them.
pub fn build(
    store: &HistoryStore,
    st: &Stats,
    enabled: &HashSet<String>,
    cost_on: bool,
) -> ReportData {
    let now = Local::now();
    let mut projects: HashMap<String, u32> = HashMap::new();
    for (name, _) in &st.projects {
        intern(&mut projects, name);
    }
    let mut providers: HashMap<String, u32> = HashMap::new();
    let mut models: HashMap<String, u32> = HashMap::new();
    let mut sessions: HashMap<String, u32> = HashMap::new();
    let mut session_list: Vec<(u32, u32)> = Vec::new();
    let mut grouped: BTreeMap<RowKey, Totals> = BTreeMap::new();

    for d in store.live_days() {
        if !enabled.contains(&d.provider) || !d.has_activity() {
            continue;
        }
        let Some(hour_utc) = query::parse_bucket_hour(&d.hour) else {
            continue;
        };
        let local: DateTime<Local> = hour_utc.with_timezone(&Local);
        let provider = intern(&mut providers, &d.provider);
        let model = intern(&mut models, &d.model);
        let project = intern(&mut projects, &d.project);
        let session = session_index(&mut sessions, &mut session_list, d, provider, project);
        grouped
            .entry((
                local.date_naive().format("%Y-%m-%d").to_string(),
                local.hour(),
                hour_utc.timestamp().div_euclid(3600),
                provider,
                model,
                project,
                session,
            ))
            .or_default()
            .add(d);
    }

    let days: Vec<String> = {
        let unique: std::collections::BTreeSet<&String> = grouped.keys().map(|k| &k.0).collect();
        unique.into_iter().cloned().collect()
    };
    let day_index: HashMap<&str, u32> = days
        .iter()
        .enumerate()
        .map(|(i, d)| (d.as_str(), i as u32))
        .collect();
    let model_names = sorted_names(&models);
    let rows = grouped
        .iter()
        .map(
            |((day, hour, t, provider, model, project, session), totals)| {
                let cost = cost_on
                    .then(|| pricing::cost_usd(&model_names[*model as usize], totals))
                    .flatten()
                    .map(|c| (c * 1e7).round() / 1e7);
                (
                    day_index[day.as_str()],
                    *hour,
                    *t,
                    *provider,
                    *model,
                    *project,
                    *session,
                    totals.input,
                    totals.output,
                    totals.cache_read,
                    totals.cache_write,
                    totals.thinking,
                    totals.messages,
                    cost,
                )
            },
        )
        .collect();

    ReportData {
        v: DATA_VERSION,
        generated: now.date_naive().format("%Y-%m-%d").to_string(),
        tz: now.format("%:z").to_string(),
        cost_on,
        days,
        providers: sorted_names(&providers)
            .into_iter()
            .map(|id| ProviderEntry {
                name: report::provider_name(&id).to_string(),
                color: report::provider_color(&id).to_string(),
                id,
            })
            .collect(),
        models: model_names
            .into_iter()
            .map(|name| ModelEntry {
                saved_per_mtok: saved_per_mtok(&name),
                name,
            })
            .collect(),
        projects: sorted_names(&projects),
        sessions: session_list,
        rows,
    }
}

/// `compute` keys a session by provider and id, and takes its project from
/// the first line it meets; so does this.
fn session_index(
    sessions: &mut HashMap<String, u32>,
    list: &mut Vec<(u32, u32)>,
    d: &DayLine,
    provider: u32,
    project: u32,
) -> u32 {
    let next = list.len() as u32;
    let index = *sessions
        .entry(format!("{}:{}", d.provider, d.session))
        .or_insert(next);
    if index == next {
        list.push((provider, project));
    }
    index
}

/// A dictionary's keys in index order.
fn sorted_names(map: &HashMap<String, u32>) -> Vec<String> {
    let mut names: Vec<(&String, &u32)> = map.iter().collect();
    names.sort_by_key(|(_, i)| **i);
    names.into_iter().map(|(n, _)| n.clone()).collect()
}

/// `data` as text safe inside `<script type="application/json">`: nothing in
/// it can close the element, and a project name cannot turn into markup.
pub fn embed_json(data: &ReportData) -> Result<String, serde_json::Error> {
    Ok(serde_json::to_string(data)?
        .replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029"))
}

/// Replace every project name with `project-N`, in all-time order, wherever
/// the report would print or embed one. What `--mask` does; the name must not
/// survive anywhere in the file, not merely be hidden on screen.
pub fn mask_projects(st: &mut Stats, data: &mut ReportData) {
    let aliases: HashMap<String, String> = data
        .projects
        .iter()
        .enumerate()
        .map(|(i, name)| (name.clone(), format!("project-{}", i + 1)))
        .collect();
    let alias = |name: &str| {
        aliases
            .get(name)
            .cloned()
            .unwrap_or_else(|| name.to_string())
    };
    for (name, _) in &mut st.projects {
        *name = alias(name);
    }
    for session in &mut st.sessions {
        session.project = alias(&session.project);
    }
    for name in &mut data.projects {
        *name = alias(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::store::SCHEMA_VERSION;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("tickover-report-data-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn line(session: &str, project: &str, model: &str, input: u64, messages: u32) -> DayLine {
        DayLine {
            v: SCHEMA_VERSION,
            hour: "2026-09-22T14".into(),
            provider: "claude".into(),
            project: project.into(),
            model: model.into(),
            session: session.into(),
            file: format!("/{session}"),
            gen: 0,
            lo: 0,
            hi: 0,
            full: false,
            b: 0,
            input,
            output: 0,
            cache_read: 0,
            cache_write: 0,
            thinking: 0,
            messages,
        }
    }

    fn fixture(tag: &str, cost_on: bool) -> (std::path::PathBuf, Stats, ReportData) {
        let dir = tmpdir(tag);
        let mut store = HistoryStore::open(&dir).unwrap();
        store
            .append_days(&[
                line("raw-session-a", "big</script>", "claude-sonnet-4", 900, 1),
                line("raw-session-b", "small", "mystery-model-x", 100, 1),
                line("raw-tombstone", "", "", 0, 0),
            ])
            .unwrap();
        let enabled: HashSet<String> = ["claude".to_string()].into_iter().collect();
        let st = query::compute(&store, 30, &enabled);
        let data = build(&store, &st, &enabled, cost_on);
        (dir, st, data)
    }

    #[test]
    fn the_file_carries_no_session_id_and_no_line_without_activity() {
        let (dir, _, data) = fixture("no-ids", true);
        let json = embed_json(&data).unwrap();
        assert!(!json.contains("raw-session"), "{json}");
        assert_eq!(data.rows.len(), 2, "the tombstone adds nothing to sum");
        assert_eq!(data.sessions.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_project_name_cannot_close_the_script_element() {
        let (dir, _, data) = fixture("escape", false);
        let json = embed_json(&data).unwrap();
        assert!(!json.contains('<'), "{json}");
        let back: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(back["projects"][0], "big</script>");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_cost_stays_out_of_the_file_until_it_is_switched_on() {
        let (dir, _, off) = fixture("cost-off", false);
        assert!(off.rows.iter().all(|r| r.13.is_none()));
        let _ = std::fs::remove_dir_all(&dir);
        let (dir, _, on) = fixture("cost-on", true);
        let priced = on.rows.iter().filter(|r| r.13.is_some()).count();
        assert_eq!(priced, 1, "a model with no price stays null, never 0");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn masking_leaves_no_project_name_anywhere() {
        let (dir, mut st, mut data) = fixture("mask", false);
        mask_projects(&mut st, &mut data);
        let json = embed_json(&data).unwrap();
        assert!(!json.contains("big") && !json.contains("small"), "{json}");
        assert_eq!(data.projects, ["project-1", "project-2"]);
        assert_eq!(st.projects[0].0, "project-1", "same order, same alias");
        assert!(st
            .sessions
            .iter()
            .all(|s| s.project.starts_with("project-")));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
