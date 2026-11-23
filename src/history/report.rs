//! Self-contained HTML usage report — `tickover stats --report`.
//!
//! One file, no network, no external assets: CSS is a `<style>` block,
//! charts are inline SVG/CSS. Dark is default; light follows
//! `prefers-color-scheme` and the toggle. The file is written `0600` —
//! project basenames are still sensitive enough for that.
//!
//! The page Rust renders is the whole report for all of history and works
//! with scripts off. `report.js` adds the period picker, period-over-period
//! comparison, chart toggles, sortable/expandable breakdown, and CSV export
//! using the rows [`report_data`] embedded, writing back through
//! `data-k` hooks and `<template>` rows authored here so markup stays in one
//! place while `tests/report_js.rs` verifies Rust/JS arithmetic parity.
//!
//! Every interpolated string goes through [`esc`]; numbers are formatted
//! by this module only. Provider content never reaches the store, so the
//! report can contain none — `esc` guards metadata such as project names.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};

use chrono::{Datelike, Duration, Local, NaiveDate};

use crate::history::pricing;
use crate::history::projects::AUTO_PING_PROJECT;
use crate::history::query::{self, Stats, Totals};
use crate::history::report_data::{self, ReportData};

/// The picker and interactive report controller. Public for the parity test.
pub const REPORT_JS: &str = include_str!("report.js");

/// Live quota card for the report's "RIGHT NOW" strip — supplied by the
/// panel when it already has a fresh reading; the CLI passes `&[]` and
/// the section is absent (an empty strip would lie by omission).
pub struct QuotaNow {
    pub provider: String,
    pub label: String,
    pub used_pct: f64,
    pub projected_pct: Option<f64>,
    pub reset_hint: String,
    /// `None` whenever `projected_pct` is — the caller only fills this
    /// once the projection itself was drawn.
    pub burn_per_hour: Option<u64>,
}

mod c {
    pub const OK: &str = "#35d79a";
    pub const WARN: &str = "#d29922";
    pub const CRIT: &str = "#f85149";
    pub const SERIES: [&str; 6] = [
        "#56d4bd", "#d97757", "#a78bfa", "#dfa93f", "#6cb6ff", "#f0883e",
    ];
}

pub fn provider_color(id: &str) -> &'static str {
    match id {
        "claude" => "#d97757",
        "codex" => "#56d4bd",
        "antigravity" => "#a78bfa",
        "grok" => "#dfa93f",
        "copilot" => "#4a515c",
        _ => "#8b929d",
    }
}

/// Provider display name — Title-case for UI, lowercase ids internally.
pub fn provider_name(id: &str) -> &str {
    match id {
        "claude" => "Claude",
        "codex" => "Codex",
        "antigravity" => "Antigravity",
        "grok" => "Grok",
        "copilot" => "Copilot",
        _ => id,
    }
}

/// HTML-escape — every interpolated string flows through this.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn fmt_tokens(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.1}B", n as f64 / 1e9)
    } else if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1e6)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1e3)
    } else {
        n.to_string()
    }
}

pub fn fmt_int(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

pub fn fmt_usd(v: Option<f64>) -> String {
    match v {
        Some(x) if x >= 100.0 => format!("${:.0}", x),
        Some(x) if x >= 1.0 => format!("${:.2}", x),
        Some(x) if x > 0.0 => format!("${:.3}", x),
        Some(_) => "$0".into(),
        None => "—".into(),
    }
}

/// The headline card's figure: whole dollars read better at that size, while
/// sub-dollar totals keep cent/sub-cent precision.
pub fn fmt_headline_usd(x: f64) -> String {
    if x >= 1000.0 {
        format!("${:.1}K", x / 1000.0)
    } else if x >= 1.0 {
        format!("${x:.0}")
    } else {
        fmt_usd(Some(x))
    }
}

pub fn active_days_label(n: u64) -> String {
    format!("{n} active {}", if n == 1 { "day" } else { "days" })
}

fn fmt_cost_pair(v: Option<f64>, partial: bool) -> String {
    let s = fmt_usd(v);
    if v.is_some() && partial {
        format!("{s}*")
    } else {
        s
    }
}

/// How many reports [`write()`] keeps in its own folder.
pub const KEEP_REPORTS: usize = 5;

fn is_own_report_name(name: &str) -> bool {
    let Some(stamp) = name
        .strip_prefix("usage-")
        .and_then(|s| s.strip_suffix(".html"))
    else {
        return false;
    };
    let b = stamp.as_bytes();
    b.len() == 15
        && b[8] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 8 || c.is_ascii_digit())
}

/// Delete all but the newest `keep` reports in `dir`, never `current` and
/// never symlinks. Returns how many were removed.
pub fn prune_reports(dir: &Path, keep: usize, current: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut own: Vec<(String, PathBuf)> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let is_file = e.file_type().ok()?.is_file();
            (is_file && is_own_report_name(&name)).then(|| (name, e.path()))
        })
        .collect();
    own.sort_by(|a, b| b.0.cmp(&a.0));
    own.into_iter()
        .skip(keep)
        .filter(|(_, p)| p != current)
        .filter(|(_, p)| std::fs::remove_file(p).is_ok())
        .count()
}

/// Write the report. `path: None` writes to `<config>/tickover/reports/
/// usage-<yyyymmdd-hhmmss>.html` and prunes older own reports past
/// [`KEEP_REPORTS`]. Created `0600`.
pub fn write(
    st: &Stats,
    path: Option<PathBuf>,
    cost_on: bool,
    quota: &[QuotaNow],
    sources: &[String],
    data: &ReportData,
) -> io::Result<PathBuf> {
    let own_folder = path.is_none();
    let path = match path {
        Some(p) => p,
        None => {
            let dir = crate::history::default_dir()
                .map(|d| d.parent().unwrap_or(&d).join("reports"))
                .unwrap_or_else(|| PathBuf::from("."));
            std::fs::create_dir_all(&dir)?;
            dir.join(format!(
                "usage-{}.html",
                Local::now().format("%Y%m%d-%H%M%S")
            ))
        }
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let html = render(st, cost_on, quota, sources, data).map_err(io::Error::other)?;
    {
        use std::io::Write as _;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path)?;
        f.write_all(html.as_bytes())?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    if own_folder {
        if let Some(dir) = path.parent() {
            prune_reports(dir, KEEP_REPORTS, &path);
        }
    }
    Ok(path)
}

fn render(
    st: &Stats,
    cost_on: bool,
    quota: &[QuotaNow],
    sources: &[String],
    data: &ReportData,
) -> Result<String, serde_json::Error> {
    let embedded = report_data::embed_json(data)?;
    let mut h = String::with_capacity(embedded.len() + 96 * 1024);
    h.push_str(HEAD);
    topbar(&mut h);
    title(&mut h, st);
    period(&mut h);
    if !quota.is_empty() {
        right_now(&mut h, quota);
    }
    filtered(&mut h, |h| {
        headline(h, st, data, cost_on);
        activity_chart(h, st, cost_on);
        breakdown(h, st, cost_on);
        projects_and_sessions(h, st, cost_on);
        habits(h, st);
    });
    heatmap(&mut h, st);
    footer(&mut h, sources, &pricing_line(st, cost_on), cost_on);
    templates(&mut h);
    h.push_str("</div></div>\n<script type=\"application/json\" id=\"report-data\">");
    h.push_str(&embedded);
    h.push_str("</script>\n<script>\n");
    h.push_str(REPORT_JS);
    h.push_str("</script>\n</body>\n</html>\n");
    Ok(h)
}

fn filtered(h: &mut String, section: impl FnOnce(&mut String)) {
    h.push_str("<div class=\"pf\">\n");
    section(h);
    h.push_str("</div>\n");
}

fn templates(h: &mut String) {
    let mut t = |id: &str, row: &dyn Fn(&mut String)| {
        let _ = write!(h, r#"<template id="{id}">"#);
        row(h);
        h.push_str("</template>\n");
    };
    t("tpl-legend", &|h| chart_legend(h, "@c@", "@name@", "@v@"));
    t("tpl-bd-prov", &|h| {
        bd_provider_row(
            h,
            "@id@",
            "@arrow@",
            "@c@",
            "@name@",
            &[
                "@in@", "@out@", "@cw@", "@cr@", "@hit@", "@tot@", "@cost@", "@share@", "@cpm@",
            ],
        )
    });
    t("tpl-bd-model", &|h| {
        bd_model_row(
            h,
            "@parent@",
            "@closed@",
            "@m@",
            &[
                "@in@", "@out@", "@cw@", "@cr@", "@hit@", "@tot@", "@cost@", "@share@", "@cpm@",
            ],
        )
    });
    t("tpl-project", &|h| {
        project_row(
            h,
            "@name@",
            "@pts@",
            "@sparkop@",
            "@w@",
            "@cost@",
            "@tok@",
            "@share@",
            "@color@",
            "@fill@",
        )
    });
    t("tpl-session", &|h| {
        session_row(
            h, "@i@", "@proj@", "@date@", "@prov@", "@model@", "@span@", "@tok@", "@cost@",
        )
    });
}

fn period(h: &mut String) {
    h.push_str(
        r#"<div id="period" class="period" hidden>
<span class="mono" style="font-size: 10px; letter-spacing: 0.15em; color: var(--meta);">PERIOD</span>
<button type="button" class="btn" data-p="7" aria-pressed="false">7d</button>
<button type="button" class="btn" data-p="30" aria-pressed="false">30d</button>
<button type="button" class="btn" data-p="90" aria-pressed="false">90d</button>
<button type="button" class="btn" data-p="month" aria-pressed="false">This month</button>
<button type="button" class="btn" data-p="all" aria-pressed="true">All</button>
<label class="mono period-date">from <input type="date" id="p-from"></label>
<label class="mono period-date">to <input type="date" id="p-to"></label>
<label class="btn" style="font-size: 11px;"><input type="checkbox" id="compare" checked style="margin: 0; accent-color: var(--ok);"> Compare previous</label>
<span class="spacer"></span>
<span class="secnote" data-k="p-note"></span>
</div>
<p id="period-empty" class="secnote" hidden style="margin: 0;">No usage in this period.</p>
"#,
    );
}

const HEAD: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>tickover — usage report</title>
<style>
:root {
  --bg: #0b0d11; --surface: #12151b; --topbar: #0d1015;
  --track: #1e232b; --track-soft: #171b22; --hairline: #262b34;
  --text: #e8eaed; --muted: #8b929d; --meta: #767d89;
  --ok: #35d79a; --warn: #d29922; --crit: #f85149;
  --cache-read: #39424f; --input: #6cb6ff; --output: #f0883e;
  --heat0: #161a20; --heat1: #17392e; --heat2: #1d5c46; --heat3: #2a9770; --heat4: #35d79a;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #f6f5f1; --surface: #fffefb; --topbar: #efece6;
    --track: #e2e0d9; --track-soft: #eceae4; --hairline: #d8d5cc;
    --text: #17191d; --muted: #5b6068; --meta: #6f747c;
    --ok: #10845f; --warn: #9a6a10; --crit: #b3261e;
    --cache-read: #8b9098; --input: #1f6feb; --output: #b3560f;
    --heat0: #eceae4; --heat1: #cfe8dd; --heat2: #9fd4bf; --heat3: #4fae8a; --heat4: #10845f;
  }
}
html.light {
  --bg: #f6f5f1; --surface: #fffefb; --topbar: #efece6;
  --track: #e2e0d9; --track-soft: #eceae4; --hairline: #d8d5cc;
  --text: #17191d; --muted: #5b6068; --meta: #6f747c;
  --ok: #10845f; --warn: #9a6a10; --crit: #b3261e;
  --cache-read: #8b9098; --input: #1f6feb; --output: #b3560f;
  --heat0: #eceae4; --heat1: #cfe8dd; --heat2: #9fd4bf; --heat3: #4fae8a; --heat4: #10845f;
}
html.dark {
  --bg: #0b0d11; --surface: #12151b; --topbar: #0d1015;
  --track: #1e232b; --track-soft: #171b22; --hairline: #262b34;
  --text: #e8eaed; --muted: #8b929d; --meta: #767d89;
  --ok: #35d79a; --warn: #d29922; --crit: #f85149;
  --cache-read: #39424f; --input: #6cb6ff; --output: #f0883e;
  --heat0: #161a20; --heat1: #17392e; --heat2: #1d5c46; --heat3: #2a9770; --heat4: #35d79a;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); }
a { color: var(--ok); text-decoration: none; }
.mono { font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace; }
.shell { max-width: 1120px; margin: 0 auto; padding: 0 32px;
  display: flex; flex-direction: column; gap: 32px; }
.topbar { display: flex; align-items: center; gap: 12px; padding: 0 32px;
  height: 58px; border-bottom: 1px solid var(--track); background: var(--topbar); }
.btn { font: inherit; font-family: 'JetBrains Mono', ui-monospace, Menlo, monospace;
  font-size: 11px; background: var(--surface); color: var(--text);
  border: 1px solid var(--hairline); border-radius: 6px; padding: 5px 10px;
  cursor: pointer; display: inline-flex; align-items: center; gap: 6px; }
.btn[aria-pressed="true"] { border-color: var(--ok); color: var(--ok); }
.seg { display: inline-flex; gap: 4px; }
h2.sec { margin: 0; font-family: 'JetBrains Mono', ui-monospace, Menlo, monospace;
  font-size: 12px; font-weight: 700; letter-spacing: 0.17em; }
.secnote { color: var(--meta); font-size: 13px; }
.card { background: var(--surface); border: 1px solid var(--track); border-radius: 12px; }
.bar-track { height: 8px; border-radius: 3px; background: var(--track-soft); overflow: hidden; }
.bar-fill { height: 100%; border-radius: 3px; background: var(--input); }
.pf { display: contents; }
.pf.off { display: none; }
.period { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
.period[hidden], [hidden] { display: none !important; }
.period-date { display: inline-flex; align-items: center; gap: 6px; font-size: 11px; color: var(--meta); }
.period-date input { font: inherit; color: var(--text); background: var(--surface);
  border: 1px solid var(--hairline); border-radius: 6px; padding: 5px 8px; color-scheme: dark; }
@media (prefers-color-scheme: light) {
  html:not(.dark) .period-date input { color-scheme: light; }
}
html.light .period-date input { color-scheme: light; }
.grid2 { display: grid; grid-template-columns: minmax(0,1fr) minmax(0,1fr); gap: 24px; }
.grid6 { display: grid; grid-template-columns: repeat(6, minmax(0,1fr)); gap: 14px; }
@media (max-width: 960px) { .grid6 { grid-template-columns: repeat(3, minmax(0,1fr)); } }
@media (max-width: 720px) {
  .shell { padding: 0 16px; gap: 24px; }
  .topbar { padding: 0 16px; }
  .grid2 { grid-template-columns: 1fr !important; }
  .grid6 { grid-template-columns: repeat(2, minmax(0,1fr)) !important; }
  .qrow { grid-template-columns: 110px 64px minmax(0,1fr) !important; }
  .qrow-extra { display: none !important; }
}
@media print {
  body { background: #fff; }
  .topbar { position: static; }
  .period, .seg { display: none; }
}
.row { display: flex; align-items: center; flex-wrap: wrap; gap: 12px; }
.spacer { flex-grow: 1; }
.dim { color: var(--muted); }
.meta { color: var(--meta); }
.delta { font-size: 11px; min-height: 15px; color: var(--meta); }
.delta-up { color: var(--warn); }
.delta-dn { color: var(--ok); }
.table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
table.bd { width: 100%; border-collapse: collapse; font-size: 12px; min-width: 760px; }
table.bd th { font-size: 10px; letter-spacing: 0.12em; color: var(--meta); font-weight: 600;
  text-align: right; padding: 8px 10px; border-bottom: 1px solid var(--track); cursor: pointer; user-select: none; white-space: nowrap; }
table.bd th:first-child { text-align: left; }
table.bd td { padding: 9px 10px; border-bottom: 1px solid var(--track-soft); text-align: right; white-space: nowrap; }
table.bd td:first-child { text-align: left; }
tr.prov-row { cursor: pointer; }
tr.prov-row:hover { background: var(--track-soft); }
tr.model-row { color: var(--muted); font-size: 11px; }
tr.model-row.is-closed { display: none; }
.scroll-x { overflow-x: auto; -webkit-overflow-scrolling: touch; }
.qrow { display: grid; grid-template-columns: 120px 68px minmax(0,1fr) 120px 90px 140px; gap: 14px; align-items: center; }
.prow { display: grid; grid-template-columns: minmax(90px,130px) 64px minmax(50px,1fr) 64px 58px 36px; gap: 10px; align-items: center; }
.srow { display: grid; grid-template-columns: 24px minmax(0,1fr) 120px 54px 58px 60px; gap: 10px; align-items: baseline; }
@media (max-width: 520px) {
  .prow { grid-template-columns: minmax(76px,110px) 52px minmax(36px,1fr) 56px 48px 32px; gap: 6px; }
  .srow { grid-template-columns: 20px minmax(0,1fr) 54px 54px; }
  .srow-hide { display: none; }
}
</style>
</head>
<body>
<div style="background: var(--bg); color: var(--text);
  font-family: 'IBM Plex Sans', system-ui, sans-serif; font-size: 14px;">
"##;

fn topbar(h: &mut String) {
    h.push_str(
        r#"<div class="topbar">
<svg width="15" height="15" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="6.4" stroke="var(--ok)" stroke-width="1.4"></circle><path d="M8 4.4V8l2.4 1.6" stroke="var(--ok)" stroke-width="1.4" stroke-linecap="round"></path></svg>
<span class="mono" style="font-size: 13px; font-weight: 600;">tickover</span>
<span class="mono" style="font-size: 11px; color: var(--meta); letter-spacing: 0.12em;">USAGE REPORT</span>
<span class="spacer"></span>
<label class="btn"><input type="checkbox" id="mask" style="margin: 0; accent-color: var(--ok);"> Mask projects</label>
<button type="button" class="btn" id="theme" aria-label="Toggle light theme"><svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="var(--muted)" stroke-width="1.4" stroke-linecap="round"><circle cx="8" cy="8" r="3.1"></circle><path d="M8 1.2v1.6M8 13.2v1.6M1.2 8h1.6M13.2 8h1.6M3.3 3.3l1.1 1.1M11.6 11.6l1.1 1.1M12.7 3.3l-1.1 1.1M4.4 11.6l-1.1 1.1"></path></svg></button>
</div>
<div class="shell">
"#,
    );
}

fn title(h: &mut String, st: &Stats) {
    let range = match st.daily.keys().next() {
        Some(first) => format!(
            "{} — {}",
            first.format("%d %b %Y"),
            Local::now().date_naive().format("%d %b %Y")
        ),
        None => "no history yet".to_string(),
    };
    let _ = write!(
        h,
        r#"<div style="padding-top: 32px; display: flex; flex-direction: column; gap: 8px;">
<h1 class="mono" style="margin: 0; font-size: 36px; font-weight: 600; letter-spacing: -0.03em; line-height: 1.08;">Where your tokens went</h1>
<p style="margin: 0; color: var(--muted); font-size: 14px; max-width: 720px; line-height: 1.55;"><span data-k="range">{range}</span>, read from CLI history files on this machine. Nothing was uploaded; no network calls and no external assets.</p>
</div>
"#
    );
}

fn right_now(h: &mut String, quota: &[QuotaNow]) {
    h.push_str(
        r#"<div style="display: flex; flex-direction: column; gap: 10px;">
<div class="row"><h2 class="sec">RIGHT NOW</h2>
<span class="secnote">live quota strip, projected forward at the window's pace</span></div>
<div class="card" style="padding: 12px 18px; display: flex; flex-direction: column; gap: 10px;">
"#,
    );
    for q in quota {
        let used = q.used_pct.clamp(0.0, 100.0);
        let proj = q.projected_pct.unwrap_or(used).clamp(0.0, 100.0);
        let color = if used >= 90.0 || proj >= 100.0 {
            c::CRIT
        } else if used >= 70.0 || proj >= 90.0 {
            c::WARN
        } else {
            c::OK
        };
        let burn = q
            .burn_per_hour
            .map(|b| format!("{}K/h", b / 1000))
            .unwrap_or_else(|| "—".into());
        let _ = write!(
            h,
            r#"<div class="qrow mono" style="font-size: 12px;">
<span style="display: inline-flex; align-items: center; gap: 7px; font-weight: 600;"><span style="width: 7px; height: 7px; border-radius: 50%; background: {pc};"></span>{name}</span>
<span style="font-size: 11px; color: var(--muted);">{label}</span>
<div style="height: 6px; border-radius: 3px; background: var(--track); position: relative; overflow: hidden;">
<div style="position: absolute; inset: 0 auto 0 0; width: {proj:.0}%; background-image: repeating-linear-gradient(135deg, {color} 0 2px, transparent 2px 5px); opacity: 0.35;"></div>
<div style="position: absolute; inset: 0 auto 0 0; width: {used:.0}%; background: {color}; border-radius: 3px;"></div>
</div>
<span class="qrow-extra" style="font-size: 11px; color: {color}; text-align: right;">{used:.0}% · ~{proj:.0}%</span>
<span class="qrow-extra" style="font-size: 11px; color: var(--muted); text-align: right;">{burn}</span>
<span class="qrow-extra" style="font-size: 11px; color: var(--meta); text-align: right;">{reset}</span>
</div>
"#,
            pc = provider_color(&q.provider),
            name = esc(&provider_name(&q.provider).to_uppercase()),
            label = esc(&q.label),
            color = color,
            used = used,
            proj = proj,
            burn = esc(&burn),
            reset = esc(&q.reset_hint),
        );
    }
    h.push_str("</div></div>\n");
}

/// Cache-read dollar cost for `models` using each model's cache-read rate.
pub fn cache_read_cost(models: &[(String, Totals)]) -> (Option<f64>, bool) {
    let cr_only: Vec<(String, Totals)> = models
        .iter()
        .map(|(m, t)| {
            (
                m.clone(),
                Totals {
                    cache_read: t.cache_read,
                    ..Totals::default()
                },
            )
        })
        .collect();
    pricing::cost_summary(&cr_only)
}

fn headline(h: &mut String, st: &Stats, data: &ReportData, cost_on: bool) {
    let total_tokens = st.total.sum();
    let active_days = st.active_days;
    let sessions = st.sessions.len() as u64;
    let span_days = match (st.daily.keys().next(), st.daily.keys().next_back()) {
        (Some(a), Some(b)) => ((*b - *a).num_days() + 1).max(1) as u64,
        _ => 1,
    };
    let (cost, partial) = if cost_on {
        pricing::cost_summary(&st.models)
    } else {
        (None, false)
    };
    let (cr_cost, cr_partial) = if cost_on {
        cache_read_cost(&st.models)
    } else {
        (None, false)
    };
    let star = if partial { "*" } else { "" };

    let cost_val = if !cost_on {
        "off".to_string()
    } else {
        cost.map(|c| format!("{}{star}", fmt_headline_usd(c)))
            .unwrap_or_else(|| "—".into())
    };
    let cost_note = if !cost_on {
        "cost accounting disabled".to_string()
    } else if partial {
        "API-equivalent, partial — unpriced models excluded".to_string()
    } else if cost.is_none() {
        "no list price for these models".to_string()
    } else {
        "API-equivalent, not your bill".to_string()
    };

    let tokens_note = if total_tokens == 0 {
        "in + out + cache".to_string()
    } else {
        let tok_pct = st.total.cache_read as f64 * 100.0 / total_tokens as f64;
        match (cost_on, cost, cr_cost) {
            (true, Some(c), Some(crc)) if c > 0.0 => {
                let usd_pct = crc * 100.0 / c;
                let m = if partial || cr_partial { "*" } else { "" };
                format!("cache read {tok_pct:.0}% tok · {usd_pct:.0}% ${m}")
            }
            _ => format!("cache read {tok_pct:.0}% tok"),
        }
    };

    let per_day_val = if active_days == 0 {
        "—".to_string()
    } else if cost_on {
        cost.map(|c| format!("{}{star}", fmt_usd(Some(c / active_days as f64))))
            .unwrap_or_else(|| "—".into())
    } else {
        fmt_tokens(total_tokens / active_days)
    };

    let pace_val = if cost_on {
        cost.map(|c| format!("{}{star}/mo", fmt_headline_usd(c / span_days as f64 * 30.0)))
            .unwrap_or_else(|| "—".into())
    } else {
        format!(
            "{}/mo",
            fmt_tokens((total_tokens as f64 / span_days as f64 * 30.0).round() as u64)
        )
    };

    let plan_sum: f64 = st
        .providers
        .iter()
        .filter_map(|p| data.plans.get(p).copied())
        .filter(|v| v.is_finite() && *v > 0.0)
        .sum();
    let (plan_val, plan_note) = if !cost_on {
        ("—".to_string(), "cost off".to_string())
    } else if plan_sum > 0.0 {
        let prorated = plan_sum * (span_days as f64 / 30.0);
        let val = cost
            .filter(|_| prorated > 0.0)
            .map(|c| format!("×{:.1}{star}", c / prorated))
            .unwrap_or_else(|| "—".into());
        (
            val,
            format!("API-equiv ÷ {}/mo (not savings)", fmt_usd(Some(plan_sum))),
        )
    } else {
        ("—".to_string(), "set [plans] in prices.toml".to_string())
    };

    let cards = [
        ("API-EQUIVALENT", "cost", cost_val, cost_note),
        ("TOKENS", "tokens", fmt_tokens(total_tokens), tokens_note),
        (
            "ACTIVE DAYS",
            "days",
            fmt_int(active_days),
            format!("{sessions} sessions · {} msgs", fmt_int(st.total.messages)),
        ),
        (
            "PER ACTIVE DAY",
            "per-day",
            per_day_val,
            if cost_on {
                "API-equiv / active day".to_string()
            } else {
                "tokens / active day".to_string()
            },
        ),
        (
            "MONTHLY PACE",
            "pace",
            pace_val,
            format!("at {span_days}d pace"),
        ),
        ("VS PLAN", "plan", plan_val, plan_note),
    ];

    h.push_str(r#"<div class="grid6">"#);
    for (label, key, value, note) in cards {
        let value = esc(&value);
        let note = esc(&note);
        let _ = write!(
            h,
            r#"<div class="card" style="padding: 14px 16px; display: flex; flex-direction: column; gap: 5px;">
<div class="mono" style="font-size: 10px; letter-spacing: 0.13em; color: var(--meta);">{label}</div>
<div class="mono" data-k="card-{key}" style="font-size: 22px; font-weight: 600; letter-spacing: -0.025em; line-height: 1.1;">{value}</div>
<div class="mono delta" data-k="delta-{key}"></div>
<div data-k="card-{key}-note" style="font-size: 11px; color: var(--muted);">{note}</div>
</div>
"#
        );
    }
    h.push_str("</div>\n");
}

fn chart_legend(h: &mut String, c: &str, name: &str, v: &str) {
    let _ = write!(
        h,
        r#"<span style="display: inline-flex; align-items: center; gap: 6px;"><span style="width: 9px; height: 9px; border-radius: 2px; background: {c};"></span><span style="color: var(--text);">{name}</span> <span class="meta">{v}</span></span>"#,
    );
}

fn activity_chart(h: &mut String, st: &Stats, cost_on: bool) {
    let daily: Vec<(NaiveDate, &Totals)> = st.daily.iter().map(|(d, t)| (*d, t)).collect();
    let (first_d, last_d) = match (daily.first(), daily.last()) {
        (Some((a, _)), Some((b, _))) => (*a, *b),
        _ => {
            let today = Local::now().date_naive();
            (today, today)
        }
    };
    let span_days = ((last_d - first_d).num_days() + 1).max(1);
    let weekly = span_days > 90;
    let monday_of = |d: NaiveDate| d - Duration::days(d.weekday().num_days_from_monday() as i64);

    let mut keys = Vec::new();
    let mut cursor = if weekly { monday_of(first_d) } else { first_d };
    let end_key = if weekly { monday_of(last_d) } else { last_d };
    while cursor <= end_key {
        keys.push(cursor);
        cursor += Duration::days(if weekly { 7 } else { 1 });
    }
    if keys.is_empty() {
        keys.push(first_d);
    }

    let total_val: f64 = st.daily.values().map(|t| t.sum() as f64).sum();
    let mut bucket_vals: BTreeMap<NaiveDate, f64> = keys.iter().map(|&k| (k, 0.0)).collect();
    for (d, t) in &st.daily {
        let bk = if weekly { monday_of(*d) } else { *d };
        *bucket_vals.entry(bk).or_default() += t.sum() as f64;
    }
    let max_val = bucket_vals
        .values()
        .copied()
        .fold(0.0_f64, f64::max)
        .max(1.0);

    const W: f64 = 1072.0;
    const H: f64 = 200.0;
    const L: f64 = 56.0;
    const R: f64 = 1064.0;
    const TOP: f64 = 16.0;
    const BASE: f64 = 180.0;
    let plot_w = R - L;
    let plot_h = BASE - TOP;
    let n = keys.len().max(1) as f64;
    let slot = plot_w / n;
    let bar_w = (slot * 0.72).clamp(2.0, 28.0);

    let mut svg = String::new();
    for step in 0..=3 {
        let frac = step as f64 / 3.0;
        let y = BASE - frac * plot_h;
        let stroke = if step == 0 {
            "var(--hairline)"
        } else {
            "var(--track)"
        };
        let label = fmt_tokens((max_val * frac).round() as u64);
        let _ = write!(
            svg,
            r#"<line x1="{L}" y1="{y:.1}" x2="{R}" y2="{y:.1}" stroke="{stroke}" stroke-width="1"/><text x="{lx}" y="{ty:.1}" text-anchor="end" font-size="10" fill="var(--meta)" font-family="ui-monospace,monospace">{label}</text>"#,
            lx = L - 8.0,
            ty = y + 3.0,
        );
    }
    for (i, bk) in keys.iter().enumerate() {
        let v = bucket_vals.get(bk).copied().unwrap_or(0.0);
        if v > 0.0 {
            let x = L + i as f64 * slot + (slot - bar_w) / 2.0;
            let bh = (v / max_val) * plot_h;
            let y = BASE - bh;
            let _ = write!(
                svg,
                r#"<rect x="{x:.1}" y="{y:.1}" width="{bar_w:.1}" height="{bh:.1}" fill="{fill}" rx="1"><title>{bk} — {val}</title></rect>"#,
                fill = c::SERIES[0],
                val = fmt_tokens(v.round() as u64),
            );
        }
    }

    let cost_pressed = if cost_on { "true" } else { "false" };
    let tok_pressed = if cost_on { "false" } else { "true" };
    let cost_hidden = if cost_on { "" } else { " hidden" };
    let mid_d = keys[keys.len() / 2];
    let _ = write!(
        h,
        r#"<div style="display: flex; flex-direction: column; gap: 12px;">
<div class="row">
<h2 class="sec">ACTIVITY OVER TIME</h2>
<span class="secnote" data-k="ch-note">{unit} per {cadence}, {cnt} {cadence}s</span>
<span class="spacer"></span>
<div id="chart-metric" class="seg">
<button type="button" class="btn" data-m="cost" aria-pressed="{cost_pressed}"{cost_hidden}>Cost ($)</button>
<button type="button" class="btn" data-m="tokens" aria-pressed="{tok_pressed}">Tokens</button>
</div>
<div id="chart-group" class="seg">
<button type="button" class="btn" data-g="provider" aria-pressed="true">Provider</button>
<button type="button" class="btn" data-g="model" aria-pressed="false">Model</button>
<button type="button" class="btn" data-g="project" aria-pressed="false">Project</button>
</div>
</div>
<div class="card" style="padding: 18px 20px 14px; display: flex; flex-direction: column; gap: 10px;">
<svg id="ch-svg" viewBox="0 0 {W:.0} {H:.0}" width="100%" role="img" aria-label="Activity over time">{svg}</svg>
<div class="mono" style="display: flex; justify-content: space-between; font-size: 10px; color: var(--meta);">
<span data-k="ch-first">{first}</span><span data-k="ch-mid">{mid}</span><span data-k="ch-last">{last}</span>
</div>
<div id="ch-legend" class="mono" style="display: flex; flex-wrap: wrap; gap: 16px; font-size: 11px; color: var(--muted);">"#,
        unit = if cost_on { "API-equiv USD" } else { "tokens" },
        cadence = if weekly { "week" } else { "day" },
        cnt = keys.len(),
        first = keys
            .first()
            .map(|d| d.format("%d %b %Y").to_string())
            .unwrap_or_default(),
        mid = mid_d.format("%d %b %Y"),
        last = keys
            .last()
            .map(|d| d.format("%d %b %Y").to_string())
            .unwrap_or_default(),
    );
    chart_legend(
        h,
        c::SERIES[0],
        "Total",
        &fmt_tokens(total_val.round() as u64),
    );
    h.push_str("</div></div></div>\n");
}

fn bd_provider_row(h: &mut String, id: &str, arrow: &str, c: &str, name: &str, cells: &[&str; 9]) {
    let _ = write!(
        h,
        r#"<tr class="prov-row mono" data-prov="{id}" aria-expanded="false">
<td><span style="display: inline-flex; align-items: center; gap: 8px; font-weight: 600;"><span class="bd-arrow" style="color: var(--meta);">{arrow}</span><span style="width: 8px; height: 8px; border-radius: 2px; background: {c};"></span>{name}</span></td>
<td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td style="font-weight: 600;">{}</td><td>{}</td><td>{}</td><td>{}</td>
</tr>
"#,
        cells[0], cells[1], cells[2], cells[3], cells[4], cells[5], cells[6], cells[7], cells[8],
    );
}

fn bd_model_row(h: &mut String, parent: &str, closed: &str, m: &str, cells: &[&str; 9]) {
    let _ = write!(
        h,
        r#"<tr class="model-row{closed} mono" data-parent="{parent}">
<td style="padding-left: 28px;">{m}</td>
<td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>
</tr>
"#,
        cells[0], cells[1], cells[2], cells[3], cells[4], cells[5], cells[6], cells[7], cells[8],
    );
}

fn breakdown(h: &mut String, st: &Stats, cost_on: bool) {
    let total_cost = if cost_on {
        pricing::cost_for_models(&st.models).filter(|c| *c > 0.0)
    } else {
        None
    };

    h.push_str(
        r#"<div style="display: flex; flex-direction: column; gap: 12px;">
<div class="row">
<h2 class="sec">BREAKDOWN</h2>
<span class="secnote">provider → models, click a row to expand</span>
<span class="spacer"></span>
<button type="button" class="btn" id="bd-toggle-all">Expand all</button>
<button type="button" class="btn" id="export-csv">Export CSV</button>
</div>
<div class="card table-wrap" style="padding: 8px 14px;">
<table id="bd-table" class="bd mono">
<thead><tr>
<th data-sort="name">PROVIDER / MODEL</th>
<th data-sort="in">IN</th>
<th data-sort="out">OUT</th>
<th data-sort="cw">CACHE WRITE</th>
<th data-sort="cr">CACHE READ</th>
<th data-sort="hit">CACHE HIT</th>
<th data-sort="total">TOTAL</th>
<th data-sort="cost">COST</th>
<th data-sort="share">% OF $</th>
<th data-sort="cpm">$ / MSG</th>
</tr></thead>
<tbody id="bd-body">
"#,
    );

    let cells_of = |t: &Totals, models: &[(String, Totals)]| -> [String; 9] {
        let hit = t
            .cache_hit_pct()
            .map(|p| format!("{p:.0}%"))
            .unwrap_or_else(|| "—".into());
        let (cost, partial) = if cost_on {
            pricing::cost_summary(models)
        } else {
            (None, false)
        };
        let share = match (total_cost, cost) {
            (Some(tc), Some(rc)) => format!("{:.0}%", rc * 100.0 / tc),
            _ => "—".into(),
        };
        let cpm = match cost {
            Some(c) if t.messages > 0 => fmt_cost_pair(Some(c / t.messages as f64), partial),
            _ => "—".into(),
        };
        [
            fmt_tokens(t.input),
            fmt_tokens(t.output + t.thinking),
            fmt_tokens(t.cache_write),
            fmt_tokens(t.cache_read),
            hit,
            fmt_tokens(t.sum()),
            if cost_on {
                fmt_cost_pair(cost, partial)
            } else {
                "—".into()
            },
            share,
            cpm,
        ]
    };

    for (p, t) in &st.by_provider {
        let p_models = st.provider_models(p);
        let pc = cells_of(t, &p_models);
        let pc_ref = [
            pc[0].as_str(),
            pc[1].as_str(),
            pc[2].as_str(),
            pc[3].as_str(),
            pc[4].as_str(),
            pc[5].as_str(),
            pc[6].as_str(),
            pc[7].as_str(),
            pc[8].as_str(),
        ];
        bd_provider_row(
            h,
            &esc(p),
            "▸",
            provider_color(p),
            &esc(provider_name(p)),
            &pc_ref,
        );
        for (m, mt) in &p_models {
            let single = [(m.clone(), *mt)];
            let mc = cells_of(mt, &single);
            let mc_ref = [
                mc[0].as_str(),
                mc[1].as_str(),
                mc[2].as_str(),
                mc[3].as_str(),
                mc[4].as_str(),
                mc[5].as_str(),
                mc[6].as_str(),
                mc[7].as_str(),
                mc[8].as_str(),
            ];
            bd_model_row(h, &esc(p), " is-closed", &esc(m), &mc_ref);
        }
    }
    h.push_str("</tbody></table></div></div>\n");
}

#[allow(clippy::too_many_arguments)]
fn project_row(
    h: &mut String,
    name: &str,
    pts: &str,
    sparkop: &str,
    w: &str,
    cost: &str,
    tok: &str,
    share: &str,
    color: &str,
    fill: &str,
) {
    let _ = write!(
        h,
        r#"<div class="prow">
<span class="mono proj" data-name="{name}" style="font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: {color};">{name}</span>
<svg viewBox="0 0 64 16" width="64" height="16" aria-hidden="true" style="opacity: {sparkop};"><polyline fill="none" stroke="{fill}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" points="{pts}"/></svg>
<div class="bar-track"><div class="bar-fill" style="width: {w}%; background: {fill};"></div></div>
<span class="mono" style="font-size: 12px; text-align: right; color: var(--text);">{cost}</span>
<span class="mono" style="font-size: 11px; text-align: right; color: var(--muted);">{tok}</span>
<span class="mono" style="font-size: 11px; text-align: right; color: var(--meta);">{share}%</span>
</div>
"#,
    );
}

#[allow(clippy::too_many_arguments)]
fn session_row(
    h: &mut String,
    i: &str,
    proj: &str,
    date: &str,
    prov: &str,
    model: &str,
    span: &str,
    tok: &str,
    cost: &str,
) {
    let _ = write!(
        h,
        r#"<div class="srow" style="padding-bottom: 8px; border-bottom: 1px solid var(--track-soft);">
<span class="mono" style="font-size: 12px; color: var(--meta);">{i}</span>
<span style="display: flex; flex-direction: column; gap: 2px; min-width: 0;">
<span class="mono proj" data-name="{proj}" style="font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{proj}</span>
<span style="font-size: 11px; color: var(--meta);">{date} · {prov}</span>
</span>
<span class="mono srow-hide" style="font-size: 11px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{model}</span>
<span class="mono srow-hide" style="font-size: 12px; text-align: right; color: var(--muted);">{span}</span>
<span class="mono" style="font-size: 12px; text-align: right; color: var(--muted);">{tok}</span>
<span class="mono" style="font-size: 12px; text-align: right; color: var(--text);">{cost}</span>
</div>
"#,
    );
}

fn projects_and_sessions(h: &mut String, st: &Stats, cost_on: bool) {
    let total_tokens = st.total.sum().max(1);
    let total_cost = if cost_on {
        pricing::cost_for_models(&st.models).filter(|c| *c > 0.0)
    } else {
        None
    };

    let mut ping_entry: Option<(&String, &Totals)> = None;
    let mut user_projects: Vec<(&String, &Totals)> = Vec::new();
    for (name, t) in &st.projects {
        if name == AUTO_PING_PROJECT {
            ping_entry = Some((name, t));
        } else {
            user_projects.push((name, t));
        }
    }

    let proj_cost = |name: &str| -> (Option<f64>, bool) {
        if cost_on {
            pricing::cost_summary(&st.project_models(name))
        } else {
            (None, false)
        }
    };
    if cost_on {
        user_projects.sort_by(|a, b| {
            let ca = proj_cost(a.0).0;
            let cb = proj_cost(b.0).0;
            match (ca, cb) {
                (Some(x), Some(y)) => y
                    .partial_cmp(&x)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| b.1.sum().cmp(&a.1.sum()))
                    .then_with(|| a.0.cmp(b.0)),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => b.1.sum().cmp(&a.1.sum()).then_with(|| a.0.cmp(b.0)),
            }
        });
    }

    let top_p: Vec<_> = user_projects.iter().take(10).copied().collect();
    let max_metric = top_p
        .first()
        .map(|(name, t)| {
            if total_cost.is_some() {
                proj_cost(name).0.unwrap_or(0.0)
            } else {
                t.sum() as f64
            }
        })
        .unwrap_or(1.0)
        .max(1e-9);
    let denom = total_cost.unwrap_or(total_tokens as f64);

    h.push_str(
        r#"<div class="grid2">
<div style="display: flex; flex-direction: column; gap: 12px;">
<h2 class="sec">PROJECTS</h2>
<div class="card" style="padding: 18px 20px; display: flex; flex-direction: column; gap: 10px;">
<div id="p-rows" style="display: flex; flex-direction: column; gap: 10px;">
"#,
    );
    let emit_project = |h: &mut String,
                        name: &str,
                        tokens: u64,
                        c_pair: (Option<f64>, bool),
                        dimmed: bool,
                        show_spark: bool| {
        let m_val = if total_cost.is_some() {
            c_pair.0.unwrap_or(0.0)
        } else {
            tokens as f64
        };
        let w = (m_val * 100.0 / max_metric).min(100.0);
        let share = m_val * 100.0 / denom;
        let cost_str = if cost_on {
            fmt_cost_pair(c_pair.0, c_pair.1)
        } else {
            "—".to_string()
        };
        project_row(
            h,
            &esc(name),
            "0,14 64,14",
            if show_spark { "1" } else { "0" },
            &format!("{w:.0}"),
            &cost_str,
            &fmt_tokens(tokens),
            &format!("{share:.0}"),
            if dimmed { "var(--meta)" } else { "var(--text)" },
            if dimmed {
                "var(--cache-read)"
            } else {
                "var(--input)"
            },
        );
    };
    for (name, t) in &top_p {
        emit_project(h, name, t.sum(), proj_cost(name), false, true);
    }
    if user_projects.len() > 10 {
        let rest_tokens: u64 = user_projects[10..].iter().map(|(_, t)| t.sum()).sum();
        let mut rest_models: HashMap<String, Totals> = HashMap::new();
        for (name, _) in &user_projects[10..] {
            for (m, mt) in st.project_models(name) {
                let entry = rest_models.entry(m).or_default();
                entry.input += mt.input;
                entry.output += mt.output;
                entry.cache_read += mt.cache_read;
                entry.cache_write += mt.cache_write;
                entry.thinking += mt.thinking;
                entry.messages += mt.messages;
            }
        }
        let rest_vec: Vec<(String, Totals)> = rest_models.into_iter().collect();
        let rest_cost = if cost_on {
            pricing::cost_summary(&rest_vec)
        } else {
            (None, false)
        };
        emit_project(
            h,
            &format!("{} others", user_projects.len() - 10),
            rest_tokens,
            rest_cost,
            true,
            false,
        );
    }
    h.push_str("</div>\n");
    if let Some((name, t)) = ping_entry {
        h.push_str(
            r#"<div id="p-ping" style="padding-top: 8px; border-top: 1px solid var(--track);">"#,
        );
        emit_project(h, name, t.sum(), proj_cost(name), true, false);
        h.push_str("</div>\n");
    } else {
        h.push_str(
            r#"<div id="p-ping" hidden style="padding-top: 8px; border-top: 1px solid var(--track);"></div>"#,
        );
    }
    h.push_str(
        r#"<div style="font-size: 12px; color: var(--meta); padding-top: 6px; border-top: 1px solid var(--track);"><span class="mono" style="color: var(--muted);">Mask projects</span> hides names on screen only. To share a report, use <span class="mono" style="color: var(--muted);">tickover stats --report --mask</span>.</div>
</div></div>
<div style="display: flex; flex-direction: column; gap: 12px;">
<div class="row"><h2 class="sec">TOP SESSIONS</h2>
<span class="secnote" data-k="s-note">top 10 in all history</span></div>
<div class="card" style="padding: 18px 20px; display: flex; flex-direction: column; gap: 10px;">
<div class="srow mono" style="font-size: 10px; letter-spacing: 0.13em; color: var(--meta);">
<span>#</span><span>PROJECT · DATE</span><span class="srow-hide">MODEL</span><span class="srow-hide" style="text-align: right;">LEN</span><span style="text-align: right;">TOKENS</span><span style="text-align: right;">COST</span>
</div>
<div id="s-rows" style="display: flex; flex-direction: column; gap: 9px;">
"#,
    );

    let mut sessions = st.sessions.clone();
    let sess_cost = |s: &query::SessionStat| -> (Option<f64>, bool) {
        if !cost_on {
            return (None, false);
        }
        let models: Vec<(String, Totals)> = s.models.iter().map(|(m, t)| (m.clone(), *t)).collect();
        pricing::cost_summary(&models)
    };
    if cost_on {
        sessions.sort_by(|a, b| {
            let ca = sess_cost(a).0;
            let cb = sess_cost(b).0;
            match (ca, cb) {
                (Some(x), Some(y)) => y
                    .partial_cmp(&x)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| b.totals.sum().cmp(&a.totals.sum())),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => b.totals.sum().cmp(&a.totals.sum()),
            }
        });
    }
    for (i, s) in sessions.iter().take(10).enumerate() {
        let span = session_span(&s.first_hour, &s.last_hour);
        let date = query::parse_bucket_hour(&s.first_hour)
            .map(|h| h.with_timezone(&Local).format("%d %b %Y").to_string())
            .unwrap_or_else(|| s.first_hour.clone());
        let (c, partial) = sess_cost(s);
        let cost = if cost_on {
            fmt_cost_pair(c, partial)
        } else {
            "—".into()
        };
        let model = s.top_model();
        session_row(
            h,
            &(i + 1).to_string(),
            &esc(&s.project),
            &date,
            &esc(provider_name(&s.provider)),
            &esc(if model.is_empty() { "—" } else { model }),
            &span,
            &fmt_tokens(s.totals.sum()),
            &cost,
        );
    }
    h.push_str("</div></div></div></div>\n");
}

fn habits(h: &mut String, st: &Stats) {
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    let mut max = 0u64;
    let mut total = 0u64;
    let mut peak = (0usize, 0usize);
    for (w, row) in st.weekday_hours.iter().enumerate() {
        for (hr, &v) in row.iter().enumerate() {
            total += v;
            if v > max {
                max = v;
                peak = (w, hr);
            }
        }
    }
    let denom = max.max(1) as f64;
    let peak_share = st.weekday_hours[peak.0][peak.1] as f64 * 100.0 / total.max(1) as f64;
    h.push_str(
        r#"<div style="display: flex; flex-direction: column; gap: 12px;">
<div class="row"><h2 class="sec">USAGE HABITS</h2>
<span class="secnote">day of week × hour, local time</span></div>
<div class="card" style="padding: 18px 20px; display: flex; flex-direction: column; gap: 10px;">
<div class="scroll-x">
<div style="display: grid; grid-template-columns: 36px repeat(24, minmax(12px, 1fr)); gap: 3px; min-width: 420px; align-items: center;">
<span></span>
"#,
    );
    for hr in 0..24 {
        let label = if hr % 3 == 0 {
            format!("{hr:02}")
        } else {
            String::new()
        };
        let _ = write!(
            h,
            r#"<span class="mono" style="font-size: 9px; color: var(--meta); text-align: center;">{label}</span>"#,
        );
    }
    for (w, day_name) in DAYS.iter().enumerate() {
        let _ = write!(
            h,
            r#"<span class="mono" style="font-size: 10px; color: var(--meta);">{day_name}</span>"#,
        );
        for (hr, &v) in st.weekday_hours[w].iter().enumerate() {
            let level = if v == 0 {
                0
            } else {
                (1 + (v as f64 / denom * 3.999) as usize).min(4)
            };
            let _ = write!(
                h,
                r#"<div data-wh="{w}-{hr}" title="{day_name} {hr:02}:00 — {tok}" style="height: 14px; border-radius: 2px; background: var(--heat{level});"></div>"#,
                tok = fmt_tokens(v),
            );
        }
    }
    let _ = write!(
        h,
        r#"</div></div>
<div style="font-size: 12px; color: var(--muted); padding-top: 6px; border-top: 1px solid var(--track);">Peak slot <span class="mono" data-k="hb-peak" style="color: var(--text);">{day} {hr:02}:00</span> — <span data-k="hb-share">{peak_share:.0}</span>% of tokens in this period.</div>
</div></div>
"#,
        day = DAYS[peak.0],
        hr = peak.1,
    );
}

fn heatmap(h: &mut String, st: &Stats) {
    if st.heatmap.is_empty() {
        return;
    }
    let max = st
        .heatmap
        .iter()
        .flatten()
        .map(|(_, v)| *v)
        .max()
        .unwrap_or(1)
        .max(1);
    let active = st.active_days;
    let busiest = st
        .daily
        .iter()
        .max_by_key(|(_, t)| t.sum())
        .map(|(d, t)| (*d, t.sum()));
    let _ = write!(
        h,
        r#"<details class="card" style="padding: 16px 20px;">
<summary class="mono" style="cursor: pointer; font-size: 12px; font-weight: 700; letter-spacing: 0.14em;">52 WEEKS <span style="font-weight: 400; letter-spacing: normal; color: var(--meta);">· {active} active days · streak {streak} · all history, whatever the period</span></summary>
<div style="margin-top: 14px; display: flex; flex-direction: column; gap: 12px;">
<div class="scroll-x">
<div style="display: flex; gap: 12px; align-items: flex-start; min-width: 780px;">
<div class="mono" style="display: flex; flex-direction: column; gap: 3px; font-size: 9px; color: var(--meta); padding-top: 1px;">
<span style="height: 12px; line-height: 12px;">Sun</span><span style="height: 12px; line-height: 12px;">Mon</span><span style="height: 12px;"></span><span style="height: 12px; line-height: 12px;">Wed</span><span style="height: 12px;"></span><span style="height: 12px; line-height: 12px;">Fri</span><span style="height: 12px;"></span>
</div>
<div style="display: grid; grid-auto-flow: column; grid-template-rows: repeat(7, 12px); grid-auto-columns: 12px; gap: 3px;">
"#,
        streak = st.streak_days,
    );
    for week in &st.heatmap {
        for (d, v) in week {
            let level = if *v == 0 {
                0
            } else {
                (1 + (*v as f64 / max as f64 * 3.999) as usize).min(4)
            };
            let _ = write!(
                h,
                r#"<div title="{d} — {v}" style="width:12px;height:12px;border-radius:2px;background:var(--heat{level});"></div>"#,
                v = fmt_tokens(*v),
            );
        }
    }
    h.push_str("</div></div></div>\n");
    let busiest_s = busiest
        .map(|(d, v)| format!("{} — {}", d.format("%d %b %Y"), fmt_tokens(v)))
        .unwrap_or_else(|| "—".into());
    let _ = write!(
        h,
        r#"<div class="mono" style="display: flex; align-items: center; gap: 12px; padding-top: 4px; font-size: 11px; color: var(--meta);">
<span>busiest: <span style="color: var(--text);">{busiest_s}</span></span>
<span class="spacer"></span>
<span>less</span>
<span style="display: flex; gap: 3px;">
<span style="width: 12px; height: 12px; border-radius: 2px; background: var(--heat0);"></span>
<span style="width: 12px; height: 12px; border-radius: 2px; background: var(--heat1);"></span>
<span style="width: 12px; height: 12px; border-radius: 2px; background: var(--heat2);"></span>
<span style="width: 12px; height: 12px; border-radius: 2px; background: var(--heat3);"></span>
<span style="width: 12px; height: 12px; border-radius: 2px; background: var(--heat4);"></span>
</span>
<span>more</span>
</div>
</div></details>
"#
    );
}

/// `"YYYY-MM-DDTHH"` × 2 → `"6h"` or `"2d 3h"` (buckets are hour-granular).
pub fn session_span(first: &str, last: &str) -> String {
    fn parse(h: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        let d = chrono::NaiveDate::parse_from_str(h.get(..10)?, "%Y-%m-%d").ok()?;
        let hr: u32 = h.get(11..)?.parse().ok()?;
        Some(chrono::Utc.from_utc_datetime(&d.and_hms_opt(hr, 0, 0)?))
    }
    use chrono::TimeZone;
    match (parse(first), parse(last)) {
        (Some(a), Some(b)) if b > a => {
            let hrs = (b - a).num_hours() + 1;
            if hrs >= 24 {
                format!("{}d {}h", hrs / 24, hrs % 24)
            } else {
                format!("{hrs}h")
            }
        }
        _ => "1h".into(),
    }
}

/// What the cache saved: those tokens at full input price minus their actual
/// cache-read price.
pub fn cache_saved(models: &[(String, Totals)]) -> (f64, bool) {
    let mut any_unpriced_with_reads = false;
    let saved = models
        .iter()
        .filter_map(|(m, t)| {
            let at = |totals: Totals| pricing::cost_usd(m, &totals);
            let as_input = at(Totals {
                input: t.cache_read,
                ..Totals::default()
            });
            let as_cache = at(Totals {
                cache_read: t.cache_read,
                ..Totals::default()
            });
            match (as_input, as_cache) {
                (Some(ai), Some(ac)) => Some(ai - ac),
                _ if t.cache_read > 0 => {
                    any_unpriced_with_reads = true;
                    None
                }
                _ => None,
            }
        })
        .sum();
    (saved, any_unpriced_with_reads)
}

fn pricing_line(st: &Stats, cost_on: bool) -> String {
    if !cost_on {
        return String::new();
    }
    let missing = pricing::unpriced(&st.models);
    let mut line = format!(" Costs: {}.", esc(&pricing::sources_note()));
    if !missing.is_empty() {
        let total = st.total.sum().max(1) as f64;
        let share: u64 = st
            .models
            .iter()
            .filter(|(m, _)| missing.contains(m))
            .map(|(_, t)| t.sum())
            .sum();
        let names = missing
            .iter()
            .map(|m| format!(r#"<span class="mono">{}</span>"#, esc(m)))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = write!(
            line,
            " No list price, left out of every cost ({:.1}% of tokens): {names}.",
            share as f64 * 100.0 / total
        );
    }
    line
}

fn footer(h: &mut String, sources: &[String], prices: &str, cost_on: bool) {
    let srcs = if sources.is_empty() {
        "local history files".to_string()
    } else {
        sources
            .iter()
            .map(|s| format!(r#"<span class="mono">{}</span>"#, esc(s)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let estimate_note = if cost_on {
        " Costs are API-equivalent estimates at published list prices, not your bill."
    } else {
        ""
    };
    let _ = write!(
        h,
        r#"<div style="padding: 8px 0 40px; display: flex; gap: 32px; flex-wrap: wrap; border-top: 1px solid var(--track);">
<div style="max-width: 620px; font-size: 12px; color: var(--meta); line-height: 1.7; padding-top: 14px;">
Generated {now} by tickover {ver}. Read from {srcs}. Duplicate message ids removed; Codex cumulative counters differenced. Claude sub-agent turns count once, from their own transcript file.{prices}{estimate_note}
</div>
<span class="spacer"></span>
<div class="mono" style="font-size: 11px; color: var(--meta); text-align: right; line-height: 1.8; padding-top: 14px;">file mode 0600<br>no network calls<br>no external assets</div>
</div>
"#,
        now = Local::now().format("%d %b %Y %H:%M"),
        ver = env!("CARGO_PKG_VERSION"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::store::{DayLine, HistoryStore, SCHEMA_VERSION};
    use std::fs;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tickover-report-test-{tag}-{}-{:?}",
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

    #[test]
    fn only_names_the_report_writer_chooses_count_as_its_own() {
        assert!(is_own_report_name("usage-20261111-170716.html"));
        for name in [
            "usage-20261111-170716.htm",
            "usage-20261111170716.html",
            "usage-2026111-170716.html",
            "usage-20261111-17071a.html",
            "usage-20261111-170716.html.bak",
            "my-usage-20261111-170716.html",
            "usage-20261111-170716-2.html",
            "usage-.html",
        ] {
            assert!(!is_own_report_name(name), "{name}");
        }
    }

    #[test]
    fn pruning_keeps_the_newest_reports_and_nothing_else_is_touched() {
        let dir = tmpdir("prune");
        let own: Vec<String> = (1..=8)
            .map(|d| format!("usage-202611{d:02}-120000.html"))
            .collect();
        for n in &own {
            fs::write(dir.join(n), "x").unwrap();
        }
        fs::write(dir.join("mine.html"), "x").unwrap();
        fs::write(dir.join("usage-latest.html"), "x").unwrap();
        let current = dir.join(&own[0]);

        let removed = prune_reports(&dir, 3, &current);

        assert_eq!(removed, 4);
        let mut left: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec![
                "mine.html".to_string(),
                own[0].clone(),
                own[5].clone(),
                own[6].clone(),
                own[7].clone(),
                "usage-latest.html".to_string(),
            ]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn pruning_never_follows_or_removes_a_symlink() {
        let dir = tmpdir("prune-link");
        let outside = tmpdir("prune-link-target");
        let target = outside.join("keep-me.html");
        fs::write(&target, "x").unwrap();
        std::os::unix::fs::symlink(&target, dir.join("usage-20200101-000000.html")).unwrap();
        for d in 1..=3 {
            fs::write(dir.join(format!("usage-202611{d:02}-120000.html")), "x").unwrap();
        }

        assert_eq!(prune_reports(&dir, 1, &dir.join("none")), 2);
        assert!(target.exists());
        assert!(fs::symlink_metadata(dir.join("usage-20200101-000000.html")).is_ok());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
    }

    fn day(hour: &str, model: &str, cache_read: u64) -> DayLine {
        DayLine {
            v: SCHEMA_VERSION,
            hour: hour.to_string(),
            provider: "claude".into(),
            project: "proj".into(),
            model: model.into(),
            session: "s1".into(),
            file: "/f".into(),
            gen: 0,
            lo: 0,
            hi: 0,
            full: false,
            b: 0,
            input: 1_000_000,
            output: 1_000_000,
            cache_read,
            cache_write: 0,
            thinking: 0,
            messages: 1,
        }
    }

    fn render_for(
        store: &HistoryStore,
        st: &Stats,
        enabled: &std::collections::HashSet<String>,
    ) -> String {
        let data = report_data::build(store, st, enabled, true);
        let html = render(st, true, &[], &[], &data).unwrap();
        let end = html.find(r#"<script type="application/json""#).unwrap();
        html[..end].to_string()
    }

    #[test]
    fn the_script_cannot_end_its_own_element_and_the_page_loads_nothing_external() {
        assert!(!REPORT_JS.contains("</script"));
        for needle in ["http://", "https://", "fetch(", "XMLHttpRequest", "import("] {
            assert!(!REPORT_JS.contains(needle), "{needle}");
        }
    }

    #[test]
    fn every_hook_the_script_writes_to_exists_in_the_page() {
        let dir = tmpdir("report-hooks");
        let mut store = HistoryStore::open(&dir).unwrap();
        let hour = chrono::Utc::now().format("%Y-%m-%dT%H").to_string();
        store
            .append_days(&[day(&hour, "claude-sonnet-4-6", 500_000)])
            .unwrap();
        store.commit().unwrap();
        let store = HistoryStore::open(&dir).unwrap();
        let enabled: std::collections::HashSet<String> =
            ["claude".to_string()].into_iter().collect();
        let st = query::compute(&store, 30, &enabled);
        let data = report_data::build(&store, &st, &enabled, true);
        let html = render(&st, true, &[], &[], &data).unwrap();

        let quoted = |marker: &str| -> Vec<String> {
            REPORT_JS
                .split(marker)
                .skip(1)
                .filter_map(|rest| rest.split('"').next().map(str::to_string))
                .collect()
        };
        let texts = quoted("setText(\"");
        assert!(texts.len() >= 15, "{texts:?}");
        for key in texts {
            assert!(html.contains(&format!("data-k=\"{key}\"")), "data-k {key}");
        }
        for key in quoted("setDelta(\"") {
            assert!(html.contains(&format!("data-k=\"{key}\"")), "delta {key}");
        }
        for key in quoted("setWidth(\"") {
            assert!(html.contains(&format!("data-w=\"{key}\"")), "data-w {key}");
        }
        for key in quoted("getElementById(\"")
            .into_iter()
            .chain(quoted("fill(\""))
            .chain(quoted("row(\""))
        {
            assert!(html.contains(&format!("id=\"{key}\"")), "id {key}");
        }
        for hole in [
            "@id@", "@name@", "@tok@", "@proj@", "@m@", "@pts@", "@cost@",
        ] {
            assert!(html.contains(hole), "{hole}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_report_with_cost_on_marks_every_partial_sum() {
        let dir = tmpdir("report-partial-cost");
        let mut store = HistoryStore::open(&dir).unwrap();
        let hour = chrono::Utc::now().format("%Y-%m-%dT%H").to_string();
        store
            .append_days(&[
                day(&hour, "claude-sonnet-4-6", 0),
                day(&hour, "mystery-model-x", 500_000),
            ])
            .unwrap();
        store.commit().unwrap();
        let store = HistoryStore::open(&dir).unwrap();
        let enabled: std::collections::HashSet<String> =
            ["claude".to_string()].into_iter().collect();
        let st = query::compute(&store, 30, &enabled);

        let html = render_for(&store, &st, &enabled);

        assert!(html.contains("$18*"), "headline must mark the partial sum");
        assert!(
            html.contains("API-equivalent, partial — unpriced models excluded"),
            "headline caption must name the exclusion"
        );
        assert!(
            html.contains("$18.00*"),
            "breakdown, projects, and sessions cost cells must carry the partial marker"
        );
        assert!(
            html.contains("cache read 11% tok") && !html.contains("0% $*"),
            "when only unpriced models had cache reads, no bogus $ share appears: {html}"
        );
        let _ = fs::remove_dir_all(&dir);

        let dir2 = tmpdir("report-partial-cost-cr");
        let mut store2 = HistoryStore::open(&dir2).unwrap();
        store2
            .append_days(&[
                day(&hour, "claude-sonnet-4-6", 1_000_000),
                day(&hour, "mystery-model-x", 500_000),
            ])
            .unwrap();
        store2.commit().unwrap();
        let store2 = HistoryStore::open(&dir2).unwrap();
        let st2 = query::compute(&store2, 30, &enabled);
        let html2 = render_for(&store2, &st2, &enabled);
        assert!(
            html2.contains("cache read 27% tok · 2% $*"),
            "cache-read share note must show both token and cost shares and mark partial cache reads: {html2}"
        );
        let _ = fs::remove_dir_all(&dir2);
    }

    #[test]
    fn a_report_with_cost_on_and_one_priced_model_carries_no_marker() {
        let dir = tmpdir("report-full-cost");
        let mut store = HistoryStore::open(&dir).unwrap();
        let hour = chrono::Utc::now().format("%Y-%m-%dT%H").to_string();
        store
            .append_days(&[day(&hour, "claude-sonnet-4-6", 0)])
            .unwrap();
        store.commit().unwrap();
        let store = HistoryStore::open(&dir).unwrap();
        let enabled: std::collections::HashSet<String> =
            ["claude".to_string()].into_iter().collect();
        let st = query::compute(&store, 30, &enabled);

        let html = render_for(&store, &st, &enabled);
        assert!(html.contains("$18"), "the priced total still shows");
        assert!(
            !html.contains("$18*"),
            "fully priced sum must not be marked"
        );
        assert!(
            !html.contains("partial"),
            "no caption should mention partial coverage"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn right_now_renders_as_compact_rows() {
        let dir = tmpdir("report-right-now");
        let store = HistoryStore::open(&dir).unwrap();
        let enabled: std::collections::HashSet<String> =
            ["claude".to_string()].into_iter().collect();
        let st = query::compute(&store, 30, &enabled);
        let data = report_data::build(&store, &st, &enabled, true);
        let quota = [QuotaNow {
            provider: "claude".into(),
            label: "5H".into(),
            used_pct: 42.0,
            projected_pct: Some(75.0),
            reset_hint: "2h 10m".into(),
            burn_per_hour: Some(12_000),
        }];
        let html = render(&st, true, &quota, &[], &data).unwrap();
        let strip = &html[..html.find(r#"<script type="application/json""#).unwrap()];
        assert!(strip.contains("class=\"qrow mono\""), "compact row layout");
        assert!(strip.contains("42% · ~75%"), "used and projected pct");
        assert!(strip.contains("12K/h"), "burn rate");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn plan_ratio_card_renders_when_configured_and_dash_when_absent() {
        let dir = tmpdir("report-plan-ratio");
        let mut store = HistoryStore::open(&dir).unwrap();
        let hour = chrono::Utc::now().format("%Y-%m-%dT%H").to_string();
        store
            .append_days(&[day(&hour, "claude-sonnet-4-6", 0)])
            .unwrap();
        store.commit().unwrap();
        let store = HistoryStore::open(&dir).unwrap();
        let enabled: std::collections::HashSet<String> =
            ["claude".to_string()].into_iter().collect();
        let st = query::compute(&store, 30, &enabled);
        let mut data = report_data::build(&store, &st, &enabled, true);

        let absent_html = render(&st, true, &[], &[], &data).unwrap();
        let absent_head = &absent_html[..absent_html
            .find(r#"<script type="application/json""#)
            .unwrap()];
        assert!(absent_head.contains("set [plans] in prices.toml"));

        data.plans.insert("claude".to_string(), 200.0);
        let set_html = render(&st, true, &[], &[], &data).unwrap();
        let set_head = &set_html[..set_html.find(r#"<script type="application/json""#).unwrap()];
        // $18 over 1d vs $200/30 = $6.67 => ×2.7
        assert!(set_head.contains("×2.7"), "{set_head}");
        assert!(set_head.contains("API-equiv ÷ $200/mo (not savings)"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fifty_two_weeks_section_is_collapsed_by_default() {
        let dir = tmpdir("report-52w-collapsed");
        let store = HistoryStore::open(&dir).unwrap();
        let enabled = std::collections::HashSet::new();
        let st = query::compute(&store, 30, &enabled);
        let html = render_for(&store, &st, &enabled);
        assert!(html.contains(r#"<details class="card""#));
        assert!(!html.contains(r#"<details class="card" open"#));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn projects_section_separates_auto_ping_row() {
        let dir = tmpdir("report-auto-ping-row");
        let mut store = HistoryStore::open(&dir).unwrap();
        let hour = chrono::Utc::now().format("%Y-%m-%dT%H").to_string();
        let mut ping_day = day(&hour, "claude-haiku-4-5", 0);
        ping_day.project = "tickover-ping-99".into();
        ping_day.session = "s-ping".into();
        let mut repo_day = day(&hour, "claude-sonnet-4-6", 0);
        repo_day.project = "my-repo".into();
        store.append_days(&[ping_day, repo_day]).unwrap();
        store.commit().unwrap();
        let store = HistoryStore::open(&dir).unwrap();
        let enabled: std::collections::HashSet<String> =
            ["claude".to_string()].into_iter().collect();
        let st = query::compute(&store, 30, &enabled);
        let html = render_for(&store, &st, &enabled);
        let ping_start = html.find(r#"id="p-ping""#).unwrap();
        assert!(html[ping_start..].contains(AUTO_PING_PROJECT));
        assert!(html[..ping_start].contains("my-repo"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn habits_section_renders_seven_by_twenty_four_weekday_hour_grid() {
        let dir = tmpdir("report-habits-grid");
        let store = HistoryStore::open(&dir).unwrap();
        let enabled = std::collections::HashSet::new();
        let st = query::compute(&store, 30, &enabled);
        let html = render_for(&store, &st, &enabled);
        let cells = html.matches("data-wh=\"").count();
        assert_eq!(cells, 7 * 24);
        let _ = fs::remove_dir_all(&dir);
    }
}
