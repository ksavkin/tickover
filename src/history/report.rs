//! Self-contained HTML usage report — `tickover stats --report`.
//!
//! One file, no network, no external assets: CSS is a `<style>` block,
//! charts are inline SVG/CSS. Dark is default; light follows
//! `prefers-color-scheme` and the toggle. The file is written `0600` —
//! project basenames are still sensitive enough for that.
//!
//! The page Rust renders is the whole report for all of history and works
//! with scripts off. `report.js` adds the period picker: it sums the rows
//! [`report_data`] embedded, and writes the
//! result back through `data-k`/`data-w` hooks and `<template>` rows. Those
//! templates are this module's own row functions called with `@name@` holes,
//! so the markup has one author; only the arithmetic exists twice, and
//! `tests/report_js.rs` holds the two together.
//!
//! Every interpolated string goes through [`esc`]; numbers are formatted
//! by this module only. Provider content never reaches the store, so the
//! report can contain none — there is nothing to escape *from*, and the
//! escape is defence against metadata like project names anyway.

use std::fmt::Write as _;
use std::io;
use std::path::PathBuf;

use chrono::{Datelike, Local};

use crate::history::pricing;
use crate::history::query::{self, Stats, Totals};
use crate::history::report_data::{self, ReportData};

/// The picker. Public for the parity test, which runs this exact text.
pub const REPORT_JS: &str = include_str!("report.js");

/// Live quota card for the report's "RIGHT NOW" strip — supplied by the
/// panel when it already has a fresh reading; the CLI passes `&[]` and
/// the section is simply absent (an empty strip would lie by omission).
pub struct QuotaNow {
    pub provider: String,
    pub label: String,
    pub used_pct: f64,
    pub projected_pct: Option<f64>,
    pub reset_hint: String,
    /// `None` whenever `projected_pct` is — the caller only ever fills this
    /// once the projection itself was drawn, so the card never states a pace
    /// for a window its own bar has nothing to show for.
    pub burn_per_hour: Option<u64>,
}

/// Status colors needed where a CSS variable won't do — SVG `stroke`/
/// `fill` accepts `var()`, so only the computed-worst-case choice in
/// `right_now` and the habits bars need literals. Both pick from the same
/// tokens the stylesheet declares.
mod c {
    pub const OK: &str = "#35d79a";
    pub const WARN: &str = "#d29922";
    pub const CRIT: &str = "#f85149";
    /// The habits bars' muted teal — inside the SVG-less markup it could
    /// be a var, but a named constant reads clearer next to the ramp.
    pub const HABIT: &str = "#265c4c";
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

/// Provider display name — the report shows Title-case, ids stay
/// lowercase internally.
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

/// HTML-escape — the one function every interpolated string takes.
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
    // thousands-separated integer
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

/// The headline card's figure: whole dollars read better at that size, but
/// a short period can sit under one, and "$0" would say it cost nothing.
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

/// [`pricing::cost_for_models`] rendered through [`fmt_usd`], with a
/// trailing `*` when `models` includes one this table has no price for —
/// a sum missing a whole model's share must not print as confidently as
/// one that knows every model it summed.
fn fmt_usd_for_models(models: &[(String, Totals)]) -> String {
    let (v, partial) = pricing::cost_summary(models);
    let s = fmt_usd(v);
    if partial {
        format!("{s}*")
    } else {
        s
    }
}

/// Write the report. `path: None` → `<config>/tickover/reports/
/// usage-<yyyymmdd-hhmmss>.html`; the file is created `0600`. Returns the
/// path actually written.
pub fn write(
    st: &Stats,
    path: Option<PathBuf>,
    cost_on: bool,
    quota: &[QuotaNow],
    sources: &[String],
    data: &ReportData,
) -> io::Result<PathBuf> {
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
    // Ensure mode even when the file pre-existed (create+truncate keeps
    // the old mode otherwise).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
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
    filtered(&mut h, |h| headline(h, st, cost_on));
    coverage(&mut h, st);
    filtered(&mut h, |h| {
        tools(h, st, cost_on);
        context_efficiency(h, st);
        hot_zones_and_models(h, st);
        weekly_trail(h, st);
    });
    heatmap(&mut h, st);
    filtered(&mut h, |h| {
        habits_and_sessions(h, st, cost_on);
        wrapped(h, st, cost_on);
    });
    footer(&mut h, sources);
    templates(&mut h);
    h.push_str("</div></div>\n<script type=\"application/json\" id=\"report-data\">");
    h.push_str(&embedded);
    h.push_str("</script>\n<script>\n");
    h.push_str(REPORT_JS);
    h.push_str("</script>\n</body>\n</html>\n");
    Ok(h)
}

/// Wrap the sections a period changes, for the picker to hide when a period
/// holds nothing. `display: contents`, so the page's own layout sees through.
fn filtered(h: &mut String, section: impl FnOnce(&mut String)) {
    h.push_str("<div class=\"pf\">\n");
    section(h);
    h.push_str("</div>\n");
}

/// The rows the picker redraws, as `<template>`s: each row function again,
/// handed `@name@` where it would take a value.
fn templates(h: &mut String) {
    let mut t = |id: &str, row: &dyn Fn(&mut String)| {
        let _ = write!(h, r#"<template id="{id}">"#);
        row(h);
        h.push_str("</template>\n");
    };
    t("tpl-seg", &|h| {
        tool_segment(h, "@w@", "@c@", "@radius@", "@name@", "@label@")
    });
    t("tpl-legend", &|h| tool_legend(h, "@c@", "@name@", "@w@"));
    t("tpl-tool", &|h| {
        tool_row(
            h,
            "@c@",
            "@name@",
            ["@cr@", "@cw@", "@inp@", "@out@"],
            "@tokens@",
            "@last@",
        )
    });
    t("tpl-context", &|h| {
        context_row(h, "@name@", "@pp@", "@color@")
    });
    t("tpl-project", &|h| {
        project_row(h, "@name@", "@w@", "@share@", "@v@", "@color@", "@fill@")
    });
    t("tpl-model", &|h| model_row(h, "@m@", "@v@", "@w@"));
    t("tpl-session", &|h| {
        session_row(
            h, "@i@", "@proj@", "@date@", "@prov@", "@span@", "@tok@", "@cost@",
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
<button type="button" class="btn" data-p="all" aria-pressed="false">All</button>
<label class="mono period-date">from <input type="date" id="p-from"></label>
<label class="mono period-date">to <input type="date" id="p-to"></label>
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
  --cache-read: #39424f; --cache-read-base: #232a34; --cache-write: #2d5f8f;
  --input: #6cb6ff; --output: #f0883e;
  --p-claude: #d97757; --p-codex: #56d4bd; --p-agy: #a78bfa;
  --p-grok: #dfa93f; --p-copilot: #4a515c;
  --heat0: #161a20; --heat1: #17392e; --heat2: #1d5c46; --heat3: #2a9770; --heat4: #35d79a;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #f6f5f1; --surface: #fffefb; --topbar: #efece6;
    --track: #e2e0d9; --track-soft: #eceae4; --hairline: #d8d5cc;
    --text: #17191d; --muted: #5b6068; --meta: #6f747c;
    --ok: #10845f; --warn: #9a6a10; --crit: #b3261e;
    --cache-read: #8b9098; --cache-read-base: #eceae4; --cache-write: #0b6247;
    --input: #1f6feb; --output: #b3560f;
    --p-claude: #b2543a; --p-codex: #157f6c; --p-agy: #6d4fc4;
    --p-grok: #8a6208; --p-copilot: #8b9098;
    --heat0: #eceae4; --heat1: #cfe8dd; --heat2: #9fd4bf; --heat3: #4fae8a; --heat4: #10845f;
  }
}
html.light {
  --bg: #f6f5f1; --surface: #fffefb; --topbar: #efece6;
  --track: #e2e0d9; --track-soft: #eceae4; --hairline: #d8d5cc;
  --text: #17191d; --muted: #5b6068; --meta: #6f747c;
  --ok: #10845f; --warn: #9a6a10; --crit: #b3261e;
  --cache-read: #8b9098; --cache-read-base: #eceae4; --cache-write: #0b6247;
  --input: #1f6feb; --output: #b3560f;
  --p-claude: #b2543a; --p-codex: #157f6c; --p-agy: #6d4fc4;
  --p-grok: #8a6208; --p-copilot: #8b9098;
  --heat0: #eceae4; --heat1: #cfe8dd; --heat2: #9fd4bf; --heat3: #4fae8a; --heat4: #10845f;
}
html.dark {
  --bg: #0b0d11; --surface: #12151b; --topbar: #0d1015;
  --track: #1e232b; --track-soft: #171b22; --hairline: #262b34;
  --text: #e8eaed; --muted: #8b929d; --meta: #767d89;
  --ok: #35d79a; --warn: #d29922; --crit: #f85149;
  --cache-read: #39424f; --cache-read-base: #232a34; --cache-write: #2d5f8f;
  --input: #6cb6ff; --output: #f0883e;
  --p-claude: #d97757; --p-codex: #56d4bd; --p-agy: #a78bfa;
  --p-grok: #dfa93f; --p-copilot: #4a515c;
  --heat0: #161a20; --heat1: #17392e; --heat2: #1d5c46; --heat3: #2a9770; --heat4: #35d79a;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); }
a { color: var(--ok); text-decoration: none; }
.mono { font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace; }
.shell { max-width: 1120px; margin: 0 auto; padding: 0 32px;
  display: flex; flex-direction: column; gap: 40px; }
.topbar { display: flex; align-items: center; gap: 12px; padding: 0 32px;
  height: 60px; border-bottom: 1px solid var(--track); background: var(--topbar); }
.btn { font: inherit; font-family: 'JetBrains Mono', ui-monospace, Menlo, monospace;
  font-size: 11px; background: var(--surface); color: var(--text);
  border: 1px solid var(--hairline); border-radius: 6px; padding: 6px 10px;
  cursor: pointer; display: inline-flex; align-items: center; gap: 6px; }
h2.sec { margin: 0; font-family: 'JetBrains Mono', ui-monospace, Menlo, monospace;
  font-size: 12px; font-weight: 700; letter-spacing: 0.17em; }
.secnote { color: var(--meta); font-size: 13px; }
.card { background: var(--surface); border: 1px solid var(--track); border-radius: 12px; }
.pill { display: inline-flex; align-items: center; gap: 7px;
  border: 1px solid var(--hairline); border-radius: 999px;
  padding: 5px 12px 5px 9px; font-size: 11px; color: var(--text);
  font-family: 'JetBrains Mono', ui-monospace, Menlo, monospace; }
.bar-track { height: 10px; border-radius: 3px; background: var(--track-soft); overflow: hidden; }
.bar-fill { height: 100%; border-radius: 3px; background: var(--input); }
.hatch-cr { background-image: repeating-linear-gradient(45deg,
  var(--cache-read) 0 2px, var(--cache-read-base) 2px 4px); }
.hatch-none { background-image: repeating-linear-gradient(45deg,
  var(--hairline) 0 3px, var(--surface) 3px 6px);
  border: 1px dashed var(--hairline); border-radius: 2px; }
.hatch-proj { background-image: repeating-linear-gradient(135deg,
  var(--ok) 0 2px, transparent 2px 5px); opacity: 0.30; }
.proj-masked { letter-spacing: 0.02em; }
.pf { display: contents; }
.pf.off { display: none; }
.period { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
.period[hidden], #sec-context[hidden] { display: none; }
.period .btn[aria-pressed="true"] { border-color: var(--ok); color: var(--ok); }
.period-date { display: inline-flex; align-items: center; gap: 6px; font-size: 11px; color: var(--meta); }
.period-date input { font: inherit; color: var(--text); background: var(--surface);
  border: 1px solid var(--hairline); border-radius: 6px; padding: 5px 8px; color-scheme: dark; }
@media (prefers-color-scheme: light) {
  html:not(.dark) .period-date input { color-scheme: light; }
}
html.light .period-date input { color-scheme: light; }
@media (max-width: 720px) {
  .shell { padding: 0 16px; gap: 28px; }
  .topbar { padding: 0 16px; }
  .grid2, .grid3, .grid6 { grid-template-columns: 1fr !important; }
}
@media print {
  body { background: #fff; }
  .topbar { position: static; }
  .period { display: none; }
}
.grid2 { display: grid; grid-template-columns: minmax(0,1.25fr) minmax(0,1fr); gap: 24px; }
.grid2e { display: grid; grid-template-columns: minmax(0,1fr) minmax(0,1fr); gap: 24px; }
.grid3 { display: grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap: 20px; }
.grid6 { display: grid; grid-template-columns: repeat(6, minmax(0,1fr)); gap: 16px; }
.row { display: flex; align-items: baseline; gap: 12px; }
.spacer { flex-grow: 1; }
.dim { color: var(--muted); }
.meta { color: var(--meta); }
.tooltip { position: absolute; background: var(--surface); border: 1px solid var(--hairline);
  border-radius: 8px; padding: 9px 12px; font-size: 11px; pointer-events: none;
  font-family: 'JetBrains Mono', ui-monospace, Menlo, monospace;
  display: none; z-index: 5; }
svg .tip { opacity: 0; }
svg g.wk:hover .tip { opacity: 1; }
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
        r#"<div style="padding-top: 44px; display: flex; flex-direction: column; gap: 10px;">
<h1 class="mono" style="margin: 0; font-size: 42px; font-weight: 600; letter-spacing: -0.03em; line-height: 1.05;">Where your tokens went</h1>
<p style="margin: 0; color: var(--muted); font-size: 14px; max-width: 720px; line-height: 1.6;"><span data-k="range">{range}</span>, read from CLI history files on this machine. Nothing was uploaded; this file has no network calls and no external assets.</p>
</div>
"#
    );
}

fn right_now(h: &mut String, quota: &[QuotaNow]) {
    h.push_str(
        r#"<div style="display: flex; flex-direction: column; gap: 14px;">
<div class="row"><h2 class="sec">RIGHT NOW</h2>
<span class="secnote">live quota, projected forward at the window's current pace</span></div>
<div class="grid3">
"#,
    );
    for q in quota {
        let used = q.used_pct.clamp(0.0, 100.0);
        let proj = q.projected_pct.unwrap_or(used).clamp(0.0, 100.0);
        // 90 here, not the round-number 85 this used to say: the panel's own
        // hatch turns amber at 90, and a card and its own bar disagreeing on
        // where amber starts would tell two stories about the same window.
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
            r#"<div class="card" style="padding: 18px 20px 16px; display: flex; flex-direction: column; gap: 12px;">
<div class="mono" style="display: flex; align-items: center; gap: 8px;">
<span style="width: 8px; height: 8px; border-radius: 50%; background: {pc};"></span>
<span style="font-size: 11px; font-weight: 700; letter-spacing: 0.15em;">{name}</span>
<span class="spacer"></span>
<span style="font-size: 11px; color: var(--muted);">{label}</span>
</div>
<div class="mono" style="display: flex; align-items: baseline; gap: 8px;">
<span style="font-size: 30px; font-weight: 600; letter-spacing: -0.02em; line-height: 1; color: {color};">{used:.0}%</span>
<span style="font-size: 12px; color: var(--meta);">used · projected {proj:.0}%</span>
</div>
<div style="height: 7px; border-radius: 4px; background: var(--track); position: relative; overflow: hidden;">
<div style="position: absolute; inset: 0 auto 0 0; width: {proj:.0}%; background-image: repeating-linear-gradient(135deg, {color} 0 2px, transparent 2px 5px); opacity: 0.35;"></div>
<div style="position: absolute; inset: 0 auto 0 0; width: {used:.0}%; background: {color}; border-radius: 4px;"></div>
</div>
<div class="mono" style="display: flex; justify-content: space-between; font-size: 11px; color: var(--meta);">
<span>burn <span style="color: var(--text);">{burn}</span></span>
<span>{reset}</span>
</div>
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

fn headline(h: &mut String, st: &Stats, cost_on: bool) {
    let active_days = st.active_days;
    let sessions = st.sessions.len() as u64;
    let msgs_per_day = st.total.messages.checked_div(active_days).unwrap_or(0);
    let avg_msg = st.total.sum().checked_div(st.total.messages).unwrap_or(0);
    let cache = st
        .total
        .cache_hit_pct()
        .map(|p| format!("{p:.0}%"))
        .unwrap_or_else(|| "—".into());
    let cost_card = if cost_on {
        let models: Vec<(String, Totals)> = st.models.clone();
        // A model this table doesn't know still contributed tokens the sum
        // leaves out entirely — the headline must say so rather than let a
        // partial total pass for the whole picture.
        let (v, partial) = pricing::cost_summary(&models);
        (
            "EST. COST".to_string(),
            "cost",
            v.map(|x| {
                let s = fmt_headline_usd(x);
                if partial {
                    format!("{s}*")
                } else {
                    s
                }
            })
            .unwrap_or_else(|| "—".into()),
            if partial {
                "at list price, partial — unpriced models excluded".to_string()
            } else if v.is_none() {
                "no list price for these models".to_string()
            } else {
                "at list price".to_string()
            },
        )
    } else {
        (
            "THIS WEEK".to_string(),
            "week",
            fmt_tokens(st.week.sum()),
            "tokens, Mon → today, whatever the period".to_string(),
        )
    };
    let cards = [
        (
            "TOKENS".to_string(),
            "tokens",
            fmt_tokens(st.total.sum()),
            "in + out + cache".to_string(),
        ),
        cost_card,
        (
            "SESSIONS".to_string(),
            "sessions",
            fmt_int(sessions),
            active_days_label(active_days),
        ),
        (
            "MESSAGES".to_string(),
            "messages",
            fmt_int(st.total.messages),
            format!("{msgs_per_day} / active day"),
        ),
        (
            "AVG / MESSAGE".to_string(),
            "avg",
            fmt_tokens(avg_msg),
            "across all providers".to_string(),
        ),
        (
            "CACHE HIT".to_string(),
            "cache",
            cache,
            "context reused".to_string(),
        ),
    ];
    h.push_str(r#"<div class="grid6">"#);
    for (label, key, value, note) in cards {
        let _ = write!(
            h,
            r#"<div class="card" style="padding: 16px 18px; display: flex; flex-direction: column; gap: 6px;">
<div class="mono" style="font-size: 10px; letter-spacing: 0.13em; color: var(--meta);">{label}</div>
<div class="mono" data-k="card-{key}" style="font-size: 24px; font-weight: 600; letter-spacing: -0.025em; line-height: 1.1;">{value}</div>
<div data-k="card-{key}-note" style="font-size: 11px; color: var(--muted);">{note}</div>
</div>
"#
        );
    }
    h.push_str("</div>\n");
}

fn coverage(h: &mut String, st: &Stats) {
    h.push_str(
        r#"<div class="card" style="padding: 16px 20px; display: flex; align-items: center; gap: 14px; flex-wrap: wrap;">
<span class="mono" style="font-size: 10px; letter-spacing: 0.15em; color: var(--meta);">COVERAGE</span>
"#,
    );
    for p in &st.providers {
        let _ = writeln!(
            h,
            r#"<span class="pill"><span style="width: 7px; height: 7px; border-radius: 50%; background: {color};"></span>{name}</span>"#,
            color = provider_color(p),
            name = esc(provider_name(p)),
        );
    }
    h.push_str(
        r#"<span class="spacer"></span>
<span style="font-size: 12px; color: var(--meta);">Token counts are exact as logged; costs are estimates at public list prices, not your invoice.</span>
</div>
"#,
    );
}

/// The 4-class token mix bar used in "YOUR TOOLS" rows, as percentages of
/// `[cache read, cache write, input, output]`.
fn mix_bar(h: &mut String, [cr, cw, input, output]: [&str; 4]) {
    let _ = write!(
        h,
        r#"<div style="display: flex; gap: 2px; height: 10px;"><div class="hatch-cr" style="width:{cr}%;border-radius:2px 0 0 2px;"></div><div style="width:{cw}%;background:var(--cache-write);"></div><div style="width:{input}%;background:var(--input);"></div><div style="width:{output}%;background:var(--output);border-radius:0 2px 2px 0;"></div></div>"#,
    );
}

fn tool_segment(h: &mut String, w: &str, c: &str, radius: &str, name: &str, label: &str) {
    let _ = write!(
        h,
        r#"<div style="width: {w}%; background: {c}; border-radius: {radius};" title="{name} {label}%"></div>"#,
    );
}

fn tool_legend(h: &mut String, c: &str, name: &str, w: &str) {
    let _ = write!(
        h,
        r#"<span style="display: inline-flex; align-items: center; gap: 7px;"><span style="width: 9px; height: 9px; border-radius: 2px; background: {c};"></span><span style="color: var(--text);">{name}</span> {w}%</span>"#,
    );
}

fn tool_row(h: &mut String, c: &str, name: &str, mix: [&str; 4], tokens: &str, last: &str) {
    let _ = write!(
        h,
        r#"<div style="display: grid; grid-template-columns: 150px minmax(0,1fr) 110px 90px; gap: 20px; align-items: center;">
<span class="mono" style="display: inline-flex; align-items: center; gap: 8px; font-size: 12px;"><span style="width: 9px; height: 9px; border-radius: 2px; background: {c};"></span>{name}</span>
"#,
    );
    mix_bar(h, mix);
    let _ = writeln!(
        h,
        r#"<span class="mono" style="font-size: 12px; text-align: right; color: var(--text);">{tokens}</span><span class="mono" style="font-size: 12px; text-align: right; color: var(--text);">{last}</span></div>"#,
    );
}

fn tools(h: &mut String, st: &Stats, cost_on: bool) {
    let total = st.total.sum().max(1);
    let _ = write!(
        h,
        r#"<div style="display: flex; flex-direction: column; gap: 14px;">
<div class="row"><h2 class="sec">YOUR TOOLS</h2>
<span class="secnote">share of <span data-k="tools-total">{tot}</span> tokens</span></div>
<div class="card" style="padding: 22px 24px 20px; display: flex; flex-direction: column; gap: 18px;">
<div id="t-bar" style="display: flex; gap: 2px; height: 14px;">"#,
        tot = fmt_tokens(st.total.sum()),
    );
    let n = st.by_provider.len();
    for (i, (p, t)) in st.by_provider.iter().enumerate() {
        let w = t.sum() as f64 * 100.0 / total as f64;
        let radius = match (i == 0, i + 1 == n) {
            (true, true) => "3px",
            (true, false) => "3px 0 0 3px",
            (false, true) => "0 3px 3px 0",
            _ => "0",
        };
        tool_segment(
            h,
            &format!("{w:.1}"),
            provider_color(p),
            radius,
            &esc(provider_name(p)),
            &format!("{w:.0}"),
        );
    }
    h.push_str("</div>\n<div id=\"t-legend\" class=\"mono\" style=\"display: flex; gap: 24px; font-size: 11px; color: var(--muted);\">");
    for (p, t) in &st.by_provider {
        tool_legend(
            h,
            provider_color(p),
            &esc(provider_name(p)),
            &format!("{:.0}", t.sum() as f64 * 100.0 / total as f64),
        );
    }
    h.push_str(
        r#"</div>
<div style="height: 1px; background: var(--track);"></div>
<div style="display: flex; flex-direction: column; gap: 14px;">
<div class="mono" style="display: grid; grid-template-columns: 150px minmax(0,1fr) 110px 90px; gap: 20px; font-size: 10px; letter-spacing: 0.13em; color: var(--meta);">
<span>PROVIDER</span><span>TOKEN MIX</span><span style="text-align: right;">TOKENS</span><span style="text-align: right;">"#,
    );
    h.push_str(if cost_on { "EST. COST" } else { "MESSAGES" });
    h.push_str("</span></div>\n<div id=\"t-rows\" style=\"display: flex; flex-direction: column; gap: 14px;\">\n");
    for (p, t) in &st.by_provider {
        let sum = t.sum();
        let pct = |v: u64| format!("{:.0}", v as f64 * 100.0 / sum.max(1) as f64);
        let last = if cost_on {
            // Priced at the provider×model split — never at a guessed blend.
            fmt_usd_for_models(&st.provider_models(p))
        } else {
            fmt_int(t.messages)
        };
        tool_row(
            h,
            provider_color(p),
            &esc(provider_name(p)),
            [
                &pct(t.cache_read),
                &pct(t.cache_write),
                &pct(t.input),
                &pct(t.output + t.thinking),
            ],
            &fmt_tokens(sum),
            &last,
        );
    }
    h.push_str(
        r#"</div></div>
<div class="mono" style="display: flex; gap: 22px; padding-top: 4px; border-top: 1px solid var(--track); font-size: 11px; color: var(--muted);">
<span style="display: inline-flex; align-items: center; gap: 7px;"><span class="hatch-cr" style="width: 12px; height: 9px; border-radius: 2px;"></span>cache read</span>
<span style="display: inline-flex; align-items: center; gap: 7px;"><span style="width: 12px; height: 9px; border-radius: 2px; background: var(--cache-write);"></span>cache write</span>
<span style="display: inline-flex; align-items: center; gap: 7px;"><span style="width: 12px; height: 9px; border-radius: 2px; background: var(--input);"></span>input</span>
<span style="display: inline-flex; align-items: center; gap: 7px;"><span style="width: 12px; height: 9px; border-radius: 2px; background: var(--output);"></span>output</span>
<span class="spacer"></span>
<span>Grok and Antigravity report no cache-write class.</span>
</div>
</div></div>
"#,
    );
}

fn context_row(h: &mut String, name: &str, pp: &str, color: &str) {
    let _ = write!(
        h,
        r#"<div class="mono" style="display: grid; grid-template-columns: 110px minmax(0,1fr) 48px; gap: 14px; align-items: center; font-size: 11px;">
<span class="dim">{name}</span>
<div style="height: 6px; border-radius: 3px; background: var(--track); overflow: hidden;"><div style="height: 100%; border-radius: 3px; width: {pp}%; background: {color};"></div></div>
<span style="text-align: right;">{pp}%</span>
</div>
"#,
    );
}

fn context_efficiency(h: &mut String, st: &Stats) {
    let Some(pct) = st.total.cache_hit_pct() else {
        return;
    };
    let saved = st
        .total
        .cache_hit_pct()
        .map(|_| fmt_tokens(st.total.cache_read))
        .unwrap_or_default();
    let _ = write!(
        h,
        r#"<div id="sec-context" style="display: flex; flex-direction: column; gap: 14px;">
<div class="row"><h2 class="sec">CONTEXT EFFICIENCY</h2>
<span class="secnote">cache read ÷ (cache read + cache write + input)</span></div>
<div class="card" style="padding: 24px; display: grid; grid-template-columns: 300px minmax(0,1fr); gap: 40px; align-items: center;">
<div style="display: flex; flex-direction: column; gap: 8px;">
<div class="mono" data-k="ctx-pct" style="font-size: 64px; font-weight: 600; letter-spacing: -0.04em; line-height: 1; color: var(--ok);">{pct:.0}%</div>
<div style="font-size: 13px; color: var(--muted); line-height: 1.6;">of the context you sent was served from cache — <span data-k="ctx-saved">{saved}</span> tokens not re-billed at full input price.</div>
</div>
<div style="display: flex; flex-direction: column; gap: 10px;">
<div style="display: flex; gap: 2px; height: 26px;">
<div class="hatch-cr" data-w="ctx-read" style="width: {pct:.0}%; border-radius: 3px 0 0 3px;"></div>
<div data-w="ctx-input" style="width: {rest:.0}%; background: var(--input); border-radius: 0 3px 3px 0;"></div>
</div>
<div class="mono" style="display: flex; justify-content: space-between; font-size: 11px; color: var(--muted);">
<span>cache read <span data-k="ctx-read">{cr}</span></span><span>input <span data-k="ctx-input">{inp}</span></span>
</div>
<div id="c-rows" style="display: flex; flex-direction: column; gap: 7px; padding-top: 8px; border-top: 1px solid var(--track);">
"#,
        pct = pct,
        rest = 100.0 - pct,
        cr = fmt_tokens(st.total.cache_read),
        inp = fmt_tokens(st.total.input),
        saved = saved,
    );
    for (p, t) in &st.by_provider {
        let Some(pp) = t.cache_hit_pct() else {
            continue;
        };
        let color = if pp < 50.0 { c::WARN } else { c::OK };
        context_row(h, &esc(provider_name(p)), &format!("{pp:.0}"), color);
    }
    h.push_str("</div></div></div></div>\n");
}

fn hot_zones_and_models(h: &mut String, st: &Stats) {
    if st.projects.is_empty() {
        return;
    }
    let total = st.total.sum().max(1);
    let top_p: Vec<_> = st.projects.iter().take(6).collect();
    let rest_p: u64 = st.projects.iter().skip(6).map(|(_, t)| t.sum()).sum();
    let max_p = top_p.first().map(|(_, t)| t.sum()).unwrap_or(1).max(1);
    h.push_str(
        r#"<div class="grid2">
<div style="display: flex; flex-direction: column; gap: 14px;">
<h2 class="sec">PROJECT HOT ZONES</h2>
<div class="card" style="padding: 20px 24px; display: flex; flex-direction: column; gap: 12px;">
<div id="p-rows" style="display: flex; flex-direction: column; gap: 12px;">
"#,
    );
    let row = |h: &mut String, name: &str, tokens: u64, dimmed: bool| {
        project_row(
            h,
            &esc(name),
            &format!("{:.0}", tokens as f64 * 100.0 / max_p as f64),
            &format!("{:.0}", tokens as f64 * 100.0 / total as f64),
            &fmt_tokens(tokens),
            if dimmed { "var(--meta)" } else { "var(--text)" },
            if dimmed {
                "var(--cache-read)"
            } else {
                "var(--input)"
            },
        )
    };
    for (name, t) in &top_p {
        row(h, name, t.sum(), false);
    }
    if rest_p > 0 {
        let n = st.projects.len() - top_p.len();
        row(h, &format!("{n} others"), rest_p, true);
    }
    h.push_str(
        r#"</div>
<div style="font-size: 12px; color: var(--meta); padding-top: 6px; border-top: 1px solid var(--track);"><span class="mono" style="color: var(--muted);">Mask projects</span> hides names on screen only; this file still contains them. To share a report, write one with <span class="mono" style="color: var(--muted);">tickover stats --report --mask</span>.</div>
</div></div>
<div style="display: flex; flex-direction: column; gap: 14px;">
<h2 class="sec">MOST-USED MODELS</h2>
<div id="m-rows" class="card" style="padding: 20px 24px; display: flex; flex-direction: column; gap: 12px;">
"#,
    );
    let max_m = st.models.first().map(|(_, t)| t.sum()).unwrap_or(1).max(1);
    for (m, t) in st.models.iter().take(6) {
        let w = t.sum() as f64 * 100.0 / max_m as f64;
        model_row(h, &esc(m), &fmt_tokens(t.sum()), &format!("{w:.0}"));
    }
    h.push_str("</div></div></div>\n");
}

fn model_row(h: &mut String, m: &str, v: &str, w: &str) {
    let _ = write!(
        h,
        r#"<div style="display: flex; flex-direction: column; gap: 5px;">
<div class="mono" style="display: flex; justify-content: space-between; align-items: baseline; font-size: 12px;">
<span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{m}</span>
<span style="color: var(--muted); padding-left: 12px;">{v}</span>
</div>
<div class="bar-track" style="height: 8px;"><div class="bar-fill" style="width: {w}%;"></div></div>
</div>
"#,
    );
}

fn project_row(h: &mut String, name: &str, w: &str, share: &str, v: &str, color: &str, fill: &str) {
    let _ = write!(
        h,
        r#"<div style="display: grid; grid-template-columns: 150px minmax(0,1fr) 76px 54px; gap: 16px; align-items: center;">
<span class="mono proj" data-name="{name}" style="font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: {color};">{name}</span>
<div class="bar-track"><div class="bar-fill" style="width: {w}%; background: {fill};"></div></div>
<span class="mono" style="font-size: 12px; text-align: right; color: var(--text);">{v}</span>
<span class="mono" style="font-size: 11px; text-align: right; color: var(--meta);">{share}%</span>
</div>
"#,
    );
}

/// Weekly totals (Mon-start) for the burn trail — derived from the
/// heatmap data (which is Sun-start, so regroup by ISO week).
fn weekly_series(st: &Stats) -> Vec<(chrono::NaiveDate, u64)> {
    use std::collections::BTreeMap;
    let mut weeks: BTreeMap<chrono::NaiveDate, u64> = BTreeMap::new();
    for row in &st.heatmap {
        for (d, v) in row {
            let monday = *d - chrono::Duration::days(d.weekday().num_days_from_monday() as i64);
            *weeks.entry(monday).or_default() += v;
        }
    }
    // Quiet weeks inside the span stay, flat at zero; the heatmap's empty run
    // before the first week of use and after the last is not part of it.
    let mut series: Vec<_> = weeks.into_iter().collect();
    while series.last().is_some_and(|(_, v)| *v == 0) {
        series.pop();
    }
    let first = series.iter().position(|(_, v)| *v > 0).unwrap_or(0);
    series.split_off(first)
}

fn weekly_trail(h: &mut String, st: &Stats) {
    let weeks = weekly_series(st);
    if weeks.is_empty() {
        return;
    }
    const W: f64 = 1072.0;
    const H: f64 = 180.0;
    const TOP: f64 = 20.0;
    const BASE: f64 = 160.0;
    let max = weeks.iter().map(|(_, v)| *v).max().unwrap_or(1).max(1) as f64;
    let n = weeks.len().max(2) as f64;
    let x = |i: usize| i as f64 / (n - 1.0) * W;
    let y = |v: u64| BASE - (v as f64 / max) * (BASE - TOP);
    let mut pts = String::new();
    let mut area = format!("M0,{BASE} ");
    for (i, (_, v)) in weeks.iter().enumerate() {
        let _ = write!(pts, "{:.1},{:.1} ", x(i), y(*v));
        let _ = write!(area, "L{:.1},{:.1} ", x(i), y(*v));
    }
    let _ = write!(area, "L{W:.0},{BASE} Z");
    // Peak week gets the dashed marker + tooltip, like the mock.
    let (peak_i, (peak_w, peak_v)) = weeks
        .iter()
        .enumerate()
        .max_by_key(|(_, (_, v))| *v)
        .map(|(i, (d, v))| (i, (*d, *v)))
        .unwrap_or((0, (chrono::Local::now().date_naive(), 0)));
    let _ = write!(
        h,
        r#"<div style="display: flex; flex-direction: column; gap: 14px;">
<div class="row"><h2 class="sec">WEEKLY BURN TRAIL</h2>
<span class="secnote" data-k="tr-note">tokens per week, {n} weeks</span></div>
<div class="card" style="padding: 22px 24px 16px; display: flex; flex-direction: column; gap: 10px; position: relative;">
<svg id="tr-svg" viewBox="0 0 {W:.0} {H:.0}" width="100%" role="img" aria-label="Weekly token totals, peaking at {peak_fmt} the week of {peak_date}.">
<line x1="0" y1="{TOP}" x2="{W}" y2="{TOP}" stroke="var(--track)" stroke-width="1"></line>
<line x1="0" y1="70" x2="{W}" y2="70" stroke="var(--track)" stroke-width="1"></line>
<line x1="0" y1="120" x2="{W}" y2="120" stroke="var(--track)" stroke-width="1"></line>
<line x1="0" y1="{BASE}" x2="{W}" y2="{BASE}" stroke="var(--hairline)" stroke-width="1"></line>
<path id="tr-area" d="{area}" fill="var(--ok)" fill-opacity="0.10"></path>
<polyline id="tr-line" points="{pts}" fill="none" stroke="var(--ok)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"></polyline>
<line id="tr-mark" x1="{px:.0}" y1="{TOP}" x2="{px:.0}" y2="{BASE}" stroke="var(--muted)" stroke-width="1" stroke-dasharray="3 3"></line>
<circle id="tr-dot" cx="{px:.0}" cy="{py:.1}" r="5" fill="var(--ok)" stroke="var(--surface)" stroke-width="2"><title>week of {peak_date} — {peak_fmt} tokens</title></circle>
</svg>
<div class="mono" style="display: flex; justify-content: space-between; font-size: 10px; color: var(--meta);">
<span data-k="tr-first">{first}</span><span data-k="tr-last">{last}</span>
</div>
</div></div>
"#,
        W = W as u32,
        H = H as u32,
        TOP = TOP,
        BASE = BASE,
        n = weeks.len(),
        area = area,
        pts = pts.trim(),
        px = x(peak_i),
        py = y(peak_v),
        peak_fmt = fmt_tokens(peak_v),
        peak_date = peak_w.format("%d %b %Y"),
        first = weeks
            .first()
            .map(|(d, _)| d.format("%b %Y").to_string())
            .unwrap_or_default(),
        last = weeks
            .last()
            .map(|(d, _)| d.format("%b %Y").to_string())
            .unwrap_or_default(),
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
        r#"<div style="display: flex; flex-direction: column; gap: 14px;">
<div class="row"><h2 class="sec">52 WEEKS</h2>
<span class="secnote">{active} active days · current streak {streak} · all history, whatever the period</span></div>
<div class="card" style="padding: 22px 24px; display: flex; flex-direction: column; gap: 12px;">
<div style="display: flex; gap: 12px; align-items: flex-start;">
<div class="mono" style="display: flex; flex-direction: column; gap: 3px; font-size: 9px; color: var(--meta); padding-top: 1px;">
<span style="height: 12px; line-height: 12px;">Sun</span><span style="height: 12px; line-height: 12px;">Mon</span><span style="height: 12px;"></span><span style="height: 12px; line-height: 12px;">Wed</span><span style="height: 12px;"></span><span style="height: 12px; line-height: 12px;">Fri</span><span style="height: 12px;"></span>
</div>
<div style="display: grid; grid-auto-flow: column; grid-template-rows: repeat(7, 12px); grid-auto-columns: 12px; gap: 3px;">
"#,
        streak = st.streak_days,
    );
    // Column-major order: `grid-auto-flow: column` fills row-by-row per
    // column, so emit day-by-day within each week row.
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
    h.push_str("</div></div>\n");
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
</div></div>
"#
    );
}

fn habits_and_sessions(h: &mut String, st: &Stats, cost_on: bool) {
    let max_h = st.active_hours.iter().copied().max().unwrap_or(1).max(1);
    let total = st.active_hours.iter().sum::<u64>().max(1);
    let peak_h = st
        .active_hours
        .iter()
        .enumerate()
        .max_by_key(|(_, v)| *v)
        .map(|(i, _)| i)
        .unwrap_or(0);
    let peak_share = st.active_hours[peak_h] as f64 * 100.0 / total as f64;
    h.push_str(
        r#"<div class="grid2e">
<div style="display: flex; flex-direction: column; gap: 14px;">
<div class="row"><h2 class="sec">USAGE HABITS</h2>
<span class="secnote">tokens by hour, local time</span></div>
<div class="card" style="padding: 22px 24px 16px; display: flex; flex-direction: column; gap: 10px;">
<div style="display: flex; align-items: flex-end; gap: 4px; height: 130px;">
"#,
    );
    for (hr, v) in st.active_hours.iter().enumerate() {
        let px = (*v as f64 / max_h as f64 * 124.0).max(3.0);
        let _ = write!(
            h,
            r#"<div data-hr="{hr}" title="{hr:02}:00 — {v}" style="flex-grow:1;height:{px:.0}px;border-radius:3px 3px 0 0;background:{habit};"></div>"#,
            habit = c::HABIT,
            v = fmt_tokens(*v),
        );
    }
    let _ = write!(
        h,
        r#"</div>
<div class="mono" style="display: flex; justify-content: space-between; font-size: 10px; color: var(--meta);">
<span>00</span><span>06</span><span>12</span><span>18</span><span>23</span>
</div>
<div style="font-size: 12px; color: var(--muted); padding-top: 6px; border-top: 1px solid var(--track);">Peak hour <span class="mono" data-k="hb-peak" style="color: var(--text);">{peak_h:02}:00</span> — <span data-k="hb-share">{peak_share:.0}</span>% of everything you burned.</div>
</div></div>
<div style="display: flex; flex-direction: column; gap: 14px;">
<div class="row"><h2 class="sec">TOP BURN SESSIONS</h2>
<span class="secnote" data-k="s-note">single sessions, all time</span></div>
<div class="card" style="padding: 20px 24px; display: flex; flex-direction: column; gap: 11px;">
<div class="mono" style="display: grid; grid-template-columns: 26px minmax(0,1fr) 74px 66px 62px; gap: 12px; font-size: 10px; letter-spacing: 0.13em; color: var(--meta);">
<span>#</span><span>PROJECT · DATE</span><span style="text-align: right;">LENGTH</span><span style="text-align: right;">TOKENS</span><span style="text-align: right;">COST</span>
</div>
<div id="s-rows" style="display: flex; flex-direction: column; gap: 11px;">
"#
    );
    for (i, s) in st.sessions.iter().take(5).enumerate() {
        let span = session_span(&s.first_hour, &s.last_hour);
        // The local day, like the period that selects this session: the
        // stored hour is UTC, and can sit on the far side of midnight.
        let date = query::parse_bucket_hour(&s.first_hour)
            .map(|h| h.with_timezone(&Local).format("%d %b %Y").to_string())
            .unwrap_or_else(|| s.first_hour.clone());
        let cost = if cost_on {
            // Priced per model the session actually used, never a guessed
            // blend at whichever model its first bucket happened to log.
            let models: Vec<(String, Totals)> =
                s.models.iter().map(|(m, t)| (m.clone(), *t)).collect();
            fmt_usd_for_models(&models)
        } else {
            "—".into()
        };
        session_row(
            h,
            &(i + 1).to_string(),
            &esc(&s.project),
            &date,
            &esc(provider_name(&s.provider)),
            &span,
            &fmt_tokens(s.totals.sum()),
            &cost,
        );
    }
    h.push_str("</div></div></div></div>\n");
}

#[allow(clippy::too_many_arguments)] // Eight cells, each already a string.
fn session_row(
    h: &mut String,
    i: &str,
    proj: &str,
    date: &str,
    prov: &str,
    span: &str,
    tok: &str,
    cost: &str,
) {
    let _ = write!(
        h,
        r#"<div style="display: grid; grid-template-columns: 26px minmax(0,1fr) 74px 66px 62px; gap: 12px; align-items: baseline; padding-bottom: 9px; border-bottom: 1px solid var(--track-soft);">
<span class="mono" style="font-size: 12px; color: var(--meta);">{i}</span>
<span style="display: flex; flex-direction: column; gap: 2px; min-width: 0;">
<span class="mono proj" data-name="{proj}" style="font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{proj}</span>
<span style="font-size: 11px; color: var(--meta);">{date} · {prov}</span>
</span>
<span class="mono" style="font-size: 12px; text-align: right; color: var(--muted);">{span}</span>
<span class="mono" style="font-size: 12px; text-align: right;">{tok}</span>
<span class="mono" style="font-size: 12px; text-align: right; color: var(--muted);">{cost}</span>
</div>
"#,
    );
}

/// `"YYYY-MM-DDTHH"` × 2 → "6h 41m"-ish label (hours only — buckets are
/// hour-granular, so minutes would be invented precision).
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
/// cache-read price — an estimate of an estimate, so it is printed with `≈`.
/// A model this table can't price contributes nothing to the sum, silently,
/// unless it actually read from cache; the second value says so.
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

fn wrapped(h: &mut String, st: &Stats, cost_on: bool) {
    if st.providers.is_empty() {
        return;
    }
    let busiest = st
        .daily
        .iter()
        .max_by_key(|(_, t)| t.sum())
        .map(|(d, t)| format!("{} — {}", d.format("%d %b"), fmt_tokens(t.sum())))
        .unwrap_or_else(|| "—".into());
    let top_model = st
        .models
        .first()
        .map(|(m, _)| m.clone())
        .unwrap_or_default();
    let top_proj = st
        .projects
        .first()
        .map(|(p, _)| p.clone())
        .unwrap_or_default();
    let saved_row = if cost_on {
        let (approx, any_unpriced_with_reads) = cache_saved(&st.models);
        let marker = if any_unpriced_with_reads { "*" } else { "" };
        format!(
            r#"<div style="display: flex; justify-content: space-between; align-items: baseline; padding: 11px 0; border-bottom: 1px solid var(--track);">
<span class="mono" style="font-size: 10px; letter-spacing: 0.13em; color: var(--meta);">SAVED BY CACHE</span>
<span class="mono" data-k="w-saved" style="font-size: 14px;">≈ {}{marker}</span>
</div>"#,
            fmt_usd(Some(approx))
        )
    } else {
        String::new()
    };
    let _ = write!(
        h,
        r#"<div class="card" style="border-color: var(--hairline); border-radius: 14px; padding: 36px 40px; display: grid; grid-template-columns: minmax(0,1fr) 380px; gap: 48px; align-items: center;">
<div style="display: flex; flex-direction: column; gap: 14px;">
<span class="mono" data-k="w-label" style="font-size: 11px; letter-spacing: 0.22em; color: var(--ok);">SO FAR</span>
<div class="mono" data-k="w-total" style="font-size: 76px; font-weight: 600; letter-spacing: -0.045em; line-height: 0.95;">{total}</div>
<p style="margin: 0; font-size: 15px; color: var(--muted); line-height: 1.65; max-width: 480px;">tokens through your assistants on this machine, across <span data-k="w-days" style="color: var(--text);">{days}</span>.</p>
</div>
<div style="display: flex; flex-direction: column;">
<div style="display: flex; justify-content: space-between; align-items: baseline; padding: 11px 0; border-bottom: 1px solid var(--track);">
<span class="mono" style="font-size: 10px; letter-spacing: 0.13em; color: var(--meta);">CURRENT STREAK</span>
<span class="mono" style="font-size: 14px;">{streak} days</span>
</div>
<div style="display: flex; justify-content: space-between; align-items: baseline; padding: 11px 0; border-bottom: 1px solid var(--track);">
<span class="mono" style="font-size: 10px; letter-spacing: 0.13em; color: var(--meta);">BUSIEST DAY</span>
<span class="mono" data-k="w-busiest" style="font-size: 14px;">{busiest}</span>
</div>
<div style="display: flex; justify-content: space-between; align-items: baseline; padding: 11px 0; border-bottom: 1px solid var(--track);">
<span class="mono" style="font-size: 10px; letter-spacing: 0.13em; color: var(--meta);">TOP MODEL</span>
<span class="mono" data-k="w-model" style="font-size: 14px;">{top_model}</span>
</div>
<div style="display: flex; justify-content: space-between; align-items: baseline; padding: 11px 0; border-bottom: 1px solid var(--track);">
<span class="mono" style="font-size: 10px; letter-spacing: 0.13em; color: var(--meta);">TOP PROJECT</span>
<span class="mono proj" data-k="w-project" data-name="{top_proj_esc}" style="font-size: 14px;">{top_proj}</span>
</div>
{saved_row}
</div>
</div>
"#,
        total = fmt_tokens(st.total.sum()),
        days = active_days_label(st.active_days),
        streak = st.streak_days,
        top_model = esc(&top_model),
        top_proj = esc(&top_proj),
        top_proj_esc = esc(&top_proj),
    );
}

fn footer(h: &mut String, sources: &[String]) {
    let srcs = if sources.is_empty() {
        "local history files".to_string()
    } else {
        sources
            .iter()
            .map(|s| format!(r#"<span class="mono">{}</span>"#, esc(s)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let _ = write!(
        h,
        r#"<div style="padding: 8px 0 44px; display: flex; gap: 40px; border-top: 1px solid var(--track);">
<div style="max-width: 560px; font-size: 12px; color: var(--meta); line-height: 1.7; padding-top: 14px;">
Generated {now} by tickover {ver}. Read from {srcs}. Duplicate message ids removed; Codex cumulative counters differenced. Claude sub-agent turns count once, from their own transcript file.
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

    /// One session's bucket for a given model — round numbers throughout
    /// so the rendered dollar figures land on exact cent/dollar strings,
    /// not ones a test would have to fight floating rounding to match.
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
        // The page alone: the script spells out every caption it might
        // write, which would satisfy any assertion about what is showing.
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
            .append_days(&[day(&hour, "claude-sonnet-4", 500_000)])
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
        assert!(texts.len() > 20, "{texts:?}");
        for key in texts {
            assert!(html.contains(&format!("data-k=\"{key}\"")), "data-k {key}");
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
        for hole in ["@w@", "@name@", "@tok@", "@proj@", "@pp@", "@m@"] {
            assert!(html.contains(hole), "{hole}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_report_with_cost_on_marks_every_partial_sum() {
        // One session, one provider, two models: one this table prices
        // ("claude-sonnet-4"), one it does not ("mystery-model-x", which
        // also reads from cache so the cache-savings row mixes too).
        let dir = tmpdir("report-partial-cost");
        let mut store = HistoryStore::open(&dir).unwrap();
        let hour = chrono::Utc::now().format("%Y-%m-%dT%H").to_string();
        store
            .append_days(&[
                day(&hour, "claude-sonnet-4", 0),
                day(&hour, "mystery-model-x", 500_000),
            ])
            .unwrap();
        store.commit().unwrap();
        let store = HistoryStore::open(&dir).unwrap();
        let enabled: std::collections::HashSet<String> =
            ["claude".to_string()].into_iter().collect();
        let st = query::compute(&store, 30, &enabled);

        let html = render_for(&store, &st, &enabled);

        // Headline EST. COST: only "claude-sonnet-4" prices (3.0 + 15.0
        // per 1M at its own rate = $18), and the caption says so.
        assert!(html.contains("$18*"), "headline must mark the partial sum");
        assert!(
            html.contains("at list price, partial — unpriced models excluded"),
            "headline caption must name the exclusion"
        );
        // Per-provider row and session row sum the same two models —
        // both must carry the same marker.
        assert!(
            html.contains("$18.00*"),
            "the per-provider and per-session cost cells must be marked"
        );
        // SAVED BY CACHE: only the unpriced model has cache reads, so the
        // estimate is $0 with nothing to add — still marked, since that
        // $0 is not "no savings", it is "unknown savings".
        assert!(
            html.contains("≈ $0*"),
            "the cache-savings row must be marked when only an unpriced model read from cache"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_report_with_cost_on_and_one_priced_model_carries_no_marker() {
        let dir = tmpdir("report-full-cost");
        let mut store = HistoryStore::open(&dir).unwrap();
        let hour = chrono::Utc::now().format("%Y-%m-%dT%H").to_string();
        store
            .append_days(&[day(&hour, "claude-sonnet-4", 0)])
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
            "a fully priced sum must not be marked"
        );
        assert!(
            !html.contains("partial"),
            "no caption should mention partial coverage"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
