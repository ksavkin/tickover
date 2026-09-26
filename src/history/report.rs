//! Self-contained HTML usage report — `tickover stats --report`.
//!
//! One file, no network, no external assets: CSS is a `<style>` block,
//! charts are inline SVG/CSS, the only script is a few lines for the
//! project-name mask and theme toggles. Dark is default; light follows
//! `prefers-color-scheme` and the toggle. The file is written `0600` —
//! project basenames are still sensitive enough for that.
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
use crate::history::query::{Stats, Totals};

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

fn provider_color(id: &str) -> &'static str {
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
fn provider_name(id: &str) -> &str {
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

fn fmt_tokens(n: u64) -> String {
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

fn fmt_int(n: u64) -> String {
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

fn fmt_usd(v: Option<f64>) -> String {
    match v {
        Some(x) if x >= 100.0 => format!("${:.0}", x),
        Some(x) if x >= 1.0 => format!("${:.2}", x),
        Some(x) if x > 0.0 => format!("${:.3}", x),
        Some(_) => "$0".into(),
        None => "—".into(),
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
    let html = render(st, cost_on, quota, sources);
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

fn render(st: &Stats, cost_on: bool, quota: &[QuotaNow], sources: &[String]) -> String {
    let mut h = String::with_capacity(48 * 1024);
    h.push_str(HEAD);
    topbar(&mut h);
    title(&mut h, st);
    if !quota.is_empty() {
        right_now(&mut h, quota);
    }
    headline(&mut h, st, cost_on);
    coverage(&mut h, st);
    tools(&mut h, st, cost_on);
    context_efficiency(&mut h, st);
    hot_zones_and_models(&mut h, st);
    weekly_trail(&mut h, st);
    heatmap(&mut h, st);
    habits_and_sessions(&mut h, st, cost_on);
    wrapped(&mut h, st, cost_on);
    footer(&mut h, sources);
    h.push_str("</div></div>\n</body>\n</html>\n");
    h
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
@media (max-width: 720px) {
  .shell { padding: 0 16px; gap: 28px; }
  .topbar { padding: 0 16px; }
  .grid2, .grid3, .grid6 { grid-template-columns: 1fr !important; }
}
@media print {
  body { background: #fff; }
  .topbar { position: static; }
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
<p style="margin: 0; color: var(--muted); font-size: 14px; max-width: 720px; line-height: 1.6;">{range}, read from CLI history files on this machine. Nothing was uploaded; this file has no network calls and no external assets.</p>
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
        let v = pricing::cost_for_models(&models);
        (
            "EST. COST".to_string(),
            v.map(|x| {
                if x >= 1000.0 {
                    format!("${:.1}K", x / 1000.0)
                } else {
                    format!("${x:.0}")
                }
            })
            .unwrap_or_else(|| "—".into()),
            "at list price".to_string(),
        )
    } else {
        (
            "THIS WEEK".to_string(),
            fmt_tokens(st.week.sum()),
            "tokens, Mon → today".to_string(),
        )
    };
    let cards = [
        (
            "TOKENS".to_string(),
            fmt_tokens(st.total.sum()),
            "in + out + cache".to_string(),
        ),
        cost_card,
        (
            "SESSIONS".to_string(),
            fmt_int(sessions),
            format!("{active_days} active days"),
        ),
        (
            "MESSAGES".to_string(),
            fmt_int(st.total.messages),
            format!("{msgs_per_day} / active day"),
        ),
        (
            "AVG / MESSAGE".to_string(),
            fmt_tokens(avg_msg),
            "across all providers".to_string(),
        ),
        ("CACHE HIT".to_string(), cache, "context reused".to_string()),
    ];
    h.push_str(r#"<div class="grid6">"#);
    for (label, value, note) in cards {
        let _ = write!(
            h,
            r#"<div class="card" style="padding: 16px 18px; display: flex; flex-direction: column; gap: 6px;">
<div class="mono" style="font-size: 10px; letter-spacing: 0.13em; color: var(--meta);">{label}</div>
<div class="mono" style="font-size: 24px; font-weight: 600; letter-spacing: -0.025em; line-height: 1.1;">{value}</div>
<div style="font-size: 11px; color: var(--muted);">{note}</div>
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

/// The 4-class token mix bar used in "YOUR TOOLS" rows.
fn mix_bar(h: &mut String, t: &Totals) {
    let total = t.sum();
    if total == 0 {
        h.push_str(r#"<div class="hatch-none" style="width:100%;height:10px;"></div>"#);
        return;
    }
    let pct = |v: u64| v as f64 * 100.0 / total as f64;
    h.push_str(r#"<div style="display: flex; gap: 2px; height: 10px;">"#);
    let _ = write!(
        h,
        r#"<div class="hatch-cr" style="width:{:.0}%;border-radius:2px 0 0 2px;"></div><div style="width:{:.0}%;background:var(--cache-write);"></div><div style="width:{:.0}%;background:var(--input);"></div><div style="width:{:.0}%;background:var(--output);border-radius:0 2px 2px 0;"></div></div>"#,
        pct(t.cache_read),
        pct(t.cache_write),
        pct(t.input),
        pct(t.output + t.thinking),
    );
}

fn tools(h: &mut String, st: &Stats, cost_on: bool) {
    let total = st.total.sum().max(1);
    let _ = write!(
        h,
        r#"<div style="display: flex; flex-direction: column; gap: 14px;">
<div class="row"><h2 class="sec">YOUR TOOLS</h2>
<span class="secnote">share of {tot} tokens</span></div>
<div class="card" style="padding: 22px 24px 20px; display: flex; flex-direction: column; gap: 18px;">
<div style="display: flex; gap: 2px; height: 14px;">"#,
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
        let _ = write!(
            h,
            r#"<div style="width: {w:.1}%; background: {c}; border-radius: {radius};" title="{name} {w:.0}%"></div>"#,
            c = provider_color(p),
            name = esc(provider_name(p)),
        );
    }
    h.push_str("</div>\n<div class=\"mono\" style=\"display: flex; gap: 24px; font-size: 11px; color: var(--muted);\">");
    for (p, t) in &st.by_provider {
        let _ = write!(
            h,
            r#"<span style="display: inline-flex; align-items: center; gap: 7px;"><span style="width: 9px; height: 9px; border-radius: 2px; background: {c};"></span><span style="color: var(--text);">{name}</span> {w:.0}%</span>"#,
            c = provider_color(p),
            name = esc(provider_name(p)),
            w = t.sum() as f64 * 100.0 / total as f64,
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
    h.push_str("</span></div>\n");
    for (p, t) in &st.by_provider {
        let _ = write!(
            h,
            r#"<div style="display: grid; grid-template-columns: 150px minmax(0,1fr) 110px 90px; gap: 20px; align-items: center;">
<span class="mono" style="display: inline-flex; align-items: center; gap: 8px; font-size: 12px;"><span style="width: 9px; height: 9px; border-radius: 2px; background: {c};"></span>{name}</span>
"#,
            c = provider_color(p),
            name = esc(provider_name(p)),
        );
        mix_bar(h, t);
        let _ = write!(
            h,
            r#"<span class="mono" style="font-size: 12px; text-align: right; color: var(--text);">{}</span>"#,
            fmt_tokens(t.sum())
        );
        if cost_on {
            // Priced at the provider×model split — never at a guessed blend.
            let usd = pricing::cost_for_models(&st.provider_models(p));
            let _ = write!(
                h,
                r#"<span class="mono" style="font-size: 12px; text-align: right; color: var(--text);">{}</span>"#,
                fmt_usd(usd)
            );
        } else {
            let _ = write!(
                h,
                r#"<span class="mono" style="font-size: 12px; text-align: right; color: var(--text);">{}</span>"#,
                fmt_int(t.messages)
            );
        }
        h.push_str("</div>\n");
    }
    h.push_str(
        r#"</div>
<div class="mono" style="display: flex; gap: 22px; padding-top: 4px; border-top: 1px solid var(--track); font-size: 11px; color: var(--muted);">
<span style="display: inline-flex; align-items: center; gap: 7px;"><span class="hatch-cr" style="width: 12px; height: 9px; border-radius: 2px;"></span>cache read</span>
<span style="display: inline-flex; align-items: center; gap: 7px;"><span style="width: 12px; height: 9px; border-radius: 2px; background: var(--cache-write);"></span>cache write</span>
<span style="display: inline-flex; align-items: center; gap: 7px;"><span style="width: 12px; height: 9px; border-radius: 2px; background: var(--input);"></span>input</span>
<span style="display: inline-flex; align-items: center; gap: 7px;"><span style="width: 12px; height: 9px; border-radius: 2px; background: var(--output);"></span>output</span>
<span class="spacer"></span>
<span>Codex reports no cache-write class; Antigravity folds reasoning into output.</span>
</div>
</div></div>
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
        r#"<div style="display: flex; flex-direction: column; gap: 14px;">
<div class="row"><h2 class="sec">CONTEXT EFFICIENCY</h2>
<span class="secnote">cache read ÷ (cache read + input)</span></div>
<div class="card" style="padding: 24px; display: grid; grid-template-columns: 300px minmax(0,1fr); gap: 40px; align-items: center;">
<div style="display: flex; flex-direction: column; gap: 8px;">
<div class="mono" style="font-size: 64px; font-weight: 600; letter-spacing: -0.04em; line-height: 1; color: var(--ok);">{pct:.0}%</div>
<div style="font-size: 13px; color: var(--muted); line-height: 1.6;">of the context you sent was served from cache — {saved} tokens not re-billed at full input price.</div>
</div>
<div style="display: flex; flex-direction: column; gap: 10px;">
<div style="display: flex; gap: 2px; height: 26px;">
<div class="hatch-cr" style="width: {pct:.0}%; border-radius: 3px 0 0 3px;"></div>
<div style="width: {rest:.0}%; background: var(--input); border-radius: 0 3px 3px 0;"></div>
</div>
<div class="mono" style="display: flex; justify-content: space-between; font-size: 11px; color: var(--muted);">
<span>cache read {cr}</span><span>input {inp}</span>
</div>
<div style="display: flex; flex-direction: column; gap: 7px; padding-top: 8px; border-top: 1px solid var(--track);">
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
        let _ = write!(
            h,
            r#"<div class="mono" style="display: grid; grid-template-columns: 110px minmax(0,1fr) 48px; gap: 14px; align-items: center; font-size: 11px;">
<span class="dim">{name}</span>
<div style="height: 6px; border-radius: 3px; background: var(--track); overflow: hidden;"><div style="height: 100%; border-radius: 3px; width: {pp:.0}%; background: {color};"></div></div>
<span style="text-align: right;">{pp:.0}%</span>
</div>
"#,
            name = esc(provider_name(p)),
        );
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
"#,
    );
    for (name, t) in &top_p {
        project_row(h, name, t.sum(), max_p, total, false);
    }
    if rest_p > 0 {
        let n = st.projects.len() - top_p.len();
        project_row(h, &format!("{n} others"), rest_p, max_p, total, true);
    }
    h.push_str(
        r#"<div style="font-size: 12px; color: var(--meta); padding-top: 6px; border-top: 1px solid var(--track);">Turn on <span class="mono" style="color: var(--muted);">Mask projects</span> before sharing — names become project-1, project-2.</div>
</div></div>
<div style="display: flex; flex-direction: column; gap: 14px;">
<h2 class="sec">MOST-USED MODELS</h2>
<div class="card" style="padding: 20px 24px; display: flex; flex-direction: column; gap: 12px;">
"#,
    );
    let max_m = st.models.first().map(|(_, t)| t.sum()).unwrap_or(1).max(1);
    for (m, t) in st.models.iter().take(6) {
        let w = t.sum() as f64 * 100.0 / max_m as f64;
        let _ = write!(
            h,
            r#"<div style="display: flex; flex-direction: column; gap: 5px;">
<div class="mono" style="display: flex; justify-content: space-between; align-items: baseline; font-size: 12px;">
<span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{m}</span>
<span style="color: var(--muted); padding-left: 12px;">{v}</span>
</div>
<div class="bar-track" style="height: 8px;"><div class="bar-fill" style="width: {w:.0}%;"></div></div>
</div>
"#,
            m = esc(m),
            v = fmt_tokens(t.sum()),
        );
    }
    h.push_str("</div></div></div>\n");
}

fn project_row(h: &mut String, name: &str, tokens: u64, max: u64, total: u64, dimmed: bool) {
    let w = tokens as f64 * 100.0 / max as f64;
    let share = tokens as f64 * 100.0 / total as f64;
    let color = if dimmed { "var(--meta)" } else { "var(--text)" };
    let fill = if dimmed {
        "var(--cache-read)"
    } else {
        "var(--input)"
    };
    let _ = write!(
        h,
        r#"<div style="display: grid; grid-template-columns: 150px minmax(0,1fr) 76px 54px; gap: 16px; align-items: center;">
<span class="mono proj" data-name="{name}" style="font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: {color};">{name}</span>
<div class="bar-track"><div class="bar-fill" style="width: {w:.0}%; background: {fill};"></div></div>
<span class="mono" style="font-size: 12px; text-align: right; color: var(--text);">{v}</span>
<span class="mono" style="font-size: 11px; text-align: right; color: var(--meta);">{share:.0}%</span>
</div>
"#,
        name = esc(name),
        v = fmt_tokens(tokens),
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
    weeks.into_iter().collect()
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
<span class="secnote">tokens per week, {n} weeks</span></div>
<div class="card" style="padding: 22px 24px 16px; display: flex; flex-direction: column; gap: 10px; position: relative;">
<svg viewBox="0 0 {W:.0} {H:.0}" width="100%" role="img" aria-label="Weekly token totals, peaking at {peak_fmt} the week of {peak_date}.">
<line x1="0" y1="{TOP}" x2="{W}" y2="{TOP}" stroke="var(--track)" stroke-width="1"></line>
<line x1="0" y1="70" x2="{W}" y2="70" stroke="var(--track)" stroke-width="1"></line>
<line x1="0" y1="120" x2="{W}" y2="120" stroke="var(--track)" stroke-width="1"></line>
<line x1="0" y1="{BASE}" x2="{W}" y2="{BASE}" stroke="var(--hairline)" stroke-width="1"></line>
<path d="{area}" fill="var(--ok)" fill-opacity="0.10"></path>
<polyline points="{pts}" fill="none" stroke="var(--ok)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"></polyline>
<line x1="{px:.0}" y1="{TOP}" x2="{px:.0}" y2="{BASE}" stroke="var(--muted)" stroke-width="1" stroke-dasharray="3 3"></line>
<circle cx="{px:.0}" cy="{py:.1}" r="5" fill="var(--ok)" stroke="var(--surface)" stroke-width="2"><title>week of {peak_date} — {peak_fmt} tokens</title></circle>
</svg>
<div class="mono" style="display: flex; justify-content: space-between; font-size: 10px; color: var(--meta);">
<span>{first}</span><span>{last}</span>
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
<span class="secnote">{active} active days · current streak {streak}</span></div>
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
            r#"<div title="{hr:02}:00 — {v}" style="flex-grow:1;height:{px:.0}px;border-radius:3px 3px 0 0;background:{habit};"></div>"#,
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
<div style="font-size: 12px; color: var(--muted); padding-top: 6px; border-top: 1px solid var(--track);">Peak hour <span class="mono" style="color: var(--text);">{peak_h:02}:00</span> — {peak_share:.0}% of everything you burned.</div>
</div></div>
<div style="display: flex; flex-direction: column; gap: 14px;">
<div class="row"><h2 class="sec">TOP BURN SESSIONS</h2>
<span class="secnote">single sessions, all time</span></div>
<div class="card" style="padding: 20px 24px; display: flex; flex-direction: column; gap: 11px;">
<div class="mono" style="display: grid; grid-template-columns: 26px minmax(0,1fr) 74px 66px 62px; gap: 12px; font-size: 10px; letter-spacing: 0.13em; color: var(--meta);">
<span>#</span><span>PROJECT · DATE</span><span style="text-align: right;">LENGTH</span><span style="text-align: right;">TOKENS</span><span style="text-align: right;">COST</span>
</div>
"#
    );
    for (i, s) in st.sessions.iter().take(5).enumerate() {
        let span = session_span(&s.first_hour, &s.last_hour);
        let date = s
            .first_hour
            .get(..10)
            .and_then(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
            .map(|d| d.format("%d %b %Y").to_string())
            .unwrap_or_else(|| s.first_hour.clone());
        let cost = if cost_on {
            fmt_usd(pricing::cost_usd(&s.model, &s.totals))
        } else {
            "—".into()
        };
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
            i = i + 1,
            proj = esc(&s.project),
            prov = esc(provider_name(&s.provider)),
            tok = fmt_tokens(s.totals.sum()),
        );
    }
    h.push_str("</div></div></div>\n");
}

/// `"YYYY-MM-DDTHH"` × 2 → "6h 41m"-ish label (hours only — buckets are
/// hour-granular, so minutes would be invented precision).
fn session_span(first: &str, last: &str) -> String {
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
        let models: Vec<(String, Totals)> = st.models.clone();
        // What the cache saved: those tokens at full input price minus
        // their actual cache-read price. ≈-labelled — it is an estimate
        // of an estimate.
        let approx: f64 = models
            .iter()
            .filter_map(|(m, t)| {
                let as_input = pricing::cost_usd(
                    m,
                    &Totals {
                        input: t.cache_read,
                        ..Totals::default()
                    },
                )?;
                let as_cache = pricing::cost_usd(
                    m,
                    &Totals {
                        cache_read: t.cache_read,
                        ..Totals::default()
                    },
                )?;
                Some(as_input - as_cache)
            })
            .sum();
        format!(
            r#"<div style="display: flex; justify-content: space-between; align-items: baseline; padding: 11px 0; border-bottom: 1px solid var(--track);">
<span class="mono" style="font-size: 10px; letter-spacing: 0.13em; color: var(--meta);">SAVED BY CACHE</span>
<span class="mono" style="font-size: 14px;">≈ {}</span>
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
<span class="mono" style="font-size: 11px; letter-spacing: 0.22em; color: var(--ok);">SO FAR</span>
<div class="mono" style="font-size: 76px; font-weight: 600; letter-spacing: -0.045em; line-height: 0.95;">{total}</div>
<p style="margin: 0; font-size: 15px; color: var(--muted); line-height: 1.65; max-width: 480px;">tokens through your assistants on this machine, across <span style="color: var(--text);">{days}</span> active days.</p>
</div>
<div style="display: flex; flex-direction: column;">
<div style="display: flex; justify-content: space-between; align-items: baseline; padding: 11px 0; border-bottom: 1px solid var(--track);">
<span class="mono" style="font-size: 10px; letter-spacing: 0.13em; color: var(--meta);">CURRENT STREAK</span>
<span class="mono" style="font-size: 14px;">{streak} days</span>
</div>
<div style="display: flex; justify-content: space-between; align-items: baseline; padding: 11px 0; border-bottom: 1px solid var(--track);">
<span class="mono" style="font-size: 10px; letter-spacing: 0.13em; color: var(--meta);">BUSIEST DAY</span>
<span class="mono" style="font-size: 14px;">{busiest}</span>
</div>
<div style="display: flex; justify-content: space-between; align-items: baseline; padding: 11px 0; border-bottom: 1px solid var(--track);">
<span class="mono" style="font-size: 10px; letter-spacing: 0.13em; color: var(--meta);">TOP MODEL</span>
<span class="mono" style="font-size: 14px;">{top_model}</span>
</div>
<div style="display: flex; justify-content: space-between; align-items: baseline; padding: 11px 0; border-bottom: 1px solid var(--track);">
<span class="mono" style="font-size: 10px; letter-spacing: 0.13em; color: var(--meta);">TOP PROJECT</span>
<span class="mono proj" data-name="{top_proj_esc}" style="font-size: 14px;">{top_proj}</span>
</div>
{saved_row}
</div>
</div>
"#,
        total = fmt_tokens(st.total.sum()),
        days = st.active_days,
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
Generated {now} by tickover {ver}. Read from {srcs}. Duplicate message ids removed; Codex cumulative counters differenced. Claude sub-agent turns count once, through their parent session.
</div>
<span class="spacer"></span>
<div class="mono" style="font-size: 11px; color: var(--meta); text-align: right; line-height: 1.8; padding-top: 14px;">file mode 0600<br>no network calls<br>no external assets</div>
</div>
<script>
(function(){{
  var mask=document.getElementById('mask');
  if(mask)mask.addEventListener('change',function(){{
    var i=0,map={{}};
    document.querySelectorAll('.proj').forEach(function(el){{
      var n=el.getAttribute('data-name')||el.textContent;
      if(!(n in map)){{i++;map[n]='project-'+i;}}
      el.textContent=mask.checked?map[n]:(el.getAttribute('data-name')||el.textContent);
      if(!el.getAttribute('data-name'))el.setAttribute('data-name',n);
    }});
  }});
  var th=document.getElementById('theme');
  if(th)th.addEventListener('click',function(){{
    var d=document.documentElement;
    d.classList.toggle('light');d.classList.remove('dark');
    if(!d.classList.contains('light'))d.classList.add('dark');
  }});
}})();
</script>
"#,
        now = Local::now().format("%d %b %Y %H:%M"),
        ver = env!("CARGO_PKG_VERSION"),
    );
}
