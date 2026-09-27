//! `tickover stats` — the CLI face of the history collector.
//!
//! Runs before any GUI setup: arg parsing is the first thing `main` does
//! after the legacy-dir migration, so a `stats` invocation never touches
//! Slint, the tray, or the single-instance lock. Exit code is the return
//! value; all human output goes to stdout, diagnostics to stderr.

use std::io::Write;
use std::path::PathBuf;

use tickover::history::store::HistoryStore;
use tickover::history::{pricing, query};
use tickover::plugin::manifest::PluginManifest;

/// What a well-formed `stats` invocation asks for, `--report`/`--json`'s
/// precedence already resolved: only one of these ever reaches `run`.
/// `--report` (or its `--html` alias) wins over `--json` however the two are
/// ordered on the command line — a report is a file written to disk and
/// opened for a human, the fuller of the two answers, and `--json`'s stdout
/// has nothing to add once that file exists. A caller that wants both would
/// need two separate invocations; this CLI does not attempt to hand back
/// machine-readable output alongside an artifact it already opened.
#[derive(Debug, PartialEq, Eq)]
enum Output {
    Report(Option<PathBuf>),
    Json,
    Text,
}

/// `argv` after the `stats` word itself, parsed into what to do — or a
/// refusal, carrying the same two early exits `maybe_run` returns a code
/// for: `--help`/`-h` and a flag nothing above recognized.
#[derive(Debug, PartialEq, Eq)]
enum ParsedArgs {
    Run(Output),
    Help,
    Unknown(String),
}

/// The pure half of argument handling — never touches `std::env::args`
/// itself, so it is testable against any list of words. [`maybe_run`] is the
/// thin shell that supplies the real one.
fn parse_args(args: impl IntoIterator<Item = String>) -> ParsedArgs {
    let mut json = false;
    let mut report: Option<Option<PathBuf>> = None;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "--report" | "--html" => report = Some(None),
            _ if arg.starts_with("--report=") || arg.starts_with("--html=") => {
                report = arg.split_once('=').map(|(_, p)| Some(PathBuf::from(p)));
            }
            "--help" | "-h" => return ParsedArgs::Help,
            other => return ParsedArgs::Unknown(other.to_string()),
        }
    }
    ParsedArgs::Run(match report {
        Some(path) => Output::Report(path),
        None if json => Output::Json,
        None => Output::Text,
    })
}

/// If argv names the `stats` subcommand, run it and return the process
/// exit code. `None` → argv is not ours, `main` continues to the tray app.
pub fn maybe_run(load_manifests: impl FnOnce() -> Vec<PluginManifest>) -> Option<i32> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("stats") {
        return None;
    }
    Some(match parse_args(args) {
        ParsedArgs::Help => {
            print!("{}", usage());
            0
        }
        ParsedArgs::Unknown(flag) => {
            eprintln!("tickover stats: unknown flag `{flag}`\n\n{}", usage());
            64
        }
        ParsedArgs::Run(output) => run(output, load_manifests()),
    })
}

fn usage() -> &'static str {
    "tickover stats — local token-usage history\n\
     \n\
     USAGE: tickover stats [--json] [--report[=PATH]]\n\
     \n\
       --json           machine-readable output\n\
       --report[=PATH]  write a self-contained HTML report and open it\n\
                      (default: <config>/tickover/reports/usage-<ts>.html)\n"
}

fn run(output: Output, manifests: Vec<PluginManifest>) -> i32 {
    // A provider the user disabled keeps its history files untouched and
    // drops out of the report entirely — same filter the tray scan
    // applies in `spawn_history_scan`.
    let manifests: Vec<PluginManifest> = manifests
        .into_iter()
        .filter(crate::plugin_enabled)
        .collect();
    let Some(dir) = tickover::history::default_dir() else {
        eprintln!("tickover stats: no config directory on this platform");
        return 1;
    };
    // The tray app scans this same store on its own timer — serialize
    // open+scan+commit so neither process commits stale cursors over the
    // other's work.
    let _lock = match tickover::history::store::lock_store(&dir) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("tickover stats: could not lock history store: {e}");
            return 1;
        }
    };
    let mut store = match HistoryStore::open(&dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tickover stats: could not open history store: {e}");
            return 1;
        }
    };
    // Fresh data first: resumable ticks until the budget stops coming back
    // early. A cold corpus takes a few passes; a warm one costs a stat.
    let mut scans;
    let mut guard = 0;
    loop {
        scans = tickover::history::scan_tick(&mut store, &manifests, &crate::plugin_options);
        let _ = store.commit();
        guard += 1;
        if !scans.iter().any(|s| s.outcome.partial) || guard >= 60 {
            break;
        }
    }

    // Buckets from a disabled provider stay on disk but leave every
    // figure — `manifests` was already filtered to enabled above.
    let enabled: std::collections::HashSet<String> =
        manifests.iter().map(|m| m.id.clone()).collect();
    let stats = query::compute(&store, 30, &enabled);
    let cost_on = crate::config::history_cost_estimate();

    match output {
        Output::Report(path) => {
            let sources: Vec<String> = manifests
                .iter()
                .filter_map(|m| m.history.as_ref().map(|h| h.root.clone()))
                .collect();
            let path = match tickover::history::report::write(&stats, path, cost_on, &[], &sources)
            {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("tickover stats: report failed: {e}");
                    return 1;
                }
            };
            println!("report written: {}", path.display());
            open_in_browser(&path);
        }
        Output::Json => {
            let out = json_out(&stats, &scans, &manifests, cost_on);
            let _ = writeln!(std::io::stdout(), "{out}");
        }
        Output::Text => {
            print!("{}", text_out(&stats, &scans, &manifests, cost_on));
        }
    }
    0
}

/// Providers whose manifests carry no `[history]` — shown as quota-only
/// rather than averaged into anything. A provider that declares history
/// but simply had no usage in range is counted, not quota-only.
fn quota_only(manifests: &[PluginManifest]) -> Vec<String> {
    manifests
        .iter()
        .filter(|m| m.history.is_none())
        .map(|m| m.id.clone())
        .collect()
}

/// Open `path` in the default browser — plain `open`/`start`/`xdg-open`.
/// The CLI exits right after, so no child reaping is needed.
pub(crate) fn open_in_browser(path: &std::path::Path) {
    #[cfg(target_os = "macos")]
    let cmd = std::process::Command::new("open").arg(path).spawn();
    #[cfg(target_os = "windows")]
    let cmd = std::process::Command::new("cmd")
        .args(["/c", "start", ""])
        .arg(path)
        .spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let cmd = std::process::Command::new("xdg-open").arg(path).spawn();
    let _ = cmd;
}

pub(crate) fn fmt_tokens(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1e6)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1e3)
    } else {
        n.to_string()
    }
}

fn text_out(
    st: &query::Stats,
    scans: &[tickover::history::ProviderScan],
    manifests: &[PluginManifest],
    cost_on: bool,
) -> String {
    let mut s = String::new();
    s.push_str("tickover stats — local usage history\n\n");
    if st.providers.is_empty() {
        s.push_str("no usage history found yet.\n");
        s.push_str("history is collected from providers' local files as the app runs;\n");
        s.push_str("providers without a history source are quota-only.\n");
    } else {
        s.push_str(&format!(
            "total    {:>9}   (in {} / out {} / cache r {} w {} / think {})\n",
            fmt_tokens(st.total.sum()),
            fmt_tokens(st.total.input),
            fmt_tokens(st.total.output),
            fmt_tokens(st.total.cache_read),
            fmt_tokens(st.total.cache_write),
            fmt_tokens(st.total.thinking),
        ));
        s.push_str(&format!("today    {:>9}\n", fmt_tokens(st.today.sum())));
        s.push_str(&format!("this week {:>8}\n", fmt_tokens(st.week.sum())));
        if let Some(pct) = st.total.cache_hit_pct() {
            s.push_str(&format!("cache hit {pct:>8.0}%\n"));
        }
        if cost_on {
            let per_model: Vec<(String, query::Totals)> = st.models.clone();
            if let Some(usd) = pricing::cost_for_models(&per_model) {
                s.push_str(&format!(
                    "est. cost {:>8.2} USD (list price, opt-in)\n",
                    usd
                ));
            }
        }
        s.push_str(&format!("streak   {:>8} days\n\n", st.streak_days));
        s.push_str("by provider\n");
        for (p, t) in &st.by_provider {
            s.push_str(&format!("  {p:<12} {:>9}\n", fmt_tokens(t.sum())));
        }
        s.push('\n');
        if !st.projects.is_empty() {
            s.push_str("top projects\n");
            for (p, t) in st.projects.iter().take(5) {
                s.push_str(&format!("  {p:<24} {:>9}\n", fmt_tokens(t.sum())));
            }
            s.push('\n');
        }
    }
    let qo = quota_only(manifests);
    if !qo.is_empty() {
        s.push_str(&format!("quota only: {}\n", qo.join(", ")));
    }
    let skipped: u64 = scans
        .iter()
        .map(|s| s.outcome.skipped_unparsed)
        .sum::<u64>()
        .max(st.skipped_unparsed);
    if skipped > 0 {
        s.push_str(&format!(
            "note: {skipped} history line(s) didn't parse — provider format drift; \
             totals above cover what did.\n"
        ));
    }
    if scans.iter().any(|s| s.outcome.partial) {
        s.push_str("note: scan is still catching up — rerun for complete totals.\n");
    }
    s
}

/// Stable JSON shape — additive-only across releases (fields may be added;
/// existing names/types never change).
fn json_out(
    st: &query::Stats,
    scans: &[tickover::history::ProviderScan],
    manifests: &[PluginManifest],
    cost_on: bool,
) -> String {
    fn totals_json(t: &query::Totals) -> serde_json::Value {
        serde_json::json!({
            "input": t.input,
            "output": t.output,
            "cache_read": t.cache_read,
            "cache_write": t.cache_write,
            "thinking": t.thinking,
            "total": t.sum(),
            "messages": t.messages,
        })
    }
    let mut v = serde_json::json!({
        "schema": 1,
        "total": totals_json(&st.total),
        "today": totals_json(&st.today),
        "week": totals_json(&st.week),
        "month": totals_json(&st.month),
        "cache_hit_pct": st.total.cache_hit_pct(),
        "streak_days": st.streak_days,
        "providers": st.by_provider.iter()
            .map(|(k, t)| (k.clone(), totals_json(t)))
            .collect::<serde_json::Map<_, _>>(),
        "quota_only": quota_only(manifests),
        "top_projects": st.projects.iter().take(10)
            .map(|(p, t)| serde_json::json!({"project": p, "tokens": t.sum()}))
            .collect::<Vec<_>>(),
        "models": st.models.iter().take(10)
            .map(|(m, t)| serde_json::json!({"model": m, "tokens": t.sum()}))
            .collect::<Vec<_>>(),
        "daily": st.daily.iter()
            .map(|(d, t)| serde_json::json!({"date": d.to_string(), "tokens": t.sum()}))
            .collect::<Vec<_>>(),
        "scan": {
            "files_scanned": scans.iter().map(|s| s.outcome.files_scanned).sum::<usize>(),
            "skipped_unparsed": scans.iter().map(|s| s.outcome.skipped_unparsed).sum::<u64>()
                .max(st.skipped_unparsed),
            "partial": scans.iter().any(|s| s.outcome.partial),
        },
    });
    if cost_on {
        let per_model: Vec<(String, query::Totals)> = st.models.clone();
        v["est_cost_usd"] = pricing::cost_for_models(&per_model)
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null);
    }
    serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds the `String` iterator [`parse_args`] takes from plain string
    /// literals — argv words are owned, so a test's `&str` slice needs this
    /// conversion whether the flags parse cleanly or not.
    fn words(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_flags_at_all_means_plain_text() {
        assert_eq!(parse_args(words(&[])), ParsedArgs::Run(Output::Text));
    }

    #[test]
    fn json_alone_asks_for_json() {
        assert_eq!(
            parse_args(words(&["--json"])),
            ParsedArgs::Run(Output::Json)
        );
    }

    #[test]
    fn report_alone_with_no_value_uses_the_default_path() {
        assert_eq!(
            parse_args(words(&["--report"])),
            ParsedArgs::Run(Output::Report(None))
        );
    }

    /// `--html` is a bare alias for `--report`, not a distinct output mode —
    /// same variant, same default-path behavior.
    #[test]
    fn html_is_an_alias_for_report() {
        assert_eq!(
            parse_args(words(&["--html"])),
            ParsedArgs::Run(Output::Report(None))
        );
    }

    #[test]
    fn report_with_a_value_names_the_path() {
        assert_eq!(
            parse_args(words(&["--report=out.html"])),
            ParsedArgs::Run(Output::Report(Some(PathBuf::from("out.html"))))
        );
        assert_eq!(
            parse_args(words(&["--html=out.html"])),
            ParsedArgs::Run(Output::Report(Some(PathBuf::from("out.html"))))
        );
    }

    /// `--report=` with nothing after the `=` is not the same thing as bare
    /// `--report`: today it names an empty path rather than falling back to
    /// the default one. Pinned as-is — nothing here asks the parser to
    /// second-guess a value the user actually typed.
    #[test]
    fn report_with_an_empty_value_names_an_empty_path_rather_than_the_default() {
        assert_eq!(
            parse_args(words(&["--report="])),
            ParsedArgs::Run(Output::Report(Some(PathBuf::from(""))))
        );
    }

    #[test]
    fn help_short_and_long_both_stop_parsing_at_once() {
        assert_eq!(parse_args(words(&["--help"])), ParsedArgs::Help);
        assert_eq!(parse_args(words(&["-h"])), ParsedArgs::Help);
        // A flag already seen does not change the answer — `--help` wins
        // outright, the same way `maybe_run` printed usage and returned
        // before this was split out.
        assert_eq!(parse_args(words(&["--json", "--help"])), ParsedArgs::Help);
    }

    #[test]
    fn an_unrecognized_flag_is_refused_by_name() {
        assert_eq!(
            parse_args(words(&["--bogus"])),
            ParsedArgs::Unknown("--bogus".to_string())
        );
        // Refused at the point it is found — a flag after it is never
        // reached, matching the loop's own early return.
        assert_eq!(
            parse_args(words(&["--json", "--bogus", "--report"])),
            ParsedArgs::Unknown("--bogus".to_string())
        );
    }

    /// The rule named on [`Output`]'s own doc, pinned both ways round:
    /// `--report` wins over `--json` whichever comes first on the line.
    #[test]
    fn report_wins_over_json_in_either_order() {
        assert_eq!(
            parse_args(words(&["--report", "--json"])),
            ParsedArgs::Run(Output::Report(None))
        );
        assert_eq!(
            parse_args(words(&["--json", "--report"])),
            ParsedArgs::Run(Output::Report(None))
        );
        assert_eq!(
            parse_args(words(&["--json", "--report=out.html"])),
            ParsedArgs::Run(Output::Report(Some(PathBuf::from("out.html"))))
        );
    }
}
