// Dev probe: exercise one provider plugin end-to-end (auth chain → engine →
// ProviderReading) without spinning up the tray/UI. Prints per-surface
// results; no tokens are ever exposed by the plugin engines/API.
//
// Usage: cargo run --example plugin_probe -- <plugin-id> [--all-surfaces]
//   <plugin-id>      the manifest `id` to probe, e.g. "codex" or "claude"
//   --all-surfaces   also fetch opt-in surfaces (e.g. Claude's desktop
//                    account), which normally need an explicit user opt-in
use tickover::plugin::{manifest, scheduler, seed};

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(id) = args.next() else {
        eprintln!("usage: plugin_probe <plugin-id> [--all-surfaces]");
        std::process::exit(2);
    };
    let include_opt_in = args.any(|a| a == "--all-surfaces");

    let dir = seed::plugins_dir();
    if let Err(e) = seed::seed_if_empty(&dir) {
        eprintln!(
            "warning: could not seed plugin manifests in {}: {e}",
            dir.display()
        );
    }

    let manifests: Vec<manifest::PluginManifest> = manifest::load_dir(&dir)
        .into_iter()
        .filter_map(|result| match result {
            Ok(m) => Some(m),
            Err((path, msg)) => {
                eprintln!(
                    "warning: skipping invalid manifest {}: {msg}",
                    path.display()
                );
                None
            }
        })
        .collect();

    let Some(m) = manifests.into_iter().find(|m| m.id == id) else {
        eprintln!("no plugin manifest with id {id:?} in {}", dir.display());
        std::process::exit(1);
    };

    let active_surface_ids: Vec<String> = m
        .surface
        .iter()
        .filter(|s| !s.opt_in || include_opt_in)
        .map(|s| s.id.clone())
        .collect();

    // This dev probe has no flag to override an `[[option]]` — every declared
    // option fetches at its manifest default (same as an untouched config).
    let options: std::collections::BTreeMap<String, bool> = m
        .option
        .iter()
        .map(|opt| (opt.key.clone(), opt.default))
        .collect();
    let readings = scheduler::fetch(&m, &active_surface_ids, &options);
    if readings.is_empty() {
        println!("{id}: no active surfaces (try --all-surfaces to include opt-in ones)");
        return;
    }
    // Read once, ahead of both loops below, rather than once per balance —
    // it never changes mid-run, and this probe fetches every surface first
    // anyway, so nothing is lost by reading it before the readings are even
    // printed.
    let show_values = show_values();
    for r in readings {
        let fmt = |w: Option<&tickover::model::Window>| {
            w.and_then(|w| w.used_percent)
                .map(|p| format!("{p:.0}%"))
                .unwrap_or_else(|| "—".into())
        };
        match &r.error {
            None => println!(
                "{:<8} {:<10} 5h={:<6} wk={}",
                r.name,
                r.tag.as_deref().unwrap_or("-"),
                fmt(r.primary_window()),
                fmt(r.secondary_window())
            ),
            Some(e) => println!(
                "{:<8} {:<10} ERROR: {e}",
                r.name,
                r.tag.as_deref().unwrap_or("-")
            ),
        }

        // The identity and quota-status wiring, as *shape* rather than as the
        // account's figures: a key is built from the manifest, and the status
        // line reports which fields the provider stated, never what it said.
        // This output is meant to be shared outside this machine, so it must
        // never carry a token or an account address.
        let keys: Vec<&str> = r.windows.iter().map(|w| w.key.as_str()).collect();
        println!("         window keys: {keys:?}");
        match &r.quota_status {
            None => println!("         quota: none stated by this provider"),
            Some(s) => println!(
                "         quota status: allowed={} limit_reached={} reached_type={} blocked={}",
                s.allowed.is_some(),
                s.limit_reached.is_some(),
                s.reached_type.is_some(),
                s.is_blocked(),
            ),
        }

        // Balances, in the same register as the two lines above: which figures
        // the provider stated, not what they were. Without this a provider that
        // reports no window at all — Grok, Copilot — probes as a row of dashes
        // and there is no way to tell a manifest that read everything from one
        // that read nothing.
        if r.balances.is_empty() {
            println!("         balances: none stated by this provider");
        }
        for b in &r.balances {
            println!(
                "         balance {} ({}): used={} cap={} remaining={} stated_percent={} period_end={} limit_reached={}",
                b.key,
                b.label,
                b.used.is_some(),
                b.cap.is_some(),
                b.remaining.is_some(),
                b.stated_percent.is_some(),
                b.period_end.is_some(),
                b.limit_reached.is_some(),
            );
            if show_values {
                println!(
                    "             VALUES {}: used={} cap={} remaining={} percent={:?} period_end={:?}",
                    b.key,
                    amount(b.used.as_ref()),
                    amount(b.cap.as_ref()),
                    amount(b.remaining.as_ref()),
                    b.stated_percent,
                    b.period_end,
                );
            }
        }
    }
}

/// The account's own figures, printed only when explicitly asked for.
///
/// Off by default, and deliberately awkward to turn on: this output is meant
/// to be shared outside this machine, so it must never carry a token or an
/// account address, and every field printed above is chosen so those shape
/// questions can be answered without the numbers.
fn show_values() -> bool {
    std::env::var("TICKOVER_PROBE_SHOW_VALUES").is_ok_and(|v| v == "1")
}

/// One balance figure as text — a dev rendering, not the panel's: the panel's
/// own formatter lives in the binary and is not reachable from an example.
fn amount(a: Option<&tickover::model::BalanceAmount>) -> String {
    use tickover::model::BalanceAmount;
    match a {
        None => "—".to_string(),
        Some(BalanceAmount::Money {
            minor,
            currency,
            exponent,
        }) => {
            format!("{minor} minor@1e-{exponent} {currency}")
        }
        Some(BalanceAmount::Number { value, unit }) => match unit {
            Some(u) => format!("{value} {u}"),
            None => format!("{value}"),
        },
        Some(BalanceAmount::Text(s)) => s.clone(),
    }
}
