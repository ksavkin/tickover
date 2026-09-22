//! Bundled per-model list prices — the *only* source of cost figures.
//!
//! Deliberately local and deliberately small: fetching a live price sheet
//! would break the feature's no-network rule, so ~20 current models are
//! pinned here instead, and a model this table does not know prices as
//! `None` — rendered `—` — rather than being silently estimated at a
//! neighbour's rate. Figures are USD per 1M tokens at public list price;
//! subscription seats are never list-priced, so every cost this produces
//! is labelled "estimated" wherever it is shown.
//!
//! Cache classes price differently on purpose: cache *writes* are billed
//! above input rate (Anthropic's 1.25×), cache *reads* far below it
//! (0.10×), and thinking tokens bill as output. Providers that do not
//! split cache classes (Grok, Antigravity's surface) get input/output
//! rates only — their `cache_read` still counts toward volume, not cost.

use crate::history::query::Totals;

/// USD per 1M tokens: `(input, output, cache_read, cache_write)`.
/// `thinking` is priced at the output rate — every provider that exposes
/// it bills it that way.
struct Price {
    input: f64,
    output: f64,
    cache_read: f64,
    cache_write: f64,
}

/// Match order matters: entries are prefix-matched against the model id
/// the provider wrote, so a longer prefix must precede its shorter
/// siblings (`claude-opus-4` before `claude-`).
const TABLE: &[(&str, Price)] = &[
    // Anthropic — cache write 1.25×, cache read 0.10× input.
    ("claude-opus-4", p(15.0, 75.0, 1.50, 18.75)),
    ("claude-sonnet-4", p(3.0, 15.0, 0.30, 3.75)),
    ("claude-haiku-4", p(1.0, 5.0, 0.10, 1.25)),
    ("claude-3-5-sonnet", p(3.0, 15.0, 0.30, 3.75)),
    ("claude-3-5-haiku", p(0.80, 4.0, 0.08, 1.0)),
    ("claude-3-opus", p(15.0, 75.0, 1.50, 18.75)),
    // OpenAI / Codex — cached input ~0.10×, no write premium reported.
    ("gpt-5.2-codex", p(1.75, 14.0, 0.175, 1.75)),
    ("gpt-5.1-codex", p(1.25, 10.0, 0.125, 1.25)),
    ("gpt-5-codex", p(1.25, 10.0, 0.125, 1.25)),
    ("gpt-5.2", p(1.75, 14.0, 0.175, 1.75)),
    ("gpt-5.1", p(1.25, 10.0, 0.125, 1.25)),
    ("gpt-5", p(1.25, 10.0, 0.125, 1.25)),
    ("codex-mini", p(1.50, 6.0, 0.375, 1.50)),
    ("o4-mini", p(1.10, 4.40, 0.275, 1.10)),
    ("o3", p(2.0, 8.0, 0.50, 2.0)),
    // Grok — no cache split exposed.
    ("grok-4.5", p(3.0, 15.0, 0.30, 3.0)),
    ("grok-4", p(3.0, 15.0, 0.30, 3.0)),
    ("grok-code-fast", p(0.20, 1.50, 0.02, 0.20)),
    // Gemini / Antigravity.
    ("gemini-3-pro", p(2.0, 12.0, 0.20, 2.0)),
    ("gemini-2.5-pro", p(1.25, 10.0, 0.125, 1.25)),
    ("gemini-2.5-flash", p(0.30, 2.50, 0.03, 0.30)),
];

const fn p(input: f64, output: f64, cache_read: f64, cache_write: f64) -> Price {
    Price {
        input,
        output,
        cache_read,
        cache_write,
    }
}

/// Longest-prefix lookup — `"claude-sonnet-4-6-20250922"` prices at the
/// `claude-sonnet-4` row, an unlisted id prices at nothing.
fn price_for(model: &str) -> Option<&'static Price> {
    let model = model.to_ascii_lowercase();
    TABLE
        .iter()
        .filter(|(prefix, _)| model.starts_with(prefix))
        .max_by_key(|(prefix, _)| prefix.len())
        .map(|(_, price)| price)
}

/// Estimated list-price cost of `totals` under `model`'s rates — `None`
/// for an unknown model, so callers render `—` rather than `$0.00` and a
/// wrong number never masquerades as a free one.
pub fn cost_usd(model: &str, totals: &Totals) -> Option<f64> {
    let p = price_for(model)?;
    let per_m = |tokens: u64, rate: f64| tokens as f64 / 1_000_000.0 * rate;
    Some(
        per_m(totals.input, p.input)
            + per_m(totals.output + totals.thinking, p.output)
            + per_m(totals.cache_read, p.cache_read)
            + per_m(totals.cache_write, p.cache_write),
    )
}

/// Cost of `totals` when its tokens span several models — the caller
/// supplies per-model totals (from `query::Stats::models` intersected by
/// provider or project). `None` if *every* model is unknown; a mix prices
/// the known share (documented behaviour: partial estimates are still
/// labelled "estimated").
pub fn cost_for_models(models: &[(String, Totals)]) -> Option<f64> {
    let mut any = false;
    let sum: f64 = models
        .iter()
        .filter_map(|(m, t)| cost_usd(m, t))
        .inspect(|_| any = true)
        .sum();
    any.then_some(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_model_prices_per_class() {
        let t = Totals {
            input: 1_000_000,
            output: 1_000_000,
            cache_read: 1_000_000,
            cache_write: 1_000_000,
            thinking: 0,
            messages: 0,
        };
        // sonnet-4: 3 + 15 + 0.30 + 3.75 = 22.05
        let c = cost_usd("claude-sonnet-4-6-20250922", &t).unwrap();
        assert!((c - 22.05).abs() < 0.01);
    }

    #[test]
    fn thinking_bills_at_output_rate() {
        let t = Totals {
            thinking: 1_000_000,
            ..Totals::default()
        };
        assert_eq!(cost_usd("gpt-5.1", &t), Some(10.0));
    }

    #[test]
    fn unknown_model_is_none_not_zero() {
        assert_eq!(cost_usd("madeup-9000", &Totals::default()), None);
    }
}
