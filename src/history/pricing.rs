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
    // Anthropic's 5-generation line, from claude.com/pricing (checked
    // 2026-09). That page also lists a "Fable" tier (Fable 5, Fable
    // 5.1) — left out on purpose: nothing here can confirm the API
    // model-id slug a real transcript would carry for it, and a guessed
    // prefix risks silently mispricing whatever model actually owns it.
    // Opus 5.5 is listed under both minor-version spellings: this
    // table's own convention hyphenates minor versions in a real model
    // id (`price_for`'s doc example is `claude-sonnet-4-6-20250922`,
    // not `4.6`), so the dotted form alone would never match and the id
    // would silently price as plain Opus 5 instead — whichever spelling
    // a real id turns out to use, the longer prefix still wins. Opus
    // 5.5's cache-read is 0.05× input, not this section's usual 0.10× —
    // checked against the cited page, not a transcription slip.
    ("claude-opus-5-5", p(4.0, 20.0, 0.20, 5.0)),
    ("claude-opus-5.5", p(4.0, 20.0, 0.20, 5.0)),
    ("claude-opus-5", p(5.0, 25.0, 0.50, 6.25)),
    ("claude-sonnet-5", p(2.0, 10.0, 0.20, 2.50)),
    // OpenAI / Codex — cached input ~0.10×, no write premium reported.
    ("gpt-5.2-codex", p(1.75, 14.0, 0.175, 1.75)),
    ("gpt-5.1-codex", p(1.25, 10.0, 0.125, 1.25)),
    ("gpt-5-codex", p(1.25, 10.0, 0.125, 1.25)),
    ("gpt-5.2", p(1.75, 14.0, 0.175, 1.75)),
    ("gpt-5.1", p(1.25, 10.0, 0.125, 1.25)),
    ("gpt-5", p(1.25, 10.0, 0.125, 1.25)),
    ("codex-mini", p(1.50, 6.0, 0.375, 1.50)),
    ("o4-mini", p(1.10, 4.40, 0.275, 1.10)),
    // o3-mini's cached-input rate is half off input, not the 75% off
    // o4-mini gets — sharing "o3"'s row would price it at o3's full
    // rate instead. From developers.openai.com/api/docs/pricing
    // (checked 2026-09).
    ("o3-mini", p(1.10, 4.40, 0.55, 1.10)),
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

/// Whether every model in `models` that carries any usage also has a
/// listed price — `false` means [`cost_for_models`]'s sum leaves out at
/// least one model's whole share, not merely a light one, so a caller
/// showing that sum as a headline figure should mark it partial.
pub fn fully_priced(models: &[(String, Totals)]) -> bool {
    models
        .iter()
        .filter(|(_, t)| t.sum() > 0)
        .all(|(m, _)| price_for(m).is_some())
}

/// [`cost_for_models`] and [`fully_priced`] together — every caller that
/// shows a cost figure needs both (the number, and whether it left
/// anything out), so this is the one call site for that pair rather than
/// each caller re-deriving "is it partial" its own way. The second
/// element is only meaningful when the first is `Some`: a figure that
/// isn't shown at all has nothing to be partial about.
pub fn cost_summary(models: &[(String, Totals)]) -> (Option<f64>, bool) {
    let cost = cost_for_models(models);
    let partial = cost.is_some() && !fully_priced(models);
    (cost, partial)
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

    #[test]
    fn o3_mini_prices_differently_from_o3() {
        // A shared "o3" prefix would price o3-mini at o3's much higher
        // rate — o3-mini's real cached-input discount is also half off,
        // not the 75% off a bare `o4-mini`-shaped guess would apply.
        let t = Totals {
            input: 1_000_000,
            output: 1_000_000,
            cache_read: 1_000_000,
            cache_write: 0,
            thinking: 0,
            messages: 0,
        };
        let mini = cost_usd("o3-mini-2026-01-31", &t).unwrap();
        let full = cost_usd("o3-2026-01-31", &t).unwrap();
        assert!(mini < full, "mini={mini} full={full}");
        // 1.10 (input) + 4.40 (output) + 0.55 (cache read) = 6.05
        assert!((mini - 6.05).abs() < 0.01);
    }

    #[test]
    fn a_5_generation_claude_session_is_priced_not_left_at_nothing() {
        let t = Totals {
            input: 1_000_000,
            output: 1_000_000,
            cache_read: 1_000_000,
            cache_write: 0,
            thinking: 0,
            messages: 0,
        };
        assert!(cost_usd("claude-sonnet-5-20260915", &t).is_some());
        assert!(cost_usd("claude-opus-5-20260915", &t).is_some());
        // A real transcript hyphenates minor versions (`price_for`'s own
        // doc example is `claude-sonnet-4-6-20250922`, not `4.6`) — this
        // is the spelling that must price correctly, not just the dotted
        // form a table comment happens to also carry.
        let opus5 = cost_usd("claude-opus-5-20260915", &t).unwrap();
        let opus55_hyphenated = cost_usd("claude-opus-5-5-20260915", &t).unwrap();
        let opus55_dotted = cost_usd("claude-opus-5.5-20260915", &t).unwrap();
        assert_eq!(
            opus55_hyphenated, opus55_dotted,
            "both spellings must price identically"
        );
        // A collapse to plain Opus 5's rate (5.0 input + 25.0 output +
        // 0.50 cache read) would total 30.50; the real Opus 5.5 rate
        // (4.0 + 20.0 + 0.20) totals 24.20 — cache reads alone are 2.5x
        // apart (0.50 vs 0.20), the dominant class in a cache-heavy
        // session.
        assert!(
            (opus55_hyphenated - 24.20).abs() < 1e-9,
            "opus55={opus55_hyphenated} (must not collapse to opus5's 30.50)"
        );
        assert_ne!(
            opus5, opus55_hyphenated,
            "the longer prefix must win over plain Opus 5"
        );
    }

    #[test]
    fn fully_priced_flags_an_unpriced_model_in_the_mix() {
        let known = ("gpt-5.1".to_string(), Totals::default());
        let unknown = ("claude-fable-5".to_string(), Totals::default());
        let some_usage = Totals {
            input: 100,
            ..Totals::default()
        };
        assert!(
            fully_priced(&[("gpt-5.1".to_string(), some_usage)]),
            "every model with usage is priced"
        );
        assert!(
            !fully_priced(&[
                ("gpt-5.1".to_string(), some_usage),
                ("claude-fable-5".to_string(), some_usage),
            ]),
            "an unpriced model carrying usage must flag the mix as partial"
        );
        // A model with no usage at all doesn't matter either way.
        assert!(fully_priced(&[known, (unknown.0, Totals::default())]));
    }
}
