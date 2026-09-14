//! Provider-agnostic usage model.
//!
//! Every provider source (a Codex-style log file, an HTTP usage API, …) is
//! adapted into a [`ProviderReading`] by its plugin engine (`crate::plugin`),
//! and the UI consumers — the popup provider list, the menu-bar pill and the
//! compact tray title — read only this shape. This module holds just the
//! neutral data types.

/// Which slot a quota window occupies. `Primary` is the short (5-hour) window
/// — it fills the first UI row and drives the 5h auto-ping; `Secondary` is the
/// long (weekly) window on the second row.
///
/// `Extra` is neither, and that is the whole point of it. A provider may
/// report quotas beside its subscription one — Codex answers with a
/// per-model allowance in `additional_rate_limits` — and those are worth
/// showing and must never be mistaken for the subscription. They are not: the
/// two accessors below select by role, so an `Extra` window can fill neither
/// slot, and everything that reads a provider's headline number (the menu-bar
/// pill, the compact tray title, the auto-ping's reset time) goes through
/// them. The one place a model quota appeared in the main row cost this
/// project a panel reading 0% while the real weekly window sat at 69%.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Primary,
    Secondary,
    Extra,
}

/// One quota window of a provider reading.
#[derive(Debug, Clone, PartialEq)]
pub struct Window {
    /// This window's identity, stable across the things about a window that
    /// legitimately change: `<entry>:<element>`.
    ///
    /// `<entry>` is the declared `[[windows]]` entry (its `id`, or its position
    /// when it has none). `<element>` is empty until an entry can enumerate an
    /// array — nothing in either shipped manifest does yet.
    ///
    /// What is deliberately *not* in it: the response slot the window arrived
    /// in, and its length. Both move on their own. Codex sends its weekly
    /// window as `primary_window` whenever the 5-hour one has nothing to
    /// report, which is the ordinary state this app's hysteresis exists for —
    /// so a key built on the slot would change identity precisely when the
    /// window is being remembered. Length is the classifier, never the name.
    ///
    /// The honest limit, written here rather than promised away: at Codex
    /// neither slot nor length is stable and the response carries nothing else,
    /// so a window whose length crosses its entry's classification bound is
    /// re-identified. That degrades into a stale row which expires, and one
    /// extra ping, rather than into a wrong number.
    pub key: String,
    /// Short row label shown in the popup ("5H" / "WK").
    pub label: String,
    /// Slot this window fills (see [`Role`]).
    pub role: Role,
    /// Percent of the window consumed (0–100); `None` when the provider
    /// reported the window without data.
    pub used_percent: Option<f64>,
    /// Absolute reset time as Unix seconds, if known.
    pub resets_at: Option<u64>,
    /// Nominal window length in minutes (300 = 5h, 10080 = week) — feeds the
    /// elapsed-time tick and the pace figure.
    pub period_minutes: Option<u64>,
}

/// What a provider says about a quota as a whole, above its windows.
///
/// Every field is optional on its own, and that is the point: a provider is
/// answered with what it stated. `None` is "did not say", never "no".
#[derive(Debug, Clone, Default, PartialEq)]
pub struct QuotaStatus {
    /// May this account spend against the quota at all.
    pub allowed: Option<bool>,
    /// Has a limit been reached.
    pub limit_reached: Option<bool>,
    /// Which limit, in the provider's own words. Deliberately not mapped onto
    /// an enum of ours: a vocabulary that grows on the server would otherwise
    /// arrive as a silent "unknown".
    pub reached_type: Option<String>,
}

impl QuotaStatus {
    /// Whether the provider stated anything at all.
    pub fn is_stated(&self) -> bool {
        self.allowed.is_some() || self.limit_reached.is_some() || self.reached_type.is_some()
    }

    /// Whether the provider is refusing this quota right now.
    ///
    /// Two statements count outright: `limit_reached = true` and
    /// `allowed = false`. A provider that said neither is not blocked, because
    /// silence is not a refusal.
    ///
    /// Naming *which* limit was reached counts as a third — but only when
    /// nothing contradicts it. Codex sends `rate_limit_reached_type` solely on
    /// a refusal, so a body carrying that and no booleans is one, and reading
    /// it as "fine" would answer a locked-out account with "no usage reported
    /// yet". That inference is about a *field being present*, though, and the
    /// path it is read from is whatever a manifest points at — so a provider
    /// that fills the same field in the ordinary case (`"type": "none"`) would
    /// otherwise be reported as refusing every account it has.
    ///
    /// So the inference yields to **any** explicit statement: it applies only
    /// when the provider set neither boolean. A provider that answered the
    /// question directly has answered it, and this app reading the opposite out
    /// of a neighbouring field would be exactly the invention the rest of this
    /// type is built to avoid.
    pub fn is_blocked(&self) -> bool {
        self.allowed == Some(false) || self.limit_was_reached()
    }

    /// Whether a limit specifically has been reached — as opposed to the
    /// account being refused for some other reason.
    ///
    /// Split out because two callers need it and a rule stated twice is the
    /// shape of a latent hole in this project: the panel's wording picks
    /// between "limit reached" and "the provider is refusing this account", and
    /// [`QuotaStatus::is_blocked`] needs the same question answered. Written
    /// out in both places, the two drifted on the first change.
    pub fn limit_was_reached(&self) -> bool {
        if self.limit_reached == Some(true) {
            return true;
        }
        // Naming which limit was hit counts only when nothing else was said.
        self.limit_reached.is_none() && self.allowed.is_none() && self.reached_type.is_some()
    }
}

/// One balance reading: figures against a calendar period, as opposed to a
/// [`Window`]'s percentage against a rolling one.
///
/// A sibling of `Window` and [`QuotaStatus`], not a kind of either. The check
/// that settled it was per-field: a window's `used_percent` is its contract,
/// and two of the three providers that report a balance state no percentage at
/// all — filling that field would mean inventing one. Its `period_minutes` is
/// the classifier, and a calendar month is 28–31 days, so classifying by length
/// is meaningless here. And a window drags its consumers with it: the menu-bar
/// pill, the auto-ping and the `seen_records` registry all read percent and
/// length, and a balance disguised as a window would have to be excluded from
/// each of them by a special case.
///
/// Everything is `Option` for the usual reason: `None` is "the provider did not
/// say", never "zero". Nothing here is ever computed — see `stated_percent`.
#[derive(Debug, Clone, PartialEq)]
pub struct Balance {
    /// Identity for the row reconciler, built the same way a [`Window::key`] is
    /// — from the declared manifest entry, never from a label the provider may
    /// reword.
    ///
    /// Shaped `<entry>:<element>` like a window's key, with `<element>` empty
    /// until an entry can enumerate an array. That empty half is deliberate:
    /// no live balance was observed bound to a single quota rather than to the
    /// account, so this ships flat — but a provider that binds one later must
    /// be expressible without re-keying every row, and a key with no room for
    /// the quota it belongs to would have to be.
    pub key: String,
    /// Row label from the manifest — a literal written by the manifest author,
    /// never a template filled from the response.
    pub label: String,
    /// Spent. `None` when the provider did not report it.
    pub used: Option<BalanceAmount>,
    /// Ceiling. `None` when the provider did not report one.
    ///
    /// **A zero here is drawn, and nothing is concluded from it.** No provider
    /// documents what a zero in a cap means, and no live response distinguishes
    /// "no cap is set" from "the cap is zero" in a way a single account can
    /// observe. So the figure the provider sent is shown as sent —
    /// dropping it would be this app asserting the cap is absent, which is
    /// exactly as unmeasured as asserting it is a real zero. What never
    /// happens either way: no ratio is computed from it (none is computed from
    /// any cap), and no "exhausted" is inferred.
    pub cap: Option<BalanceAmount>,
    /// What is left, for providers that report the remainder instead of the
    /// used/cap pair (Codex states `credits.balance`, and states it as a
    /// string).
    pub remaining: Option<BalanceAmount>,
    /// A percentage **the provider stated** (Claude `spend.percent`). Never
    /// computed from `used` and `cap`: a figure this app derived would be
    /// indistinguishable in the UI from one the provider published, and the
    /// rule that the app never prints a number nobody sent is what makes the
    /// rest of the panel trustworthy.
    pub stated_percent: Option<f64>,
    /// End of the calendar period, Unix seconds. A date, not a length —
    /// a billing month is 28–31 days, so a length would be a fiction.
    pub period_end: Option<u64>,
    /// The provider said a spending limit has been reached.
    ///
    /// Kept on the balance rather than folded into [`QuotaStatus`] because a
    /// provider may report one and not the other: Claude declares no `[status]`
    /// section at all, so for it this is the only channel a refusal can arrive
    /// through. Not repeating a refusal the quota level already stated is a
    /// *rendering* rule, not a reason to drop the field.
    pub limit_reached: Option<bool>,
}

/// A figure in a balance, in whichever form the provider states it.
///
/// Three variants because three are filled by live providers, and no more for
/// the same reason: a variant nothing fills is a branch nobody can test.
#[derive(Debug, Clone, PartialEq)]
pub enum BalanceAmount {
    /// Money in minor units, with the scale stated by the response itself
    /// (Claude sends `amount_minor` + `currency` + `exponent` together). The
    /// scale is never assumed — "cents have two digits" is true until the
    /// first currency for which it is not.
    Money {
        minor: i64,
        currency: String,
        exponent: u32,
    },
    /// A number, with the unit the manifest names for it as a literal —
    /// `None` when the provider names none and the manifest invents none
    /// (Grok's figures are like that). Never inferred from the magnitude.
    ///
    /// The unit is part of the value rather than decoration: two numbers may
    /// be drawn as one "used / cap" pair only if they count the same thing,
    /// and `12 tokens / 100 requests` is a comparison nobody made.
    ///
    /// **It is a caption, not a measure of money.** A manifest may write
    /// `unit_label = "USD"` beside a plain number and the panel will print
    /// `12 USD`, which looks like [`BalanceAmount::Money`] and is not: no
    /// currency and no scale came from the response. That is allowed, and
    /// stated here rather than left to be discovered — the figure is still the
    /// provider's, the word is still the manifest author's, and this app
    /// invents neither. What it does mean is that the money triplet's
    /// guarantee (currency and scale as the provider stated them) belongs to
    /// `Money` alone, and a reader comparing two rows cannot infer it from a
    /// label.
    Number { value: f64, unit: Option<String> },
    /// The provider's own words (Codex states `credits.balance` as a string),
    /// already passed through `plugin::sanitize_provider_text`.
    Text(String),
}

impl BalanceAmount {
    /// A tag identifying what this figure is measured in.
    ///
    /// Two figures may be shown as a pair ("12 / 100") only when their tags
    /// match: pairing dollars with credits, or minor units at different scales,
    /// would render a comparison the provider never made.
    pub fn unit_tag(&self) -> Option<String> {
        match self {
            BalanceAmount::Money {
                currency, exponent, ..
            } => Some(format!("money:{currency}:{exponent}")),
            BalanceAmount::Number { unit, .. } => {
                Some(format!("number:{}", unit.as_deref().unwrap_or("")))
            }
            // Never pairable. Two provider sentences ("$5.00", "Pro tier")
            // have no common unit to compare in — reading them as a pair
            // would render `used $5.00 / cap Pro tier`, a ratio between two
            // things that are not quantities of the same kind.
            BalanceAmount::Text(_) => None,
        }
    }
}

impl Balance {
    /// Whether the provider stated anything at all worth a row.
    pub fn is_stated(&self) -> bool {
        self.used.is_some()
            || self.cap.is_some()
            || self.remaining.is_some()
            || self.stated_percent.is_some()
            // `Some(true)` only. A provider answering "no, the limit is not
            // reached" has said nothing to draw: with no figure beside it the
            // row would be a label, a period end and empty space — the shape
            // this method exists to keep off the panel. `Some(false)` still
            // matters elsewhere (it is a statement, and `None` is not), so the
            // field keeps all three states.
            || self.limit_reached == Some(true)
    }

    /// Whether `used` and `cap` may be drawn as one "used / cap" pair — same
    /// unit, same scale. Mixed units are shown as separate figures instead.
    pub fn pair_is_comparable(&self) -> bool {
        Self::same_unit(self.used.as_ref(), self.cap.as_ref())
    }

    /// Whether `remaining` and `cap` may be drawn as one "remaining / cap"
    /// pair, under exactly the rule above.
    ///
    /// The other half of the same fact: a provider states a ceiling with
    /// either what has been spent against it or what is left of it, and both
    /// are one figure against another. Copilot is the first to report the
    /// second form (its premium allowance states no spent figure at all), and
    /// before this its row drew as two stacked lines while a used/cap row of
    /// the same shape drew as one.
    ///
    /// Only when there is no `used`. A balance stating all three already has
    /// its pair, and drawing a second one would put the same ceiling on the
    /// row twice.
    pub fn remainder_pair_is_comparable(&self) -> bool {
        self.used.is_none() && Self::same_unit(self.remaining.as_ref(), self.cap.as_ref())
    }

    /// Two figures are a pair only if both are there and both count the same
    /// thing. A figure with no unit to compare in (a provider's own sentence)
    /// never pairs.
    fn same_unit(a: Option<&BalanceAmount>, b: Option<&BalanceAmount>) -> bool {
        match (a, b) {
            (Some(a), Some(b)) => match (a.unit_tag(), b.unit_tag()) {
                (Some(x), Some(y)) => x == y,
                _ => false,
            },
            _ => false,
        }
    }
}

/// What [`ProviderReading::token_renewal`] says about renewing the token
/// behind a reading's `error` — set only alongside `error`, by
/// `plugin::engine_http` (the one engine that reads a token at all), and
/// read by `main.rs`'s tick to decide whether to run a plugin's `[ping]`
/// outside its usual empty-window schedule (`[ping] renews_token`). This app
/// never spends a provider's refresh token itself (see
/// `plugin::throttle`'s module doc), so this is the "someone else has to"
/// signal — and, for both variants that carry one, a *key* naming which
/// token lapsed, so a renewal ping fires once per distinct token rather than
/// once per ten-minute floor forever (a token the CLI cannot renew either —
/// its own refresh token has expired too, say, and it now needs an
/// interactive login — must not be pinged indefinitely).
/// [`Lapsed::expires_at`](TokenRenewal::Lapsed) and
/// [`Unauthorized::token_hash`](TokenRenewal::Unauthorized) are both plain
/// `u64`s, but `main.rs`'s dedup table (`LAST_RENEWED_FOR:
/// HashMap<String, TokenRenewal>`) stores and compares the whole
/// `TokenRenewal` value, not either number on its own — a `Lapsed { expires_at:
/// 42 }` and an `Unauthorized { token_hash: 42 }` are different variants and
/// so never equal, however their numbers happen to line up. `TokenRenewal`
/// deriving `Copy`/`Eq` is what lets one table do this cheaply, keyed by
/// surface reading id (not plugin id — a plugin can have more than one
/// renewal-eligible surface, each lapsing on its own schedule), rather than
/// needing two tables or a tagged key type of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRenewal {
    /// No renewal is wanted for this reading — the ordinary case.
    No,
    /// The auth chain ended with a credential past its own declared expiry
    /// (Unix seconds) and no working step behind it (`auth::TOKEN_LAPSED`).
    /// Named by that expiry, read from `expiry_json_path` by
    /// `auth::token_expiry`, not just a bool.
    Lapsed { expires_at: u64 },
    /// An HTTP 401 arrived on a surface with no declared expiry to key a
    /// "once per token" ping on directly, so it is keyed on the token
    /// itself instead: `token_hash` is `plugin::throttle::fingerprint`'s
    /// hash of the bearer token and the request's other credential-derived
    /// values — never the token itself, never persisted or logged, the same
    /// fingerprint the throttle already computes to notice a credential
    /// change. A 401 with the same `token_hash` as the last renewal ping
    /// suppresses; a different one (the CLI rotated the token some other
    /// way, or this is the first 401 seen) pings again.
    Unauthorized { token_hash: u64 },
}

/// One provider's snapshot in a provider-agnostic shape.
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderReading {
    /// Stable identifier ("codex", "claude-cli", "claude-desktop").
    pub id: String,
    /// Display name for the popup section header ("Codex" / "Claude").
    pub name: String,
    /// Short label for the menu-bar pill and title ("Cx" / "Cl").
    pub short: String,
    /// Plan or surface chip next to the name ("PROLITE" / "CLI" / "Desktop").
    pub tag: Option<String>,
    /// Account email (shown faint), if known.
    pub account: Option<String>,
    /// Quota windows; empty when `error` is set.
    pub windows: Vec<Window>,
    /// The provider's statement about the quota itself, when it makes one.
    ///
    /// It exists because a quota's standing and its windows are separate facts.
    /// Codex's schema makes `allowed`/`limit_reached` required on `rate_limit`
    /// while both window slots are optional, so a blocked account with nothing
    /// running reports a status and no windows — and the reader, correctly,
    /// emits no row for a window nobody reported. Hung off the windows, that state
    /// would draw an empty section at the moment it matters most.
    ///
    /// `None` for a provider whose response carries no such statement — Claude
    /// says nothing of the kind, and answering with a blank status would be
    /// this app inventing a sentence nobody spoke.
    ///
    /// A bare status rather than a `Quota { key, class, status }`: with no way
    /// to enumerate an array yet, every provider has exactly one quota, so a
    /// key and a class would both hold one value each and be read by nobody.
    /// Keeping one while dropping the other would apply that rule
    /// selectively, so both wait for the same thing: an enumerating entry
    /// (`windows.for_each`) and the second quota that gives them something
    /// to distinguish.
    ///
    /// **Empty whenever `error` is set**, on the same reasoning that empties
    /// `windows`: a provider we could not read has told us nothing about its
    /// quota. Enforced in one place, [`ProviderReading::fail`], so the rule
    /// cannot live in one of two halves.
    pub quota_status: Option<QuotaStatus>,
    /// Balances this provider reported — figures against a calendar period.
    /// Empty means "reported none", and is the ordinary state for a provider
    /// that only has windows.
    ///
    /// **Empty whenever `error` is set**, by the same rule and in the same
    /// place ([`ProviderReading::fail`]) as `windows` and `quota_status`: a
    /// provider we could not read has told us nothing. The one case where
    /// that costs something is settled the same way: a `required` window
    /// that did not arrive means the author of the manifest declared the
    /// whole response untrustworthy, and a balance parsed out of an
    /// untrustworthy response is untrustworthy too.
    pub balances: Vec<Balance>,
    /// Human message when the provider couldn't be read (not installed, no
    /// usage yet, token expired, …) — shown instead of the window rows.
    pub error: Option<String>,
    /// Whether renewing the token behind `error` is possible, and how —
    /// see [`TokenRenewal`]. [`TokenRenewal::No`] whenever `error` is unset,
    /// and for any other reason a surface could not be read.
    pub token_renewal: TokenRenewal,
    /// Whether this reading participates in the menu-bar pill/title. The
    /// Claude desktop account is popup-only.
    pub in_menu_bar: bool,
    /// Whether the compact tray title may show this provider's numbers bare —
    /// without the short label — when it is the only visible provider. Set for
    /// the first *visible* provider (smallest `order` among those with readings
    /// on screen); with the shipped codex-then-claude order a bare "96/80"
    /// reads as Codex, but if Codex is disabled a lone Claude takes the bare
    /// slot instead.
    pub bare_when_sole: bool,
}

impl ProviderReading {
    /// Mark this reading as failed, and drop everything it was going to claim
    /// about the provider's quota.
    ///
    /// The one place the invariant lives. "We could not read this provider" and
    /// "this provider has no such limit" are different sentences, and `fail`
    /// goes to some trouble to keep the second from standing in for the first;
    /// a status left behind by a half-finished read would say the second one
    /// again, in a new field. Setting the message and clearing the claims are
    /// therefore a single operation rather than two an engine has to remember
    /// to pair — the shape of a latent hole is a rule that lives in one of two
    /// halves.
    pub fn fail(&mut self, message: impl Into<String>) {
        self.error = Some(message.into());
        self.windows.clear();
        self.quota_status = None;
        self.balances.clear();
    }

    /// The `Primary` (5-hour) window, selected by role — never by position.
    pub fn primary_window(&self) -> Option<&Window> {
        self.windows.iter().find(|w| w.role == Role::Primary)
    }

    /// The `Secondary` (weekly) window, selected by role — never by position.
    pub fn secondary_window(&self) -> Option<&Window> {
        self.windows.iter().find(|w| w.role == Role::Secondary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win(label: &str, role: Role) -> Window {
        Window {
            key: format!("{label}:"),
            label: label.into(),
            role,
            used_percent: Some(1.0),
            resets_at: None,
            period_minutes: None,
        }
    }

    fn reading(windows: Vec<Window>) -> ProviderReading {
        ProviderReading {
            id: "test".into(),
            name: "Test".into(),
            short: "Ts".into(),
            tag: None,
            account: None,
            windows,
            balances: Vec::new(),
            error: None,
            token_renewal: TokenRenewal::No,
            quota_status: None,
            in_menu_bar: true,
            bare_when_sole: false,
        }
    }

    #[test]
    fn window_helpers_select_by_role_not_position() {
        let r = reading(vec![win("WK", Role::Secondary), win("5H", Role::Primary)]);
        assert_eq!(r.primary_window().unwrap().label, "5H");
        assert_eq!(r.secondary_window().unwrap().label, "WK");
    }

    #[test]
    fn window_helpers_are_none_when_the_slot_is_missing() {
        let r = reading(vec![win("WK", Role::Secondary)]);
        assert_eq!(r.primary_window(), None);
        assert_eq!(r.secondary_window().unwrap().label, "WK");

        let empty = reading(Vec::new());
        assert_eq!(empty.primary_window(), None);
        assert_eq!(empty.secondary_window(), None);
    }

    fn balance(label: &str) -> Balance {
        Balance {
            key: format!("{label}:"),
            label: label.into(),
            used: Some(BalanceAmount::Money {
                minor: 1234,
                currency: "USD".into(),
                exponent: 2,
            }),
            cap: None,
            remaining: None,
            stated_percent: Some(12.0),
            period_end: Some(1_787_207_494),
            limit_reached: Some(false),
        }
    }

    #[test]
    fn a_failed_reading_claims_nothing_including_balances() {
        let mut r = reading(vec![win("5H", Role::Primary)]);
        r.balances = vec![balance("spend")];
        r.quota_status = Some(QuotaStatus {
            allowed: Some(true),
            ..QuotaStatus::default()
        });

        r.fail("session expired");

        // The invariant is "an error claims nothing", and a balance is a claim
        // about the provider exactly as much as a window is. Extending the rule
        // rather than adding a second one is the point: `fail` stays the single
        // place it lives.
        assert_eq!(r.error.as_deref(), Some("session expired"));
        assert!(r.windows.is_empty());
        assert_eq!(r.quota_status, None);
        assert!(
            r.balances.is_empty(),
            "a failed reading must not carry balances"
        );
    }

    #[test]
    fn amounts_are_only_a_pair_when_they_share_a_unit_and_a_scale() {
        let usd = |minor| BalanceAmount::Money {
            minor,
            currency: "USD".into(),
            exponent: 2,
        };
        let mut b = balance("spend");

        // Same currency and scale: a "used / cap" pair is a comparison the
        // provider itself makes sense of.
        b.cap = Some(usd(10_000));
        assert!(b.pair_is_comparable());

        // A different currency, and the pair would render a conversion nobody
        // performed.
        b.cap = Some(BalanceAmount::Money {
            minor: 10_000,
            currency: "EUR".into(),
            exponent: 2,
        });
        assert!(!b.pair_is_comparable());

        // Same currency, different scale — the trap the response's own
        // `exponent` exists to close. 10000 at exponent 3 is not 10000 at 2.
        b.cap = Some(BalanceAmount::Money {
            minor: 10_000,
            currency: "USD".into(),
            exponent: 3,
        });
        assert!(!b.pair_is_comparable());

        // Money against a bare number: two different kinds of thing.
        b.cap = Some(BalanceAmount::Number {
            value: 100.0,
            unit: None,
        });
        assert!(!b.pair_is_comparable());

        // And a cap nobody reported is not a pair either.
        b.cap = None;
        assert!(!b.pair_is_comparable());
    }

    #[test]
    fn two_figures_pair_only_when_they_count_the_same_thing() {
        let mut b = balance("spend");

        // Two bare numbers with the same declared unit: a pair.
        b.used = Some(BalanceAmount::Number {
            value: 12.0,
            unit: Some("credits".into()),
        });
        b.cap = Some(BalanceAmount::Number {
            value: 100.0,
            unit: Some("credits".into()),
        });
        assert!(b.pair_is_comparable());

        // Different units: `12 tokens / 100 requests` is a ratio nobody stated.
        b.cap = Some(BalanceAmount::Number {
            value: 100.0,
            unit: Some("requests".into()),
        });
        assert!(!b.pair_is_comparable());

        // A unit against no unit is not a match either — the manifest declared
        // one for the used figure and nothing for the cap.
        b.cap = Some(BalanceAmount::Number {
            value: 100.0,
            unit: None,
        });
        assert!(!b.pair_is_comparable());

        // Two provider sentences never pair: they are words, not quantities of
        // a common kind, and "used $5.00 / cap Pro tier" is a comparison this
        // app would be inventing.
        b.used = Some(BalanceAmount::Text("$5.00".into()));
        b.cap = Some(BalanceAmount::Text("Pro tier".into()));
        assert!(!b.pair_is_comparable());
        assert_eq!(BalanceAmount::Text("$5.00".into()).unit_tag(), None);
    }

    #[test]
    fn a_limit_that_was_not_reached_is_not_something_to_draw() {
        // A provider answering "no, nothing is exhausted" beside no figure at
        // all leaves a caption and a date over empty space. `Some(false)` is
        // still a statement the model keeps — it just does not hold up a row.
        let quiet = Balance {
            key: "x:".into(),
            label: "X".into(),
            used: None,
            cap: None,
            remaining: None,
            stated_percent: None,
            period_end: Some(1_787_207_494),
            limit_reached: Some(false),
        };
        assert!(!quiet.is_stated());
        assert!(Balance {
            limit_reached: Some(true),
            ..quiet.clone()
        }
        .is_stated());
        assert_eq!(
            quiet.limit_reached,
            Some(false),
            "the statement itself is kept"
        );
    }

    #[test]
    fn a_balance_with_nothing_in_it_is_not_stated() {
        let empty = Balance {
            key: "x:".into(),
            label: "X".into(),
            used: None,
            cap: None,
            remaining: None,
            stated_percent: None,
            period_end: Some(1_787_207_494),
            limit_reached: None,
        };
        // A period end alone says nothing about the account: every month has
        // one. A row drawn from it would be a label and a date beside empty
        // space.
        assert!(!empty.is_stated());

        assert!(balance("spend").is_stated());
        assert!(Balance {
            remaining: Some(BalanceAmount::Text("$5".into())),
            ..empty.clone()
        }
        .is_stated());
        assert!(Balance {
            limit_reached: Some(true),
            ..empty
        }
        .is_stated());
    }
}
