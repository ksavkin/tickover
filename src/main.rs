// Tickover — meters Codex, Claude, Grok, Antigravity and GitHub Copilot from
// the menu bar / system tray.
//
// No console window on Windows release builds.
#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

mod autostart;
mod config;
mod diag;
mod platform;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use slint::{
    ComponentHandle, Model, ModelRc, PhysicalPosition, SharedString, Timer, TimerMode, VecModel,
};
use tickover::menubar;
use tickover::model::{Balance, BalanceAmount, ProviderReading, Role, Window};
use tickover::plugin::auth;
use tickover::plugin::manifest::{self, EngineKind, PluginManifest};
use tickover::plugin::registry::{
    self, RegistryEntry, RegistryIndex, RegistryPluginState, TrustDisclosure,
};
use tickover::plugin::signature;
use tickover::plugin::{scheduler, seed};

use tray_icon::{
    menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent,
};

slint::include_modules!();

type Anchor = Rc<RefCell<Option<(f64, f64, f64, f64)>>>;
/// Every loaded plugin manifest (regardless of its per-plugin enable state —
/// that gates fetch/readings, not membership, so a disabled plugin still shows
/// in the manager and can be re-enabled), already sorted by `order` (ties by
/// `id` — see `plugin::manifest::load_dir`). Wrapped in a `RefCell` so the
/// settings sheet's "Reset plugins" can reload the manifest set live.
type Plugins = Rc<RefCell<Vec<PluginManifest>>>;
/// The latest fetch result per plugin id — NOT per reading id, so a
/// multi-surface plugin's whole `engine::fetch` result lands (and is
/// replaced) atomically. [`readings`] flattens this into the ordered,
/// filtered list every UI consumer reads.
type PluginCache = Rc<RefCell<HashMap<String, Vec<ProviderReading>>>>;
/// Plugin ids with a background fetch currently in flight (dedup so a slow
/// provider doesn't pile up redundant threads).
type Fetching = Rc<RefCell<HashMap<String, InFlight>>>;

/// One fetch this app is still waiting on.
///
/// A fetch that *panics* is covered by [`FetchGuard`], and one that never
/// starts by the spawn check — but one that **hangs** was covered by nothing.
/// Its plugin stayed marked in-flight for the life of the process and was
/// never polled again: the row simply stopped changing, with no error to show
/// for it. A thread cannot be killed, so what happens instead is that the app
/// stops waiting for it (see [`FETCH_PATIENCE`]), and the result it may still
/// send eventually is recognised as stale and dropped — by the generation,
/// which is why a bare "is it fetching" flag isn't enough.
#[derive(Debug, Clone, Copy)]
struct InFlight {
    generation: u64,
    started: Instant,
}

/// How long a single fetch may be outstanding before this app gives up
/// waiting and allows a fresh one.
///
/// Generous on purpose. A healthy fetch is a couple of HTTP requests with
/// their own timeouts, so seconds; but a credential step can legitimately sit
/// for a long time waiting for a user to answer an OS keychain prompt, and
/// abandoning that quickly would ask again — a prompt every refresh instead of
/// a row that went quiet.
const FETCH_PATIENCE: Duration = Duration::from_secs(600);

/// What to do about a fetch asked for while one may already be in flight.
#[derive(Debug, PartialEq, Eq)]
enum Admission {
    /// Nothing is in flight for this plugin.
    Start,
    /// One is, but it has outstayed [`FETCH_PATIENCE`]; stop waiting on it.
    Replace,
    /// One is, and it is still within its time.
    Wait,
}

/// Decide by how long the outstanding fetch (if any) has been running.
fn admit_fetch(in_flight_for: Option<Duration>, patience: Duration) -> Admission {
    match in_flight_for {
        None => Admission::Start,
        Some(elapsed) if elapsed < patience => Admission::Wait,
        Some(_) => Admission::Replace,
    }
}

/// Whether a fetch result belongs to the fetch this app is currently waiting
/// on. A result from an abandoned one must not clear the in-flight mark of its
/// replacement, nor overwrite that replacement's newer reading with an older.
fn result_is_current(in_flight: Option<InFlight>, generation: u64) -> bool {
    in_flight.is_some_and(|f| f.generation == generation)
}

/// Generation of the next fetch. Global rather than per-plugin: it only has to
/// be unique, and a single counter is the smallest thing that is.
static FETCH_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn next_fetch_generation() -> u64 {
    FETCH_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
}
type Providers = Rc<VecModel<ProviderData>>;
/// Persistent per-provider window models, keyed by reading id, living across
/// refreshes alongside [`Providers`]. Reusing the same inner `VecModel` (by
/// `Rc` identity) whenever a provider's row is structurally stable (same
/// reading id and window count) keeps the Slint `for w in data.windows`
/// repeater from re-creating its `ConsoleRow`s every tick — so the bar's
/// hover tooltip and its width/x animations survive the one-second refresh
/// instead of flickering/snapping. See [`refresh_model`]/[`reconcile_window_model`].
type WindowModels = Rc<RefCell<HashMap<String, WindowModel>>>;

/// One provider's persisted window rows, with the identity of each row beside
/// them.
///
/// The keys are carried here because [`WindowData`] is a Slint struct with no
/// room for one — it is what the panel draws, not what the reader knows. Without
/// them the reconciler can only compare row *counts*, which is the check that
/// let one row's label survive over another row's numbers.
struct WindowModel {
    model: Rc<VecModel<WindowData>>,
    keys: Vec<String>,
}

/// Persistent per-provider balance models, the balance row's own mirror of
/// [`WindowModels`] — a second map rather than a shared one, because a
/// balance and a window are reconciled by different identities
/// (`Balance::key` vs `Window::key`) and go stale on different schedules: a
/// window's row survives its provider going quiet via the seen-window TTL, a
/// balance's has no such hysteresis (see [`balance_rows`]) and simply stops
/// being emitted the moment the provider stops stating it. Folding the two
/// together would make one kind's staleness rule leak into the other's.
type BalanceModels = Rc<RefCell<HashMap<String, BalanceModel>>>;

/// One provider's persisted balance rows, with the identity of each row
/// beside them — [`WindowModel`]'s counterpart, for the same reason: a
/// `BalanceData` carries no key of its own, so without this the reconciler
/// could only compare row *counts*.
struct BalanceModel {
    model: Rc<VecModel<BalanceData>>,
    keys: Vec<String>,
}
/// The plugin-manager rows shown in the settings sheet, one per loaded
/// manifest (rebuilt from config on every relevant change).
type PluginRows = Rc<VecModel<PluginRow>>;
// The native status item is created after Slint's event loop begins. macOS
// does not reliably register a status item created before winit is running.
type TraySlot = Rc<RefCell<Option<Rc<TrayIcon>>>>;

/// The "AVAILABLE FROM REGISTRY" rows shown in the settings sheet — every
/// registry-listed plugin the last successful "Check updates" found is *not*
/// installed locally (see [`RegistryPluginState::New`]).
type RegistryRows = Rc<VecModel<RegistryPluginRow>>;
/// The last successfully-fetched-and-parsed `index.toml`, cached so
/// Install/Update can resolve a [`RegistryEntry`] by id without re-fetching
/// it. `None` until the first successful "Check updates"; a later network or
/// parse *failure* deliberately leaves a previously-cached index in place
/// (see `apply_registry_check`) rather than throwing away otherwise-still-
/// valid install/update targets over a transient blip.
type RegistryIndexCache = Rc<RefCell<Option<RegistryIndex>>>;
/// Registry plugin ids with an install/update fetch+verify currently in
/// flight — dedups a double-click the same way [`Fetching`] dedups a plugin
/// data fetch.
type RegistryBusy = Rc<RefCell<HashSet<String>>>;

/// The one official registry index that "Check updates" points at: the raw
/// `plugins/index.toml` of this app's own repository, fetched over HTTPS —
/// the registry is not a separate project, so "official" and "built from
/// this source tree" are the same claim. See `docs/PLUGIN-ARCHITECTURE.md`'s
/// "Transport" section.
const DEFAULT_REGISTRY_URL: &str =
    "https://raw.githubusercontent.com/ksavkin/tickover/main/plugins/index.toml";

fn ss(s: impl AsRef<str>) -> SharedString {
    SharedString::from(s.as_ref())
}

fn mono_family() -> &'static str {
    if cfg!(target_os = "macos") {
        "Menlo"
    } else if cfg!(target_os = "windows") {
        "Consolas"
    } else {
        "monospace"
    }
}

/// What the "put the figures next to the clock" toggle is called.
///
/// The place has a different name on each platform, and — since
/// `menubar::render_badge` — a different shape too: macOS gets a wide pill
/// standing in for the status item's title, Windows gets bars inside the
/// notification icon itself. Calling the Windows one "menu bar" names
/// something that platform does not have, next to a switch whose effect is
/// somewhere the user then has to find.
fn menu_bar_text_label() -> &'static str {
    if cfg!(target_os = "windows") {
        "Show stats in the tray icon"
    } else {
        "Show stats in menu bar"
    }
}

fn ui_family() -> &'static str {
    if cfg!(target_os = "macos") {
        "SF Pro Text"
    } else if cfg!(target_os = "windows") {
        "Segoe UI"
    } else {
        "sans-serif"
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Before anything else so much as looks at the config directory:
    // `platform::claim_single_instance` below, `diag::line` and
    // `seed::seed_if_empty` all create `<config>/tickover` the moment they
    // run — an instance lock, a log file, a seeded manifest — and once that
    // empty directory exists `migrate_legacy_dir` finds a destination already
    // there and does nothing, silently orphaning a still-full
    // `<config>/codex-limits`. So this runs first, before there is even a log
    // to report a failure into.
    let migrated_legacy_dir = match config::migrate_legacy_dir() {
        Ok(migrated) => migrated,
        Err(e) => {
            diag::line(format!("could not migrate the old config directory: {e}"));
            false
        }
    };
    // Only when a pre-rename install was actually found and moved — a fresh
    // install never held the old login item this retires, and asking macOS
    // to touch one it does not hold can raise the same permission prompt
    // `autostart::set` swallows the failure of. A fresh install must not see
    // it for nothing.
    if migrated_legacy_dir {
        // Said once, here, rather than left to speak for itself: the "already
        // settled" branch of `upgrade_builtin_manifests` used to be the one
        // silent path through this kind of decision, and it cost a shipped
        // manifest once (see that function's docs). A migration is rarer and
        // more surprising than a settled one, so it earns a line even more.
        diag::line(
            "moved the old config directory to its new name; retiring the old \
                     \"Codex Limits\" login item too, if there was one"
                .to_string(),
        );
        // `retire_legacy_entry` carries the toggle forward on its own; this
        // just says so, the same reason the move above gets a line.
        if autostart::retire_legacy_entry() {
            diag::line(
                "launch-at-login was on for the old install — carried it forward to Tickover"
                    .to_string(),
            );
        }
    }

    // Before anything is created that would be visible or would poll: a second
    // copy is a second pill in the menu bar, a second timer asking every
    // provider, and a second writer of the auto-ping's on-disk bookkeeping.
    // The guard lives until `main` returns, which is the life of the app.
    let _instance = match platform::claim_single_instance() {
        Ok(guard) => guard,
        Err(platform::AlreadyRunning) => {
            // The copy already running answers this launch by opening its
            // panel; this one has nothing to add.
            platform::leave_show_request();
            diag::line("already running — asked the running copy to show its panel".to_string());
            return Ok(());
        }
    };

    if std::env::var_os("SLINT_BACKEND").is_none() {
        std::env::set_var("SLINT_BACKEND", "winit");
    }

    let app = AppWindow::new()?;
    app.set_mono_family(ss(mono_family()));
    app.set_ui_family(ss(ui_family()));
    app.set_autostart(autostart::is_enabled());

    // First-run seeding happens exactly once, here — never inside
    // `load_plugins` (see that function's docs). The only other place the
    // built-in manifests get (re)written is the explicit "Reset plugins"
    // action (`seed::reseed_defaults`, in the `on_reset_plugins` handler
    // below).
    let seeded_dir = seed::plugins_dir();
    if let Err(e) = seed::seed_if_empty(&seeded_dir) {
        diag::line(format!(
            "could not seed plugin manifests in {}: {e}",
            seeded_dir.display()
        ));
    }
    upgrade_builtin_manifests(&seeded_dir);
    let plugins: Plugins = Rc::new(RefCell::new(load_plugins()));
    let cache: PluginCache = Rc::new(RefCell::new(HashMap::new()));
    let fetching: Fetching = Rc::new(RefCell::new(HashMap::new()));
    let anchor: Anchor = Rc::new(RefCell::new(None));
    let shown_at = Rc::new(Cell::new(Instant::now()));
    // When the status item was last clicked. Clicking it activates the app,
    // and dock mode restores the panel on exactly that activation edge — so
    // without this the two would fight over a single click and the panel would
    // flicker or land inverted. See `TRAY_CLICK_OWNS_ACTIVATION`.
    let tray_click_at: Rc<Cell<Option<Instant>>> = Rc::new(Cell::new(None));
    // When the panel last hid itself because it lost focus. Pressing the
    // status item is what takes that focus away, so the hide lands *before*
    // the click that caused it — see `TRAY_CLICK_DISMISS_WINDOW`.
    let hidden_by_focus_at: Rc<Cell<Option<Instant>>> = Rc::new(Cell::new(None));
    // Change-detection key for the tray indicator (avoids icon churn).
    let tray_key = Rc::new(RefCell::new(String::new()));

    let model: Providers = Rc::new(VecModel::from(Vec::<ProviderData>::new()));
    app.set_providers(ModelRc::from(model.clone()));
    // Per-provider window models reused across refreshes (see [`WindowModels`]).
    let window_models: WindowModels = Rc::new(RefCell::new(HashMap::new()));
    // Per-provider balance models, the same reuse trick for balance rows —
    // see [`BalanceModels`].
    let balance_models: BalanceModels = Rc::new(RefCell::new(HashMap::new()));

    // Plugin-manager model (settings sheet), rebuilt from config whenever a
    // toggle changes or the manifest set is reloaded.
    let plugin_model: PluginRows = Rc::new(VecModel::from(Vec::<PluginRow>::new()));
    app.set_plugins(ModelRc::from(plugin_model.clone()));
    refresh_plugins_model(&plugin_model, &plugins.borrow());

    // Registry ("Check updates" / Install / Update): the
    // "available from registry" model, the last successful index fetch
    // (Install/Update resolve a `RegistryEntry` from this without a second
    // fetch of `index.toml`), and the install/update in-flight dedup set.
    let registry_model: RegistryRows = Rc::new(VecModel::from(Vec::<RegistryPluginRow>::new()));
    app.set_registry_new(ModelRc::from(registry_model.clone()));
    let registry_index_cache: RegistryIndexCache = Rc::new(RefCell::new(None));
    let registry_busy: RegistryBusy = Rc::new(RefCell::new(HashSet::new()));
    // Unix seconds of the last successful "Check updates" — `None` renders
    // as Slint's own "Last checked: never" (`registry-status == 0`, never
    // touched here); `Some` drives the live "just now" → "Nm ago" relabeling
    // in the slow tick timer below.
    let last_registry_check: Rc<Cell<Option<u64>>> = Rc::new(Cell::new(None));

    // Background per-plugin fetch: one worker thread per fetch → a single
    // channel, shared by every plugin, polled on the UI thread. Each result
    // carries its own plugin id so the UI thread knows which cache slot to
    // replace.
    let (plugin_tx, plugin_rx) = mpsc::channel::<(String, u64, Vec<ProviderReading>)>();
    // "Check updates": the background fetch+parse of `index.toml` reports
    // back over this channel — network error, malformed index, or a parsed
    // `RegistryIndex` (see `RegistryCheckMsg`).
    let (registry_tx, registry_rx) = mpsc::channel::<RegistryCheckMsg>();
    // Install/Update: the background fetch+verify of one manifest reports
    // back over this channel, tagged with which action it was and the
    // registry entry it came from (see `PendingKind`/`InstallOutcome`) — the
    // trust dialog and the actual disk write both need the UI thread, so
    // only the network+sha256 half runs off it.
    let (install_tx, install_rx) = mpsc::channel::<(PendingKind, RegistryEntry, InstallOutcome)>();

    // ── UI callbacks ────────────────────────────────────────────────────
    {
        let weak = app.as_weak();
        let plugins = plugins.clone();
        let cache = cache.clone();
        let model = model.clone();
        let window_models = window_models.clone();
        let balance_models = balance_models.clone();
        let tx = plugin_tx.clone();
        let fetching = fetching.clone();
        app.on_refresh(move || {
            spawn_all_plugin_fetches(&plugins.borrow(), &tx, &fetching);
            if let Some(app) = weak.upgrade() {
                refresh_model(
                    &app,
                    &model,
                    &plugins.borrow(),
                    &cache,
                    &window_models,
                    &balance_models,
                );
            }
        });
    }

    let menubar_on = config::menu_bar_text();
    app.set_menu_bar_text(menubar_on);
    app.set_menu_bar_text_label(ss(menu_bar_text_label()));

    // ── Frameless popover chrome + hide-on-focus-loss ───────────────────
    // The UI needs both: dock mode gates window dragging, and only platforms
    // that draw their own edge around a frameless window want the card flush
    // with the window bounds (macOS does, Windows does not — there the card's
    // own border and shadow are the flyout's only chrome).
    app.set_dock_mode(platform::dock_mode());
    app.set_system_window_edge(cfg!(target_os = "macos"));
    // Dock mode always: the panel is an ordinary window there, with no title
    // bar to grab. A tray flyout is a different matter, and the answer is not
    // the same on both platforms. On macOS it hangs off a status item in a
    // menu bar that is one fixed row at the top of the screen, so it is never
    // in the way of anything and dragging it off that anchor would only
    // strand it. Windows hangs it off a taskbar the user can move to any edge,
    // make several rows tall, or set to auto-hide — and the flyout can land on
    // top of whatever they were reading. Being able to shove it aside is worth
    // more there than keeping it pinned, and costs nothing: the next open
    // re-anchors it against the item regardless.
    app.set_draggable(platform::dock_mode() || cfg!(target_os = "windows"));
    {
        use slint::winit_030::{winit::event::WindowEvent, EventResult, WinitWindowAccessor};
        let weak = app.as_weak();
        let shown_at = shown_at.clone();
        let hidden_by_focus_at = hidden_by_focus_at.clone();
        // Dock mode has no tray icon to re-open the panel from, so a window
        // that vanished on focus loss could never be brought back.
        let auto_hide = std::env::var_os("TICKOVER_SNAPSHOT").is_none()
            && std::env::var_os("TICKOVER_SHOW_ON_START").is_none()
            && !platform::dock_mode();
        app.window().on_winit_window_event(move |_win, event| {
            if let WindowEvent::Focused(false) = event {
                if auto_hide && shown_at.get().elapsed() > Duration::from_millis(250) {
                    if let Some(app) = weak.upgrade() {
                        let _ = app.window().hide();
                        // Remember *when*, so the click that took this focus
                        // away is not then read as a request to re-open.
                        hidden_by_focus_at.set(Some(Instant::now()));
                    }
                }
            }
            EventResult::Propagate
        });

        // Drag the frameless window by its own background (see the TouchArea
        // in `app.slint`). Decorations are deliberately left off even in dock
        // mode: a title bar would sit above a card that is flush with the
        // window edge, which is exactly the doubled-chrome look the layout
        // avoids.
        {
            let weak = app.as_weak();
            app.on_start_drag(move || {
                if let Some(app) = weak.upgrade() {
                    app.window().with_winit_window(|win| {
                        let _ = win.drag_window();
                    });
                }
            });
        }
    }

    // ── Tray icon + menu ────────────────────────────────────────────────
    // The tray context menu now carries only the app-wide toggles; per-plugin
    // ping / opt-in-surface options moved into the settings-sheet plugin
    // manager (their well-known ids live only in `config`'s legacy-key bridge).
    let menu = Menu::new();
    let refresh_item = MenuItem::new("Refresh now", true, None);
    let autostart_item = CheckMenuItem::new("Launch at login", true, autostart::is_enabled(), None);
    let menubar_item = CheckMenuItem::new(menu_bar_text_label(), true, menubar_on, None);
    let quit_item = MenuItem::new("Quit", true, None);
    menu.append(&refresh_item)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&autostart_item)?;
    menu.append(&menubar_item)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&quit_item)?;

    let refresh_id = refresh_item.id().clone();
    let autostart_id = autostart_item.id().clone();
    let menubar_id = menubar_item.id().clone();
    let quit_id = quit_item.id().clone();

    {
        let weak = app.as_weak();
        let check = autostart_item.clone();
        app.on_autostart_changed(move |requested| {
            let actual = autostart::set(requested);
            check.set_checked(actual);
            if let Some(app) = weak.upgrade() {
                app.set_autostart(actual);
            }
        });
    }

    let tray_builder = TrayIconBuilder::new()
        .with_tooltip("Tickover")
        // Set an initial title while the native status item is created. The
        // live compact quota title replaces it after the first refresh.
        .with_title("Limits")
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false);
    let tray_builder = match load_tray_icon() {
        Some(icon) => {
            #[cfg(target_os = "macos")]
            {
                tray_builder.with_icon(icon).with_icon_as_template(true)
            }
            #[cfg(not(target_os = "macos"))]
            {
                tray_builder.with_icon(icon)
            }
        }
        None => tray_builder,
    };
    // Slint creates the native macOS application lazily. Deferring tray
    // construction by one event-loop turn makes the status item durable even
    // when the popover has not been shown yet.
    let tray: TraySlot = Rc::new(RefCell::new(None));
    let tray_builder = Rc::new(RefCell::new(Some(tray_builder)));
    let tray_init_timer = Timer::default();
    {
        let tray = tray.clone();
        let tray_builder = tray_builder.clone();
        let plugins = plugins.clone();
        let cache = cache.clone();
        let tray_key = tray_key.clone();
        tray_init_timer.start(TimerMode::SingleShot, Duration::from_millis(1), move || {
            let Some(tray_builder) = tray_builder.borrow_mut().take() else {
                return;
            };
            // Built in dock mode too. Dock mode exists because the status item
            // cannot be *relied* on, not because it is unwanted: when the menu
            // bar does have room, the item is the whole point of this app —
            // it is where the numbers live. The two used to be exclusive
            // because a tray click also activates the app, so the
            // activation-edge restore and the tray's own toggle raced each
            // other; `tray_click_at` below is what settles that.
            match tray_builder.build() {
                Ok(native) => {
                    *tray.borrow_mut() = Some(Rc::new(native));
                    sync_tray_indicator(
                        &tray,
                        config::menu_bar_text(),
                        &plugins.borrow(),
                        &cache,
                        &tray_key,
                    );
                }
                Err(error) => {
                    diag::line(format!("could not create menu-bar item: {error}"));
                }
            }
        });
    }

    {
        let weak = app.as_weak();
        let check = menubar_item.clone();
        let tray = tray.clone();
        let plugins = plugins.clone();
        let cache = cache.clone();
        let tray_key = tray_key.clone();
        app.on_menu_bar_text_changed(move |enabled| {
            config::set_menu_bar_text(enabled);
            check.set_checked(enabled);
            if let Some(app) = weak.upgrade() {
                app.set_menu_bar_text(enabled);
            }
            sync_tray_indicator(&tray, enabled, &plugins.borrow(), &cache, &tray_key);
        });
    }

    // ── Plugin manager (settings sheet) ─────────────────────────────────
    // Each toggle persists to `config` by plugin/surface id, then rebuilds
    // the plugin-manager model (so sub-toggles dim with their parent) and —
    // where the change affects what is fetched or shown — the provider list
    // and tray. Everything stays generic over plugin ids; the well-known
    // codex/claude bridge lives entirely in `config`.
    {
        let weak = app.as_weak();
        let plugins = plugins.clone();
        let cache = cache.clone();
        let model = model.clone();
        let window_models = window_models.clone();
        let balance_models = balance_models.clone();
        let plugin_model = plugin_model.clone();
        let tx = plugin_tx.clone();
        let fetching = fetching.clone();
        let tray = tray.clone();
        let tray_key = tray_key.clone();
        app.on_plugin_enabled_changed(move |id, on| {
            let id = id.to_string();
            config::set_plugin_enabled(&id, on);
            if on {
                // Re-enabled: fetch it now so its row appears without waiting
                // for the next refresh cadence.
                let guard = plugins.borrow();
                if let Some(m) = plugin_by_id(&guard, &id) {
                    spawn_plugin_fetch(m, active_surface_ids(m), plugin_options(m), &tx, &fetching);
                }
            } else {
                // Disabled: drop its cached readings so it disappears at once
                // (fetch is gated too, so nothing repopulates the slot).
                cache.borrow_mut().remove(&id);
            }
            if let Some(app) = weak.upgrade() {
                refresh_plugins_model(&plugin_model, &plugins.borrow());
                refresh_model(
                    &app,
                    &model,
                    &plugins.borrow(),
                    &cache,
                    &window_models,
                    &balance_models,
                );
                sync_tray_indicator(
                    &tray,
                    app.get_menu_bar_text(),
                    &plugins.borrow(),
                    &cache,
                    &tray_key,
                );
            }
        });
    }
    {
        let weak = app.as_weak();
        let plugins = plugins.clone();
        let plugin_model = plugin_model.clone();
        app.on_plugin_ping_changed(move |id, on| {
            config::set_plugin_ping(id.as_ref(), on);
            // The auto-ping gate reads config live; only the model needs a
            // refresh to keep the checkbox in sync.
            if weak.upgrade().is_some() {
                refresh_plugins_model(&plugin_model, &plugins.borrow());
            }
        });
    }
    {
        let weak = app.as_weak();
        let plugins = plugins.clone();
        let cache = cache.clone();
        let model = model.clone();
        let window_models = window_models.clone();
        let balance_models = balance_models.clone();
        let plugin_model = plugin_model.clone();
        let tx = plugin_tx.clone();
        let fetching = fetching.clone();
        let tray = tray.clone();
        let tray_key = tray_key.clone();
        app.on_surface_opt_in_changed(move |plugin_id, surface_id, on| {
            let plugin_id = plugin_id.to_string();
            config::set_plugin_surface_enabled(&plugin_id, surface_id.as_ref(), on);
            // Enabling: re-fetch so the surface shows at once (a disabled one
            // needs no fetch — `readings` drops the now-inactive surface at read
            // time). Fetching on *disable* would only fire a redundant request
            // and risk a late reply landing the surface back in the cache before
            // the next filter, so it is skipped entirely.
            if on {
                let guard = plugins.borrow();
                if let Some(m) = plugin_by_id(&guard, &plugin_id) {
                    spawn_plugin_fetch(m, active_surface_ids(m), plugin_options(m), &tx, &fetching);
                }
            } else {
                // Drop what the surface last read, the way disabling a whole
                // plugin drops its readings. `readings_with` already hides an
                // inactive surface, so this changes nothing on screen — what it
                // changes is what the *next* fetch compares against. A stale
                // healthy reading left here is a row that was taken off the
                // panel by a toggle and would then be announced as having
                // "disappeared" the moment the surface is switched back on and
                // the token turns out to be gone (`credentials_just_lost`).
                drop_surface_reading(&cache, &plugin_id, surface_id.as_ref());
            }
            if let Some(app) = weak.upgrade() {
                refresh_plugins_model(&plugin_model, &plugins.borrow());
                refresh_model(
                    &app,
                    &model,
                    &plugins.borrow(),
                    &cache,
                    &window_models,
                    &balance_models,
                );
                sync_tray_indicator(
                    &tray,
                    app.get_menu_bar_text(),
                    &plugins.borrow(),
                    &cache,
                    &tray_key,
                );
            }
        });
    }
    {
        let weak = app.as_weak();
        let plugins = plugins.clone();
        let cache = cache.clone();
        let model = model.clone();
        let window_models = window_models.clone();
        let balance_models = balance_models.clone();
        let plugin_model = plugin_model.clone();
        let tx = plugin_tx.clone();
        let fetching = fetching.clone();
        let tray = tray.clone();
        let tray_key = tray_key.clone();
        app.on_reset_plugins(move || {
            // Restore the built-in codex/claude manifests (leaving any
            // third-party manifest and every user config toggle untouched),
            // then reload the manifest set and re-fetch under it.
            let dir = seed::plugins_dir();
            if let Err(e) = seed::reseed_defaults(&dir) {
                diag::line(format!("could not reset plugins in {}: {e}", dir.display()));
            }
            *plugins.borrow_mut() = load_plugins();
            cache.borrow_mut().clear();
            // Clear in-flight markers so the fresh fetches below aren't
            // deduped away by an old worker that is still running against the
            // pre-reset manifest — otherwise its stale result would be the one
            // that lands in the (now-cleared) cache.
            fetching.borrow_mut().clear();
            spawn_all_plugin_fetches(&plugins.borrow(), &tx, &fetching);
            if let Some(app) = weak.upgrade() {
                refresh_plugins_model(&plugin_model, &plugins.borrow());
                refresh_model(
                    &app,
                    &model,
                    &plugins.borrow(),
                    &cache,
                    &window_models,
                    &balance_models,
                );
                sync_tray_indicator(
                    &tray,
                    app.get_menu_bar_text(),
                    &plugins.borrow(),
                    &cache,
                    &tray_key,
                );
            }
        });
    }
    {
        let weak = app.as_weak();
        let plugins = plugins.clone();
        let cache = cache.clone();
        let model = model.clone();
        let window_models = window_models.clone();
        let balance_models = balance_models.clone();
        let plugin_model = plugin_model.clone();
        let tx = plugin_tx.clone();
        let fetching = fetching.clone();
        let tray = tray.clone();
        let tray_key = tray_key.clone();
        let shown_at = shown_at.clone();
        app.on_plugin_option_changed(move |id, key, on| {
            let id = id.to_string();
            config::set_plugin_option(&id, key.as_ref(), on);
            // Unlike a ping toggle (which only gates the auto-ping and needs
            // no refetch), an option is substituted straight into the
            // outgoing request (a header, URL or log-file path — see
            // `plugin::substitute_options`), so the currently cached reading
            // would otherwise stay visibly stale until the next scheduled
            // tick. Refetch immediately, mirroring the "enabling" branch of
            // `surface-opt-in-changed` above.
            {
                let guard = plugins.borrow();
                if let Some(m) = plugin_by_id(&guard, &id) {
                    spawn_plugin_fetch(m, active_surface_ids(m), plugin_options(m), &tx, &fetching);
                }
            }
            if let Some(app) = weak.upgrade() {
                refresh_plugins_model(&plugin_model, &plugins.borrow());
                refresh_model(
                    &app,
                    &model,
                    &plugins.borrow(),
                    &cache,
                    &window_models,
                    &balance_models,
                );
                sync_tray_indicator(
                    &tray,
                    app.get_menu_bar_text(),
                    &plugins.borrow(),
                    &cache,
                    &tray_key,
                );
            }
            // A native dialog never opens for this callback, but keeping the
            // popover's focus-loss clock fresh here too costs nothing and
            // keeps every plugin-manager callback consistent.
            shown_at.set(Instant::now());
        });
    }
    {
        // Add a third-party plugin: pick a `.toml` via a native file dialog,
        // validate it, and copy it into the plugins directory under
        // `<id>.toml` (not the picked file's own name — see
        // `reload_and_fetch`'s doc comment for why the id is what matters).
        let weak = app.as_weak();
        let plugins = plugins.clone();
        let cache = cache.clone();
        let model = model.clone();
        let window_models = window_models.clone();
        let balance_models = balance_models.clone();
        let plugin_model = plugin_model.clone();
        let tx = plugin_tx.clone();
        let fetching = fetching.clone();
        let tray = tray.clone();
        let tray_key = tray_key.clone();
        let shown_at = shown_at.clone();
        app.on_add_plugin(move || {
            // A labeled block, not a chain of early `return`s: every exit
            // path below (Cancel, a bad file, an `id` collision, a write
            // failure) still needs the trailing `shown_at.set` after it —
            // see that statement's own doc comment for why.
            'import: {
                let Some(picked) = pick_toml_file() else {
                    break 'import;
                }; // Cancel/closed
                if picked.extension().and_then(|e| e.to_str()) != Some("toml") {
                    show_alert(
                        "Not a plugin manifest",
                        "Choose a \".toml\" plugin manifest file.",
                    );
                    break 'import;
                }
                let text = match std::fs::read_to_string(&picked) {
                    Ok(t) => t,
                    Err(e) => {
                        diag::line(format!(
                            "add-plugin: could not read {}: {e}",
                            picked.display()
                        ));
                        show_alert("Could not read file", &e.to_string());
                        break 'import;
                    }
                };
                let manifest = match PluginManifest::from_str(&text) {
                    Ok(m) => m,
                    Err(e) => {
                        diag::line(format!(
                            "add-plugin: invalid manifest {}: {e}",
                            picked.display()
                        ));
                        show_alert("Invalid plugin manifest", &e);
                        break 'import;
                    }
                };
                let dir = seed::plugins_dir();
                if let Err(e) = std::fs::create_dir_all(&dir) {
                    diag::line(format!(
                        "add-plugin: could not create {}: {e}",
                        dir.display()
                    ));
                    show_alert("Could not import plugin", &e.to_string());
                    break 'import;
                }
                // `PluginManifest::from_str` above already restricted `id` to
                // a safe charset (`plugin::manifest::validate`), so this can
                // only fail if `dir` itself doesn't resolve cleanly — but the
                // containment check runs unconditionally anyway (defence in
                // depth, see `plugin_manifest_target`'s own docs).
                let Some(target) = plugin_manifest_target(&dir, &manifest.id) else {
                    diag::line(format!(
                        "add-plugin: refusing unsafe target path for id \"{}\"",
                        manifest.id
                    ));
                    show_alert(
                        "Invalid plugin manifest",
                        &format!("Plugin id \"{}\" is not a valid filename.", manifest.id),
                    );
                    break 'import;
                };
                // Refuse a silent clobber in memory: a *different*-named file
                // already loaded under this id — `dedup_plugin_ids` would
                // otherwise just drop the newly-added one without telling the
                // user anything happened. The on-disk case (same filename
                // already there) is caught below by `create_new` instead of a
                // separate `target.exists()` check — TOCTOU-safe: nothing can
                // create the file between a check and the write.
                if plugins.borrow().iter().any(|m| m.id == manifest.id) {
                    show_alert(
                        "Plugin already exists",
                        &format!("A plugin with id \"{}\" is already installed.", manifest.id),
                    );
                    break 'import;
                }
                let write_result = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&target)
                    .and_then(|mut f| std::io::Write::write_all(&mut f, text.as_bytes()));
                if let Err(e) = write_result {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        show_alert(
                            "Plugin already exists",
                            &format!("A plugin with id \"{}\" is already installed.", manifest.id),
                        );
                    } else {
                        diag::line(format!(
                            "add-plugin: could not write {}: {e}",
                            target.display()
                        ));
                        show_alert("Could not import plugin", &e.to_string());
                    }
                    break 'import;
                }
                reload_and_fetch(&plugins, &fetching, &plugin_model, &tx);
                if let Some(app) = weak.upgrade() {
                    refresh_model(
                        &app,
                        &model,
                        &plugins.borrow(),
                        &cache,
                        &window_models,
                        &balance_models,
                    );
                    sync_tray_indicator(
                        &tray,
                        app.get_menu_bar_text(),
                        &plugins.borrow(),
                        &cache,
                        &tray_key,
                    );
                }
            }
            // Every path above closed with a native dialog (`choose file` or
            // a `display alert`) having had focus. The popover's own
            // `Focused(false)` handler runs on the *next* event-loop turn —
            // any such event raised while the dialog was up is only
            // processed once this synchronous callback returns — so
            // resetting the clock here (not before the dialog) is what
            // actually keeps the sheet from hiding right after the reload
            // above finally lands.
            shown_at.set(Instant::now());
        });
    }
    {
        // Edit a plugin's manifest in the user's default text editor. This
        // process can't be told when the external editor saves/closes (`open
        // -t` returns immediately), so there is no reload here — the settings
        // sheet re-reads every manifest from disk the next time it is opened
        // (see the `settings-open` rising-edge check in the fast timer below).
        let shown_at = shown_at.clone();
        app.on_edit_plugin(move |id| {
            shown_at.set(Instant::now()); // the editor window steals focus
            let dir = seed::plugins_dir();
            match find_plugin_manifest_path(&dir, id.as_ref()) {
                Some(path) => open_in_text_editor(&path),
                None => diag::line(format!(
                    "edit-plugin: no manifest file found for id \"{id}\""
                )),
            }
        });
    }
    {
        let weak = app.as_weak();
        let plugins = plugins.clone();
        let cache = cache.clone();
        let model = model.clone();
        let window_models = window_models.clone();
        let balance_models = balance_models.clone();
        let plugin_model = plugin_model.clone();
        let tx = plugin_tx.clone();
        let fetching = fetching.clone();
        let tray = tray.clone();
        let tray_key = tray_key.clone();
        let shown_at = shown_at.clone();
        app.on_remove_plugin(move |id| {
            let id = id.to_string();
            let confirmed = confirm_remove_plugin(&id);
            // The confirm dialog has already closed (confirmed or not) by
            // the time this call returns — reset the clock now, not before,
            // so a `Focused(false)` queued while it had focus (processed
            // only once this callback returns control to the event loop)
            // doesn't hide the sheet on the very next tick.
            shown_at.set(Instant::now());
            if !confirmed {
                return; // Cancel, closed, or no dialog at all — never destructive by default
            }
            let dir = seed::plugins_dir();
            if let Some(path) = find_plugin_manifest_path(&dir, &id) {
                match std::fs::remove_file(&path) {
                    // Also drop this plugin's registry provenance record, if
                    // any — see `remove_lockfile_entry`'s own docs for why a
                    // later reinstall of the same id must not be diffed
                    // against a now-deleted file's stale origin_sha256.
                    Ok(()) => remove_lockfile_entry(&registry::lockfile_path(), &id),
                    Err(e) => diag::line(format!(
                        "could not remove plugin manifest {}: {e}",
                        path.display()
                    )),
                }
            } else {
                diag::line(format!(
                    "remove-plugin: no manifest file found for id \"{id}\""
                ));
            }
            // Drop this plugin's generic `plugin.<id>.*` config keys (enabled
            // / ping / surface.* / option.*) — leaving them behind would
            // survive forever and silently apply to a future plugin that
            // happens to reuse this id. Never touches the well-known
            // codex/claude bridge keys — see `config::remove_plugin_keys`.
            config::remove_plugin_keys(&id);
            cache.borrow_mut().remove(&id);
            fetching.borrow_mut().remove(&id);
            reload_and_fetch(&plugins, &fetching, &plugin_model, &tx);
            if let Some(app) = weak.upgrade() {
                refresh_model(
                    &app,
                    &model,
                    &plugins.borrow(),
                    &cache,
                    &window_models,
                    &balance_models,
                );
                sync_tray_indicator(
                    &tray,
                    app.get_menu_bar_text(),
                    &plugins.borrow(),
                    &cache,
                    &tray_key,
                );
            }
        });
    }
    {
        let shown_at = shown_at.clone();
        app.on_open_plugins_folder(move || {
            shown_at.set(Instant::now()); // Finder/the file manager steals focus
            open_in_file_manager(&seed::plugins_dir());
        });
    }

    // ── Registry (Check updates / Install / Update) ─────────────────────
    // "Check updates" is a manual, user-triggered action (never on a timer
    // or at launch — see `docs/PLUGIN-ARCHITECTURE.md`'s Transport section);
    // the network fetch runs on a background thread so it can never freeze
    // the popover, and its result is drained on the UI thread in the fast
    // event timer below (`apply_registry_check`), the same idiom as
    // `plugin_rx`.
    {
        let weak = app.as_weak();
        let tx = registry_tx.clone();
        app.on_check_updates(move || {
            if let Some(app) = weak.upgrade() {
                app.set_registry_status(1); // checking — flips the button to "Checking…"
            }
            let tx = tx.clone();
            std::thread::spawn(move || {
                let _ = tx.send(fetch_registry_index(DEFAULT_REGISTRY_URL));
            });
        });
    }
    {
        // Install a not-yet-installed registry plugin (its id comes off a
        // `registry-new` row). The `RegistryEntry` itself comes from the last
        // successful "Check updates" — an install click with no cached index
        // (or for an id that check no longer lists) is a no-op, since there
        // is nothing to fetch a manifest from.
        let registry_index_cache = registry_index_cache.clone();
        let registry_model = registry_model.clone();
        let registry_busy = registry_busy.clone();
        let tx = install_tx.clone();
        app.on_install_plugin(move |id| {
            let id = id.to_string();
            let Some(entry) = registry_index_cache
                .borrow()
                .as_ref()
                .and_then(|idx| idx.plugins.iter().find(|e| e.id == id).cloned())
            else {
                diag::line(format!(
                    "install-plugin: no cached registry entry for id \"{id}\" \
                     (run Check updates again)"
                ));
                return;
            };
            if !registry_busy.borrow_mut().insert(id.clone()) {
                return; // an install/update for this id is already in flight
            }
            set_registry_row_status(&registry_model, &id, 1, ""); // installing…
            let tx = tx.clone();
            std::thread::spawn(move || {
                let outcome = fetch_and_verify_manifest(DEFAULT_REGISTRY_URL, &entry);
                let _ = tx.send((PendingKind::Install, entry, outcome));
            });
        });
    }
    {
        // Update an already-installed plugin (its id is `PluginRow.id`,
        // whatever the plugin's *installed* id is — the entry that produced
        // it is looked up by that same id in the cached index).
        let plugins = plugins.clone();
        let plugin_model = plugin_model.clone();
        let registry_index_cache = registry_index_cache.clone();
        let registry_busy = registry_busy.clone();
        let tx = install_tx.clone();
        app.on_update_plugin(move |id| {
            let id = id.to_string();
            let Some(entry) = registry_index_cache
                .borrow()
                .as_ref()
                .and_then(|idx| idx.plugins.iter().find(|e| e.id == id).cloned())
            else {
                diag::line(format!(
                    "update-plugin: no cached registry entry for id \"{id}\" \
                     (run Check updates again)"
                ));
                return;
            };
            if !registry_busy.borrow_mut().insert(id.clone()) {
                return; // an install/update for this id is already in flight
            }
            set_plugin_update_status(&plugin_model, &plugins, &id, 1, ""); // updating…
            let tx = tx.clone();
            std::thread::spawn(move || {
                let outcome = fetch_and_verify_manifest(DEFAULT_REGISTRY_URL, &entry);
                let _ = tx.send((PendingKind::Update, entry, outcome));
            });
        });
    }

    // ── First readings ──────────────────────────────────────────────────
    if std::env::var_os("TICKOVER_SNAPSHOT").is_some() {
        // A screenshot needs data present synchronously, before the first
        // render — every plugin is fetched on this thread, blocking.
        *cache.borrow_mut() = sync_fetch_all(&plugins.borrow());
    } else {
        spawn_all_plugin_fetches(&plugins.borrow(), &plugin_tx, &fetching);
    }
    refresh_model(
        &app,
        &model,
        &plugins.borrow(),
        &cache,
        &window_models,
        &balance_models,
    );
    sync_tray_indicator(&tray, menubar_on, &plugins.borrow(), &cache, &tray_key);

    if std::env::var_os("TICKOVER_SHOW_ON_START").is_some() || platform::dock_mode() {
        present_popover(&app, &anchor, &shown_at, Shown::ByAnythingElse);
    }

    if let Some(path) = std::env::var_os("TICKOVER_SNAPSHOT") {
        present_popover(&app, &anchor, &shown_at, Shown::ByAnythingElse);
        // Snapshot the settings sheet instead of the gauges when asked.
        if std::env::var_os("TICKOVER_SNAPSHOT_SETTINGS").is_some() {
            app.set_settings_open(true);
        }
        let weak = app.as_weak();
        Timer::single_shot(Duration::from_millis(700), move || {
            // Not attempted on Windows. `take_snapshot` there returns a
            // fully transparent buffer — measured on both the femtovg and
            // the software renderer, with the window visible, sized and
            // drawn on screen at the time — so the only thing it can produce
            // is an empty PNG reported as a success. Worse, it sometimes
            // does not return at all: roughly one run in ten aborts inside
            // femtovg's `imgref` on `assertion failed: stride > 0`, and a
            // release build has `panic = "abort"`, so that is the process
            // gone. The window really is drawn — every screenshot of it on
            // this platform was captured off the screen — so that is what
            // the message points at.
            #[cfg(target_os = "windows")]
            {
                let _ = &weak;
                eprintln!(
                    "[tickover] TICKOVER_SNAPSHOT is not supported on Windows: the \
                     renderer hands back an empty image for a window it has drawn correctly. \
                     Capture the screen instead. Nothing written to {path:?}."
                );
            }
            #[cfg(not(target_os = "windows"))]
            if let Some(app) = weak.upgrade() {
                if let Ok(buf) = app.window().take_snapshot() {
                    let (w, h) = (buf.width(), buf.height());
                    if let Some(img) = image::RgbaImage::from_raw(w, h, buf.as_bytes().to_vec()) {
                        let _ = img.save(std::path::Path::new(&path));
                        diag::line(format!("snapshot {w}x{h} -> {path:?}"));
                    }
                }
            }
            let _ = slint::quit_event_loop();
        });
    }

    // ── Timers ──────────────────────────────────────────────────────────
    // Fast: drain tray/menu events + collect finished plugin fetches.
    let event_timer = Timer::default();
    {
        let weak = app.as_weak();
        let plugins = plugins.clone();
        let cache = cache.clone();
        let model = model.clone();
        let window_models = window_models.clone();
        let balance_models = balance_models.clone();
        let plugin_model = plugin_model.clone();
        let anchor = anchor.clone();
        let shown_at = shown_at.clone();
        let check = autostart_item.clone();
        let menubar_check = menubar_item.clone();
        let tray = tray.clone();
        let tray_key = tray_key.clone();
        let fetching = fetching.clone();
        let tx = plugin_tx.clone();
        let tray_click_at = tray_click_at.clone();
        let hidden_by_focus_at = hidden_by_focus_at.clone();
        let registry_model = registry_model.clone();
        let registry_index_cache = registry_index_cache.clone();
        let registry_busy = registry_busy.clone();
        let last_registry_check = last_registry_check.clone();
        // Rising-edge state for the "settings sheet just opened" reload
        // below — a plain `Cell`, mirroring `tick_timer`'s own `ticks` Cell.
        let settings_open_prev = Cell::new(false);
        event_timer.start(TimerMode::Repeated, Duration::from_millis(80), move || {
            let Some(app) = weak.upgrade() else { return };

            // The settings sheet has no Rust-side "opened" callback (frozen
            // Slint contract: `settings-open` is a plain `in-out` property
            // toggled directly by the gear/Close buttons — see
            // `ui/app.slint`). Polling it here and reacting to the
            // false→true edge is what picks up a manifest edited in the
            // external `edit-plugin` text editor (or dropped by hand into
            // the plugins folder) without needing that process to notify
            // this one. Manifests-only, deliberately no fetch — see
            // `reload_manifests_only`'s docs.
            let settings_open_now = app.get_settings_open();
            if settings_open_now && !settings_open_prev.get() {
                reload_manifests_only(&plugins, &plugin_model);
            }
            settings_open_prev.set(settings_open_now);

            // Plugin fetch results.
            let mut got = false;
            while let Ok((id, generation, plugin_readings)) = plugin_rx.try_recv() {
                // A result from a fetch this app gave up waiting on (see
                // `FETCH_PATIENCE`) belongs to a fetch that has since been
                // replaced: dropping it keeps it from clearing the in-flight
                // mark of the fetch now running, and from overwriting that
                // fetch's newer reading with an older one.
                if !result_is_current(fetching.borrow().get(&id).copied(), generation) {
                    continue;
                }
                fetching.borrow_mut().remove(&id);
                // Drop a result for a plugin disabled (or removed) while its
                // fetch was in flight, so a late landing can't resurface it.
                let manifest = plugins.borrow().iter().find(|m| m.id == id).cloned();
                let keep = manifest.as_ref().is_some_and(plugin_enabled);
                if keep {
                    // Before the insert, while the previous reading is still
                    // there to compare against — see `credentials_just_lost`.
                    for r in credentials_just_lost(
                        cache
                            .borrow()
                            .get(&id)
                            .map(Vec::as_slice)
                            .unwrap_or_default(),
                        &plugin_readings,
                    ) {
                        diag::line(format!(
                            "{} ({}) was on screen a moment ago and is hidden now: its \
                             credential chain came up empty. The row returns when a \
                             credential does.",
                            r.name, r.id
                        ));
                    }
                    cache.borrow_mut().insert(id, plugin_readings);
                    got = true;
                }
            }

            // "Check updates" results.
            while let Ok(msg) = registry_rx.try_recv() {
                apply_registry_check(
                    &app,
                    msg,
                    &plugins,
                    &plugin_model,
                    &registry_model,
                    &registry_index_cache,
                    &last_registry_check,
                );
            }

            // Install/Update fetch+verify results. The trust dialog (when
            // required) and the actual disk write both happen here, on the
            // UI thread — same idiom as `confirm_remove_plugin` blocking this
            // thread on a native dialog.
            while let Ok((kind, entry, outcome)) = install_rx.try_recv() {
                registry_busy.borrow_mut().remove(&entry.id);
                if handle_install_outcome(
                    kind,
                    entry,
                    outcome,
                    &plugins,
                    &plugin_model,
                    &registry_model,
                ) {
                    reload_and_fetch(&plugins, &fetching, &plugin_model, &tx);
                    got = true;
                }
                // Every path through `handle_install_outcome` may have shown
                // a native dialog (trust confirmation) that stole focus —
                // reset unconditionally, mirroring
                // `plugin-option-changed`'s own "costs nothing" comment.
                shown_at.set(Instant::now());
            }

            if got {
                refresh_model(
                    &app,
                    &model,
                    &plugins.borrow(),
                    &cache,
                    &window_models,
                    &balance_models,
                );
                sync_tray_indicator(
                    &tray,
                    app.get_menu_bar_text(),
                    &plugins.borrow(),
                    &cache,
                    &tray_key,
                );
            }

            while let Ok(event) = TrayIconEvent::receiver().try_recv() {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    rect,
                    ..
                } = event
                {
                    *anchor.borrow_mut() = Some((
                        rect.position.x,
                        rect.position.y,
                        rect.size.width as f64,
                        rect.size.height as f64,
                    ));
                    // This click owns whatever activation it causes.
                    let now = Instant::now();
                    tray_click_at.set(Some(now));
                    // Taken whatever the platform, so the mark cannot go
                    // stale and answer for a much later click.
                    let hidden_at = hidden_by_focus_at.take();
                    let dismissed = TRAY_CLICK_CAN_ARRIVE_AFTER_ITS_OWN_DISMISSAL
                        && tray_click_dismissed_panel(hidden_at, now);
                    if app.window().is_visible() {
                        let _ = app.window().hide();
                    } else if !dismissed {
                        spawn_all_plugin_fetches(&plugins.borrow(), &tx, &fetching);
                        refresh_model(
                            &app,
                            &model,
                            &plugins.borrow(),
                            &cache,
                            &window_models,
                            &balance_models,
                        );
                        present_popover(&app, &anchor, &shown_at, Shown::ByTrayClick);
                    }
                }
            }

            while let Ok(event) = MenuEvent::receiver().try_recv() {
                if event.id == refresh_id {
                    spawn_all_plugin_fetches(&plugins.borrow(), &tx, &fetching);
                    refresh_model(
                        &app,
                        &model,
                        &plugins.borrow(),
                        &cache,
                        &window_models,
                        &balance_models,
                    );
                    sync_tray_indicator(
                        &tray,
                        app.get_menu_bar_text(),
                        &plugins.borrow(),
                        &cache,
                        &tray_key,
                    );
                } else if event.id == autostart_id {
                    let actual = autostart::set(check.is_checked());
                    check.set_checked(actual);
                    app.set_autostart(actual);
                } else if event.id == menubar_id {
                    let enabled = menubar_check.is_checked();
                    config::set_menu_bar_text(enabled);
                    app.set_menu_bar_text(enabled);
                    sync_tray_indicator(&tray, enabled, &plugins.borrow(), &cache, &tray_key);
                } else if event.id == quit_id {
                    let _ = slint::quit_event_loop();
                }
            }
        });
    }

    // Slow: tick the countdowns every second; re-fetch each plugin on its own
    // `refresh_secs` cadence, and auto-ping shortly after a 5-hour window
    // resets.
    let tick_timer = Timer::default();
    {
        let weak = app.as_weak();
        let plugins = plugins.clone();
        let cache = cache.clone();
        let model = model.clone();
        let window_models = window_models.clone();
        let balance_models = balance_models.clone();
        let tray = tray.clone();
        let tray_key = tray_key.clone();
        let fetching = fetching.clone();
        let tx = plugin_tx.clone();
        let last_registry_check = last_registry_check.clone();
        let anchor = anchor.clone();
        let shown_at = shown_at.clone();
        let ticks = Cell::new(0u32);
        tick_timer.start(
            TimerMode::Repeated,
            Duration::from_millis(1000),
            move || {
                let Some(app) = weak.upgrade() else { return };
                let n = ticks.get().wrapping_add(1);
                ticks.set(n);

                for m in plugins.borrow().iter() {
                    if scheduler::due(n, m.refresh_secs) {
                        spawn_plugin_fetch(
                            m,
                            active_surface_ids(m),
                            plugin_options(m),
                            &tx,
                            &fetching,
                        );
                    }
                }

                refresh_model(
                    &app,
                    &model,
                    &plugins.borrow(),
                    &cache,
                    &window_models,
                    &balance_models,
                );
                // Cheap no-op unless data, theme, or the toggle actually changed.
                sync_tray_indicator(
                    &tray,
                    app.get_menu_bar_text(),
                    &plugins.borrow(),
                    &cache,
                    &tray_key,
                );

                let now = now_unix();

                // A second launch can't put a window on screen — it exits before
                // it has one — so it leaves a note instead, and this instance
                // answers the click that started it. Without this, launching the
                // app while it is already running does nothing whatsoever, which
                // looks exactly like an app that failed to start.
                if platform::take_show_request() && !app.window().is_visible() {
                    present_popover(&app, &anchor, &shown_at, Shown::ByAnythingElse);
                }

                // Keep "· checked <registry-checked-at>" live (Slint only ever
                // sees whatever string Rust last set — see the property's own
                // doc comment in `ui/app.slint`) — only meaningful once a check
                // has actually completed (`registry-status` 4 "up to date" or 5
                // "results"; idle/checking/error render their own line instead).
                if let Some(checked) = last_registry_check.get() {
                    let status = app.get_registry_status();
                    if status == 4 || status == 5 {
                        app.set_registry_checked_at(ss(relative_checked_at(
                            now.saturating_sub(checked),
                        )));
                    }
                }

                // Auto-ping a plugin's first-surface 5-hour window while it sits
                // empty (opt-in per plugin, one ping per window — see
                // [`ping_target`] for why this is a state and not an edge). Only
                // an enabled plugin arms it — a disabled one is skipped even if it
                // still declares `[ping]`.
                let current = readings(&plugins.borrow(), &cache.borrow());
                // Remember the newest reset every provider states, while it is
                // still stating one: once a window empties, a provider like Codex
                // reports it not at all, and the registry is then the only record
                // of where its boundary was. Runs before the ping loop below and
                // outside its `[ping]` filter, so the boundary is there for the
                // panel's hysteresis and for a ping toggle switched on later —
                // under that filter, a manifest without a `[ping]` section (every
                // third-party one) recorded nothing at all.
                //
                // Scoped because the borrow is held across a loop rather than for a
                // single statement. Nothing else in this tick takes the manifest
                // set mutably today; a reload added later (`*plugins.borrow_mut() =
                // load_plugins()`, as the settings sheet does) would panic rather
                // than fail to compile, so the block keeps the region it could
                // happen in as small as the loop that needs it.
                {
                    let ps = plugins.borrow();
                    record_seen_windows(&ps, &current);
                    for m in ps.iter().filter(|m| m.ping.is_some() && plugin_enabled(m)) {
                        let Some(first_id) = first_surface_reading_id(m) else {
                            continue;
                        };
                        let Some(window) =
                            ping_window(m, current.iter().find(|r| r.id == first_id))
                        else {
                            continue;
                        };
                        // `seen_window_for`, not `seen_window_of`: this loop already
                        // holds the manifest, and the registry key is namespaced by
                        // the *owner's* id, so asking with `m` reads exactly the key
                        // `record_seen_windows` wrote for it. Going back through the
                        // reading id would run the inverse again only to have it
                        // answer `None` for a reading id two manifests both claim —
                        // costing this provider its auto-ping over a collision the
                        // panel is right to be cautious about and the ping need not
                        // be.
                        let seen = seen_window_for(m, &first_id, Role::Primary).map_or(0, |s| s.at);
                        if !plugin_ping_armed(plugin_enabled(m), config::plugin_ping(&m.id)) {
                            continue;
                        }
                        if !ping_due(
                            window.used_percent,
                            window.resets_at,
                            window.period_minutes,
                            seen,
                            config::plugin_pinged_at(&m.id),
                            now,
                        ) {
                            continue;
                        }
                        // Recorded first, and the command run on this same tick. There
                        // is deliberately no delay between the two: a gap is a window
                        // in which the app can be quit with the ping recorded and never
                        // sent, which on-disk state would then remember for good.
                        config::set_plugin_pinged_at(&m.id, now);
                        send_ping(m.ping.as_ref().expect("filtered by ping.is_some() above"));
                    }
                }
            },
        );
    }

    Timer::single_shot(Duration::from_millis(60), platform::set_accessory_policy);

    // Dock mode: clicking the Dock icon of a running app is an app-level
    // reopen that never reaches the winit event loop, so a hidden panel would
    // stay hidden with no way back. Watch the activation flag's rising edge
    // instead — an edge, not the level, so hiding the window while the app is
    // still frontmost doesn't immediately re-present it.
    //
    // `panel_target_visibility` resolves each tick to a single target state
    // rather than reacting per event, because several clicks can land inside
    // one interval and their order is not recoverable afterwards.
    let reopen_timer = Timer::default();
    if platform::dock_mode() {
        let weak = app.as_weak();
        let anchor = anchor.clone();
        let shown_at = shown_at.clone();
        let was_active = Cell::new(platform::app_is_active());
        let handler_ready = Cell::new(false);
        let tray_click_at = tray_click_at.clone();
        // Short enough that a Dock click feels immediate; the tick is one
        // atomic read plus one `isActive` message, so it costs nothing.
        reopen_timer.start(TimerMode::Repeated, Duration::from_millis(120), move || {
            // winit sets the delegate once the loop is running, so keep trying
            // until it exists.
            if !handler_ready.get() {
                handler_ready.set(platform::install_reopen_handler());
            }
            let active = platform::app_is_active();
            // An activation the status item caused is that click's business:
            // the tray handler has already toggled the panel, and treating the
            // same click as a Dock reopen would toggle it straight back.
            let by_tray = activation_owned_by_tray(tray_click_at.get(), Instant::now());
            let became_active = active && !was_active.replace(active) && !by_tray;
            let Some(app) = weak.upgrade() else { return };
            let clicks = platform::take_reopen_requests();
            let visible = app.window().is_visible();

            let want_visible = panel_target_visibility(became_active, clicks, visible);
            if want_visible && !visible {
                present_popover(&app, &anchor, &shown_at, Shown::ByAnythingElse);
            } else if !want_visible && visible {
                let _ = app.window().hide();
            }
        });
    }

    slint::run_event_loop_until_quit()?;
    Ok(())
}

// ── Plugin loading ────────────────────────────────────────────────────────

/// Load every plugin manifest from the plugins directory, in the order
/// `plugin::manifest::load_dir` sorts them (`order`, ties by `id`). A thin,
/// non-test wrapper around [`load_plugins_from`] — see that function's docs
/// for what "pure read" means and why it matters.
fn load_plugins() -> Vec<PluginManifest> {
    load_plugins_from(&seed::plugins_dir())
}

/// Bring untouched copies of the built-in manifests up to the version this
/// build ships, once per shipped version.
///
/// Seeding only ever fires on a machine with no manifests at all, so without
/// this an existing install keeps whatever it was first given — including a
/// Codex manifest that reads rollout logs whose figures this app now knows to
/// be unreliable. A manifest the user has edited is never touched: their file
/// stays theirs, and the decision is recorded either way so a deliberate
/// rollback isn't quietly undone on the next launch (see
/// `plugin::seed::BUILTIN_UPGRADES`).
fn upgrade_builtin_manifests(dir: &std::path::Path) {
    for upgrade in seed::BUILTIN_UPGRADES {
        // Every launch, not once: the remembered "plan tier -> address" cache
        // is dead weight now that the provider states the address, and an
        // older build of this app still running alongside a new one writes it
        // straight back after a one-time cleanup — leaving an email address
        // sitting in a config file for no reason. Costs a read; writes only if
        // the key is actually there.
        config::forget_remembered_accounts(upgrade.id);
        if config::builtin_migrated(upgrade.id).as_deref() == Some(upgrade.to_version) {
            // The decision stands — but say so when there is nothing to show
            // for it. This was the one branch of the loop that wrote no line
            // anywhere: Replace, Delivered and the failed write all speak, and
            // "already settled" was silent, so "why is this provider not in
            // the panel?" had no answer in the log at all. It cost a shipped
            // manifest exactly once, on 22.08: a test run under the real HOME
            // wrote this function's `builtin_migrated` marker into a live
            // install while the manifests it seeded went to a temp dir, which
            // would have kept a shipped manifest from ever being delivered.
            if let Some(note) = decided_yet_absent(dir, upgrade) {
                diag::line(note);
            }
            continue;
        }
        match seed::upgrade_builtin(dir, upgrade) {
            Ok(action) => {
                if action == seed::UpgradeAction::Replace {
                    diag::line(format!(
                        "updated the built-in {} to {}",
                        upgrade.file, upgrade.to_version
                    ));
                }
                // A provider that was not there before, rather than one that
                // changed — worth its own sentence in the log, since what the
                // user will notice is a new section in the panel.
                if action == seed::UpgradeAction::Delivered {
                    diag::line(format!(
                        "added the built-in {} ({})",
                        upgrade.file, upgrade.to_version
                    ));
                }
                // The same sentence at the moment the decision is taken, so
                // the launch that settles it reads like every later one. This
                // is a built-in that ships `deliver_if_absent = false` and
                // isn't there: nothing was written and nothing will be.
                if action == seed::UpgradeAction::Absent {
                    if let Some(note) = decided_yet_absent(dir, upgrade) {
                        diag::line(note);
                    }
                }
                config::set_builtin_migrated(upgrade.id, upgrade.to_version);
            }
            // A write that failed is not a decision: leave the marker unset so
            // the next launch tries again rather than skipping the upgrade for
            // good.
            Err(e) => diag::line(format!(
                "could not update the built-in {}: {e}",
                upgrade.file
            )),
        }
    }
}

/// The line for a built-in this install has settled and has no file for —
/// `None` when the file is there, which is the ordinary case and says nothing.
///
/// Deliberately a **statement, not a warning**. The state is legitimate far
/// more often than not: deleting a delivered manifest is supposed to stick,
/// and `deliver_if_absent` plus the marker exist to make it stick. What the
/// line is for is the case nobody chose — a `config.json` carried to another
/// machine brings its markers along, and `seed_if_empty` stands down as soon
/// as the folder holds any `*.toml` at all, so a single third-party manifest
/// there is enough for the built-ins to never arrive and never be mentioned.
///
/// Every launch rather than once. A note that fires only on the launch that
/// created the state is a note the person investigating a week later cannot
/// see, and this is written for exactly that reader. The cost is bounded by
/// the size of `BUILTIN_UPGRADES` — at most one line per shipped manifest, once
/// per launch of a desktop app that starts at login — and a healthy install
/// prints none at all.
///
/// It speaks about the **file**, not about the provider, and the sentence says
/// so: `id` is not checked, only `file`. A user who renamed the manifest or
/// dropped in their own under the same name has a working provider, and this
/// line saying that `codex.toml` is not there is still true of the file. The
/// alternative — "provider X is missing" — would need the loaded manifest set,
/// which does not exist yet at this point in startup, and would be the claim
/// that is actually wrong in both of those cases.
///
/// The `exists` check on the `Absent` outcome, where the caller already knows
/// the file was not read, is not redundant: `seed::upgrade_builtin` answers
/// `Absent` for anything `read_regular_file` refuses, a directory at that path
/// included, and "not in the plugins folder" would then be false.
fn decided_yet_absent(dir: &std::path::Path, upgrade: &seed::BuiltinUpgrade) -> Option<String> {
    if dir.join(upgrade.file).exists() {
        return None;
    }
    Some(absent_note(upgrade))
}

/// The sentence itself, without asking the filesystem anything.
///
/// Split from [`decided_yet_absent`] so a test can say what the log must *not*
/// contain. Asking that of `decided_yet_absent` is impossible by construction —
/// it answers `None` for the file that is there — so the negative half of the
/// test had drifted into asserting that `exists()` works, and a `diag::line`
/// hoisted out of its `if let` would have filled a healthy install's log with
/// "not in the plugins folder" on every launch with the test still green.
///
/// The advice names its side effect. "Reset plugins" writes every shipped
/// manifest unconditionally (`seed::reseed_defaults`), so telling someone to
/// press it to get one file back, without saying it overwrites the edits they
/// made to the others, is advice that costs them something.
fn absent_note(upgrade: &seed::BuiltinUpgrade) -> String {
    format!(
        "{} ({}) is not in the plugins folder and this install has already had its \
         say — not putting it back. \"Reset plugins\" restores every shipped \
         manifest, overwriting edits.",
        upgrade.file, upgrade.to_version
    )
}

/// Load every plugin manifest directly inside `dir`. An invalid manifest is
/// logged and skipped — one broken third-party `.toml` must never take the
/// whole app down. A manifest whose `id` duplicates an earlier one is
/// dropped too (see [`dedup_plugin_ids`]) — two manifests sharing one id
/// would otherwise share (and clobber) that id's single `PluginCache` slot.
///
/// Deliberately a **pure directory read** — it never seeds the built-in
/// Codex/Claude manifests. Seeding happens exactly once, in `main`, before
/// the very first call to this function; the only other place the built-ins
/// get (re)written is the explicit "Reset plugins" action
/// (`plugin::seed::reseed_defaults`). This matters because this function is
/// also what every reload path (`reload_manifests_only`, run on every
/// settings-sheet open) calls: if it seeded an empty directory, deleting the
/// last plugin manifest and reopening Settings would silently resurrect
/// codex/claude — which is exactly the bug this split fixes.
///
/// A plugin's enable state is **not** applied here: a disabled plugin still
/// belongs to the loaded set (so the manager can list and re-enable it), it
/// is merely skipped at fetch ([`spawn_plugin_fetch`]/[`sync_fetch_all`]) and
/// hidden from [`readings`] because its cache slot stays empty.
fn load_plugins_from(dir: &std::path::Path) -> Vec<PluginManifest> {
    diag::line(format!(
        "loading plugin manifests from {} ({})",
        dir.display(),
        std::fs::read_dir(dir)
            .map(|entries| {
                let mut names: Vec<String> = entries
                    .filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect();
                names.sort();
                names.join(", ")
            })
            .unwrap_or_else(|e| format!("unreadable: {e}"))
    ));
    let manifests: Vec<PluginManifest> = manifest::load_dir(dir)
        .into_iter()
        .filter_map(|result| match result {
            Ok(m) => Some(m),
            Err((path, msg)) => {
                diag::line(format!(
                    "skipping invalid plugin manifest {}: {msg}",
                    path.display()
                ));
                None
            }
        })
        .collect();
    let manifests = dedup_plugin_ids(manifests);
    for id in colliding_reading_ids(&manifests) {
        diag::line(format!(
            "two plugin manifests both claim the reading id \"{id}\" (a plugin id and another \
             plugin's id-plus-surface can spell the same thing); neither will remember its quota \
             windows — no \"not started\" row and no auto-ping boundary — until one is renamed or \
             removed"
        ));
    }
    manifests
}

/// Reading ids more than one manifest claims, which [`owning_manifest`]
/// deliberately refuses to resolve. Pure so the rule is testable; the caller
/// logs, because a feature that switches itself off has to say so — the two
/// providers involved keep working in every other respect, so there is nothing
/// on screen to notice.
fn colliding_reading_ids(manifests: &[PluginManifest]) -> Vec<String> {
    let mut claims: BTreeMap<String, usize> = BTreeMap::new();
    for m in manifests {
        // Counted once per manifest: one manifest declaring two surfaces that
        // spell the same reading id is its own bug, not a collision between
        // plugins, and it must not report itself as one.
        let own: HashSet<String> = m
            .surface
            .iter()
            .map(|s| surface_reading_id(&m.id, &s.id))
            .collect();
        for id in own {
            *claims.entry(id).or_default() += 1;
        }
    }
    claims
        .into_iter()
        .filter(|(_, claimants)| *claimants > 1)
        .map(|(id, _)| id)
        .collect()
}

/// Drop every manifest after the first with a given `id`. `manifests` is
/// already sorted by `order`, ties by `id` (see `plugin::manifest::load_dir`),
/// so "first" here is well-defined and stable — the lowest-`order` (then
/// lowest-`id`) manifest always wins a duplicate. Runs over every
/// successfully-parsed manifest regardless of `enabled`, so a disabled
/// well-known manifest still shadows a stray third-party one claiming the
/// same id. Split out from [`load_plugins`] so the dedup rule itself is a
/// pure, directly testable function.
fn dedup_plugin_ids(manifests: Vec<PluginManifest>) -> Vec<PluginManifest> {
    let ids: Vec<String> = manifests.iter().map(|m| m.id.clone()).collect();
    let mut seen: HashSet<String> = HashSet::new();
    manifests
        .into_iter()
        .filter(|m| {
            if seen.insert(m.id.clone()) {
                true
            } else {
                // The version and the whole loaded set, because the message
                // without them is unactionable: it says a duplicate arrived
                // and nothing about where from, and a folder holding one file
                // per id can still produce one if something loads twice.
                diag::line(format!(
                    "ignoring plugin manifest with duplicate id \"{}\" version \"{}\" (keeping the first one loaded); loaded set was [{}]",
                    m.id,
                    m.version,
                    ids.join(", ")
                ));
                false
            }
        })
        .collect()
}

fn plugin_by_id<'a>(plugins: &'a [PluginManifest], id: &str) -> Option<&'a PluginManifest> {
    plugins.iter().find(|m| m.id == id)
}

// ── Plugin manager actions: reload / add / edit / remove ──────────────────
//
// The manager (settings sheet) lets the user manage manifests as *files* on
// disk, not just config toggles: add one via a native file picker, open one
// in a text editor, remove one after a native confirm. None of that needs a
// new dependency. macOS reaches all three through `osascript` (AppleScript);
// Windows reaches them through the SDK the `windows` crate already binds for
// the Claude desktop token — `MessageBoxW` and `GetOpenFileNameW`. An
// `rfd`-style dialog crate was considered and rejected on that basis: it
// would add a dependency for a handful of one-liners that are already
// written, on both platforms.

/// Reload every plugin manifest from disk (**no reseed** — that's what
/// `reset-plugins` is for; `load_plugins` is a pure read, see its own docs)
/// and rebuild the plugin-manager model. `load_plugins` only reads local TOML
/// files, so this never touches the network — safe to call on every
/// settings-sheet open (see the `settings-open` rising-edge check in the fast
/// timer) without adding a surprise network hit just for opening a sheet, and
/// safe to call after the last plugin manifest was deleted without
/// resurrecting the built-ins.
fn reload_manifests_only(plugins: &Plugins, plugin_model: &PluginRows) {
    *plugins.borrow_mut() = load_plugins();
    refresh_plugins_model(plugin_model, &plugins.borrow());
}

/// [`reload_manifests_only`] plus a fresh fetch of every (enabled) plugin —
/// used after add/remove, where the plugin set just changed and its rows
/// should show real data without waiting for the next scheduled tick, rather
/// than the cheaper manifests-only reload used merely for opening the
/// settings sheet.
fn reload_and_fetch(
    plugins: &Plugins,
    fetching: &Fetching,
    plugin_model: &PluginRows,
    tx: &mpsc::Sender<(String, u64, Vec<ProviderReading>)>,
) {
    reload_manifests_only(plugins, plugin_model);
    // Clear in-flight markers so a fetch still running against the pre-reload
    // manifest set can't dedupe away the fresh one spawned below — mirrors
    // `reset-plugins`'s own comment on the same race.
    fetching.borrow_mut().clear();
    spawn_all_plugin_fetches(&plugins.borrow(), tx, fetching);
}

/// `add-plugin`'s intended write target for a newly-imported manifest's
/// `id`: `<dir>/<id>.toml`, but only if that path actually resolves *inside*
/// `dir` once both sides are canonicalized. Defence in depth alongside the
/// `id` charset check in `plugin::manifest::validate` (which already forbids
/// `/`, `..` and the like) — this check doesn't trust that validation alone;
/// it re-derives containment from the filesystem itself, so a future change
/// that constructs a `PluginManifest` some other way can't silently reopen
/// the path-traversal hole. Canonicalizing `dir` matters even for a
/// perfectly safe `id`: on macOS the OS config dir sits under a symlink
/// (`/var/folders/...` or `/tmp` → `/private/tmp`), so comparing raw paths
/// would reject every legitimate call. Fails closed: `None` if `dir` doesn't
/// exist yet, or if the resolved parent doesn't canonicalize to `dir` (either
/// because `id` tried to escape, or for any other reason canonicalization
/// can't complete) — callers must treat `None` as "refuse to write", never as
/// "fall back to something else".
fn plugin_manifest_target(dir: &std::path::Path, id: &str) -> Option<std::path::PathBuf> {
    let target = dir.join(format!("{id}.toml"));
    let dir_canon = dir.canonicalize().ok()?;
    let target_parent = target.parent()?;
    let target_parent_canon = target_parent.canonicalize().ok()?;
    if target_parent_canon != dir_canon {
        return None;
    }
    Some(target)
}

/// The on-disk path of a loaded plugin's manifest file. `load_dir` doesn't
/// retain an id → path mapping once manifests are merged into [`Plugins`]
/// (see its own docs), and re-deriving it here — only needed for the
/// occasional edit/remove click, never the hot fetch path — is simpler than
/// threading a path field through every manifest everywhere else: re-scan
/// `dir` and match each `*.toml`'s *parsed* `id`, which is authoritative
/// (unlike the filename, which is only a convention).
///
/// Deliberately **no blind `<id>.toml` fallback** when nothing in the
/// directory actually parses to this id right now: `remove-plugin` deletes
/// whatever path this returns, and a fallback-by-filename would risk
/// deleting the *wrong* file on an id collision, or (before the `id` charset
/// was validated — see `plugin::manifest::validate`) let a hostile `id`
/// resolve to a path outside `dir` entirely. `None` here means "don't touch
/// anything" for both callers (`edit-plugin` logs and gives up; `remove-plugin`
/// does the same) — safer than guessing. One accepted regression: a manifest
/// broken badly enough that it no longer parses can no longer be reopened via
/// `edit-plugin` to fix it by its conventional filename; the plugins folder
/// (`open-plugins-folder`) is still reachable for that case.
fn find_plugin_manifest_path(dir: &std::path::Path, id: &str) -> Option<std::path::PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(m) = PluginManifest::from_str(&text) {
                if m.id == id {
                    return Some(path);
                }
            }
        }
    }
    None
}

/// Drop a removed plugin's provenance record from the registry lockfile at
/// `path` — the registry-state.json counterpart of
/// `config::remove_plugin_keys`'s cleanup-on-delete role for `config.json`.
/// Without this, reinstalling the same `id` by hand later would keep the
/// stale `origin_sha256` from the deleted install around, making
/// `registry::diff_installed`'s local-edits/overwrite-safe verdict for the
/// new install wrong (it would be diffed against bytes that no longer exist
/// on disk at all). No-op — never even opens the file for writing — when
/// there's no record for `id` (nothing to clean up) or no lockfile at all
/// yet (`RegistryLockState::get` on the default-empty state), so a plugin
/// that was never installed via the registry doesn't spuriously create an
/// empty `registry-state.json`. `path` is a parameter (rather than this
/// function calling `registry::lockfile_path()` itself) purely so it's
/// testable against a tempdir instead of the real lockfile — the caller
/// (`remove-plugin`) passes the real path.
fn remove_lockfile_entry(path: &std::path::Path, id: &str) {
    let mut lock = registry::load_lockfile(path);
    if lock.get(id).is_none() {
        return;
    }
    lock.remove(id);
    if let Err(e) = registry::save_lockfile(path, &lock) {
        diag::line(format!(
            "could not save registry lockfile {}: {e}",
            path.display()
        ));
    }
}

/// Reveal the plugin manifests directory in the OS file manager.
fn open_in_file_manager(dir: &std::path::Path) {
    let _ = std::fs::create_dir_all(dir); // best effort, so there is something to open
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(dir).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("explorer").arg(dir).spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(dir).spawn();
    }
}

/// Open one manifest file in the user's default *text* editor. `open -t`
/// (macOS) forces a text-editor handler even if `.toml` happens to be
/// associated with something else; the other platforms have no equivalent
/// flag, so they fall back to the same "open with whatever's registered"
/// launcher used for the folder above — good enough for a manifest that is,
/// after all, a plain-text file.
fn open_in_text_editor(path: &std::path::Path) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open")
            .arg("-t")
            .arg(path)
            .spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("notepad").arg(path).spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(path).spawn();
    }
}

/// Escape a string for embedding inside an AppleScript double-quoted string
/// literal (`"` and `\` are the whole alphabet AppleScript string literals
/// care about). Defence-in-depth: a plugin id is free text — the manifest
/// schema only requires it non-empty (see `plugin::manifest::validate`) — so
/// it must never be able to break out of the `display dialog`/`display
/// alert` string it gets interpolated into.
#[cfg(any(target_os = "macos", test))]
fn applescript_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            // Backslash first, always: escaping the quote first would then
            // double every backslash this step just added.
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            // A raw newline cannot appear inside an AppleScript string
            // literal — the script becomes a syntax error, osascript exits
            // non-zero, and every dialog here reads that as "not approved".
            // Failing closed is right, but a manifest could then suppress its
            // own disclosure by putting a newline in the text, and the user
            // would see nothing at all rather than the thing they should be
            // deciding about. Escaped, it stays inside the literal and gets
            // shown.
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Anything else below space has no AppleScript escape and no
            // business in a dialog.
            c if (c as u32) < 0x20 => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// Best-effort native "something went wrong" alert. A failure to put anything
/// on screen at all is swallowed — the `eprintln!` logged next to every call
/// site is the fallback a developer (not the user) can see.
fn show_alert(title: &str, message: &str) {
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            r#"display alert "{}" message "{}""#,
            applescript_escape(title),
            applescript_escape(message)
        );
        let _ = std::process::Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .output();
    }
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::UI::WindowsAndMessaging::{MB_ICONWARNING, MB_OK};
        let _ = windows_message_box(title, message, MB_OK | MB_ICONWARNING);
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = (title, message);
    }
}

/// Native "are you sure?" gate for a destructive remove, run synchronously on
/// the calling (UI) thread. `remove-plugin` fires with no confirmation of its
/// own by design (see the callback's doc comment in `ui/app.slint`) — this is
/// the only thing standing between one click and a deleted manifest file.
/// Each platform's own dialog rather than a crate that draws one: a native
/// dialog is indistinguishable from a Slint-drawn one to the user, and both
/// platforms already ship what this needs (`osascript` here, `MessageBoxW`
/// there — see [`windows_message_box`]).
///
/// Any failure to get an answer at all (no display, a missing binary, an API
/// that returned nothing) is treated as "not confirmed", never as
/// "confirmed", so a broken environment fails safe — see [`confirm_parse`]
/// for the pure part of this.
fn confirm_remove_plugin(id: &str) -> bool {
    let prompt = format!("Remove plugin \"{id}\"? Its .toml file will be deleted.");
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            r#"display dialog "{}" buttons {{"Cancel","Remove"}} default button "Cancel" cancel button "Cancel" with icon caution"#,
            applescript_escape(&prompt)
        );
        match std::process::Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .output()
        {
            Ok(out) if out.status.success() => confirm_parse(&String::from_utf8_lossy(&out.stdout)),
            _ => false, // Cancel, window closed, or osascript missing/failed
        }
    }
    #[cfg(target_os = "windows")]
    {
        // Yes/No rather than Cancel/Remove: a message box's buttons are the
        // ones Windows gives it, and the alternative — the abort/retry/ignore
        // set — names nothing a user would recognise as removing a plugin.
        // The prompt says what "Yes" does, which is what the button labels
        // were carrying on macOS.
        use windows::Win32::UI::WindowsAndMessaging::{
            IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_YESNO,
        };
        windows_message_box(
            "Remove plugin",
            &prompt,
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2,
        ) == Some(IDYES)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = prompt;
        false
    }
}

/// One native message box, returning the clicked button's `ID*` constant —
/// `None` when the box could not be shown at all, which every caller reads
/// the same way it reads a Cancel.
///
/// `MB_TOPMOST` because the popover this is raised over sets its own window
/// level to always-on-top (see [`present_popover`]); without it the dialog
/// can open *behind* the card that prompted it, leaving a UI thread blocked
/// on a window the user cannot see. `MB_SETFOREGROUND` for the same reason
/// one level up — the app may not be the foreground process when a fetch
/// result lands and asks for approval.
#[cfg(target_os = "windows")]
fn windows_message_box(
    title: &str,
    message: &str,
    style: windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_STYLE,
) -> Option<windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_RESULT> {
    use windows::core::PCWSTR;
    use windows::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, MB_SETFOREGROUND, MB_TOPMOST, MESSAGEBOX_RESULT,
    };

    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let (text, caption) = (wide(message), wide(title));
    let result = unsafe {
        MessageBoxW(
            None,
            PCWSTR(text.as_ptr()),
            PCWSTR(caption.as_ptr()),
            style | MB_TOPMOST | MB_SETFOREGROUND,
        )
    };
    // Zero is the documented "could not create the dialog" answer (out of
    // memory, or no window station to put it on). It is not a button, so it
    // must not be compared against one.
    (result != MESSAGEBOX_RESULT(0)).then_some(result)
}

/// Pure parse of `display dialog`'s stdout when a button was clicked
/// ("button returned:Remove" on success, part of a comma-joined AppleEvent
/// record that may carry other fields too — e.g. "button returned:Remove,
/// gave up:false" when a timeout parameter is present). `contains`, not an
/// exact match, so this survives that record growing a field this build
/// doesn't otherwise use; it still can never match the Cancel button's own
/// text, so an unrecognized or unexpected format stays "not confirmed" —
/// never accidentally authorizing a delete.
#[cfg(any(target_os = "macos", test))]
fn confirm_parse(stdout: &str) -> bool {
    stdout.contains("button returned:Remove")
}

/// Native "choose a `.toml` file" dialog, returning the picked path.
/// `None` on Cancel, a closed window, or the dialog failing to open at all —
/// the same fail-safe stance as [`confirm_remove_plugin`] (never invents a
/// path to import).
fn pick_toml_file() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let script = r#"POSIX path of (choose file with prompt "Choose a plugin .toml file" of type {"toml"})"#;
        let out = std::process::Command::new("osascript")
            .arg("-e")
            .arg(script)
            .output()
            .ok()?;
        if !out.status.success() {
            return None; // user cancelled, or osascript itself failed
        }
        parse_choose_file_output(&String::from_utf8_lossy(&out.stdout))
    }
    #[cfg(target_os = "windows")]
    {
        windows_pick_toml_file()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

/// The common-dialog file picker, filtered to `.toml`.
///
/// `OFN_NOCHANGEDIR` is not optional: without it the dialog leaves the
/// *process* sitting in whatever directory the user browsed to, and every
/// relative path this app resolves afterwards would follow it there.
/// `OFN_FILEMUSTEXIST` keeps a typed-in name that names nothing from coming
/// back as a path to import.
#[cfg(target_os = "windows")]
fn windows_pick_toml_file() -> Option<std::path::PathBuf> {
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::UI::Controls::Dialogs::{
        GetOpenFileNameW, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST, OPENFILENAMEW,
    };

    // A filter is a run of null-separated label/pattern pairs closed by a
    // second null — not a string with separators in it, so it is spelled out
    // as UTF-16 with the nulls in place rather than built with `wide()`.
    let filter: Vec<u16> = "Plugin manifest (*.toml)\0*.toml\0All files (*.*)\0*.*\0\0"
        .encode_utf16()
        .collect();
    let title: Vec<u16> = "Choose a plugin .toml file\0".encode_utf16().collect();
    // The buffer is the only place the answer can land, and a path can be up
    // to 32767 UTF-16 units. Sized for that rather than MAX_PATH, so a file
    // under a deep path is pickable instead of silently truncated.
    let mut file = vec![0u16; 32768];

    let mut ofn = OPENFILENAMEW {
        lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
        lpstrFilter: PCWSTR(filter.as_ptr()),
        lpstrFile: PWSTR(file.as_mut_ptr()),
        nMaxFile: file.len() as u32,
        lpstrTitle: PCWSTR(title.as_ptr()),
        Flags: OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
        ..Default::default()
    };
    // FALSE is both "cancelled" and "failed to open"; neither is a path.
    if !unsafe { GetOpenFileNameW(&mut ofn) }.as_bool() {
        return None;
    }
    let len = file.iter().position(|&c| c == 0).unwrap_or(file.len());
    parse_picked_path(&String::from_utf16_lossy(&file[..len]))
}

/// Pure part of the Windows picker: the buffer's contents as a path, or
/// `None` when there is nothing usable in it. Split out so the same
/// "never turn nothing into a path" rule as [`parse_choose_file_output`] is
/// testable without a dialog on screen.
#[cfg(any(target_os = "windows", test))]
fn parse_picked_path(raw: &str) -> Option<std::path::PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(trimmed))
    }
}

/// Pure parse of `choose file`'s stdout on success (the raw POSIX path,
/// trailing newline). Never trust external process output blindly: empty
/// output (shouldn't happen on a successful exit, but might) yields `None`
/// rather than an empty path.
#[cfg(any(target_os = "macos", test))]
fn parse_choose_file_output(stdout: &str) -> Option<std::path::PathBuf> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(trimmed))
    }
}

// ── Plugin state (generic over id) ───────────────────────────────────────

/// Whether a plugin is currently enabled — its config override if the user
/// set one, else the manifest's own `enabled` (precedence config > manifest).
/// The well-known-id bridge for the legacy config keys lives entirely in
/// [`config`]; nothing here hard-codes a plugin id.
fn plugin_enabled(m: &PluginManifest) -> bool {
    config::plugin_enabled(&m.id, m.enabled)
}

// ── Active surfaces ──────────────────────────────────────────────────────

/// Which of a plugin's surfaces are active right now: every non-opt-in
/// surface always, an opt-in one only when the user has enabled it (per
/// plugin/surface, via [`config::plugin_surface_enabled`] — which bridges the
/// legacy `monitor_desktop` key for Claude's desktop surface). Manifest
/// surface order is preserved.
fn active_surface_ids(m: &PluginManifest) -> Vec<String> {
    m.surface
        .iter()
        .filter(|s| !s.opt_in || config::plugin_surface_enabled(&m.id, &s.id))
        .map(|s| s.id.clone())
        .collect()
}

// ── Plugin options ────────────────────────────────────────────────────────

/// Every `[[option]]` a plugin declares, resolved to its current value
/// ([`config::plugin_option`]: config override if the user set one, else the
/// manifest's own `default`). `BTreeMap` for the deterministic iteration
/// order [`crate::plugin::substitute_options`] relies on. Read once per fetch
/// (mirrors [`active_surface_ids`]) and passed straight into
/// [`scheduler::fetch`] — the engines never read config themselves (see their
/// module docs).
fn plugin_options(m: &PluginManifest) -> BTreeMap<String, bool> {
    m.option
        .iter()
        .map(|opt| {
            (
                opt.key.clone(),
                config::plugin_option(&m.id, &opt.key, opt.default),
            )
        })
        .collect()
}

// ── Fetch scheduling ─────────────────────────────────────────────────────

/// Kick off a background fetch for one plugin, unless it is disabled, or a
/// fetch is already in flight for it (dedup by plugin id — generalizes the
/// old `spawn_claude_fetch`'s single `fetching` flag to any number of
/// plugins). `active_surface_ids`/`options` are resolved by the caller at
/// spawn time — the same instant a fetch is decided to happen — not inside
/// the background thread, so a config change mid-flight can't retroactively
/// alter an already-dispatched fetch.
fn spawn_plugin_fetch(
    m: &PluginManifest,
    active_surface_ids: Vec<String>,
    options: BTreeMap<String, bool>,
    tx: &mpsc::Sender<(String, u64, Vec<ProviderReading>)>,
    fetching: &Fetching,
) {
    if !plugin_enabled(m) {
        return; // disabled plugins are never fetched
    }
    let generation = next_fetch_generation();
    {
        let mut in_flight = fetching.borrow_mut();
        let elapsed = in_flight.get(&m.id).map(|f| f.started.elapsed());
        match admit_fetch(elapsed, FETCH_PATIENCE) {
            Admission::Wait => return,
            Admission::Replace => diag::line(format!(
                "plugin \"{}\": fetch still running after {}s — starting a fresh one",
                m.id,
                FETCH_PATIENCE.as_secs()
            )),
            Admission::Start => {}
        }
        in_flight.insert(
            m.id.clone(),
            InFlight {
                generation,
                started: Instant::now(),
            },
        );
    }
    let manifest = m.clone();
    let tx = tx.clone();
    // `Builder::spawn` rather than `thread::spawn`: the latter panics when the
    // OS won't give out a thread, and the panic would land here — after the
    // in-flight flag went up and before anything exists to take it down again,
    // leaving this plugin marked as fetching for good.
    let spawned = std::thread::Builder::new().spawn(move || {
        // The in-flight flag is cleared by the receiver, on the strength of a
        // message arriving — so this thread has to send one however it ends.
        // A panic anywhere in a fetch (a provider's response is JSON from the
        // network, parsed by manifest-driven code) would otherwise leave this
        // plugin marked as fetching for the life of the process, and it would
        // never be polled again.
        let guard = FetchGuard {
            id: manifest.id.clone(),
            generation,
            tx: Some(tx),
        };
        let readings = scheduler::fetch(&manifest, &active_surface_ids, &options);
        // `auth::oauth_refresh_step`'s client discovery can only queue a
        // diagnostic (`auth::PENDING_DIAGNOSTICS`) — it has no way to reach
        // `diag::line` itself (see that queue's own doc). Drained here,
        // right after the fetch that might have filled it, rather than on a
        // timer: a queue not drained this pass is drained the next one, and
        // draining after every fetch means nothing waits longer than one
        // `refresh_secs` tick to actually reach the log.
        for line in auth::take_pending_diagnostics() {
            diag::line(line);
        }
        guard.finish(readings);
    });
    if spawned.is_err() {
        // No thread, so no result will ever arrive to clear the flag. Only
        // ours: a later fetch that replaced this entry must keep its place.
        let mut in_flight = fetching.borrow_mut();
        if in_flight
            .get(&m.id)
            .is_some_and(|f| f.generation == generation)
        {
            in_flight.remove(&m.id);
        }
    }
}

/// Sends a fetch's result exactly once — on [`FetchGuard::finish`], or, if the
/// fetch never got that far (a panic unwinding through it), an empty one on
/// drop. The receiver reads that as "this plugin has nothing right now": its
/// rows go quiet until the next fetch restores them, which is a great deal
/// better than the plugin staying marked in-flight and never being polled
/// again.
struct FetchGuard {
    id: String,
    /// Which fetch this is, so a result that arrives after the app stopped
    /// waiting for it is recognised as stale rather than applied.
    generation: u64,
    /// Taken by whichever of [`FetchGuard::finish`] and `drop` runs first, so
    /// the result is sent exactly once and the guard still drops normally.
    tx: Option<mpsc::Sender<(String, u64, Vec<ProviderReading>)>>,
}

impl FetchGuard {
    fn finish(mut self, readings: Vec<ProviderReading>) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send((self.id.clone(), self.generation, readings));
        }
    }
}

impl Drop for FetchGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send((self.id.clone(), self.generation, Vec::new()));
        }
    }
}

/// Kick off a background fetch for every plugin (dedup still applies per
/// plugin) — used on startup, a tray-icon click and the "Refresh now" menu
/// item.
fn spawn_all_plugin_fetches(
    plugins: &[PluginManifest],
    tx: &mpsc::Sender<(String, u64, Vec<ProviderReading>)>,
    fetching: &Fetching,
) {
    for m in plugins {
        spawn_plugin_fetch(m, active_surface_ids(m), plugin_options(m), tx, fetching);
    }
}

/// Fetch every enabled plugin synchronously, blocking the calling thread —
/// used only by the screenshot snapshot modes, which need data present before
/// the first render. Disabled plugins are skipped, matching the async path.
fn sync_fetch_all(plugins: &[PluginManifest]) -> HashMap<String, Vec<ProviderReading>> {
    plugins
        .iter()
        .filter(|m| plugin_enabled(m))
        .map(|m| {
            let readings = scheduler::fetch(m, &active_surface_ids(m), &plugin_options(m));
            // Same drain as `spawn_plugin_fetch`'s background thread — this
            // is the other of the two places `scheduler::fetch` runs from.
            for line in auth::take_pending_diagnostics() {
                diag::line(line);
            }
            (m.id.clone(), readings)
        })
        .collect()
}

/// Current Unix time in seconds (0 if the clock is before the epoch).
fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Provider readings (universal model) ─────────────────────────────────────

/// The reading id a given surface of a plugin appears under. Mirrors
/// `engine_http::surface_reading_id`'s naming scheme so this always matches a
/// real reading id in the merged list: the synthesized "default" surface
/// reads under the plugin id verbatim, any other surface under
/// "{plugin_id}-{surface_id}".
fn surface_reading_id(plugin_id: &str, surface_id: &str) -> String {
    if surface_id == "default" {
        plugin_id.to_string()
    } else {
        format!("{plugin_id}-{surface_id}")
    }
}

/// Whether a reading id belongs to an active surface. A plain reading id must
/// itself be active (`"claude-desktop"` stays gated by the desktop surface's
/// opt-in). A dynamic *sub-account* row — a log-file engine can emit several
/// accounts under one surface, id'd `"<surface id>#<account>"` (e.g.
/// `"codex#plus"`) — is active whenever its surface base is: the `#` suffix
/// distinguishes accounts for the per-row window model without being a surface
/// of its own. Existing ids carry no `#`, so their routing is unchanged.
fn surface_id_active(reading_id: &str, active_ids: &HashSet<String>) -> bool {
    let base = reading_id.split('#').next().unwrap_or(reading_id);
    active_ids.contains(base)
}

/// The reading id of a plugin's first declared surface — "the plugin's
/// primary account" for the auto-ping (Claude's CLI surface, never its
/// desktop one; Codex's single synthesized "default" surface).
fn first_surface_reading_id(m: &PluginManifest) -> Option<String> {
    let s = m.surface.first()?;
    Some(surface_reading_id(&m.id, &s.id))
}

/// The manifest a reading came from — [`surface_reading_id`] run backwards,
/// with the same `#` sub-account rule [`surface_id_active`] uses.
///
/// One function, because two independent inverses of the same naming scheme is
/// how this project has already shipped a rule that was alive in one engine and
/// dead in the other. Both callers that need to get from a reading back to what
/// its manifest *declares* — the seen-window registry and the panel's window
/// rows — come through here, and a test pins it to the ids [`readings_with`]
/// actually produces rather than to the scheme as written twice.
///
/// **Two manifests claiming one reading id means no answer, not the first
/// one.** The forward map flattens a plugin id and a surface id into a single
/// string, and that is not reversible in general: a third-party plugin whose
/// *id* is `claude-cli` produces the same reading id as plugin `claude`'s `cli`
/// surface. Picking either would file one provider's remembered windows under
/// the other's plugin — where `config::remove_plugin_keys` would not find them
/// on uninstall, and where the panel would draw one provider's declared windows
/// on the other's card.
///
/// Answering nothing is the safe half of a real cost, not a free one: **both**
/// providers then lose their remembered boundary, so the innocent one loses its
/// hysteresis row *and* its auto-ping (which needs that boundary once the
/// window stops being reported). That is why the collision is reported at load
/// time ([`colliding_reading_ids`]) instead of quietly degrading — the fix is
/// for one of the two to be renamed or removed, and nobody can do that without
/// being told.
fn owning_manifest<'a>(
    plugins: &'a [PluginManifest],
    reading_id: &str,
) -> Option<&'a PluginManifest> {
    let base = reading_id.split('#').next().unwrap_or(reading_id);
    let mut claimants = plugins.iter().filter(|m| {
        m.surface
            .iter()
            .any(|s| surface_reading_id(&m.id, &s.id) == base)
    });
    let only = claimants.next()?;
    claimants.next().is_none().then_some(only)
}

/// All provider readings, merged from each plugin's cached fetch result, in
/// plugin-manifest order (`plugins` is already sorted by `order`, ties by
/// `id` — see `plugin::manifest::load_dir`). This is the single source for
/// the popup list, the menu-bar pill and the compact tray title. Delegates to
/// [`readings_with`] (production `active_surface_ids` resolver) — see there
/// for the transforms applied.
fn readings(
    plugins: &[PluginManifest],
    cache: &HashMap<String, Vec<ProviderReading>>,
) -> Vec<ProviderReading> {
    readings_with(plugins, cache, active_surface_ids, plugin_enabled)
}

/// [`readings`]'s pure core. Both `active_surface_ids` and `enabled` are
/// injected — production passes the real [`active_surface_ids`] (which reads
/// the per-surface opt-in state from `config`) and [`plugin_enabled`]; tests
/// pass resolvers pinned to fixed values, so this stays unit-testable without
/// touching the real on-disk config.
///
/// Four transforms happen here, never inside an engine (`engine_logfile`'s
/// and `engine_http`'s own tests assert they always leave `bare_when_sole`
/// false):
///   * a disabled plugin contributes no reading. Its `PluginCache` slot is
///     already emptied on disable, so this is defense-in-depth — but making
///     it explicit closes any window where a fetch in flight at disable time
///     lands in the cache before the slot is cleared, and future code paths
///     that populate the cache differently.
///   * a reading whose surface is not *currently* active — an opt-in surface
///     the user has since toggled off (e.g. "Include Claude desktop
///     account") — is dropped entirely, even if it is still sitting in the
///     cache. A plugin's `PluginCache` slot holds a whole `engine::fetch`
///     result (every surface fetched *at fetch time*), so without this check
///     a stale desktop reading would keep showing until the next successful
///     fetch overwrites the slot (up to `refresh_secs` later), and a fetch
///     that was already in flight when the surface was toggled off would
///     still land in the cache and reappear once it completes. Comparing
///     against the active set at read time — not fetch time — closes both
///     gaps.
///   * a reading whose auth chain came back entirely absent
///     (`error == "no credentials found"` — every step of
///     `plugin::auth::resolve_token`'s chain was Absent) is dropped
///     entirely — an absent surface shows no row at all, matching the old
///     `claude::push_reading`'s `CredError::NotFound => {}`. Any other error
///     is kept and shown inline, unchanged.
///   * `bare_when_sole` is set true for every reading belonging to the
///     smallest-`order` plugin that actually produced a *visible* reading
///     (plugins are pre-sorted by order, so the first contributor wins),
///     false for every other plugin's — a bare "96/80" tray title reads as
///     that provider by convention. Tracking the first *visible* plugin (not
///     the first *loaded* one) means disabling the lowest-order provider
///     promotes the next visible one to bare, rather than leaving a bare
///     title pinned to a hidden plugin.
fn readings_with(
    plugins: &[PluginManifest],
    cache: &HashMap<String, Vec<ProviderReading>>,
    active_surface_ids: impl Fn(&PluginManifest) -> Vec<String>,
    enabled: impl Fn(&PluginManifest) -> bool,
) -> Vec<ProviderReading> {
    let mut out: Vec<ProviderReading> = Vec::new();
    // The owning plugin id for each pushed reading, parallel to `out` — used
    // below to pick the "bare" plugin (the first visible one).
    let mut owners: Vec<&str> = Vec::new();
    for m in plugins {
        if !enabled(m) {
            continue; // disabled plugins never contribute a reading
        }
        let Some(cached) = cache.get(&m.id) else {
            continue;
        };
        let active_ids: HashSet<String> = active_surface_ids(m)
            .iter()
            .map(|sid| surface_reading_id(&m.id, sid))
            .collect();
        for r in cached {
            if !surface_id_active(&r.id, &active_ids) {
                continue;
            }
            if r.error.as_deref() == Some(tickover::plugin::auth::NO_CREDENTIALS) {
                continue;
            }
            out.push(r.clone());
            owners.push(m.id.as_str());
        }
    }
    // The bare slot belongs to the first plugin with a *window*, not merely the
    // first with a reading. What the flag licenses is printing this provider's
    // numbers without its label — and the numbers in that title are window
    // percentages. A balances-only provider (Grok reports no window at all)
    // contributes none, so handing it the slot would leave the lone remaining
    // provider printing `Cl 94/23` where it used to print `94/23`, and Grok
    // alone would print the bare word `Limits` beside a live account.
    let bare_plugin_id = owners
        .iter()
        .zip(out.iter())
        .find(|(_, r)| !r.windows.is_empty())
        .map(|(owner, _)| *owner);
    for (r, owner) in out.iter_mut().zip(owners.iter()) {
        r.bare_when_sole = Some(*owner) == bare_plugin_id;
    }
    out
}

/// Forget what one surface last read, leaving its plugin's other surfaces
/// alone.
///
/// Split out of the toggle handler because the id it has to match is composed
/// (`surface_reading_id`: `"<plugin>-<surface>"`, or bare `"<plugin>"` for a
/// lone `"default"` surface), and matching it by hand at the call site is the
/// kind of detail that goes wrong silently — it would simply clear nothing.
fn drop_surface_reading(cache: &PluginCache, plugin_id: &str, surface_id: &str) {
    let base = surface_reading_id(plugin_id, surface_id);
    if let Some(readings) = cache.borrow_mut().get_mut(plugin_id) {
        // `surface_id_active`'s rule, applied to one surface: the id itself,
        // plus the `"<id>#<account>"` sub-account rows a log-file engine can
        // emit under it. Dropping only the exact id would leave those behind.
        readings.retain(|r| r.id != base && !r.id.starts_with(&format!("{base}#")));
    }
}

/// The readings whose row was on screen a moment ago and is not now.
///
/// A row that vanishes is the one panel state with no explanation anywhere. It
/// is *correct* to hide it — a provider whose credential store is not on this
/// machine is one the user does not have, and five shipped manifests would
/// otherwise fill the panel with rows about tools they never installed — but
/// "correct" and "silent" together are how the last two of these went
/// unexplained for a day each (the built-in that was never delivered, the
/// marker with no file). So the disappearance is stated where the other two
/// now are: in the log, at the moment it happens.
///
/// The predicate is "was drawn, is hidden now", not "had a working token": a
/// row showing `HTTP 500` is still a row, and its disappearance is exactly as
/// unexplained as a healthy one's. Only [`auth::NO_CREDENTIALS`] hides a row —
/// `readings()` filters on that one string — so only it can be the new state
/// here.
///
/// What that buys is silence where it matters. A provider nobody signed into
/// never had a drawn row to lose: its first poll has nothing cached to compare
/// against, and every poll after that compares hidden with hidden. So
/// installing this app with one CLI signed in writes one line about that CLI
/// and none about the other four, and a credential that goes away stays one
/// line rather than one a minute. A credential that
/// *flaps* speaks once per disappearance — the honest count, rather than a
/// promise of one that a latch would have to keep.
///
/// This is not the expired-token case. A token that is present and no longer
/// accepted comes back 401, which keeps the row and writes
/// `engine_http::UNAUTHORIZED` on it. This is the credential being **gone**.
fn credentials_just_lost<'a>(
    previous: &[ProviderReading],
    now: &'a [ProviderReading],
) -> Vec<&'a ProviderReading> {
    let lost = |r: &ProviderReading| r.error.as_deref() == Some(auth::NO_CREDENTIALS);
    now.iter()
        .filter(|r| lost(r))
        .filter(|r| previous.iter().any(|p| p.id == r.id && !lost(p)))
        .collect()
}

/// A reading's Primary (5-hour) window, by reading id.
///
/// Test-only since the auto-ping started carrying its own `PingWindow`: the
/// tests still need "the window this reading calls Primary" in one line, and
/// compiling it into the binary would ship a function nothing calls.
#[cfg(test)]
fn primary_window_of<'a>(readings: &'a [ProviderReading], id: &str) -> Option<&'a Window> {
    readings.iter().find(|r| r.id == id)?.primary_window()
}

/// What the auto-ping needs to know about a plugin's 5-hour window — whether
/// or not the provider is currently reporting one.
struct PingWindow {
    used_percent: Option<f64>,
    resets_at: Option<u64>,
    period_minutes: Option<u64>,
}

/// The 5-hour window the auto-ping is about, or `None` when there is nothing
/// to ping for.
///
/// This exists because the two states the ping has to tell apart used to be
/// distinguishable by accident. "We could not read the provider" arrived as a
/// reading with no windows at all; "the provider reports no 5-hour window
/// because it is empty" arrived as a window with every field `None`. The
/// difference between them was that the second one was *emitted*, and the
/// presence rule has just deleted that signal — a window nothing resolved for
/// is no longer emitted, so both now look like an absent Primary slot.
///
/// So the question is asked of the manifest instead, which is where it always
/// belonged: the manifest is what knows the window exists. An errored reading
/// stops the ping (a provider we cannot read says nothing about its quota, and
/// pinging on that guess spends the user's own allowance); a clean reading with
/// no Primary row is the empty window this feature exists for.
fn ping_window(m: &PluginManifest, reading: Option<&ProviderReading>) -> Option<PingWindow> {
    let reading = reading?;
    if reading.error.is_some() {
        return None;
    }
    let declared = m
        .windows
        .iter()
        .find(|w| w.role == manifest::Role::Primary)?;
    Some(match reading.primary_window() {
        Some(w) => PingWindow {
            used_percent: w.used_percent,
            resets_at: w.resets_at,
            period_minutes: w.period_minutes,
        },
        // Nothing reported. The length has to come from the manifest too, and
        // for the provider this matters for (Codex, whose period is read out
        // of the response) there is nothing to come — which is what
        // `ping_due`'s `ASSUMED_WINDOW_SECS` fallback is for.
        None => PingWindow {
            used_percent: None,
            resets_at: None,
            period_minutes: match declared.period.mode {
                manifest::PeriodMode::Assumed => declared.period.assumed,
                manifest::PeriodMode::FromField => None,
            },
        },
    })
}

// ── Seen-window registry ────────────────────────────────────────────────────
//
// One record of what each provider last *stated* about each of its quota
// windows, kept on disk (`config`'s `plugin.<id>.seen.…` keys). Two features
// read it, and they read the same entry: the auto-ping, to know where the
// boundary of a window that has stopped being reported was, and the panel, to
// keep drawing a row for a window the provider has gone quiet about. They must
// not disagree about whether a window was ever seen — one registry is what
// makes that impossible rather than merely unlikely.
//
// They do reach different conclusions from it, and deliberately so: see
// [`SEEN_WINDOW_TTL_PERIODS`].

/// The registry's name for a window's role. `Extra` has none, and that is the
/// answer rather than an omission: a per-model allowance is a row the provider
/// may withdraw at any time — `plugins/codex.toml` promises exactly that
/// — so remembering it would both contradict the manifest and let keys pile up
/// for every model that ever appeared.
fn seen_role_key(role: Role) -> Option<&'static str> {
    match role {
        Role::Primary => Some("primary"),
        Role::Secondary => Some("secondary"),
        Role::Extra => None,
    }
}

/// One window of one reading, as the provider currently states it — what the
/// registry would record if this is the newest it has heard.
///
/// Carries the manifest it was resolved from rather than just its id, so the
/// writer doesn't run [`owning_manifest`] a second time for a reading it has
/// already matched — this runs on the one-second tick.
#[derive(Debug, Clone, PartialEq)]
struct SeenRecord<'a> {
    manifest: &'a PluginManifest,
    reading_id: String,
    role: Role,
    seen: config::SeenWindow,
}

/// Everything the current readings state about their windows, ready for the
/// registry.
///
/// Pure, and separate from the writing, so the loop itself can be tested: pure
/// functions over scalars keep passing over a loop that never reaches them,
/// which is how the auto-ping's own window lookup was broken while every test
/// around it stayed green.
///
/// A reading with an `error` states nothing — a provider we could not read has
/// told us nothing about its quota, and recording a boundary on that guess is
/// exactly the reasoning the presence work removed everywhere else. Today an
/// errored reading carries no windows anyway; if that ever changes, this
/// check is what keeps this loop right when it does.
fn seen_records<'a>(
    plugins: &'a [PluginManifest],
    readings: &[ProviderReading],
) -> Vec<SeenRecord<'a>> {
    let mut out = Vec::new();
    for r in readings.iter().filter(|r| r.error.is_none()) {
        let Some(m) = owning_manifest(plugins, &r.id) else {
            continue;
        };
        for w in &r.windows {
            if seen_role_key(w.role).is_none() {
                continue;
            }
            let Some(at) = w.resets_at else { continue };
            out.push(SeenRecord {
                manifest: m,
                reading_id: r.id.clone(),
                role: w.role,
                // The manifest is the fallback, never the source: only a
                // manifest whose window declares `period.mode = "assumed"` has
                // a length to give, and the windows that vanish read theirs out
                // of the response (see `config::SeenWindow::period_minutes`).
                seen: config::SeenWindow {
                    at,
                    period_minutes: w
                        .period_minutes
                        .or_else(|| declared_period_minutes(m, w.role)),
                },
            });
        }
    }
    out
}

/// The length a manifest fixes for one of its windows, if it fixes one at all.
fn declared_period_minutes(m: &PluginManifest, role: Role) -> Option<u64> {
    let declared = m
        .windows
        .iter()
        .find(|w| tickover::plugin::map_role(w.role) == role)?;
    match declared.period.mode {
        manifest::PeriodMode::Assumed => declared.period.assumed,
        manifest::PeriodMode::FromField => None,
    }
}

/// What to record for a window the provider is stating now, or `None` when
/// there is nothing new to write.
///
/// Forwards only: a stale or cached reading must never move a boundary back
/// onto a window already dealt with, or the auto-ping would ping it twice.
///
/// **A length once learnt is never unlearnt.** A response that carries the
/// reset but not the length is not evidence that the window has no length —
/// and letting it clear the stored one would disable the panel's hysteresis
/// (which needs a length for its TTL) for as long as the provider kept omitting
/// it, which for the provider this exists for is *while the window is empty*:
/// precisely when the row is wanted. The length belongs to the kind of window,
/// not to the instance of it, so a newer reset inherits it; a provider that
/// really changes a window's length states the new one, and that replaces it.
///
/// The inheritance is unbounded, and the panel's TTL is computed from the
/// inherited number: a provider that both changed a window's length and stopped
/// stating it would keep the old one indefinitely. That is the accepted side of
/// the trade — the alternative, unlearning a length on any response that omits
/// it, is the defect this rule was written to remove.
fn seen_merge(
    previous: Option<config::SeenWindow>,
    stated: config::SeenWindow,
) -> Option<config::SeenWindow> {
    let Some(previous) = previous else {
        return Some(stated);
    };
    if stated.at < previous.at {
        return None;
    }
    let merged = config::SeenWindow {
        at: stated.at,
        period_minutes: stated.period_minutes.or(previous.period_minutes),
    };
    (merged != previous).then_some(merged)
}

/// Resolve the registry entry for one window, falling back to the pre-registry
/// key (`plugin.<id>.seen_window`) for the one window it used to hold.
///
/// Pure half, so both the fallback and its bounds are testable: `legacy_at`
/// reads that key and `legacy_is_this_window` says whether this is the window
/// it was about. Without the fallback, the first launch after an upgrade would
/// forget the boundary of a window that has already vanished — reproducing
/// exactly the silent auto-ping failure `a870bae` was written to fix — and it
/// would stay forgotten, because a provider reporting nothing has nothing to
/// remind us with.
///
/// Both are closures rather than values because this runs several times a
/// second and neither is free — one parses `config.json` again, the other
/// builds a reading id to compare. Nothing about the old key is touched once
/// the registry has an entry of its own.
fn seen_window_from(
    entry: Option<config::SeenWindow>,
    legacy_at: impl FnOnce() -> u64,
    legacy_is_this_window: impl FnOnce() -> bool,
) -> Option<config::SeenWindow> {
    if let Some(entry) = entry {
        return Some(entry);
    }
    if !legacy_is_this_window() {
        return None;
    }
    match legacy_at() {
        0 => None,
        // No length was stored beside it, and none is invented here: the
        // provider states one again the moment it reports the window.
        at => Some(config::SeenWindow {
            at,
            period_minutes: None,
        }),
    }
}

/// What the registry knows about one window of one reading of a known plugin.
/// **The single place either feature asks** — see the section comment above.
fn seen_window_for(m: &PluginManifest, reading_id: &str, role: Role) -> Option<config::SeenWindow> {
    let key = seen_role_key(role)?;
    seen_window_from(
        config::plugin_seen_window_for(&m.id, reading_id, key),
        || config::plugin_seen_window(&m.id),
        || role == Role::Primary && first_surface_reading_id(m).as_deref() == Some(reading_id),
    )
}

/// [`seen_window_for`] for a caller holding only a reading id.
fn seen_window_of(
    plugins: &[PluginManifest],
    reading_id: &str,
    role: Role,
) -> Option<config::SeenWindow> {
    seen_window_for(owning_manifest(plugins, reading_id)?, reading_id, role)
}

/// Record what every reading currently states about its windows.
///
/// Runs for every plugin with a reading, not only ones with a `[ping]` section:
/// the panel's hysteresis needs the boundary of any provider that goes quiet,
/// and a registry only third-party manifests happened to be excluded from would
/// have failed silently for exactly them.
fn record_seen_windows(plugins: &[PluginManifest], readings: &[ProviderReading]) {
    for rec in seen_writes(seen_records(plugins, readings), seen_window_for) {
        let Some(key) = seen_role_key(rec.role) else {
            continue;
        };
        config::set_plugin_seen_window_for(&rec.manifest.id, &rec.reading_id, key, rec.seen);
    }
}

/// Which of the stated windows are actually worth writing, given what the
/// registry already holds (`previous`, production's [`seen_window_for`]).
///
/// A seam rather than a loop body, because "an unchanged reading costs no write"
/// is the property the whole `seen_merge` comparison exists for, and it is a
/// property of *this loop* — a pure function over scalars keeps passing over a
/// loop that never consults it, which is how this project's auto-ping was once
/// broken with every test around it green. Tests cannot reach `config.json`
/// from here (its path override is `#[cfg(test)]`-local to that module), so the
/// decision comes out and the writing stays behind.
fn seen_writes<'a>(
    stated: Vec<SeenRecord<'a>>,
    previous: impl Fn(&PluginManifest, &str, Role) -> Option<config::SeenWindow>,
) -> Vec<SeenRecord<'a>> {
    let mut out: Vec<SeenRecord<'a>> = Vec::new();
    for rec in stated {
        // At most one write per remembered window, however many windows of that
        // role the reading carries. Validation caps `primary` at one, but
        // nothing caps `secondary`, so a manifest may declare two — and each
        // record is otherwise compared against what is *on disk*, which the
        // earlier records of this same tick have not reached yet. Left alone
        // the last would win rather than the newest, so an older boundary could
        // overwrite a newer one: forward-only, undone by a loop.
        let same = out.iter().position(|w| {
            w.manifest.id == rec.manifest.id && w.reading_id == rec.reading_id && w.role == rec.role
        });
        let known = match same {
            Some(i) => Some(out[i].seen),
            None => previous(rec.manifest, &rec.reading_id, rec.role),
        };
        let Some(merged) = seen_merge(known, rec.seen) else {
            continue;
        };
        match same {
            Some(i) => out[i].seen = merged,
            None => out.push(SeenRecord {
                seen: merged,
                ..rec
            }),
        }
    }
    out
}

/// Window length assumed when the reading doesn't state one — which is the
/// case that matters, since a provider reporting no 5-hour window reports no
/// length for it either. It bounds the retry cadence below, so it is a rate
/// limit as much as a guess: at worst one ping per five hours.
const ASSUMED_WINDOW_SECS: u64 = 5 * 3600;

/// How far after a ping a window may still begin and count as the window that
/// ping started.
///
/// `pinged_at` is recorded when the command is launched; the request it makes
/// lands seconds later, after a process has been spawned and a model has
/// answered. A provider that anchors the new window on that arrival — rather
/// than on the boundary the old one ended at — therefore reports a window
/// starting *after* our own ping, which without this would read as a second
/// empty window and be pinged again. Two minutes is enormous beside a
/// five-hour window and larger than any spawn-and-answer takes.
const PING_GRACE_SECS: u64 = 120;

/// When the 5-hour window currently on screen began.
///
/// Two shapes, because a provider names the same window differently before and
/// after it starts reporting it:
///
/// * **Stated** (`resets_at = Some`) — the window ends there and began one
///   period earlier. Claude is always in this shape, including at 0% used.
/// * **Vanished** (`resets_at = None`) — Codex reports no 5-hour window at all
///   once it has nothing to report, so the window that is running now is the
///   one that began when the last *stated* reset passed (`seen_window`). Past
///   that, the boundary is projected forward a period at a time: without that,
///   a ping that failed to start a window would leave the boundary frozen at a
///   value already recorded as pinged, and the provider — silent precisely
///   because no window started — would never supply a newer one. The retry
///   would then never come, which is the failure this whole rule exists to
///   remove.
fn window_start(
    resets_at: Option<u64>,
    period_secs: u64,
    seen_window: u64,
    now: u64,
) -> Option<u64> {
    match resets_at {
        Some(reset) => Some(reset.saturating_sub(period_secs)),
        None => {
            if seen_window == 0 || now < seen_window {
                return None;
            }
            Some(seen_window + (now - seen_window) / period_secs * period_secs)
        }
    }
}

/// Whether the auto-ping is due: **this window is empty and has not been
/// pinged since it began**.
///
/// The condition is a *state*, not an *edge* ("the reset just passed"). An edge
/// is only observable by a process awake at that instant, so a Mac asleep at
/// the boundary — or an app started a minute later — missed the ping for good,
/// which is exactly what used to happen. A state is still true afterwards, so
/// the ping goes out late instead of not at all.
///
/// De-duplication is by time rather than by window identity
/// (`config::plugin_pinged_at` against [`window_start`], plus
/// [`PING_GRACE_SECS`]): a ping fired inside the current window — or in the two
/// minutes before it began — has already done its job, whichever of the two
/// shapes above the reading was in when it fired. That is what stops Codex
/// being pinged twice: once while it reported nothing, then again a moment
/// later when it began reporting the window our own ping had just started,
/// still rounded to 0% used.
fn ping_due(
    used_percent: Option<f64>,
    resets_at: Option<u64>,
    period_minutes: Option<u64>,
    seen_window: u64,
    pinged_at: u64,
    now: u64,
) -> bool {
    // "Empty" has to mean *definitely* empty: no figure at all, or one that is
    // zero. A NaN fails this comparison as it fails every other, and so counts
    // as busy — a figure that cannot be read must never spend quota.
    let empty = match used_percent {
        None => true,
        Some(used) => used <= 0.0,
    };
    if !empty {
        return false;
    }
    let period = period_minutes
        .filter(|m| *m > 0)
        .map_or(ASSUMED_WINDOW_SECS, |m| m * 60);
    window_start(resets_at, period, seen_window, now)
        .is_some_and(|start| pinged_at.saturating_add(PING_GRACE_SECS) < start)
}

/// Whether a plugin's auto-ping may fire at all: both its master enable and
/// its per-plugin ping toggle must be on. Evaluated when arming the 5s
/// single-shot *and* re-evaluated inside it, so a plugin disabled (or its
/// ping switched off) during that delay is never actually pinged.
fn plugin_ping_armed(enabled: bool, ping_on: bool) -> bool {
    enabled && ping_on
}

// ── Provider model building ──────────────────────────────────────────────────

/// Rebuild the provider list from the cache. Two nested reconciles keep the UI
/// stable across the one-second tick:
///   * the outer list reuses each `ProviderData` slot in place (`set_row_data`
///     by index) whenever the provider count is unchanged, so a provider
///     appearing/disappearing doesn't churn its neighbours' cards;
///   * the inner `WindowData` list is reused *by `Rc` identity* (see
///     [`reconcile_window_model`]) whenever a provider's row is structurally
///     stable — same reading id and window count. Because Slint's repeater
///     detects a model change by the `ModelRc`'s pointer, handing back the
///     same inner `Rc` keeps the `for w in data.windows` `ConsoleRow`s alive:
///     the bar `pct` glides and its hover tooltip survives, instead of the
///     repeater re-creating every row (and snapping/flickering) each second.
fn refresh_model(
    app: &AppWindow,
    model: &Providers,
    plugins: &[PluginManifest],
    cache: &PluginCache,
    window_models: &WindowModels,
    balance_models: &BalanceModels,
) {
    let now = now_unix();
    let readings = readings(plugins, &cache.borrow());

    let mut win_models = window_models.borrow_mut();
    let mut bal_models = balance_models.borrow_mut();
    let list: Vec<ProviderData> = readings
        .iter()
        .map(|r| {
            // Only a live reading carries window/balance rows; an errored one
            // shows its message instead, with no (and no persisted) row
            // model of either kind.
            let (windows, balances) = match &r.error {
                None => {
                    let m = owning_manifest(plugins, &r.id);
                    let rows = window_rows(m, r, now, &|role| seen_window_of(plugins, &r.id, role));
                    let windows = reconcile_window_model(&mut win_models, &r.id, rows);
                    let brows = balance_rows(r, now);
                    let balances = reconcile_balance_model(&mut bal_models, &r.id, brows);
                    (windows, balances)
                }
                Some(_) => (ModelRc::default(), ModelRc::default()),
            };
            provider_data_from_reading(r, windows, balances)
        })
        .collect();

    // Drop row models for providers no longer visible, so opt-in surfaces
    // coming and going can't grow either map without bound.
    let live: HashSet<&str> = readings.iter().map(|r| r.id.as_str()).collect();
    win_models.retain(|id, _| live.contains(id.as_str()));
    bal_models.retain(|id, _| live.contains(id.as_str()));
    drop(win_models);
    drop(bal_models);

    if model.row_count() != list.len() {
        model.set_vec(list);
    } else {
        for (i, pd) in list.into_iter().enumerate() {
            model.set_row_data(i, pd);
        }
    }

    let has_live = readings.iter().any(|r| r.error.is_none());
    let (updated, updated_live) = header_status(has_live, !readings.is_empty());
    app.set_updated(ss(updated));
    app.set_updated_live(updated_live);
}

/// Return a `ModelRc` for one provider's window rows, reusing the persisted
/// inner `VecModel` (updating each row in place) when it is structurally
/// unchanged — same count under the same reading id — and building a fresh one
/// otherwise. Preserving the inner `Rc`'s identity across ticks is what stops
/// the Slint window repeater from re-creating its rows (see [`refresh_model`]).
fn reconcile_window_model(
    models: &mut HashMap<String, WindowModel>,
    id: &str,
    rows: Vec<(String, WindowData)>,
) -> ModelRc<WindowData> {
    let (keys, data): (Vec<String>, Vec<WindowData>) = rows.into_iter().unzip();
    if let Some(existing) = models.get(id) {
        // Reuse in place only when the whole identity *sequence* is unchanged;
        // any difference rebuilds. Be precise about what that is and is not: it
        // is not per-key matching, so a reordering or a partial change rebuilds
        // the model rather than moving rows around inside it. What it buys is
        // the guarantee that a row is only ever overwritten by the same window.
        //
        // Equal counts was the old test, and it is a different question: the
        // set of rows is variable, so one window appearing as another vanishes
        // keeps the count and shifts every later index — and each row is then
        // overwritten in place with a different window's figures under the
        // caption it already had. A deterministic sort does not fix that; it
        // makes the order predictable, not the indices stable.
        if existing.keys == keys {
            for (i, wd) in data.into_iter().enumerate() {
                existing.model.set_row_data(i, wd);
            }
            return ModelRc::from(existing.model.clone());
        }
    }
    let fresh = Rc::new(VecModel::from(data));
    models.insert(
        id.to_string(),
        WindowModel {
            model: fresh.clone(),
            keys,
        },
    );
    ModelRc::from(fresh)
}

/// [`reconcile_window_model`], for balance rows: reuses the persisted inner
/// `VecModel` in place when the row identities are unchanged, rebuilds
/// otherwise, and for the same reason (equal counts is not equal
/// identities — see that function's own comment for the failure this
/// guards against). Kept as a straight mirror rather than a shared generic
/// helper: window rows already carry hysteresis a balance row does not (see
/// [`balance_rows`]), so the two are one behavioural change away from
/// diverging, and a shared helper would only have to be pulled back apart
/// the day that happens.
fn reconcile_balance_model(
    models: &mut HashMap<String, BalanceModel>,
    id: &str,
    rows: Vec<(String, BalanceData)>,
) -> ModelRc<BalanceData> {
    let (keys, data): (Vec<String>, Vec<BalanceData>) = rows.into_iter().unzip();
    if let Some(existing) = models.get(id) {
        if existing.keys == keys {
            for (i, bd) in data.into_iter().enumerate() {
                existing.model.set_row_data(i, bd);
            }
            return ModelRc::from(existing.model.clone());
        }
    }
    let fresh = Rc::new(VecModel::from(data));
    models.insert(
        id.to_string(),
        BalanceModel {
            model: fresh.clone(),
            keys,
        },
    );
    ModelRc::from(fresh)
}

fn header_status(has_live_provider: bool, has_provider_reading: bool) -> (&'static str, bool) {
    if has_live_provider {
        ("LIVE", true)
    } else if has_provider_reading {
        ("no data", false)
    } else {
        ("reading…", false)
    }
}

/// The account label as it should appear on screen.
///
/// `TICKOVER_DEMO_ACCOUNT` replaces it, so documentation screenshots can be
/// taken without publishing whichever address the machine happens to be logged
/// in as. It only rewrites the label: the reading itself, and the token it was
/// resolved from, are untouched.
fn display_account(account: &str) -> String {
    match std::env::var("TICKOVER_DEMO_ACCOUNT") {
        Ok(demo) if !demo.is_empty() && !account.is_empty() => demo,
        _ => account.to_string(),
    }
}

/// Build the Slint-side `ProviderData` for one reading. The `windows` model is
/// supplied by the caller ([`refresh_model`]), which reuses a persisted inner
/// model across ticks when the row is structurally stable — an errored reading
/// gets an empty model and shows its message instead of window rows.
fn provider_data_from_reading(
    reading: &ProviderReading,
    windows: ModelRc<WindowData>,
    balances: ModelRc<BalanceData>,
) -> ProviderData {
    let name = ss(&reading.name);
    let tag = ss(reading.tag.as_deref().unwrap_or_default());
    let account = ss(display_account(
        reading.account.as_deref().unwrap_or_default(),
    ));
    let notice = reading
        .quota_status
        .as_ref()
        .map(quota_notice)
        .unwrap_or_default();
    // A balance row is exactly as much "usage reported" as a window row is —
    // Grok never reports a window at all, so a section gated on `windows`
    // alone would show "no usage reported yet" over its own stated balance
    // forever. Both counts feed the same guard.
    let nothing_to_draw = windows.row_count() == 0 && balances.row_count() == 0;
    match &reading.error {
        // Windows the provider reported no percentage for are filtered out
        // before they reach the model, so an account can arrive live and yet
        // have nothing to draw. Say so: a header with empty space under it
        // reads as a rendering fault, and is indistinguishable from a provider
        // that declares no quota windows at all.
        //
        // Unless the provider said something about the quota itself, which it
        // can do while reporting no window at all — a blocked account with
        // nothing running is exactly that shape. "No usage reported yet" would
        // then be the friendliest possible way of hiding a refusal.
        // A refusal is drawn as a refusal even with nothing under it. Routing
        // it through `message` put it in the same faint grey as "no usage
        // reported yet" — the sentence it replaced — so the one state the
        // quota status exists to surface arrived looking like the calmest
        // thing on the panel. It goes through `notice`, which is drawn in the
        // colour the bars keep for ≥ 90%.
        None if nothing_to_draw && !notice.is_empty() => ProviderData {
            name,
            tag,
            account,
            live: true,
            status: 0,
            windows,
            balances,
            notice: ss(&notice),
            ..Default::default()
        },
        None if nothing_to_draw => ProviderData {
            name,
            tag,
            account,
            live: true,
            status: 1,
            message: ss("no usage reported yet"),
            ..Default::default()
        },
        None => ProviderData {
            name,
            tag,
            account,
            live: true,
            status: 0,
            windows,
            balances,
            notice: ss(&notice),
            ..Default::default()
        },
        Some(msg) => ProviderData {
            name,
            tag,
            account,
            status: 1,
            message: ss(msg),
            ..Default::default()
        },
    }
}

/// The one line a quota's own status is worth on the panel, or empty when the
/// provider is not refusing anything.
///
/// Only a refusal is drawn. A provider stating `allowed = true` is stating the
/// ordinary case, and a line saying so on every account, forever, would train
/// the eye to skip the place the real message appears in.
///
/// `reached_type` is printed as the provider's own word rather than mapped onto
/// a vocabulary of ours. An unfamiliar value is shown as it arrived: neutral
/// and visible, never silently dropped, because a word we do not recognise is
/// the first sign the server's vocabulary has moved.
fn quota_notice(status: &tickover::model::QuotaStatus) -> String {
    if !status.is_blocked() {
        return String::new();
    }
    // Two sentences, because the provider says two different things and only
    // one of them is "you have run out". `allowed = false` without
    // `limit_reached` is an account that may not spend for some other reason
    // — suspended, unpaid, out of region — and printing "limit reached" over
    // it would be this app inventing a sentence nobody spoke, which is the
    // failure `parse_quota` and `is_stated` are both built to avoid.
    //
    // Asked of the model rather than worked out again here: this is the same
    // question `is_blocked` answers, and stating it twice is how the two come
    // to disagree.
    match (status.limit_was_reached(), status.reached_type.as_deref()) {
        (true, Some(kind)) => format!("limit reached · {kind}"),
        (true, None) => "limit reached".to_string(),
        (false, _) => "the provider is refusing this account".to_string(),
    }
}

/// Build one `WindowData` row from a reading window and the percentage it
/// reported. The window's `role` decides the tooltip name and clock format
/// (5-hour vs weekly); its numbers drive the bar, countdown and pace via
/// [`window_view`].
///
/// `used` is passed rather than read back off the window because only a window
/// that reported one becomes a row at all — the caller establishes that, and
/// taking it as an argument keeps this from carrying a second, unreachable
/// shape for the case it has already excluded.
/// What a quota window is called on screen.
///
/// The manifest's own label is a chip meant for the menu-bar pill — "5H",
/// "WK" — and reading it in the panel costs a beat of translation every time.
/// The window's declared length says the same thing in words, so use that when
/// it lands on a duration with a name, and keep the manifest's label for the
/// ones it doesn't. Derived from the length rather than the role, since a
/// plugin is free to declare a primary window that isn't five hours long.
fn window_title(w: &Window) -> String {
    window_title_of(&w.label, w.role, w.period_minutes)
}

/// [`window_title`] over the parts, so a row for a window the provider is not
/// currently reporting is named by exactly the same rule as the live one it
/// replaces — a window that changed its caption as it emptied would read as a
/// different window.
fn window_title_of(label: &str, role: Role, period_minutes: Option<u64>) -> String {
    // A quota that is not the subscription is named by the manifest, not by
    // its length: a per-model weekly allowance titled "Weekly limit" would sit
    // directly under the subscription's weekly row, saying the same words
    // about a different number.
    if role == Role::Extra {
        return label.to_string();
    }
    match period_minutes {
        Some(10_080) => "Weekly limit".to_string(),
        Some(1_440) => "Daily limit".to_string(),
        Some(m) if m > 0 && m % 60 == 0 => format!("{}-hour limit", m / 60),
        Some(m) if m > 0 && m < 60 => format!("{m}-minute limit"),
        _ => format!("{label} limit"),
    }
}

/// How many of a window's own periods it stays on screen after the provider
/// stops reporting it.
///
/// The registry entry itself never expires — the auto-ping projects the next
/// boundary from it a period at a time, and dropping the entry would take that
/// retry with it (the failure `a870bae` fixed). This is the *panel's* rule, and
/// it is a different question: a stale row is a limit the user believes they
/// have, while a stale boundary costs an unattended `hello` the user opted into.
/// So one remembered fact, two decisions — the point of a single registry is
/// that they cannot disagree about whether the window was ever seen, not that
/// they must act alike once it is gone.
///
/// Be precise about what the ping's side of that costs, because it is not
/// nothing: for an account whose plan has genuinely dropped the window, the
/// projection keeps coming due **once per period, indefinitely**, long after
/// this rule has taken the row off the panel. That is the existing behaviour of
/// the projection rather than something added here — and the alternative it
/// replaced was a ping that stopped forever after one failure — but the
/// asymmetry is deliberate and should be revisited alongside the ping's own
/// pacing, not silently here.
///
/// Two periods is the slack for the case this is all for: a window that empties
/// and stays empty because nobody used it. Past that the likelier explanation
/// is that the plan no longer has this window at all, and a row for a limit
/// that no longer exists is worse than no row.
const SEEN_WINDOW_TTL_PERIODS: u64 = 2;

/// Ceiling on the *slack* above, because two periods scales with the window and
/// the confidence behind it does not. Two periods of a *weekly* window is a
/// fortnight: an account that loses its weekly allowance would be shown "Weekly
/// limit — not started" for two weeks, which is the failure the TTL exists to
/// bound, at the longest possible duration.
///
/// It is a ceiling on the slack and never on the window itself — see
/// [`seen_window_ttl_secs`], which never cuts before one full period. Three days
/// is what a plain `min` would have taken off a weekly row, and taking it would
/// have deleted the row four days *inside* a window whose boundary and length
/// the provider itself gave us: while `now < at + period`, an empty window
/// explains the silence completely and there is nothing stale to bound.
const SEEN_WINDOW_TTL_MAX_SLACK_SECS: u64 = 3 * 24 * 3600;

/// How long a remembered window stays on screen after the provider goes quiet:
/// its own length first — during which "not started" is simply true if nothing
/// was spent — and then up to one more period of benefit of the doubt, capped.
///
/// Below 36 hours the cap cannot bite, so every window this feature was written
/// for keeps the plain two periods (a 5-hour window: ten hours). A weekly window
/// gets one week rather than two.
fn seen_window_ttl_secs(period_minutes: u64) -> u64 {
    let period = period_minutes.saturating_mul(60);
    period
        .saturating_mul(SEEN_WINDOW_TTL_PERIODS)
        .min(period.max(SEEN_WINDOW_TTL_MAX_SLACK_SECS))
}

/// The rows one provider's panel section shows: the windows it reported, plus
/// the ones it has stopped reporting since we last saw them.
///
/// `seen` answers what the registry knows about this reading's window in a
/// given role ([`seen_window_of`] in production) — passed in so the decision
/// below is testable without a config file, and so the panel and the auto-ping
/// demonstrably read the same fact.
///
/// A row is added only when all of it holds:
/// * **the reading is not in error.** A provider we could not read has said
///   nothing about its quota, and "not started" is a claim about usage. The
///   caller draws the message instead of rows for such a reading, so this is
///   today unreachable from there — it is here anyway, because the same
///   reasoning is written into `seen_records` and a rule that lives in only one
///   of the two halves is the shape of this project's last latent hole;
/// * the manifest declares the window, and it is not `Extra` (never
///   remembered — see [`seen_role_key`]);
/// * **the reading carries no window in that role at all** — asked of
///   `r.windows` and not of the rows built below, which are the windows that
///   also had a percentage to draw. A window reported *without* a usable figure
///   is still a window the provider reported, and calling it "not started"
///   would be a claim about usage made from a response that stated none. Only
///   an absent window is absent;
/// * the provider stated the window at some point, *and* said how long it was
///   — without a length there is no TTL to apply, and a row that can never
///   expire is worse than one that never appears;
/// * the window it stated has ended (`now >= at`) and less than
///   [`SEEN_WINDOW_TTL_PERIODS`] of it have passed since. Before its end, the
///   provider going quiet says nothing about the *next* window, and "not
///   started" over a window that was being spent would be a lie.
fn window_rows(
    m: Option<&PluginManifest>,
    r: &ProviderReading,
    now: u64,
    seen: &dyn Fn(Role) -> Option<config::SeenWindow>,
) -> Vec<(String, WindowData)> {
    // A window the provider reported no percentage for is left out rather than
    // drawn as an empty bar over "no data": it occupies a block's worth of
    // height to say nothing, and the reader has to check it every time to
    // confirm that. A provider whose windows are all like that still shows its
    // header, so the account itself doesn't vanish.
    let mut rows: Vec<(Role, String, WindowData)> = r
        .windows
        .iter()
        .filter_map(|w| {
            w.used_percent
                .map(|used| (w.role, w.key.clone(), window_data(now, w, used)))
        })
        .collect();
    if let Some(m) = m.filter(|_| r.error.is_none()) {
        for (index, declared) in m.windows.iter().enumerate() {
            let role = tickover::plugin::map_role(declared.role);
            if seen_role_key(role).is_none() || r.windows.iter().any(|w| w.role == role) {
                continue;
            }
            let Some((at, period_minutes)) = seen(role).and_then(|s| {
                s.period_minutes
                    .filter(|mins| *mins > 0)
                    .map(|mins| (s.at, mins))
            }) else {
                continue;
            };
            if now < at || now >= at.saturating_add(seen_window_ttl_secs(period_minutes)) {
                continue;
            }
            // Ordered by role, and by scanning the rows built so far rather
            // than the reading's own: two windows that both went quiet are
            // inserted one after the other, and the second must land after the
            // first rather than at the same index.
            let slot = rows
                .iter()
                .position(|(have, _, _)| role_rank(*have) > role_rank(role))
                .unwrap_or(rows.len());
            rows.insert(
                slot,
                (
                    role,
                    // The same key the window itself would carry, so a window
                    // going quiet and coming back is one row throughout rather
                    // than a rebuild — and so the reconciler can tell the two
                    // quiet rows of one provider apart.
                    tickover::plugin::window_key(declared, index),
                    not_started_row(&declared.label, role, period_minutes),
                ),
            );
        }
    }
    rows.into_iter().map(|(_, key, wd)| (key, wd)).collect()
}

/// Row order within a provider: the subscription's short window, then its long
/// one, then everything that is neither. Fixed here rather than left to the
/// order windows happen to arrive in, because a row that moves as its
/// neighbour empties reads as a different limit.
fn role_rank(role: Role) -> u8 {
    match role {
        Role::Primary => 0,
        Role::Secondary => 1,
        Role::Extra => 2,
    }
}

/// The row for a window the provider has stopped reporting. Deliberately a
/// `WindowData` and never a `Window`: a synthesized `Window { used_percent:
/// Some(0.0) }` would be picked up by `primary_window()` — feeding the auto-ping
/// a window the provider never reported — and printed by the menu bar as a `0`
/// where it currently shows nothing. This row exists only on the panel, which
/// is the only surface with room to say what it means.
fn not_started_row(label: &str, role: Role, period_minutes: u64) -> WindowData {
    WindowData {
        label: ss(window_title_of(label, role, Some(period_minutes))),
        // Nothing has been spent, and the row draws no bar — but a stray
        // percentage would still reach the reconciler, so it says zero rather
        // than whatever the row it replaced was showing.
        pct: 0.0,
        not_started: true,
        // No countdown: the window has not begun, so there is no reset to
        // count to. The clock the provider will state once it does is not ours
        // to guess.
        reset_rel: ss(""),
        reset_at: ss(""),
        tooltip: ss(""),
    }
}

fn window_data(now: u64, w: &Window, used: f64) -> WindowData {
    // Whether the reset clock carries a date. A week away needs one; five
    // hours away does not. An extra quota can be either length, so it is
    // asked rather than assumed.
    let weekly = match w.role {
        Role::Secondary => true,
        Role::Primary => false,
        Role::Extra => w.period_minutes.is_some_and(|m| m > 720),
    };
    let name = window_title(w);
    let (rel, at, tooltip, _, _) =
        window_view(now, used, w.resets_at, w.period_minutes, weekly, &name);
    WindowData {
        label: ss(window_title(w)),
        pct: used as f32,
        not_started: false,
        reset_rel: ss(rel),
        reset_at: ss(at),
        tooltip: ss(tooltip),
    }
}

// ── Balance rows ──────────────────────────────────────────────────────────

/// The balance rows one provider's section shows: exactly what the current
/// reading states, no more. Unlike [`window_rows`] there is no hysteresis: a
/// balance carries no length to project a "still inside its own period"
/// window from — `Balance::period_end` is a date, not a duration, so there is
/// nothing to hold a stale row open with — and a balance the provider stops
/// reporting simply stops being drawn.
fn balance_rows(r: &ProviderReading, now: u64) -> Vec<(String, BalanceData)> {
    // Asked once here rather than inside `balance_data`: it is a fact about
    // the whole reading, and a single balance has no way to know it on its
    // own.
    let quota_blocked = r.quota_status.as_ref().is_some_and(|q| q.is_blocked());
    r.balances
        .iter()
        .filter_map(|b| balance_data(now, b, quota_blocked).map(|bd| (b.key.clone(), bd)))
        .collect()
}

/// Build one `BalanceData` row from a balance, or `None` once there is
/// nothing left on it to draw.
///
/// `quota_blocked` is `reading.quota_status.is_blocked()` — when the quota
/// level has already stated the refusal, this balance's own `limit_reached`
/// would only say the same sentence again, so it is dropped here. And if
/// that sentence was the only thing this balance had (a row whose sole
/// stated field is `limit_reached`), the row itself is dropped with it: a
/// label beside empty space reads as a rendering fault, exactly what
/// `Balance::is_stated` exists to keep off the panel at parse time — and
/// this dedup can produce that same emptiness at render time just as easily.
fn balance_data(now: u64, b: &Balance, quota_blocked: bool) -> Option<BalanceData> {
    let mut lines = Vec::new();
    // Which of the two pairs this balance has, if either: a ceiling with what
    // was spent against it, or the same ceiling with what is left of it. Asked
    // once, because the answer decides both what the first line says and
    // whether `remaining` still needs a line of its own.
    let remainder_paired = b.remainder_pair_is_comparable();
    if b.pair_is_comparable() {
        // `pair_is_comparable` already established both are `Some` — asked
        // again as `if let` rather than assumed with `.unwrap()`, because
        // that guarantee lives in a method this function does not re-derive.
        if let (Some(used), Some(cap)) = (&b.used, &b.cap) {
            lines.push(format!(
                "used {} / cap {}",
                format_amount(used),
                format_amount(cap)
            ));
        }
    } else if remainder_paired {
        if let (Some(remaining), Some(cap)) = (&b.remaining, &b.cap) {
            lines.push(format!(
                "remaining {} / cap {}",
                format_amount(remaining),
                format_amount(cap)
            ));
        }
    } else {
        if let Some(used) = &b.used {
            lines.push(format!("used {}", format_amount(used)));
        }
        if let Some(cap) = &b.cap {
            lines.push(format!("cap {}", format_amount(cap)));
        }
    }
    if !remainder_paired {
        if let Some(remaining) = &b.remaining {
            lines.push(format!("remaining {}", format_amount(remaining)));
        }
    }

    // The provider's own percentage, and only that: nothing here divides
    // `used` by `cap`. See `BalanceAmount`'s own docs for why a figure this
    // app derived would be indistinguishable on screen from one the
    // provider actually sent.
    // Printed as the provider stated it: no rounding, no clamping. `25.5`
    // rounded to `26%` is a figure nobody sent, sitting beside figures that
    // were — the same rule that forbids computing a percentage from used and
    // cap forbids adjusting one that arrived.
    let percent_line = b
        .stated_percent
        .map(|p| format!("{}% used", format_bare_number(p)))
        .unwrap_or_default();

    let period_line = b
        .period_end
        .map(|end| balance_period_line(now, end))
        .unwrap_or_default();

    let notice = if b.limit_reached == Some(true) && !quota_blocked {
        "spending limit reached".to_string()
    } else {
        String::new()
    };

    // A period end alone does not hold a row up: every month has one, and a
    // caption with a date beside empty space announces a balance whose size
    // nobody stated. `Balance::is_stated` refuses that shape at parse time;
    // dedup can produce it again here, one figure later.
    if lines.is_empty() && percent_line.is_empty() && notice.is_empty() {
        return None;
    }

    Some(BalanceData {
        label: ss(&b.label),
        amount_line: ss(lines.join("\n")),
        percent_line: ss(&percent_line),
        period_line: ss(&period_line),
        notice: ss(&notice),
    })
}

/// One balance figure, in whichever form the provider stated it — mirrors
/// `BalanceAmount`'s three variants one-for-one and adds nothing: a `Text`
/// value is already the provider's own words, sanitized at parse time, so it
/// is printed exactly as received.
fn format_amount(a: &BalanceAmount) -> String {
    match a {
        BalanceAmount::Money {
            minor,
            currency,
            exponent,
        } => {
            format!("{} {currency}", format_money_minor(*minor, *exponent))
        }
        // The unit is the manifest author's word, printed beside the figure
        // when they gave one and omitted when they did not — never supplied
        // here, since a unit this app chose would be indistinguishable from
        // one the manifest declared.
        BalanceAmount::Number { value, unit } => match unit {
            Some(u) => format!("{} {u}", format_bare_number(*value)),
            None => format_bare_number(*value),
        },
        BalanceAmount::Text(s) => s.clone(),
    }
}

/// `minor` at `exponent` digits of scale, as a plain decimal string —
/// integer arithmetic throughout, because `minor as f64 / 10f64.powi(e)`
/// loses precision exactly where money can least afford it, and
/// `minor.abs()` panics on `i64::MIN`. `exponent == 0` (a currency with no
/// minor unit) prints no decimal point at all: there is nothing after it to
/// show.
fn format_money_minor(minor: i64, exponent: u32) -> String {
    let sign = if minor < 0 { "-" } else { "" };
    let scale = 10u64.pow(exponent);
    let whole = minor.unsigned_abs() / scale;
    if exponent == 0 {
        return format!("{sign}{whole}");
    }
    let frac = minor.unsigned_abs() % scale;
    format!("{sign}{whole}.{frac:0width$}", width = exponent as usize)
}

/// A bare number with no stated unit (`BalanceAmount::Number`) — plain `f64`
/// `Display`, not a fixed two decimals. `BalanceAmount`'s own docs are explicit
/// that this variant's unit is unknown (Grok's is), and assuming "two decimal
/// places" would be exactly the assumption `format_money_minor` is forbidden
/// from making on the *better*-specified variant ("cents have two digits" is
/// true until the first currency for which it is not). `Display` on `f64` is
/// shortest round-trip — `25.0` prints `"25"`, `0.001` prints `"0.001"` — so a
/// JSON-sourced double prints back as the literal it arrived as, rounding
/// nothing and inventing no trailing zero.
fn format_bare_number(n: f64) -> String {
    format!("{n}")
}

/// `period_end` as a date, or a countdown to it — never as the period's own
/// length: a calendar month is 28–31 days, and stating a length would be
/// this app inventing a fact the timestamp alone cannot support. Mirrors
/// `window_view`'s date formatting: `chrono::Local`, and `.single()` →
/// `unwrap_or_default()` for a timestamp that doesn't resolve to one.
fn balance_period_line(now: u64, period_end: u64) -> String {
    use chrono::{Local, TimeZone};
    let date = Local
        .timestamp_opt(period_end as i64, 0)
        .single()
        .map(|dt| dt.format("%-d %b %Y").to_string())
        .unwrap_or_default();
    if date.is_empty() {
        return String::new();
    }
    let secs = period_end as i64 - now as i64;
    if secs <= 0 {
        // A stale reading (or a boundary the provider has already rolled
        // past) must not print a negative countdown.
        format!("period ended {date}")
    } else {
        let days = secs / 86_400;
        if days >= 1 {
            format!("ends in {days}d · {date}")
        } else {
            format!("ends today · {date}")
        }
    }
}

// ── Plugin-manager model building ──────────────────────────────────────────

/// Rebuild the whole plugin-manager model from the current manifest set and
/// config state. Cheap and rebuilt as a unit (the settings sheet has no
/// per-row animation to preserve), so a plain `set_vec` is fine.
fn refresh_plugins_model(plugin_model: &PluginRows, plugins: &[PluginManifest]) {
    plugin_model.set_vec(plugins.iter().map(plugin_row).collect::<Vec<_>>());
}

/// One plugin's manager row: its identity/engine, its effective enable and
/// ping state (from config, bridged for the well-known ids), a `SurfaceRow`
/// for each *opt-in* surface (non-opt-in surfaces are always on, so they
/// carry no toggle here), and an `OptionRow` for each declarative `[[option]]`
/// the manifest exposes, resolved to its current value.
/// A `[ping]` rendered as the command line it will actually run. The toggle
/// that fires it is a checkbox in Settings, and a checkbox that says "ping"
/// while running something else is how a third-party manifest would get a
/// command executed without ever saying so.
fn ping_command_line(ping: &manifest::PingConfig) -> String {
    if ping.args.is_empty() {
        ping.bin.clone()
    } else {
        format!("{} {}", ping.bin, ping.args.join(" "))
    }
}

fn plugin_row(m: &PluginManifest) -> PluginRow {
    let surfaces: Vec<SurfaceRow> = m
        .surface
        .iter()
        .filter(|s| s.opt_in)
        .map(|s| SurfaceRow {
            id: ss(&s.id),
            label: ss(&s.label),
            enabled: config::plugin_surface_enabled(&m.id, &s.id),
        })
        .collect();

    let options: Vec<OptionRow> = m
        .option
        .iter()
        .map(|o| OptionRow {
            key: ss(&o.key),
            label: ss(&o.label),
            enabled: config::plugin_option(&m.id, &o.key, o.default),
        })
        .collect();

    PluginRow {
        id: ss(&m.id),
        name: ss(&m.name),
        menu_label: ss(&m.menu_label),
        engine: ss(engine_label(m.engine)),
        enabled: plugin_enabled(m),
        has_ping: m.ping.is_some(),
        ping_command: ss(m.ping.as_ref().map(ping_command_line).unwrap_or_default()),
        ping_enabled: config::plugin_ping(&m.id),
        surfaces: ModelRc::from(Rc::new(VecModel::from(surfaces))),
        options: ModelRc::from(Rc::new(VecModel::from(options))),
        // Registry fields start idle on every plain reload — the "no update
        // known" state — and are only ever populated by a successful "Check
        // updates" (`apply_registry_check`) or reset back here by the very
        // next reload after an install/update lands. See the module-level
        // contract in the "Registry" section below: a rebuild here is
        // deliberately *not* preserved across a check, so any other plugin's
        // still-pending update badge goes stale until the next manual check
        // — the same "manual, user-triggered" stance the registry's fetch
        // itself takes.
        current_version: ss(&m.version),
        available_version: ss(""),
        has_local_edits: false,
        update_status: 0,
        update_error: ss(""),
    }
}

/// The manifest `engine` kind, in the manifest's own kebab-case spelling — the
/// label shown faintly next to each plugin in the manager.
fn engine_label(kind: EngineKind) -> &'static str {
    match kind {
        EngineKind::LogFile => "log-file",
        EngineKind::HttpApi => "http-api",
    }
}

/// Build (reset-rel, reset-at, tooltip, time-progress, time-known) for one
/// window. `reset-rel` is the compact countdown ("6d 2h"); `reset-at` the
/// absolute clock ("19 Jul 22:18" for weekly, "22:10" for 5h).
fn window_view(
    now: u64,
    used_percent: f64,
    resets_at: Option<u64>,
    window_minutes: Option<u64>,
    weekly: bool,
    name: &str,
) -> (String, String, String, f32, bool) {
    use chrono::{Local, TimeZone};

    // Round once and derive the complement — matching `LimitBlock`'s caption,
    // which does the same. Rounding both sides independently makes a 34.5%
    // reading say "35% used · 66% left" in the tooltip while the caption says
    // "35% / 65% left".
    let used = used_percent.round();
    let left = 100.0 - used;

    let Some(mut target) = resets_at else {
        let tip = format!("{name}\n{used:.0}% used · {left:.0}% left\nno reset time reported");
        return ("unknown".to_string(), String::new(), tip, 0.0, false);
    };

    let period = window_minutes
        .map(|m| m.saturating_mul(60))
        .filter(|p| *p > 0);
    if let Some(p) = period {
        target = next_reset_after(target, now, p);
    }
    let secs = (target as i64 - now as i64).max(0);

    let rel = if secs == 0 {
        "due".to_string()
    } else {
        let d = secs / 86400;
        let h = (secs % 86400) / 3600;
        let m = (secs % 3600) / 60;
        let s = secs % 60;
        if d > 0 {
            format!("{d}d {h}h")
        } else if h > 0 {
            format!("{h}h {m}m")
        } else if m > 0 {
            format!("{m}m {s:02}s")
        } else {
            format!("{s}s")
        }
    };

    let clock = Local
        .timestamp_opt(target as i64, 0)
        .single()
        .map(|dt| {
            if weekly {
                dt.format("%-d %b %H:%M").to_string()
            } else {
                dt.format("%H:%M").to_string()
            }
        })
        .unwrap_or_default();

    let progress = match period {
        Some(p) if secs > 0 => (1.0 - secs as f64 / p as f64).clamp(0.0, 1.0) as f32,
        _ => 0.0,
    };
    let time_known = period.is_some();

    let mut tooltip = format!("{name}\n{used:.0}% used · {left:.0}% left\nresets in {rel}");
    if !clock.is_empty() {
        tooltip.push_str(&format!(" · {clock}"));
    }
    if time_known {
        tooltip.push_str(&format!(
            "\npace {:+.0} pp (usage − elapsed time)",
            used - progress as f64 * 100.0
        ));
    }
    (rel, clock, tooltip, progress, time_known)
}

// ── Menu-bar title (Codex + Claude CLI) ──────────────────────────────────────

/// Compact used-quota value, matching every other figure this app shows: the
/// panel's caption, the widget's bar and its number. A trailing `!` is the
/// only severity signal the plain macOS menu-bar title can carry.
fn title_chunk(used: f64) -> String {
    let used = used.clamp(0.0, 100.0).round();
    let critical = if used >= 90.0 { "!" } else { "" };
    format!("{used:02.0}{critical}")
}

/// Compact tray title: used quota for `5h/week` per visible provider. Short
/// labels ("Cx"/"Cl") are always shown, except that the sole visible provider
/// may render bare when it allows it (`bare_when_sole` — a bare "96/80" reads
/// as Codex by convention). This stays within the 25–30 character budget.
fn menu_bar_title(readings: &[ProviderReading]) -> String {
    // Both values are always rendered as `5h/wk`; a missing window shows `--`
    // so the two positions never get confused.
    fn chunk_pair(r: &ProviderReading) -> Option<String> {
        // A reading we could not take is not a reading to print numbers out
        // of. Today no engine produces an error *and* windows, so this only
        // ever short-circuits an already-empty list — but the invariant that
        // makes it safe to skip is nowhere stated, and a future reading that
        // is partly wrong and partly usable would break it. Asking here costs
        // nothing and is the difference between the menu bar agreeing with
        // the panel and quietly contradicting it.
        if r.error.is_some() {
            return None;
        }
        let five = r.primary_window().and_then(|w| w.used_percent);
        let week = r.secondary_window().and_then(|w| w.used_percent);
        if five.is_none() && week.is_none() {
            return None;
        }
        Some(format!(
            "{}/{}",
            five.map(title_chunk).unwrap_or_else(|| "--".into()),
            week.map(title_chunk).unwrap_or_else(|| "--".into()),
        ))
    }

    let visible: Vec<(&ProviderReading, String)> = readings
        .iter()
        .filter(|r| r.in_menu_bar)
        .filter_map(|r| chunk_pair(r).map(|pair| (r, pair)))
        .collect();

    match visible.as_slice() {
        [] => "Limits".to_string(),
        [(r, pair)] if r.bare_when_sole => pair.clone(),
        _ => visible
            .iter()
            .map(|(r, pair)| format!("{} {}", r.short, pair))
            .collect::<Vec<_>>()
            .join(" · "),
    }
}

// ── Menu-bar widget (image) with plain-text fallback ─────────────────────────

/// The next occurrence of a reset at or after `now`, given a window that
/// repeats every `period` seconds.
///
/// Arithmetic rather than a loop, because the numbers are the provider's:
/// a reset timestamp far in the past next to a short window — `reset_at: 1`
/// with a one-minute window, say — is tens of millions of iterations, and both
/// callers run on the UI thread once a second, for every window on screen.
/// Saturating throughout: a period long enough to overflow simply never comes
/// round again, which is the honest answer for it.
fn next_reset_after(target: u64, now: u64, period: u64) -> u64 {
    if target > now || period == 0 {
        return target;
    }
    let missed = (now - target) / period + 1;
    target.saturating_add(missed.saturating_mul(period))
}

/// Elapsed fraction (0..1) of a quota window, for the widget playhead.
fn time_progress(now: u64, resets_at: Option<u64>, window_minutes: Option<u64>) -> Option<f32> {
    let target = resets_at?;
    let period = window_minutes
        .map(|m| m.saturating_mul(60))
        .filter(|p| *p > 0)?;
    let target = next_reset_after(target, now, period);
    let secs = target.saturating_sub(now) as f64;
    Some((1.0 - secs / period as f64).clamp(0.0, 1.0) as f32)
}

/// Widget rows from the readings: every menu-bar provider with data, in order.
fn widget_rows(now: u64, readings: &[ProviderReading]) -> Vec<menubar::ProviderRow> {
    fn stat(now: u64, window: Option<&Window>) -> Option<menubar::WindowStat> {
        let w = window?;
        Some(menubar::WindowStat {
            used_percent: w.used_percent?,
            time_progress: time_progress(now, w.resets_at, w.period_minutes),
        })
    }

    let mut rows = Vec::new();
    // Same rule as `menu_bar_title`'s, for the same reason.
    for r in readings
        .iter()
        .filter(|r| r.in_menu_bar && r.error.is_none())
    {
        let five_hour = stat(now, r.primary_window());
        let weekly = stat(now, r.secondary_window());
        if five_hour.is_some() || weekly.is_some() {
            rows.push(menubar::ProviderRow {
                label: r.short.clone(),
                five_hour,
                weekly,
            });
        }
    }
    rows
}

/// Menu-bar theme: `TICKOVER_THEME=light|dark` overrides (screenshots),
/// otherwise the system appearance.
fn menu_theme_dark() -> bool {
    match std::env::var("TICKOVER_THEME").ok().as_deref() {
        Some("light") => false,
        Some("dark") => true,
        _ => platform::system_dark_theme(),
    }
}

/// The tooltip shown on hovering the tray icon.
///
/// Windows has no title beside a notification-area icon, so the compact
/// figures the menu-bar pill carries in its own image have nowhere to go
/// there — except here, where hovering has always been how a tray icon says
/// more than its 16 pixels can. macOS gets the same string for the same
/// reason it is worth having at all: the pill states used-% and nothing else,
/// and the tooltip is the one place the app's own name still appears.
fn tray_tooltip(readings: &[ProviderReading]) -> String {
    let figures = menu_bar_title(readings);
    // `menu_bar_title`'s own "nothing to report" answer. Repeating it after
    // the name would read as a second, emptier label.
    if figures == "Limits" {
        "Tickover".to_string()
    } else {
        format!("Tickover\n{figures}")
    }
}

/// Sync the tray to the current state: rendered widget image when enabled and
/// data is present; compact text title when the widget can't render; plain
/// template glyph otherwise. `last_key` suppresses redundant native calls.
fn sync_tray_indicator(
    tray: &TraySlot,
    enabled: bool,
    plugins: &[PluginManifest],
    cache: &PluginCache,
    last_key: &Rc<RefCell<String>>,
) {
    let Some(tray) = tray.borrow().as_ref().cloned() else {
        return;
    };
    let now = now_unix();
    let readings = readings(plugins, &cache.borrow());

    let widget = if enabled {
        let rows = widget_rows(now, &readings);
        if rows.is_empty() {
            None
        } else {
            let dark = menu_theme_dark();
            Some((rows, dark))
        }
    } else {
        None
    };

    let tooltip = tray_tooltip(&readings);
    let key = match &widget {
        Some((rows, dark)) => format!("{}|{tooltip}", menubar::cache_key(rows, *dark)),
        None if enabled => format!("empty|{tooltip}"),
        None => format!("off|{tooltip}"),
    };
    if *last_key.borrow() == key {
        return;
    }
    // The figures move once a minute even when the widget's own rounded
    // numbers have not, so this is set on every key change rather than only
    // alongside an icon that actually changed.
    let _ = tray.set_tooltip(Some(&tooltip));

    if let Some((rows, dark)) = widget {
        // Two shapes of the same reading, because the two trays are not the
        // same shape. macOS lets a status item carry a wide image in place of
        // its title, which is what the pill is; Windows draws a small square
        // and has no title at all, so it gets `render_badge` — the pill's
        // bars without its text, the text having moved to the tooltip.
        #[cfg(target_os = "windows")]
        let rendered = menubar::render_badge(&rows, dark, tray_badge_px());
        #[cfg(not(target_os = "windows"))]
        let rendered = menubar::render(&rows, dark, 2.0);

        if let Some(img) = rendered {
            let (w, h) = img.dimensions();
            if let Ok(icon) = tray_icon::Icon::from_rgba(img.into_raw(), w, h) {
                let _ = tray.set_icon(Some(icon));
                tray.set_icon_as_template(false);
                tray.set_title(Some(""));
                *last_key.borrow_mut() = key;
                return;
            }
        }
        // Fallback: template glyph + compact text title. Nothing renders it
        // on Windows (`set_title` is macOS-only in `tray-icon`), but the
        // tooltip above already carries the same figures there.
        if let Some(icon) = load_tray_icon() {
            let _ = tray.set_icon(Some(icon));
        }
        tray.set_icon_as_template(cfg!(target_os = "macos"));
        tray.set_title(Some(menu_bar_title(&readings)));
        *last_key.borrow_mut() = key;
        return;
    }

    // Disabled (or no data yet): plain template glyph, no text.
    if let Some(icon) = load_tray_icon() {
        let _ = tray.set_icon(Some(icon));
    }
    tray.set_icon_as_template(cfg!(target_os = "macos"));
    tray.set_title(Some(""));
    *last_key.borrow_mut() = key;
}

/// Edge, in real pixels, of the badge handed to the notification area.
///
/// Asked of the system rather than fixed, because whatever else is handed
/// over gets *resampled* — and the badge is a stack of 2px bars separated by
/// 1px gaps, which is exactly the kind of picture that resampling turns to
/// mush. Rendering at 32 and letting Windows halve it was tried here and
/// looked it: the bars blurred into each other and the grouping that
/// separates one provider from the next stopped reading at all. Drawn at the
/// size it will be shown at, every bar lands on whole pixels.
///
/// `SM_CXSMICON` is the small-icon metric the notification area uses, already
/// scaled for the display (16 at 100%, 24 at 150%, 32 at 200%). A zero or
/// nonsense answer falls back to 16, the metric's own default.
#[cfg(target_os = "windows")]
fn tray_badge_px() -> u32 {
    use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSMICON};
    let px = unsafe { GetSystemMetrics(SM_CXSMICON) };
    if (8..=64).contains(&px) {
        px as u32
    } else {
        16
    }
}

// ── Popover chrome ───────────────────────────────────────────────────────────

/// Where the dock-mode panel should end up after one poll tick.
///
/// `clicks` is how many Dock-icon reopen events arrived since the last tick and
/// `became_active` whether the app went frontmost during it. Both can be true
/// at once, and the events' relative order is not recoverable, so the tick is
/// resolved as a net effect rather than replayed.
///
/// Activation means "show me the panel", not "toggle": a Dock click on a
/// background app, or a Cmd-Tab (which sends no reopen event at all), should
/// never dismiss what the user just asked to see. So activation pins the target
/// to visible and consumes the click that caused it; every remaining click is a
/// toggle, and an even number of them cancels out.
/// How long a status-item click stays responsible for the activation it
/// causes. Long enough to cover the gap between the click and the app becoming
/// frontmost (both are delivered on the main thread, so this is scheduling
/// latency, not user time); short enough that a Dock click a moment later is
/// still a Dock click.
const TRAY_CLICK_OWNS_ACTIVATION: Duration = Duration::from_millis(600);

/// Whether an activation edge is the tail of a status-item click rather than a
/// Dock click of its own. Saturating, so a clock that jumps backwards reads as
/// "not the tray's" — the worse failure is a click that toggles twice, not one
/// that toggles once.
fn activation_owned_by_tray(tray_click_at: Option<Instant>, now: Instant) -> bool {
    tray_click_at.is_some_and(|at| now.saturating_duration_since(at) < TRAY_CLICK_OWNS_ACTIVATION)
}

/// Whether this platform delivers the focus loss a status-item click causes
/// *before* the click itself.
///
/// Windows does — measured there, and the reason the window below exists. macOS
/// does not, and the evidence is this app's own history: the click handler has
/// always read `is_visible()` and hidden an open panel on that branch, and the
/// panel has closed on a second click for as long as it has been in daily use.
/// Were the hide arriving first, `is_visible()` would have been false every
/// time and the item could only ever have opened the panel.
///
/// It matters because the mark is set by *any* focus loss — clicking another
/// app, or the desktop, or the window that takes focus at launch. Off Windows
/// that turns a legitimate open into a swallowed click whenever one follows a
/// dismissal inside the window below, and buys nothing in return.
const TRAY_CLICK_CAN_ARRIVE_AFTER_ITS_OWN_DISMISSAL: bool = cfg!(target_os = "windows");

/// How long after hiding on focus loss a status-item click still counts as
/// the thing that caused it.
///
/// Only has to cover the gap between the press taking focus off the panel and
/// the click being delivered — both on the same thread, so this is scheduling
/// latency. Short enough that going away, clicking something else, and coming
/// back to the item is an ordinary open.
const TRAY_CLICK_DISMISS_WINDOW: Duration = Duration::from_millis(500);

/// Whether a status-item click has already had its effect — closing the panel
/// — before it arrived.
///
/// Clicking the item while the panel is open never reaches the click handler
/// with the panel still open. Pressing anywhere outside the card takes focus
/// away from it, the focus-loss handler hides it, and only then is the tray
/// click delivered; `is_visible()` says false by that point. Read literally,
/// that is "closed, so open it" — so the panel the user just dismissed flicks
/// straight back, and the item only ever opens, never closes. Measured here:
/// two clicks in a row both logged `visible=false`.
///
/// Saturating only so the subtraction cannot panic; `Instant` is monotonic,
/// so the ordering this relies on holds.
fn tray_click_dismissed_panel(hidden_by_focus_at: Option<Instant>, now: Instant) -> bool {
    hidden_by_focus_at
        .is_some_and(|at| now.saturating_duration_since(at) < TRAY_CLICK_DISMISS_WINDOW)
}

fn panel_target_visibility(became_active: bool, clicks: usize, visible: bool) -> bool {
    let (base, toggles) = if became_active {
        (true, clicks.saturating_sub(1))
    } else {
        (visible, clicks)
    };
    base != (toggles % 2 == 1)
}

/// Fit the provider list's height budget to the monitor the window is on.
///
/// The cap cannot live in the UI as a constant: 620px sized for a 768px
/// display still overflows that same display at 125% scaling, and once the
/// window extends past the screen the Flickable believes its whole viewport is
/// visible, so the overflow cannot even be scrolled to. Measured per show —
/// the window can move between monitors.
fn sync_providers_cap(app: &AppWindow) {
    use slint::winit_030::{winit, WinitWindowAccessor};
    let mut cap = 620.0_f32;
    app.window().with_winit_window(|w: &winit::window::Window| {
        if let Some(monitor) = w.current_monitor() {
            let logical_h = monitor.size().height as f64 / monitor.scale_factor();
            // Leave room for the panel chrome around the list (~80) plus the
            // menu bar / taskbar and the anchor gap the popover hangs from.
            cap = ((logical_h - 200.0) as f32).clamp(240.0, 620.0);
        }
    });
    app.set_providers_cap(cap);
}

/// What asked for the panel — which decides whether showing it also moves it.
///
/// Only dock mode makes the distinction. There the window is an ordinary one
/// the user can drag, so a show that re-places it would throw away wherever
/// they left it. A click on the status item is the one show that names a
/// place: the panel belongs under the icon that was clicked, draggable or not.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Shown {
    /// The status item in the menu bar was clicked.
    ByTrayClick,
    /// First launch, a second launch's note, or a Dock reopen — none of which
    /// point at a spot on screen.
    ByAnythingElse,
}

/// Whether this presentation places the window.
///
/// Outside dock mode the panel is a transient flyout that always hangs off the
/// status item, so it is placed every time. Inside dock mode it is placed once
/// — a window with no position is worse than one in the wrong place — and
/// after that only a tray click moves it.
fn popover_moves(dock_mode: bool, placed_before: bool, shown: Shown) -> bool {
    !dock_mode || !placed_before || shown == Shown::ByTrayClick
}

fn present_popover(app: &AppWindow, anchor: &Anchor, shown_at: &Rc<Cell<Instant>>, shown: Shown) {
    // A new popover presentation always starts on the gauges, not a stale modal.
    app.set_settings_open(false);
    // Nor a stale tooltip. A bubble raised by hovering a bar has no leave
    // event coming once the panel is dismissed out from under the pointer, so
    // without this it is what greets the next presentation.
    app.set_tip(BarTip::default());
    let _ = app.window().show();
    position_popover(app, anchor, shown);
    // Only after show + position: Slint creates the winit window lazily, so
    // measuring before `show()` is a no-op on the first presentation, and
    // measuring before `position_popover` reads the monitor the window is
    // *leaving* when the anchor moved to another screen.
    sync_providers_cap(app);
    shown_at.set(Instant::now());

    use slint::winit_030::{winit, WinitWindowAccessor};
    // A tray popover is transient and dismisses on focus loss, so floating
    // above everything is what makes it feel attached to the menu bar. The
    // dock-mode window is neither: it stays open on focus loss, so the same
    // level would leave it covering every other app until it is toggled off.
    let level = if platform::dock_mode() {
        winit::window::WindowLevel::Normal
    } else {
        winit::window::WindowLevel::AlwaysOnTop
    };
    app.window().with_winit_window(|w: &winit::window::Window| {
        w.set_window_level(level);
        w.focus_window();
    });
    platform::activate_app();
}

/// A screen the popover has to stay inside: `(x, y, width, height)` in
/// physical pixels, the same space the tray event's rect and `set_position`
/// already speak.
type ScreenRect = (f64, f64, f64, f64);

/// Gap between the status item and the card hanging off it.
const POPOVER_GAP: f64 = 6.0;
/// Closest the card is allowed to sit to a screen edge.
const POPOVER_MARGIN: f64 = 8.0;

/// Where a popover of `win_w` × `win_h` belongs against its status item.
///
/// Which *side* of the item the card hangs off cannot be assumed. macOS keeps
/// the menu bar at the top of the screen, so underneath is the only
/// arrangement that reads right there — and that is what this used to do
/// unconditionally. Windows puts the notification area in the taskbar, which
/// sits at the bottom by default: hanging the card underneath drops it off
/// the screen, and the quota numbers this app exists to show are precisely
/// the part that ends up cut off (observed here — a 339px card placed at
/// y=1261 on a 1440px screen, with everything below the Codex row past the
/// edge). So the side is read off where the item actually is, which also
/// covers a taskbar moved to the top, and the horizontal clamp covers one
/// moved to a side.
///
/// Everything is physical pixels.
fn popover_origin(
    anchor: Option<(f64, f64, f64, f64)>,
    (win_w, win_h): (f64, f64),
    screen: ScreenRect,
    scale: f64,
) -> (f64, f64) {
    let (sx, sy, sw, sh) = screen;
    let gap = POPOVER_GAP * scale;
    let margin = POPOVER_MARGIN * scale;

    let Some((ax, ay, aw, ah)) = anchor else {
        // Nothing to hang off: a snapshot run, or dock mode's one placement
        // before the user has moved the window themselves. Still held inside
        // the screen — the offsets below are an opening position, not a
        // promise that the card fits to the right of and beneath them, and a
        // display smaller than the card would otherwise start it off the edge
        // with no anchor to pull it back.
        return (
            clamp_onto(sx + 240.0 * scale, win_w, sx, sw, margin),
            clamp_onto(sy + 48.0 * scale, win_h, sy, sh, margin),
        );
    };

    let below = ay + ah + gap;
    let above = ay - win_h - gap;
    let y = if below + win_h + margin <= sy + sh {
        below
    } else if above >= sy + margin {
        above
    } else {
        // A screen shorter than the card, on either side of the item. Sit as
        // high as the margin allows and let the provider list scroll the rest
        // — `sync_providers_cap` sizes that budget against this same screen.
        sy + margin
    };

    // Centred on the item, then pulled back inside the screen.
    (
        clamp_onto(ax + aw / 2.0 - win_w / 2.0, win_w, sx, sw, margin),
        y,
    )
}

/// Hold one axis of the card inside one axis of the screen.
///
/// `max` on the upper bound rather than a bare `clamp`, because a card longer
/// than the screen would otherwise give `clamp` an inverted range and panic —
/// which is reachable: `sync_providers_cap` bounds the provider list, not the
/// chrome around it, and a small enough display can be shorter than what is
/// left. Such a card starts at the margin and runs past the far edge, which is
/// the same thing the fallback above settles for and the list scrolls.
fn clamp_onto(pos: f64, len: f64, screen_pos: f64, screen_len: f64, margin: f64) -> f64 {
    let lo = screen_pos + margin;
    pos.clamp(lo, (screen_pos + screen_len - len - margin).max(lo))
}

/// The screen the status item sits on.
///
/// Deliberately not `current_monitor()`: that answers where the *window* is,
/// which on every show after the first is the screen the popover is about to
/// leave when the tray lives on another one. The item's own centre picks the
/// right screen directly. `None` when winit can name no monitor at all, which
/// [`position_popover`] reads as "don't constrain".
fn anchor_screen(app: &AppWindow, anchor: Option<(f64, f64, f64, f64)>) -> Option<ScreenRect> {
    use slint::winit_030::{winit, WinitWindowAccessor};
    fn rect(m: &winit::monitor::MonitorHandle) -> ScreenRect {
        let (p, s) = (m.position(), m.size());
        (p.x as f64, p.y as f64, s.width as f64, s.height as f64)
    }
    let mut found = None;
    app.window().with_winit_window(|w: &winit::window::Window| {
        if let Some((ax, ay, aw, ah)) = anchor {
            let (cx, cy) = (ax + aw / 2.0, ay + ah / 2.0);
            found = w
                .available_monitors()
                .find(|m| {
                    let (x, y, mw, mh) = rect(m);
                    cx >= x && cx < x + mw && cy >= y && cy < y + mh
                })
                .map(|m| rect(&m));
        }
        if found.is_none() {
            found = w
                .current_monitor()
                .or_else(|| w.primary_monitor())
                .map(|m| rect(&m));
        }
    });
    found
}

fn position_popover(app: &AppWindow, anchor: &Anchor, shown: Shown) {
    // Recorded whatever the mode, so that switching into dock mode mid-session
    // does not count the window as never placed.
    thread_local! {
        static PLACED: Cell<bool> = const { Cell::new(false) };
    }
    let placed_before = PLACED.with(|placed| placed.replace(true));
    if !popover_moves(platform::dock_mode(), placed_before, shown) {
        return;
    }
    let scale = app.window().scale_factor() as f64;
    let size = app.window().size();
    let anchor = *anchor.borrow();
    // No monitor to be had: fall back to a screen so large that every fit
    // test passes, which reproduces the unconstrained placement this had
    // before there was anything to constrain it with.
    let screen = anchor_screen(app, anchor).unwrap_or((0.0, 0.0, f64::MAX, f64::MAX));
    let (x, y) = popover_origin(
        anchor,
        (size.width as f64, size.height as f64),
        screen,
        scale,
    );
    app.window()
        .set_position(PhysicalPosition::new(x as i32, y as i32));
}

/// The directories a provider CLI is looked for in — and, just as importantly,
/// the ones it is handed as `PATH` when it runs.
///
/// A thin wrapper, kept only so `find_bin`/`cli_path_env` and their tests
/// below don't have to move: the list itself is canonical in
/// [`tickover::plugin::cli_install_dirs`] now, shared with
/// `plugin::auth::bin_candidates`'s `oauth-refresh` client discovery, which
/// needed the exact same "where a CLI this app didn't install lives" answer
/// and has no way to reach a function private to this binary.
fn cli_dirs() -> Vec<std::path::PathBuf> {
    tickover::plugin::cli_install_dirs()
}

/// Locate a CLI binary by name (a bundled app has a minimal PATH). Prefers the
/// real npm/homebrew install over anything in PATH.
fn find_bin(name: &str) -> Option<std::path::PathBuf> {
    let exe = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    let mut dirs_to_check = cli_dirs();
    if let Some(p) = std::env::var_os("PATH") {
        dirs_to_check.extend(std::env::split_paths(&p));
    }
    dirs_to_check
        .into_iter()
        .map(|d| d.join(&exe))
        .find(|c| c.is_file())
}

/// `PATH` for a spawned CLI: whatever this process inherited, **then**
/// [`cli_dirs`], so a wrapper script can reach its interpreter (see
/// [`cli_dirs`]).
///
/// Appended, not prepended — the opposite of [`find_bin`], and deliberately.
/// `find_bin` is choosing *which* CLI to run and prefers a real install over
/// whatever a stray PATH entry offers. This is the environment that CLI then
/// runs in, unattended, and every one of these directories is user-writable:
/// putting them first would let anything dropped in one shadow the `git`,
/// `ssh` or `curl` the CLI reaches for. Appending only ever *adds* places to
/// look, which is all the interpreter needed.
///
/// Joining can only fail on a directory containing the path separator itself,
/// which none of these do; if it somehow does, the caller keeps the inherited
/// environment rather than invents a truncated one.
fn cli_path_env() -> Option<std::ffi::OsString> {
    let inherited = std::env::var_os("PATH").unwrap_or_default();
    let mut dirs: Vec<std::path::PathBuf> = std::env::split_paths(&inherited).collect();
    dirs.extend(cli_dirs());
    std::env::join_paths(dirs).ok()
}

/// The directory the ping's command runs in: an empty one this app owns,
/// beside the plugins folder.
///
/// Not the home directory, which is where it used to run. These CLIs read the
/// directory they start in — `codex exec` picks up `AGENTS.md` from it as
/// instructions — and the ping is a model run on a timer that nobody is
/// watching and whose output is discarded. Handing it the home directory's
/// contents as instructions is the ideal setup for a prompt injection; handing
/// it an empty directory gives it nothing to read. Falls back to the home
/// directory only if that directory can't be created, since a command with no
/// working directory at all won't start.
fn ping_cwd() -> std::path::PathBuf {
    let dir = seed::plugins_dir().with_file_name("ping-workdir");
    match std::fs::create_dir_all(&dir) {
        Ok(()) => dir,
        Err(_) => dirs::home_dir().unwrap_or_else(|| ".".into()),
    }
}

/// How long the ping's command may run before it is killed.
///
/// It exists to bound a *hang* — a CLI waiting on a read that never returns
/// holds a thread and a process for as long as this app lives. Deliberately
/// far longer than any healthy answer takes (the real thing is seconds),
/// because the failure it guards against is unbounded while killing a slow but
/// living run would be a worse bug than the one being fixed.
const PING_DEADLINE: Duration = Duration::from_secs(600);

/// Most stderr worth quoting from a failed run; the rest is dropped. A CLI
/// that fails by printing a megabyte must not put a megabyte in the log.
const PING_STDERR_MAX: usize = 2000;

/// A command's stderr as one quotable line.
///
/// Cut by **characters**, not bytes: replacing an invalid byte with `U+FFFD`
/// makes the lossy decode longer than the bytes it read, so a byte-indexed
/// `String::truncate` could land inside a character — which panics, in a
/// thread whose whole job is reporting that something else went wrong. And a
/// panic here is not a lost log line: this crate builds with `panic = "abort"`.
///
/// Newlines become `⏎` so one failure stays one line: the log is grepped, and
/// its trimming counts on a record being a line.
fn quotable(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .trim()
        .chars()
        .take(PING_STDERR_MAX)
        .map(|c| if c == '\n' || c == '\r' { '⏎' } else { c })
        .collect()
}

/// How a command that was started ended.
#[derive(Debug)]
enum RunOutcome {
    /// It exited on its own.
    Exited(std::process::ExitStatus),
    /// It outlived the deadline and was killed.
    Killed,
    /// Waiting on it failed; it has been killed and reaped anyway.
    Unwaitable(std::io::Error),
}

/// Wait for `child`, killing it if it outlives `deadline`. Returns how it
/// ended, plus up to [`PING_STDERR_MAX`] bytes of the **tail** of its stderr.
///
/// Split out from [`spawn_hello`] so the three things that are easy to get
/// wrong here — the deadline, the drain, and which end of the output is kept
/// — can be tested against a real process without a plugin, a manifest, or a
/// provider (see this module's tests).
///
/// The tail rather than the head: a CLI that fails usually says why last, and
/// what precedes it is warnings. `diag.rs` keeps the tail of the log for the
/// same reason.
fn run_with_deadline(mut child: std::process::Child, deadline: Duration) -> (RunOutcome, Vec<u8>) {
    // Drained on a thread of its own rather than after the wait: a command
    // chatty enough to fill the pipe would otherwise block writing to it while
    // we block waiting for it to exit, and neither would move again. Read to
    // EOF even though most of it is dropped — stopping early would close this
    // end, and the next thing the command wrote would kill it, turning "warned
    // more than we cared to quote" into a failed ping.
    //
    // Shared rather than joined: the pipe stays open while *anything* holds
    // its write end, and a killed command may well have left a grandchild that
    // inherited it. Joining could then wait forever — reinstating, inside the
    // deadline's own cleanup, the hang the deadline exists to stop.
    let stderr = child.stderr.take();
    let collected = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let sink = std::sync::Arc::clone(&collected);
    std::thread::spawn(move || {
        use std::io::Read;
        if let Some(mut stderr) = stderr {
            let mut chunk = [0u8; 4096];
            while let Ok(n) = stderr.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                if let Ok(mut kept) = sink.lock() {
                    kept.extend_from_slice(&chunk[..n]);
                    let over = kept.len().saturating_sub(PING_STDERR_MAX);
                    kept.drain(..over);
                }
            }
        }
    });

    let expiry = Instant::now() + deadline;
    let outcome = loop {
        match child.try_wait() {
            Ok(Some(status)) => break RunOutcome::Exited(status),
            Ok(None) if Instant::now() >= expiry => {
                // Asked once more first: a process that finished during the
                // last sleep is not one this deadline killed, and reporting it
                // as killed would send someone looking for a hang that never
                // happened.
                let _ = child.kill();
                break match child.wait() {
                    Ok(status) if status.success() => RunOutcome::Exited(status),
                    _ => RunOutcome::Killed,
                };
            }
            // Polled rather than blocked on, because a blocking wait can't be
            // woken by a deadline. A quarter-second costs nothing against a
            // command that normally takes seconds.
            Ok(None) => std::thread::sleep(Duration::from_millis(250)),
            Err(e) => {
                // Whatever went wrong asking after it, this process started
                // it: end it and reap it rather than leave it behind.
                let _ = child.kill();
                let _ = child.wait();
                break RunOutcome::Unwaitable(e);
            }
        }
    };
    // Whatever the drain has by now. It is still running if a grandchild holds
    // the pipe; that thread ends when the last writer does.
    let raw = collected
        .lock()
        .map(|kept| kept.clone())
        .unwrap_or_default();
    (outcome, raw)
}

/// Fire-and-forget CLI run, stdout discarded, everything else recorded. A
/// failure to start, a non-zero exit, or a run that outlives
/// [`PING_DEADLINE`], is recorded **with the command's own stderr quoted**:
/// the whole point of the ping is a run nobody watches, and the one line that
/// explains such a failure ("Not inside a trusted directory…") is the one that
/// used to be thrown away with it.
fn spawn_hello(bin: std::path::PathBuf, args: Vec<String>) {
    let cwd = ping_cwd();
    let path = cli_path_env();
    std::thread::spawn(move || {
        let mut cmd = std::process::Command::new(&bin);
        cmd.args(&args)
            .current_dir(cwd)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        if let Some(path) = path {
            cmd.env("PATH", path);
        }
        diag::line(format!(
            "auto-ping: running {} {}",
            bin.display(),
            args.join(" ")
        ));
        let child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                diag::line(format!("auto-ping: {} did not start: {e}", bin.display()));
                return;
            }
        };

        let (outcome, raw) = run_with_deadline(child, PING_DEADLINE);
        let quoted = match quotable(&raw) {
            why if why.is_empty() => String::new(),
            why => format!(": {why}"),
        };
        match outcome {
            RunOutcome::Exited(status) if status.success() => {
                diag::line(format!("auto-ping: {} finished", bin.display()));
            }
            RunOutcome::Exited(status) => {
                diag::line(format!(
                    "auto-ping: {} exited with {status}{quoted}",
                    bin.display()
                ));
            }
            RunOutcome::Killed => diag::line(format!(
                "auto-ping: {} killed after {}s without finishing{quoted}",
                bin.display(),
                PING_DEADLINE.as_secs()
            )),
            RunOutcome::Unwaitable(e) => {
                diag::line(format!(
                    "auto-ping: {} could not be waited on: {e}",
                    bin.display()
                ));
            }
        }
    });
}

/// Run a plugin's `[ping]` command (e.g. `codex exec hello` / `claude -p
/// hello`) — fired 5s after its first surface's 5-hour window resets, if the
/// user opted in (gated by `config::plugin_ping`).
fn send_ping(ping: &manifest::PingConfig) {
    match find_bin(&ping.bin) {
        Some(bin) => spawn_hello(bin, ping.args.clone()),
        None => diag::line(format!("auto-ping: {} binary not found", ping.bin)),
    }
}

// ── Registry: Check updates / Install / Update ───────────────────────────
//
// `src/plugin/registry.rs` is pure and hermetic except for its two network
// calls, `fetch_text` (`index.toml`) and `fetch_bytes` (a manifest file,
// undecoded — see its own docs for why a manifest can't go through
// `fetch_text`) — parsing/validating `index.toml`, resolving a manifest URL,
// sha256 verification, the lockfile, the installed-vs-registry diff, and the
// trust disclosure all live there and are unit-tested with zero network
// access. Everything below is this app's orchestration of those primitives:
// running the fetch on a background thread so it can never freeze the
// popover, driving the native two-pass trust dialog before a third-party
// manifest is ever written to disk, and the actual filesystem writes
// (`registry.rs` never writes a plugin manifest itself — see its own module
// docs).

/// The result of a background "Check updates" fetch+parse, crossing from the
/// worker thread to the UI thread over the `registry_tx`/`registry_rx`
/// channel set up in `main`. The two error variants carry no message of
/// their own — [`apply_registry_check`] renders a fixed, full user-facing
/// sentence for each (`registry-error`'s own doc comment in `ui/app.slint`
/// calls for exactly that: Rust picks the wording, Slint renders it
/// verbatim); the raw underlying error is only ever logged to stderr, for a
/// developer, not shown to the user.
enum RegistryCheckMsg {
    NetworkError,
    Malformed,
    Success(RegistryIndex),
}

/// The signature file that goes with an index, by minisign's convention:
/// the index's own URL with `.minisig` on the end.
fn signature_url(index_url: &str) -> String {
    format!("{index_url}.minisig")
}

/// Fetch `url` and parse it as an `index.toml` — the whole background-thread
/// body of `check-updates`. Never touches the UI or the filesystem; safe to
/// run off the calling thread.
///
/// The signature is checked **before** the index is parsed. That order is the
/// point: an index this app will not vouch for is never read for what it says
/// about itself, so nothing downstream — not a version comparison, not a
/// manifest URL, not a `sha256` — ever comes from bytes whose publisher is in
/// doubt. Everything downstream still happens afterwards, unchanged; this is
/// a gate in front of them, never a substitute for one.
fn fetch_registry_index(url: &str) -> RegistryCheckMsg {
    // Fetched as bytes rather than text, because a signature is over the
    // bytes a server sent and nothing else. Decoding first and verifying the
    // decoded form would check a signature over something the publisher never
    // signed — the same argument `registry::fetch_bytes` already makes for a
    // manifest's sha256, and it applies here for the same reason.
    match registry::fetch_bytes(url) {
        Ok(raw) => {
            // "Not published" and "could not be fetched" are different
            // answers, and only the first is what this check is against. A
            // 404 is the registry saying it publishes no signature; anything
            // else is a network event, and reporting it as a malformed index
            // would blame the publisher for the reader's bad minute — and
            // hand anyone who can drop one request the power to make an
            // honest registry look corrupt.
            let signature = match registry::fetch_text(&signature_url(url)) {
                Ok(text) => Some(text),
                Err(e) if e.starts_with("HTTP 404") => None,
                Err(e) => {
                    if signature::REGISTRY_PUBLIC_KEY.is_some() {
                        diag::line(format!(
                            "check-updates: could not fetch the signature for \
                             {url}: {e}"
                        ));
                        return RegistryCheckMsg::NetworkError;
                    }
                    None
                }
            };
            match signature::verify_index(&raw, signature.as_deref()) {
                Ok(signature::Verification::Signed) => {}
                Ok(signature::Verification::Unverifiable) => {
                    // Said on every check, not once at startup: a check that
                    // is off is only safe while it is visible that it is off.
                    diag::line(format!(
                        "check-updates: this build pins no registry public key, \
                         so nothing about who published {url} was verified"
                    ));
                }
                Err(e) => {
                    diag::line(format!("check-updates: refusing {url}: {e}"));
                    return RegistryCheckMsg::Malformed;
                }
            }
            // Only now is it read for what it says about itself.
            let text = match String::from_utf8(raw) {
                Ok(text) => text,
                Err(e) => {
                    diag::line(format!("check-updates: {url} is not UTF-8: {e}"));
                    return RegistryCheckMsg::Malformed;
                }
            };
            match RegistryIndex::from_str(&text) {
                Ok(index) => RegistryCheckMsg::Success(index),
                Err(e) => {
                    diag::line(format!(
                        "check-updates: index.toml failed to parse ({url}): {e}"
                    ));
                    RegistryCheckMsg::Malformed
                }
            }
        }
        Err(e) => {
            diag::line(format!("check-updates: network error fetching {url}: {e}"));
            RegistryCheckMsg::NetworkError
        }
    }
}

/// One successful "Check updates" folded into what the UI needs: which
/// already-installed plugins have an update (id → (available version,
/// has-local-edits)), and one [`RegistryPluginRow`] per not-yet-installed
/// plugin — the pure core of [`apply_registry_check`]'s success path, kept
/// separate so the diff→row mapping is unit-testable on fixtures without a
/// plugins directory or a running `AppWindow`.
struct RegistryDiff {
    updates: HashMap<String, (String, bool)>,
    new_rows: Vec<RegistryPluginRow>,
    update_count: usize,
    new_count: usize,
}

/// Fold [`registry::diff_installed`]'s per-entry states into a
/// [`RegistryDiff`]. `installed` and `lockfile` are exactly
/// `diff_installed`'s own parameters — see that function's doc comment for
/// their contract (byte-exact `current_file_sha256` in particular).
fn fold_registry_diff(
    index: &RegistryIndex,
    installed: &[(String, String, String)],
    lockfile: &registry::RegistryLockState,
) -> RegistryDiff {
    let states = registry::diff_installed(index, installed, lockfile);
    let mut diff = RegistryDiff {
        updates: HashMap::new(),
        new_rows: Vec::new(),
        update_count: 0,
        new_count: 0,
    };
    for (entry, state) in index.plugins.iter().zip(states.iter()) {
        match state {
            RegistryPluginState::New => {
                diff.new_count += 1;
                diff.new_rows.push(registry_entry_row(entry));
            }
            RegistryPluginState::UpdateAvailable { overwrite_safe, .. } => {
                diff.update_count += 1;
                diff.updates
                    .insert(entry.id.clone(), (entry.version.clone(), !overwrite_safe));
            }
            RegistryPluginState::UpToDate { .. } => {}
        }
    }
    diff
}

/// One not-yet-installed registry entry as a `registry-new` row: `status =
/// 0` (available) with no error — [`set_registry_row_status`] is what moves
/// it to installing/failed once the user actually clicks Install.
fn registry_entry_row(entry: &RegistryEntry) -> RegistryPluginRow {
    RegistryPluginRow {
        id: ss(&entry.id),
        name: ss(&entry.name),
        version: ss(&entry.version),
        description: ss(entry.description.as_deref().unwrap_or_default()),
        status: 0,
        error: ss(""),
    }
}

/// Apply a "Check updates" background result to the UI. The two error
/// statuses render a fixed sentence (`registry-error`); a successful fetch
/// re-reads every installed manifest's on-disk sha256 ([`fold_registry_diff`]
/// requires the byte-exact hash, never a re-serialization — see
/// `registry::diff_installed`'s own doc comment), diffs against the index,
/// then rebuilds the plugin manager's update badges and the "available from
/// registry" list. A network/parse failure deliberately leaves a
/// previously-cached [`RegistryIndex`] in `registry_index_cache` alone,
/// rather than throwing away an otherwise-still-valid install/update target
/// over a transient blip.
fn apply_registry_check(
    app: &AppWindow,
    msg: RegistryCheckMsg,
    plugins: &Plugins,
    plugin_model: &PluginRows,
    registry_model: &RegistryRows,
    registry_index_cache: &RegistryIndexCache,
    last_registry_check: &Rc<Cell<Option<u64>>>,
) {
    match msg {
        RegistryCheckMsg::NetworkError => {
            app.set_registry_status(2);
            app.set_registry_error(ss("Registry unreachable — check your connection"));
        }
        RegistryCheckMsg::Malformed => {
            app.set_registry_status(3);
            app.set_registry_error(ss(
                "Registry index is corrupted (index.toml failed to parse)",
            ));
        }
        RegistryCheckMsg::Success(index) => {
            let dir = seed::plugins_dir();
            let installed: Vec<(String, String, String)> = plugins
                .borrow()
                .iter()
                .filter_map(|m| {
                    let path = find_plugin_manifest_path(&dir, &m.id)?;
                    let bytes = std::fs::read(&path).ok()?;
                    Some((
                        m.id.clone(),
                        registry::sha256_hex(&bytes),
                        m.version.clone(),
                    ))
                })
                .collect();
            let lockfile = registry::load_lockfile(&registry::lockfile_path());
            let diff = fold_registry_diff(&index, &installed, &lockfile);

            // Rebuild every plugin row from a clean slate (this also
            // re-aligns the model's length/order with `plugins`), then layer
            // the update badge on top of whichever rows `diff` found one
            // for — see `plugin_row`'s own doc comment on why a plain
            // rebuild elsewhere in this file (add/remove/toggle) is allowed
            // to drop a still-pending badge until the next manual check.
            refresh_plugins_model(plugin_model, &plugins.borrow());
            for (i, m) in plugins.borrow().iter().enumerate() {
                let Some((available, has_local_edits)) = diff.updates.get(&m.id) else {
                    continue;
                };
                let Some(mut row) = plugin_model.row_data(i) else {
                    continue;
                };
                row.available_version = ss(available);
                row.has_local_edits = *has_local_edits;
                plugin_model.set_row_data(i, row);
            }

            registry_model.set_vec(diff.new_rows);
            *registry_index_cache.borrow_mut() = Some(index);

            last_registry_check.set(Some(now_unix()));
            app.set_registry_checked_at(ss(relative_checked_at(0)));

            if diff.update_count == 0 && diff.new_count == 0 {
                app.set_registry_status(4);
            } else {
                app.set_registry_summary(ss(registry_summary(diff.update_count, diff.new_count)));
                app.set_registry_status(5);
            }
        }
    }
}

/// The `registry-summary` text for `registry-status == 5` — the fixed
/// template `"N update, M new"`, omitting whichever half is zero. `"update"`
/// deliberately never pluralizes: the template is literal — `"N update"` for
/// any N, and `"N new"` — with no plural form, rather than guessing one.
fn registry_summary(update_count: usize, new_count: usize) -> String {
    let mut parts = Vec::new();
    if update_count > 0 {
        parts.push(format!("{update_count} update"));
    }
    if new_count > 0 {
        parts.push(format!("{new_count} new"));
    }
    parts.join(", ")
}

/// `registry-checked-at`'s relative-time text ("just now" / "2m ago" / …),
/// bucketed from `elapsed_secs` since the last successful check. Slint
/// prepends "· checked " itself (see the property's own doc comment in
/// `ui/app.slint`) — this only ever returns the bare relative phrase.
fn relative_checked_at(elapsed_secs: u64) -> String {
    if elapsed_secs < 60 {
        "just now".to_string()
    } else if elapsed_secs < 3600 {
        format!("{}m ago", elapsed_secs / 60)
    } else if elapsed_secs < 86400 {
        format!("{}h ago", elapsed_secs / 3600)
    } else {
        format!("{}d ago", elapsed_secs / 86400)
    }
}

/// Find and update one `registry-new` row's `status`/`error` by id — used to
/// move a row through available (0) → installing (1) → failed (2), or back
/// to available on a user Cancel. A no-op if `id` isn't (or is no longer) in
/// the list, e.g. a stale message landing after the row was already removed.
fn set_registry_row_status(model: &RegistryRows, id: &str, status: i32, error: &str) {
    for i in 0..model.row_count() {
        let Some(mut row) = model.row_data(i) else {
            continue;
        };
        if row.id == id {
            row.status = status;
            row.error = ss(error);
            model.set_row_data(i, row);
            return;
        }
    }
}

/// Drop one `registry-new` row by id — called once an Install actually lands
/// (the plugin is no longer "available", it's installed).
fn remove_registry_new_row(model: &RegistryRows, id: &str) {
    for i in 0..model.row_count() {
        let Some(row) = model.row_data(i) else {
            continue;
        };
        if row.id == id {
            model.remove(i);
            return;
        }
    }
}

/// Find and update one installed plugin's `update-status`/`update-error` by
/// id — mirrors [`set_registry_row_status`], but looks the row up by index
/// into `plugins` (`plugin_model`'s rows are always the same length/order as
/// `plugins`, see [`refresh_plugins_model`]) rather than by scanning
/// `PluginRow.id`, since that index is already the cheap, obvious lookup
/// every other per-plugin mutation in this file uses.
fn set_plugin_update_status(
    plugin_model: &PluginRows,
    plugins: &Plugins,
    id: &str,
    status: i32,
    error: &str,
) {
    let Some(i) = plugins.borrow().iter().position(|m| m.id == id) else {
        return;
    };
    let Some(mut row) = plugin_model.row_data(i) else {
        return;
    };
    row.update_status = status;
    row.update_error = ss(error);
    plugin_model.set_row_data(i, row);
}

/// Which UI action produced an [`InstallOutcome`] — carried alongside it
/// (rather than splitting into two channels) so Install and Update share one
/// background fetch+verify function ([`fetch_and_verify_manifest`]) and one
/// drain loop; only [`handle_install_outcome`] branches on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingKind {
    Install,
    Update,
}

/// The result of fetching + sha256-verifying one registry manifest
/// ([`fetch_and_verify_manifest`]), crossing from the background thread to
/// the UI thread. `Failed` covers every step before a verified manifest
/// exists — URL resolution, the network fetch, a sha256 mismatch, or a
/// verified-but-unparseable manifest (`registry::verify_and_prepare`'s own
/// contract: hash-check first, parse second) — nothing is ever written to
/// disk in that case. `manifest` is boxed: `PluginManifest` is large enough
/// that an inlined `Ready` variant would otherwise force the same stack/heap
/// footprint onto every `Failed` value too.
enum InstallOutcome {
    Failed(String),
    Ready {
        raw_bytes: Vec<u8>,
        manifest: Box<PluginManifest>,
        sha_hex: String,
    },
}

/// The network+verification half of install/update — resolve the entry's
/// manifest URL against `base_url`, fetch its raw bytes (via
/// [`registry::fetch_bytes`], never `fetch_text` — sha256 must be computed
/// over the exact transport bytes, and `fetch_text`'s `into_string` would
/// UTF-8-decode them first), then sha256-verify them against `entry.sha256`
/// before ever parsing (see `registry::verify_and_prepare`'s own contract),
/// and finally check the parsed manifest's own `id` against `entry.id` (see
/// [`verify_manifest_id_matches_entry`]) before ever calling this a `Ready`
/// result — a mismatch here means either a honest-but-buggy or an outright
/// dishonest registry (an entry that downloads a manifest declaring a
/// *different* id than the one it was listed under), and must never reach
/// the trust dialog or a disk write under either id. Runs entirely on a
/// background thread (see `on_install_plugin`/`on_update_plugin`); its
/// result crosses back to the UI thread for the trust dialog and the actual
/// write, neither of which may happen off it.
fn fetch_and_verify_manifest(base_url: &str, entry: &RegistryEntry) -> InstallOutcome {
    let manifest_url = match registry::resolve_manifest_url(base_url, &entry.manifest) {
        Ok(u) => u,
        Err(e) => return InstallOutcome::Failed(e),
    };
    let raw_bytes = match registry::fetch_bytes(&manifest_url) {
        Ok(b) => b,
        Err(e) => return InstallOutcome::Failed(e),
    };
    match registry::verify_and_prepare(&raw_bytes, &entry.sha256) {
        Ok((manifest, sha_hex)) => match verify_manifest_id_matches_entry(&manifest, entry) {
            Ok(()) => InstallOutcome::Ready {
                raw_bytes,
                manifest: Box::new(manifest),
                sha_hex,
            },
            Err(e) => InstallOutcome::Failed(e),
        },
        Err(e) => InstallOutcome::Failed(e),
    }
}

/// Defense-in-depth against a honest-but-buggy or outright dishonest
/// registry: check that a freshly-downloaded manifest's own declared `id`
/// matches the registry entry it was installed/updated *from* (`entry.id`,
/// the id the user actually clicked Install/Update on). Without this check,
/// clicking Install on an entry listed as `"gemini"` whose manifest actually
/// declares `id = "claude"` would write `claude.toml` (every write path
/// keys off the *parsed* manifest's own id, not the entry's) while the
/// `"gemini"` row silently vanishes off `registry-new` as if it had been
/// installed; an Update would overwrite `gemini.toml` with content
/// declaring `id = "claude"` — a duplicate id the moment `manifest::load_dir`
/// next scans the plugins directory. Enforcing this here (before the trust
/// dialog or any write, from within [`fetch_and_verify_manifest`]) means an
/// install always ends up writing under `entry.id` (guaranteed `==
/// manifest.id` past this check) and an update always keeps overwriting the
/// id the user actually clicked.
fn verify_manifest_id_matches_entry(
    manifest: &PluginManifest,
    entry: &RegistryEntry,
) -> Result<(), String> {
    if manifest.id != entry.id {
        return Err(format!(
            "manifest id mismatch: registry lists \"{}\" but the downloaded manifest declares \"{}\"",
            entry.id, manifest.id
        ));
    }
    Ok(())
}

/// Write a freshly-verified registry manifest for a *new* install:
/// `<dir>/<id>.toml`, refusing to clobber an existing file (`create_new`) —
/// the same write shape as `add-plugin`'s own, including the canonical-
/// containment check via [`plugin_manifest_target`]. `id` is the *parsed*
/// manifest's own id — [`verify_manifest_id_matches_entry`] guarantees this
/// is always the same string as the registry entry's own `id` (the one the
/// user actually clicked Install on) by the time this is called, so an
/// install always ends up writing under the id shown in the UI — this is
/// what ends up on disk and is what every later reload/diff addresses the
/// plugin by.
fn install_write(dir: &std::path::Path, id: &str, raw_bytes: &[u8]) -> Result<(), String> {
    let target = plugin_manifest_target(dir, id)
        .ok_or_else(|| format!("plugin id \"{id}\" is not a valid filename"))?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
        .and_then(|mut f| std::io::Write::write_all(&mut f, raw_bytes))
        .map_err(|e| e.to_string())
}

/// Overwrite an already-installed plugin's manifest with a freshly-verified
/// update. `id` is the *installed* plugin's own id (the one the Update click
/// carried, looked up via [`find_plugin_manifest_path`]) rather than the
/// freshly-downloaded manifest's own id — belt-and-braces alongside
/// [`verify_manifest_id_matches_entry`] (which already guarantees the two
/// agree by the time this is called): this function still never trusts the
/// downloaded manifest's id to name the file it's replacing, so a future
/// regression that weakens that guarantee can't silently overwrite the
/// wrong file. Writes to a sibling temp file first (an extension other than
/// `.toml`, so `manifest::load_dir`'s glob can never pick up a half-written
/// file) then atomically renames it over the target — never a direct
/// in-place write, which a reload racing this write could observe
/// half-written.
fn update_write(dir: &std::path::Path, id: &str, raw_bytes: &[u8]) -> Result<(), String> {
    let target = find_plugin_manifest_path(dir, id)
        .ok_or_else(|| format!("no installed manifest file found for id \"{id}\""))?;
    let mut tmp_name = target.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(format!(".tmp{}", std::process::id()));
    let tmp = target.with_file_name(tmp_name);
    // `create_new`, like `install_write` — never `create().truncate()`. The
    // temp path is predictable, and anything running as this user can leave a
    // symlink sitting on it; `create().truncate()` follows that link and
    // overwrites whatever is on the other end, outside this directory
    // entirely. Whatever is already at the path goes first (removing a
    // symlink removes the link, not its target), and then the create must be
    // the one that makes the file.
    let _ = std::fs::remove_file(&tmp);
    let result = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .and_then(|mut f| std::io::Write::write_all(&mut f, raw_bytes))
        .and_then(|_| std::fs::rename(&tmp, &target));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp); // best-effort cleanup of a half-written temp file
    }
    result.map_err(|e| e.to_string())
}

/// Apply one install/update's fetch+verify result: run the trust dialog when
/// `analyze_trust` requires it, write the verified bytes to disk, record
/// provenance in the lockfile, and (for an install) drop the plugin off
/// `registry-new`. Returns `true` iff a manifest was actually written —
/// the caller (the install/update drain loop in `main`'s fast timer) uses
/// that to decide whether to `reload_and_fetch` and refresh the provider
/// list/tray, mirroring how a landed plugin fetch drives the same refresh.
/// `false` for every failure and for a user Cancel — nothing was written
/// either way.
fn handle_install_outcome(
    kind: PendingKind,
    entry: RegistryEntry,
    outcome: InstallOutcome,
    plugins: &Plugins,
    plugin_model: &PluginRows,
    registry_model: &RegistryRows,
) -> bool {
    let (raw_bytes, manifest, sha_hex) = match outcome {
        InstallOutcome::Failed(err) => {
            diag::line(format!("{kind:?} \"{}\": {err}", entry.id));
            match kind {
                PendingKind::Install => set_registry_row_status(registry_model, &entry.id, 2, &err),
                PendingKind::Update => {
                    set_plugin_update_status(plugin_model, plugins, &entry.id, 2, &err)
                }
            }
            return false;
        }
        InstallOutcome::Ready {
            raw_bytes,
            manifest,
            sha_hex,
        } => (raw_bytes, manifest, sha_hex),
    };

    let allowed_hosts = all_allowed_hosts(&manifest);
    let disclosure = registry::analyze_trust(&manifest, registry::TRUSTED_HOSTS);
    let approved = !disclosure.requires_approval
        || show_trust_dialog(&manifest.id, &disclosure, &allowed_hosts);
    if !approved {
        match kind {
            PendingKind::Install => set_registry_row_status(registry_model, &entry.id, 0, ""),
            PendingKind::Update => {
                set_plugin_update_status(plugin_model, plugins, &entry.id, 0, "")
            }
        }
        return false;
    }

    let dir = seed::plugins_dir();
    let (write_result, lock_id): (Result<(), String>, &str) = match kind {
        PendingKind::Install => (
            install_write(&dir, &manifest.id, &raw_bytes),
            manifest.id.as_str(),
        ),
        PendingKind::Update => (update_write(&dir, &entry.id, &raw_bytes), entry.id.as_str()),
    };
    if let Err(e) = write_result {
        diag::line(format!(
            "{kind:?} \"{}\": could not write manifest: {e}",
            entry.id
        ));
        match kind {
            PendingKind::Install => set_registry_row_status(registry_model, &entry.id, 2, &e),
            PendingKind::Update => {
                set_plugin_update_status(plugin_model, plugins, &entry.id, 2, &e)
            }
        }
        return false;
    }

    let lock_path = registry::lockfile_path();
    let mut lock = registry::load_lockfile(&lock_path);
    lock.set(
        lock_id,
        registry::RegistryLockEntry {
            origin_registry_url: DEFAULT_REGISTRY_URL.to_string(),
            origin_version: entry.version.clone(),
            origin_sha256: sha_hex,
            installed_at: now_unix(),
        },
    );
    if let Err(e) = registry::save_lockfile(&lock_path, &lock) {
        diag::line(format!(
            "could not save registry lockfile {}: {e}",
            lock_path.display()
        ));
    }

    if kind == PendingKind::Install {
        remove_registry_new_row(registry_model, &entry.id);
    }
    true
}

/// Every `allowed_hosts` entry declared by any of `m`'s surfaces, in
/// first-seen order, case-insensitively de-duplicated — mirrors
/// `registry::analyze_trust`'s own `dest_hosts` de-dup idiom, over the
/// manifest's declared guard-rail rather than its actual request URLs, for
/// the trust dialog's "Allowed hosts" line.
fn all_allowed_hosts(m: &PluginManifest) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for s in &m.surface {
        for h in &s.allowed_hosts {
            if !hosts
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(h))
            {
                hosts.push(h.clone());
            }
        }
    }
    hosts
}

/// A `[[surface.auth]].type` value in its manifest-schema kebab-case
/// spelling — mirrors [`engine_label`] for the other half of the trust
/// dialog's disclosure text.
fn auth_type_label(kind: manifest::AuthType) -> &'static str {
    match kind {
        manifest::AuthType::CredentialsFile => "credentials-file",
        manifest::AuthType::Keychain => "keychain",
        manifest::AuthType::Env => "env",
        manifest::AuthType::ElectronSafeStorage => "electron-safe-storage",
        manifest::AuthType::WinCredential => "win-credential",
        manifest::AuthType::CredentialsMap => "credentials-map",
        manifest::AuthType::RejectWhen => "reject-when",
        manifest::AuthType::OauthRefresh => "oauth-refresh",
    }
}

/// The trust-dialog copy for a manifest whose `analyze_trust` disclosure
/// requires approval: a short first-pass warning and a fuller second-pass
/// breakdown (id, engine, the ordered auth chain, every destination host
/// with untrusted ones flagged, the manifest's own declared `allowed_hosts`,
/// and the fixed `redirects(0)` guarantee — see `registry::fetch_bytes`'s own
/// docs (the function this trust dialog gates a manifest download through)
/// for why that's always zero). Pure, so the wording is testable
/// without any dialog on screen at all — see [`show_trust_dialog`].
/// `["a", "b", "c"]` as `"a, b and c"` — a list a person reads, not one a
/// program prints.
fn join_with_and(parts: &[String]) -> String {
    match parts {
        [] => String::new(),
        [only] => only.clone(),
        [rest @ .., last] => format!("{}, and {last}", rest.join(", ")),
    }
}

fn build_trust_message(
    id: &str,
    disclosure: &TrustDisclosure,
    allowed_hosts: &[String],
) -> (String, String) {
    let auth_chain = disclosure
        .auth_types
        .iter()
        .map(|t| auth_type_label(*t))
        .collect::<Vec<_>>()
        .join(" → ");
    let engine = engine_label(disclosure.engine);

    // The first pass is a screen somebody can approve from without opening
    // the second, so it names *every* thing this manifest does that is worth
    // stopping for — strongest first, because a command that runs is worse
    // news than a file that is read.
    let mut does: Vec<String> = Vec::new();
    if let Some(cmd) = &disclosure.ping {
        does.push(format!(
            "runs a command after a quota window resets ({cmd})"
        ));
    }
    if !disclosure.local_files.is_empty() {
        does.push(format!(
            "reads local files ({})",
            disclosure.local_files.join(", ")
        ));
    }
    if !disclosure.auth_types.is_empty() {
        does.push(format!("reads a stored credential ({auth_chain})"));
    }
    if !disclosure.untrusted_hosts.is_empty() {
        does.push(format!(
            "sends to {}",
            disclosure.untrusted_hosts.join(", ")
        ));
    }
    if does.is_empty() {
        does.push(format!("runs on the {engine} engine"));
    }
    let short = format!(
        "\"{id}\" {}. Review before installing.",
        join_with_and(&does)
    );

    let dest_hosts = if disclosure.dest_hosts.is_empty() {
        "(none declared)".to_string()
    } else {
        disclosure
            .dest_hosts
            .iter()
            .map(|h| {
                if disclosure
                    .untrusted_hosts
                    .iter()
                    .any(|u| u.eq_ignore_ascii_case(h))
                {
                    format!("{h} (untrusted)")
                } else {
                    h.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let allowed = if allowed_hosts.is_empty() {
        "(none declared)".to_string()
    } else {
        allowed_hosts.join(", ")
    };

    let local_files = if disclosure.local_files.is_empty() {
        "(none)".to_string()
    } else {
        disclosure.local_files.join(", ")
    };
    let runs = disclosure
        .ping
        .clone()
        .unwrap_or_else(|| "(nothing)".to_string());

    let detailed = format!(
        "Plugin id: {id}\nEngine: {engine}\nAuth chain: {auth_chain}\nDestination hosts: {dest_hosts}\n\
         Allowed hosts: {allowed}\nReads local files: {local_files}\nRuns after a reset: {runs}\n\
         Redirects: 0 (blocked)"
    );

    (short, detailed)
}

/// Native trust confirmation before writing a registry-sourced manifest to
/// disk — only shown when [`TrustDisclosure::requires_approval`] is true.
///
/// macOS runs it in two passes: [`build_trust_message`]'s short warning with
/// Cancel / Show Details / Install Anyway (default Cancel), and, if details
/// were asked for, the full breakdown with Cancel / Install Anyway. Windows
/// runs one pass carrying the full breakdown — see the arm itself for why.
///
/// Fails closed like `confirm_remove_plugin` on either: a dialog that could
/// not be shown, or one that was closed, is "not approved", never
/// "approved".
fn show_trust_dialog(id: &str, disclosure: &TrustDisclosure, allowed_hosts: &[String]) -> bool {
    let (short, detailed) = build_trust_message(id, disclosure, allowed_hosts);
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            r#"display dialog "{}" buttons {{"Cancel","Show Details","Install Anyway"}} default button "Cancel" cancel button "Cancel" with icon caution"#,
            applescript_escape(&short)
        );
        match run_osascript_dialog(&script).as_deref() {
            Some("Install Anyway") => true,
            Some("Show Details") => {
                let script2 = format!(
                    r#"display dialog "{}" buttons {{"Cancel","Install Anyway"}} default button "Cancel" cancel button "Cancel" with icon caution"#,
                    applescript_escape(&detailed)
                );
                run_osascript_dialog(&script2).as_deref() == Some("Install Anyway")
            }
            _ => false, // Cancel, closed, or osascript missing/failed
        }
    }
    #[cfg(target_os = "windows")]
    {
        // One pass, carrying the full breakdown. A message box's buttons are
        // the ones Windows supplies, so "Show Details" cannot be one of them
        // — and it does not need to be: that button exists only so the whole
        // disclosure isn't dumped on someone who never asked for it, and a
        // message box holds it comfortably. Showing `detailed` rather than
        // `short` is the safer direction to err in for a dialog whose whole
        // job is to state what is about to be trusted.
        let _ = &short;
        use windows::Win32::UI::WindowsAndMessaging::{
            IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_YESNO,
        };
        windows_message_box(
            "Install plugin?",
            &detailed,
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2,
        ) == Some(IDYES)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = (short, detailed);
        false
    }
}

/// Run one native `display dialog` and return the clicked button's text
/// (`None` on Cancel, a closed window, or osascript itself failing to
/// launch) — the multi-button generalization of `confirm_remove_plugin`'s
/// single-expected-button check.
#[cfg(target_os = "macos")]
fn run_osascript_dialog(script: &str) -> Option<String> {
    let out = std::process::Command::new("osascript")
        .arg("-e")
        .arg(script)
        .output()
        .ok()?;
    if !out.status.success() {
        return None; // Cancel/window closed surfaces as a non-zero exit
    }
    parse_button_returned(&String::from_utf8_lossy(&out.stdout))
}

/// Pure parse of `display dialog`'s stdout, generalizing [`confirm_parse`]
/// beyond a single expected button: returns whatever text followed `"button
/// returned:"`, up to the next comma (the AppleEvent record may carry other
/// fields — see `confirm_parse`'s own doc comment on the same shape).
#[cfg(any(target_os = "macos", test))]
fn parse_button_returned(stdout: &str) -> Option<String> {
    let marker = "button returned:";
    let start = stdout.find(marker)? + marker.len();
    let rest = &stdout[start..];
    let end = rest.find(',').unwrap_or(rest.len());
    let text = rest[..end].trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

#[cfg(test)]
mod dock_panel_tests {
    use std::time::{Duration, Instant};

    use super::{
        activation_owned_by_tray, panel_target_visibility as target, popover_moves as moves, Shown,
        TRAY_CLICK_OWNS_ACTIVATION,
    };

    // Nothing happened this tick: whatever is on screen stays.
    #[test]
    fn idle_ticks_change_nothing() {
        assert!(target(false, 0, true));
        assert!(!target(false, 0, false));
    }

    // App already frontmost, so a Dock click is the only thing that click can
    // mean: toggle, exactly like the tray item does.
    #[test]
    fn click_on_frontmost_app_toggles() {
        assert!(!target(false, 1, true), "visible + click -> dismissed");
        assert!(target(false, 1, false), "hidden + click -> restored");
    }

    // Cmd-Tab sends no reopen event at all; without this the app comes forward
    // with nothing on screen and no way back.
    #[test]
    fn activation_alone_restores_a_hidden_panel() {
        assert!(target(true, 0, false));
        assert!(target(true, 0, true), "already visible -> left alone");
    }

    // Clicking a background app's Dock icon means "show me", never "dismiss".
    #[test]
    fn activating_click_never_dismisses() {
        assert!(target(true, 1, true), "visible -> stays up, just raised");
        assert!(target(true, 1, false), "hidden -> restored");
    }

    // Clicks can batch inside one poll interval. The activating click is
    // consumed; the rest toggle, so the count's parity decides.
    #[test]
    fn batched_clicks_resolve_by_parity() {
        assert!(!target(true, 2, true), "raise, then dismiss");
        assert!(!target(true, 2, false), "restore, then dismiss");
        assert!(target(true, 3, false), "restore, dismiss, restore");
        assert!(target(false, 2, true), "two toggles cancel out");
        assert!(!target(false, 3, true), "odd count still toggles");
    }

    // Both icons on screen at once: clicking the status item also activates
    // the app, and the dock-mode restore watches exactly that edge. Without
    // this, one click would be counted twice and the panel would toggle
    // straight back — which is why the two used to be mutually exclusive.
    #[test]
    fn a_status_item_click_owns_the_activation_it_causes() {
        let click = Instant::now();
        assert!(activation_owned_by_tray(Some(click), click));
        assert!(activation_owned_by_tray(
            Some(click),
            click + TRAY_CLICK_OWNS_ACTIVATION - Duration::from_millis(1)
        ));
        assert!(
            !activation_owned_by_tray(Some(click), click + TRAY_CLICK_OWNS_ACTIVATION),
            "a Dock click a moment later is still a Dock click"
        );
        assert!(
            !activation_owned_by_tray(None, click),
            "no click, nothing to own it"
        );
    }

    // The flyout hangs off the status item, so every show places it. Nothing
    // about it is the user's to arrange, and a stale position would leave it
    // pointing at an icon it is no longer under.
    #[test]
    fn a_flyout_is_placed_every_time_it_is_shown() {
        for shown in [Shown::ByTrayClick, Shown::ByAnythingElse] {
            assert!(moves(false, false, shown), "first show");
            assert!(moves(false, true, shown), "and every one after it");
        }
    }

    // In dock mode the window is the user's to put somewhere, so it is placed
    // once — a window that has never been placed has no position worth
    // keeping — and left alone from then on.
    #[test]
    fn a_dock_window_is_placed_once_and_then_left_where_it_was_put() {
        assert!(
            moves(true, false, Shown::ByAnythingElse),
            "it has to start somewhere"
        );
        assert!(
            !moves(true, true, Shown::ByAnythingElse),
            "a Dock reopen restores the panel, it does not rearrange it"
        );
    }

    // The exception, and the reason this decision exists: clicking the status
    // item points at a spot on screen. Dock mode does not make that click mean
    // anything else, so the panel goes under the icon that was clicked even
    // though the same window can be dragged anywhere the rest of the time.
    #[test]
    fn a_tray_click_moves_the_panel_under_its_icon_even_in_dock_mode() {
        assert!(moves(true, true, Shown::ByTrayClick));
    }

    #[test]
    fn a_click_that_closed_the_panel_does_not_also_reopen_it() {
        use super::{tray_click_dismissed_panel as dismissed, TRAY_CLICK_DISMISS_WINDOW};
        let hidden = Instant::now();
        assert!(
            dismissed(Some(hidden), hidden + Duration::from_millis(10)),
            "the click arrives just after the hide it caused"
        );
        assert!(
            !dismissed(Some(hidden), hidden + TRAY_CLICK_DISMISS_WINDOW),
            "long enough later and it is a fresh request to open"
        );
        assert!(
            !dismissed(None, hidden),
            "a panel that was never hidden by focus loss cannot have been dismissed"
        );
    }

    #[test]
    fn only_the_platform_that_needs_the_suppression_applies_it() {
        use super::TRAY_CLICK_CAN_ARRIVE_AFTER_ITS_OWN_DISMISSAL as APPLIES;
        // The mark is armed by *any* focus loss — another app taking focus,
        // the desktop, the one at launch — so wherever this is on, a click
        // that follows an unrelated dismissal inside the window is swallowed.
        // That price is worth paying only where the click really can arrive
        // after the hide it caused, which is Windows.
        assert_eq!(APPLIES, cfg!(target_os = "windows"));
    }
}

#[cfg(test)]
mod popover_placement_tests {
    use super::{popover_origin, POPOVER_GAP, POPOVER_MARGIN};

    // A 2560×1440 screen at the origin, the machine this was first found on.
    const SCREEN: (f64, f64, f64, f64) = (0.0, 0.0, 2560.0, 1440.0);
    // The card as it is actually sized (see `AppWindow`'s own width).
    const CARD: (f64, f64) = (420.0, 339.0);

    #[test]
    fn a_card_with_nothing_to_hang_off_still_lands_on_the_screen() {
        // Dock mode's first placement and the snapshot path pass no anchor.
        // The offsets used there are an opening position, not a fit: on a
        // display smaller than the card they used to start it off the edge.
        let small = (0.0, 0.0, 320.0, 240.0);
        let (x, y) = popover_origin(None, CARD, small, 1.0);
        assert!(x >= POPOVER_MARGIN, "starts inside the left edge");
        assert!(y >= POPOVER_MARGIN, "and inside the top");
        // Wider than the screen: pinned to the margin rather than panicking on
        // an inverted clamp range.
        assert_eq!(x, POPOVER_MARGIN);
        // Roomy screen: the opening offsets are used as they were.
        let (x, y) = popover_origin(None, CARD, SCREEN, 1.0);
        assert_eq!((x, y), (240.0, 48.0));
    }

    #[test]
    fn a_menu_bar_item_at_the_top_still_hangs_its_card_underneath() {
        // macOS's arrangement, which must not change: the item is at the top
        // of the screen and there is room below it for the whole card.
        let item = (1200.0, 0.0, 24.0, 24.0);
        let (x, y) = popover_origin(Some(item), CARD, SCREEN, 1.0);
        assert_eq!(y, 24.0 + POPOVER_GAP);
        assert_eq!(x, 1200.0 + 12.0 - 210.0, "centred on the item");
    }

    #[test]
    fn a_taskbar_item_at_the_bottom_puts_the_card_above_it() {
        // The Windows default, and the placement that used to run off the
        // screen: a 339px card at y=1261 on a 1440px screen showed only its
        // first row.
        let item = (2260.0, 1215.0, 40.0, 40.0);
        let (_, y) = popover_origin(Some(item), CARD, SCREEN, 1.0);
        assert_eq!(y, 1215.0 - 339.0 - POPOVER_GAP);
        assert!(
            y + 339.0 <= 1215.0,
            "the card clears the taskbar it hangs off"
        );
        assert!(y >= 0.0, "and stays on the screen");
    }

    #[test]
    fn an_item_near_a_screen_edge_pulls_the_card_back_inside() {
        // The notification area sits at the right-hand end of the taskbar, so
        // a card centred on it would hang off the right edge by ~200px.
        let item = (2540.0, 1400.0, 20.0, 20.0);
        let (x, _) = popover_origin(Some(item), CARD, SCREEN, 1.0);
        assert_eq!(x, 2560.0 - 420.0 - POPOVER_MARGIN);
    }

    #[test]
    fn a_second_monitor_is_measured_from_its_own_origin_not_the_desktops() {
        // A screen to the left of the primary one: negative coordinates, where
        // clamping against a 0-based origin would shove the card onto the
        // wrong display.
        let screen = (-1920.0, 0.0, 1920.0, 1080.0);
        let item = (-40.0, 1040.0, 40.0, 40.0);
        let (x, y) = popover_origin(Some(item), CARD, screen, 1.0);
        assert_eq!(y, 1040.0 - 339.0 - POPOVER_GAP);
        assert_eq!(x, -1920.0 + 1920.0 - 420.0 - POPOVER_MARGIN);
        assert!(x >= -1920.0, "still on the monitor the item is on");
    }

    #[test]
    fn a_card_taller_than_the_screen_sits_at_the_top_rather_than_off_either_end() {
        // Neither side fits. The list scrolls; the card must still be on
        // screen for that to be reachable at all.
        let screen = (0.0, 0.0, 1024.0, 300.0);
        let item = (900.0, 260.0, 24.0, 24.0);
        let (_, y) = popover_origin(Some(item), CARD, screen, 1.0);
        assert_eq!(y, POPOVER_MARGIN);
    }

    #[test]
    fn a_card_wider_than_the_screen_is_placed_rather_than_panicking() {
        // `clamp` with an inverted range panics; the upper bound is held at or
        // above the lower one so this can only ever be a placement.
        let screen = (0.0, 0.0, 320.0, 1440.0);
        let item = (300.0, 1400.0, 20.0, 20.0);
        let (x, _) = popover_origin(Some(item), CARD, screen, 1.0);
        assert_eq!(x, POPOVER_MARGIN);
    }

    #[test]
    fn scaling_scales_the_gap_and_the_margin_with_everything_else() {
        let screen = (0.0, 0.0, 2560.0, 1440.0);
        let item = (1200.0, 0.0, 48.0, 48.0);
        let (_, y) = popover_origin(Some(item), CARD, screen, 2.0);
        assert_eq!(y, 48.0 + POPOVER_GAP * 2.0);
    }

    #[test]
    fn with_no_item_to_hang_off_the_card_lands_inside_the_screen_it_was_given() {
        let screen = (-1920.0, 0.0, 1920.0, 1080.0);
        let (x, y) = popover_origin(None, CARD, screen, 1.0);
        assert_eq!((x, y), (-1920.0 + 240.0, 48.0));
    }
}

#[cfg(test)]
mod title_tests {
    use super::*;
    use tickover::model::Role;

    const NOW: u64 = 1_800_000_000;

    /// Test-only uniform-gate resolver: every non-opt-in surface always, every
    /// opt-in one iff `opt_in_enabled`. Production's [`active_surface_ids`]
    /// reads each opt-in surface's state independently from `config`; this
    /// pins them all to one bool so the `readings_with`/`active_surface_ids`
    /// tests stay pure (no on-disk config).
    fn active_surface_ids_with(m: &PluginManifest, opt_in_enabled: bool) -> Vec<String> {
        m.surface
            .iter()
            .filter(|s| !s.opt_in || opt_in_enabled)
            .map(|s| s.id.clone())
            .collect()
    }

    fn win(label: &str, role: Role, used: f64, in_secs: u64, minutes: u64) -> Window {
        Window {
            // The key an engine would have built from `two_window_manifest`,
            // which is the manifest these fixtures stand in for: it declares no
            // window ids, so each entry falls back to its position. Left empty,
            // these rows would carry no identity and the reconciler could not
            // tell one from another — which is the thing under test elsewhere.
            key: match label {
                "5H" => "w0:".to_string(),
                "WK" => "w1:".to_string(),
                other => format!("{other}:"),
            },
            label: label.into(),
            role,
            used_percent: Some(used),
            resets_at: Some(NOW + in_secs),
            period_minutes: Some(minutes),
        }
    }

    fn empty_window(label: &str, role: Role) -> Window {
        Window {
            key: String::new(),
            label: label.into(),
            role,
            used_percent: None,
            resets_at: None,
            period_minutes: None,
        }
    }

    /// The Primary window's reset time, which is what the auto-ping selects a
    /// window by. A test-local helper now that `primary_window_of` hands back
    /// the whole window (the ping also needs its `used_percent`, and a window
    /// reported *without* a reset is a state it must still see).
    fn primary_reset(readings: &[ProviderReading], id: &str) -> Option<u64> {
        primary_window_of(readings, id)?.resets_at
    }

    #[test]
    fn window_title_names_the_length_and_falls_back_to_the_manifest_chip() {
        let titled = |minutes: Option<u64>| {
            window_title(&Window {
                key: String::new(),
                label: "WK".into(),
                role: Role::Secondary,
                used_percent: Some(1.0),
                resets_at: None,
                period_minutes: minutes,
            })
        };
        assert_eq!(titled(Some(10_080)), "Weekly limit");
        assert_eq!(titled(Some(1_440)), "Daily limit");
        assert_eq!(titled(Some(300)), "5-hour limit");
        assert_eq!(titled(Some(60)), "1-hour limit");
        assert_eq!(titled(Some(30)), "30-minute limit");
        // Lengths with no natural phrase, and windows that declare none at
        // all, keep the label the manifest chose.
        assert_eq!(
            titled(Some(90)),
            "WK limit",
            "an hour and a half has no name"
        );
        assert_eq!(titled(None), "WK limit");
        assert_eq!(
            titled(Some(0)),
            "WK limit",
            "a zero-length window names nothing"
        );
    }

    /// Direct `ProviderReading` fixture, mirroring what a log-file-engine
    /// plugin (Codex) produces — see `plugin::engine_logfile`'s own tests for
    /// the classification that gets it there. `bare_when_sole: true` here
    /// mirrors what `readings()` (below) sets for the lowest-`order` plugin.
    fn codex_reading(windows: Vec<Window>) -> ProviderReading {
        ProviderReading {
            id: "codex".into(),
            name: "Codex".into(),
            short: "Cx".into(),
            tag: None,
            account: None,
            windows,
            balances: Vec::new(),
            error: None,
            quota_status: None,
            in_menu_bar: true,
            bare_when_sole: true,
        }
    }

    /// Direct `ProviderReading` fixture for one Claude surface — mirrors what
    /// `engine_http` produces (`bare_when_sole` always false).
    fn claude_reading(
        id: &str,
        in_menu_bar: bool,
        windows: Vec<Window>,
        error: Option<&str>,
    ) -> ProviderReading {
        ProviderReading {
            id: id.into(),
            name: "Claude".into(),
            short: "Cl".into(),
            tag: None,
            account: None,
            windows,
            balances: Vec::new(),
            error: error.map(str::to_string),
            quota_status: None,
            in_menu_bar,
            bare_when_sole: false,
        }
    }

    // ── credentials_just_lost ────────────────────────────────────────────

    #[test]
    fn a_surface_switched_off_leaves_nothing_behind_to_be_announced_later() {
        // The scenario this test pins: turn off an opt-in surface
        // while it is healthy, sign out of that tool, turn the surface back on.
        // With its reading still cached, the next fetch compares a healthy
        // reading against an empty chain and announces a row as having
        // disappeared — a row that left the panel when the toggle did, and was
        // not on screen "a moment ago" at all.
        //
        // Disabling a whole *plugin* already drops its readings
        // (`on_plugin_enabled_changed`); a surface is the same fact one level
        // down, so it drops its own.
        let cache: PluginCache = Rc::new(RefCell::new(HashMap::new()));
        cache.borrow_mut().insert(
            "claude".to_string(),
            vec![
                claude_reading("claude-cli", true, codex_windows(), None),
                claude_reading("claude-desktop", false, codex_windows(), None),
                // A log-file engine's sub-account row, filed under the surface
                // it came from — `surface_id_active` treats it as part of that
                // surface, so forgetting the surface has to forget this too.
                claude_reading("claude-desktop#work", false, codex_windows(), None),
            ],
        );

        drop_surface_reading(&cache, "claude", "desktop");

        let left: Vec<String> = cache.borrow()["claude"]
            .iter()
            .map(|r| r.id.clone())
            .collect();
        assert_eq!(
            left,
            vec!["claude-cli".to_string()],
            "only the other surface survives"
        );

        // The lone synthesized surface is filed under the bare plugin id, and
        // the same call has to find it there.
        cache.borrow_mut().insert(
            "grok".to_string(),
            vec![claude_reading("grok", true, codex_windows(), None)],
        );
        drop_surface_reading(&cache, "grok", "default");
        assert!(
            cache.borrow()["grok"].is_empty(),
            "a default surface is the plugin id itself"
        );
    }

    #[test]
    fn a_row_that_disappears_says_so_once_and_only_if_it_was_on_screen() {
        let with_token = |id: &str| claude_reading(id, true, codex_windows(), None);
        let empty = |id: &str| claude_reading(id, true, Vec::new(), Some(auth::NO_CREDENTIALS));
        let names = |v: Vec<&ProviderReading>| -> Vec<String> {
            v.into_iter().map(|r| r.id.clone()).collect()
        };

        // The case this exists for: drawn a moment ago, hidden now.
        assert_eq!(
            names(credentials_just_lost(
                &[with_token("claude-cli")],
                &[empty("claude-cli")]
            )),
            vec!["claude-cli".to_string()]
        );

        // A provider nobody ever signed into. Five manifests ship and most
        // machines have one or two of the tools; this is why installing the
        // app does not write four lines about the others.
        assert!(credentials_just_lost(&[], &[empty("grok")]).is_empty());

        // The poll after the transition. Without this the same sentence lands
        // every refresh_secs, forever, and the log stops being readable.
        assert!(credentials_just_lost(&[empty("grok")], &[empty("grok")]).is_empty());

        // Some other failure is already on the row, where the user can see it.
        // Only the vanishing state is unexplained, so only it speaks here.
        let http_500 = |id: &str| claude_reading(id, true, Vec::new(), Some("HTTP 500"));
        assert!(
            credentials_just_lost(&[with_token("claude-cli")], &[http_500("claude-cli")])
                .is_empty()
        );

        // The other side of that: a row that was showing an error and is hidden
        // now has still disappeared, and "where did it go?" is the same
        // question. The predicate is "was drawn", not "was healthy" — a version
        // demanding a previous success would go quiet exactly when a provider
        // fails its way out of the panel.
        assert_eq!(
            names(credentials_just_lost(&[http_500("grok")], &[empty("grok")])),
            vec!["grok".to_string()]
        );

        // A recovery is visible on the panel itself — the row comes back — so
        // it needs no line of its own.
        assert!(
            credentials_just_lost(&[empty("claude-cli")], &[with_token("claude-cli")]).is_empty()
        );

        // Per surface, not per plugin: one Claude login can lapse while the
        // other keeps working, and the line has to name which.
        assert_eq!(
            names(credentials_just_lost(
                &[with_token("claude-cli"), with_token("claude-desktop")],
                &[empty("claude-cli"), with_token("claude-desktop")],
            )),
            vec!["claude-cli".to_string()]
        );
    }

    fn codex_windows() -> Vec<Window> {
        vec![
            win("5H", Role::Primary, 4.0, 3720, 300), // 4% used · 1h2m
            win("WK", Role::Secondary, 20.0, 3 * 86400 + 4 * 3600, 10080), // 20% used · 3d4h
        ]
    }

    fn claude_windows() -> Vec<Window> {
        vec![
            win("5H", Role::Primary, 45.4, 7800, 300), // 45% used · 2h10m
            win("WK", Role::Secondary, 70.0, 2 * 86400 + 16 * 3600, 10080), // 70% used · 2d16h
        ]
    }

    #[test]
    fn codex_only_keeps_bare_form() {
        let title = menu_bar_title(&[codex_reading(codex_windows())]);
        assert_eq!(title, "04/20");
    }

    #[test]
    fn both_providers_get_prefixes() {
        let title = menu_bar_title(&[
            codex_reading(codex_windows()),
            claude_reading("claude-cli", true, claude_windows(), None),
        ]);
        assert_eq!(title, "Cx 04/20 · Cl 45/70");
    }

    #[test]
    fn claude_only_when_codex_absent() {
        let title = menu_bar_title(&[claude_reading("claude-cli", true, claude_windows(), None)]);
        assert_eq!(title, "Cl 45/70");
    }

    #[test]
    fn errored_or_desktop_claude_readings_are_ignored() {
        let title = menu_bar_title(&[
            codex_reading(codex_windows()),
            claude_reading("claude-cli", true, Vec::new(), Some("token expired")),
        ]);
        assert_eq!(title, "04/20");

        let desktop = claude_reading("claude-desktop", false, claude_windows(), None);
        let title = menu_bar_title(&[desktop]);
        assert_eq!(title, "Limits", "menu bar tracks the CLI account only");
    }

    #[test]
    fn no_data_falls_back_to_app_name() {
        assert_eq!(menu_bar_title(&[]), "Limits");
    }

    #[test]
    fn a_reset_far_in_the_past_projects_forward_without_counting_to_it() {
        // The provider supplies both numbers. A stale timestamp beside a short
        // window used to be a loop of tens of millions of iterations, run once
        // a second per window, on the thread that draws the panel.
        // The grid is `target + k*period`, so the answer is the first point on
        // that grid strictly after `now` — 100, 160, … 1000, 1060.
        assert_eq!(
            next_reset_after(100, 1_000, 60),
            1_060,
            "first reset strictly after now"
        );
        assert_eq!(
            next_reset_after(1_000, 1_000, 60),
            1_060,
            "a reset landing exactly on now moves on"
        );
        assert_eq!(
            next_reset_after(2_000, 1_000, 60),
            2_000,
            "a future reset is left alone"
        );
        assert_eq!(
            next_reset_after(1, 1_787_000_000, 60) % 60,
            1,
            "phase is preserved"
        );
        assert!(next_reset_after(1, 1_787_000_000, 60) > 1_787_000_000);
        assert_eq!(
            next_reset_after(1, 1_000, 0),
            1,
            "a zero period never comes round"
        );
        assert_eq!(
            next_reset_after(1, u64::MAX - 1, u64::MAX),
            u64::MAX,
            "a period that overflows saturates instead of wrapping"
        );
    }

    #[test]
    fn lapsed_reset_projects_forward_one_window() {
        // Reset was 100s ago on a 5h window → next reset in 300*60-100s = 4h58m.
        let windows = vec![
            Window {
                key: String::new(),
                label: "5H".into(),
                role: Role::Primary,
                used_percent: Some(0.0),
                resets_at: Some(NOW - 100),
                period_minutes: Some(300),
            },
            empty_window("WK", Role::Secondary),
        ];
        let title = menu_bar_title(&[codex_reading(windows)]);
        assert_eq!(title, "00/--", "missing weekly renders as a placeholder");
    }

    /// A log-file provider that doesn't fix slot order can report the weekly
    /// window alone (see `plugin::engine_logfile`'s own classification
    /// tests, which cover getting from the raw log line to this shape); this
    /// test only checks what `menu_bar_title`/`primary_reset` do with an
    /// already-classified "weekly only" reading — Primary empty, Secondary
    /// populated.
    #[test]
    fn weekly_only_reading_leaves_the_primary_slot_empty() {
        let windows = vec![
            empty_window("5H", Role::Primary),
            win("WK", Role::Secondary, 3.0, 6 * 86400, 10080),
        ];
        let readings = vec![codex_reading(windows)];
        assert_eq!(menu_bar_title(&readings), "--/03");

        // And the 5h auto-ping must NOT arm off the weekly reset.
        assert_eq!(primary_reset(&readings, "codex"), None);
    }

    #[test]
    fn critical_window_marks_the_compact_used_value() {
        let windows = vec![
            win("5H", Role::Primary, 98.0, 3600, 300),
            win("WK", Role::Secondary, 20.0, 3 * 86400, 10080),
        ];
        let title = menu_bar_title(&[codex_reading(windows)]);
        assert_eq!(title, "98!/20");
    }

    /// The Claude auto-ping arms off the CLI account's Primary (5h) window
    /// only — never the weekly reset, an errored reading, or another id.
    #[test]
    fn claude_ping_arms_off_the_cli_primary_window_only() {
        let weekly_only = vec![
            empty_window("5H", Role::Primary),
            win("WK", Role::Secondary, 70.0, 86400, 10080),
        ];
        assert_eq!(
            primary_reset(
                &[claude_reading("claude-cli", true, weekly_only, None)],
                "claude-cli"
            ),
            None
        );
        assert_eq!(
            primary_reset(
                &[claude_reading(
                    "claude-cli",
                    true,
                    Vec::new(),
                    Some("token expired")
                )],
                "claude-cli"
            ),
            None
        );

        let readings = vec![
            codex_reading(codex_windows()),
            claude_reading("claude-cli", true, claude_windows(), None),
        ];
        assert_eq!(primary_reset(&readings, "claude-cli"), Some(NOW + 7800));
        assert_eq!(primary_reset(&readings, "codex"), Some(NOW + 3720));
    }

    #[test]
    fn window_without_reset_time_marks_pace_unknown() {
        let (rel, at, _tooltip, progress, time_known) =
            window_view(NOW, 42.0, None, Some(300), false, "5-hour limit");
        assert_eq!(rel, "unknown");
        assert_eq!(at, "");
        assert_eq!(progress, 0.0);
        assert!(!time_known);
    }

    #[test]
    fn fresh_window_keeps_a_visible_time_marker() {
        let (rel, _at, _tooltip, progress, time_known) = window_view(
            NOW,
            0.0,
            Some(NOW + 300 * 60),
            Some(300),
            false,
            "5-hour limit",
        );
        assert_eq!(rel, "5h 0m");
        assert_eq!(progress, 0.0);
        assert!(time_known);
    }

    #[test]
    fn reset_timestamp_without_window_length_marks_pace_unknown() {
        let (_rel, _at, tooltip, progress, time_known) =
            window_view(NOW, 42.0, Some(NOW + 3600), None, false, "5-hour limit");
        assert_eq!(progress, 0.0);
        assert!(!time_known);
        assert!(
            tooltip.contains("resets in 1h 0m"),
            "tooltip keeps the countdown: {tooltip}"
        );
    }

    #[test]
    fn header_status_is_not_live_without_a_fresh_provider() {
        assert_eq!(header_status(false, false), ("reading…", false));
        assert_eq!(header_status(false, true), ("no data", false));
        assert_eq!(header_status(true, true), ("LIVE", true));
    }

    // ── merge (`readings()`) ─────────────────────────────────────────────

    /// Raw TOML text for a minimal valid manifest — factored out of
    /// [`stub_manifest`] so the id → path tests below can write it straight
    /// to a temp file without round-tripping through a parsed manifest.
    fn stub_manifest_toml(id: &str, order: i64) -> String {
        format!(
            r#"
            id         = "{id}"
            name       = "{id}"
            menu_label = "{id}"
            order      = {order}
            engine     = "log-file"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "p"
            resets_at_path = "r"
            [logfile]
            root = "~/.x"
            glob = "*.jsonl"
            container_key = "rate_limits"
            "#
        )
    }

    fn stub_manifest(id: &str, order: i64) -> PluginManifest {
        PluginManifest::from_str(&stub_manifest_toml(id, order)).expect("valid stub manifest")
    }

    fn stub_reading(id: &str) -> ProviderReading {
        ProviderReading {
            id: id.into(),
            name: id.into(),
            short: id.into(),
            tag: None,
            account: None,
            windows: vec![win("5H", Role::Primary, 1.0, 100, 300)],
            balances: Vec::new(),
            error: None,
            quota_status: None,
            in_menu_bar: true,
            bare_when_sole: false,
        }
    }

    #[test]
    fn readings_preserve_plugin_manifest_order_across_multiple_plugins() {
        let plugins = vec![stub_manifest("alpha", 10), stub_manifest("beta", 20)];
        let mut cache = HashMap::new();
        // Insert in reverse-of-manifest order to prove the output follows
        // `plugins`, not insertion order.
        cache.insert("beta".to_string(), vec![stub_reading("beta")]);
        cache.insert("alpha".to_string(), vec![stub_reading("alpha")]);

        let out = readings(&plugins, &cache);
        assert_eq!(
            out.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["alpha", "beta"]
        );
    }

    #[test]
    fn readings_sets_bare_when_sole_only_for_the_smallest_order_plugin() {
        let plugins = vec![stub_manifest("alpha", 10), stub_manifest("beta", 20)];
        let mut cache = HashMap::new();
        cache.insert("alpha".to_string(), vec![stub_reading("alpha")]);
        cache.insert("beta".to_string(), vec![stub_reading("beta")]);

        let out = readings(&plugins, &cache);
        assert!(out.iter().find(|r| r.id == "alpha").unwrap().bare_when_sole);
        assert!(!out.iter().find(|r| r.id == "beta").unwrap().bare_when_sole);
    }

    #[test]
    fn a_delivered_built_in_is_not_delivered_again_after_the_user_removes_it() {
        // The flag says a manifest may arrive; the *marker* is what makes that
        // a decision taken once. Tested through the caller that owns the
        // marker, because a test that flips the flag by hand proves only that
        // the flag is read.
        let dir = std::env::temp_dir().join(format!(
            "tickover-deliver-{}-{}",
            std::process::id(),
            now_unix()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join("codex.toml"), "# somebody else's\n").expect("existing manifest");

        // The marker lives in the user's config, not in `dir`, so this test
        // states the state it needs rather than inheriting whatever another
        // test left. (Under the fake HOME every test runs in, that config is a
        // scratch file — but "runs in any order" is the property being kept.)
        config::set_builtin_migrated("grok", "");

        upgrade_builtin_manifests(&dir);
        assert!(
            dir.join("grok.toml").exists(),
            "a new built-in reaches an existing install"
        );

        // The user does not want it. Removing it must stick: the marker
        // already records that this version's decision was made.
        std::fs::remove_file(dir.join("grok.toml")).expect("remove");
        upgrade_builtin_manifests(&dir);
        assert!(
            !dir.join("grok.toml").exists(),
            "a manifest the user deleted must not come back on the next launch"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The branch that used to be the only silent one. Walks the three states
    /// a built-in can be in, in the order a real install reaches them, and
    /// checks the log rather than a return value — `diag::take_recorded` exists
    /// so that "this branch writes a line" is a claim a test can hold to.
    ///
    /// The expected text is asked of `decided_yet_absent` rather than spelled
    /// out here: what is under test is that the line reaches the log from the
    /// right branch, not how it is worded.
    #[test]
    fn a_built_in_that_is_settled_and_missing_says_so_on_every_launch() {
        let dir = std::env::temp_dir().join(format!(
            "tickover-absent-note-{}-{}",
            std::process::id(),
            now_unix()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");

        // The markers live in config, not in `dir`. Measured (`cargo test`,
        // `--test-threads=1`, and `--test-threads=1 --nocapture` all give a
        // thread per test, hence a scratch config per test) they are this
        // test's own — but that is libtest's behaviour, not its promise, so
        // the precondition is stated instead of inherited. The neighbour above
        // does the same, for the same reason.
        // `""` clears the decision because the marker is compared to
        // `to_version` by **equality** (`upgrade_builtin_manifests`), so any
        // value that is not a shipped version reads as "not decided". Written
        // down rather than assumed: a marker compared by version *order* some
        // day would keep this test green while meaning something else.
        for upgrade in seed::BUILTIN_UPGRADES {
            config::set_builtin_migrated(upgrade.id, "");
        }
        let by_id = |id: &str| {
            seed::BUILTIN_UPGRADES
                .iter()
                .find(|u| u.id == id)
                .expect("a built-in with this id")
        };
        let _ = diag::take_recorded();

        // Launch 1, empty folder. The built-ins that ship
        // `deliver_if_absent = true` arrive and say nothing about being gone;
        // the ones that do not are settled where they stand, and that is the
        // sentence.
        upgrade_builtin_manifests(&dir);
        let first = diag::take_recorded();
        // Both directions, against the log itself. The negative half is the
        // one that catches the opposite regression — a note hoisted out of its
        // condition, filling a healthy install's log every launch — and it can
        // only be written because `absent_note` does not consult the disk.
        logged_exactly_for(&dir, &first);
        for id in ["codex", "claude"] {
            assert!(
                first.contains(&absent_note(by_id(id))),
                "{id} was left absent and unmentioned: {first:?}"
            );
        }

        // Launch 2, nothing changed. Said again, because the person reading
        // the log is not necessarily the person who was there for launch 1.
        upgrade_builtin_manifests(&dir);
        let second = diag::take_recorded();
        assert!(
            second.contains(&absent_note(by_id("codex"))),
            "the note is not a one-off: {second:?}"
        );
        logged_exactly_for(&dir, &second);

        // The state that cost a provider: the decision is recorded, the file
        // is gone. Deleting it is legitimate and still honoured — the loop
        // does not put it back — but the log now answers "where did it go".
        std::fs::remove_file(dir.join("grok.toml")).expect("remove");
        upgrade_builtin_manifests(&dir);
        let third = diag::take_recorded();
        assert!(
            third.contains(&absent_note(by_id("grok"))),
            "a settled built-in gone missing: {third:?}"
        );
        assert!(!dir.join("grok.toml").exists(), "and it stays deleted");
        logged_exactly_for(&dir, &third);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Every built-in whose file is missing from `dir` is named in `logged`,
    /// and **no** built-in whose file is there is.
    fn logged_exactly_for(dir: &std::path::Path, logged: &[String]) {
        for upgrade in seed::BUILTIN_UPGRADES {
            let note = absent_note(upgrade);
            let on_disk = dir.join(upgrade.file).exists();
            assert_eq!(
                logged.contains(&note),
                !on_disk,
                "{} is {} disk, so the log {} name it: {logged:?}",
                upgrade.file,
                if on_disk { "on" } else { "off" },
                if on_disk { "must not" } else { "must" }
            );
        }
    }

    #[test]
    fn a_provider_with_only_balances_does_not_take_the_bare_tray_slot() {
        // Grok reports no window at all — measured, both response shapes — so
        // it contributes nothing to the tray title's numbers. If it took the
        // bare slot anyway, the provider that *does* print numbers would start
        // printing them with its label back on (`Cx 96/80` where it used to
        // print `96/80`), and a lone Grok would render the bare word "Limits".
        let plugins = vec![stub_manifest("grok", 5), stub_manifest("codex", 10)];
        let mut cache = HashMap::new();
        let mut balances_only = stub_reading("grok");
        balances_only.windows.clear();
        balances_only.balances = vec![tickover::model::Balance {
            key: "monthly:".into(),
            label: "Month".into(),
            used: Some(tickover::model::BalanceAmount::Number {
                value: 12.0,
                unit: None,
            }),
            cap: None,
            remaining: None,
            stated_percent: None,
            period_end: None,
            limit_reached: None,
        }];
        cache.insert("grok".to_string(), vec![balances_only]);
        cache.insert("codex".to_string(), vec![stub_reading("codex")]);

        let out = readings(&plugins, &cache);
        assert!(
            !out.iter().find(|r| r.id == "grok").unwrap().bare_when_sole,
            "a reading with no window has no numbers for a bare title"
        );
        assert!(
            out.iter().find(|r| r.id == "codex").unwrap().bare_when_sole,
            "the slot goes to the first provider that actually reports a window"
        );
    }

    #[test]
    fn readings_drops_no_credentials_found_reading_entirely() {
        let plugins = vec![stub_manifest("alpha", 10)];
        let mut absent = stub_reading("alpha");
        absent.error = Some("no credentials found".to_string());
        absent.windows.clear();
        let mut cache = HashMap::new();
        cache.insert("alpha".to_string(), vec![absent]);

        assert!(
            readings(&plugins, &cache).is_empty(),
            "an absent surface must not produce a row at all"
        );
    }

    #[test]
    fn readings_keeps_other_error_messages_inline() {
        let plugins = vec![stub_manifest("alpha", 10)];
        let mut errored = stub_reading("alpha");
        errored.error = Some("token expired".to_string());
        errored.windows.clear();
        let mut cache = HashMap::new();
        cache.insert("alpha".to_string(), vec![errored]);

        let out = readings(&plugins, &cache);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].error.as_deref(), Some("token expired"));
    }

    // ── readings_with — opt-in surface filtering (fix 3) ──────────────────

    fn claude_surface_reading(surface_id: &str) -> ProviderReading {
        ProviderReading {
            id: surface_reading_id("claude", surface_id),
            name: "Claude".into(),
            short: "Cl".into(),
            tag: None,
            account: None,
            windows: vec![win("5H", Role::Primary, 1.0, 100, 300)],
            balances: Vec::new(),
            error: None,
            quota_status: None,
            in_menu_bar: surface_id != "desktop",
            bare_when_sole: false,
        }
    }

    /// A desktop reading already sitting in the cache (e.g. a fetch that was
    /// in flight when the user toggled the opt-in off, and only landed
    /// afterwards) must not show once the surface is no longer active —
    /// `readings_with` filters at read time, not fetch time.
    #[test]
    fn readings_with_drops_a_cached_reading_whose_opt_in_surface_is_now_inactive() {
        let plugins = vec![claude_like_two_surface_manifest()];
        let mut cache = HashMap::new();
        cache.insert(
            "claude".to_string(),
            vec![
                claude_surface_reading("cli"),
                claude_surface_reading("desktop"),
            ],
        );

        let out = readings_with(
            &plugins,
            &cache,
            |m| active_surface_ids_with(m, false),
            |_| true,
        );
        assert_eq!(
            out.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["claude-cli"],
            "the stale desktop reading must disappear immediately, even though it's still cached"
        );
    }

    /// The mirror case: while the opt-in surface is active, its cached
    /// reading is kept.
    #[test]
    fn readings_with_keeps_a_cached_reading_whose_opt_in_surface_is_active() {
        let plugins = vec![claude_like_two_surface_manifest()];
        let mut cache = HashMap::new();
        cache.insert(
            "claude".to_string(),
            vec![
                claude_surface_reading("cli"),
                claude_surface_reading("desktop"),
            ],
        );

        let out = readings_with(
            &plugins,
            &cache,
            |m| active_surface_ids_with(m, true),
            |_| true,
        );
        assert_eq!(
            out.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["claude-cli", "claude-desktop"]
        );
    }

    // ── readings_with — disabled-plugin filter + bare-follows-visible ─────

    /// A disabled plugin must not surface a reading even when its cache slot
    /// still holds one (fix 5 — the explicit `enabled` gate is defense over
    /// the emptied-cache-slot invariant). And with the lower-order plugin
    /// disabled, the remaining visible plugin becomes the bare one (fix 4).
    #[test]
    fn readings_with_drops_a_disabled_plugin_and_promotes_the_visible_one_to_bare() {
        let plugins = vec![stub_manifest("alpha", 10), stub_manifest("beta", 20)];
        let mut cache = HashMap::new();
        cache.insert("alpha".to_string(), vec![stub_reading("alpha")]);
        cache.insert("beta".to_string(), vec![stub_reading("beta")]);

        let out = readings_with(
            &plugins,
            &cache,
            |m| active_surface_ids_with(m, true),
            |m| m.id != "alpha",
        );
        assert_eq!(
            out.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["beta"],
            "the disabled alpha must not contribute a reading"
        );
        assert!(
            out[0].bare_when_sole,
            "the sole visible plugin must be bare, not the disabled lower-order one"
        );
    }

    /// While every plugin is visible the smallest-order one (alpha) stays
    /// bare — the fix-4 change must not disturb the existing behaviour.
    #[test]
    fn readings_with_keeps_the_lowest_order_visible_plugin_bare() {
        let plugins = vec![stub_manifest("alpha", 10), stub_manifest("beta", 20)];
        let mut cache = HashMap::new();
        cache.insert("alpha".to_string(), vec![stub_reading("alpha")]);
        cache.insert("beta".to_string(), vec![stub_reading("beta")]);

        let out = readings_with(
            &plugins,
            &cache,
            |m| active_surface_ids_with(m, true),
            |_| true,
        );
        assert!(out.iter().find(|r| r.id == "alpha").unwrap().bare_when_sole);
        assert!(!out.iter().find(|r| r.id == "beta").unwrap().bare_when_sole);
    }

    // ── dynamic sub-account rows (log-file multi-account) ─────────────────

    #[test]
    fn surface_id_active_routes_dynamic_subaccounts_via_their_surface_base() {
        let active: HashSet<String> = ["codex".to_string(), "claude".to_string()]
            .into_iter()
            .collect();
        // Plain surface ids match exactly, as before.
        assert!(surface_id_active("codex", &active));
        assert!(
            !surface_id_active("claude-desktop", &active),
            "a distinct surface still needs to be active"
        );
        // A "#"-suffixed sub-account is active whenever its surface base is.
        assert!(surface_id_active("codex#plus", &active));
        assert!(
            !surface_id_active("gemini#x", &active),
            "an inactive base doesn't route its sub-accounts"
        );
    }

    /// A log-file plugin's cache can hold a primary reading plus one or more
    /// `"<id>#<account>"` sub-account rows; both must surface as distinct rows.
    #[test]
    fn readings_with_surfaces_a_dynamic_subaccount_row() {
        let plugins = vec![stub_manifest("codex", 10)];
        let mut cache = HashMap::new();
        cache.insert(
            "codex".to_string(),
            vec![stub_reading("codex"), stub_reading("codex#plus")],
        );

        let out = readings_with(
            &plugins,
            &cache,
            |m| active_surface_ids_with(m, true),
            |_| true,
        );
        assert_eq!(
            out.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["codex", "codex#plus"],
            "the sub-account row rides on the plugin's active surface"
        );
    }

    // ── remembered account emails ─────────────────────────────────────────

    // ── active surfaces ───────────────────────────────────────────────────

    fn claude_like_two_surface_manifest() -> PluginManifest {
        let toml = r#"
            id         = "claude"
            name       = "Claude"
            menu_label = "Cl"
            order      = 20
            engine     = "http-api"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "utilization"
            resets_at_path = "resets_at"
            [http]
            [[http.request]]
            url = "https://example.com/usage"
            [[surface]]
            id = "cli"
            label = "CLI"
            opt_in = false
            [[surface]]
            id = "desktop"
            label = "Desktop"
            opt_in = true
            in_menu_bar = false
        "#;
        PluginManifest::from_str(toml).expect("valid test manifest")
    }

    #[test]
    fn active_surface_ids_always_include_non_opt_in_and_gate_opt_in_ones() {
        let m = claude_like_two_surface_manifest();
        assert_eq!(active_surface_ids_with(&m, false), vec!["cli".to_string()]);
        assert_eq!(
            active_surface_ids_with(&m, true),
            vec!["cli".to_string(), "desktop".to_string()]
        );
    }

    // ── owning_manifest ───────────────────────────────────────────────────

    /// Pinned to the ids [`readings_with`] actually produces, not to the naming
    /// scheme written out a second time. Two independent inverses of the same
    /// scheme is how `required` came to be alive in one engine and dead in the
    /// other; this test fails the moment they drift apart.
    #[test]
    fn owning_manifest_answers_for_every_reading_id_readings_with_can_produce() {
        let plugins = vec![
            stub_manifest("codex", 10),
            claude_like_two_surface_manifest(),
        ];
        let mut cache = HashMap::new();
        cache.insert(
            "codex".to_string(),
            vec![stub_reading("codex"), stub_reading("codex#plus")],
        );
        cache.insert(
            "claude".to_string(),
            vec![
                claude_surface_reading("cli"),
                claude_surface_reading("desktop"),
            ],
        );

        let out = readings_with(
            &plugins,
            &cache,
            |m| active_surface_ids_with(m, true),
            |_| true,
        );
        assert_eq!(
            out.len(),
            4,
            "two plugins, one with a sub-account row and one with two surfaces"
        );
        for r in &out {
            let owner = owning_manifest(&plugins, &r.id)
                .unwrap_or_else(|| panic!("no manifest owns reading {:?}", r.id));
            let expected = if r.id.starts_with("codex") {
                "codex"
            } else {
                "claude"
            };
            assert_eq!(owner.id, expected, "reading {:?}", r.id);
        }
    }

    #[test]
    fn owning_manifest_has_no_answer_for_a_reading_no_manifest_declares() {
        let plugins = vec![stub_manifest("codex", 10)];
        assert!(owning_manifest(&plugins, "gemini").is_none());
        assert!(
            owning_manifest(&plugins, "codex-desktop").is_none(),
            "a surface this manifest does not declare is not its reading"
        );
    }

    /// The forward map flattens a plugin id and a surface id into one string,
    /// so it is not reversible in general: a third-party plugin *named*
    /// `claude-cli` claims the same reading id as plugin `claude`'s `cli`
    /// surface. Answering with either would file one provider's remembered
    /// windows under the other's plugin id — where `remove_plugin_keys` will
    /// not find them on uninstall — and draw one provider's declared windows on
    /// the other's card.
    /// The collision costs both providers their remembered windows, and nothing
    /// on screen says so — so the load has to.
    #[test]
    fn a_reading_id_two_manifests_claim_is_reported_at_load() {
        let plugins = vec![
            claude_like_two_surface_manifest(),
            stub_manifest("claude-cli", 30),
        ];
        assert_eq!(
            colliding_reading_ids(&plugins),
            vec!["claude-cli".to_string()]
        );

        assert!(
            colliding_reading_ids(&[
                claude_like_two_surface_manifest(),
                stub_manifest("codex", 10)
            ])
            .is_empty(),
            "distinct plugins that spell nothing alike are not a collision"
        );
        assert!(
            colliding_reading_ids(std::slice::from_ref(&claude_like_two_surface_manifest()))
                .is_empty(),
            "a plugin is never in collision with itself"
        );
    }

    #[test]
    fn owning_manifest_refuses_a_reading_id_two_manifests_both_claim() {
        let plugins = vec![
            claude_like_two_surface_manifest(),
            stub_manifest("claude-cli", 30),
        ];
        assert_eq!(
            surface_reading_id("claude", "cli"),
            "claude-cli",
            "the collision this is about"
        );
        assert!(
            owning_manifest(&plugins, "claude-cli").is_none(),
            "ambiguous: no answer is the only safe one"
        );
        assert_eq!(
            owning_manifest(&plugins, "claude-desktop").map(|m| m.id.as_str()),
            Some("claude"),
            "the plugin's other surface is unaffected"
        );
    }

    // ── first_surface_reading_id ──────────────────────────────────────────

    #[test]
    fn first_surface_reading_id_uses_the_plugin_id_for_a_synthesized_default_surface() {
        let m = stub_manifest("codex", 10);
        assert_eq!(first_surface_reading_id(&m).as_deref(), Some("codex"));
    }

    #[test]
    fn first_surface_reading_id_uses_the_plugin_surface_scheme_for_explicit_surfaces() {
        let m = claude_like_two_surface_manifest();
        assert_eq!(
            first_surface_reading_id(&m).as_deref(),
            Some("claude-cli"),
            "cli is first in manifest order"
        );
    }

    // ── auto-ping de-dup ──────────────────────────────────────────────────

    /// A 5-hour window, `mins` minutes from its reset, as the reading states it.
    const FIVE_H: Option<u64> = Some(300);

    #[test]
    fn ping_due_leaves_a_window_that_is_already_running_alone() {
        assert!(
            !ping_due(Some(3.0), Some(NOW + 300), FIVE_H, 0, 0, NOW),
            "usage on the clock: there is no window left to start"
        );
        assert!(
            !ping_due(Some(0.4), Some(NOW + 300), FIVE_H, 0, 0, NOW),
            "a fraction of a percent is still usage, however it renders"
        );
        assert!(
            !ping_due(Some(f64::NAN), Some(NOW + 300), FIVE_H, 0, 0, NOW),
            "a figure that cannot be read must never spend quota"
        );
    }

    #[test]
    fn ping_due_fires_once_for_an_empty_window_and_not_again() {
        let reset = NOW + 300;
        assert!(
            ping_due(Some(0.0), Some(reset), FIVE_H, 0, 0, NOW),
            "never pinged: due"
        );
        assert!(
            ping_due(None, Some(reset), FIVE_H, 0, 0, NOW),
            "a window reported without data is empty, not busy"
        );
        // The window began 5h before its reset; a ping from inside it counts.
        let started = reset - 5 * 3600;
        assert!(
            !ping_due(Some(0.0), Some(reset), FIVE_H, 0, started + 1, NOW),
            "already pinged inside this window"
        );
        assert!(
            !ping_due(
                Some(0.0),
                Some(reset),
                FIVE_H,
                0,
                started - PING_GRACE_SECS,
                NOW
            ),
            "a ping just before the window began is the one that began it"
        );
        assert!(
            ping_due(
                Some(0.0),
                Some(reset),
                FIVE_H,
                0,
                started - PING_GRACE_SECS - 1,
                NOW
            ),
            "past the grace, the last ping belongs to the window before this one"
        );
    }

    /// The regression this rule exists for: a machine asleep at the boundary
    /// wakes hours later, and the window it slept through is still empty. The
    /// edge rule this replaced armed only within 120 s of the reset, so that
    /// window was never pinged at all.
    #[test]
    fn ping_due_still_fires_for_a_boundary_that_was_slept_through() {
        let reset = NOW + 3600; // four hours into a five-hour window
        assert!(
            ping_due(Some(0.0), Some(reset), FIVE_H, 0, reset - 6 * 3600, NOW),
            "late is not the same as never"
        );
    }

    /// Codex stops reporting the 5-hour window entirely once it has nothing to
    /// report, so after its boundary the reading names no reset at all — the
    /// last one it did state is where the running window began.
    #[test]
    fn ping_due_uses_the_last_stated_reset_when_the_window_vanishes() {
        assert!(ping_due(None, None, None, NOW - 60, 0, NOW));
        assert!(
            !ping_due(None, None, None, NOW + 60, 0, NOW),
            "that boundary hasn't passed yet"
        );
        assert!(
            !ping_due(None, None, None, 0, 0, NOW),
            "nothing was ever stated: no boundary to compare against"
        );
    }

    /// A Codex-shaped manifest: a `[ping]` and one primary window whose length
    /// comes out of the response, so there is none to be had when the provider
    /// reports nothing. Deliberately the only window it declares — the weekly
    /// row the tests put in a reading is one this manifest never mentions,
    /// which is the point: `ping_window` must find its answer in the manifest,
    /// not in whatever rows happen to have arrived.
    fn pingable_manifest() -> PluginManifest {
        let toml = r#"
            id         = "codex"
            name       = "Codex"
            menu_label = "Cx"
            order      = 10
            engine     = "http-api"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode  = "from_field"
            field = "limit_window_seconds"
            unit  = "seconds"
            [windows.source]
            used_percent_path = "used_percent"
            resets_at_path    = "reset_at"
            [http]
            [[http.request]]
            url = "https://example.com/usage"
            [ping]
            bin = "codex"
        "#;
        PluginManifest::from_str(toml).expect("valid pingable manifest")
    }

    fn reading_with(windows: Vec<Window>, error: Option<&str>) -> ProviderReading {
        ProviderReading {
            id: "codex".into(),
            name: "Codex".into(),
            short: "Cx".into(),
            tag: None,
            account: None,
            windows,
            balances: Vec::new(),
            error: error.map(str::to_string),
            quota_status: None,
            in_menu_bar: true,
            bare_when_sole: false,
        }
    }

    /// The loop above `ping_due`, which its own tests cannot see: they are pure
    /// functions over scalars and would keep passing over a loop that never
    /// reaches them. Which is what nearly happened — the loop used to find its
    /// window by asking the *reading* for a Primary row, and told "we could not
    /// read this provider" from "this provider reports no 5-hour window right
    /// now" purely by whether a row had been emitted. Dropping unreported
    /// windows deletes that signal, so the question moved to the manifest.
    #[test]
    fn the_ping_still_has_a_window_when_the_provider_reports_none() {
        let m = pingable_manifest();
        let weekly = Window {
            key: String::new(),
            label: "WK".into(),
            role: Role::Secondary,
            used_percent: Some(69.0),
            resets_at: Some(NOW + 600),
            period_minutes: Some(10080),
        };

        // The case this whole feature exists for: Codex is empty, so it reports
        // no 5-hour window at all, and the panel shows only the weekly row.
        let empty = reading_with(vec![weekly.clone()], None);
        let target = ping_window(&m, Some(&empty)).expect("an empty 5h window is still a window");
        assert_eq!(target.used_percent, None);
        assert_eq!(target.resets_at, None);
        assert_eq!(
            target.period_minutes, None,
            "no length to read out of a window not reported"
        );
        assert!(
            ping_due(
                target.used_percent,
                target.resets_at,
                target.period_minutes,
                NOW - 60,
                0,
                NOW
            ),
            "with a boundary remembered on disk, this is exactly the ping that was going missing"
        );

        // And the state that must *not* ping, which used to be told apart by
        // the same accident: a provider we could not read says nothing about
        // its quota, and a ping on that guess spends the user's own allowance.
        let unreadable = reading_with(Vec::new(), Some("session expired"));
        assert!(ping_window(&m, Some(&unreadable)).is_none());

        // A reported window is passed through as itself.
        let five = Window {
            key: String::new(),
            label: "5H".into(),
            role: Role::Primary,
            used_percent: Some(4.0),
            resets_at: Some(NOW + 300),
            period_minutes: Some(300),
        };
        let live =
            ping_window(&m, Some(&reading_with(vec![five, weekly], None))).expect("reported");
        assert_eq!(live.used_percent, Some(4.0));
        assert_eq!(live.period_minutes, Some(300));

        // No reading at all, and a manifest that declares no 5-hour window:
        // neither is something to ping for.
        assert!(ping_window(&m, None).is_none());
        let mut weekly_only = pingable_manifest();
        weekly_only.windows[0].role = manifest::Role::Secondary;
        assert!(ping_window(&weekly_only, Some(&reading_with(Vec::new(), None))).is_none());
    }

    /// An invariant nothing states and two menu-bar functions rely on.
    ///
    /// `menu_bar_title` and `widget_rows` read `primary_window()` and
    /// `secondary_window()` without ever looking at `error`. That is safe only
    /// because every path that sets an error leaves the window list empty —
    /// true today in both engines, and nowhere written down. The day a
    /// reading can be partly wrong and partly usable, the menu bar would
    /// start printing numbers out of a reading the panel is showing as
    /// broken. This fails first instead.
    #[test]
    fn an_errored_reading_carries_no_windows_for_the_menu_bar_to_print() {
        let broken = ProviderReading {
            windows: vec![Window {
                key: String::new(),
                label: "5H".into(),
                role: Role::Primary,
                used_percent: Some(96.0),
                resets_at: None,
                period_minutes: None,
            }],
            error: Some("session expired".into()),
            ..reading_with(Vec::new(), None)
        };
        assert_eq!(
            menu_bar_title(std::slice::from_ref(&broken)),
            menu_bar_title(&[]),
            "if a reading may carry both an error and windows, the menu bar has to start              checking for the error — it does not"
        );
    }

    // ── the quota's own standing ────────────────────────────────────────

    fn blocked_quota() -> tickover::model::QuotaStatus {
        tickover::model::QuotaStatus {
            allowed: Some(false),
            limit_reached: Some(true),
            reached_type: Some("rate_limit_reached".to_string()),
        }
    }

    /// The defect the quota level was introduced for. Codex states `allowed`
    /// and `limit_reached` beside two *optional* window slots, so an account
    /// that is cut off with nothing running answers with a status and no
    /// window — and presence, correctly, draws no row for a window nobody
    /// reported. Before this, the panel said "no usage reported yet" to a user
    /// who was locked out.
    #[test]
    fn a_blocked_quota_with_no_windows_still_states_its_status() {
        let blocked = ProviderReading {
            quota_status: Some(blocked_quota()),
            ..reading_with(Vec::new(), None)
        };
        let data = provider_data_from_reading(&blocked, ModelRc::default(), ModelRc::default());

        // Through `notice`, not `message`. Routing it through the message put
        // the refusal in the same faint grey as "no usage reported yet" and
        // "not installed" — so the one state the quota status exists to
        // surface arrived looking like the calmest thing on the panel, and a
        // user could not tell "the provider refused you" from "we could not
        // read it", which is exactly the distinction the quota status draws.
        assert!(
            data.notice.contains("limit reached"),
            "the refusal has to reach the screen in the colour of a refusal: {}",
            data.notice
        );
        assert!(
            data.notice.contains("rate_limit_reached"),
            "and in the provider's own words, so a vocabulary that grows on the server is visible"
        );
        assert_ne!(
            data.message, "no usage reported yet",
            "the friendly sentence is exactly the one that would hide this"
        );
    }

    /// The other half of the same rule, kept here so it cannot live in one of
    /// two places: a provider we could not read has said nothing about its
    /// quota, and a status surviving from a previous tick would say it again.
    #[test]
    fn an_errored_reading_states_no_quota_status() {
        let mut broken = ProviderReading {
            quota_status: Some(blocked_quota()),
            ..reading_with(Vec::new(), None)
        };
        broken
            .windows
            .push(win("5H", Role::Primary, 96.0, 600, 300));

        broken.fail("session expired");

        assert_eq!(
            broken.quota_status, None,
            "the claim goes with the reading that could not be read"
        );
        assert!(
            broken.windows.is_empty(),
            "and so do the windows, which is the older half of it"
        );

        let data = provider_data_from_reading(&broken, ModelRc::default(), ModelRc::default());
        assert_eq!(data.message, "session expired");
        assert_eq!(
            data.notice, "",
            "no refusal is drawn beside an error we invented nothing for"
        );
    }

    /// The state that actually occurs, rather than the tidy one. A provider
    /// whose windows have been seen keeps hysteresis rows, so "blocked with no
    /// rows at all" is rare — the ordinary shape is a blocked quota *beside*
    /// rows, one of which may honestly be "not started".
    ///
    /// Both are drawn, and deliberately: the weekly allowance being exhausted
    /// and the five-hour window not having started are simultaneously true, and
    /// suppressing the row would hide a fact the provider did state. The notice
    /// says who refused; the rows say what each window is doing.
    #[test]
    fn a_blocked_quota_states_its_status_beside_the_rows_it_does_not_contradict() {
        let reading = ProviderReading {
            quota_status: Some(blocked_quota()),
            ..reading_with(vec![win("WK", Role::Secondary, 100.0, 3600, 10_080)], None)
        };
        let m = two_window_manifest();
        let seen = config::SeenWindow {
            at: NOW - 600,
            period_minutes: Some(300),
        };
        let rows = window_rows(Some(&m), &reading, NOW, &seen_only(Role::Primary, seen));

        assert_eq!(
            labels(&rows),
            vec!["5-hour limit", "Weekly limit"],
            "the quiet window still gets its row"
        );
        assert!(rows[0].1.not_started, "and still says it has not started");

        let mut models: HashMap<String, WindowModel> = HashMap::new();
        let windows = reconcile_window_model(&mut models, "codex", rows);
        let data = provider_data_from_reading(&reading, windows, ModelRc::default());

        assert_eq!(data.status, 0, "there are rows, so the section draws them");
        assert!(
            data.notice.contains("limit reached"),
            "with the refusal above them rather than instead of them: {}",
            data.notice
        );
    }

    /// A provider stating that nothing is wrong states it to us, not to the
    /// user: a line saying "all fine" on every account forever would train the
    /// eye to skip the place the real message appears in.
    #[test]
    fn a_quota_that_is_not_refused_draws_no_line_at_all() {
        let fine = ProviderReading {
            quota_status: Some(tickover::model::QuotaStatus {
                allowed: Some(true),
                limit_reached: Some(false),
                reached_type: None,
            }),
            ..reading_with(vec![win("5H", Role::Primary, 12.0, 600, 300)], None)
        };
        assert_eq!(
            provider_data_from_reading(&fine, ModelRc::default(), ModelRc::default()).notice,
            ""
        );
    }

    // ── balance rows ─────────────────────────────────────────────────────

    fn one_balance_row(label: &str, amount_line: &str) -> ModelRc<BalanceData> {
        ModelRc::from(Rc::new(VecModel::from(vec![BalanceData {
            label: ss(label),
            amount_line: ss(amount_line),
            percent_line: ss(""),
            period_line: ss(""),
            notice: ss(""),
        }])))
    }

    /// The defect the balance level exists to fix a second time: Grok states
    /// only a balance and never a window, and the "nothing to draw" guard used
    /// to look at `windows` alone — which would have hidden a provider's only
    /// stated figure behind the same friendly sentence the quota status
    /// already fixed for a blocked quota with no window (see
    /// `a_blocked_quota_with_no_windows_still_states_its_status` above).
    #[test]
    fn a_balances_only_section_does_not_say_no_usage_reported_yet() {
        let reading = reading_with(Vec::new(), None);
        let balances = one_balance_row("Spend", "used 12.34 USD");

        let data = provider_data_from_reading(&reading, ModelRc::default(), balances);

        assert_eq!(
            data.status, 0,
            "there is a balance row, so the section draws it"
        );
        assert_ne!(
            data.message, "no usage reported yet",
            "a stated balance with no window is still a stated account"
        );
    }

    /// `balance_rows` keys each row by `Balance.key`, never by its label —
    /// the label is a display string the manifest author may reword, and the
    /// reconciler (`reconcile_balance_model`) has to keep matching the same
    /// row across that. The key and the label are deliberately different here
    /// so a version keying on the wrong field would still pass every other
    /// balance test in this file (they all happen to give a row's key and
    /// label the same text) and only fail here.
    #[test]
    fn balance_rows_are_keyed_by_balance_key_not_by_the_label() {
        let b = tickover::model::Balance {
            key: "spend:".into(),
            label: "Monthly spend".into(),
            used: Some(tickover::model::BalanceAmount::Number {
                value: 1.0,
                unit: None,
            }),
            ..empty_balance("x")
        };
        let reading = ProviderReading {
            balances: vec![b],
            ..reading_with(Vec::new(), None)
        };

        let rows = balance_rows(&reading, NOW);

        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].0, "spend:",
            "the reconciler matches on Balance::key, never the label"
        );
    }

    /// The rule that must never leave Rust: a percentage is drawn only when
    /// the provider stated one, never computed from `used`/`cap` even when
    /// both are present and a ratio is trivial to produce. `used`/`cap` are a
    /// computable 25/100 on purpose — a naive `used / cap * 100`
    /// implementation would print "25% used" over what should be an empty
    /// `percent_line`, and this fixture is the one that would catch it.
    #[test]
    fn a_missing_stated_percent_is_never_computed_from_used_and_cap() {
        let b = tickover::model::Balance {
            key: "spend:".into(),
            label: "Spend".into(),
            used: Some(tickover::model::BalanceAmount::Number {
                value: 25.0,
                unit: None,
            }),
            cap: Some(tickover::model::BalanceAmount::Number {
                value: 100.0,
                unit: None,
            }),
            remaining: None,
            stated_percent: None,
            period_end: None,
            limit_reached: None,
        };

        let data = balance_data(NOW, &b, false).expect("used/cap alone is still something to draw");

        assert_eq!(
            data.percent_line, "",
            "no percentage the provider did not send"
        );
        assert!(
            !data.amount_line.contains('%'),
            "and none hiding inside the amount line either"
        );
    }

    /// `BalanceAmount::Number`'s unit is unknown (Grok's is), so a fixed two
    /// decimals would be this app assuming a precision nobody stated — the
    /// same mistake `format_money_minor` is forbidden from making on the
    /// better-specified `Money` variant. A tiny remaining balance is the case
    /// that catches a hardcoded `{:.2}`: it would print `"0.00"` for a
    /// genuinely nonzero figure.
    #[test]
    fn a_bare_number_prints_at_its_own_precision_never_a_fixed_two_decimals() {
        let b = tickover::model::Balance {
            remaining: Some(tickover::model::BalanceAmount::Number {
                value: 0.001,
                unit: None,
            }),
            ..empty_balance("Credits")
        };
        let data = balance_data(NOW, &b, false).expect("remaining alone is something to draw");
        assert_eq!(
            data.amount_line, "remaining 0.001",
            "a fixed two decimals would round this nonzero figure down to 0.00"
        );
    }

    /// The shape Copilot ships: a ceiling and what is left of it, with no
    /// spent figure anywhere in the response. It draws as one line, the same
    /// way a spent-against-a-ceiling row does — the two are the same fact
    /// stated from opposite ends, and stacking one of them while pairing the
    /// other made the same shape read as two different kinds of row.
    ///
    /// What must never appear is the third figure: `cap − remaining` is a
    /// subtraction this app did not receive, exactly like the ratio the test
    /// above forbids.
    #[test]
    fn a_ceiling_with_what_is_left_of_it_draws_as_one_pair_and_invents_no_spent_figure() {
        let unit = |v: f64| tickover::model::BalanceAmount::Number {
            value: v,
            unit: Some("interactions".into()),
        };
        let b = tickover::model::Balance {
            cap: Some(unit(300.0)),
            remaining: Some(unit(271.6)),
            ..empty_balance("Premium")
        };

        let data = balance_data(NOW, &b, false).expect("a ceiling and a remainder are drawable");

        assert_eq!(
            data.amount_line,
            "remaining 271.6 interactions / cap 300 interactions"
        );
        assert!(
            !data.amount_line.contains("used"),
            "no spent figure was stated to draw"
        );
        assert_eq!(
            data.percent_line, "",
            "and no percentage, the provider's own being a remaining one"
        );

        // The ceiling in a different unit is not the same ceiling: the pair
        // comes apart rather than rendering a comparison nobody made — the
        // rule `pair_is_comparable` already holds for used/cap, asserted here
        // for the other half so both halves cannot drift.
        let mixed = tickover::model::Balance {
            cap: Some(tickover::model::BalanceAmount::Number {
                value: 300.0,
                unit: None,
            }),
            ..b.clone()
        };
        let split = balance_data(NOW, &mixed, false).expect("both figures are still drawable");
        assert_eq!(split.amount_line, "cap 300\nremaining 271.6 interactions");

        // The shape a free Copilot plan ships: both figures unitless, because
        // the row label already names what is counted. This case is easy to
        // misread as incomparable — two bare numbers with no unit look like
        // they have nothing to compare — so it is settled here directly:
        // `unit_tag` gives a unitless number the tag `number:`, which equals
        // itself, so the pair holds. The same reading is what has always
        // paired Grok's unitless used/cap row, asserted just below so the two
        // cannot drift apart.
        let bare = |v: f64| tickover::model::BalanceAmount::Number {
            value: v,
            unit: None,
        };
        let free = tickover::model::Balance {
            cap: Some(bare(50.0)),
            remaining: Some(bare(20.0)),
            ..empty_balance("Chat")
        };
        let free_line = balance_data(NOW, &free, false).expect("both figures are drawable");
        assert_eq!(free_line.amount_line, "remaining 20 / cap 50");

        let grok_shaped = tickover::model::Balance {
            used: Some(bare(4.0)),
            cap: Some(bare(25.0)),
            ..empty_balance("Pay-as-you-go")
        };
        let grok_line = balance_data(NOW, &grok_shaped, false).expect("both figures are drawable");
        assert_eq!(
            grok_line.amount_line, "used 4 / cap 25",
            "the unitless pair Grok has always shipped still draws as one line"
        );

        // And a balance that states all three keeps its used/cap pair, with
        // the remainder on its own line: pairing the ceiling twice would print
        // it twice.
        let all_three = tickover::model::Balance {
            used: Some(unit(28.4)),
            ..b.clone()
        };
        let full = balance_data(NOW, &all_three, false).expect("all three are drawable");
        assert_eq!(
            full.amount_line,
            "used 28.4 interactions / cap 300 interactions\nremaining 271.6 interactions"
        );
    }

    fn empty_balance(label: &str) -> tickover::model::Balance {
        tickover::model::Balance {
            key: format!("{label}:"),
            label: label.into(),
            used: None,
            cap: None,
            remaining: None,
            stated_percent: None,
            period_end: None,
            limit_reached: None,
        }
    }

    /// The two branches `a_comparable_pair_renders_as_one_line...` below never
    /// reaches: `exponent == 0` (the early return that must print no decimal
    /// point at all) and a negative `minor` (the sign path `unsigned_abs()`
    /// exists for, added specifically to dodge the `i64::MIN` panic
    /// `minor.abs()` would have). Worked out by hand, not just asserted: for
    /// `minor = -5, exponent = 2`, `sign = "-"`, `whole = 5 / 100 = 0`,
    /// `frac = 5`, so the join has to land as `"-0.05"` — a sign applied
    /// after the whole/fraction split instead of before it would produce
    /// `"0.-05"`, and nothing but this assertion would catch that.
    #[test]
    fn format_money_minor_handles_a_zero_exponent_and_a_negative_amount() {
        assert_eq!(
            format_money_minor(100, 0),
            "100",
            "no decimal point when the currency has no minor unit"
        );
        assert_eq!(format_money_minor(-100, 0), "-100");
        assert_eq!(
            format_money_minor(5, 2),
            "0.05",
            "the fractional part is zero-padded to the exponent"
        );
        assert_eq!(
            format_money_minor(-5, 2),
            "-0.05",
            "the sign belongs to the whole figure, not just the integer part"
        );
    }

    /// `used`/`cap` in the same currency and scale draw as one line; a cap in
    /// a different currency (or a different `exponent` at the same currency —
    /// `Balance::pair_is_comparable`'s own trap) draws as two. Also the money
    /// formatter's only exercise here: minor units at exponent 2 have to come
    /// out as a two-decimal figure, not `1234`.
    #[test]
    fn a_comparable_pair_renders_as_one_line_and_an_incomparable_one_as_two() {
        let usd = |m| tickover::model::BalanceAmount::Money {
            minor: m,
            currency: "USD".into(),
            exponent: 2,
        };
        let mut b = tickover::model::Balance {
            used: Some(usd(1234)),
            cap: Some(usd(10_000)),
            ..empty_balance("Spend")
        };
        let paired =
            balance_data(NOW, &b, false).expect("used and cap alone are something to draw");
        assert_eq!(paired.amount_line, "used 12.34 USD / cap 100.00 USD");

        b.cap = Some(tickover::model::BalanceAmount::Money {
            minor: 10_000,
            currency: "EUR".into(),
            exponent: 2,
        });
        let separate =
            balance_data(NOW, &b, false).expect("used and cap alone are something to draw");
        assert_eq!(
            separate.amount_line, "used 12.34 USD\ncap 100.00 EUR",
            "a currency mismatch must not be joined into one comparison"
        );

        // The same rule on the plain-number side, which is where a manifest
        // author can trip it: a `unit_label` on one figure and none on the
        // other. This is what makes `copilot.toml` declare the unit twice —
        // asserted here rather than left as a claim about that manifest, since
        // no test on the manifest itself could tell the two cases apart.
        let n = |v: f64, u: Option<&str>| tickover::model::BalanceAmount::Number {
            value: v,
            unit: u.map(str::to_string),
        };
        let mismatched = tickover::model::Balance {
            used: Some(n(25.0, Some("interactions"))),
            cap: Some(n(300.0, None)),
            ..empty_balance("Premium")
        };
        let split = balance_data(NOW, &mismatched, false).expect("used and cap are drawable");
        assert_eq!(
            split.amount_line, "used 25 interactions\ncap 300",
            "a unit on one side only is not a comparison, so the pair comes apart"
        );
    }

    /// `remaining` draws on its own line regardless of `used`/`cap`, and
    /// `period_end` draws as a countdown-to-date ahead of now but must not
    /// print a negative one once the boundary has passed — see
    /// `balance_period_line`'s own doc for why that would be a lie about a
    /// stale reading rather than a fact about the period.
    #[test]
    fn remaining_and_a_future_period_end_render_their_own_lines_but_a_past_one_never_counts_down() {
        let ahead = tickover::model::Balance {
            remaining: Some(tickover::model::BalanceAmount::Text("$5 left".into())),
            period_end: Some(NOW + 3 * 86_400),
            ..empty_balance("Credits")
        };
        let data = balance_data(NOW, &ahead, false).expect("remaining alone is something to draw");
        assert_eq!(data.amount_line, "remaining $5 left");
        assert!(
            data.period_line.starts_with("ends in 3d"),
            "{}",
            data.period_line
        );

        let behind = tickover::model::Balance {
            period_end: Some(NOW - 86_400),
            ..ahead
        };
        let stale =
            balance_data(NOW, &behind, false).expect("remaining alone is something to draw");
        assert!(
            stale.period_line.starts_with("period ended"),
            "a period end in the past must not print a negative countdown: {}",
            stale.period_line
        );
    }

    /// The corner the render-time dedup opens: a balance whose only stated
    /// field is `limit_reached` draws nothing once the quota level has
    /// already said the account is blocked — repeating it here would be a
    /// label beside empty space, exactly what `Balance::is_stated` exists to
    /// keep off the panel at parse time. Undeduped, it is the only channel
    /// the refusal can arrive through for a provider (Claude) that sends no
    /// `[status]` section at all.
    #[test]
    fn a_balance_whose_only_field_is_a_deduped_limit_reached_draws_no_row() {
        let b = tickover::model::Balance {
            limit_reached: Some(true),
            ..empty_balance("Spend")
        };

        assert!(
            balance_data(NOW, &b, true).is_none(),
            "the quota level already said the account is blocked; repeating it here would be a label over nothing"
        );
        let undeduped = balance_data(NOW, &b, false).expect("the only channel this refusal has");
        assert_eq!(undeduped.notice, "spending limit reached");
    }

    #[test]
    fn an_account_with_every_window_empty_still_gets_its_ping() {
        // The whole chain, because each link looked right on its own while the
        // path through them was broken. A Codex body with both windows empty
        // is a legitimate reading, not an error; a legitimate reading with no
        // primary row still yields a ping target; and with a boundary
        // remembered on disk the ping is due. Break any link — refuse the body,
        // or ask the reading instead of the manifest — and the auto-ping dies
        // silently in precisely the state it was built for.
        let m = pingable_manifest();
        let both_empty = reading_with(Vec::new(), None);

        let target = ping_window(&m, Some(&both_empty))
            .expect("an account with nothing running is still an account with a window");
        assert!(ping_due(
            target.used_percent,
            target.resets_at,
            target.period_minutes,
            NOW - 60,
            0,
            NOW
        ));
    }

    /// Codex reports nothing while empty, so our own ping is what makes it
    /// report a window again — and that window arrives rounded to 0% used.
    /// Without time-based de-duplication that reads as a second empty window.
    #[test]
    fn ping_due_does_not_ping_the_window_its_own_ping_just_started() {
        let boundary = NOW - 60; // the vanished window's start
        let pinged = NOW - 55; // we pinged just after it
        let reset = boundary + 5 * 3600; // the window Codex now reports
        assert!(
            !ping_due(Some(0.0), Some(reset), FIVE_H, boundary, pinged, NOW),
            "same window, differently named"
        );
        // And when the provider anchors the new window on the request that
        // started it, rather than on the old boundary, its start lands *after*
        // the moment we recorded the ping — spawning a process and waiting on a
        // model takes seconds. Without the grace below that reads as a second
        // empty window and pings again.
        let anchored_on_arrival = pinged + 3 + 5 * 3600;
        assert!(
            !ping_due(
                Some(0.0),
                Some(anchored_on_arrival),
                FIVE_H,
                boundary,
                pinged,
                NOW
            ),
            "the window our own ping started, anchored a few seconds later"
        );
    }

    /// A ping that fails to start a window leaves the provider silent, so the
    /// vanished-window boundary would stay frozen at a value already recorded
    /// as pinged. Projecting it forward a period at a time is what turns
    /// "never again" into "retry next window".
    #[test]
    fn ping_due_retries_a_period_later_when_the_provider_stays_silent() {
        let boundary = NOW - 5 * 3600;
        let pinged = boundary + 5; // that period's ping, which achieved nothing
        assert!(
            !ping_due(None, None, None, boundary, pinged, boundary + 4 * 3600),
            "still inside the period that was pinged"
        );
        assert!(
            ping_due(None, None, None, boundary, pinged, NOW),
            "a period later the boundary has moved on, so the ping is owed again"
        );
    }

    // ── seen-window registry ──────────────────────────────────────────────

    /// A Codex-shaped manifest with both subscription windows and a per-model
    /// extra — the three-window shape `plugins/codex.toml` ships, and
    /// the one the hysteresis rules are about.
    fn two_window_manifest() -> PluginManifest {
        let toml = r#"
            id         = "codex"
            name       = "Codex"
            menu_label = "Cx"
            order      = 10
            engine     = "http-api"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode  = "from_field"
            field = "limit_window_seconds"
            unit  = "seconds"
            [windows.source]
            used_percent_path  = "used_percent"
            resets_at_path     = "reset_at"
            max_period_minutes = 720
            [[windows]]
            label = "WK"
            role  = "secondary"
            [windows.period]
            mode  = "from_field"
            field = "limit_window_seconds"
            unit  = "seconds"
            [windows.source]
            used_percent_path  = "used_percent"
            resets_at_path     = "reset_at"
            min_period_minutes = 721
            [[windows]]
            label = "GPT-5.3-Codex-Spark"
            role  = "extra"
            [windows.period]
            mode  = "from_field"
            field = "limit_window_seconds"
            unit  = "seconds"
            [windows.source]
            containers        = ["additional_rate_limits[limit_name=GPT-5.3-Codex-Spark].rate_limit.primary_window"]
            used_percent_path = "used_percent"
            resets_at_path    = "reset_at"
            [http]
            [[http.request]]
            url = "https://example.com/usage"
        "#;
        PluginManifest::from_str(toml).expect("valid two-window manifest")
    }

    /// A registry answer for one role and nothing else — the shape
    /// [`window_rows`] takes so it can be tested without a config file.
    fn seen_only(
        role: Role,
        seen: config::SeenWindow,
    ) -> impl Fn(Role) -> Option<config::SeenWindow> {
        move |asked| (asked == role).then_some(seen)
    }

    fn labels(rows: &[(String, WindowData)]) -> Vec<String> {
        rows.iter().map(|(_, w)| w.label.to_string()).collect()
    }

    /// The keys `window_rows` gave its rows, which is what the reconciler
    /// matches on — see `reconcile_window_model`.
    fn row_keys(rows: &[(String, WindowData)]) -> Vec<String> {
        rows.iter().map(|(key, _)| key.clone()).collect()
    }

    /// The feature itself: Codex stops reporting its 5-hour window while
    /// nothing has been spent in it, and the row it used to occupy stays —
    /// named as before, saying what is true about it.
    #[test]
    fn a_window_the_provider_has_gone_quiet_about_keeps_its_row() {
        let m = two_window_manifest();
        let weekly_only = reading_with(vec![win("WK", Role::Secondary, 69.0, 3600, 10_080)], None);
        let seen = config::SeenWindow {
            at: NOW - 600,
            period_minutes: Some(300),
        };

        let rows = window_rows(Some(&m), &weekly_only, NOW, &seen_only(Role::Primary, seen));

        assert_eq!(
            labels(&rows),
            vec!["5-hour limit", "Weekly limit"],
            "and in role order"
        );
        // The quiet row carries the same identity the window itself would, so
        // a window going silent and coming back is one row throughout rather
        // than a model rebuilt — and so two quiet rows are told apart. This
        // manifest declares no ids, so the entries fall back to their position.
        assert_eq!(row_keys(&rows), vec!["w0:", "w1:"]);
        let five_h = &rows[0].1;
        assert!(
            five_h.not_started,
            "the row says the window has not started"
        );
        assert_eq!(five_h.pct, 0.0);
        assert_eq!(
            five_h.reset_rel, "",
            "no countdown to a reset nobody stated"
        );
        assert_eq!(five_h.reset_at, "");
        assert!(
            !rows[1].1.not_started,
            "the window that did arrive is untouched"
        );
    }

    /// The row is bounded by two of the window's own periods, and the bound is
    /// in *seconds* — a missing minutes-to-seconds conversion would cut ten
    /// hours to ten minutes and fail the middle assertion.
    #[test]
    fn a_remembered_window_stops_being_drawn_after_two_of_its_own_periods() {
        let m = two_window_manifest();
        let nothing = reading_with(Vec::new(), None);
        let five_h = 300 * 60;
        let rows_at = |elapsed: u64| {
            let seen = config::SeenWindow {
                at: NOW - elapsed,
                period_minutes: Some(300),
            };
            window_rows(Some(&m), &nothing, NOW, &seen_only(Role::Primary, seen))
        };

        assert_eq!(
            labels(&rows_at(0)),
            vec!["5-hour limit"],
            "the moment it went quiet"
        );
        assert_eq!(
            labels(&rows_at(2 * five_h - 1)),
            vec!["5-hour limit"],
            "just inside the TTL"
        );
        assert!(
            rows_at(2 * five_h).is_empty(),
            "two periods on, this is a limit the plan may no longer have"
        );
        assert!(rows_at(30 * five_h).is_empty());
    }

    /// Two periods scales with the window; the confidence behind it does not.
    /// Without the ceiling an account that loses its weekly allowance is told
    /// "Weekly limit — not started" for a fortnight — but the ceiling must not
    /// cut inside the window the provider itself described, where an empty
    /// window explains the silence completely.
    #[test]
    fn a_long_windows_slack_is_capped_but_never_the_window_itself() {
        let week = 10_080 * 60;
        let m = two_window_manifest();
        let nothing = reading_with(Vec::new(), None);
        let rows_at = |elapsed: u64| {
            let seen = config::SeenWindow {
                at: NOW - elapsed,
                period_minutes: Some(10_080),
            };
            window_rows(Some(&m), &nothing, NOW, &seen_only(Role::Secondary, seen))
        };

        assert_eq!(labels(&rows_at(0)), vec!["Weekly limit"]);
        assert_eq!(
            labels(&rows_at(week - 1)),
            vec!["Weekly limit"],
            "the whole window it is talking about, which has provably not ended"
        );
        assert!(
            rows_at(week).is_empty(),
            "and no slack on top of it, because three days is less"
        );
        assert_eq!(
            seen_window_ttl_secs(10_080),
            week,
            "one week, not two, and not three days"
        );
        assert_eq!(
            seen_window_ttl_secs(300),
            2 * 300 * 60,
            "the five-hour window — what the feature was written for — keeps both periods"
        );
        assert_eq!(
            seen_window_ttl_secs(36 * 60),
            2 * 36 * 3600,
            "the cap cannot bite below 36 hours"
        );
    }

    /// "Not started" is a claim about the window *after* the one we saw. While
    /// the window we saw is still running, the provider going quiet says
    /// nothing about it — and it may well have had usage in it.
    #[test]
    fn a_window_that_has_not_ended_yet_gets_no_not_started_row() {
        let m = two_window_manifest();
        let nothing = reading_with(Vec::new(), None);
        let seen = config::SeenWindow {
            at: NOW + 600,
            period_minutes: Some(300),
        };
        assert!(window_rows(Some(&m), &nothing, NOW, &seen_only(Role::Primary, seen)).is_empty());
    }

    /// A reading we could not take is not evidence that a window is empty. The
    /// panel draws the error message instead of rows for such a reading, so
    /// this is unreachable from there today — it is asserted because the same
    /// rule is written into `seen_records`, and a rule kept in only one of two
    /// halves is exactly the kind of latent hole this test exists to close.
    #[test]
    fn an_errored_reading_gets_no_not_started_row_either() {
        let m = two_window_manifest();
        let broken = reading_with(Vec::new(), Some("session expired"));
        let seen = config::SeenWindow {
            at: NOW - 600,
            period_minutes: Some(300),
        };
        assert!(window_rows(Some(&m), &broken, NOW, &seen_only(Role::Primary, seen)).is_empty());
    }

    /// A window nobody ever saw is not a window we can say anything about —
    /// which is also the state of a fresh install, where the panel must look
    /// exactly as it did before this feature existed.
    #[test]
    fn a_window_never_seen_gets_no_row() {
        let m = two_window_manifest();
        let nothing = reading_with(Vec::new(), None);
        assert!(window_rows(Some(&m), &nothing, NOW, &|_| None).is_empty());
    }

    /// Graceful degradation on the first launch after an upgrade: the
    /// pre-registry key carries a boundary but no length, and a row with no
    /// length has no TTL. Rather than invent one, there is no row until the
    /// provider states the window once — which is what it does the moment
    /// anything is spent, so this heals itself.
    #[test]
    fn a_remembered_window_with_no_remembered_length_gets_no_row() {
        let m = two_window_manifest();
        let nothing = reading_with(Vec::new(), None);
        let no_length = config::SeenWindow {
            at: NOW - 600,
            period_minutes: None,
        };
        assert!(window_rows(
            Some(&m),
            &nothing,
            NOW,
            &seen_only(Role::Primary, no_length)
        )
        .is_empty());
        let zero_length = config::SeenWindow {
            at: NOW - 600,
            period_minutes: Some(0),
        };
        assert!(window_rows(
            Some(&m),
            &nothing,
            NOW,
            &seen_only(Role::Primary, zero_length)
        )
        .is_empty());
    }

    /// A window the provider *is* reporting is drawn from what it reported.
    /// The registry must never add a second row for the same role — one window
    /// twice, once with a number and once claiming it has not started.
    #[test]
    fn a_live_window_is_never_doubled_by_the_registry() {
        let m = two_window_manifest();
        let live = reading_with(vec![win("5H", Role::Primary, 12.0, 600, 300)], None);
        let seen = config::SeenWindow {
            at: NOW - 600,
            period_minutes: Some(300),
        };

        let rows = window_rows(Some(&m), &live, NOW, &seen_only(Role::Primary, seen));
        assert_eq!(labels(&rows), vec!["5-hour limit"]);
        assert!(!rows[0].1.not_started);
        assert_eq!(rows[0].1.pct, 12.0);
    }

    /// "Not started" is a claim about *usage*, so only a window the provider
    /// did not report at all may carry it. A window reported without a usable
    /// percentage draws no row (it has no figure to draw) — but it must not
    /// therefore be called empty, which would state as fact the very thing the
    /// response failed to say. Unreachable today, because both engines only
    /// build a window once a percentage resolves; reachable the moment a
    /// reading may be partly populated, whenever that becomes possible.
    #[test]
    fn a_window_reported_without_a_figure_is_still_reported() {
        let m = two_window_manifest();
        let figureless = reading_with(
            vec![Window {
                key: String::new(),
                label: "5H".into(),
                role: Role::Primary,
                used_percent: None,
                resets_at: Some(NOW + 600),
                period_minutes: Some(300),
            }],
            None,
        );
        let seen = config::SeenWindow {
            at: NOW - 600,
            period_minutes: Some(300),
        };

        let rows = window_rows(Some(&m), &figureless, NOW, &seen_only(Role::Primary, seen));
        assert!(
            rows.is_empty(),
            "no row to draw, and no claim that the window is empty: {:?}",
            labels(&rows)
        );
    }

    /// An extra quota is never remembered (`seen_role_key`), and this proves
    /// the row builder agrees even when handed a registry that answers for
    /// every role: `plugins/codex.toml` promises that a model Codex
    /// withdraws simply stops being a row.
    #[test]
    fn an_extra_quota_never_gets_a_not_started_row() {
        let m = two_window_manifest();
        let nothing = reading_with(Vec::new(), None);
        // Answers for *every* role, the per-model one included, and with its
        // own length each so a row filed under the wrong role is visible in
        // the caption rather than hidden behind an identical one.
        let seen = |role: Role| {
            Some(config::SeenWindow {
                at: NOW - 600,
                period_minutes: Some(match role {
                    Role::Primary => 300,
                    Role::Secondary => 10_080,
                    Role::Extra => 1_440,
                }),
            })
        };

        let rows = window_rows(Some(&m), &nothing, NOW, &seen);
        assert_eq!(
            labels(&rows),
            vec!["5-hour limit", "Weekly limit"],
            "both subscription windows, and nothing for the per-model one"
        );
        assert!(
            seen_role_key(Role::Extra).is_none(),
            "and the registry has no name to file it under"
        );
    }

    /// Two windows going quiet at once — Codex in the hours after a weekly
    /// reset. Each remembered row must land in its own place: inserting both at
    /// the position the *reading* implies puts them at the same index.
    #[test]
    fn two_remembered_windows_keep_their_order_around_a_live_one() {
        let m = two_window_manifest();
        let extra_only = reading_with(
            vec![Window {
                key: String::new(),
                label: "GPT-5.3-Codex-Spark".into(),
                role: Role::Extra,
                used_percent: Some(4.0),
                resets_at: Some(NOW + 600),
                period_minutes: Some(300),
            }],
            None,
        );
        let seen = |role: Role| match role {
            Role::Primary => Some(config::SeenWindow {
                at: NOW - 600,
                period_minutes: Some(300),
            }),
            Role::Secondary => Some(config::SeenWindow {
                at: NOW - 600,
                period_minutes: Some(10_080),
            }),
            Role::Extra => None,
        };

        let rows = window_rows(Some(&m), &extra_only, NOW, &seen);
        assert_eq!(
            labels(&rows),
            vec!["5-hour limit", "Weekly limit", "GPT-5.3-Codex-Spark"],
            "primary, secondary, then what is neither"
        );
        assert_eq!(
            rows.iter().map(|(_, w)| w.not_started).collect::<Vec<_>>(),
            vec![true, true, false]
        );
    }

    /// A reading whose manifest is not in the set gets what it always got: its
    /// own rows and nothing invented beside them.
    #[test]
    fn a_reading_with_no_manifest_still_draws_the_windows_it_carries() {
        let live = reading_with(vec![win("WK", Role::Secondary, 69.0, 3600, 10_080)], None);
        let seen = config::SeenWindow {
            at: NOW - 600,
            period_minutes: Some(300),
        };
        let rows = window_rows(None, &live, NOW, &seen_only(Role::Primary, seen));
        assert_eq!(labels(&rows), vec!["Weekly limit"]);
    }

    /// **One registry, two readers.** The panel's row and the auto-ping's
    /// target are both worked out from the same remembered entry, so they can
    /// never disagree about whether the window was ever seen. They *do* reach
    /// different conclusions once it is stale — see `SEEN_WINDOW_TTL_PERIODS`
    /// for why that is the point rather than a leak.
    #[test]
    fn the_panel_row_and_the_ping_target_come_from_the_same_remembered_window() {
        let m = two_window_manifest();
        let empty = reading_with(Vec::new(), None);
        let seen = config::SeenWindow {
            at: NOW - 600,
            period_minutes: Some(300),
        };

        let rows = window_rows(Some(&m), &empty, NOW, &seen_only(Role::Primary, seen));
        assert!(
            rows.iter()
                .any(|(_, w)| w.label == "5-hour limit" && w.not_started),
            "the panel draws it"
        );

        let target = ping_window(&pingable_manifest(), Some(&empty)).expect("a window to ping for");
        assert!(
            ping_due(
                target.used_percent,
                target.resets_at,
                target.period_minutes,
                seen.at,
                0,
                NOW
            ),
            "and the ping owes it a request — from the same `at`"
        );
    }

    /// The loop that fills the registry, which the pure rules below cannot see.
    #[test]
    fn seen_records_takes_every_subscription_window_of_every_reading() {
        let plugins = vec![two_window_manifest(), claude_like_two_surface_manifest()];
        let readings = vec![
            reading_with(
                vec![
                    win("5H", Role::Primary, 3.0, 600, 300),
                    win("WK", Role::Secondary, 69.0, 3600, 10_080),
                    Window {
                        key: String::new(),
                        label: "GPT-5.3-Codex-Spark".into(),
                        role: Role::Extra,
                        used_percent: Some(4.0),
                        resets_at: Some(NOW + 600),
                        period_minutes: Some(300),
                    },
                ],
                None,
            ),
            claude_surface_reading("desktop"),
        ];

        let out = seen_records(&plugins, &readings);
        assert_eq!(
            out.iter().map(|r| (r.manifest.id.as_str(), r.reading_id.as_str(), r.role)).collect::<Vec<_>>(),
            vec![
                ("codex", "codex", Role::Primary),
                ("codex", "codex", Role::Secondary),
                ("claude", "claude-desktop", Role::Primary),
            ],
            "both subscription windows, never the extra, and a second surface under its own reading id"
        );
        assert_eq!(
            out[0].seen,
            config::SeenWindow {
                at: NOW + 600,
                period_minutes: Some(300)
            },
            "the length is remembered beside the boundary — the response it came in stops arriving"
        );
    }

    /// The write loop, which the pure rules above cannot see: an unchanged
    /// reading must cost no write, or the tick rewrites `config.json` once a
    /// second forever.
    #[test]
    fn a_window_the_registry_already_knows_is_not_written_again() {
        let plugins = vec![two_window_manifest()];
        let readings = vec![reading_with(
            vec![win("5H", Role::Primary, 3.0, 600, 300)],
            None,
        )];
        let stated = config::SeenWindow {
            at: NOW + 600,
            period_minutes: Some(300),
        };

        let knows_nothing = seen_writes(seen_records(&plugins, &readings), |_, _, _| None);
        assert_eq!(
            knows_nothing.iter().map(|w| w.seen).collect::<Vec<_>>(),
            vec![stated],
            "a boundary nothing has recorded yet is written"
        );

        let knows_it = seen_writes(seen_records(&plugins, &readings), |_, _, _| Some(stated));
        assert!(knows_it.is_empty(), "and the same one again is not");

        let knows_it_without_a_length =
            seen_writes(seen_records(&plugins, &readings), |_, _, _| {
                Some(config::SeenWindow {
                    at: stated.at,
                    period_minutes: None,
                })
            });
        assert_eq!(
            knows_it_without_a_length
                .iter()
                .map(|w| w.seen)
                .collect::<Vec<_>>(),
            vec![stated],
            "but a length it was missing is worth the one write"
        );
    }

    /// Nothing caps how many `secondary` windows a manifest may declare (only
    /// `primary` is capped at one), so a reading can carry two windows of one
    /// role. Each record is compared against what is on disk, which the earlier
    /// records of the same tick have not reached — so without folding them, the
    /// *last* would win rather than the newest, and an older boundary could
    /// overwrite a newer one inside a single tick.
    #[test]
    fn two_windows_of_one_role_produce_one_write_and_the_newest_boundary_wins() {
        let plugins = vec![two_window_manifest()];
        let newer = win("WK", Role::Secondary, 69.0, 7200, 10_080);
        let older = win("WK", Role::Secondary, 12.0, 600, 10_080);
        let reading = |windows: Vec<Window>| vec![reading_with(windows, None)];

        let out = seen_writes(
            seen_records(&plugins, &reading(vec![newer.clone(), older.clone()])),
            |_, _, _| None,
        );
        assert_eq!(
            out.iter().map(|w| w.seen.at).collect::<Vec<_>>(),
            vec![NOW + 7200],
            "one write, and the newer boundary survives the older one that followed it"
        );

        let out = seen_writes(
            seen_records(&plugins, &reading(vec![older, newer])),
            |_, _, _| None,
        );
        assert_eq!(
            out.iter().map(|w| w.seen.at).collect::<Vec<_>>(),
            vec![NOW + 7200],
            "and the same however they are ordered"
        );
    }

    /// A provider we could not read has told us nothing about its quota, so it
    /// must move no boundary. Today an errored reading carries no windows at
    /// all; if that ever changes, this is the check that keeps the loop
    /// honest when it does.
    #[test]
    fn seen_records_ignores_a_reading_that_carries_an_error() {
        let plugins = vec![two_window_manifest()];
        let broken = ProviderReading {
            windows: vec![win("5H", Role::Primary, 3.0, 600, 300)],
            balances: Vec::new(),
            error: Some("session expired".into()),
            ..reading_with(Vec::new(), None)
        };
        assert!(seen_records(&plugins, std::slice::from_ref(&broken)).is_empty());
    }

    /// A window without a stated reset is not a boundary — there is nothing to
    /// remember about it.
    #[test]
    fn seen_records_skips_a_window_with_no_reset_time() {
        let plugins = vec![two_window_manifest()];
        let r = reading_with(vec![empty_window("5H", Role::Primary)], None);
        assert!(seen_records(&plugins, std::slice::from_ref(&r)).is_empty());
    }

    /// When the reading states no length, the manifest's own fixed one is the
    /// fallback — and for a manifest that reads its length out of the response
    /// there is nothing to fall back to, which is why the length is remembered
    /// at all.
    #[test]
    fn seen_records_falls_back_to_a_length_the_manifest_fixes() {
        let assumed = stub_manifest("codex", 10); // period.mode = "assumed", 300
        let from_field = two_window_manifest(); // period.mode = "from_field"
        let no_length = reading_with(
            vec![Window {
                key: String::new(),
                label: "5H".into(),
                role: Role::Primary,
                used_percent: Some(3.0),
                resets_at: Some(NOW + 600),
                period_minutes: None,
            }],
            None,
        );

        let assumed = [assumed];
        let from_field = [from_field];
        let out = seen_records(&assumed, std::slice::from_ref(&no_length));
        assert_eq!(
            out[0].seen.period_minutes,
            Some(300),
            "the manifest fixes this window's length"
        );

        let out = seen_records(&from_field, std::slice::from_ref(&no_length));
        assert_eq!(
            out[0].seen.period_minutes, None,
            "and this one has none to give"
        );
    }

    /// Forwards only, or a stale reading would move the boundary back onto a
    /// window the auto-ping has already dealt with and it would be pinged
    /// twice.
    #[test]
    fn seen_merge_moves_the_boundary_forward_and_never_back() {
        let stored = config::SeenWindow {
            at: NOW,
            period_minutes: Some(300),
        };
        let newer = config::SeenWindow {
            at: NOW + 1,
            ..stored
        };
        assert_eq!(
            seen_merge(None, stored),
            Some(stored),
            "nothing remembered yet"
        );
        assert_eq!(seen_merge(Some(stored), newer), Some(newer));
        assert_eq!(
            seen_merge(
                Some(stored),
                config::SeenWindow {
                    at: NOW - 1,
                    ..stored
                }
            ),
            None,
            "a stale reading"
        );
        assert_eq!(
            seen_merge(Some(stored), stored),
            None,
            "the same window again costs no write"
        );
    }

    /// A response that carries the reset but not the length is not evidence
    /// that the window has no length. Letting it clear the stored one would
    /// switch the panel's hysteresis off — it needs a length for its TTL —
    /// for as long as the provider kept omitting it, which for the provider
    /// this exists for is *while the window is empty*: exactly when the row is
    /// wanted.
    #[test]
    fn seen_merge_never_unlearns_a_window_length() {
        let stored = config::SeenWindow {
            at: NOW,
            period_minutes: Some(300),
        };

        assert_eq!(
            seen_merge(
                Some(stored),
                config::SeenWindow {
                    at: NOW + 5 * 3600,
                    period_minutes: None
                }
            ),
            Some(config::SeenWindow {
                at: NOW + 5 * 3600,
                period_minutes: Some(300)
            }),
            "a newer window inherits the length rather than dropping it"
        );
        assert_eq!(
            seen_merge(
                Some(stored),
                config::SeenWindow {
                    at: NOW,
                    period_minutes: None
                }
            ),
            None,
            "and the same window with nothing new costs no write"
        );
        assert_eq!(
            seen_merge(
                Some(config::SeenWindow {
                    at: NOW,
                    period_minutes: None
                }),
                config::SeenWindow {
                    at: NOW,
                    period_minutes: Some(300)
                }
            ),
            Some(stored),
            "but a length arriving for the window already remembered is worth the write"
        );
        assert_eq!(
            seen_merge(
                Some(stored),
                config::SeenWindow {
                    at: NOW + 1,
                    period_minutes: Some(600)
                }
            ),
            Some(config::SeenWindow {
                at: NOW + 1,
                period_minutes: Some(600)
            }),
            "a length the provider actually states still replaces the old one"
        );
    }

    /// The pre-registry key, which is all an install upgrading into the
    /// registry has. Without it the first launch after an update forgets the
    /// boundary of a window that has already vanished — and a provider
    /// reporting nothing never reminds us of it again.
    #[test]
    fn the_pre_registry_key_answers_for_the_one_window_it_was_about() {
        let legacy = 1_700_000_000;
        assert_eq!(
            seen_window_from(None, || legacy, || true),
            Some(config::SeenWindow {
                at: legacy,
                period_minutes: None
            }),
            "read, with no length invented for it"
        );
        assert_eq!(
            seen_window_from(None, || legacy, || false),
            None,
            "and only for that window"
        );
        assert_eq!(
            seen_window_from(None, || 0, || true),
            None,
            "an install that never had one"
        );

        let entry = config::SeenWindow {
            at: legacy + 5 * 3600,
            period_minutes: Some(300),
        };
        assert_eq!(
            seen_window_from(Some(entry), || legacy, || true),
            Some(entry),
            "once the registry has an entry, the old key is not consulted again"
        );
    }

    // ── window model reconciliation ───────────────────────────────────────

    /// The reconciler updates rows in place when their count is unchanged, and
    /// hysteresis makes that the *normal* path — the row count stops changing
    /// as a window empties, so a window flipping between reported and not is
    /// now a row rewritten rather than a model replaced. Every field has to be
    /// rewritten with it, or the row keeps the caption, bar and countdown of
    /// the window it no longer is.
    #[test]
    fn reconcile_rewrites_every_field_of_a_row_that_flips_to_not_started() {
        let mut models: HashMap<String, WindowModel> = HashMap::new();
        let m = two_window_manifest();
        let seen = config::SeenWindow {
            at: NOW - 600,
            period_minutes: Some(300),
        };

        let live = reading_with(vec![win("5H", Role::Primary, 42.0, 600, 300)], None);
        let before = window_rows(Some(&m), &live, NOW, &|_| None);
        let model = reconcile_window_model(&mut models, "codex", before);
        let was = model.row_data(0).expect("one row");
        assert!(!was.not_started);
        assert_ne!(was.reset_rel, "");

        let gone = reading_with(Vec::new(), None);
        let after = window_rows(Some(&m), &gone, NOW, &seen_only(Role::Primary, seen));
        let model = reconcile_window_model(&mut models, "codex", after);
        assert_eq!(
            model.row_count(),
            1,
            "same count: the in-place path is the one under test"
        );

        let now_row = model.row_data(0).expect("still one row");
        assert!(now_row.not_started, "the flag");
        assert_eq!(now_row.pct, 0.0, "the bar's figure");
        assert_eq!(now_row.reset_rel, "", "the countdown");
        assert_eq!(now_row.reset_at, "", "the clock");
        assert_eq!(
            now_row.tooltip, "",
            "and the tooltip that described the old window"
        );
        assert_eq!(now_row.label, "5-hour limit", "named the same either way");
    }

    /// The reason the reconciler matches on identity rather than on how many
    /// rows there are.
    ///
    /// Equal counts is not the same question. The set of rows is variable, so
    /// one window can appear in the same tick another vanishes — the count is
    /// unchanged, every later index shifts by one, and each row is then
    /// overwritten in place with a different window's figures under the caption
    /// it already had. A deterministic sort does not help: it makes the order
    /// predictable, not the indices stable.
    ///
    /// Built from rows directly rather than through a manifest, because the
    /// point is what the reconciler does with two row *lists* — the identities
    /// have to differ while the count does not, which is exactly the shape a
    /// manifest with hysteresis would produce as one model quota replaces
    /// another.
    #[test]
    fn reconcile_rebuilds_when_the_row_identities_change_under_an_unchanged_count() {
        let mut models: HashMap<String, WindowModel> = HashMap::new();
        let row = |key: &str, label: &str, pct: f32| {
            (
                key.to_string(),
                WindowData {
                    label: ss(label),
                    pct,
                    not_started: false,
                    reset_rel: ss(""),
                    reset_at: ss(""),
                    tooltip: ss(""),
                },
            )
        };

        let first = reconcile_window_model(&mut models, "codex", vec![row("a:", "Alpha", 10.0)]);
        assert_eq!(first.row_data(0).expect("a row").label, "Alpha");

        // Same count, different window. Reused in place, "Alpha" would keep its
        // caption over Beta's number.
        let second = reconcile_window_model(&mut models, "codex", vec![row("b:", "Beta", 90.0)]);
        let drawn = second.row_data(0).expect("a row");
        assert_eq!(
            drawn.label, "Beta",
            "the caption belongs to the window whose figure is shown"
        );
        assert_eq!(drawn.pct, 90.0);

        // And the in-place path is still taken when the identities *do* match,
        // which is what keeps the bar's animation and tooltip alive across the
        // one-second tick. Compared by the `Rc` the map holds, since that
        // identity is precisely what the Slint repeater keys off.
        let kept = Rc::as_ptr(&models.get("codex").expect("stored").model);
        let same_again =
            reconcile_window_model(&mut models, "codex", vec![row("b:", "Beta", 91.0)]);
        assert_eq!(
            kept,
            Rc::as_ptr(&models.get("codex").expect("stored").model),
            "an unchanged identity has to reuse the model, or every tick re-creates the rows"
        );
        assert_eq!(
            same_again.row_data(0).expect("a row").pct,
            91.0,
            "and still updates it"
        );
    }

    // ── balance model reconciliation ────────────────────────────────────────

    /// [`reconcile_balance_model`]'s own version of the check above: a row is
    /// reused in place — surviving as the same `Rc` the Slint repeater keys
    /// off — only when the key *sequence* is unchanged, and rebuilt the
    /// moment it isn't, even though the row count stays the same. A balance
    /// row carries no percentage bar to animate, but it is exactly as liable
    /// to have one window's identity overwritten in place with another
    /// window's figures under its old caption if the reconciler only counted.
    #[test]
    fn reconcile_balance_model_reuses_rows_by_key_and_rebuilds_when_they_change() {
        let mut models: HashMap<String, BalanceModel> = HashMap::new();
        let row = |key: &str, label: &str, amount: &str| {
            (
                key.to_string(),
                BalanceData {
                    label: ss(label),
                    amount_line: ss(amount),
                    percent_line: ss(""),
                    period_line: ss(""),
                    notice: ss(""),
                },
            )
        };

        let first =
            reconcile_balance_model(&mut models, "grok", vec![row("a:", "Spend", "used 1 USD")]);
        assert_eq!(first.row_data(0).expect("a row").label, "Spend");

        // Same count, a different balance under it: reused in place, "Spend"
        // would keep its caption over Credits' figure.
        let second = reconcile_balance_model(
            &mut models,
            "grok",
            vec![row("b:", "Credits", "used 2 USD")],
        );
        let drawn = second.row_data(0).expect("a row");
        assert_eq!(
            drawn.label, "Credits",
            "the caption belongs to the balance whose figure is shown"
        );
        assert_eq!(drawn.amount_line, "used 2 USD");

        // And the in-place path is taken when the key *is* unchanged, which is
        // what keeps the row from being torn down and rebuilt every tick.
        let kept = Rc::as_ptr(&models.get("grok").expect("stored").model);
        let same_again = reconcile_balance_model(
            &mut models,
            "grok",
            vec![row("b:", "Credits", "used 3 USD")],
        );
        assert_eq!(
            kept,
            Rc::as_ptr(&models.get("grok").expect("stored").model),
            "an unchanged key has to reuse the model, or every tick re-creates the row"
        );
        assert_eq!(
            same_again.row_data(0).expect("a row").amount_line,
            "used 3 USD",
            "and still updates it"
        );
    }

    // ── hung fetch ────────────────────────────────────────────────────────

    /// A fetch that hangs used to mark its plugin in-flight for the life of
    /// the process: no panic, no error, just a row that stopped changing and
    /// was never polled again. Patience runs out instead.
    #[test]
    fn admit_fetch_waits_on_a_live_fetch_and_replaces_a_hung_one() {
        let patience = Duration::from_secs(600);
        assert_eq!(
            admit_fetch(None, patience),
            Admission::Start,
            "nothing in flight"
        );
        assert_eq!(
            admit_fetch(Some(Duration::from_secs(3)), patience),
            Admission::Wait,
            "a fetch that is simply still working must not be doubled"
        );
        assert_eq!(
            admit_fetch(Some(patience), patience),
            Admission::Replace,
            "at the limit, stop waiting"
        );
        assert_eq!(
            admit_fetch(Some(Duration::from_secs(4 * 3600)), patience),
            Admission::Replace,
            "and long past it"
        );
    }

    /// The abandoned fetch may still come back. Its result must not clear the
    /// in-flight mark of the fetch that replaced it — that would leave the
    /// live one unaccounted for — nor overwrite a newer reading with an older.
    #[test]
    fn result_is_current_only_for_the_fetch_being_waited_on() {
        let in_flight = InFlight {
            generation: 7,
            started: Instant::now(),
        };
        assert!(
            result_is_current(Some(in_flight), 7),
            "the one we are waiting on"
        );
        assert!(
            !result_is_current(Some(in_flight), 6),
            "the abandoned one, back late"
        );
        assert!(
            !result_is_current(None, 7),
            "nothing in flight: the plugin was removed or reset while this ran"
        );
    }

    /// A real child process for the `run_with_deadline` cases below. `sh` is
    /// present on every platform this test module runs on (the tests are
    /// `cfg(unix)`, since a Windows shell would need a different script).
    #[cfg(unix)]
    fn sh(script: &str) -> std::process::Child {
        std::process::Command::new("/bin/sh")
            .args(["-c", script])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("/bin/sh")
    }

    #[cfg(unix)]
    #[test]
    fn run_with_deadline_reports_a_command_that_ends_on_its_own() {
        let (outcome, raw) =
            run_with_deadline(sh("echo trouble >&2; exit 3"), Duration::from_secs(30));
        match outcome {
            RunOutcome::Exited(status) => assert_eq!(status.code(), Some(3)),
            other => panic!("expected a plain exit, got {other:?}"),
        }
        assert_eq!(
            quotable(&raw),
            "trouble",
            "its own stderr is what gets quoted"
        );
    }

    /// The whole point of the deadline: a command that would otherwise hold a
    /// thread and a process for as long as this app lives is killed, and the
    /// kill is what gets reported.
    #[cfg(unix)]
    #[test]
    fn run_with_deadline_kills_a_command_that_outlives_it() {
        let started = Instant::now();
        let (outcome, _) = run_with_deadline(sh("sleep 30"), Duration::from_millis(300));
        assert!(matches!(outcome, RunOutcome::Killed), "got {outcome:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "returned promptly, not after the sleep"
        );
    }

    /// A command that writes more than we keep must still run to completion:
    /// closing the pipe early would kill it, turning "warned a lot" into a
    /// failed ping. And what survives is the **tail** — a CLI that fails says
    /// why last.
    #[cfg(unix)]
    #[test]
    fn run_with_deadline_keeps_the_tail_of_a_chatty_command_without_killing_it() {
        let script = format!(
            "i=0; while [ $i -lt {} ]; do echo 0123456789012345678901234567890123456789 >&2; i=$((i+1)); done; echo THE-LAST-WORD >&2",
            PING_STDERR_MAX / 10
        );
        let (outcome, raw) = run_with_deadline(sh(&script), Duration::from_secs(30));
        match outcome {
            RunOutcome::Exited(status) => {
                assert!(status.success(), "finished on its own, not killed by us")
            }
            other => panic!("expected a clean exit, got {other:?}"),
        }
        assert!(raw.len() <= PING_STDERR_MAX, "bounded to what we keep");
        assert!(
            quotable(&raw).ends_with("THE-LAST-WORD"),
            "the tail survives, not the head"
        );
    }

    /// The quoted stderr of a failed ping is cut by characters, because a
    /// lossy decode is *longer* than the bytes it read — one invalid byte
    /// becomes a three-byte `U+FFFD` — so a byte-indexed cut can land inside a
    /// character and panic. In the thread whose only job is reporting a
    /// failure, that would swallow the very report.
    #[test]
    fn quotable_cuts_by_characters_and_never_panics() {
        // Every byte invalid: 2000 of them decode to 2000 replacement chars,
        // 6000 bytes, with a byte-index cut landing mid-character.
        let invalid = vec![0xffu8; PING_STDERR_MAX + 500];
        let quoted = quotable(&invalid);
        assert_eq!(
            quoted.chars().count(),
            PING_STDERR_MAX,
            "cut at the character limit"
        );
        assert!(
            quoted.len() > PING_STDERR_MAX,
            "and those characters are multi-byte"
        );

        assert_eq!(quotable(b"  spaced  "), "spaced", "trimmed");
        assert_eq!(quotable(b""), "", "nothing to quote");
        assert_eq!(
            quotable("многобайтные символы".as_bytes()),
            "многобайтные символы"
        );
    }

    /// A ping that finds its CLI must also be able to *start* it: several of
    /// these CLIs are wrapper scripts whose shebang needs an interpreter from
    /// the same install dirs (`~/.npm-global/bin/codex` is `codex.js`, needing
    /// `node`). Under launchd's minimal PATH that run failed silently. The
    /// install dirs go **last**, so they add places to look without letting a
    /// user-writable directory shadow the system tools the CLI shells out to.
    #[test]
    fn cli_path_env_appends_the_install_dirs_after_the_inherited_path() {
        let joined = cli_path_env().expect("no install dir contains a path separator");
        let path: Vec<std::path::PathBuf> = std::env::split_paths(&joined).collect();
        let dirs = cli_dirs();
        assert_eq!(
            path[path.len() - dirs.len()..],
            dirs[..],
            "install dirs come last, in order"
        );
        assert!(
            path.len() > dirs.len(),
            "the inherited PATH is appended to, never replaced"
        );
    }

    /// The auto-ping gate (fix 2): both the plugin's master enable and its
    /// ping toggle must be on — checked when arming and re-checked inside the
    /// 5s single-shot, so a plugin disabled (or its ping cleared) during the
    /// delay is never actually pinged.
    #[test]
    fn plugin_ping_armed_requires_both_enable_and_ping_toggle() {
        assert!(plugin_ping_armed(true, true), "enabled + ping on: arm");
        assert!(
            !plugin_ping_armed(false, true),
            "a disabled plugin never pings"
        );
        assert!(
            !plugin_ping_armed(true, false),
            "ping toggle off never pings"
        );
        assert!(!plugin_ping_armed(false, false), "neither: never pings");
    }

    // ── plugin id dedup (fix 9) ────────────────────────────────────────────

    #[test]
    fn dedup_plugin_ids_keeps_only_the_first_manifest_with_a_duplicate_id() {
        let manifests = vec![stub_manifest("codex", 10), stub_manifest("codex", 20)];
        let out = dedup_plugin_ids(manifests);
        assert_eq!(
            out.len(),
            1,
            "a duplicate id must not double up the plugin's cache slot"
        );
        assert_eq!(
            out[0].order, 10,
            "the first manifest with this id (by order,id) wins"
        );
    }

    #[test]
    fn dedup_plugin_ids_keeps_every_manifest_when_ids_are_distinct() {
        let manifests = vec![stub_manifest("alpha", 10), stub_manifest("beta", 20)];
        let out = dedup_plugin_ids(manifests);
        assert_eq!(
            out.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            vec!["alpha", "beta"]
        );
    }

    // ── load_plugins_from: pure read, never reseeds ─────────────────────────

    #[test]
    fn load_plugins_from_reads_an_empty_dir_as_empty_never_reseeding_it() {
        // A directory that exists but holds no `*.toml` at all — e.g. every
        // plugin manifest was just removed. `load_plugins_from` must never
        // call `seed::seed_if_empty` (that's `main`'s and `reset-plugins`'
        // job, not a reload's) — otherwise reopening Settings after deleting
        // the last plugin would silently resurrect codex/claude.
        let dir = temp_plugins_dir("empty-no-reseed");
        let found = load_plugins_from(&dir);
        std::fs::remove_dir_all(&dir).ok();

        assert!(
            found.is_empty(),
            "an empty plugins dir must stay empty on a plain reload"
        );
    }

    #[test]
    fn load_plugins_from_reads_and_sorts_whatever_manifests_are_actually_present() {
        let dir = temp_plugins_dir("reads-present");
        std::fs::write(dir.join("b.toml"), stub_manifest_toml("bbb", 20)).expect("write fixture");
        std::fs::write(dir.join("a.toml"), stub_manifest_toml("aaa", 10)).expect("write fixture");

        let found = load_plugins_from(&dir);
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(
            found.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
            vec!["aaa", "bbb"]
        );
    }

    // ── plugin manager actions: native-dialog output parsing ───────────────

    #[test]
    fn confirm_parse_only_true_for_the_remove_button_text() {
        assert!(
            confirm_parse("button returned:Remove\n"),
            "the osascript success text confirms"
        );
        assert!(
            confirm_parse("button returned:Remove"),
            "trailing newline is optional"
        );
        assert!(
            confirm_parse("button returned:Remove, gave up:false"),
            "must tolerate other fields in the AppleEvent record, not just this exact single-field form"
        );
        assert!(
            !confirm_parse("button returned:Cancel"),
            "the Cancel button must never confirm"
        );
        assert!(
            !confirm_parse(""),
            "empty output (unexpected format) must never confirm"
        );
        assert!(
            !confirm_parse("garbage"),
            "an unrecognized format must never confirm"
        );
    }

    #[test]
    fn parse_choose_file_output_trims_and_rejects_empty() {
        assert_eq!(
            parse_choose_file_output("/Users/x/plugin.toml\n"),
            Some(std::path::PathBuf::from("/Users/x/plugin.toml"))
        );
        assert_eq!(
            parse_choose_file_output("/Users/x/plugin.toml"),
            Some(std::path::PathBuf::from("/Users/x/plugin.toml")),
            "no trailing newline is also accepted"
        );
        assert_eq!(
            parse_choose_file_output(""),
            None,
            "empty output must not become an empty path"
        );
        assert_eq!(
            parse_choose_file_output("   \n"),
            None,
            "whitespace-only output must not become a path"
        );
    }

    #[test]
    fn parse_picked_path_trims_and_rejects_empty() {
        // The Windows picker's buffer, read up to its first NUL. Same rule as
        // the macOS side above: a dialog that came back with nothing in it
        // must not turn into a path that gets read and imported.
        assert_eq!(
            parse_picked_path(r"C:\Users\x\plugin.toml"),
            Some(std::path::PathBuf::from(r"C:\Users\x\plugin.toml"))
        );
        assert_eq!(
            parse_picked_path(""),
            None,
            "an empty buffer must not become an empty path"
        );
        assert_eq!(
            parse_picked_path("   "),
            None,
            "nor a buffer holding only spaces"
        );
    }

    #[test]
    fn applescript_escape_neutralizes_quotes_and_backslashes() {
        assert_eq!(applescript_escape("plain"), "plain");
        assert_eq!(applescript_escape(r#"say "hi""#), r#"say \"hi\""#);
        assert_eq!(applescript_escape(r"back\slash"), r"back\\slash");
        // A hostile plugin id (the manifest schema only requires it
        // non-empty — free text otherwise) can't break out of the dialog
        // string it's interpolated into.
        assert_eq!(
            applescript_escape(r#"x" & (do shell script "rm -rf ~") & ""#),
            r#"x\" & (do shell script \"rm -rf ~\") & \""#
        );
    }

    // ── plugin manager actions: id -> manifest path resolution ─────────────

    /// A fresh temp dir per test, mirroring `plugin::seed::tests::temp_dir`
    /// (no external tempdir crate — `std::env::temp_dir()` + a unique suffix).
    fn temp_plugins_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tickover-main-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn the_signature_sits_beside_the_index_it_signs() {
        // minisign's own convention, and the reason the publisher does not
        // have to configure a second URL anywhere: `minisign -Sm index.toml`
        // writes `index.toml.minisig` next to it, and that is where this
        // looks. Whatever registry URL is in use, including a self-hosted one.
        assert_eq!(
            signature_url(DEFAULT_REGISTRY_URL),
            format!("{DEFAULT_REGISTRY_URL}.minisig")
        );
        assert_eq!(
            signature_url("https://example.com/some/where/index.toml"),
            "https://example.com/some/where/index.toml.minisig"
        );
    }

    #[test]
    fn plugin_manifest_target_resolves_a_safe_id_inside_the_plugins_dir() {
        let dir = temp_plugins_dir("target-ok");
        let target = plugin_manifest_target(&dir, "my-plugin_2");
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(target, Some(dir.join("my-plugin_2.toml")));
    }

    #[test]
    fn plugin_manifest_target_rejects_an_id_that_escapes_the_plugins_dir() {
        let dir = temp_plugins_dir("target-escape");
        // `..` components walk the target's parent up and out of `dir`
        // entirely — this must be rejected even though
        // `plugin::manifest::validate` already forbids such an `id` at parse
        // time (defence in depth, see the function's own docs).
        let target = plugin_manifest_target(&dir, "../../evil");
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(
            target, None,
            "a path-traversal id must never resolve to a write target"
        );
    }

    #[test]
    fn plugin_manifest_target_rejects_an_absolute_id() {
        let dir = temp_plugins_dir("target-absolute");
        // `PathBuf::join` with an absolute-looking `id` (a leading `/`) would
        // otherwise replace `dir` wholesale.
        let target = plugin_manifest_target(&dir, "/tmp/evil");
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(
            target, None,
            "an absolute-looking id must never resolve to a write target"
        );
    }

    #[test]
    fn find_plugin_manifest_path_matches_by_parsed_id_not_filename() {
        let dir = temp_plugins_dir("by-id");
        // Filename deliberately doesn't match the manifest's own id, proving
        // the match is on the parsed `id`, not the file's name.
        let manifest_path = dir.join("weird-name.toml");
        std::fs::write(&manifest_path, stub_manifest_toml("real-id", 5)).expect("write fixture");

        let found = find_plugin_manifest_path(&dir, "real-id");
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(found, Some(manifest_path));
    }

    #[test]
    fn find_plugin_manifest_path_does_not_fall_back_to_the_id_dot_toml_naming_convention() {
        let dir = temp_plugins_dir("no-fallback");
        // No file in the directory parses successfully to this id (it was
        // broken by hand) — even though a same-named file exists, matching
        // the naming convention `add-plugin` writes new imports under, it
        // must NOT be returned: `remove-plugin` deletes whatever this
        // returns, and guessing by filename risks deleting the wrong file
        // (see `find_plugin_manifest_path`'s own docs).
        let conventional = dir.join("codex.toml");
        std::fs::write(&conventional, "not valid toml at all").expect("write fixture");

        let found = find_plugin_manifest_path(&dir, "codex");
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(
            found, None,
            "a broken manifest must never be resolved by filename alone"
        );
    }

    #[test]
    fn find_plugin_manifest_path_is_none_when_nothing_matches() {
        let dir = temp_plugins_dir("missing");
        std::fs::write(dir.join("other.toml"), stub_manifest_toml("other", 1))
            .expect("write fixture");

        let found = find_plugin_manifest_path(&dir, "nowhere");
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(found, None);
    }

    // ── Registry: check-updates / install / update ────────────────────────
    // Every test here is hermetic — `registry::fetch_text`/`fetch_bytes`
    // (the module's two network calls) are never invoked; fixtures are built
    // directly or via `RegistryIndex::from_str`/`PluginManifest::from_str` on
    // in-memory text.

    #[test]
    fn plugin_row_defaults_registry_fields_when_no_check_has_run() {
        let m = stub_manifest("codex", 10); // stub_manifest_toml sets no `version`
        let row = plugin_row(&m);
        assert_eq!(
            row.current_version.as_str(),
            "",
            "no `version` field -> blank, per the manifest schema"
        );
        assert_eq!(row.available_version.as_str(), "");
        assert!(!row.has_local_edits);
        assert_eq!(row.update_status, 0);
        assert_eq!(row.update_error.as_str(), "");
    }

    #[test]
    fn plugin_row_carries_the_manifests_own_declared_version_as_current_version() {
        let toml = stub_manifest_toml("versioned", 1).replacen(
            "order      = 1",
            "order = 1\nversion = \"2.3.4\"",
            1,
        );
        let m = PluginManifest::from_str(&toml).expect("valid manifest with a version field");
        assert_eq!(plugin_row(&m).current_version.as_str(), "2.3.4");
    }

    fn make_registry_entry(id: &str, name: &str, version: &str, sha256: &str) -> RegistryEntry {
        RegistryEntry {
            id: id.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            description: Some(format!("{name} description")),
            manifest: format!("manifests/{id}.toml"),
            sha256: sha256.to_string(),
        }
    }

    #[test]
    fn fold_registry_diff_separates_updates_from_new_plugins() {
        let origin_sha = registry::sha256_hex(b"existing-origin-bytes");
        let moved_sha = registry::sha256_hex(b"existing-moved-bytes");
        let new_sha = registry::sha256_hex(b"brandnew-bytes");

        let index = RegistryIndex {
            schema_version: 1,
            plugins: vec![
                make_registry_entry("existing", "Existing", "1.1.0", &moved_sha),
                make_registry_entry("brandnew", "Brand New", "0.3.0", &new_sha),
            ],
        };

        let mut lockfile = registry::RegistryLockState::default();
        lockfile.set(
            "existing",
            registry::RegistryLockEntry {
                origin_registry_url: "https://example.com/index.toml".to_string(),
                origin_version: "1.0.0".to_string(),
                origin_sha256: origin_sha.clone(),
                installed_at: 0,
            },
        );
        let installed = vec![("existing".to_string(), origin_sha, "1.0.0".to_string())];

        let diff = fold_registry_diff(&index, &installed, &lockfile);

        assert_eq!(diff.update_count, 1);
        assert_eq!(diff.new_count, 1);
        let (available, has_local_edits) = diff
            .updates
            .get("existing")
            .expect("existing has an update");
        assert_eq!(available, "1.1.0");
        assert!(
            !has_local_edits,
            "a pristine, still-matching local file is a safe overwrite"
        );
        assert_eq!(diff.new_rows.len(), 1);
        assert_eq!(diff.new_rows[0].id.as_str(), "brandnew");
        assert_eq!(diff.new_rows[0].name.as_str(), "Brand New");
        assert_eq!(diff.new_rows[0].version.as_str(), "0.3.0");
        assert_eq!(
            diff.new_rows[0].description.as_str(),
            "Brand New description"
        );
        assert_eq!(diff.new_rows[0].status, 0);
        assert_eq!(diff.new_rows[0].error.as_str(), "");
    }

    #[test]
    fn fold_registry_diff_flags_local_edits_when_overwrite_is_unsafe() {
        let origin_sha = registry::sha256_hex(b"origin-bytes");
        let edited_sha = registry::sha256_hex(b"user-edited-bytes");
        let moved_sha = registry::sha256_hex(b"registry-moved-bytes");

        let index = RegistryIndex {
            schema_version: 1,
            plugins: vec![make_registry_entry("prov", "Prov", "2.0.0", &moved_sha)],
        };
        let mut lockfile = registry::RegistryLockState::default();
        lockfile.set(
            "prov",
            registry::RegistryLockEntry {
                origin_registry_url: "https://example.com/index.toml".to_string(),
                origin_version: "1.0.0".to_string(),
                origin_sha256: origin_sha,
                installed_at: 0,
            },
        );
        let installed = vec![("prov".to_string(), edited_sha, "1.0.0".to_string())];

        let diff = fold_registry_diff(&index, &installed, &lockfile);

        assert_eq!(diff.update_count, 1);
        assert_eq!(diff.new_count, 0);
        let (_, has_local_edits) = diff.updates.get("prov").expect("prov has an update");
        assert!(
            has_local_edits,
            "the installed file diverged from its recorded origin"
        );
    }

    #[test]
    fn registry_summary_formats_the_fixed_template_and_omits_the_zero_half() {
        assert_eq!(registry_summary(1, 2), "1 update, 2 new");
        assert_eq!(registry_summary(0, 2), "2 new");
        assert_eq!(registry_summary(1, 0), "1 update");
        assert_eq!(
            registry_summary(0, 0),
            "",
            "never invoked for the 0/0 case (that's status 4), but must not panic"
        );
    }

    #[test]
    fn relative_checked_at_buckets_elapsed_time() {
        assert_eq!(relative_checked_at(0), "just now");
        assert_eq!(relative_checked_at(59), "just now");
        assert_eq!(relative_checked_at(60), "1m ago");
        assert_eq!(relative_checked_at(125), "2m ago");
        assert_eq!(relative_checked_at(3600), "1h ago");
        assert_eq!(relative_checked_at(86399), "23h ago");
        assert_eq!(relative_checked_at(86400), "1d ago");
    }

    #[test]
    fn all_allowed_hosts_dedups_case_insensitively_across_surfaces_in_first_seen_order() {
        let toml = r#"
            id         = "x"
            name       = "X"
            menu_label = "X"
            order      = 1
            engine     = "http-api"
            [[windows]]
            label = "5H"
            role  = "primary"
            [windows.period]
            mode = "assumed"
            assumed = 300
            [windows.source]
            used_percent_path = "p"
            resets_at_path = "r"
            [http]
            [[http.request]]
            url = "https://api.example.com/usage"
            [[surface]]
            id = "cli"
            label = "CLI"
            allowed_hosts = ["Api.Example.com", "other.example.com"]
            [[surface]]
            id = "desktop"
            label = "Desktop"
            opt_in = true
            allowed_hosts = ["other.example.com", "third.example.com"]
        "#;
        let m = PluginManifest::from_str(toml).expect("valid manifest");
        assert_eq!(
            all_allowed_hosts(&m),
            vec![
                "Api.Example.com".to_string(),
                "other.example.com".to_string(),
                "third.example.com".to_string()
            ],
            "case-insensitive de-dup keeps the first-seen spelling, in first-seen order"
        );
    }

    #[test]
    fn build_trust_message_discloses_id_engine_auth_chain_and_untrusted_hosts() {
        let disclosure = TrustDisclosure {
            engine: EngineKind::HttpApi,
            auth_types: vec![
                manifest::AuthType::CredentialsFile,
                manifest::AuthType::Keychain,
            ],
            dest_hosts: vec![
                "api.example.com".to_string(),
                "evil.example.com".to_string(),
            ],
            untrusted_hosts: vec!["evil.example.com".to_string()],
            local_files: Vec::new(),
            ping: None,
            requires_approval: true,
        };
        let allowed_hosts = vec!["api.example.com".to_string()];
        let (short, detailed) = build_trust_message("some-plugin", &disclosure, &allowed_hosts);

        assert!(short.contains("some-plugin"), "short: {short}");
        assert!(short.contains("credentials-file"), "short: {short}");

        assert!(
            detailed.contains("Plugin id: some-plugin"),
            "detailed: {detailed}"
        );
        assert!(
            detailed.contains("Engine: http-api"),
            "detailed: {detailed}"
        );
        assert!(
            detailed.contains("credentials-file → keychain"),
            "detailed: {detailed}"
        );
        assert!(
            detailed.contains("evil.example.com (untrusted)"),
            "detailed: {detailed}"
        );
        assert!(
            !detailed.contains("api.example.com (untrusted)"),
            "the trusted host must not be marked untrusted: {detailed}"
        );
        assert!(
            detailed.contains("Allowed hosts: api.example.com"),
            "detailed: {detailed}"
        );
        assert!(detailed.contains("Redirects: 0"), "detailed: {detailed}");
    }

    /// Walks an escaped string the way AppleScript's parser would: a
    /// backslash consumes whatever follows it, and the first quote that
    /// survives that ends the string literal. True means the value could
    /// close the literal it was interpolated into — the thing escaping
    /// exists to prevent.
    fn closes_the_literal_early(escaped: &str) -> bool {
        let bytes = escaped.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'\\' => i += 2,
                b'"' => return true,
                _ => i += 1,
            }
        }
        false
    }

    #[test]
    fn applescript_escape_cannot_be_broken_out_of() {
        // What reaches this now includes a manifest's own [ping] command and
        // the paths it reads — free-form strings from a TOML file that may
        // have come from a registry.
        for hostile in [
            r#"a"b"#,
            r"trailing\\",
            r#"\" buttons {"Yes"} default button "Yes"#,
            r#"\\" buttons {"Install Anyway"}"#,
            "two\nlines",
        ] {
            let escaped = applescript_escape(hostile);
            assert!(
                !closes_the_literal_early(&escaped),
                "{hostile:?} escaped to {escaped:?}, which ends the literal early"
            );
            assert!(
                !escaped.contains('\n'),
                "a raw newline breaks the script: {escaped:?}"
            );
        }

        // And the ordinary case is left readable.
        assert_eq!(applescript_escape("codex exec hello"), "codex exec hello");
        assert_eq!(applescript_escape("bell\u{7}here"), "bell here");
    }

    #[test]
    fn build_trust_message_names_the_command_a_manifest_runs_and_the_files_it_reads() {
        // The one field in a manifest that executes anything used to be
        // invisible here, and the toggle that later fires it says only
        // "Ping \"hello\" on 5h reset" — so a third-party plugin could have
        // arrived with `sh -c ...` and disclosed nothing at all.
        let disclosure = TrustDisclosure {
            engine: manifest::EngineKind::LogFile,
            auth_types: Vec::new(),
            dest_hosts: Vec::new(),
            untrusted_hosts: Vec::new(),
            local_files: vec!["~/.claude/.credentials.json".to_string()],
            ping: Some("sh -c curl evil.example.com".to_string()),
            requires_approval: true,
        };
        let (short, detailed) = build_trust_message("sneaky", &disclosure, &[]);
        assert!(short.contains("runs a command"), "short: {short}");
        assert!(
            short.contains("sh -c curl evil.example.com"),
            "short: {short}"
        );
        assert!(
            short.contains("reads local files"),
            "the first screen can be approved from, so it names every vector: {short}"
        );
        assert!(
            detailed.contains("Runs after a reset: sh -c curl evil.example.com"),
            "detailed: {detailed}"
        );
        assert!(
            detailed.contains("Reads local files: ~/.claude/.credentials.json"),
            "detailed: {detailed}"
        );
    }

    #[test]
    fn build_trust_message_discloses_no_destinations_or_allowed_hosts_when_none_are_declared() {
        let disclosure = TrustDisclosure {
            engine: EngineKind::LogFile,
            auth_types: vec![],
            dest_hosts: vec![],
            untrusted_hosts: vec![],
            local_files: Vec::new(),
            ping: None,
            requires_approval: false,
        };
        let (_short, detailed) = build_trust_message("x", &disclosure, &[]);
        assert!(
            detailed.contains("Destination hosts: (none declared)"),
            "detailed: {detailed}"
        );
        assert!(
            detailed.contains("Allowed hosts: (none declared)"),
            "detailed: {detailed}"
        );
    }

    #[test]
    fn parse_button_returned_extracts_the_clicked_buttons_text() {
        assert_eq!(
            parse_button_returned("button returned:Install Anyway\n"),
            Some("Install Anyway".to_string())
        );
        assert_eq!(
            parse_button_returned("button returned:Show Details, gave up:false"),
            Some("Show Details".to_string()),
            "must tolerate other fields in the AppleEvent record, mirroring confirm_parse"
        );
        assert_eq!(
            parse_button_returned("button returned:Cancel"),
            Some("Cancel".to_string())
        );
        assert_eq!(
            parse_button_returned(""),
            None,
            "empty output (unexpected format) must never resolve to a button"
        );
        assert_eq!(parse_button_returned("garbage"), None);
    }

    #[test]
    fn install_write_creates_a_new_manifest_file_and_refuses_to_clobber_an_existing_one() {
        let dir = temp_plugins_dir("install-write");
        let bytes = stub_manifest_toml("newid", 1).into_bytes();

        install_write(&dir, "newid", &bytes).expect("first write succeeds");
        let on_disk = std::fs::read(dir.join("newid.toml")).expect("file was written");

        let clobber = install_write(&dir, "newid", &bytes);
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(
            on_disk, bytes,
            "the exact downloaded bytes land on disk, not a re-serialization"
        );
        assert!(
            clobber.is_err(),
            "a second install of the same id must never overwrite the first"
        );
    }

    #[test]
    fn update_write_atomically_overwrites_the_existing_manifest_and_leaves_no_tmp_file_behind() {
        let dir = temp_plugins_dir("update-write");
        let path = dir.join("existing.toml");
        std::fs::write(&path, stub_manifest_toml("existing", 1)).expect("seed the original file");

        let new_bytes = stub_manifest_toml("existing", 2).into_bytes();
        update_write(&dir, "existing", &new_bytes).expect("overwrite succeeds");

        let on_disk = std::fs::read(&path).unwrap();
        let tmp_left_behind = dir.join("existing.toml.tmp").exists();
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(on_disk, new_bytes);
        assert!(
            !tmp_left_behind,
            "the temp file must be renamed away, never left sitting next to the target"
        );
    }

    #[test]
    #[cfg(unix)]
    fn update_write_will_not_follow_a_symlink_planted_on_its_temp_path() {
        // The temp path is predictable, and the plugins directory is writable
        // by anything running as this user. A link left there used to be
        // followed, truncating and overwriting its target — a file outside
        // this directory entirely.
        let dir = temp_plugins_dir("update-write-symlink");
        let path = dir.join("existing.toml");
        std::fs::write(&path, stub_manifest_toml("existing", 1)).expect("seed the original file");

        let outside = dir.join("precious.txt");
        std::fs::write(&outside, b"do not touch").unwrap();
        let tmp = dir.join(format!("existing.toml.tmp{}", std::process::id()));
        std::os::unix::fs::symlink(&outside, &tmp).expect("plant the link");

        let new_bytes = stub_manifest_toml("existing", 2).into_bytes();
        let result = update_write(&dir, "existing", &new_bytes);

        let victim = std::fs::read(&outside).unwrap();
        let manifest = std::fs::read(&path).unwrap();
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(
            victim, b"do not touch",
            "the link's target must be untouched"
        );
        assert!(
            result.is_ok(),
            "and the update itself still goes through: {result:?}"
        );
        assert_eq!(manifest, new_bytes);
    }

    #[test]
    fn update_write_fails_when_no_installed_manifest_matches_the_id() {
        let dir = temp_plugins_dir("update-write-missing");
        let err = update_write(&dir, "nowhere", b"irrelevant bytes");
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            err.is_err(),
            "there is nothing on disk to overwrite for this id"
        );
    }

    // ── verify_manifest_id_matches_entry (id-consistency, defense in depth) ─

    #[test]
    fn verify_manifest_id_matches_entry_accepts_a_match() {
        let manifest = stub_manifest("gemini", 1);
        let entry = make_registry_entry("gemini", "Gemini", "1.0.0", &"a".repeat(64));
        assert!(verify_manifest_id_matches_entry(&manifest, &entry).is_ok());
    }

    #[test]
    fn verify_manifest_id_matches_entry_rejects_a_mismatch() {
        // A registry entry listed as "gemini" whose downloaded manifest
        // actually declares `id = "claude"` — the honest-but-buggy-or-
        // dishonest-registry scenario this check exists to catch.
        let manifest = stub_manifest("claude", 1);
        let entry = make_registry_entry("gemini", "Gemini", "1.0.0", &"a".repeat(64));
        let err = verify_manifest_id_matches_entry(&manifest, &entry).expect_err(
            "a manifest declaring a different id than its registry entry must be rejected",
        );
        assert!(err.contains("\"gemini\""), "unexpected error: {err}");
        assert!(err.contains("\"claude\""), "unexpected error: {err}");
    }

    // `fetch_and_verify_manifest` itself is not directly unit-tested (it
    // makes the real `registry::fetch_bytes` network call — see the
    // "Registry" test-module comment above); `verify_manifest_id_matches_entry`
    // is the pure check it's wired to call immediately after
    // `registry::verify_and_prepare` succeeds, before ever producing a
    // `Ready` outcome, so testing it directly exercises the exact mismatch
    // path `fetch_and_verify_manifest` can take: an `Err` here becomes
    // `InstallOutcome::Failed`, and `handle_install_outcome` never calls
    // `install_write`/`update_write` for that variant — so "nothing is
    // written" follows structurally from the `Err` case above, the same way
    // it already does for a `registry::verify_and_prepare` sha256 mismatch.

    // ── remove_lockfile_entry (tempdir only — never the real lockfile) ─────

    #[test]
    fn remove_lockfile_entry_clears_the_records_id_and_leaves_others_untouched() {
        let dir = temp_plugins_dir("lockfile-remove");
        let path = dir.join("registry-state.json");

        let mut state = registry::RegistryLockState::default();
        state.set(
            "gone",
            registry::RegistryLockEntry {
                origin_registry_url: "https://example.com/index.toml".to_string(),
                origin_version: "1.0.0".to_string(),
                origin_sha256: "a".repeat(64),
                installed_at: 0,
            },
        );
        state.set(
            "stays",
            registry::RegistryLockEntry {
                origin_registry_url: "https://example.com/index.toml".to_string(),
                origin_version: "2.0.0".to_string(),
                origin_sha256: "b".repeat(64),
                installed_at: 0,
            },
        );
        registry::save_lockfile(&path, &state).expect("seed the lockfile");

        remove_lockfile_entry(&path, "gone");

        let reloaded = registry::load_lockfile(&path);
        std::fs::remove_dir_all(&dir).ok();

        assert!(
            reloaded.get("gone").is_none(),
            "the removed plugin's provenance record must be gone"
        );
        assert!(
            reloaded.get("stays").is_some(),
            "an unrelated plugin's record must survive"
        );
    }

    #[test]
    fn remove_lockfile_entry_is_a_no_op_when_the_lockfile_doesnt_exist() {
        let dir = temp_plugins_dir("lockfile-remove-missing-file");
        let path = dir.join("registry-state.json");

        remove_lockfile_entry(&path, "whatever");
        let existed = path.exists();
        std::fs::remove_dir_all(&dir).ok();

        assert!(
            !existed,
            "no lockfile existed and there was nothing to remove -> must not create one"
        );
    }

    #[test]
    fn remove_lockfile_entry_is_a_no_op_when_the_id_has_no_record() {
        let dir = temp_plugins_dir("lockfile-remove-missing-id");
        let path = dir.join("registry-state.json");

        let mut state = registry::RegistryLockState::default();
        state.set(
            "stays",
            registry::RegistryLockEntry {
                origin_registry_url: "https://example.com/index.toml".to_string(),
                origin_version: "1.0.0".to_string(),
                origin_sha256: "a".repeat(64),
                installed_at: 0,
            },
        );
        registry::save_lockfile(&path, &state).expect("seed the lockfile");
        let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();

        remove_lockfile_entry(&path, "never-installed");

        let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
        let reloaded = registry::load_lockfile(&path);
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(
            mtime_before, mtime_after,
            "an id with no record must not even rewrite the file"
        );
        assert!(reloaded.get("stays").is_some());
    }
}

fn load_tray_icon() -> Option<tray_icon::Icon> {
    #[cfg(target_os = "macos")]
    let bytes: &[u8] = include_bytes!("../assets/tray-icon-template@2x.png");
    #[cfg(not(target_os = "macos"))]
    let bytes: &[u8] = include_bytes!("../assets/tray-icon-color@2x.png");

    let img = image::load_from_memory(bytes).ok()?.into_rgba8();
    let (w, h) = img.dimensions();
    tray_icon::Icon::from_rgba(img.into_raw(), w, h).ok()
}
