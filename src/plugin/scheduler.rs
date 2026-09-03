//! Generic per-plugin fetch dispatch and refresh cadence.
//!
//! The actual timers, background threads and mpsc plumbing live in
//! `src/main.rs` (that wiring is Slint/tray specific, not a library
//! concern); this module holds the two pieces of it that are plugin-agnostic
//! and worth unit-testing on their own:
//!
//! * [`fetch`] — pick the right engine ([`crate::plugin::engine_logfile`] or
//!   [`crate::plugin::engine_http`]) for a manifest's declared `engine` kind.
//! * [`due`] — whether a given one-second tick is due for a plugin's own
//!   `refresh_secs` cadence.

use std::collections::BTreeMap;

use crate::model::ProviderReading;
use crate::plugin::manifest::{EngineKind, PluginManifest};
use crate::plugin::{engine_http, engine_logfile};

/// Fetch one plugin's readings via whichever engine its manifest declares.
/// `active_surface_ids` is meaningful only to `engine_http` (see its own
/// docs); `engine_logfile` ignores it and always returns one reading.
///
/// `options` is the plugin's declared `[[option]]` set resolved to its
/// current value — see `crate::config::plugin_option`, read once per fetch
/// by the caller (`src/main.rs`) and passed straight through to whichever
/// engine handles this plugin; neither engine reads config itself.
pub fn fetch(
    m: &PluginManifest,
    active_surface_ids: &[String],
    options: &BTreeMap<String, bool>,
) -> Vec<ProviderReading> {
    match m.engine {
        EngineKind::LogFile => engine_logfile::fetch(m, active_surface_ids, options),
        EngineKind::HttpApi => engine_http::fetch(m, active_surface_ids, options),
    }
}

/// Whether tick `n` (a one-second counter starting at 1) is due for a plugin
/// whose manifest declares `refresh_secs`. A manifest can't declare
/// `refresh_secs = 0` through normal validation (the default is 60), but a
/// hand-edited one might — treated as "due every tick" rather than dividing
/// by zero.
pub fn due(n: u32, refresh_secs: u64) -> bool {
    match refresh_secs {
        0 => true,
        secs => (n as u64).is_multiple_of(secs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn due_fires_on_multiples_of_refresh_secs() {
        assert!(due(15, 15));
        assert!(due(30, 15));
        assert!(!due(14, 15));
        assert!(!due(16, 15));
        assert!(due(60, 60));
        assert!(!due(59, 60));
    }

    #[test]
    fn due_zero_refresh_secs_is_always_due_and_never_panics() {
        assert!(due(1, 0));
        assert!(due(0, 0));
    }
}
