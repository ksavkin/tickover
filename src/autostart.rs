//! "Launch at login" via the `auto-launch` crate.
//!
//! macOS → login item (AppleScript), Windows → HKCU `...\Run` registry key.
//! All functions are best-effort: a failure is logged and swallowed so the UI
//! toggle never brings the app down.

use auto_launch::{AutoLaunch, AutoLaunchBuilder};

const APP_NAME: &str = "Tickover";

/// The name this app registered its login item under before the rename to
/// Tickover. Only [`retire_legacy_entry`] ever builds an `AutoLaunch` with
/// it — everywhere else in this module means [`APP_NAME`].
const LEGACY_APP_NAME: &str = "Codex Limits";

fn build() -> Option<AutoLaunch> {
    let exe = std::env::current_exe().ok()?;
    AutoLaunchBuilder::new()
        .set_app_name(APP_NAME)
        .set_app_path(&run_key_path(&exe.to_string_lossy()))
        .build()
        .ok()
}

/// A fresh `AutoLaunch` naming [`LEGACY_APP_NAME`] rather than [`APP_NAME`] —
/// the two point at different entries in the same store, so [`build`] cannot
/// be reused for the old one.
fn build_legacy() -> Option<AutoLaunch> {
    let exe = std::env::current_exe().ok()?;
    AutoLaunchBuilder::new()
        .set_app_name(LEGACY_APP_NAME)
        .set_app_path(&run_key_path(&exe.to_string_lossy()))
        .build()
        .ok()
}

/// Turn off the login item this app registered under [`LEGACY_APP_NAME`],
/// carrying its state forward to [`APP_NAME`] first if it was on — an
/// upgrader who had launch-at-login enabled must not find it silently off,
/// and the surviving entry has to point at the new exe path regardless of
/// where the old one pointed, which is exactly what [`set`] already does.
/// Called only when `crate::config::migrate_legacy_dir` actually moved a
/// pre-rename install — never on a fresh one, which never held the old item
/// and must not be shown the permission prompt macOS's login-item AppleScript
/// can raise for one it does not hold.
///
/// Best-effort like the rest of this module: every failure is logged and
/// swallowed, never surfaced to the user. Returns the state actually
/// achieved for the new entry — the outcome of [`set`], not merely what
/// this function meant to leave it in.
///
/// Not tested here: `is_enabled`, `enable` and `disable` shell out to
/// `osascript` on macOS, and a test that ran them for real would touch the
/// login items of whatever machine `cargo test` runs on.
pub fn retire_legacy_entry() -> bool {
    let Some(legacy) = build_legacy() else {
        return false;
    };
    let was_enabled = legacy.is_enabled().unwrap_or(false);
    if let Err(e) = legacy.disable() {
        crate::diag::line(format!(
            "could not retire the old \"{LEGACY_APP_NAME}\" login item: {e}"
        ));
    }
    if was_enabled {
        set(true)
    } else {
        false
    }
}

/// The path as the platform's own autostart store wants it written.
///
/// Windows needs it quoted. `auto-launch` writes `<path> <args>` into the Run
/// key verbatim, quoting nothing, and Windows then reads that value as a
/// command line: the first space ends the program name. From
/// `C:\Users\Ann Lee\apps\tickover.exe` it would try to run
/// `C:\Users\Ann.exe` with `Lee\apps\tickover.exe` as an argument, and
/// the app silently never starts with the login it was asked to start with.
/// Only a path with no space in it — the one this was developed against —
/// happens to work.
///
/// macOS must not be quoted: `auto-launch` writes the path straight into an
/// AppleScript string literal of its own (`path:"…"` inside the
/// `make login item` properties it sends to `osascript`), which already
/// supplies the surrounding quotes — wrapping it again would double them.
fn run_key_path(path: &str) -> String {
    if cfg!(target_os = "windows") {
        format!("\"{path}\"")
    } else {
        path.to_string()
    }
}

/// Is launch-at-login currently enabled?
pub fn is_enabled() -> bool {
    build().and_then(|a| a.is_enabled().ok()).unwrap_or(false)
}

/// Enable or disable launch-at-login. Returns the state actually achieved.
pub fn set(enabled: bool) -> bool {
    let Some(auto) = build() else {
        return false;
    };
    let result = if enabled {
        auto.enable()
    } else {
        auto.disable()
    };
    if let Err(e) = result {
        crate::diag::line(format!("autostart {enabled} failed: {e}"));
    }
    auto.is_enabled().unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::run_key_path;

    #[test]
    fn a_path_with_a_space_in_it_survives_the_round_trip() {
        // The Run key holds a command line, not a path, so an unquoted
        // `C:\Users\Ann Lee\...` starts at the first space. Every install
        // under a user folder with a space in the name is that case.
        let quoted = run_key_path(r"C:\Users\Ann Lee\apps\tickover.exe");
        if cfg!(target_os = "windows") {
            assert_eq!(quoted, r#""C:\Users\Ann Lee\apps\tickover.exe""#);
        } else {
            assert_eq!(quoted, r"C:\Users\Ann Lee\apps\tickover.exe");
        }
    }

    // macOS-only: `run_key_path`'s `if` only has a Windows arm and an
    // everyone-else arm, so this asserts nothing new on Linux and would
    // silently pass without checking anything on the Windows CI job too —
    // cfg'd out there rather than left to assert nothing.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_is_left_alone_because_applescript_quotes_it_itself() {
        let path = "/Applications/Tickover.app/Contents/MacOS/tickover";
        assert_eq!(
            run_key_path(path),
            path,
            "a quote here would land inside auto-launch's own AppleScript string literal"
        );
    }
}
