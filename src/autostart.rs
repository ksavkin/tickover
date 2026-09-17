//! "Launch at login" via the `auto-launch` crate.
//!
//! macOS → login item (AppleScript), Windows → HKCU `...\Run` registry key.
//! All functions are best-effort: a failure is logged and swallowed so the UI
//! toggle never brings the app down.

use auto_launch::{AutoLaunch, AutoLaunchBuilder};

const APP_NAME: &str = "Tickover";

/// The name this app registered its login item under before the rename to
/// Tickover. Only meaningful on Windows: `auto-launch`'s own `AutoLaunch::new`
/// there keeps `app_name` verbatim as the Run-key value name (see
/// `windows.rs` in that crate), so [`build_legacy`] really does name an entry
/// distinct from [`APP_NAME`]'s. macOS never reads this constant at all — see
/// [`retire_macos_legacy_login_items`]'s own doc for why a name-keyed lookup
/// cannot find the old entry there in the first place.
const LEGACY_APP_NAME: &str = "Codex Limits";

fn build() -> Option<AutoLaunch> {
    let exe = std::env::current_exe().ok()?;
    AutoLaunchBuilder::new()
        .set_app_name(APP_NAME)
        .set_app_path(&run_key_path(&exe.to_string_lossy()))
        .build()
        .ok()
}

/// A fresh `AutoLaunch` naming [`LEGACY_APP_NAME`] rather than [`APP_NAME`],
/// used only by [`retire_windows_legacy_entry`] — the two name different
/// values under the same Windows Run key. On macOS the name this actually
/// builds ends up identical to [`build`]'s own regardless of
/// [`LEGACY_APP_NAME`]; see [`retire_macos_legacy_login_items`]'s own doc for
/// why, and why macOS never calls this function at all.
fn build_legacy() -> Option<AutoLaunch> {
    let exe = std::env::current_exe().ok()?;
    AutoLaunchBuilder::new()
        .set_app_name(LEGACY_APP_NAME)
        .set_app_path(&run_key_path(&exe.to_string_lossy()))
        .build()
        .ok()
}

/// Turn off the login item this app registered under the pre-rename name,
/// carrying its state forward to [`APP_NAME`] first if it was on — an
/// upgrader who had launch-at-login enabled must not find it silently off,
/// and the surviving entry has to point at the new exe path regardless of
/// where the old one pointed, which is exactly what [`set`] already does.
/// Called only when `crate::config::migrate_legacy_dir` actually moved a
/// pre-rename install — never on a fresh one, which never held the old item
/// and must not be shown the permission prompt macOS's login-item AppleScript
/// can raise for one it does not hold.
///
/// The two platforms need genuinely different logic here, not just
/// different names. On Windows a login entry is keyed by name, and the old
/// one really is a separate Run-key value from this app's own current entry
/// — see [`retire_windows_legacy_entry`]. On macOS it is not: `auto-launch`
/// derives the actual login-item name from the executable's own path rather
/// than the name its caller asked for (see its own `AutoLaunch::new` doc:
/// "the app_name should be same as the executable's name… or it will be
/// corrected automatically"), so [`build_legacy`] and [`build`] — passing
/// the *same* current exe path — end up naming the *same* entry, and calling
/// `.disable()` on the "legacy" one used to just delete the entry this app
/// had itself just registered, never the pre-rename "Codex Limits" one.
/// [`retire_macos_legacy_login_items`] finds the real old entry by its path
/// instead of its name.
///
/// Best-effort like the rest of this module: every failure is logged and
/// swallowed, never surfaced to the user. Returns the state actually
/// achieved for the new entry — the outcome of [`set`], not merely what
/// this function meant to leave it in.
///
/// Not tested here: both platforms shell out for real (`osascript` on
/// macOS, the registry via `auto-launch` on Windows), and a test that ran
/// either would touch the login items of whatever machine `cargo test` runs
/// on. [`names_legacy_install`] and [`delete_by_path_command`] carry the
/// parts of the macOS path that can be tested without doing that.
pub fn retire_legacy_entry() -> bool {
    let was_enabled = if cfg!(target_os = "macos") {
        retire_macos_legacy_login_items()
    } else {
        retire_windows_legacy_entry()
    };
    if was_enabled {
        set(true)
    } else {
        false
    }
}

/// Windows half of [`retire_legacy_entry`]: `auto-launch`'s Windows
/// implementation keys a login entry by name and keeps whatever name its
/// caller gave it, so [`build_legacy`]'s [`LEGACY_APP_NAME`] really does name
/// a different Run-key value from [`build`]'s [`APP_NAME`] — deleting it by
/// name, the way this always worked, is exactly right here. Returns whether
/// the legacy entry was enabled before this call disabled it.
fn retire_windows_legacy_entry() -> bool {
    let Some(legacy) = build_legacy() else {
        return false;
    };
    let was_enabled = legacy.is_enabled().unwrap_or(false);
    if let Err(e) = legacy.disable() {
        crate::diag::line(format!(
            "could not retire the old \"{LEGACY_APP_NAME}\" login item: {e}"
        ));
    }
    was_enabled
}

/// macOS half of [`retire_legacy_entry`]. Matches by *path* rather than
/// name, for the reason [`retire_legacy_entry`]'s own doc gives: a
/// name-keyed lookup here would find (and delete) this app's own current
/// entry instead of the pre-rename one. [`LEGACY_LOGIN_ITEM_PATH_NEEDLES`]
/// names the two shapes a pre-rename login item's path could take.
///
/// Returns whether any login item actually matched, before either needle's
/// delete ran — the caller carries that forward to the new entry the same
/// way the Windows half's `was_enabled` does.
fn retire_macos_legacy_login_items() -> bool {
    let paths = login_item_paths();
    let matched = paths.as_deref().is_some_and(names_legacy_install);
    if should_delete_legacy_login_items(paths.as_deref()) {
        delete_legacy_login_items();
    }
    matched
}

/// Whether [`retire_macos_legacy_login_items`] should call
/// [`delete_legacy_login_items`] at all, given what [`login_item_paths`]
/// found. `true` on `None` — the listing itself failed (`osascript`
/// missing, System Events refusing automation) — is the fail-safe this
/// always had before `login_item_paths` could even distinguish "found
/// nothing" from "couldn't check": a failed listing does not rule out that
/// the legacy item is still there, so deletion still runs, same as every
/// launch before this `Option` existed. Skipped only when the listing
/// actually *ran* and found no match (`Some(paths)`, no match) — that is
/// the one case safe to read as "nothing to clean up". Pulled out from
/// `retire_macos_legacy_login_items` so this decision has a test that
/// doesn't touch the machine's real login items.
fn should_delete_legacy_login_items(paths: Option<&[String]>) -> bool {
    paths.is_none() || paths.is_some_and(names_legacy_install)
}

/// The two path substrings a pre-rename "Codex Limits" macOS login item
/// could be registered under, depending on how it was launched:
/// `packaging/macos/make-app.sh` produced `Codex Limits.app` before the
/// rename, and a dev build or a direct run outside any bundle registers the
/// bare executable, `codex-limits`. Neither string is ever user-supplied, so
/// — unlike [`run_key_path`]'s own path — nothing built from these needs
/// escaping for the AppleScript literal it goes into.
const LEGACY_LOGIN_ITEM_PATH_NEEDLES: &[&str] = &["codex-limits", "Codex Limits.app"];

/// Whether any of `paths` names the pre-rename "Codex Limits" install — see
/// [`LEGACY_LOGIN_ITEM_PATH_NEEDLES`]. Pulled out as its own pure function
/// so the one piece of [`retire_macos_legacy_login_items`] that isn't an
/// `osascript` call has a test that doesn't touch the machine's real login
/// items.
fn names_legacy_install(paths: &[String]) -> bool {
    paths
        .iter()
        .any(|p| LEGACY_LOGIN_ITEM_PATH_NEEDLES.iter().any(|n| p.contains(n)))
}

/// Every login item's own `path`, as macOS's `System Events` reports it —
/// mirrors `auto-launch`'s own `is_enabled` (`"get the name of every login
/// item"`), asking for `path` instead of `name` since a path is what
/// [`names_legacy_install`] needs to tell a pre-rename "Codex Limits" entry
/// apart from this app's own current one. `None` on any failure (`osascript`
/// missing, System Events refusing automation) — distinct from `Some(vec![])`
/// (the listing ran and genuinely found no login items at all), since
/// [`should_delete_legacy_login_items`] has to tell those two apart: only
/// the latter is safe to skip the deletion for, and a failed listing falls
/// back to attempting it anyway (see that function's own doc).
fn login_item_paths() -> Option<Vec<String>> {
    let output = std::process::Command::new("osascript")
        .args([
            "-e",
            "tell application \"System Events\" to get the path of every login item",
        ])
        .output();
    let Ok(output) = output else {
        return None;
    };
    if !output.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&output.stdout)
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    )
}

/// The `osascript` command that deletes every login item whose path contains
/// `needle` — pulled out so its exact text has a test independent of
/// actually running it. Never handed anything but one of
/// [`LEGACY_LOGIN_ITEM_PATH_NEEDLES`]'s own literal strings.
fn delete_by_path_command(needle: &str) -> String {
    format!(
        "tell application \"System Events\" to delete (every login item whose path contains \"{needle}\")"
    )
}

/// Run [`delete_by_path_command`] for every needle in
/// [`LEGACY_LOGIN_ITEM_PATH_NEEDLES`]. Best-effort like the rest of this
/// module: a needle matching nothing, or `osascript` itself failing, is
/// logged and otherwise ignored.
fn delete_legacy_login_items() {
    for needle in LEGACY_LOGIN_ITEM_PATH_NEEDLES {
        let output = std::process::Command::new("osascript")
            .args(["-e", &delete_by_path_command(needle)])
            .output();
        match output {
            Ok(out) if out.status.success() => {}
            Ok(out) => crate::diag::line(format!(
                "could not retire the old \"Codex Limits\" login item ({needle}): {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )),
            Err(e) => crate::diag::line(format!(
                "could not retire the old \"Codex Limits\" login item ({needle}): {e}"
            )),
        }
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
/// macOS must not be *wrapped* in quotes: `auto-launch` writes the path
/// straight into an AppleScript string literal of its own (`path:"…"` inside
/// the `make login item` properties it sends to `osascript`), which already
/// supplies the surrounding quotes — wrapping it again would double them.
/// It still needs escaping *inside* that literal: `auto-launch` never
/// escapes `self.app_path` before embedding it, so a `"` in the exe's own
/// path (installed under a directory a user happened to name with one, say)
/// would close the literal early and let whatever follows run as
/// AppleScript of its own — the same shape `main.rs`'s `applescript_escape`
/// exists to close for a manifest's `[ping] args`, self-inflicted here
/// instead of manifest-inflicted. `\` goes first, so a literal backslash
/// isn't read as starting an escape of whatever follows it. Neither
/// character occurs in a real install path in practice, so this is a no-op
/// for every install this was ever tested against and only changes anything
/// for the one it exists to protect.
fn run_key_path(path: &str) -> String {
    if cfg!(target_os = "windows") {
        format!("\"{path}\"")
    } else {
        path.replace('\\', "\\\\").replace('"', "\\\"")
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
    use super::{
        delete_by_path_command, names_legacy_install, run_key_path,
        should_delete_legacy_login_items,
    };

    // Windows-only: the fixture is a Windows-shaped path with backslashes in
    // it, which `run_key_path`'s non-Windows arm now escapes (see
    // `macos_path_escapes_a_quote_and_a_backslash_before_reaching_auto_launchs_own_literal`)
    // rather than leaving alone — so this fixture no longer round-trips
    // unchanged on that arm, and asserting on it there would be checking
    // Windows behaviour on the wrong platform's branch.
    #[cfg(target_os = "windows")]
    #[test]
    fn a_path_with_a_space_in_it_survives_the_round_trip() {
        // The Run key holds a command line, not a path, so an unquoted
        // `C:\Users\Ann Lee\...` starts at the first space. Every install
        // under a user folder with a space in the name is that case.
        assert_eq!(
            run_key_path(r"C:\Users\Ann Lee\apps\tickover.exe"),
            r#""C:\Users\Ann Lee\apps\tickover.exe""#
        );
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
            "no quote or backslash in this path for the escape to touch"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_path_escapes_a_quote_and_a_backslash_before_reaching_auto_launchs_own_literal() {
        assert_eq!(
            run_key_path(r#"/Applications/say "hi"\Tickover.app/tickover"#),
            r#"/Applications/say \"hi\"\\Tickover.app/tickover"#,
            "unescaped, either character would break out of auto-launch's own path:\"…\" literal"
        );
    }

    #[test]
    fn names_legacy_install_matches_either_the_bundle_or_the_bare_binary() {
        assert!(names_legacy_install(&[
            "/Applications/Codex Limits.app/Contents/MacOS/codex-limits".to_string()
        ]));
        assert!(names_legacy_install(&[
            "/usr/local/bin/codex-limits".to_string()
        ]));
        assert!(!names_legacy_install(&[
            "/Applications/Tickover.app/Contents/MacOS/tickover".to_string()
        ]));
        assert!(!names_legacy_install(&[]));
    }

    #[test]
    fn should_delete_legacy_login_items_skips_only_a_successful_listing_that_found_nothing() {
        assert!(
            should_delete_legacy_login_items(Some(&["/usr/local/bin/codex-limits".to_string()])),
            "a successful listing that named the pre-rename install is safe to act on"
        );
        assert!(
            !should_delete_legacy_login_items(Some(&[
                "/Applications/Tickover.app/Contents/MacOS/tickover".to_string()
            ])),
            "a successful listing that found only this app's own current entry has nothing to delete"
        );
        assert!(
            !should_delete_legacy_login_items(Some(&[])),
            "a successful listing that found no login items at all has nothing to delete"
        );
        assert!(
            should_delete_legacy_login_items(None),
            "a listing that failed outright cannot rule out the legacy item still being there, \
             so the fail-safe is to still attempt the deletion"
        );
    }

    #[test]
    fn delete_by_path_command_names_exactly_the_needle_it_was_given() {
        assert_eq!(
            delete_by_path_command("codex-limits"),
            "tell application \"System Events\" to delete (every login item whose path contains \"codex-limits\")"
        );
    }
}
