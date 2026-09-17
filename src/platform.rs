//! Platform glue that doesn't belong in the UI or the reader.
//!
//! On macOS we flip the process to *accessory* activation policy so it lives
//! only in the menu bar (no Dock icon, no app-switcher entry) even when run as
//! a bare binary, and we explicitly activate the app when showing the popover
//! so an accessory window can take key focus. Neither has a Windows
//! counterpart — a tray-only process is already the default there — so both
//! are no-ops off macOS.
//!
//! [`system_dark_theme`] is the exception: both platforms answer it, from
//! their own settings store, because the tray widget is drawn by this app and
//! has to be drawn for the background it will land on.

/// Make the app a menu-bar accessory (equivalent to `LSUIElement`).
/// Safe to call after the event loop has started; it overrides the Regular
/// policy winit sets up by default.
///
/// In *dock mode* (see [`dock_mode`]) this deliberately does nothing, so the
/// process keeps winit's Regular policy and stays reachable from the Dock.
#[cfg(target_os = "macos")]
pub fn set_accessory_policy() {
    if dock_mode() {
        return;
    }
    use objc::runtime::Object;
    use objc::{class, msg_send, sel, sel_impl};
    // NSApplicationActivationPolicyAccessory = 1
    const ACCESSORY: i64 = 1;
    // SAFETY: `sharedApplication` either returns the process-wide singleton
    // or nil, never a dangling pointer, and the nil case is checked before
    // the second message is sent; `setActivationPolicy:` takes a plain
    // integer, no buffer for either side to misjudge the length of.
    unsafe {
        let app: *mut Object = msg_send![class!(NSApplication), sharedApplication];
        if !app.is_null() {
            let _: () = msg_send![app, setActivationPolicy: ACCESSORY];
        }
    }
}

/// Dock-mode escape hatch.
///
/// The menu-bar item is not guaranteed to be reachable: when the bar has no
/// room left (common on notched laptops with a full bar) macOS silently drops
/// the status item — every API still reports it as created and visible, and
/// there is no overflow affordance to reveal it. A tray-only app is then
/// completely unusable. Dock mode keeps the Regular activation policy so the
/// panel is always reachable from the Dock and the app switcher.
///
/// It *adds* that way in rather than replacing the menu bar: the status item
/// is still created, since when the bar does have room the item is where this
/// app's numbers live. macOS offers no way to ask whether an item was dropped
/// — `isVisible` answers what was asked for, not what is drawn — so which of
/// the two is currently reachable is the user's call, not a guess this makes.
///
/// `TICKOVER_DOCK` writes the persisted setting rather than only applying
/// to the current run: enabling it needs a launch environment precisely when
/// the menu bar is unusable, so a one-shot flag would have to be re-passed on
/// every launch. `TICKOVER_DOCK=0` turns it back off the same way.
pub fn dock_mode() -> bool {
    if let Some(v) = std::env::var_os("TICKOVER_DOCK") {
        let on = v != "0";
        if crate::config::dock_mode() != on {
            crate::config::set_dock_mode(on);
        }
        return on;
    }
    crate::config::dock_mode()
}

// ── Single instance ───────────────────────────────────────────────────────
//
// Two copies of a tray app are two identical pills in the menu bar, each with
// its own poll timer — so every provider is asked twice as often as its
// manifest says, and the auto-ping's on-disk bookkeeping is read-modify-written
// by two processes that never see each other's decisions. Launching twice is
// easy to do by accident: the bundle from Finder while a `cargo run` is up, or
// a second click on an app whose only window is a popover.
//
// The claim is a lock **held for the life of the process** on a file beside
// `config.json`, which the OS releases however the process ends — crash and
// kill included, so there is no stale lock to clean up and no pid to
// second-guess. The two implementations differ only in which OS call refuses
// the second opener.

/// Path of the lock file. Beside `config.json`, in the app's own config dir —
/// asked of `config` rather than re-derived, so the two can't drift apart.
fn instance_lock_path() -> Option<std::path::PathBuf> {
    let dir = crate::config::dir()?;
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join("instance.lock"))
}

/// Another copy of this app already holds the single-instance lock.
pub struct AlreadyRunning;

/// Path of the note a losing launch leaves for the running instance.
fn show_request_path() -> Option<std::path::PathBuf> {
    Some(crate::config::dir()?.join("show-panel"))
}

/// Leave that note. Called by the copy that is about to exit: it cannot show a
/// window itself, but the click that launched it still deserves an answer.
///
/// A file rather than a signal or a socket, because the running instance
/// already looks at the filesystem once a second and this needs nothing else
/// to exist — a same-user channel, exactly as private as `config.json`
/// itself, not a cross-user one. Best-effort: a note that can't be written
/// costs a panel that doesn't open, which is what would have happened
/// anyway.
///
/// `create_new`, never `std::fs::write`'s `create().truncate()`: the path is
/// predictable, and `write` follows a symlink anything running as this user
/// could have left there, truncating whatever it points at instead of
/// leaving the note. `create_new` refuses to touch anything already at the
/// path — a symlink, or simply a note [`take_show_request`] hasn't consumed
/// yet — rather than write through or over it; either way the outcome is
/// the same as any other failure here, a panel that doesn't open this once.
pub fn leave_show_request() {
    let Some(path) = show_request_path() else {
        return;
    };
    leave_show_request_at(&path);
}

/// [`leave_show_request`]'s own logic against an explicit path — split out
/// so it has a test: `show_request_path` resolves through
/// `crate::config::dir`, which has no test override (unlike, say,
/// `diag::path`), so the public function itself can't be called from a test
/// without touching whatever config directory `cargo test` happens to run
/// under.
fn leave_show_request_at(path: &std::path::Path) {
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path);
}

/// Take that note if one is there, removing it. False when there is none.
///
/// Removed before it is acted on, so a panel that fails to open doesn't leave
/// a note that opens one on every tick from then on.
pub fn take_show_request() -> bool {
    let Some(path) = show_request_path() else {
        return false;
    };
    // `remove_file` both tests and takes it, in one step that two readers
    // cannot both win.
    std::fs::remove_file(path).is_ok()
}

/// What one attempt at the lock came to.
enum Claim {
    /// Ours; the file must stay open for as long as the app runs.
    Held(std::fs::File),
    /// Another process holds it.
    Taken,
    /// Neither could be established — the file wouldn't open at all.
    Unknown,
}

/// `flock(LOCK_EX | LOCK_NB)`: held until the descriptor closes, which the
/// kernel does for us when the process ends however it ends — crash and kill
/// included, so there is never a stale lock to clear.
#[cfg(unix)]
fn claim_instance_lock(path: &std::path::Path) -> Claim {
    use std::os::unix::io::AsRawFd;

    let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
    else {
        return Claim::Unknown;
    };
    // SAFETY: `file` owns a valid descriptor for the whole call, and `flock`
    // only reads it.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Claim::Held(file);
    }
    // Only "someone else holds it" means a second instance. A filesystem that
    // doesn't implement locking at all must not stop the app from starting.
    match std::io::Error::last_os_error().kind() {
        std::io::ErrorKind::WouldBlock => Claim::Taken,
        _ => Claim::Unknown,
    }
}

/// Opened with no sharing at all, so a second process's open fails outright —
/// Windows' equivalent of the advisory lock above, released by the same handle
/// close.
#[cfg(windows)]
fn claim_instance_lock(path: &std::path::Path) -> Claim {
    use std::os::windows::fs::OpenOptionsExt;

    const ERROR_SHARING_VIOLATION: i32 = 32;
    let open = || {
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .share_mode(0)
            .open(path)
    };
    match open() {
        Ok(file) => return Claim::Held(file),
        Err(e) if e.raw_os_error() != Some(ERROR_SHARING_VIOLATION) => return Claim::Unknown,
        Err(_) => {}
    }
    // A sharing violation is how the other instance's claim shows up — and
    // also how an antivirus or indexer that opened this file for a moment
    // shows up. Since the two are indistinguishable, and refusing to start is
    // the worse mistake, ask once more after the moment has passed. One retry
    // at a fixed 300ms is a guess, not a guarantee: a scanner that still holds
    // the file past that window reads exactly like a second instance and this
    // launch exits, same as if it really were one — the failure mode this
    // trades against (refusing to start at all rather than risk two copies
    // racing the same on-disk state) is judged the worse of the two.
    std::thread::sleep(std::time::Duration::from_millis(300));
    match open() {
        Ok(file) => Claim::Held(file),
        Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => Claim::Taken,
        Err(_) => Claim::Unknown,
    }
}

/// Claim this machine's single-instance slot.
///
/// `Ok(guard)` — this process may run. **The guard must be kept alive for as
/// long as the app does**; dropping it releases the claim, so callers hold it
/// in `main`'s own scope. It is `None` when no lock could be taken for a reason
/// other than a second instance (no config directory, a filesystem without
/// locking): being unable to *prove* another copy exists is not evidence that
/// one does, and an indicator that refuses to launch is worse than two of them.
///
/// `Err(AlreadyRunning)` — another copy holds the lock and this one should
/// exit.
pub fn claim_single_instance() -> Result<Option<std::fs::File>, AlreadyRunning> {
    let Some(path) = instance_lock_path() else {
        crate::diag::line(
            "single instance: no config directory to lock in — not checking".to_string(),
        );
        return Ok(None);
    };
    match claim_instance_lock(&path) {
        Claim::Held(file) => Ok(Some(file)),
        Claim::Taken => Err(AlreadyRunning),
        // Said out loud rather than assumed: this is the branch where two
        // copies can end up running, and the log is where that gets explained
        // afterwards.
        Claim::Unknown => {
            crate::diag::line(format!(
                "single instance: could not lock {} — a second copy would not be noticed",
                path.display()
            ));
            Ok(None)
        }
    }
}

/// Whether this process is the frontmost application.
///
/// Clicking a running app's Dock icon is delivered as an app-level reopen,
/// which the winit event loop never surfaces; watching this flag's rising edge
/// is what lets dock mode bring a hidden panel back.
#[cfg(target_os = "macos")]
pub fn app_is_active() -> bool {
    use objc::runtime::{Object, BOOL, NO};
    use objc::{class, msg_send, sel, sel_impl};
    // SAFETY: `sharedApplication` either returns the process-wide singleton
    // or nil, never a dangling pointer, and the nil case is checked before
    // `isActive` is sent to it; `isActive` takes no arguments to mismatch.
    unsafe {
        let app: *mut Object = msg_send![class!(NSApplication), sharedApplication];
        if app.is_null() {
            return false;
        }
        let active: BOOL = msg_send![app, isActive];
        active != NO
    }
}

#[cfg(not(target_os = "macos"))]
pub fn app_is_active() -> bool {
    false
}

/// Dock-icon clicks seen by the reopen handler; drained by
/// [`take_reopen_requests`]. A count rather than a flag: each click is a
/// toggle, so two clicks arriving inside one poll interval must not collapse
/// into one or the panel ends up in the opposite state to what was asked for.
static REOPEN_REQUESTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Number of Dock-icon clicks since the last call.
pub fn take_reopen_requests() -> usize {
    REOPEN_REQUESTS.swap(0, std::sync::atomic::Ordering::SeqCst)
}

#[cfg(target_os = "macos")]
extern "C" fn on_reopen(
    _this: &objc::runtime::Object,
    _cmd: objc::runtime::Sel,
    _sender: *mut objc::runtime::Object,
    _has_visible_windows: objc::runtime::BOOL,
) -> objc::runtime::BOOL {
    REOPEN_REQUESTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    // NO: the panel's visibility is ours to decide, so don't let AppKit also
    // unminimise/order windows in on our behalf.
    objc::runtime::NO
}

/// The ObjC type-encoding string for `on_reopen`'s signature, handed to
/// `class_addMethod` below. It has to name `BOOL`'s *actual* encoding, and
/// that differs by architecture: `objc::runtime::BOOL` is `bool` (encoding
/// `B`) on aarch64, matching Apple's own ABI change for arm64, and `c_schar`
/// (encoding `c`) everywhere else — this picks the one that matches the
/// `BOOL` this file actually compiles against, for both the return value and
/// the `hasVisibleWindows` argument.
#[cfg(target_os = "macos")]
const REOPEN_METHOD_TYPES: &std::ffi::CStr = if cfg!(target_arch = "aarch64") {
    c"B@:@B"
} else {
    c"c@:@c"
};

/// Teach the app delegate to report Dock-icon clicks.
///
/// `isActive` only changes on the *first* click, so it cannot drive a toggle:
/// clicking the icon of an already-frontmost app produces no state change at
/// all. AppKit does send `applicationShouldHandleReopen:hasVisibleWindows:`
/// every time, so add that selector to whatever delegate class winit
/// installed. This adds a *method* to an existing class — it does not register
/// a new ObjC class, so it cannot reproduce the duplicate-class abort that the
/// tray-icon/muda pairing is pinned to avoid. If the delegate already
/// implements the selector, `class_addMethod` reports failure and nothing is
/// overwritten.
///
/// Returns whether the handler is in place (false while winit has yet to set a
/// delegate, so callers should retry).
#[cfg(target_os = "macos")]
pub fn install_reopen_handler() -> bool {
    use objc::runtime::{Class, Object, BOOL};
    use objc::{class, msg_send, sel, sel_impl};
    // SAFETY: every `msg_send!` below checks its receiver for null before the
    // next one uses it. The `transmute` turns `on_reopen`'s function-pointer
    // type into `objc::runtime::Imp`; that is sound because `on_reopen`'s
    // `extern "C"` signature matches `REOPEN_METHOD_TYPES` argument for
    // argument, and the pointer stays valid for as long as the class exists
    // because `on_reopen` is a `'static` item, not a value this stack frame
    // owns.
    unsafe {
        let app: *mut Object = msg_send![class!(NSApplication), sharedApplication];
        if app.is_null() {
            return false;
        }
        let delegate: *mut Object = msg_send![app, delegate];
        if delegate.is_null() {
            return false;
        }
        let cls: *mut Class = msg_send![delegate, class];
        if cls.is_null() {
            return false;
        }
        // `class_addMethod`'s own return says whether it added the method or
        // found the selector already implemented, but this function has
        // nothing different to do either way — the handler responds to
        // reopen either because this call just installed it or because it
        // was already there — so the result is not read.
        //
        // Adding the selector *after* winit has assigned the delegate is fine:
        // AppKit resolves this one at call time rather than caching the
        // delegate's capabilities at `setDelegate:`. Verified on macOS 26.2 by
        // instrumenting both ends — the delegate is winit's
        // `WinitApplicationDelegate`, `class_addMethod` returns true,
        // `respondsToSelector:` is true afterwards, and the handler is entered
        // on a real reopen. So no delegate reassignment is needed here.
        let _: BOOL = objc::runtime::class_addMethod(
            cls,
            sel!(applicationShouldHandleReopen:hasVisibleWindows:),
            std::mem::transmute::<
                extern "C" fn(&Object, objc::runtime::Sel, *mut Object, BOOL) -> BOOL,
                objc::runtime::Imp,
            >(on_reopen),
            REOPEN_METHOD_TYPES.as_ptr(),
        );
        true
    }
}

#[cfg(not(target_os = "macos"))]
pub fn install_reopen_handler() -> bool {
    true
}

/// Bring the app forward so the just-shown popover can become key window.
#[cfg(target_os = "macos")]
pub fn activate_app() {
    use objc::runtime::{Object, YES};
    use objc::{class, msg_send, sel, sel_impl};
    // SAFETY: `sharedApplication` either returns the process-wide singleton
    // or nil, never a dangling pointer, and the nil case is checked before
    // `activateIgnoringOtherApps:` is sent to it; the argument is a plain
    // `BOOL` constant, no buffer to misjudge the length of.
    unsafe {
        let app: *mut Object = msg_send![class!(NSApplication), sharedApplication];
        if !app.is_null() {
            let _: () = msg_send![app, activateIgnoringOtherApps: YES];
        }
    }
}

/// Whether the system (and hence the menu bar) is in dark appearance.
/// Reads `AppleInterfaceStyle` from the user defaults — set to "Dark" in dark
/// mode, absent in light mode. Cheap enough to poll.
#[cfg(target_os = "macos")]
pub fn system_dark_theme() -> bool {
    use objc::runtime::Object;
    use objc::{class, msg_send, sel, sel_impl};
    // SAFETY: `standardUserDefaults` either returns the process-wide
    // singleton or nil, never a dangling pointer, and the nil case is
    // checked before it is used; `c"AppleInterfaceStyle".as_ptr()` is a
    // NUL-terminated static string, exactly what `stringWithUTF8String:`
    // requires, so `key` is a valid string object; the final `style`
    // pointer is only null-tested, never dereferenced.
    unsafe {
        let defaults: *mut Object = msg_send![class!(NSUserDefaults), standardUserDefaults];
        if defaults.is_null() {
            return true;
        }
        let key: *mut Object = msg_send![
            class!(NSString),
            stringWithUTF8String: c"AppleInterfaceStyle".as_ptr()
        ];
        let style: *mut Object = msg_send![defaults, stringForKey: key];
        !style.is_null()
    }
}

/// Whether the system (and hence the taskbar the tray icon is drawn onto) is
/// in dark appearance.
///
/// `SystemUsesLightTheme`, not `AppsUseLightTheme`: Windows tracks the two
/// separately, and someone running dark apps on a light taskbar (or the
/// reverse — both are one click apart in Settings) would otherwise get a
/// widget rendered for the wrong background, which for a dark-on-dark pill is
/// the difference between readable and invisible. The value the taskbar
/// follows is the system one.
///
/// A missing value reads as dark, matching the taskbar's own out-of-the-box
/// appearance. Cheap enough to poll, which is what the caller does — so a
/// theme switched while the app is running is picked up on the next tick
/// rather than at the next launch.
#[cfg(target_os = "windows")]
pub fn system_dark_theme() -> bool {
    use windows::core::w;
    use windows::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD};

    let mut value: u32 = 0;
    let mut size = std::mem::size_of::<u32>() as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            w!(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"),
            w!("SystemUsesLightTheme"),
            RRF_RT_REG_DWORD,
            None,
            Some(std::ptr::addr_of_mut!(value).cast()),
            Some(&mut size),
        )
    };
    // Anything other than a DWORD that was actually read leaves `value`
    // untouched, so the answer has to come from the status, not from it.
    match status.is_ok() {
        true => value == 0,
        false => true,
    }
}

#[cfg(not(target_os = "macos"))]
pub fn set_accessory_policy() {}

#[cfg(not(target_os = "macos"))]
pub fn activate_app() {}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn system_dark_theme() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::leave_show_request_at;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tickover-platform-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn leave_show_request_creates_a_fresh_note() {
        let dir = temp_dir("fresh");
        let path = dir.join("show-panel");
        leave_show_request_at(&path);
        assert!(path.is_file());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg(unix)]
    fn leave_show_request_never_writes_through_a_symlink_planted_at_the_note_path() {
        // The gap this closes: `std::fs::write` follows a symlink, so a link
        // planted at the predictable "show-panel" path — by anything running
        // as this user — would have its *target* truncated instead of the
        // note being left, the target being whatever file that symlink
        // happens to point at.
        let dir = temp_dir("symlink");
        let target = dir.join("elsewhere");
        std::fs::write(&target, "do not touch").unwrap();
        let link = dir.join("show-panel");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        leave_show_request_at(&link);

        assert!(link.is_symlink(), "the symlink itself must survive");
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "do not touch",
            "and never written through"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn leave_show_request_does_not_error_when_a_note_is_already_there() {
        // A note `take_show_request` hasn't consumed yet is not a failure —
        // there is already something for the running instance to find.
        let dir = temp_dir("already-there");
        let path = dir.join("show-panel");
        leave_show_request_at(&path);
        leave_show_request_at(&path); // must not panic, must not remove it
        assert!(path.is_file());
        std::fs::remove_dir_all(&dir).ok();
    }
}
