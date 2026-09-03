fn main() {
    // Compile the Slint UI. `app.slint` imports theme.slint + widgets.slint and
    // references the bundled fonts/images under ../assets relative to ui/.
    slint_build::compile("ui/app.slint").expect("failed to compile Slint UI");

    #[cfg(windows)]
    embed_windows_icon();
}

/// Give the binary its own Win32 icon resource.
///
/// macOS carries the icon in the bundle `make-app.sh` builds; a bare Windows
/// .exe carries it inside the file or not at all, and "not at all" is the
/// generic grey placeholder — in Explorer, in the Alt-Tab list, on the
/// taskbar button in dock mode, and on every message box the app raises. The
/// same `assets/app-icon.ico` the packaging notes point at, embedded at build
/// time instead of left as a step to do by hand.
///
/// Best-effort: a resource compiler that isn't there fails the *resource*,
/// not the build. An .exe with a placeholder icon still runs, and refusing to
/// produce one over a cosmetic detail would be the worse trade.
#[cfg(windows)]
fn embed_windows_icon() {
    println!("cargo:rerun-if-changed=assets/app-icon.ico");
    let mut res = winresource::WindowsResource::new();
    res.set_icon("assets/app-icon.ico");
    if let Err(e) = res.compile() {
        println!("cargo:warning=could not embed the app icon: {e}");
    }
}
