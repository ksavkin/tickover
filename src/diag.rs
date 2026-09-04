//! Where this app's own diagnostics go.
//!
//! Everything here used to be an `eprintln!`, which is fine for a binary run
//! from a terminal and useless where this app actually runs: an `.app`
//! launched from Finder has no stderr anyone reads — not Console, not the
//! unified log, nowhere. That gap is not theoretical. The Codex auto-ping
//! failed on every single attempt for two separate reasons, printed a reason
//! each time, and still looked exactly like a feature that had never run.
//!
//! So each line goes to **both**: stderr, for the terminal case, and a file
//! beside `config.json`, for every other case.
//!
//! Best-effort throughout, like [`crate::config`]: a diagnostic that cannot be
//! written is not worth failing an app launch over, so every error here is
//! swallowed. Nothing sensitive is written — tokens are never handed to this
//! module, and the app never logs one anywhere (see the security section of
//! `docs/PLUGIN-ARCHITECTURE.md`).

use std::io::Write;

/// Size at which the log is trimmed.
const MAX_BYTES: u64 = 64 * 1024;
/// How much of the tail survives a trim. Trimming keeps the *end*: the last
/// thing that happened is what a diagnostic is read for.
const KEEP_BYTES: usize = 32 * 1024;

/// Only [`append_to_log`] resolves this, and that is compiled out under
/// `cargo test` — the whole point being that a test run must not find, let
/// alone append to, the real log (see [`line`]).
#[cfg(not(test))]
fn path() -> Option<std::path::PathBuf> {
    Some(crate::config::dir()?.join("tickover.log"))
}

/// Serializes trim-then-append across this process's threads. Without it, one
/// thread can be appending to the file another thread is in the middle of
/// replacing — and the append lands in an inode nothing points at any more,
/// which is a log line that was written and then silently wasn't. Between
/// *processes* the same race is closed by there only ever being one (see
/// `platform::claim_single_instance`).
///
/// Guards [`append_to_log`] only, which is compiled out under `cargo test`.
#[cfg(not(test))]
static WRITING: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Record one line: stderr, and the log file.
///
/// **Under `cargo test`, stderr only.** The path comes from
/// [`crate::config::dir`], which has no test override — so a test that reaches
/// any code calling this used to append to the *running app's* live log, in the
/// real config directory. That is not merely untidy: `dedup_plugin_ids`'s own
/// test builds two manifests both claiming the id `codex`, so every test run
/// wrote `duplicate id "codex" … loaded set was [codex, codex]` into the log a
/// user reads. It was investigated as a real defect of the running app, twice,
/// and a diagnostic commit was written to chase it. The app never did it.
pub fn line(message: String) {
    eprintln!("[tickover] {message}");
    // The tests below drive `trim_if_large` against their own temp files, which
    // is the part worth testing; what is skipped here is only the choice of
    // *where* an unsandboxed line would land.
    #[cfg(not(test))]
    append_to_log(&message);
    #[cfg(test)]
    RECORDED.with(|r| r.borrow_mut().push(message));
}

// What [`line`] was called with on this thread, under `cargo test` only.
//
// Without it, "this branch writes a log line" is not a testable claim: the
// file half of `line` is compiled out here, so a test can watch a branch take
// effect only if the branch *also* does something else. That is what pushed
// `upgrade_builtin_manifests` into returning its own notes for a while — a
// test hook wearing a production signature, for want of this.
//
// Thread-local and drained, for the same reason `crate::config`'s scratch path
// is thread-local: one `#[test]` is one thread, so nothing another test logged
// can appear in this one's answer.
#[cfg(test)]
thread_local! {
    /// Lines `line` was handed on this thread since the last drain.
    static RECORDED: std::cell::RefCell<Vec<String>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

/// Take (and clear) the lines [`line`] recorded on this thread.
#[cfg(test)]
pub fn take_recorded() -> Vec<String> {
    RECORDED.with(|r| std::mem::take(&mut *r.borrow_mut()))
}

#[cfg(not(test))]
fn append_to_log(message: &str) {
    let stamped = format!(
        "{} {message}\n",
        chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%:z")
    );
    let Some(path) = path() else { return };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // A poisoned lock still guards the file; a panic elsewhere must not be
    // what stops this app from recording anything ever again.
    let _writing = WRITING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    trim_if_large(&path);
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = file.write_all(stamped.as_bytes());
    }
}

/// Drop the head of the log once it grows past [`MAX_BYTES`], keeping roughly
/// the last [`KEEP_BYTES`] from the first line boundary inside them — so the
/// file never grows without bound and never starts mid-line.
///
/// Written through a temporary neighbour and renamed, the same way
/// [`crate::config`] writes: a truncate-in-place interrupted half-way would
/// leave the log unreadable, which is the one thing a log must not become.
fn trim_if_large(path: &std::path::Path) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    if meta.len() <= MAX_BYTES {
        return;
    }
    let Ok(bytes) = std::fs::read(path) else {
        return;
    };
    let cut = bytes.len().saturating_sub(KEEP_BYTES);
    // From the byte after the next newline at or past `cut`, so the first
    // surviving line is whole. With no newline in the tail at all — one
    // pathological line longer than the whole keep size — leave the file
    // alone: half a line is worse to read than an oversized log.
    let Some(offset) = bytes[cut..].iter().position(|b| *b == b'\n') else {
        return;
    };
    let start = cut + offset + 1;
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .and_then(|mut f| f.write_all(&bytes[start..]));
    if written.is_ok() {
        if std::fs::rename(&tmp, path).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    } else {
        let _ = std::fs::remove_file(&tmp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tickover-diag-{tag}-{}-{}",
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
    fn trim_keeps_the_tail_and_starts_on_a_line_boundary() {
        let dir = temp_dir("trim");
        let path = dir.join("tickover.log");
        // One line per 20 bytes, well past the trim threshold.
        let mut text = String::new();
        while text.len() as u64 <= MAX_BYTES + 4096 {
            text.push_str(&format!("line {:014}\n", text.len()));
        }
        std::fs::write(&path, &text).expect("seed log");
        trim_if_large(&path);

        let after = std::fs::read_to_string(&path).expect("still readable");
        assert!(
            after.len() <= KEEP_BYTES + 32,
            "trimmed to about the keep size"
        );
        assert!(
            after.starts_with("line "),
            "starts on a line boundary, not mid-line"
        );
        assert!(
            text.ends_with(after.as_str()),
            "what survives is the tail of what was there"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn trim_leaves_a_small_log_alone() {
        let dir = temp_dir("small");
        let path = dir.join("tickover.log");
        std::fs::write(&path, "one line\n").expect("seed log");
        trim_if_large(&path);
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "one line\n");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// One line longer than the whole keep size leaves nothing to cut on. Half
    /// a line is worse to read than an oversized log, so the file is left as
    /// it is rather than sliced mid-line.
    #[test]
    fn trim_leaves_a_log_with_no_line_boundary_alone() {
        let dir = temp_dir("noboundary");
        let path = dir.join("tickover.log");
        let one_huge_line = "x".repeat(MAX_BYTES as usize + 4096);
        std::fs::write(&path, &one_huge_line).expect("seed log");
        trim_if_large(&path);
        assert_eq!(
            std::fs::metadata(&path).expect("still there").len(),
            one_huge_line.len() as u64,
            "left alone rather than cut mid-line"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn trim_is_a_no_op_when_there_is_no_log_yet() {
        let dir = temp_dir("absent");
        trim_if_large(&dir.join("tickover.log")); // must not panic
        assert!(!dir.join("tickover.log").exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
