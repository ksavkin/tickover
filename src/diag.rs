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

// Only `append_to_log` needs `Write::write_all` now that `trim_if_large`
// goes through `write_via_temp` instead — and that fn is compiled out
// under `cargo test` (see its own doc), so this import would be too.
#[cfg(not(test))]
use std::io::Write;

/// Size at which the log is trimmed.
const MAX_BYTES: u64 = 64 * 1024;
/// How much of the tail survives a trim. Trimming keeps the *end*: the last
/// thing that happened is what a diagnostic is read for.
const KEEP_BYTES: usize = 32 * 1024;

/// Only [`append_to_log`] resolves this, and that is compiled out under
/// `cargo test` — the whole point being that a test run must not find, let
/// alone append to, the real log (see [`line`](fn@line)).
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
///
/// `message` often carries text this app didn't write itself — a manifest's
/// own strings (a header name, a `[ping] args` entry, a client's own
/// discovered id), or an error `{e}`-formatted from one. [`escape_control_chars`]
/// runs on it first: both sinks below are read one line per line, and a raw
/// `\n`/`\r` in `message` would otherwise print as more than one line, one of
/// them made to look like a diagnostic this app never actually emitted.
pub fn line(message: String) {
    let message = escape_control_chars(&message);
    eprintln!("[tickover] {message}");
    // The tests below drive `trim_if_large` against their own temp files, which
    // is the part worth testing; what is skipped here is only the choice of
    // *where* an unsandboxed line would land.
    #[cfg(not(test))]
    append_to_log(&message);
    #[cfg(test)]
    RECORDED.with(|r| r.borrow_mut().push(message));
}

/// The sixteen hex digits, indexed by nibble — every `\xHH` escape below
/// needs exactly two of these and nothing wider, so a lookup replaces a
/// `format!` call (its own throwaway `String`, allocated and discarded) for
/// every control character a manifest or an error message happens to carry.
const HEX_NIBBLES: [u8; 16] = *b"0123456789abcdef";

/// Escape every C0 control character (`\n`/`\r` spelled out, everything else
/// `\xHH`) in `message` — see [`line`](fn@line)'s own doc for why. DEL (`\u{7F}`) is
/// folded in with C0 for the same reason: neither is printable, and a stray
/// one is exactly as capable of confusing a line-oriented reader.
fn escape_control_chars(message: &str) -> String {
    let mut escaped = String::with_capacity(message.len());
    for c in message.chars() {
        match c as u32 {
            0x0A => escaped.push_str("\\n"),
            0x0D => escaped.push_str("\\r"),
            n @ (0x00..=0x1F | 0x7F) => {
                escaped.push_str("\\x");
                escaped.push(HEX_NIBBLES[(n >> 4) as usize] as char);
                escaped.push(HEX_NIBBLES[(n & 0xF) as usize] as char);
            }
            _ => escaped.push(c),
        }
    }
    escaped
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
    // A poisoned lock still guards the file; a panic elsewhere must not be
    // what stops this app from recording anything ever again.
    let _writing = WRITING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    trim_if_large(&path);
    let open = |path: &std::path::Path| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    };
    // The directory is created lazily, only once `open` says it isn't there
    // (`NotFound` covers both "the log file is missing" and "the whole
    // directory is") — not on every line this function writes, which is
    // every one of them for as long as the process runs after the first.
    let opened = match open(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            open(&path)
        }
        result => result,
    };
    if let Ok(mut file) = opened {
        let _ = file.write_all(stamped.as_bytes());
    }
}

/// Drop the head of the log once it grows past [`MAX_BYTES`], keeping roughly
/// the last [`KEEP_BYTES`] from the first line boundary inside them — so the
/// file never grows without bound and never starts mid-line.
///
/// Called before every line this app ever writes, but the [`KEEP_BYTES`]
/// tail read only happens on the line that finds the file already over
/// [`MAX_BYTES`] — every other call stops after the one cheap `metadata`
/// call in the body, because trimming drops the file back under that
/// threshold, so it takes another `MAX_BYTES - KEEP_BYTES` worth of lines
/// before the next one trips it again. When it does trip, this reads only
/// the tail — seeking to `len - KEEP_BYTES` rather than `std::fs::read`ing
/// the whole file — so even that one line never pays for the whole
/// (ever-growing) file.
///
/// Written through `tickover::plugin::write_via_temp`, the same shared
/// temp-then-rename [`crate::config`]'s own writes go through: a
/// truncate-in-place interrupted half-way would leave the log unreadable,
/// which is the one thing a log must not become.
fn trim_if_large(path: &std::path::Path) {
    use std::io::{Read, Seek};
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    let len = meta.len();
    if len <= MAX_BYTES {
        return;
    }
    let cut = len.saturating_sub(KEEP_BYTES as u64);
    let Ok(mut file) = std::fs::File::open(path) else {
        return;
    };
    if file.seek(std::io::SeekFrom::Start(cut)).is_err() {
        return;
    }
    let mut tail = Vec::new();
    if file.read_to_end(&mut tail).is_err() {
        return;
    }
    // From the byte after the next newline, so the first surviving line is
    // whole. With no newline anywhere in the tail — one pathological line
    // longer than the whole keep size — cut at the keep size regardless
    // rather than leaving the file alone: a half line at the very start of
    // what survives is worse to read than the rest of the log, but a file
    // this function can never shrink is worse still — every future write
    // would re-read the same oversized, still-growing tail from here on,
    // for good, since nothing about a line-less tail ever changes that on
    // its own. The same answer covers the edge where the tail's *only*
    // newline is its last byte: `position + 1` would then land on
    // `tail.len()`, cutting the whole tail to nothing and writing an empty
    // log — strictly worse than the half line, and no more "on a boundary"
    // than it, so the tail is kept instead.
    let start = tail
        .iter()
        .position(|b| *b == b'\n')
        .filter(|i| i + 1 < tail.len())
        .map_or(0, |i| i + 1);
    // Best-effort, like every other write in this module (see the module
    // doc): a trim that fails half-way is worth leaving the oversized file
    // in place for, not worth failing an app launch over.
    let _ = tickover::plugin::write_via_temp(path, &tail[start..], |_| Ok(()));
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

    /// One line longer than the whole keep size leaves nothing to cut *on a
    /// line boundary* — but the file still has to shrink, or every future
    /// write re-reads the same oversized tail forever. Renamed from
    /// `trim_leaves_a_log_with_no_line_boundary_alone`, whose own name and
    /// body described the opposite of what `trim_if_large` does now: that
    /// version was never reachable from [`line`] at all (nothing this app
    /// writes produces a line-less log short of a synthetic fixture exactly
    /// like this one), and left unbounded, it was an unbounded re-read on
    /// every log line once triggered.
    #[test]
    fn trim_cuts_at_keep_bytes_even_with_no_line_boundary_in_the_tail() {
        let dir = temp_dir("noboundary");
        let path = dir.join("tickover.log");
        let one_huge_line = "x".repeat(MAX_BYTES as usize + 4096);
        std::fs::write(&path, &one_huge_line).expect("seed log");
        trim_if_large(&path);
        let after = std::fs::read(&path).expect("still there");
        assert_eq!(
            after.len(),
            KEEP_BYTES,
            "cut at the keep size, not left growing forever"
        );
        assert!(
            one_huge_line.as_bytes().ends_with(&after),
            "what survives is still the tail of what was there"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The tail's only newline sitting on its last byte must not leave an
    /// empty log behind: nothing after it exists to keep, so the whole tail
    /// is kept — same as a tail with no newline at all.
    #[test]
    fn trim_keeps_the_tail_when_its_only_newline_is_the_last_byte() {
        let dir = temp_dir("lastbyte");
        let path = dir.join("tickover.log");
        // Head: ordinary lines that will be cut. Tail (the last KEEP_BYTES):
        // one huge line with a newline only at its very end.
        let head = "earlier line\n".repeat(4096);
        let tail_line = format!("{}\n", "x".repeat(KEEP_BYTES - 1));
        let text = format!("{head}{tail_line}");
        std::fs::write(&path, &text).expect("seed log");
        trim_if_large(&path);
        let after = std::fs::read(&path).expect("still there");
        assert_eq!(after, tail_line.as_bytes(), "the whole tail survives");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn trim_is_a_no_op_when_there_is_no_log_yet() {
        let dir = temp_dir("absent");
        trim_if_large(&dir.join("tickover.log")); // must not panic
        assert!(!dir.join("tickover.log").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn escape_control_chars_spells_out_newline_and_carriage_return() {
        assert_eq!(
            escape_control_chars("first\nsecond\rthird"),
            "first\\nsecond\\rthird"
        );
    }

    #[test]
    fn escape_control_chars_hex_escapes_every_other_c0_control_and_del() {
        assert_eq!(escape_control_chars("bell\x07here"), "bell\\x07here");
        assert_eq!(escape_control_chars("tab\there"), "tab\\x09here");
        assert_eq!(escape_control_chars("del\x7fhere"), "del\\x7fhere");
    }

    #[test]
    fn escape_control_chars_leaves_ordinary_text_untouched() {
        assert_eq!(
            escape_control_chars("plain diagnostic text, 100% fine"),
            "plain diagnostic text, 100% fine"
        );
    }

    #[test]
    fn line_escapes_control_characters_so_one_call_cannot_forge_extra_log_lines() {
        // A manifest string (or an error formatted from one) reaching `line`
        // could carry a real `\n` of its own — without the escape, one call
        // here would print as more than one line, one of them made to look
        // like a diagnostic this app never actually emitted.
        take_recorded(); // drain whatever an earlier test on this thread left
        line("legit line\nFAKE: pretend this is a different diagnostic".to_string());
        assert_eq!(
            take_recorded(),
            vec!["legit line\\nFAKE: pretend this is a different diagnostic".to_string()]
        );
    }
}
