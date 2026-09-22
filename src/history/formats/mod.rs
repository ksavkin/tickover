//! Per-format extractors, selected by `[history] format` in the manifest.
//!
//! Each extractor turns bytes from a provider's local history files into
//! [`UsageRecord`]s. Format-specific correctness rules (dedup keys,
//! cumulative-counter diffing, sub-agent filtering) live here and only
//! here — the scanner feeds bytes, the store keeps aggregates, and the
//! manifest names the format; none of them knows what a line looks like.

pub mod antigravity;
pub mod claude;
pub mod codex;
pub mod grok;

use std::io;
use std::path::Path;
use std::time::Instant;

use crate::history::UsageRecord;
use crate::plugin::manifest::HistoryFormat;

/// What one extraction pass over a file produced.
#[derive(Debug, Default)]
pub struct Extraction {
    /// Usage records found, in file order.
    pub records: Vec<UsageRecord>,
    /// The new cursor position — a byte offset for line formats, a
    /// timestamp watermark for SQLite. Only ever advances on success.
    pub cursor: u64,
    /// Lines/records that looked like they should carry usage but did not
    /// parse — the format-drift observability counter.
    pub skipped_unparsed: u64,
}

/// One history format's parser. Implemented per provider file shape; the
/// scanner calls it only for files whose signature changed.
pub trait HistoryExtractor: Send + Sync {
    /// Extract usage records from `path`, resuming at `st.cursor` (byte
    /// offset for JSONL formats, ms-timestamp watermark for SQLite),
    /// reading at most `byte_cap` new bytes and stopping at `deadline`.
    /// `st.aux` is the format's own persisted scratch space (cumulative
    /// baselines and the like); `st.recent_ids`/`st.gen` are the scanner's.
    ///
    /// Must never write to `path` — provider files are read-only.
    fn extract(
        &self,
        path: &Path,
        st: &mut crate::history::store::FileState,
        byte_cap: u64,
        deadline: Instant,
    ) -> io::Result<Extraction>;
}

/// The extractor a manifest's `[history] format` selects.
pub fn extractor_for(format: HistoryFormat) -> Box<dyn HistoryExtractor> {
    match format {
        HistoryFormat::ClaudeTranscripts => Box::new(claude::ClaudeExtractor),
        HistoryFormat::CodexRollouts => Box::new(codex::CodexExtractor),
        HistoryFormat::GrokUnified => Box::new(grok::GrokExtractor),
        HistoryFormat::AntigravitySqlite => Box::new(antigravity::AntigravityExtractor),
    }
}

/// Read `path` starting at byte `offset`, at most `cap` bytes, and cut the
/// buffer at the last complete `\n` — the torn tail a writer is still
/// appending stays unconsumed for the next pass. Returns `(complete_bytes,
/// cursor)` where `cursor` is `offset + complete_bytes.len()`.
fn read_new_lines(path: &Path, offset: u64, cap: u64) -> io::Result<(Vec<u8>, u64)> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = fs_open_readonly(path)?;
    if offset > 0 {
        f.seek(SeekFrom::Start(offset))?;
    }
    let mut buf = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    let mut remaining = cap;
    while remaining > 0 {
        let want = remaining.min(chunk.len() as u64) as usize;
        let n = f.read(&mut chunk[..want])?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        remaining -= n as u64;
    }
    // Keep only complete lines: the cursor stops at the last newline, so a
    // torn tail is re-read next pass rather than parsed half-written.
    let complete = match buf.iter().rposition(|&b| b == b'\n') {
        Some(pos) => pos + 1,
        None => 0,
    };
    buf.truncate(complete);
    Ok((buf, offset + complete as u64))
}

/// Open a provider file read-only with the same FIFO/device guard the rest
/// of the app uses (`O_NONBLOCK` on unix, plain `File::open` elsewhere).
fn fs_open_readonly(path: &Path) -> io::Result<std::fs::File> {
    let mut oo = std::fs::OpenOptions::new();
    oo.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        oo.custom_flags(libc::O_NONBLOCK);
    }
    oo.open(path)
}

/// `cwd` → project basename (`"unknown"` when absent/empty).
fn project_basename(cwd: Option<&str>) -> String {
    cwd.and_then(|c| {
        Path::new(c)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
    })
    .filter(|s| !s.is_empty())
    .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
pub(crate) mod testutil {
    //! A per-test temp dir that deletes itself on drop — extractors read
    //! real files, so fixtures are real files too.
    use std::path::{Path, PathBuf};

    pub struct TmpDir(pub PathBuf);

    impl TmpDir {
        pub fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "tickover-hist-{tag}-{}-{:?}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            TmpDir(dir)
        }

        pub fn write(&self, name: &str, content: &str) -> PathBuf {
            let p = self.0.join(name);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&p, content).unwrap();
            p
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    impl AsRef<Path> for TmpDir {
        fn as_ref(&self) -> &Path {
            &self.0
        }
    }
}
