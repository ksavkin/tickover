//! Display-time grouping of history project names.
//!
//! Keeps `days.jsonl` raw and untouched while collapsing transient worktrees
//! and auto-ping scratch directories into their repository or shared label
//! when queried for the panel, CLI, or HTML report. Optional user overrides
//! live in `<config>/tickover/projects.toml` under `[aliases]`.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::history::store::HistoryStore;

/// Display name used for every transient auto-ping working directory.
pub const AUTO_PING_PROJECT: &str = "Tickover auto-ping";

/// Display name used for agent/worker worktrees whose parent repository could
/// not be recovered from the transcript path.
pub const UNMAPPED_WORKTREE_PROJECT: &str = "Agent worktrees";

const PROJECTS_FILE: &str = "projects.toml";
const OVERRIDES_RECHECK: Duration = Duration::from_secs(2);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectsFile {
    #[serde(default)]
    aliases: BTreeMap<String, String>,
}

#[derive(Default)]
struct Aliases {
    exact: BTreeMap<String, String>,
    /// `(prefix_stem, target)` sorted longest stem first for deterministic
    /// longest-prefix precedence.
    prefixes: Vec<(String, String)>,
}

struct AliasesCache {
    checked: Instant,
    text: Option<Result<String, String>>,
    data: Arc<Aliases>,
}

static ALIASES: Mutex<Option<AliasesCache>> = Mutex::new(None);

fn aliases() -> Arc<Aliases> {
    // Unit tests never read the real config directory.
    if cfg!(test) {
        return Arc::new(Aliases::default());
    }
    let Some(path) = crate::plugin::app_config_dir().map(|d| d.join(PROJECTS_FILE)) else {
        return Arc::new(Aliases::default());
    };
    let mut cache = ALIASES.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(c) = cache.as_ref() {
        if c.checked.elapsed() < OVERRIDES_RECHECK {
            return Arc::clone(&c.data);
        }
    }
    let text = read_text(&path);
    if let Some(c) = cache.as_mut() {
        if c.text == text {
            c.checked = Instant::now();
            return Arc::clone(&c.data);
        }
    }
    let data = Arc::new(match &text {
        Some(Ok(t)) => parse_aliases(t).unwrap_or_default(),
        _ => Aliases::default(),
    });
    *cache = Some(AliasesCache {
        checked: Instant::now(),
        text,
        data: Arc::clone(&data),
    });
    data
}

fn read_text(path: &std::path::Path) -> Option<Result<String, String>> {
    match std::fs::read_to_string(path) {
        Ok(t) => Some(Ok(t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => Some(Err(e.to_string())),
    }
}

fn parse_aliases(text: &str) -> Result<Aliases, String> {
    let file: ProjectsFile = toml::from_str(text).map_err(|e| {
        e.to_string()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    })?;
    let mut exact = BTreeMap::new();
    let mut prefixes = Vec::new();
    for (raw_key, raw_target) in file.aliases {
        let target = raw_target.trim();
        if raw_key.trim().is_empty() || target.is_empty() {
            return Err("project alias keys and targets must be non-empty".to_string());
        }
        if let Some(stem) = raw_key.strip_suffix('*') {
            if stem.is_empty() || stem.contains('*') {
                return Err(format!(
                    "{raw_key}: wildcard is only allowed once at the end"
                ));
            }
            prefixes.push((stem.to_string(), target.to_string()));
        } else {
            if raw_key.contains('*') {
                return Err(format!("{raw_key}: wildcard is only allowed at the end"));
            }
            exact.insert(raw_key, target.to_string());
        }
    }
    prefixes.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
    Ok(Aliases { exact, prefixes })
}

impl Aliases {
    fn get(&self, name: &str) -> Option<&str> {
        if let Some(target) = self.exact.get(name) {
            return Some(target.as_str());
        }
        self.prefixes
            .iter()
            .find(|(prefix, _)| name.starts_with(prefix.as_str()))
            .map(|(_, target)| target.as_str())
    }
}

/// Resolves raw `DayLine.project` values to display project names without
/// modifying stored buckets.
pub struct ProjectGrouper {
    encoded_dirs: HashMap<String, String>,
    aliases: Arc<Aliases>,
}

impl ProjectGrouper {
    /// Build a grouper indexed over the store's live buckets plus any
    /// `<config>/tickover/projects.toml` aliases.
    pub fn from_store(store: &HistoryStore) -> Self {
        Self::from_store_with_aliases(store, aliases())
    }

    fn from_store_with_aliases(store: &HistoryStore, aliases: Arc<Aliases>) -> Self {
        let mut encoded_dirs = HashMap::new();
        for d in store.live_days() {
            if !d.has_activity()
                || d.project.is_empty()
                || d.project == "unknown"
                || is_ping_dir(&d.project)
            {
                continue;
            }
            let Some(seg) = claude_encoded_dir(&d.file) else {
                continue;
            };
            if seg.contains("--claude-worktrees-") {
                continue;
            }
            encoded_dirs.entry(seg).or_insert_with(|| d.project.clone());
        }
        Self {
            encoded_dirs,
            aliases,
        }
    }

    /// Resolve `(raw_project, file)` to the display project name.
    pub fn resolve(&self, raw_project: &str, file: &str) -> String {
        if let Some(target) = self.aliases.get(raw_project) {
            return target.to_string();
        }
        if is_ping_dir(raw_project) {
            return AUTO_PING_PROJECT.to_string();
        }
        if let Some(repo) = self.worktree_repo(file) {
            return self.aliases.get(&repo).unwrap_or(&repo).to_string();
        }
        if is_agent_worktree_name(raw_project) {
            return UNMAPPED_WORKTREE_PROJECT.to_string();
        }
        if raw_project.is_empty() {
            "unknown".to_string()
        } else {
            raw_project.to_string()
        }
    }

    fn worktree_repo(&self, file: &str) -> Option<String> {
        if let Some(seg) = claude_encoded_dir(file) {
            if let Some((before, _)) = seg.split_once("--claude-worktrees-") {
                if let Some(repo) = self.encoded_dirs.get(before) {
                    return Some(repo.clone());
                }
                if let Some(last) = before.rsplit('-').find(|s| !s.is_empty()) {
                    return Some(last.to_string());
                }
            }
        }
        let norm = normalize_slashes(file);
        if let Some((before, _)) = norm.split_once("/.claude/worktrees/") {
            if let Some(base) = before.rsplit('/').find(|s| !s.is_empty()) {
                return Some(base.to_string());
            }
        }
        None
    }
}

fn normalize_slashes(path: &str) -> std::borrow::Cow<'_, str> {
    if path.contains('\\') {
        std::borrow::Cow::Owned(path.replace('\\', "/"))
    } else {
        std::borrow::Cow::Borrowed(path)
    }
}

fn claude_encoded_dir(file: &str) -> Option<String> {
    let norm = normalize_slashes(file);
    let rest = norm
        .rsplit_once("/.claude/projects/")
        .or_else(|| norm.rsplit_once("/projects/"))
        .map(|(_, tail)| tail)?;
    let seg = rest.split('/').next()?;
    (!seg.is_empty()).then(|| seg.to_string())
}

fn is_ping_dir(name: &str) -> bool {
    name.starts_with("tickover-ping-")
        || name.starts_with("codex-limits-ping-")
        || name == "ping-workdir"
}

fn is_agent_worktree_name(name: &str) -> bool {
    if let Some(id) = name.strip_prefix("agent-") {
        return id.len() >= 4
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    }
    if let Some(rest) = name.strip_prefix('w') {
        if let Some((digits, tail)) = rest.split_once('-') {
            return !digits.is_empty()
                && digits.bytes().all(|b| b.is_ascii_digit())
                && !tail.is_empty();
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::store::{DayLine, SCHEMA_VERSION};
    use std::fs;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tickover-proj-{tag}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn bucket(project: &str, file: &str) -> DayLine {
        DayLine {
            v: SCHEMA_VERSION,
            hour: "2026-11-10T12".into(),
            provider: "claude".into(),
            project: project.into(),
            model: "claude-sonnet-4-6".into(),
            session: format!("s-{project}-{file}"),
            file: file.into(),
            gen: 0,
            lo: 0,
            hi: 0,
            full: false,
            b: 0,
            input: 100,
            output: 20,
            cache_read: 0,
            cache_write: 0,
            thinking: 0,
            messages: 1,
        }
    }

    #[test]
    fn auto_ping_directories_collapse_to_shared_label() {
        let dir = tmpdir("ping");
        let store = HistoryStore::open(&dir).unwrap();
        let g = ProjectGrouper::from_store_with_aliases(&store, Arc::new(Aliases::default()));
        for name in [
            "tickover-ping-1234-5678-0",
            "codex-limits-ping-999-1",
            "ping-workdir",
        ] {
            assert_eq!(g.resolve(name, "/tmp/x.jsonl"), AUTO_PING_PROJECT, "{name}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn claude_worktrees_resolve_to_exact_parent_repo_name_and_fall_back_cleanly() {
        let dir = tmpdir("claude-wt");
        let mut store = HistoryStore::open(&dir).unwrap();
        store
            .append_days(&[
                bucket(
                    "codex-limits-tray",
                    "/Users/u/.claude/projects/-Users-u-work-codex-limits-tray/main.jsonl",
                ),
                bucket(
                    "agent-deadbeef",
                    "/Users/u/.claude/projects/-Users-u-work-codex-limits-tray--claude-worktrees-agent-deadbeef/wt.jsonl",
                ),
                bucket(
                    "agent-cafebabe",
                    "/Users/u/.claude/projects/-Users-u-work-alpha--claude-worktrees-agent-cafebabe/wt2.jsonl",
                ),
            ])
            .unwrap();
        let g = ProjectGrouper::from_store_with_aliases(&store, Arc::new(Aliases::default()));
        assert_eq!(
            g.resolve(
                "agent-deadbeef",
                "/Users/u/.claude/projects/-Users-u-work-codex-limits-tray--claude-worktrees-agent-deadbeef/wt.jsonl"
            ),
            "codex-limits-tray",
            "multi-hyphen repo name recovered from sibling directory entry"
        );
        assert_eq!(
            g.resolve(
                "agent-cafebabe",
                "/Users/u/.claude/projects/-Users-u-work-alpha--claude-worktrees-agent-cafebabe/wt2.jsonl"
            ),
            "alpha",
            "falls back to trailing segment when parent dir has no recorded bucket"
        );
        assert_eq!(
            g.resolve(
                "agent-feedface",
                "/Users/u/work/beta/.claude/worktrees/agent-feedface/s.jsonl"
            ),
            "beta",
            "unencoded /.claude/worktrees/ path recovers parent repo basename"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unmapped_agent_worktrees_collapse_without_touching_normal_projects() {
        let dir = tmpdir("agent-wt");
        let store = HistoryStore::open(&dir).unwrap();
        let g = ProjectGrouper::from_store_with_aliases(&store, Arc::new(Aliases::default()));
        for wt in ["agent-a1b2c3d4", "agent-01ab_cd", "w1-feature", "w12-fix"] {
            assert_eq!(
                g.resolve(wt, "/Users/u/.codex/sessions/rollout-1.jsonl"),
                UNMAPPED_WORKTREE_PROJECT,
                "{wt}"
            );
        }
        for normal in ["agent", "agent-123", "web-app", "worker-1", "alpha", "beta"] {
            assert_eq!(
                g.resolve(normal, "/Users/u/.codex/sessions/rollout-1.jsonl"),
                normal,
                "{normal}"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn manual_aliases_apply_longest_prefix_and_override_builtin_rules() {
        let aliases = parse_aliases(
            r#"
[aliases]
"codex-limits-tray" = "tickover"
"wt-*" = "tickover"
"wt-special-*" = "special-repo"
"agent-pinned" = "custom-agent"
"#,
        )
        .unwrap();
        let dir = tmpdir("aliases");
        let mut store = HistoryStore::open(&dir).unwrap();
        store
            .append_days(&[bucket(
                "codex-limits-tray",
                "/Users/u/.claude/projects/-Users-u-work-codex-limits-tray/main.jsonl",
            )])
            .unwrap();
        let g = ProjectGrouper::from_store_with_aliases(&store, Arc::new(aliases));
        assert_eq!(g.resolve("codex-limits-tray", "/f"), "tickover");
        assert_eq!(g.resolve("wt-foo", "/f"), "tickover");
        assert_eq!(g.resolve("wt-special-1", "/f"), "special-repo");
        assert_eq!(g.resolve("agent-pinned", "/f"), "custom-agent");
        assert_eq!(
            g.resolve(
                "agent-deadbeef",
                "/Users/u/.claude/projects/-Users-u-work-codex-limits-tray--claude-worktrees-agent-deadbeef/wt.jsonl"
            ),
            "tickover",
            "alias on resolved parent repository applies to its worktrees too"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_projects_toml_is_rejected() {
        for bad in [
            "not toml",
            "[unknown]\na = \"b\"\n",
            "[aliases]\n\"\" = \"tickover\"\n",
            "[aliases]\n\"a\" = \"   \"\n",
            "[aliases]\n\"*\" = \"tickover\"\n",
            "[aliases]\n\"a*b\" = \"tickover\"\n",
            "[aliases]\n\"a**\" = \"tickover\"\n",
        ] {
            assert!(parse_aliases(bad).is_err(), "{bad:?}");
        }
    }
}
