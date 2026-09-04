//! Seeding the plugin directory with the app's built-in manifests.
//!
//! The shipped manifests under `plugins/` are the single source of truth
//! for how each provider is read — this module's only job is to get them
//! onto disk the first time the app runs, and to let the user restore them
//! ("Reset plugins") without disturbing any third-party manifest they've
//! dropped alongside.

use std::path::{Path, PathBuf};

/// The built-in manifests, embedded at compile time so the app works out of
/// the box even before anything has been written to disk.
pub const DEFAULT_TEMPLATES: &[(&str, &str)] = &[
    ("codex.toml", include_str!("../../plugins/codex.toml")),
    ("claude.toml", include_str!("../../plugins/claude.toml")),
    ("grok.toml", include_str!("../../plugins/grok.toml")),
    (
        "antigravity.toml",
        include_str!("../../plugins/antigravity.toml"),
    ),
    ("copilot.toml", include_str!("../../plugins/copilot.toml")),
];

/// Where user-editable plugin manifests live:
/// `crate::plugin::app_config_dir()/plugins` — the same `tickover` base
/// `config::dir()` (in the binary crate) uses for its own JSON file. Falls
/// back to the current directory on the rare platform where the OS config
/// dir can't be resolved, mirroring the `dirs::home_dir()` fallback used
/// elsewhere (`src/main.rs` `spawn_hello`) — best-effort, never a panic.
pub fn plugins_dir() -> PathBuf {
    crate::plugin::app_config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("plugins")
}

/// Write every file in `templates` into `dir`, returning the paths written.
fn write_templates(dir: &Path, templates: &[(&str, &str)]) -> std::io::Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir)?;
    let mut written = Vec::with_capacity(templates.len());
    for (name, contents) in templates {
        let path = dir.join(name);
        if let Err(e) = write_new(&path, contents) {
            // A half-seeded directory is worse than an empty one: it holds a
            // `*.toml`, so `seed_if_empty` will skip it forever and the
            // manifest that failed never appears. Undo what this call wrote
            // and let the next launch try again from scratch.
            for done in &written {
                let _ = std::fs::remove_file(done);
            }
            return Err(e);
        }
        written.push(path);
    }
    Ok(written)
}

/// Write `contents` to `path`, replacing whatever is there — but never
/// *through* it, and never something its caller hasn't already decided is
/// safe to delete. The plugins directory is writable by anything running as
/// this user, and `fs::write` follows a symlink: a link left at
/// `plugins/codex.toml` would send a manifest into whatever it points at,
/// truncating that file.
///
/// `symlink_metadata` — the directory entry itself, never following — is
/// what decides, not `classify_builtin`'s own (symlink-following) read of
/// the *content* behind it: a plain file is unlinked and then created fresh
/// in its place, so nothing here ever writes *through* whatever was there;
/// anything else found at `path` — a symlink (live or dangling), a
/// directory, a FIFO — is left exactly as it is and this returns `Err`
/// instead. That refusal is deliberate even when the symlink's target is a
/// byte-identical earlier build a caller has every right to call `Replace`:
/// `classify_builtin` answers "is the content behind this path safe to
/// overwrite", not "is this path itself safe to delete", and only the
/// latter question is this function's to answer — a user who symlinked a
/// manifest into place put it there on purpose, and an automatic upgrade is
/// not the moment to silently turn their symlink into a plain file.
fn write_new(path: &Path, contents: &str) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => {
            std::fs::remove_file(path)?;
        }
        Ok(_) => {
            return Err(std::io::Error::other(format!(
                "{}: not a plain file — refusing to delete and replace it",
                path.display()
            )));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    std::io::Write::write_all(&mut file, contents.as_bytes()).inspect_err(|_| {
        // A write that fails partway through leaves a manifest on disk that
        // is neither the built-in nor nothing — and `has_any_toml`/
        // `classify_builtin` would then read it as present, so it never gets
        // a second chance to be written correctly.
        let _ = std::fs::remove_file(path);
    })
}

/// Whether `dir` (already known to exist) contains at least one `*.toml` file.
fn has_any_toml(dir: &Path) -> std::io::Result<bool> {
    Ok(std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .any(|entry| entry.path().extension().and_then(|e| e.to_str()) == Some("toml")))
}

/// First-run seeding: create `dir` if needed, then write the built-in
/// templates only if it holds no `*.toml` manifest at all — including a
/// third-party one the user (or another plugin) may have dropped in. Returns
/// the paths written (empty if the directory was already non-empty).
pub fn seed_if_empty(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir)?;
    if has_any_toml(dir)? {
        return Ok(Vec::new());
    }
    write_templates(dir, DEFAULT_TEMPLATES)
}

/// "Reset plugins": overwrite every built-in manifest in
/// [`DEFAULT_TEMPLATES`] (`codex.toml`, `claude.toml`, `grok.toml`,
/// `antigravity.toml`, `copilot.toml`) with its shipped default — restoring
/// each even if the user edited or deleted it, as long as what's at that
/// name is a plain file or nothing at all. A symlink at one of those names is
/// left exactly as it is instead: [`write_new`] refuses to delete a
/// directory entry it can't confirm is a plain file, so this call returns
/// `Err` rather than silently replacing somebody's deliberate link with a
/// fresh regular file — and nothing in the batch is written, per
/// [`write_templates`]'s own all-or-nothing rollback. Any other file in
/// `dir` (a third-party manifest, a stray `.toml`) is left untouched either
/// way. Returns the paths written on success.
pub fn reseed_defaults(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    write_templates(dir, DEFAULT_TEMPLATES)
}

// ── Built-in upgrades ────────────────────────────────────────────────────
//
// Seeding happens once, on a machine that has no manifests at all. Everyone
// else keeps the copy already on disk — which is right, since that copy is
// theirs to edit, and wrong when a built-in changes in a way that fixes what
// the app reports. Codex moving off its rollout logs is the second kind: an
// existing install would keep reading a stale log forever, and the whole
// point of the change is that the log's readings can't be trusted.
//
// So a built-in may be replaced exactly when both hold:
//
//   * the copy on disk is byte-identical to one this app shipped before, so
//     replacing it discards nothing the user wrote; and
//   * this app has not already made that decision once
//     (`plugin.<id>.builtin_migrated` records the version migrated *to*).
//
// The recorded marker is what makes a rollback stick. Copying the previous
// manifest back would otherwise look exactly like an un-migrated install, and
// the next launch would migrate it again — an app that quietly undoes the
// thing the user just did.

/// One shipped built-in's upgrade rule.
pub struct BuiltinUpgrade {
    /// File name inside the plugins directory.
    pub file: &'static str,
    /// The plugin id, for the config marker key.
    pub id: &'static str,
    /// The version being migrated *to*; also the marker's value.
    pub to_version: &'static str,
    /// sha256 (lowercase hex) of every earlier build of this file, so an
    /// untouched copy of any of them can be recognised.
    pub previous_sha256: &'static [&'static str],
    /// Whether a file that is **not on disk at all** should be written.
    ///
    /// False for a manifest this app has always shipped: seeding gave it to
    /// every install that ever ran, so its absence now means the user deleted
    /// it, and putting it back would be the app undoing what they just did.
    ///
    /// True for a manifest that ships for the first time in this version.
    /// Seeding only fires on a machine with no manifests at all, so without
    /// this a new provider reaches nobody who already had the app — the same
    /// gap `previous_sha256` closes for a manifest that changed. The marker
    /// makes it a one-time decision either way: delete the file after it
    /// arrives and it stays deleted.
    pub deliver_if_absent: bool,
}

/// Built-ins with an upgrade rule. Extend `previous_sha256` (with the hash of
/// the version being replaced) and bump `to_version` whenever a shipped
/// manifest changes in a way existing installs must receive.
pub const BUILTIN_UPGRADES: &[BuiltinUpgrade] = &[
    BuiltinUpgrade {
        file: "codex.toml",
        id: "codex",
        to_version: "2.5.1",
        // Every codex.toml this app has shipped, so an untouched copy of any of
        // them is recognised as one rather than mistaken for the user's own work.
        // A version that is missing from this list is a version whose installs
        // never see the manifest again.
        //
        // These are historical constants and nothing in the tree can recompute
        // them: the files they describe are not in it any more. A wrong one is
        // quiet and permanent — the install it fails to recognise is left alone,
        // the decision is recorded as made, and correcting the constant afterwards
        // changes nothing for that install. So each is labelled with the shipped
        // version it is the hash of, which is the only check left available for
        // a value nothing in this tree can reproduce.
        previous_sha256: &[
            // 1.0.0 — the log-file reader.
            // sha256 of codex.toml as shipped at manifest version 1.0.0.
            "44596a24d4a6c699e01b41b386edcfb6602b31c9bd3f5473261e9b3d3f5bcf21",
            // 2.0.0 — the usage API, before the per-model quota row.
            // sha256 of codex.toml as shipped at manifest version 2.0.0.
            "b1a64508a901caf47b9440558ac89d3eeed51202b863a9e52ac1c25bb8032707",
            // 2.1.0 — before `--skip-git-repo-check`, without which the auto-ping
            // exited 1 in the home directory and never reached the network.
            // sha256 of codex.toml as shipped at manifest version 2.1.0.
            "e2a9f2d50fdca869f706e0ae9eda52f33cd16bdd9709cc33b399cd464a42ee64",
            // 2.2.0 — before the weekly window was marked `required`, so a
            // response that had lost its shape drew whatever half still parsed.
            // sha256 of codex.toml as shipped at manifest version 2.2.0.
            "a68c8dcc67fe4febb1c613a9815ed5df0bead52c9243b49bbd435af29da84605",
            // 2.3.0 — before the windows carried `id`s and before `[status]`,
            // so an install left on it keys its windows by position and never
            // hears Codex say the account is cut off.
            // sha256 of codex.toml as shipped at manifest version 2.3.0.
            "9199d5afeb9c71edecf88c8c018912edd646fd1b6b1be0b22d22db194cbd82bd",
            // 2.4.0 — before `[[balances]]`, so an install left on it never
            // hears about the credits an exhausted account is still working
            // on. Taken from the working tree just before the edit that made
            // this entry necessary, which is the only moment those bytes
            // existed as a file rather than only as this hash:
            // sha256 of codex.toml as shipped at manifest version 2.4.0.
            "64d2f27986a5b99ea06c724fb108ffcfd4487cc971c5803fb98dc795a0e3f51c",
            // 2.5.0 — the weekly-window comment still claimed an empty
            // reading is refused.
            // sha256 of codex.toml as shipped at manifest version 2.5.0.
            "bba283eb7e22d52d8b6aa4b2cf50e28a7485a9dd6d067217d7caf4fd54d6ee3f",
        ],
        // Shipped since the first release: an install without it deleted it.
        deliver_if_absent: false,
    },
    // claude.toml's first entry. Until now this file had never changed *in the
    // history that survives*, so installed copies had nothing to receive and
    // the table had nothing to say. Get an entry wrong and every existing
    // Claude install keeps a manifest whose windows are not `required`, quietly
    // and for good — which is not hypothetical: with only the 1.0.0 hash here,
    // the one real install on record was already in exactly that state.
    BuiltinUpgrade {
        file: "claude.toml",
        id: "claude",
        to_version: "1.4.1",
        previous_sha256: &[
            // 1.4.0 — the ping comment still described firing at the
            // reset instant.
            // sha256 of claude.toml as shipped at manifest version 1.4.0.
            "57e192e8c1ab58907625a48a94285749d501215ff5234178cbf7a2bd4de61ffd",
            // 1.3.0 — before `[http.version].files` learned where npm
            // installs the CLI on Windows, so an install left on it asks
            // the endpoint under a version nobody is running.
            // sha256 of claude.toml as shipped at manifest version 1.3.0.
            "e76e5c920fcb7cfb58a12fc0b75eb3637627f74ca3ba84cbe4f2ee2ce03d7d3c",
            // 1.0.0 — the first claude.toml this app shipped, unchanged
            // since.
            // sha256 of claude.toml as shipped at manifest version 1.0.0.
            "6369e65518382e62ea70ffab506412900dc3fa7229e2872c78ced012bcfef6ed",
            // Pre-1.0.0 — what a build from before this repository's
            // history was squashed seeded, and what the installed copy on
            // the author's machine still was on 2026-08-20: no `version`
            // field at all, and the narrower
            // `claudeAiOauth.accessToken|access_token` token path from
            // before the fallback chain was widened.
            //
            // Unlike every other hash here, this one names no shipped
            // version at all — the file it describes predates versioning,
            // and the build that shipped it is gone. It was taken from
            // that installed file, which is a strict subset of shipped
            // 1.0.0 (every difference is a line the repository *added*
            // later; nothing in it was written by hand), so it is the
            // seed of a lost build rather than
            // somebody's edit.
            "c502cbe8d122fb67f1309494c0f86d2460743f45a1107e63dc122ab2dffc6213",
            // 1.1.0 — `required` on both windows, before the windows
            // carried `id`s. An install left on it keys its windows by
            // position, so inserting a window in a later version would
            // silently move every later window's registry entry.
            // sha256 of claude.toml as shipped at manifest version 1.1.0.
            "693ce7284fcaf2fb88136657107ac7da9a7a761066b0fb9d5e991844bab7e9c1",
            // 1.2.0 — the two fixed windows and nothing else. An install
            // left on it draws Claude's session and weekly rows and
            // silently omits the per-model weekly allowance the provider
            // reports beside them, which is the whole point of 1.3.0.
            // sha256 of claude.toml as shipped at manifest version 1.2.0.
            "c2babc16abcd37ce5633357a468e9df653a953d2d49449aa0359b32459d78274",
        ],
        // Same as codex.toml: shipped from the beginning, so an install
        // without it is one where the user removed it.
        deliver_if_absent: false,
    },
    // grok.toml's first entry, and the first built-in that ships *new* rather
    // than changed. Nothing on disk to recognise, so `previous_sha256` is
    // empty and `deliver_if_absent` carries the whole decision: an install
    // that already has a plugins directory never runs seeding again, so
    // without this Grok would reach only machines installing the app for the
    // first time.
    //
    // Once per version, like every other entry: the marker is recorded whether
    // the file was written or not, so deleting grok.toml afterwards keeps it
    // deleted.
    BuiltinUpgrade {
        file: "grok.toml",
        id: "grok",
        to_version: "1.0.0",
        previous_sha256: &[],
        deliver_if_absent: true,
    },
    // antigravity.toml, updated: the installed-app pair its `oauth-refresh`
    // fallback needs is no longer a literal `client_id`/`client_secret` in
    // the file (the repository cannot carry that in plain text and stay
    // public) — `[surface.auth.client]` reads it back out of the client's
    // own installed binaries instead. An install left on 1.0.0 keeps the
    // literal pair on disk (not itself a new exposure — that build already
    // shipped it — but not the fix either) and never gains the fallback
    // where the app was installed some other way than this repository's own
    // shipped copy. `deliver_if_absent` stays `true`, unlike codex.toml/
    // claude.toml's `false`: the first entry below reached only installs
    // that *already had a plugins directory* when antigravity.toml first
    // shipped, so a machine that jumped straight from a pre-antigravity
    // build to this one — skipping every version in between — has still
    // never had this file delivered at all, and `false` would deny it the
    // very manifest this change exists to distribute. Left as `true`
    // deliberately rather than decided here; see the change that added this
    // comment for the tradeoff (a deleted file being redelivered on the next
    // bump, vs. an install that never gets it).
    BuiltinUpgrade {
        file: "antigravity.toml",
        id: "antigravity",
        to_version: "1.1.0",
        previous_sha256: &[
            // 1.0.0 — the literal `client_id`/`client_secret` pair typed out
            // in plain text, before `[surface.auth.client]` discovery.
            // sha256 of antigravity.toml as shipped at manifest version 1.0.0.
            "bdf34a7f87ce5fd99fa76dc378070babe176e3c2a8b49308d9b7ccda672a8f72",
        ],
        deliver_if_absent: true,
    },
    // copilot.toml's first entry — new like the two above, and the same shape
    // for the same reason: nothing on disk to recognise, and `deliver_if_absent`
    // is what reaches an install whose plugins directory already exists.
    BuiltinUpgrade {
        file: "copilot.toml",
        id: "copilot",
        to_version: "1.0.0",
        previous_sha256: &[],
        deliver_if_absent: true,
    },
];

/// What to do with one built-in found on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeAction {
    /// Replace it: it is an untouched copy of an earlier build.
    Replace,
    /// Leave it: the user has edited it, or it is a manifest this app never
    /// shipped. Their file, their call.
    KeepModified,
    /// Leave it: it is already the current built-in.
    AlreadyCurrent,
    /// Nothing on disk — seeding's business, not this function's.
    Absent,
    /// Nothing on disk, and this built-in ships for the first time in this
    /// version, so it was written. Distinct from `Replace` because the log
    /// line a user reads should say a provider arrived, not that one was
    /// updated.
    Delivered,
    /// A directory entry exists at this path, but it wasn't a plain,
    /// size-bounded file [`crate::plugin::read_regular_file`] could read
    /// back — a directory, a FIFO, a symlink (dangling, or pointing at any
    /// of those), one over the size cap, bytes that failed to decode as
    /// UTF-8. Not the same fact as [`Self::Absent`]: something *is* there,
    /// on purpose or not, and `deliver_if_absent` is not a licence to guess
    /// what it was meant to be and overwrite it — see
    /// [`upgrade_builtin`]'s own doc for how this and `Absent` are told
    /// apart. Worth its own log line at the call site, the same as
    /// [`Self::Delivered`]: unlike an ordinary `Absent`, this usually means
    /// something unexpected is sitting where a manifest should be.
    Unreadable,
    /// `upgrade.file` names nothing in [`DEFAULT_TEMPLATES`] at all — a
    /// defect in [`BUILTIN_UPGRADES`] itself, not a fact about the user's
    /// disk. `builtin_upgrade_table_agrees_with_the_templates_it_migrates_to`
    /// exists so this should never happen; if it ever does, the caller
    /// should log it as what it is rather than let it read as an ordinary
    /// first install.
    NoSuchTemplate,
}

/// What's at a built-in's path on disk, from
/// [`crate::plugin::read_regular_file`]'s point of view — enough for
/// [`classify_builtin`] to tell "nothing here" apart from "something here
/// that resisted reading", which `Option<&[u8]>` alone could not: both used
/// to read as the same `None`, which is what let a symlinked-but-otherwise-
/// fine manifest be classified `Absent` and then delivered over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnDisk<'a> {
    /// No directory entry at this path at all.
    Absent,
    /// A directory entry exists, but not one `read_regular_file` could read
    /// back as a plain, size-bounded file.
    Unreadable,
    /// Read back as a plain file's bytes.
    Present(&'a [u8]),
}

/// Classify one built-in, purely, from what [`OnDisk`] says is at its path.
/// Hashes are compared case-insensitively, mirroring
/// [`crate::plugin::registry::verify_sha256`].
fn classify_builtin(current: &str, on_disk: OnDisk, previous_sha256: &[&str]) -> UpgradeAction {
    let bytes = match on_disk {
        OnDisk::Absent => return UpgradeAction::Absent,
        OnDisk::Unreadable => return UpgradeAction::Unreadable,
        OnDisk::Present(bytes) => bytes,
    };
    if bytes == current.as_bytes() {
        return UpgradeAction::AlreadyCurrent;
    }
    let sha = crate::plugin::registry::sha256_hex(bytes);
    if previous_sha256
        .iter()
        .any(|known| known.eq_ignore_ascii_case(&sha))
    {
        UpgradeAction::Replace
    } else {
        UpgradeAction::KeepModified
    }
}

/// The built-in text shipped for `file`, if it is one of ours.
pub fn builtin_contents(file: &str) -> Option<&'static str> {
    DEFAULT_TEMPLATES
        .iter()
        .find(|(name, _)| *name == file)
        .map(|(_, contents)| *contents)
}

/// Apply one upgrade rule against `dir`, returning what was decided. Callers
/// own the "has this already been decided?" marker (it lives in config, which
/// this module deliberately doesn't read) — check it before calling and
/// record `to_version` after, whatever the outcome: the decision is made once
/// per shipped version, not once per launch.
pub fn upgrade_builtin(dir: &Path, upgrade: &BuiltinUpgrade) -> std::io::Result<UpgradeAction> {
    let Some(current) = builtin_contents(upgrade.file) else {
        // Not a fact about the user's disk at all — see
        // `UpgradeAction::NoSuchTemplate`'s own doc.
        return Ok(UpgradeAction::NoSuchTemplate);
    };
    let path = dir.join(upgrade.file);
    // A regular file only: this runs at startup, before there is any UI, and
    // `fs::read` on a FIFO left at this path would block there forever.
    let on_disk_text = crate::plugin::read_regular_file(&path, crate::plugin::SMALL_FILE_MAX_BYTES);
    let on_disk = match &on_disk_text {
        Some(text) => OnDisk::Present(text.as_bytes()),
        // `read_regular_file` says nothing about *why* there was nothing to
        // read — a missing path and a directory/FIFO/oversized/undecodable
        // one both come back `None`. `symlink_metadata` (never following)
        // tells the two apart without opening anything: no entry at all is
        // `Absent`; any entry, whatever it is, is `Unreadable`.
        None => match std::fs::symlink_metadata(&path) {
            Ok(_) => OnDisk::Unreadable,
            Err(_) => OnDisk::Absent,
        },
    };
    let mut action = classify_builtin(current, on_disk, upgrade.previous_sha256);
    // A built-in shipping for the first time has nothing on disk to compare
    // against, so `classify_builtin` says `Absent` — never `Unreadable`,
    // which means something *is* there and is excluded from this branch on
    // purpose (see `UpgradeAction::Unreadable`'s own doc). Whether an
    // `Absent` here means "deliver it" or "the user deleted it" is not
    // something the bytes can settle; the manifest's own entry says which,
    // and the caller's marker makes it a decision taken once.
    if action == UpgradeAction::Absent && upgrade.deliver_if_absent {
        action = UpgradeAction::Delivered;
    }
    if action == UpgradeAction::Replace || action == UpgradeAction::Delivered {
        write_new(&path, current)?;
    }
    Ok(action)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::manifest::{
        AccountType, AmountKind, AuthType, EngineKind, PeriodMode, PeriodUnit, PluginManifest,
        ResetsAtFormat,
    };

    /// Every entry in the upgrade table actually reaches disk, not just the
    /// first one — the table grew a second entry for the first time here,
    /// and "the loop only ever looked at the first one" is the way that
    /// would fail silently, since the migration marker records the decision
    /// as made either way.
    ///
    /// Renamed from
    /// `every_entry_in_the_table_migrates_an_untouched_copy_of_its_own_previous_version`:
    /// that name, and the comment that used to sit on the fixture below,
    /// claimed this exercises `Replace` against "the most recent previous
    /// version". It never did and structurally cannot: the fixture is a
    /// stand-in string, not the real historical bytes (which are gone — see
    /// `BUILTIN_UPGRADES`'s own doc), so its hash is never in
    /// `previous_sha256` and the outcome is always `KeepModified`. It also
    /// used `.last()` as "the most recent", which is false for claude.toml —
    /// its list is not in chronological order. `Replace` has its own test,
    /// `an_untouched_previous_builtin_is_replaced`, against a fabricated
    /// pair this module can actually reproduce the bytes of.
    #[test]
    fn every_entry_in_the_table_correctly_classifies_an_unrecognised_file_and_its_own_current_template(
    ) {
        for upgrade in BUILTIN_UPGRADES {
            // A built-in shipping for the first time has no previous version
            // to migrate from at all — that path is `deliver_if_absent`, and
            // it has its own test below.
            if upgrade.previous_sha256.is_empty() {
                continue;
            }
            let dir = temp_dir(&format!("table-{}", upgrade.id));
            // Not real previous-version bytes — see this test's own doc for
            // why there are none left to write here. Its hash will not be in
            // `previous_sha256` (nothing not already listed there could be,
            // short of a sha256 collision), so the only outcome this fixture
            // can honestly stand for is "not one of the recognised ones".
            std::fs::write(
                dir.join(upgrade.file),
                "# not a previous build of this file\n",
            )
            .expect("write fixture");

            // A file whose hash is not in the table is the user's own work.
            assert_eq!(
                upgrade_builtin(&dir, upgrade).expect("upgrade runs"),
                UpgradeAction::KeepModified,
                "{}: a file this app never shipped must be left alone",
                upgrade.file
            );

            // And the current template is recognised as current rather than
            // rewritten on every launch.
            let current = builtin_contents(upgrade.file).expect("shipped template");
            std::fs::write(dir.join(upgrade.file), current).expect("write current");
            assert_eq!(
                upgrade_builtin(&dir, upgrade).expect("upgrade runs"),
                UpgradeAction::AlreadyCurrent,
                "{}: the shipped template must not be treated as an earlier one",
                upgrade.file
            );

            std::fs::remove_dir_all(&dir).ok();
        }

        // Every built-in ships with an entry in this table. claude.toml went
        // the whole project without one, so an edit to it would not have
        // reached a single installed copy.
        let files: Vec<&str> = BUILTIN_UPGRADES.iter().map(|u| u.file).collect();
        for (name, _) in DEFAULT_TEMPLATES {
            assert!(files.contains(name), "{name} ships but has no upgrade rule");
        }
    }

    /// A fresh temp dir per test, mirroring `manifest::tests::load_dir_...`
    /// (no external tempdir crate — `std::env::temp_dir()` + a unique suffix).
    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tickover-seed-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// The upgrade table is historical constants nothing in the tree can
    /// recompute, and a wrong one is quiet and permanent: the install it fails
    /// to recognise is left alone, the decision is recorded as made, and
    /// fixing the constant afterwards changes nothing for that install. Their
    /// *values* cannot be re-derived at all any more; their shape, and the two
    /// ways the table can contradict the file it describes, are checked here.
    #[test]
    fn builtin_upgrade_table_agrees_with_the_templates_it_migrates_to() {
        for upgrade in BUILTIN_UPGRADES {
            let current = builtin_contents(upgrade.file)
                .unwrap_or_else(|| panic!("{} is not a shipped template", upgrade.file));
            let parsed = PluginManifest::from_str(current).expect("shipped template parses");
            assert_eq!(
                parsed.version, upgrade.to_version,
                "{}: the table migrates to a version the file doesn't claim",
                upgrade.file
            );
            assert_eq!(
                parsed.id, upgrade.id,
                "{}: id disagrees with the table",
                upgrade.file
            );

            let current_sha = crate::plugin::registry::sha256_hex(current.as_bytes());
            let mut seen = std::collections::HashSet::new();
            for sha in upgrade.previous_sha256 {
                assert_eq!(sha.len(), 64, "{sha}: not a sha256");
                assert!(
                    sha.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                    "{sha}: sha256 constants are lowercase hex"
                );
                assert!(seen.insert(*sha), "{sha}: listed twice");
                // Listing it would make the current file classify as an
                // earlier one, so every launch would rewrite it in place.
                assert_ne!(
                    *sha, current_sha,
                    "{}: the current template is listed as a previous version",
                    upgrade.file
                );
            }
        }
    }

    #[test]
    fn codex_template_parses_and_matches_current_behaviour() {
        let contents = builtin_contents("codex.toml").expect("codex.toml template present");
        let m = PluginManifest::from_str(contents).expect("codex.toml must be a valid manifest");

        assert_eq!(m.id, "codex");
        assert_eq!(m.engine, EngineKind::HttpApi);
        assert_eq!(m.order, 10);
        assert_eq!(m.refresh_secs, 60, "one request a minute, matching Claude");
        assert_eq!(
            m.version, "2.5.1",
            "the version BUILTIN_UPGRADES migrates to"
        );

        // The golden half of the capability rule: a key can be listed in
        // `CAPABILITIES`, declared in `requires_reader`, and still be spelled
        // wrong in the manifest — every check so far would pass and the field
        // would simply be absent from the parsed struct. So assert the values
        // arrived, not just that the file was accepted.
        assert_eq!(
            m.windows.iter().map(|w| w.id.as_str()).collect::<Vec<_>>(),
            vec!["codex-5h", "codex-wk", "codex-spark"],
            "every window carries the identity its registry key is built from"
        );
        let status = m
            .status
            .as_ref()
            .expect("Codex states the quota's own standing");
        assert_eq!(status.allowed_path.as_deref(), Some("rate_limit.allowed"));
        assert_eq!(
            status.limit_reached_path.as_deref(),
            Some("rate_limit.limit_reached")
        );
        assert_eq!(
            status.reached_type_path.as_deref(),
            Some("rate_limit_reached_type.type"),
            "the reached type sits at the response root and names its kind in a nested field"
        );
        // Credits: what an account exhausted on its subscription quota is
        // still working on. A string, because Codex's own schema types it as
        // one — see the manifest's comment on why it is not parsed back into a
        // number.
        assert_eq!(
            m.balances.len(),
            1,
            "codex reports exactly one balance today"
        );
        let credits = &m.balances[0];
        assert_eq!(credits.id, "codex-credits");
        let remaining = credits
            .remaining
            .as_ref()
            .expect("the credits figure is a remainder");
        assert_eq!(remaining.kind, AmountKind::Text);
        assert_eq!(remaining.path.as_deref(), Some("credits.balance"));
        assert!(
            credits.used.is_none() && credits.cap.is_none(),
            "Codex states neither"
        );
        assert!(
            credits.source.period_end_path.is_none(),
            "Codex names no period end for credits, and inventing one would be a date nobody promised"
        );

        for name in [
            "window-presence",
            "window-identity",
            "reading-status",
            "reading-balances",
        ] {
            assert!(
                m.requires_reader.iter().any(|d| d == name),
                "the manifest has to declare {name}, or an older build reads its fields as ours"
            );
        }

        // One surface, and it must be spelled "default": any other id would
        // change this provider's reading id from "codex" to "codex-<id>" and
        // hand the chip over to the surface label instead of the plan
        // (`engine_http::surface_reading_id` / `resolve_tag`).
        assert_eq!(m.surface.len(), 1);
        let surface = &m.surface[0];
        assert_eq!(surface.id, "default");
        assert_eq!(surface.allowed_hosts, vec!["chatgpt.com".to_string()]);
        assert!(
            surface.no_credentials_message.is_some(),
            "a signed-out Codex says so"
        );

        // The API-key rejection must come *before* the step that reads the
        // token: a credentials file present without a token is Present-err and
        // would stop the chain first.
        assert_eq!(surface.auth.len(), 2);
        assert_eq!(surface.auth[0].kind, AuthType::RejectWhen);
        assert_eq!(
            surface.auth[0].unless_json_path.as_deref(),
            Some("tokens.access_token")
        );
        assert_eq!(surface.auth[1].kind, AuthType::CredentialsFile);
        assert_eq!(
            surface.auth[1].token_json_path.as_deref(),
            Some("tokens.access_token")
        );

        let http = m.http.as_ref().expect("codex.toml declares [http]");
        assert_eq!(http.request.len(), 1);
        assert_eq!(
            http.request[0].url,
            "https://chatgpt.com/backend-api/wham/usage"
        );
        assert!(
            http.min_interval_secs < m.refresh_secs,
            "a floor at or above the cadence would skip every other scheduled refresh"
        );
        assert_eq!(
            http.request[0]
                .headers
                .get("chatgpt-account-id")
                .map(String::as_str),
            Some("{value.account_id}")
        );
        assert_eq!(http.value.len(), 1, "the account id for that header");
        assert_eq!(
            http.value[0].json_path.as_deref(),
            Some("tokens.account_id")
        );

        // The two subscription windows read both candidate slots and are told
        // apart by length: Codex sends the weekly window as `primary_window`
        // whenever the 5-hour one has nothing to report.
        let subscription: Vec<_> = m
            .windows
            .iter()
            .filter(|w| w.role != crate::plugin::manifest::Role::Extra)
            .collect();
        assert_eq!(
            subscription.len(),
            2,
            "5H and WK, and nothing else in those slots"
        );
        for w in &subscription {
            assert_eq!(w.period.mode, PeriodMode::FromField);
            assert_eq!(w.period.unit, PeriodUnit::Seconds, "the API states seconds");
            assert_eq!(w.source.resets_at_format, ResetsAtFormat::Unix);
            assert_eq!(
                w.source.containers,
                vec![
                    "rate_limit.primary_window".to_string(),
                    "rate_limit.secondary_window".to_string()
                ],
                "window {} must not be read positionally",
                w.label
            );
        }
        // The per-model allowance is a row of its own, reading a container no
        // subscription window looks at.
        let spark = m
            .windows
            .iter()
            .find(|w| w.role == crate::plugin::manifest::Role::Extra)
            .expect("the model quota is declared");
        assert_eq!(
            spark.source.containers,
            vec![
                "additional_rate_limits[limit_name=GPT-5.3-Codex-Spark].rate_limit.primary_window"
                    .to_string(),
                "additional_rate_limits[limit_name=GPT-5.3-Codex-Spark].rate_limit.secondary_window"
                    .to_string(),
            ],
            "selected by the name it calls itself, not by position in an array Codex reorders — \
             and from either slot, since Codex fixes neither"
        );
        assert!(
            spark.source.min_period_minutes.is_none() && spark.source.max_period_minutes.is_none(),
            "it reads one container, so it has nothing to be told apart from"
        );
        let five_h = m
            .windows
            .iter()
            .find(|w| w.label == "5H")
            .expect("5H window");
        assert_eq!(five_h.source.max_period_minutes, Some(720));
        let wk = m
            .windows
            .iter()
            .find(|w| w.label == "WK")
            .expect("WK window");
        assert_eq!(wk.source.min_period_minutes, Some(721));

        assert_eq!(
            m.account.kind,
            AccountType::ResponseField,
            "the email is in the response"
        );
        assert_eq!(m.account.json_path.as_deref(), Some("email"));

        // Both flags are load-bearing, not decoration. Without
        // `--skip-git-repo-check`, `codex exec` refuses to start outside a git
        // repository ("Not inside a trusted directory…", exit 1) with its
        // output already discarded — the feature failed silently for every
        // 2.1.0 install. `--sandbox read-only` is what bounds the run it then
        // allows: unattended, on a timer, with nobody reading the output.
        let ping = m.ping.as_ref().expect("codex.toml declares [ping]");
        assert_eq!(ping.bin, "codex");
        assert_eq!(
            ping.args,
            vec![
                "exec".to_string(),
                "--skip-git-repo-check".to_string(),
                "--sandbox".to_string(),
                "read-only".to_string(),
                "hello".to_string(),
            ]
        );
    }

    #[test]
    fn a_built_in_manifest_is_embedded_with_the_bytes_it_is_hashed_by() {
        // These bytes are the manifest's identity: this module recognises a
        // previous built-in by sha256, and `registry.rs` recognises a
        // downloaded one the same way. Git turns LF into CRLF on checkout on
        // Windows unless told otherwise, and a build from such a checkout
        // embeds a manifest that no declared hash describes — the migration
        // then looks at the file it was written for and does not recognise
        // it. `.gitattributes` is what prevents that; this is what says so
        // out loud, on whichever machine the build happens, including one
        // built from a checkout that predates it.
        for (name, contents) in DEFAULT_TEMPLATES {
            assert!(
                !contents.contains('\r'),
                "{name} was embedded with CRLF line endings: its sha256 is not the one this build declares"
            );
        }
    }

    /// Stand-in for "a manifest this app shipped once". The tests below are
    /// about the upgrade *mechanism* — recognise a copy of an earlier build,
    /// replace it, leave an edited one alone — and none of them is about any
    /// particular old manifest. Using a real one made them depend on keeping a
    /// retired file in the tree; this depends on one line and its hash, which
    /// anybody can check with `printf '…\n' | shasum -a 256`.
    const EARLIER_BUILD: &str = "# an earlier build of this manifest\n";
    const EARLIER_BUILD_SHA: &str =
        "1fa7d3165d880648b9e6b2fe49ca2f5bcb277d14568a632d43408fe5e405e8c7";

    fn fabricated_upgrade() -> BuiltinUpgrade {
        BuiltinUpgrade {
            file: "codex.toml",
            id: "codex",
            to_version: "9.9.9",
            previous_sha256: &[EARLIER_BUILD_SHA],
            deliver_if_absent: false,
        }
    }

    #[test]
    fn the_shipped_hashes_are_at_least_the_shape_of_a_hash_and_not_this_build() {
        // What can still be checked here, now that the files these describe
        // are no longer in the tree and nothing can recompute their hashes.
        // It is not much: a hash that is one digit wrong is still a hash, and
        // nothing left says otherwise. It does catch the mistakes that look
        // like mistakes —
        // a truncated paste, an uppercase digit, the same entry twice, or the
        // *current* manifest's hash filed as a previous one, which would
        // describe a version this app has not shipped yet.
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for upgrade in BUILTIN_UPGRADES {
            let current = builtin_contents(upgrade.file)
                .unwrap_or_else(|| panic!("{} names a file this app ships", upgrade.file));
            let current_sha = crate::plugin::registry::sha256_hex(current.as_bytes());
            for sha in upgrade.previous_sha256 {
                assert_eq!(sha.len(), 64, "not a sha256: {sha}");
                assert!(
                    sha.chars()
                        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                    "sha256 hashes are written in lowercase hex here: {sha}"
                );
                assert_ne!(
                    *sha, current_sha,
                    "that is this build's own manifest, not a previous one"
                );
                assert!(seen.insert(sha), "{sha} is listed twice");
            }
        }
    }

    #[test]
    fn the_fixture_below_really_does_hash_to_what_it_says() {
        // Or every test using it would pass by describing nothing.
        assert_eq!(
            crate::plugin::registry::sha256_hex(EARLIER_BUILD.as_bytes()),
            EARLIER_BUILD_SHA
        );
    }

    // ── built-in upgrades ────────────────────────────────────────────────

    #[test]
    fn an_untouched_previous_builtin_is_replaced() {
        let dir = temp_dir("upgrade-untouched");
        let upgrade = &fabricated_upgrade();
        let previous = EARLIER_BUILD.to_string();
        let path = dir.join(upgrade.file);
        std::fs::write(&path, &previous).unwrap();

        assert_eq!(
            upgrade_builtin(&dir, upgrade).expect("upgrade"),
            UpgradeAction::Replace
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            builtin_contents("codex.toml").unwrap(),
            "the file on disk is now the current built-in"
        );
        // And running again is idempotent, marker or no marker.
        assert_eq!(
            upgrade_builtin(&dir, upgrade).expect("upgrade"),
            UpgradeAction::AlreadyCurrent
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_edited_manifest_is_left_alone() {
        let dir = temp_dir("upgrade-edited");
        let upgrade = &BUILTIN_UPGRADES[0];
        let path = dir.join(upgrade.file);
        let edited = format!(
            "# my own notes\n{}",
            builtin_contents("codex.toml").unwrap()
        );
        std::fs::write(&path, &edited).unwrap();

        assert_eq!(
            upgrade_builtin(&dir, upgrade).expect("upgrade"),
            UpgradeAction::KeepModified
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            edited,
            "a manifest the user has touched is theirs"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_manifest_put_back_by_hand_is_only_replaced_once() {
        // Restoring an earlier built-in by hand is something a user may do
        // for any reason. That copy *is* a previous built-in, so hashes alone
        // would migrate it again on the next launch and quietly undo them.
        // What prevents it is the caller's one-per-version marker
        // (`config::builtin_migrated`); this test states the half that lives
        // here — the classification is deliberately unchanged, which is
        // exactly what makes the marker load-bearing rather than belt-and-
        // braces.
        let dir = temp_dir("upgrade-rollback");
        let upgrade = &fabricated_upgrade();
        let previous = EARLIER_BUILD.to_string();
        std::fs::write(dir.join(upgrade.file), &previous).unwrap();
        assert_eq!(
            classify_builtin(
                builtin_contents("codex.toml").unwrap(),
                OnDisk::Present(previous.as_bytes()),
                upgrade.previous_sha256
            ),
            UpgradeAction::Replace,
            "indistinguishable from a never-migrated install, hence the marker"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_manifest_is_seeding_business_not_upgrading() {
        let dir = temp_dir("upgrade-missing");
        assert_eq!(
            upgrade_builtin(&dir, &BUILTIN_UPGRADES[0]).expect("upgrade"),
            UpgradeAction::Absent
        );
        assert!(
            !dir.join("codex.toml").exists(),
            "upgrading never creates a manifest"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn classify_builtin_distinguishes_absent_from_something_unreadable_here() {
        assert_eq!(
            classify_builtin("current", OnDisk::Absent, &["deadbeef"]),
            UpgradeAction::Absent
        );
        assert_eq!(
            classify_builtin("current", OnDisk::Unreadable, &["deadbeef"]),
            UpgradeAction::Unreadable,
            "something being there, unreadable, is not the same fact as nothing being there"
        );
    }

    #[test]
    fn upgrade_builtin_leaves_an_unreadable_entry_alone_even_with_deliver_if_absent() {
        // A directory at this name isn't "nothing installed yet" — it is
        // something the user or another program put there, and
        // `deliver_if_absent` exists for the first case, not the second.
        let dir = temp_dir("upgrade-unreadable-dir");
        let path = dir.join("grok.toml");
        std::fs::create_dir_all(&path).unwrap();
        let upgrade = BuiltinUpgrade {
            file: "grok.toml",
            id: "grok",
            to_version: "1.0.0",
            previous_sha256: &[],
            deliver_if_absent: true,
        };
        assert_eq!(
            upgrade_builtin(&dir, &upgrade).expect("upgrade runs"),
            UpgradeAction::Unreadable
        );
        assert!(path.is_dir(), "left exactly as it was");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn upgrade_builtin_reports_a_table_entry_naming_no_shipped_template_distinctly() {
        // A defect in `BUILTIN_UPGRADES` itself (a typo'd `file`, an entry
        // left behind after its template was removed from
        // `DEFAULT_TEMPLATES`) is not the same fact as the user simply not
        // having the file yet — conflating the two would have this exact bug
        // read as an ordinary first install.
        let dir = temp_dir("upgrade-no-such-template");
        let bogus = BuiltinUpgrade {
            file: "does-not-exist.toml",
            id: "nonexistent",
            to_version: "1.0.0",
            previous_sha256: &[],
            deliver_if_absent: true,
        };
        assert_eq!(
            upgrade_builtin(&dir, &bogus).expect("upgrade runs"),
            UpgradeAction::NoSuchTemplate
        );
        assert!(
            !dir.join(bogus.file).exists(),
            "nothing is written for a template this app doesn't actually ship"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg(unix)]
    fn write_new_refuses_to_delete_a_symlink_and_writes_nothing() {
        let dir = temp_dir("write-new-symlink");
        let real_target = dir.join("real-target.toml");
        std::fs::write(&real_target, "# elsewhere\n").unwrap();
        let link = dir.join("codex.toml");
        std::os::unix::fs::symlink(&real_target, &link).unwrap();

        write_new(&link, "# built-in\n").expect_err("a symlink must not be unlinked here");
        assert!(link.is_symlink(), "the symlink itself must survive");
        assert_eq!(
            std::fs::read_to_string(&real_target).unwrap(),
            "# elsewhere\n",
            "and never written through, either"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg(unix)]
    fn upgrade_builtin_does_not_delete_a_symlinked_previous_build() {
        // The residual gap `read_regular_file` following symlinks opens on
        // its own: once a symlinked earlier build reads back as
        // `Replace`-worthy content, `write_new` — not `classify_builtin` — is
        // what has to refuse to unlink the user's own symlink to make room
        // for a plain file.
        let dir = temp_dir("upgrade-symlinked-previous");
        let upgrade = &fabricated_upgrade();
        let target = dir.join("elsewhere.toml");
        std::fs::write(&target, EARLIER_BUILD).unwrap();
        let link = dir.join(upgrade.file);
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(
            upgrade_builtin(&dir, upgrade).is_err(),
            "a symlink is left exactly as it is, not replaced"
        );
        assert!(link.is_symlink(), "the symlink itself must survive");
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            EARLIER_BUILD,
            "and never written through"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn claude_template_parses_and_matches_current_behaviour() {
        let (_, contents) = DEFAULT_TEMPLATES
            .iter()
            .find(|(name, _)| *name == "claude.toml")
            .expect("claude.toml template present");
        let m = PluginManifest::from_str(contents).expect("claude.toml must be a valid manifest");

        assert_eq!(m.id, "claude");
        assert_eq!(m.engine, EngineKind::HttpApi);
        assert_eq!(
            m.version, "1.4.1",
            "the version BUILTIN_UPGRADES migrates to"
        );
        assert_eq!(m.surface.len(), 2, "cli + desktop surfaces");

        assert_eq!(
            m.windows.iter().map(|w| w.id.as_str()).collect::<Vec<_>>(),
            vec!["claude-5h", "claude-wk", "claude-wk-model"],
        );
        // The third entry is the one that expands: Anthropic reports a weekly
        // allowance per scoped model inside `limits[]`, and how many there are
        // is the account's business. Asserted here as well as in the corpus
        // golden, because this test is what a reader of `seed` looks at to see
        // what the shipped Claude actually reads.
        let scoped = &m.windows[2];
        assert_eq!(scoped.for_each.as_deref(), Some("limits"));
        assert_eq!(scoped.for_each_where.as_deref(), Some("kind=weekly_scoped"));
        assert_eq!(
            scoped.element_id_path.as_deref(),
            Some("scope.model.display_name")
        );
        // And no `[status]`, which is a measurement rather than an omission:
        // Anthropic's response states no standing for the quota as a whole —
        // its `severity` lives inside `limits[]`, and `spend` is a balance.
        // Declaring an empty one would have this app inventing a sentence
        // nobody spoke.
        assert_eq!(
            m.status, None,
            "Claude states nothing of the kind, so the manifest claims nothing"
        );

        let desktop = m
            .surface
            .iter()
            .find(|s| s.id == "desktop")
            .expect("desktop surface present");
        assert!(desktop.opt_in, "desktop surface is opt-in");
        assert!(!desktop.in_menu_bar, "desktop surface is popup-only");
        assert_eq!(desktop.auth.len(), 1);
        assert_eq!(desktop.auth[0].kind, AuthType::ElectronSafeStorage);

        let cli = m
            .surface
            .iter()
            .find(|s| s.id == "cli")
            .expect("cli surface present");
        assert!(!cli.opt_in);
        assert!(cli.in_menu_bar);
        assert_eq!(
            cli.auth.len(),
            3,
            "credentials-file -> keychain -> win-credential"
        );

        for w in &m.windows {
            assert_eq!(
                w.source.resets_at_format,
                ResetsAtFormat::Iso8601,
                "Claude reset timestamps are ISO-8601, not Unix"
            );
            assert_eq!(
                w.period.mode,
                PeriodMode::Assumed,
                "Claude assumes nominal periods"
            );
        }
        let five_h = m
            .windows
            .iter()
            .find(|w| w.label == "5H")
            .expect("5H window");
        assert_eq!(five_h.period.assumed, Some(300));
        let wk = m
            .windows
            .iter()
            .find(|w| w.label == "WK")
            .expect("WK window");
        assert_eq!(wk.period.assumed, Some(10080));
    }

    #[test]
    fn a_built_in_shipping_for_the_first_time_is_delivered_to_an_existing_install() {
        // The gap this closes: seeding fires only on a machine with no
        // manifests at all, so every existing install would keep the set it
        // was first given and never see a provider added later.
        let dir = temp_dir("deliver-new");
        std::fs::write(dir.join("codex.toml"), "# somebody else's\n").expect("existing manifest");

        let new_builtin = BuiltinUpgrade {
            file: "grok.toml",
            id: "grok",
            to_version: "1.0.0",
            previous_sha256: &[],
            deliver_if_absent: true,
        };
        assert_eq!(
            upgrade_builtin(&dir, &new_builtin).expect("upgrade runs"),
            UpgradeAction::Delivered
        );
        let written = std::fs::read_to_string(dir.join("grok.toml")).expect("delivered");
        assert_eq!(
            written,
            builtin_contents("grok.toml").expect("shipped template")
        );

        // Once there, it is not rewritten on every launch.
        assert_eq!(
            upgrade_builtin(&dir, &new_builtin).expect("upgrade runs"),
            UpgradeAction::AlreadyCurrent
        );

        // And the same file, with the flag off, is left absent: that is the
        // manifest whose absence means the user deleted it.
        std::fs::remove_file(dir.join("grok.toml")).expect("remove");
        let old_builtin = BuiltinUpgrade {
            deliver_if_absent: false,
            ..new_builtin
        };
        assert_eq!(
            upgrade_builtin(&dir, &old_builtin).expect("upgrade runs"),
            UpgradeAction::Absent
        );
        assert!(
            !dir.join("grok.toml").exists(),
            "an absent old built-in stays absent"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn seed_if_empty_writes_every_built_in_template_into_a_fresh_dir() {
        let dir = temp_dir("fresh");
        let written = seed_if_empty(&dir).expect("seed");
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(written.len(), DEFAULT_TEMPLATES.len());
        for (name, _) in DEFAULT_TEMPLATES {
            assert!(
                written.iter().any(|p| p.ends_with(name)),
                "{name} missing from what seed_if_empty wrote: {written:?}"
            );
        }
    }

    #[test]
    fn seed_if_empty_is_a_no_op_once_a_manifest_exists() {
        let dir = temp_dir("noop");
        seed_if_empty(&dir).expect("first seed");

        // Simulate the user editing one of the seeded files.
        let codex_path = dir.join("codex.toml");
        std::fs::write(&codex_path, "id = \"codex\" # user edit").expect("overwrite");

        let written_again = seed_if_empty(&dir).expect("second seed is a no-op");
        let contents = std::fs::read_to_string(&codex_path).expect("read back");
        std::fs::remove_dir_all(&dir).ok();

        assert!(
            written_again.is_empty(),
            "must not write anything the second time"
        );
        assert_eq!(
            contents, "id = \"codex\" # user edit",
            "the user's edit must survive"
        );
    }

    #[test]
    fn seed_if_empty_defers_to_a_pre_existing_third_party_manifest() {
        let dir = temp_dir("third-party");
        std::fs::write(dir.join("third-party.toml"), "id = \"third-party\"").expect("seed fixture");

        let written = seed_if_empty(&dir).expect("seed");
        let has_codex = dir.join("codex.toml").is_file();
        let has_claude = dir.join("claude.toml").is_file();
        std::fs::remove_dir_all(&dir).ok();

        assert!(
            written.is_empty(),
            "a non-empty plugins dir must not be touched"
        );
        assert!(
            !has_codex && !has_claude,
            "defaults must not be written alongside a foreign manifest"
        );
    }

    #[test]
    fn reseed_defaults_restores_the_builtins_without_touching_other_files() {
        let dir = temp_dir("reseed");
        seed_if_empty(&dir).expect("initial seed");
        std::fs::write(dir.join("third-party.toml"), "id = \"third-party\"").expect("foreign file");

        // Corrupt one of the built-ins, as if the user broke it by hand.
        let codex_path = dir.join("codex.toml");
        std::fs::write(&codex_path, "not valid toml at all").expect("corrupt codex.toml");

        let written = reseed_defaults(&dir).expect("reseed");
        let restored = std::fs::read_to_string(&codex_path).expect("read back");
        let third_party = std::fs::read_to_string(dir.join("third-party.toml")).expect("read back");
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(written.len(), DEFAULT_TEMPLATES.len());
        assert!(
            PluginManifest::from_str(&restored).is_ok(),
            "codex.toml must be the valid built-in default again"
        );
        assert_eq!(
            third_party, "id = \"third-party\"",
            "foreign manifest must be untouched"
        );
    }
}
