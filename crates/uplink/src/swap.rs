//! Putting a staged update in place at the next start. The old app is moved to `backups/`,
//! never deleted; a failed swap puts it back and keeps the pending file.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::state::{StateDir, unique_path, write_atomic};
use crate::trust::Trust;
use crate::zipcheck::{self, tree_matches};
use crate::{BUNDLE_NAME, TOOL_ID, clock};

/// What starting up found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartOutcome {
    NothingPending,
    Swapped {
        from: String,
        to: String,
    },
    /// The staged copy did not pass its checks again. Pending is kept; nothing was swapped.
    VerifyFailed(String),
    /// The swap failed and the old app is back. Pending is kept.
    InstallFailed(String),
    /// The pending file could not be read.
    Unreadable(String),
}

/// `…/X.app` when `exe` is `…/X.app/Contents/MacOS/<name>`.
pub fn current_bundle(exe: &Path) -> Option<PathBuf> {
    let macos = exe.parent()?;
    let contents = macos.parent()?;
    let app = contents.parent()?;
    let is = |p: &Path, name: &str| p.file_name().is_some_and(|n| n == name);
    (is(macos, "MacOS") && is(contents, "Contents") && app.extension().is_some_and(|e| e == "app")).then(|| app.to_path_buf())
}

fn exdev(e: &io::Error) -> bool {
    e.raw_os_error() == Some(18)
}

fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(from)?;
    if meta.file_type().is_symlink() {
        let target = fs::read_link(from)?;
        #[cfg(unix)]
        return std::os::unix::fs::symlink(target, to);
        #[cfg(not(unix))]
        return Err(io::Error::other("symlinks are not supported here"));
    }
    if meta.is_dir() {
        fs::create_dir(to)?;
        for item in fs::read_dir(from)? {
            let item = item?;
            copy_tree(&item.path(), &to.join(item.file_name()))?;
        }
        return fs::set_permissions(to, meta.permissions());
    }
    fs::copy(from, to).map(|_| ())
}

/// Rename; across volumes, copy the tree and leave the source where it is.
pub fn move_path(from: &Path, to: &Path) -> io::Result<()> {
    match fs::rename(from, to) {
        Err(e) if exdev(&e) => copy_tree(from, to),
        other => other,
    }
}

/// [`finish_pending_with`] with the real mover.
pub fn finish_pending(state: &StateDir, trust: &Trust, bundle: &Path, installed_version: &str) -> StartOutcome {
    finish_pending_with(state, trust, bundle, installed_version, &move_path)
}

/// Swap in the pending update, if there is one. `mover` does the two moves (tests make one fail).
pub fn finish_pending_with(
    state: &StateDir,
    trust: &Trust,
    bundle: &Path,
    installed_version: &str,
    mover: &dyn Fn(&Path, &Path) -> io::Result<()>,
) -> StartOutcome {
    let pending_path = state.pending_file();
    let text = match fs::read_to_string(&pending_path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return StartOutcome::NothingPending,
        Err(e) => return StartOutcome::Unreadable(e.to_string()),
    };
    let mut record: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => return StartOutcome::Unreadable(e.to_string()),
    };
    let field = |k: &str| record.get(k).and_then(Value::as_str).map(str::to_string);
    let (Some(version), Some(signature), Some(zip), Some(staged)) = (field("version"), field("signature"), field("zip_path"), field("bundle_path"))
    else {
        return StartOutcome::Unreadable("the pending file is missing fields".into());
    };
    let Some(manifest) = record.get("manifest").cloned() else {
        return StartOutcome::Unreadable("the pending file has no manifest".into());
    };
    let (zip, staged) = (PathBuf::from(zip), PathBuf::from(staged));
    // A copy installed by hand since then may be as new or newer: never swap backwards.
    if !crate::client::newer(&version, installed_version) {
        let aside = unique_path(&state.pending_dir(), &format!("{TOOL_ID}.stale-{}", clock::now().stamp()), ".json");
        match fs::rename(&pending_path, &aside) {
            Ok(()) => log::info!("uplink: staged {version} is not newer than {installed_version}; pending set aside as {}", aside.display()),
            Err(e) => log::warn!("uplink: staged {version} is not newer than {installed_version}; could not set it aside: {e}"),
        }
        return StartOutcome::NothingPending;
    }

    let entries = match zipcheck::verify_package_as(trust, &zip, &manifest, &signature, zipcheck::Layout::Mac) {
        Ok(e) => e,
        Err(why) => return StartOutcome::VerifyFailed(why),
    };
    if let Err(why) = tree_matches(&entries, &staged) {
        return StartOutcome::VerifyFailed(why);
    }

    let stamp = clock::now().stamp();
    let backups = state.backups_dir();
    if let Err(e) = fs::create_dir_all(&backups) {
        return StartOutcome::InstallFailed(format!("cannot create the backups folder: {e}"));
    }
    let backup = unique_path(&backups, &format!("Panoptic-{installed_version}-{stamp}"), ".app");
    if let Err(e) = mover(bundle, &backup) {
        return StartOutcome::InstallFailed(format!("cannot move the old app aside: {e}"));
    }
    // After a copy across volumes the old app is still in place; move it out of the way here.
    let mut aside = None;
    if fs::symlink_metadata(bundle).is_ok() {
        let name = bundle.file_name().map_or_else(|| BUNDLE_NAME.into(), |n| n.to_string_lossy().into_owned());
        let to = unique_path(bundle.parent().unwrap_or(Path::new(".")), &format!("{name}.replaced-{stamp}"), "");
        if let Err(e) = fs::rename(bundle, &to) {
            return StartOutcome::InstallFailed(format!("cannot clear the old app's place: {e}"));
        }
        aside = Some(to);
    }
    if let Err(e) = mover(&staged, bundle) {
        // Put the old app back (the real move, never the test hook). A partial copy goes aside.
        if fs::symlink_metadata(bundle).is_ok() {
            let to = unique_path(&backups, &format!("Panoptic-failed-{stamp}"), ".app");
            let _ = fs::rename(bundle, to);
        }
        let source = aside.as_deref().unwrap_or(&backup);
        return match move_path(source, bundle) {
            Ok(()) => StartOutcome::InstallFailed(format!("cannot move the new app into place: {e}")),
            Err(e2) => {
                StartOutcome::InstallFailed(format!("cannot move the new app into place ({e}) and the old app is at {}: {e2}", backup.display()))
            }
        };
    }

    // Done: record the outcome in the pending file, then rename it to a `done-` name.
    if let Some(obj) = record.as_object_mut() {
        obj.insert("outcome".into(), json!("installed"));
        obj.insert("from_version".into(), json!(installed_version));
        obj.insert("to_version".into(), json!(version));
        obj.insert("finished_at".into(), json!(stamp));
    }
    let done = unique_path(&state.pending_dir(), &format!("{TOOL_ID}.done-{stamp}"), ".json");
    let written = serde_json::to_vec_pretty(&record)
        .map_err(io::Error::other)
        .and_then(|b| write_atomic(&state.pending_dir(), &pending_path, &b, false))
        .and_then(|()| fs::rename(&pending_path, &done));
    if let Err(e) = written {
        log::warn!("uplink: swapped, but could not retire the pending file: {e}");
    }
    StartOutcome::Swapped { from: installed_version.to_string(), to: version }
}

fn is_done_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("panoptic.done-").and_then(|r| r.strip_suffix(".json")) else {
        return false;
    };
    let mut parts = rest.split('-');
    let ok = |s: Option<&str>, n: usize| s.is_some_and(|s| s.len() == n && s.bytes().all(|b| b.is_ascii_digit()));
    ok(parts.next(), 8)
        && ok(parts.next(), 6)
        && parts.next().is_none_or(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        && parts.next().is_none()
}

fn shown_file(state: &StateDir) -> PathBuf {
    state.pending_dir().join(format!("{TOOL_ID}.shown.json"))
}

/// The newest `done` file name that recorded an install.
fn newest_done(state: &StateDir) -> Option<(String, Value)> {
    let mut names: Vec<String> = fs::read_dir(state.pending_dir())
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| is_done_name(n))
        .collect();
    names.sort();
    let name = names.pop()?;
    let value: Value = serde_json::from_str(&fs::read_to_string(state.pending_dir().join(&name)).ok()?).ok()?;
    (value.get("outcome").and_then(Value::as_str) == Some("installed")).then_some((name, value))
}

/// `(new, old)` of the latest install nobody was told about yet.
pub fn unshown_update(state: &StateDir) -> Option<(String, String)> {
    let (name, value) = newest_done(state)?;
    let shown: Option<Value> = fs::read_to_string(shown_file(state)).ok().and_then(|t| serde_json::from_str(&t).ok());
    if shown.as_ref().and_then(|s| s.get("done")).and_then(Value::as_str) == Some(name.as_str()) {
        return None;
    }
    let get = |k: &str| value.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    Some((get("to_version"), get("from_version")))
}

/// Remember that the latest install was shown.
pub fn mark_shown(state: &StateDir) {
    if let Some((name, _)) = newest_done(state)
        && let Ok(bytes) = serde_json::to_vec(&json!({"done": name}))
        && let Err(e) = write_atomic(&state.pending_dir(), &shown_file(state), &bytes, false)
    {
        log::warn!("uplink: could not remember the update was shown: {e}");
    }
}

/// The environment variables a relaunch passes on.
pub(crate) fn relaunch_keeps(name: &str) -> bool {
    name.starts_with("PANOPTIC_")
        || name.starts_with("LIGHTCRAFT_LOG")
        || name == "LIGHTCRAFT_LIBRARY"
        || name == "LIGHTCRAFT_CONFIG_DIR"
        || name == "LIGHTCRAFT_CONTROL_PORT"
}

/// Open the new app again (macOS). Passes on the `PANOPTIC_*`, `LIGHTCRAFT_CONFIG_DIR`,
/// `LIGHTCRAFT_LOG*`, `LIGHTCRAFT_CONTROL_PORT` and `LIGHTCRAFT_LIBRARY` variables that
/// are set here, so an isolated or automated run stays isolated, reachable and confined.
/// Does not exit; the caller does.
pub fn relaunch(bundle: &Path) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let mut cmd = std::process::Command::new("open");
        cmd.arg("-n");
        for (k, v) in std::env::vars() {
            if relaunch_keeps(&k) {
                cmd.arg("--env").arg(format!("{k}={v}"));
            }
        }
        cmd.arg(bundle);
        cmd.spawn().map(|_| ())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = bundle;
        Err(io::Error::new(io::ErrorKind::Unsupported, "relaunch is macOS only"))
    }
}
