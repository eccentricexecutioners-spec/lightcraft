//! Where the install key lives: a small file outside the app, so an update never loses it.
//! Nothing here deletes a file. A refused key is renamed `panoptic.revoked-<stamp>.json`.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::{TOOL_ID, clock};

const FOLDER: &str = "EE Cargo Bay";

/// The state folder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateDir(pub PathBuf);

/// What is saved when a copy is linked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub tool_id: String,
    pub install_key: String,
    pub base_url: String,
    /// Local time, ISO 8601 with offset, to the second.
    pub linked_at: String,
}

impl Link {
    /// A link made now.
    pub fn new(install_key: &str, base_url: &str) -> Link {
        Link { tool_id: TOOL_ID.to_string(), install_key: install_key.to_string(), base_url: base_url.to_string(), linked_at: clock::now().iso() }
    }
}

impl Default for StateDir {
    /// `PANOPTIC_CARGO_BAY_STATE_DIR`, else the per-OS folder.
    fn default() -> Self {
        if let Some(dir) = std::env::var_os("PANOPTIC_CARGO_BAY_STATE_DIR").filter(|v| !v.is_empty()) {
            return StateDir(PathBuf::from(dir));
        }
        let home = || std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
        if cfg!(target_os = "macos") {
            StateDir(home().join("Library").join("Application Support").join(FOLDER))
        } else if cfg!(windows) {
            let base = std::env::var_os("APPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from).unwrap_or_default().join("AppData").join("Roaming"));
            StateDir(base.join(FOLDER))
        } else {
            StateDir(home().join(".ee-cargo-bay"))
        }
    }
}

impl StateDir {
    pub fn new(path: impl Into<PathBuf>) -> StateDir {
        StateDir(path.into())
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn key_file(&self) -> PathBuf {
        self.0.join(format!("{TOOL_ID}.json"))
    }

    pub fn keyring_file(&self) -> PathBuf {
        self.0.join(format!("{TOOL_ID}.keyring.json"))
    }

    pub fn staging_dir(&self) -> PathBuf {
        self.0.join("staging")
    }

    pub fn pending_dir(&self) -> PathBuf {
        self.0.join("pending")
    }

    pub fn pending_file(&self) -> PathBuf {
        self.pending_dir().join(format!("{TOOL_ID}.json"))
    }

    pub fn backups_dir(&self) -> PathBuf {
        self.0.join("backups")
    }

    /// The saved install key, or `None` when there is none or the file cannot be read.
    pub fn read_key(&self) -> Option<String> {
        let text = fs::read_to_string(self.key_file()).ok()?;
        let value: serde_json::Value = serde_json::from_str(&text).ok()?;
        let key = value.get("install_key")?.as_str()?;
        (!key.is_empty()).then(|| key.to_string())
    }

    /// Save the link: a temp file in the same folder (mode 0600 on unix), then a rename.
    pub fn save_link(&self, link: &Link) -> io::Result<()> {
        let bytes = serde_json::to_vec_pretty(link).map_err(io::Error::other)?;
        write_atomic(&self.0, &self.key_file(), &bytes, true)
    }

    /// Rename the key file to `panoptic.revoked-<stamp>.json` (`-2`, `-3` on a clash).
    /// Returns the new path, or `None` when there was no file. Never deletes.
    pub fn retire_key(&self) -> io::Result<Option<PathBuf>> {
        let from = self.key_file();
        if !from.exists() {
            return Ok(None);
        }
        let base = format!("{TOOL_ID}.revoked-{}", clock::now().stamp());
        let to = unique_path(&self.0, &base, ".json");
        fs::rename(&from, &to)?;
        Ok(Some(to))
    }
}

/// `<dir>/<base><ext>`, or `<base>-2<ext>`, `-3`, … when that exists.
pub fn unique_path(dir: &Path, base: &str, ext: &str) -> PathBuf {
    let first = dir.join(format!("{base}{ext}"));
    if fs::symlink_metadata(&first).is_err() {
        return first;
    }
    let mut n = 2u32;
    loop {
        let next = dir.join(format!("{base}-{n}{ext}"));
        if fs::symlink_metadata(&next).is_err() {
            return next;
        }
        n += 1;
    }
}

/// Write `bytes` to `dest` atomically: a temp file `.panoptic.<rand>.tmp` in `dir`, fsync, rename.
pub fn write_atomic(dir: &Path, dest: &Path, bytes: &[u8], private: bool) -> io::Result<()> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    fs::create_dir_all(dir)?;
    let mut attempt = 0;
    let (mut file, tmp) = loop {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
        let rand = format!("{:x}{:x}{:x}", std::process::id(), nanos, COUNTER.fetch_add(1, Ordering::Relaxed));
        let tmp = dir.join(format!(".{TOOL_ID}.{rand}.tmp"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(not(unix))]
        let _ = private;
        match options.open(&tmp) {
            Ok(f) => break (f, tmp),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && attempt < 100 => attempt += 1,
            Err(e) => return Err(e),
        }
    };
    let result = file.write_all(bytes).and_then(|()| file.flush()).and_then(|()| file.sync_all()).and_then(|()| {
        drop(file);
        fs::rename(&tmp, dest)
    });
    if result.is_err() {
        // The temp file stays behind (we never delete); its name is dot-prefixed and unique.
        log::warn!("uplink: could not write {}", dest.display());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_with_mode_0600() {
        let tmp = tempfile::TempDir::new().unwrap();
        let state = StateDir::new(tmp.path().join("state"));
        assert_eq!(state.read_key(), None);
        let link = Link::new("cbk_abc123abc123abc123", "https://example.test");
        state.save_link(&link).unwrap();
        assert_eq!(state.read_key().as_deref(), Some("cbk_abc123abc123abc123"));
        let saved: Link = serde_json::from_slice(&fs::read(state.key_file()).unwrap()).unwrap();
        assert_eq!(saved, link);
        assert_eq!(saved.tool_id, "panoptic");
        assert!(saved.linked_at.len() >= 20, "{}", saved.linked_at);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(state.key_file()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // No temp file is left behind.
        let names: Vec<_> = fs::read_dir(state.path()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(names, vec!["panoptic.json"]);
    }

    #[test]
    fn refused_key_is_renamed_not_deleted() {
        let tmp = tempfile::TempDir::new().unwrap();
        let state = StateDir::new(tmp.path());
        assert_eq!(state.retire_key().unwrap(), None);
        state.save_link(&Link::new("cbk_one", "https://example.test")).unwrap();
        let first = state.retire_key().unwrap().unwrap();
        assert!(first.exists());
        assert!(!state.key_file().exists());
        assert_eq!(state.read_key(), None);
        let name = first.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("panoptic.revoked-") && name.ends_with(".json"), "{name}");
        // A second refusal in the same second gets a suffix; the first file is untouched.
        state.save_link(&Link::new("cbk_two", "https://example.test")).unwrap();
        let second = state.retire_key().unwrap().unwrap();
        assert_ne!(first, second);
        assert!(first.exists() && second.exists());
        assert!(fs::read_to_string(&first).unwrap().contains("cbk_one"));
        assert!(fs::read_to_string(&second).unwrap().contains("cbk_two"));
    }
}
