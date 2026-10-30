//! Looking inside a release zip: the entry rules, unzipping, and comparing an unzipped tree
//! with the zip it came from.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::BUNDLE_NAME;
use crate::trust::Trust;

/// What an entry is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Dir,
    File,
    /// A symbolic link and its (relative) target.
    Link(String),
}

/// The folder a Windows release zip holds, and the program inside it.
pub const WINDOWS_FOLDER: &str = "Panoptic";
pub const WINDOWS_EXE: &str = "Panoptic.exe";

/// Which entry rules a release zip is held to, chosen by the signed manifest's `platform`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// One top-level `Panoptic.app/` (D3's rules); also a manifest with no `platform`.
    Mac,
    /// One top-level `Panoptic/` holding the file `Panoptic/Panoptic.exe`; no symlinks.
    Windows,
}

impl Layout {
    /// The rules for a manifest: `"mac"` or no `platform` → Mac, `"windows"` → Windows, anything else → none.
    pub fn of_manifest(manifest: &Value) -> Result<Layout, String> {
        match manifest.get("platform") {
            None => Ok(Layout::Mac),
            Some(Value::String(p)) if p == "mac" => Ok(Layout::Mac),
            Some(Value::String(p)) if p == "windows" => Ok(Layout::Windows),
            Some(other) => Err(format!("no entry rules for platform {other}")),
        }
    }

    /// The one top-level folder.
    pub fn root(self) -> &'static str {
        match self {
            Layout::Mac => BUNDLE_NAME,
            Layout::Windows => WINDOWS_FOLDER,
        }
    }
}

/// One checked zip entry. `path` starts with the layout's root (`Panoptic.app`) and has no trailing slash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub kind: Kind,
    pub size: u64,
    pub crc: u32,
    pub mode: Option<u32>,
}

fn is_absolute(name: &str) -> bool {
    let b = name.as_bytes();
    name.starts_with('/') || (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':')
}

/// Where a link at `link_path` (inside `root`) points, if that stays inside `root`.
fn link_stays_inside(link_path: &str, target: &str, root: &str) -> bool {
    if target.is_empty() || target.contains('\\') || target.contains('\0') || is_absolute(target) {
        return false;
    }
    let mut stack: Vec<&str> = link_path.split('/').collect();
    stack.pop();
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                stack.pop();
                if stack.is_empty() {
                    return false;
                }
            }
            p => stack.push(p),
        }
    }
    stack.first() == Some(&root)
}

/// Read and check every entry of the zip (Mac rules).
pub fn read_entries(zip_path: &Path) -> Result<Vec<Entry>, String> {
    read_entries_in(zip_path, Layout::Mac)
}

/// Read and check every entry of the zip against `layout`'s rules.
pub fn read_entries_in(zip_path: &Path, layout: Layout) -> Result<Vec<Entry>, String> {
    let root = layout.root();
    let file = File::open(zip_path).map_err(|e| format!("cannot open the download: {e}"))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| format!("not a zip: {e}"))?;
    if archive.is_empty() {
        return Err("empty zip".into());
    }
    let mut entries: Vec<Entry> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut links = BTreeSet::new();
    for i in 0..archive.len() {
        let mut f = archive.by_index(i).map_err(|e| format!("bad zip entry: {e}"))?;
        let name = match f.name() {
            Ok(n) => n.into_owned(),
            Err(_) => String::from_utf8_lossy(f.name_raw()).into_owned(),
        };
        if name.contains('\\') {
            return Err(format!("backslash in entry: {name}"));
        }
        if name.contains('\0') || is_absolute(&name) {
            return Err(format!("absolute entry: {name}"));
        }
        let is_dir = f.is_dir();
        let trimmed = name.strip_suffix('/').unwrap_or(&name);
        let parts: Vec<&str> = trimmed.split('/').collect();
        if parts.iter().any(|p| *p == "." || *p == ".." || p.is_empty()) {
            return Err(format!("dot entry: {name}"));
        }
        if parts[0] != root {
            return Err(format!("entry outside {root}/: {name}"));
        }
        if parts.len() == 1 && !is_dir {
            return Err(format!("{root} is not a folder in the zip"));
        }
        if !seen.insert(trimmed.to_string()) {
            return Err(format!("duplicate entry: {name}"));
        }
        let mut under = String::new();
        for p in &parts[..parts.len() - 1] {
            if !under.is_empty() {
                under.push('/');
            }
            under.push_str(p);
            if links.contains(&under) {
                return Err(format!("entry under a symlink: {name}"));
            }
        }
        let kind = if f.is_symlink() {
            if layout == Layout::Windows {
                return Err(format!("symlink entry in a Windows zip: {name}"));
            }
            let mut target = String::new();
            f.by_ref().take(4097).read_to_string(&mut target).map_err(|e| format!("bad symlink entry: {e}"))?;
            if target.len() > 4096 || !link_stays_inside(trimmed, &target, root) {
                return Err(format!("symlink entry leaves {root}: {name}"));
            }
            links.insert(trimmed.to_string());
            Kind::Link(target)
        } else if is_dir {
            Kind::Dir
        } else {
            Kind::File
        };
        entries.push(Entry { path: trimmed.to_string(), kind, size: f.size(), crc: f.crc32(), mode: f.unix_mode() });
    }
    if layout == Layout::Windows {
        let exe = format!("{WINDOWS_FOLDER}/{WINDOWS_EXE}");
        if !entries.iter().any(|e| e.path == exe && e.kind == Kind::File) {
            return Err(format!("no {exe} in the zip"));
        }
    }
    Ok(entries)
}

/// Signature, size, sha256, then the entries under the rules the signed `platform` names: the
/// full check of a downloaded release.
pub fn verify_package(trust: &Trust, zip_path: &Path, manifest: &Value, signature: &str) -> Result<Vec<Entry>, String> {
    verify_package_checked(trust, zip_path, manifest, signature, None)
}

/// [`verify_package`] that also refuses a release signed for another layout (the Mac updater
/// takes only Mac releases).
pub fn verify_package_as(trust: &Trust, zip_path: &Path, manifest: &Value, signature: &str, want: Layout) -> Result<Vec<Entry>, String> {
    verify_package_checked(trust, zip_path, manifest, signature, Some(want))
}

fn verify_package_checked(trust: &Trust, zip_path: &Path, manifest: &Value, signature: &str, want: Option<Layout>) -> Result<Vec<Entry>, String> {
    if !trust.verify_manifest(manifest, signature) {
        return Err("signature does not verify".into());
    }
    let layout = Layout::of_manifest(manifest)?;
    if let Some(want) = want
        && want != layout
    {
        return Err(format!("the release is for {layout:?}, not {want:?}"));
    }
    let want_size = manifest.get("size").and_then(Value::as_u64).ok_or("manifest has no size")?;
    let want_sha = manifest.get("sha256").and_then(Value::as_str).ok_or("manifest has no sha256")?;
    let got_size = fs::metadata(zip_path).map_err(|e| format!("cannot read the download: {e}"))?.len();
    if got_size != want_size {
        return Err(format!("size {got_size} is not the manifest size {want_size}"));
    }
    let mut file = File::open(zip_path).map_err(|e| format!("cannot read the download: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| format!("cannot read the download: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    if format!("{:x}", hasher.finalize()) != want_sha {
        return Err("sha256 does not match the manifest".into());
    }
    read_entries_in(zip_path, layout)
}

/// Unzip into `dest_parent` (so the bundle lands at `dest_parent/Panoptic.app`), keeping unix
/// modes and symlinks. Plain file I/O; nothing marks the files as quarantined.
pub fn extract(zip_path: &Path, entries: &[Entry], dest_parent: &Path) -> Result<(), String> {
    let file = File::open(zip_path).map_err(|e| format!("cannot open the download: {e}"))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| format!("not a zip: {e}"))?;
    let io = |what: &str, e: std::io::Error| format!("{what}: {e}");
    let mut dir_modes: Vec<(std::path::PathBuf, u32)> = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let dest = dest_parent.join(&entry.path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| io("cannot create a folder", e))?;
        }
        match &entry.kind {
            Kind::Dir => {
                fs::create_dir_all(&dest).map_err(|e| io("cannot create a folder", e))?;
                if let Some(mode) = entry.mode {
                    dir_modes.push((dest, mode & 0o7777));
                }
            }
            Kind::File => {
                let mut f = archive.by_index(i).map_err(|e| format!("bad zip entry: {e}"))?;
                let mut out = File::create(&dest).map_err(|e| io("cannot write a file", e))?;
                std::io::copy(&mut f, &mut out).map_err(|e| io("cannot write a file", e))?;
                out.flush().map_err(|e| io("cannot write a file", e))?;
                drop(out);
                set_mode(&dest, entry.mode.map(|m| (m & 0o7777) | 0o200))?;
            }
            Kind::Link(target) => make_symlink(target, &dest)?,
        }
    }
    // Folder modes last, deepest first, so a read-only folder does not block its children.
    for (path, mode) in dir_modes.into_iter().rev() {
        set_mode(&path, Some(mode | 0o700))?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: Option<u32>) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(m) = mode {
        fs::set_permissions(path, fs::Permissions::from_mode(m)).map_err(|e| format!("cannot set a mode: {e}"))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: Option<u32>) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn make_symlink(target: &str, dest: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(target, dest).map_err(|e| format!("cannot make a symlink: {e}"))
}

#[cfg(not(unix))]
fn make_symlink(_target: &str, _dest: &Path) -> Result<(), String> {
    Err("symlinks are not supported here".into())
}

fn crc_of(path: &Path) -> std::io::Result<u32> {
    let mut f = File::open(path)?;
    let mut hasher = crc32fast::Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(hasher.finalize());
        }
        hasher.update(&buf[..n]);
    }
}

/// True when the tree at `bundle` is exactly what `entries` describe: same paths, file sizes,
/// crc32s and executable bits, same symlink targets, nothing extra (Mac layout).
pub fn tree_matches(entries: &[Entry], bundle: &Path) -> Result<(), String> {
    tree_matches_in(entries, bundle, Layout::Mac)
}

/// [`tree_matches`] for a tree unzipped under `layout`'s root (`bundle` is that root folder).
pub fn tree_matches_in(entries: &[Entry], bundle: &Path, layout: Layout) -> Result<(), String> {
    let by_path: BTreeMap<&str, &Entry> = entries.iter().map(|e| (e.path.as_str(), e)).collect();
    let mut implied = BTreeSet::new();
    for e in entries {
        let mut p = e.path.as_str();
        while let Some((parent, _)) = p.rsplit_once('/') {
            implied.insert(parent.to_string());
            p = parent;
        }
    }
    let root = fs::symlink_metadata(bundle).map_err(|e| format!("staged app is missing: {e}"))?;
    if !root.is_dir() {
        return Err("staged app is not a folder".into());
    }
    let mut seen = BTreeSet::new();
    seen.insert(layout.root().to_string());
    walk(bundle, layout.root(), &by_path, &implied, &mut seen)?;
    for e in entries {
        if !seen.contains(&e.path) {
            return Err(format!("staged app is missing {}", e.path));
        }
    }
    Ok(())
}

fn walk(dir: &Path, rel: &str, by_path: &BTreeMap<&str, &Entry>, implied: &BTreeSet<String>, seen: &mut BTreeSet<String>) -> Result<(), String> {
    let read = fs::read_dir(dir).map_err(|e| format!("cannot read the staged app: {e}"))?;
    for item in read {
        let item = item.map_err(|e| format!("cannot read the staged app: {e}"))?;
        let name = item.file_name().to_string_lossy().into_owned();
        let child = format!("{rel}/{name}");
        let path = item.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| format!("cannot read the staged app: {e}"))?;
        match by_path.get(child.as_str()) {
            Some(entry) => match &entry.kind {
                Kind::Dir => {
                    if !meta.is_dir() {
                        return Err(format!("staged {child} should be a folder"));
                    }
                }
                Kind::File => {
                    if !meta.is_file() || meta.len() != entry.size {
                        return Err(format!("staged {child} has the wrong size"));
                    }
                    if crc_of(&path).map_err(|e| format!("cannot read {child}: {e}"))? != entry.crc {
                        return Err(format!("staged {child} differs from the zip"));
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let want = entry.mode.is_some_and(|m| m & 0o111 != 0);
                        if want != (meta.permissions().mode() & 0o111 != 0) {
                            return Err(format!("staged {child} has the wrong mode"));
                        }
                    }
                }
                Kind::Link(target) => {
                    let got = fs::read_link(&path).map_err(|_| format!("staged {child} should be a symlink"))?;
                    if got.to_string_lossy() != target.as_str() {
                        return Err(format!("staged {child} points somewhere else"));
                    }
                }
            },
            None if implied.contains(&child) => {
                if !meta.is_dir() {
                    return Err(format!("staged {child} should be a folder"));
                }
            }
            None => return Err(format!("staged app has an extra item: {child}")),
        }
        seen.insert(child.clone());
        if meta.is_dir() {
            walk(&path, &child, by_path, implied, seen)?;
        }
    }
    Ok(())
}
