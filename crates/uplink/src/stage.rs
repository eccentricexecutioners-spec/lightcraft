//! Downloading and checking a release, unzipping it next to the app, and recording it as
//! pending so the next start can swap it in.

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde_json::{Value, json};

use crate::client::{Client, DownloadError, Offer, Transport, valid_version};
use crate::state::{StateDir, unique_path, write_atomic};
use crate::trust::Trust;
use crate::zipcheck::{self, tree_matches};
use crate::{BUNDLE_NAME, TOOL_ID, clock};

/// A release that is downloaded, checked and unzipped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Staged {
    pub version: String,
    pub zip_path: PathBuf,
    pub bundle_path: PathBuf,
    /// True when this version was already staged and still checks out: nothing was downloaded.
    pub already: bool,
}

/// Why staging stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StageError {
    Offline,
    TlsFailed,
    /// The release did not pass a check; the reason is for the log.
    VerifyFailed(String),
    /// A file or folder could not be written.
    Failed(String),
}

impl std::fmt::Display for StageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StageError::Offline => write!(f, "download failed"),
            StageError::TlsFailed => write!(f, "download failed securely"),
            StageError::VerifyFailed(r) => write!(f, "verify failed: {r}"),
            StageError::Failed(r) => write!(f, "staging failed: {r}"),
        }
    }
}

fn fail(what: &str) -> impl Fn(std::io::Error) -> StageError + '_ {
    move |e| StageError::Failed(format!("{what}: {e}"))
}

fn bad(reason: impl Into<String>) -> StageError {
    StageError::VerifyFailed(reason.into())
}

/// The pre-download checks on what the server offered.
fn check_offer(offer: &Offer) -> Result<(String, u64), StageError> {
    let m = &offer.manifest;
    if m.get("tool_id").and_then(Value::as_str) != Some(TOOL_ID) {
        return Err(bad("manifest is for another tool"));
    }
    let version = m.get("version").and_then(Value::as_str).unwrap_or("");
    if version != offer.version || !valid_version(version) {
        return Err(bad("manifest version is not the offered version"));
    }
    let size = m.get("size").and_then(Value::as_u64).filter(|s| *s > 0).ok_or_else(|| bad("manifest size is not a positive integer"))?;
    let file = m.get("file").and_then(Value::as_str).unwrap_or("");
    if file.is_empty() || file.contains('/') || file.contains('\\') || file == "." || file == ".." {
        return Err(bad("manifest file name is not plain"));
    }
    Ok((file.to_string(), size))
}

/// Write the pending record (atomic).
fn write_pending(state: &StateDir, record: &Value) -> Result<(), StageError> {
    let bytes = serde_json::to_vec_pretty(record).map_err(|e| StageError::Failed(e.to_string()))?;
    write_atomic(&state.pending_dir(), &state.pending_file(), &bytes, false).map_err(fail("cannot write the pending file"))
}

/// The size the offer's manifest declares, or 0 when it has none (no validation here).
pub fn offered_size(offer: &Offer) -> u64 {
    offer.manifest.get("size").and_then(Value::as_u64).unwrap_or(0)
}

/// How far a staging has got, shared with whoever watches it from another thread.
#[derive(Debug, Default)]
pub struct Progress {
    received: AtomicU64,
    total: AtomicU64,
    verifying: AtomicBool,
}

impl Progress {
    /// Bytes written so far. Never more than the manifest size plus one.
    pub fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }
    /// The manifest size, once staging has read the offer (else 0).
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
    /// True once the download has returned and the checks are running.
    pub fn verifying(&self) -> bool {
        self.verifying.load(Ordering::Relaxed)
    }
    /// Back to the start, for the next check.
    pub fn reset(&self) {
        self.received.store(0, Ordering::Relaxed);
        self.total.store(0, Ordering::Relaxed);
        self.verifying.store(false, Ordering::Relaxed);
    }
}

/// Download, verify, unzip and mark pending. Re-staging a version that still checks out
/// returns at once with `already: true`.
pub fn stage(state: &StateDir, trust: &Trust, client: &Client, offer: &Offer, from_version: &str) -> Result<Staged, StageError> {
    stage_watched(state, trust, client, offer, from_version, &Progress::default())
}

/// [`stage`], counting the download into `progress`.
pub fn stage_watched(
    state: &StateDir,
    trust: &Trust,
    client: &Client,
    offer: &Offer,
    from_version: &str,
    progress: &Progress,
) -> Result<Staged, StageError> {
    let (file, size) = check_offer(offer)?;
    progress.total.store(size, Ordering::Relaxed);
    let manifest = &offer.manifest;
    let base = format!("{TOOL_ID}-{}", offer.version);
    let staging = state.staging_dir();
    let first = staging.join(&base);

    let record = |dir: &PathBuf, zip: &PathBuf| {
        json!({
            "version": offer.version,
            "from_version": from_version,
            "zip_path": zip,
            "bundle_path": dir.join(BUNDLE_NAME),
            "manifest": manifest,
            "signature": offer.signature,
            "staged_at": clock::now().stamp(),
            "reason": "staged",
            "staged": true,
        })
    };

    // Already staged and still good?
    let zip_first = first.join(&file);
    if zip_first.exists()
        && let Ok(entries) = zipcheck::verify_package_as(trust, &zip_first, manifest, &offer.signature, zipcheck::Layout::Mac)
        && tree_matches(&entries, &first.join(BUNDLE_NAME)).is_ok()
    {
        write_pending(state, &record(&first, &zip_first))?;
        return Ok(Staged { version: offer.version.clone(), zip_path: zip_first, bundle_path: first.join(BUNDLE_NAME), already: true });
    }

    fs::create_dir_all(&staging).map_err(fail("cannot create the staging folder"))?;
    let dir = unique_path(&staging, &base, "");
    fs::create_dir(&dir).map_err(fail("cannot create the staging folder"))?;
    let zip_path = dir.join(&file);

    let mut out = File::create(&zip_path).map_err(fail("cannot create the download file"))?;
    let got = client
        .download(&offer.download_url, size, &mut |chunk| {
            out.write_all(chunk)?;
            progress.received.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            Ok(())
        })
        .map_err(|e| match e {
            DownloadError::Transport(Transport::Tls) => StageError::TlsFailed,
            DownloadError::Transport(Transport::Offline) => StageError::Offline,
            DownloadError::Write(e) => StageError::Failed(format!("cannot write the download: {e}")),
        })?;
    progress.verifying.store(true, Ordering::Relaxed);
    out.sync_all().map_err(fail("cannot write the download"))?;
    drop(out);
    if got > size {
        return Err(bad(format!("download is larger than the manifest size {size}")));
    }

    let entries = zipcheck::verify_package_as(trust, &zip_path, manifest, &offer.signature, zipcheck::Layout::Mac).map_err(bad)?;
    zipcheck::extract(&zip_path, &entries, &dir).map_err(StageError::Failed)?;
    let saved = json!({"manifest": manifest, "signature": offer.signature});
    let bytes = serde_json::to_vec_pretty(&saved).map_err(|e| StageError::Failed(e.to_string()))?;
    write_atomic(&dir, &dir.join("manifest.json"), &bytes, false).map_err(fail("cannot write manifest.json"))?;
    write_pending(state, &record(&dir, &zip_path))?;
    Ok(Staged { version: offer.version.clone(), zip_path, bundle_path: dir.join(BUNDLE_NAME), already: false })
}
