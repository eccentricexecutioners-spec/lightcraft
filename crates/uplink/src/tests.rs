//! Tests of the whole crate. Fixtures are copied from cargo-bay origin/main 9430a4a
//! (`clients/fusion-uplink/tests/fixtures/{vectors,keyring_vectors}.json`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde_json::{Value, json};

use crate::swap::{finish_pending, finish_pending_with, mark_shown, move_path, unshown_update};
use crate::testutil::*;
use crate::trust::testing::{public, sign_manifest, signing_key};
use crate::trust::{Trust, parse_spki_pem};
use crate::{LinkError, Outcome, StartOutcome, StateDir, canon, off_reason_with, outcome_message, run_check, run_link, zipcheck};

// ---- canonical JSON and signatures against the cargo-bay vectors ----

// cargo-bay origin/main 9430a4a clients/fusion-uplink/tests/fixtures/vectors.json
fn vector_rows() -> Vec<Value> {
    let v: Value = serde_json::from_str(include_str!("../tests/fixtures/cargo-bay-vectors.json")).unwrap();
    v["rows"].as_array().unwrap().clone()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn canonical_matches_cargo_bay_vectors() {
    let rows = vector_rows();
    assert_eq!(rows.len(), 11);
    for row in rows {
        let text = canon::canonical(&row["manifest"]).unwrap();
        assert_eq!(hex(text.as_bytes()), row["canonical_bytes_hex"].as_str().unwrap(), "{}", row["name"]);
    }
}

#[test]
fn cargo_bay_vectors_verify_as_expected() {
    for row in vector_rows() {
        let key = parse_spki_pem(row["public_key"].as_str().unwrap()).unwrap();
        let trust = Trust::with_master(key);
        let got = trust.verify_manifest(&row["manifest"], row["signature"].as_str().unwrap());
        assert_eq!(got, row["expect"].as_bool().unwrap(), "{}", row["name"]);
    }
}

// ---- release zips ----

fn check_zip(zip: &[u8]) -> Result<Vec<zipcheck::Entry>, String> {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("r.zip");
    fs::write(&path, zip).unwrap();
    let (m, s) = release("1.2.3", zip);
    zipcheck::verify_package(&trust(), &path, &m, &s)
}

#[test]
fn good_zip_is_accepted() {
    let entries = check_zip(&app_zip("hello")).unwrap();
    assert!(entries.iter().any(|e| e.path == "Panoptic.app/Contents/MacOS/panoptic"));
}

#[test]
fn wrong_size_is_refused() {
    let zip = app_zip("hello");
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("r.zip");
    fs::write(&path, &zip).unwrap();
    let mut m = manifest_for("1.2.3", &zip);
    m["size"] = json!(zip.len() + 1);
    let s = sign_manifest(&master(), &m);
    let err = zipcheck::verify_package(&trust(), &path, &m, &s).unwrap_err();
    assert!(err.contains("size"), "{err}");
}

#[test]
fn wrong_sha256_is_refused() {
    let zip = app_zip("hello");
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("r.zip");
    fs::write(&path, &zip).unwrap();
    let mut m = manifest_for("1.2.3", &zip);
    m["sha256"] = json!("0".repeat(64));
    let s = sign_manifest(&master(), &m);
    let err = zipcheck::verify_package(&trust(), &path, &m, &s).unwrap_err();
    assert!(err.contains("sha256"), "{err}");
}

#[test]
fn unsigned_manifest_is_refused() {
    let zip = app_zip("hello");
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("r.zip");
    fs::write(&path, &zip).unwrap();
    let m = manifest_for("1.2.3", &zip);
    let s = sign_manifest(&signing_key(77), &m);
    let err = zipcheck::verify_package(&trust(), &path, &m, &s).unwrap_err();
    assert!(err.contains("signature"), "{err}");
}

#[test]
fn zip_with_dotdot_is_refused() {
    let zip = build_zip(&[Z::Dir("Panoptic.app/"), Z::File("Panoptic.app/../evil", b"x", 0o644)]);
    let err = check_zip(&zip).unwrap_err();
    assert!(err.contains("dot entry"), "{err}");
}

#[test]
fn zip_with_absolute_path_is_refused() {
    let zip = build_zip(&[Z::Dir("Panoptic.app/"), Z::File("/etc/evil", b"x", 0o644)]);
    let err = check_zip(&zip).unwrap_err();
    assert!(err.contains("absolute entry"), "{err}");
    let zip = build_zip(&[Z::Dir("Panoptic.app/"), Z::File("C:/evil", b"x", 0o644)]);
    assert!(check_zip(&zip).unwrap_err().contains("absolute entry"));
}

#[test]
fn zip_with_two_top_level_items_is_refused() {
    let zip = build_zip(&[Z::Dir("Panoptic.app/"), Z::File("Panoptic.app/a", b"x", 0o644), Z::File("README.txt", b"x", 0o644)]);
    let err = check_zip(&zip).unwrap_err();
    assert!(err.contains("outside Panoptic.app/"), "{err}");
    let zip = build_zip(&[Z::File("Other.app/a", b"x", 0o644)]);
    assert!(check_zip(&zip).is_err());
}

#[test]
fn zip_with_escaping_symlink_is_refused() {
    for target in ["../../outside", "/etc/passwd", "../..", "a/../../.."] {
        let zip = build_zip(&[Z::Dir("Panoptic.app/"), Z::Dir("Panoptic.app/Contents/"), Z::Link("Panoptic.app/Contents/link", target)]);
        let err = check_zip(&zip).unwrap_err();
        assert!(err.contains("symlink"), "{target}: {err}");
    }
}

#[test]
fn zip_with_inner_symlink_is_accepted() {
    let zip = build_zip(&[
        Z::Dir("Panoptic.app/"),
        Z::File("Panoptic.app/real", b"x", 0o644),
        Z::Dir("Panoptic.app/Contents/"),
        Z::Link("Panoptic.app/Contents/up", "../real"),
        Z::Link("Panoptic.app/Contents/self", "."),
    ]);
    let entries = check_zip(&zip).unwrap();
    assert!(entries.iter().any(|e| e.kind == zipcheck::Kind::Link("../real".into())));
}

#[test]
fn zip_entry_under_a_symlink_is_refused() {
    let zip = build_zip(&[Z::Dir("Panoptic.app/"), Z::Link("Panoptic.app/l", "."), Z::File("Panoptic.app/l/x", b"x", 0o644)]);
    assert!(check_zip(&zip).unwrap_err().contains("under a symlink"));
}

// ---- claim ----

#[test]
fn claim_with_good_code_saves_key() {
    let tmp = tempfile::TempDir::new().unwrap();
    let server = TestServer::start(|_, _| Resp::Json(200, json!({"install_key": "cbk_goodgoodgoodgood"})));
    let cfg = config(tmp.path(), &server.url, "mac");
    run_link(&cfg, "abcd efg2").unwrap();
    assert_eq!(cfg.state.read_key().as_deref(), Some("cbk_goodgoodgoodgood"));
    let hits = server.hits();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].path, "/api/v1/installs/claim");
    assert!(hits[0].header("authorization").is_none());
    assert_eq!(hits[0].json(), json!({"link_code": "ABCD-EFG2", "tool_id": "panoptic", "platform": "mac"}));
}

#[test]
fn claim_404_403_429_give_their_messages() {
    let server = TestServer::start(|req, _| {
        let code = req.json()["link_code"].as_str().unwrap_or("").to_string();
        match code.as_str() {
            "AAAA-AAA2" => Resp::Json(404, json!({"error": "bad_code"})),
            "BBBB-BBB2" => Resp::Json(403, json!({"error": "not_granted"})),
            "CCCC-CCC2" => Resp::Json(429, json!({"error": "rate_limited", "retry_after_seconds": 5})),
            _ => Resp::Json(500, json!({"error": "server_error"})),
        }
    });
    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = config(tmp.path(), &server.url, "mac");
    let cases = [
        ("AAAA-AAA2", LinkError::BadCode, crate::messages::BAD_CODE),
        ("BBBB-BBB2", LinkError::NotGranted, crate::messages::NO_ACCESS),
        ("CCCC-CCC2", LinkError::RateLimited, crate::messages::RATE_LIMITED),
        ("DDDD-DDD2", LinkError::ServerError("server_error".into()), crate::messages::SERVER_ERROR),
    ];
    for (code, err, message) in cases {
        let got = run_link(&cfg, code).unwrap_err();
        assert_eq!(got, err, "{code}");
        assert_eq!(crate::link_message(&got), message);
    }
    assert_eq!(cfg.state.read_key(), None);
}

#[test]
fn claim_bad_code_shape_makes_no_request() {
    let server = TestServer::start(|_, _| Resp::Json(200, json!({"install_key": "cbk_x"})));
    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = config(tmp.path(), &server.url, "mac");
    for code in ["", "123", "ABCD-EFG0", "ABCD-EFGHJ", "hello world!"] {
        assert_eq!(run_link(&cfg, code).unwrap_err(), LinkError::BadCode, "{code:?}");
    }
    assert!(server.hits().is_empty());
}

// ---- check ----

#[test]
fn check_up_to_date() {
    let tmp = tempfile::TempDir::new().unwrap();
    let server = TestServer::start(|_, _| Resp::Json(200, json!({"status": "up_to_date"})));
    let cfg = config(tmp.path(), &server.url, "mac");
    link_key(tmp.path());
    assert_eq!(run_check(&cfg, &|_| {}), Outcome::UpToDate);
    assert_eq!(outcome_message(&Outcome::UpToDate, "1.0.0"), "Panoptic 1.0.0 is up to date");
    let hits = server.hits();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].header("authorization"), Some("Bearer cbk_testkeytestkeytestkey"));
    assert_eq!(
        hits[0].json(),
        json!({"tool_id": "panoptic", "installed_version": "1.0.0", "channel": "stable",
               "platform": "mac", "keyring_serial": 0})
    );
}

#[test]
fn check_when_not_linked_makes_no_request() {
    let tmp = tempfile::TempDir::new().unwrap();
    let server = TestServer::start(|_, _| Resp::Json(200, json!({"status": "up_to_date"})));
    let cfg = config(tmp.path(), &server.url, "mac");
    assert_eq!(run_check(&cfg, &|_| {}), Outcome::NotLinked);
    assert!(server.hits().is_empty());
}

#[test]
fn check_keeps_a_newer_key_list() {
    let fx: Value = serde_json::from_str(include_str!("../tests/fixtures/cargo-bay-keyring-vectors.json")).unwrap();
    let list = fx["lists"]["two_keys_2"].clone();
    let tmp = tempfile::TempDir::new().unwrap();
    let reply = list.clone();
    let server = TestServer::start(move |_, _| Resp::Json(200, json!({"status": "up_to_date", "keyring": reply})));
    let mut cfg = config(tmp.path(), &server.url, "mac");
    cfg.trust = Trust::with_master(parse_spki_pem(fx["master_public_key"].as_str().unwrap()).unwrap());
    link_key(tmp.path());
    assert_eq!(run_check(&cfg, &|_| {}), Outcome::UpToDate);
    assert_eq!(crate::keyring::held_serial(&cfg.state, &cfg.trust.masters()), 2);
    assert_eq!(run_check(&cfg, &|_| {}), Outcome::UpToDate);
    assert_eq!(server.hits()[1].json()["keyring_serial"], json!(2));
}

#[test]
fn check_update_downloads_verifies_and_stages_pending() {
    let tmp = tempfile::TempDir::new().unwrap();
    let zip = app_zip("new build");
    let server = update_server("2.0.0", zip.clone());
    let cfg = config(tmp.path(), &server.url, "mac");
    link_key(tmp.path());
    let heard = std::cell::RefCell::new(String::new());
    let out = run_check(&cfg, &|v| *heard.borrow_mut() = v.to_string());
    assert_eq!(out, Outcome::Staged { version: "2.0.0".into(), already: false });
    assert_eq!(heard.borrow().as_str(), "2.0.0");

    let hits = server.hits();
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[1].method, "GET");
    assert!(hits[1].header("authorization").is_none(), "the signed URL gets no auth header");

    let pending: Value = serde_json::from_str(&fs::read_to_string(cfg.state.pending_file()).unwrap()).unwrap();
    assert_eq!(pending["version"], "2.0.0");
    assert_eq!(pending["from_version"], "1.0.0");
    assert_eq!(pending["reason"], "staged");
    assert_eq!(pending["staged"], true);
    let bundle = PathBuf::from(pending["bundle_path"].as_str().unwrap());
    assert!(bundle.starts_with(cfg.state.staging_dir().join("panoptic-2.0.0")));
    assert_eq!(fs::read_to_string(bundle.join("Contents/MacOS/panoptic")).unwrap(), "new build");
    assert_eq!(fs::read_link(bundle.join("Contents/Frameworks/panoptic")).unwrap(), Path::new("../MacOS/panoptic"));
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(bundle.join("Contents/MacOS/panoptic")).unwrap().permissions().mode();
        assert_eq!(mode & 0o111, 0o111);
    }
    assert_eq!(fs::read(pending["zip_path"].as_str().unwrap()).unwrap(), zip);
    assert!(bundle.parent().unwrap().join("manifest.json").exists());
    assert_eq!(StateDirView(&cfg.state).ready(), Some("2.0.0".into()));

    // Staging the same version again downloads nothing.
    let again = run_check(&cfg, &|_| {});
    assert_eq!(again, Outcome::Staged { version: "2.0.0".into(), already: true });
    assert_eq!(server.hits().iter().filter(|h| h.method == "GET").count(), 1);
}

struct StateDirView<'a>(&'a StateDir);

impl StateDirView<'_> {
    fn ready(&self) -> Option<String> {
        let mut cfg = config(self.0.path(), "http://127.0.0.1:1", "mac");
        cfg.installed_version = "1.0.0".into();
        crate::Updater::new(cfg).view().ready
    }
}

#[test]
fn check_update_with_bad_signature_is_not_staged() {
    let tmp = tempfile::TempDir::new().unwrap();
    let zip = app_zip("new build");
    let manifest = manifest_for("2.0.0", &zip);
    let signature = sign_manifest(&signing_key(55), &manifest);
    let z = zip.clone();
    let server = TestServer::start(move |req, base| {
        if req.method == "POST" {
            Resp::Json(
                200,
                json!({"status": "update", "release": {"version": "2.0.0", "channel": "stable",
                "manifest": manifest, "signature": signature, "download_url": format!("{base}/dl")}}),
            )
        } else {
            Resp::Bytes(200, z.clone())
        }
    });
    let cfg = config(tmp.path(), &server.url, "mac");
    link_key(tmp.path());
    assert!(matches!(run_check(&cfg, &|_| {}), Outcome::VerifyFailed(_)));
    assert!(!cfg.state.pending_file().exists());
}

// D6: Cargo Bay may sign `"platform": "mac"` into a Mac manifest. The manifest is checked as received (a Value,
// canonicalised with every key), so the extra field is covered by the signature and ignored by every field read.
#[test]
fn check_update_with_platform_in_the_signed_manifest_is_staged() {
    let tmp = tempfile::TempDir::new().unwrap();
    let zip = app_zip("new build");
    let mut manifest = manifest_for("2.0.0", &zip);
    manifest["platform"] = json!("mac");
    let signature = sign_manifest(&master(), &manifest);
    let z = zip.clone();
    let server = TestServer::start(move |req, base| {
        if req.method == "POST" {
            Resp::Json(
                200,
                json!({"status": "update", "release": {"version": "2.0.0", "channel": "stable",
                "manifest": manifest, "signature": signature, "download_url": format!("{base}/dl")}}),
            )
        } else {
            Resp::Bytes(200, z.clone())
        }
    });
    let cfg = config(tmp.path(), &server.url, "mac");
    link_key(tmp.path());
    assert_eq!(run_check(&cfg, &|_| {}), Outcome::Staged { version: "2.0.0".into(), already: false });
    let pending: Value = serde_json::from_str(&fs::read_to_string(cfg.state.pending_file()).unwrap()).unwrap();
    assert!(pending.to_string().contains("\"platform\":\"mac\""), "{pending}");
}

#[test]
fn check_401_retires_key() {
    let tmp = tempfile::TempDir::new().unwrap();
    let server = TestServer::start(|_, _| Resp::Json(401, json!({"error": "bad_key"})));
    let cfg = config(tmp.path(), &server.url, "mac");
    link_key(tmp.path());
    assert_eq!(run_check(&cfg, &|_| {}), Outcome::LinkRemoved);
    assert_eq!(cfg.state.read_key(), None);
    let names: Vec<String> = fs::read_dir(tmp.path()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    assert!(names.iter().any(|n| n.starts_with("panoptic.revoked-")), "{names:?}");
    assert_eq!(outcome_message(&Outcome::LinkRemoved, "1.0.0"), crate::messages::LINK_REMOVED);
}

#[test]
fn check_timeout_gives_one_message_and_no_retry() {
    let tmp = tempfile::TempDir::new().unwrap();
    let server = TestServer::start(|_, _| Resp::Hang);
    let mut cfg = config(tmp.path(), &server.url, "mac");
    cfg.timeout = std::time::Duration::from_secs(1);
    link_key(tmp.path());
    let t = Instant::now();
    assert_eq!(run_check(&cfg, &|_| {}), Outcome::Offline);
    let took = t.elapsed();
    assert!(took >= std::time::Duration::from_secs(1) && took < std::time::Duration::from_secs(5), "{took:?}");
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(server.hits().len(), 1, "no retry");
    assert_eq!(outcome_message(&Outcome::Offline, "1.0.0"), crate::messages::OFFLINE);
}

#[test]
fn default_timeout_is_ten_seconds() {
    assert_eq!(crate::TIMEOUT, std::time::Duration::from_secs(10));
}

#[test]
fn check_on_windows_reports_elsewhere_without_download() {
    let tmp = tempfile::TempDir::new().unwrap();
    let server = update_server("2.0.0", app_zip("x"));
    let cfg = config(tmp.path(), &server.url, "windows");
    link_key(tmp.path());
    assert_eq!(run_check(&cfg, &|_| panic!("no staging on windows")), Outcome::Elsewhere("2.0.0".into()));
    let hits = server.hits();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].json()["platform"], "windows");
    assert!(!cfg.state.staging_dir().exists());
    assert!(outcome_message(&Outcome::Elsewhere("2.0.0".into()), "1.0.0").starts_with("2.0.0 is available"));
}

// ---- swap at start ----

/// Stage `version` through the server; return (state tempdir, config, installed bundle).
fn staged(version: &str, new_body: &str) -> (tempfile::TempDir, crate::Config, PathBuf, TestServer) {
    let tmp = tempfile::TempDir::new().unwrap();
    let server = update_server(version, app_zip(new_body));
    let state = tmp.path().join("state");
    let cfg = config(&state, &server.url, "mac");
    link_key(&state);
    assert!(matches!(run_check(&cfg, &|_| {}), Outcome::Staged { .. }));
    let bundle = fake_installed(tmp.path(), "old build");
    (tmp, cfg, bundle, server)
}

fn read_exe(bundle: &Path) -> String {
    fs::read_to_string(bundle.join("Contents/MacOS/panoptic")).unwrap()
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> =
        fs::read_dir(dir).map(|r| r.map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
    v.sort();
    v
}

#[test]
fn pending_update_swaps_in_and_backs_up_old_bundle() {
    let (_tmp, cfg, bundle, _server) = staged("2.0.0", "new build");
    let out = finish_pending(&cfg.state, &cfg.trust, &bundle, "1.0.0");
    assert_eq!(out, StartOutcome::Swapped { from: "1.0.0".into(), to: "2.0.0".into() });
    assert_eq!(read_exe(&bundle), "new build");
    assert_eq!(fs::read_link(bundle.join("Contents/Frameworks/panoptic")).unwrap(), Path::new("../MacOS/panoptic"));
    let backups = names(&cfg.state.backups_dir());
    assert_eq!(backups.len(), 1);
    assert!(backups[0].starts_with("Panoptic-1.0.0-") && backups[0].ends_with(".app"), "{backups:?}");
    assert_eq!(read_exe(&cfg.state.backups_dir().join(&backups[0])), "old build");
    // The pending file became a done file with the outcome in it.
    assert!(!cfg.state.pending_file().exists());
    let pending = names(&cfg.state.pending_dir());
    assert_eq!(pending.len(), 1);
    assert!(pending[0].starts_with("panoptic.done-"), "{pending:?}");
    let done: Value = serde_json::from_str(&fs::read_to_string(cfg.state.pending_dir().join(&pending[0])).unwrap()).unwrap();
    assert_eq!(done["outcome"], "installed");
    assert_eq!(done["from_version"], "1.0.0");
    assert_eq!(done["to_version"], "2.0.0");
    assert!(done["finished_at"].is_string());
    // Nothing pending now.
    assert_eq!(finish_pending(&cfg.state, &cfg.trust, &bundle, "2.0.0"), StartOutcome::NothingPending);
}

/// C1-P8 (D3-P9's measurement again): the app a tester opened from a browser download carries
/// `com.apple.quarantine`; the copy the updater swaps in does not, and nothing in it does.
#[test]
#[cfg(target_os = "macos")]
fn swapped_in_bundle_carries_no_quarantine_mark() {
    let quarantined = |bundle: &Path| {
        let out = std::process::Command::new("xattr").arg("-rl").arg(bundle).output().unwrap();
        String::from_utf8_lossy(&out.stdout).matches("com.apple.quarantine").count()
    };
    let (_tmp, cfg, bundle, _server) = staged("2.0.0", "new build");
    let mark = "0083;00000000;Safari;";
    assert!(std::process::Command::new("xattr").args(["-w", "com.apple.quarantine", mark]).arg(&bundle).status().unwrap().success());
    assert_eq!(quarantined(&bundle), 1, "the installed copy starts marked");
    assert!(matches!(finish_pending(&cfg.state, &cfg.trust, &bundle, "1.0.0"), StartOutcome::Swapped { .. }));
    assert_eq!(read_exe(&bundle), "new build");
    assert_eq!(quarantined(&bundle), 0, "the swapped-in bundle has no quarantine mark");
}

#[test]
fn failing_move_restores_old_bundle_and_keeps_pending() {
    let (_tmp, cfg, bundle, _server) = staged("2.0.0", "new build");
    let calls = Cell::new(0);
    let mover = |from: &Path, to: &Path| {
        calls.set(calls.get() + 1);
        if calls.get() == 2 { Err(std::io::Error::other("disk on fire")) } else { move_path(from, to) }
    };
    let out = finish_pending_with(&cfg.state, &cfg.trust, &bundle, "1.0.0", &mover);
    assert!(matches!(&out, StartOutcome::InstallFailed(r) if r.contains("disk on fire")), "{out:?}");
    assert_eq!(read_exe(&bundle), "old build");
    assert!(cfg.state.pending_file().exists());
    assert!(names(&cfg.state.pending_dir()).iter().all(|n| !n.contains("done")));
    assert!(names(&cfg.state.backups_dir()).is_empty(), "the backup went back");
    // The staged copy is still there for another try.
    let out = finish_pending(&cfg.state, &cfg.trust, &bundle, "1.0.0");
    assert!(matches!(out, StartOutcome::Swapped { .. }), "{out:?}");
}

#[test]
fn pending_that_fails_reverification_is_not_swapped() {
    // A staged file changed after staging.
    let (_tmp, cfg, bundle, _server) = staged("2.0.0", "new build");
    let pending: Value = serde_json::from_str(&fs::read_to_string(cfg.state.pending_file()).unwrap()).unwrap();
    let staged_bundle = PathBuf::from(pending["bundle_path"].as_str().unwrap());
    fs::write(staged_bundle.join("Contents/MacOS/panoptic"), "evil build").unwrap();
    let out = finish_pending(&cfg.state, &cfg.trust, &bundle, "1.0.0");
    assert!(matches!(out, StartOutcome::VerifyFailed(_)), "{out:?}");
    assert_eq!(read_exe(&bundle), "old build");
    assert!(cfg.state.pending_file().exists());
    assert!(!cfg.state.backups_dir().exists());

    // An extra file in the staged app.
    let (_tmp, cfg, bundle, _server) = staged("2.0.0", "new build");
    let pending: Value = serde_json::from_str(&fs::read_to_string(cfg.state.pending_file()).unwrap()).unwrap();
    let staged_bundle = PathBuf::from(pending["bundle_path"].as_str().unwrap());
    fs::write(staged_bundle.join("Contents/extra"), "x").unwrap();
    assert!(matches!(finish_pending(&cfg.state, &cfg.trust, &bundle, "1.0.0"), StartOutcome::VerifyFailed(_)));

    // A key that no longer trusts the signature.
    let (_tmp, cfg, bundle, _server) = staged("2.0.0", "new build");
    let other = Trust::with_master(public(&signing_key(9)));
    assert!(matches!(finish_pending(&cfg.state, &other, &bundle, "1.0.0"), StartOutcome::VerifyFailed(_)));
    assert_eq!(read_exe(&bundle), "old build");
}

#[test]
fn unreadable_pending_is_reported() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = StateDir::new(tmp.path());
    fs::create_dir_all(state.pending_dir()).unwrap();
    fs::write(state.pending_file(), "{not json").unwrap();
    let bundle = fake_installed(tmp.path(), "old");
    assert!(matches!(finish_pending(&state, &trust(), &bundle, "1.0.0"), StartOutcome::Unreadable(_)));
}

#[test]
fn done_message_is_shown_once() {
    let (_tmp, cfg, bundle, _server) = staged("2.0.0", "new build");
    assert_eq!(unshown_update(&cfg.state), None);
    finish_pending(&cfg.state, &cfg.trust, &bundle, "1.0.0");
    assert_eq!(unshown_update(&cfg.state), Some(("2.0.0".into(), "1.0.0".into())));
    assert_eq!(unshown_update(&cfg.state), Some(("2.0.0".into(), "1.0.0".into())), "reading does not mark it");
    mark_shown(&cfg.state);
    assert_eq!(unshown_update(&cfg.state), None);
    let line = crate::messages::fill(crate::messages::UPDATED_FROM, &[("new", "2.0.0"), ("old", "1.0.0")]);
    assert_eq!(line, "Updated to 2.0.0 (was 1.0.0)");
}

#[test]
fn current_bundle_is_three_levels_up() {
    let exe = Path::new("/Applications/Panoptic.app/Contents/MacOS/panoptic");
    assert_eq!(crate::current_bundle(exe), Some(PathBuf::from("/Applications/Panoptic.app")));
    assert_eq!(crate::current_bundle(Path::new("/repo/target/debug/panoptic")), None);
    assert_eq!(crate::current_bundle(Path::new("/Applications/Panoptic.app/Contents/Resources/panoptic")), None);
    assert_eq!(crate::current_bundle(Path::new("/x/Contents/MacOS/panoptic")), None);
    assert_eq!(crate::current_bundle(Path::new("panoptic")), None);
}

#[test]
fn off_switch_honours_env_headless_and_dev_runs() {
    let app = Path::new("/Applications/Panoptic.app/Contents/MacOS/panoptic");
    let dev = Path::new("/repo/target/debug/panoptic");
    let env = |pairs: &'static [(&'static str, &'static str)]| move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string());
    assert_eq!(off_reason_with(&env(&[]), false, app, true), None);
    assert!(off_reason_with(&env(&[("PANOPTIC_NO_UPDATE", "1")]), false, app, true).is_some());
    assert_eq!(off_reason_with(&env(&[("PANOPTIC_NO_UPDATE", "0")]), false, app, true), None);
    assert!(off_reason_with(&env(&[("LIGHTCRAFT_NO_PREFS", "1")]), false, app, true).is_some());
    assert_eq!(off_reason_with(&env(&[("LIGHTCRAFT_NO_PREFS", "")]), false, app, true), None);
    assert!(off_reason_with(&env(&[]), true, app, true).is_some());
    assert!(off_reason_with(&env(&[]), false, dev, true).is_some(), "mac: not in a bundle");
    assert!(off_reason_with(&env(&[]), false, dev, false).is_some(), "other: target/ in the path");
    assert_eq!(off_reason_with(&env(&[]), false, Path::new("/opt/panoptic/panoptic"), false), None);
}

#[test]
fn updater_runs_in_the_background_and_updates_the_view() {
    let tmp = tempfile::TempDir::new().unwrap();
    let server = update_server("2.0.0", app_zip("new build"));
    let cfg = config(tmp.path(), &server.url, "mac");
    link_key(tmp.path());
    let updater = crate::Updater::new(cfg);
    let changes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c2 = changes.clone();
    updater.set_on_change(move || {
        c2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    });
    assert!(updater.view().linked && updater.view().ready.is_none());
    updater.check();
    let t = Instant::now();
    while updater.view().busy || updater.view().ready.is_none() {
        assert!(t.elapsed() < std::time::Duration::from_secs(10));
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let view = updater.view();
    assert_eq!(view.ready.as_deref(), Some("2.0.0"));
    assert_eq!(view.message.as_deref(), Some("2.0.0 ready — Restart to update"));
    assert!(changes.load(std::sync::atomic::Ordering::Relaxed) >= 2);
}

#[test]
fn pending_that_is_not_newer_is_set_aside_not_swapped() {
    let (_tmp, cfg, bundle, _server) = staged("2.0.0", "new build");
    let out = finish_pending(&cfg.state, &cfg.trust, &bundle, "2.0.0");
    assert_eq!(out, StartOutcome::NothingPending);
    assert_eq!(read_exe(&bundle), "old build");
    assert!(!cfg.state.pending_file().exists());
    let pending = names(&cfg.state.pending_dir());
    assert!(pending.iter().any(|n| n.starts_with("panoptic.stale-")), "{pending:?}");
    assert!(names(&cfg.state.backups_dir()).is_empty());
}

#[test]
fn versions_compare_like_cargo_bay() {
    use crate::client::newer;
    assert!(newer("0.1.1", "0.1.0"));
    assert!(newer("0.2.0", "0.1.9"));
    assert!(newer("0.1.1", "0.1.1-beta.3"));
    assert!(newer("0.1.1-beta.2", "0.1.1-beta.1"));
    assert!(!newer("0.1.0", "0.1.0"));
    assert!(!newer("0.1.0", "0.10.0"));
    assert!(!newer("junk", "0.1.0"));
}

static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// With `LIGHTCRAFT_NO_PREFS` set the updater is off, and nothing in the crate's start-up path
/// (the off check, the configuration, a new updater) talks to the server.
#[test]
#[allow(unsafe_code)]
fn from_env_is_none_with_no_prefs_and_makes_no_request() {
    let _guard = ENV.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let tmp = tempfile::TempDir::new().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    // SAFETY: only this test touches these variables, under the ENV lock.
    unsafe {
        std::env::set_var("LIGHTCRAFT_NO_PREFS", "1");
        std::env::set_var("PANOPTIC_CARGO_BAY_URL", &url);
        std::env::set_var("PANOPTIC_CARGO_BAY_STATE_DIR", tmp.path());
    }
    let exe = Path::new("/Applications/Panoptic.app/Contents/MacOS/panoptic");
    let off = crate::off_reason(false, exe);
    let updater = crate::Updater::new(crate::Config::from_env("0.1.0"));
    let view = updater.view();
    // SAFETY: as above.
    unsafe {
        std::env::remove_var("LIGHTCRAFT_NO_PREFS");
        std::env::remove_var("PANOPTIC_CARGO_BAY_URL");
        std::env::remove_var("PANOPTIC_CARGO_BAY_STATE_DIR");
    }
    assert_eq!(off, Some("LIGHTCRAFT_NO_PREFS is set"));
    assert!(!view.linked && !view.busy);
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock), "the server heard from the crate");
}

#[test]
fn relaunch_passes_on_isolation_and_control_variables() {
    use crate::swap::relaunch_keeps;
    for k in ["PANOPTIC_CARGO_BAY_URL", "PANOPTIC_CARGO_BAY_STATE_DIR", "LIGHTCRAFT_CONFIG_DIR", "LIGHTCRAFT_CONTROL_PORT", "LIGHTCRAFT_LIBRARY"] {
        assert!(relaunch_keeps(k), "{k}");
    }
    for k in ["HOME", "PATH", "LIGHTCRAFT_NO_PREFS_X", "DYLD_INSERT_LIBRARIES"] {
        assert!(!relaunch_keeps(k), "{k}");
    }
}

// ---- progress for the update window ----

fn wait_idle(updater: &crate::Updater) {
    let t = Instant::now();
    while updater.view().busy {
        assert!(t.elapsed() < std::time::Duration::from_secs(10));
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn progress_counts_up_to_the_manifest_size() {
    use crate::{OfferInfo, Progress, run_check_watched};
    let tmp = tempfile::TempDir::new().unwrap();
    let zip = app_zip("new build");
    let server = update_server("2.0.0", zip.clone());
    let cfg = config(tmp.path(), &server.url, "mac");
    link_key(tmp.path());
    let progress = Progress::default();
    let heard: std::cell::RefCell<Vec<(OfferInfo, u64, bool)>> = Default::default();
    let out = run_check_watched(&cfg, &progress, &|info| {
        heard.borrow_mut().push((info.clone(), progress.received(), progress.verifying()));
    });
    assert_eq!(out, Outcome::Staged { version: "2.0.0".into(), already: false });
    let heard = heard.into_inner();
    assert_eq!(heard.len(), 1);
    let (info, received_then, verifying_then) = &heard[0];
    assert_eq!((info.version.as_str(), info.size, info.will_download), ("2.0.0", zip.len() as u64, true));
    assert_eq!(info.notes, "test release");
    assert!(*received_then == 0 && !*verifying_then, "the offer is heard before the download");
    assert_eq!(progress.received(), zip.len() as u64);
    assert_eq!(progress.total(), zip.len() as u64);
    assert!(progress.verifying());
}

#[test]
fn progress_is_reported_while_downloading() {
    use crate::{Progress, run_check_watched};
    let tmp = tempfile::TempDir::new().unwrap();
    let zip = app_zip("new build");
    let (manifest, signature) = release("2.0.0", &zip);
    let z = zip.clone();
    // Six pieces, 120 ms apart: far wider than the 2 ms polling below.
    let server = TestServer::start(move |req, base| {
        if req.method == "POST" {
            Resp::Json(
                200,
                json!({"status": "update", "release": {"version": "2.0.0", "channel": "stable",
                "manifest": manifest, "signature": signature, "download_url": format!("{base}/dl")}}),
            )
        } else {
            Resp::Slow(z.clone(), 6, 120)
        }
    });
    let cfg = config(tmp.path(), &server.url, "mac");
    link_key(tmp.path());
    let progress = Progress::default();
    let done = std::sync::atomic::AtomicBool::new(false);
    let total = zip.len() as u64;
    let seen_middle = std::thread::scope(|s| {
        let watcher = s.spawn(|| {
            let mut middle = false;
            while !done.load(std::sync::atomic::Ordering::Relaxed) {
                let r = progress.received();
                assert!(r <= total, "never more than the size");
                middle |= r > 0 && r < total;
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            middle
        });
        let out = run_check_watched(&cfg, &progress, &|_| {});
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(matches!(out, Outcome::Staged { .. }), "{out:?}");
        watcher.join().unwrap()
    });
    assert!(seen_middle, "saw a count between 0 and the total");
    assert_eq!(progress.received(), total);
}

#[test]
fn verification_is_unchanged_with_progress() {
    use crate::{Progress, run_check_watched};
    let tmp = tempfile::TempDir::new().unwrap();
    let zip = app_zip("new build");
    // Signed correctly, but the bytes served are not the ones the manifest names.
    let (manifest, signature) = release("2.0.0", &zip);
    let other = app_zip("tampered!!");
    let server = TestServer::start(move |req, base| {
        if req.method == "POST" {
            Resp::Json(
                200,
                json!({"status": "update", "release": {"version": "2.0.0", "channel": "stable",
                "manifest": manifest, "signature": signature, "download_url": format!("{base}/dl")}}),
            )
        } else {
            Resp::Bytes(200, other.clone())
        }
    });
    let cfg = config(tmp.path(), &server.url, "mac");
    link_key(tmp.path());
    let progress = Progress::default();
    assert!(matches!(run_check_watched(&cfg, &progress, &|_| {}), Outcome::VerifyFailed(_)));
    assert!(!cfg.state.pending_file().exists());
    assert!(progress.verifying());

    // And a bad signature, as in the D3 test.
    let manifest = manifest_for("2.0.0", &zip);
    let signature = sign_manifest(&signing_key(55), &manifest);
    let z = zip.clone();
    let server = TestServer::start(move |req, base| {
        if req.method == "POST" {
            Resp::Json(
                200,
                json!({"status": "update", "release": {"version": "2.0.0", "channel": "stable",
                "manifest": manifest, "signature": signature, "download_url": format!("{base}/dl")}}),
            )
        } else {
            Resp::Bytes(200, z.clone())
        }
    });
    let tmp2 = tempfile::TempDir::new().unwrap();
    let cfg = config(tmp2.path(), &server.url, "mac");
    link_key(tmp2.path());
    assert!(matches!(run_check_watched(&cfg, &Progress::default(), &|_| {}), Outcome::VerifyFailed(_)));
    assert!(!cfg.state.pending_file().exists());
}

#[test]
fn updater_view_carries_offer_progress_and_errors() {
    use crate::messages;
    // An update: offered, total, received == total, ready.
    let tmp = tempfile::TempDir::new().unwrap();
    let zip = app_zip("new build");
    let server = update_server("2.0.0", zip.clone());
    link_key(tmp.path());
    let updater = crate::Updater::new(config(tmp.path(), &server.url, "mac"));
    assert_eq!(updater.view().installed, "1.0.0");
    updater.check();
    wait_idle(&updater);
    let v = updater.view();
    assert_eq!(v.offered.as_deref(), Some("2.0.0"));
    assert_eq!(v.notes.as_deref(), Some("test release"));
    assert_eq!((v.total, v.received), (zip.len() as u64, zip.len() as u64));
    assert_eq!(v.ready.as_deref(), Some("2.0.0"));
    assert!(!v.verifying && !v.up_to_date && v.error.is_none());

    // Offline.
    let tmp = tempfile::TempDir::new().unwrap();
    link_key(tmp.path());
    let updater = crate::Updater::new(config(tmp.path(), "http://127.0.0.1:1", "mac"));
    updater.check();
    wait_idle(&updater);
    let v = updater.view();
    assert_eq!(v.error.as_deref(), Some(messages::OFFLINE));
    assert!(v.offered.is_none() && !v.up_to_date);

    // Up to date; a later check clears an earlier error.
    let tmp = tempfile::TempDir::new().unwrap();
    link_key(tmp.path());
    let server = TestServer::start(|_, _| Resp::Json(200, json!({"status": "up_to_date"})));
    let updater = crate::Updater::new(config(tmp.path(), &server.url, "mac"));
    updater.check();
    wait_idle(&updater);
    let v = updater.view();
    assert!(v.up_to_date && v.error.is_none());
    assert_eq!(v.message.as_deref(), Some("Panoptic 1.0.0 is up to date"));

    // Elsewhere: offered and total, nothing downloaded.
    let tmp = tempfile::TempDir::new().unwrap();
    link_key(tmp.path());
    let server = update_server("2.0.0", zip.clone());
    let updater = crate::Updater::new(config(tmp.path(), &server.url, "windows"));
    updater.check();
    wait_idle(&updater);
    let v = updater.view();
    assert_eq!((v.offered.as_deref(), v.elsewhere.as_deref()), (Some("2.0.0"), Some("2.0.0")));
    assert_eq!((v.received, v.ready), (0, None));
}

// ---- D7: Windows ----

#[test]
#[cfg(target_os = "macos")]
fn platform_is_mac_on_macos() {
    assert_eq!(crate::client::platform(), "mac");
}

#[test]
fn platform_for_os_maps_windows_and_linux() {
    use crate::client::platform_for;
    assert_eq!(platform_for("macos"), "mac");
    assert_eq!(platform_for("windows"), "windows");
    assert_eq!(platform_for("linux"), "linux");
    assert_eq!(platform_for("freebsd"), "linux");
}

#[test]
fn updater_is_on_for_a_windows_exe_with_no_off_switch() {
    let env = |pairs: &'static [(&'static str, &'static str)]| move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string());
    for exe in [r"C:\Users\Ken\Downloads\Panoptic\Panoptic.exe", "C:/Users/Ken/Downloads/Panoptic/Panoptic.exe"] {
        assert_eq!(off_reason_with(&env(&[]), false, Path::new(exe), false), None, "{exe}");
        assert!(off_reason_with(&env(&[("PANOPTIC_NO_UPDATE", "1")]), false, Path::new(exe), false).is_some(), "{exe}");
        assert!(off_reason_with(&env(&[("LIGHTCRAFT_NO_PREFS", "1")]), false, Path::new(exe), false).is_some(), "{exe}");
    }
    let dev = Path::new("C:/src/panoptic/target/release-slim/lightcraft.exe");
    assert!(off_reason_with(&env(&[]), false, dev, false).is_some(), "a build under target/ is a development run");
}

/// The zip the Windows release carries: one `Panoptic/` folder holding `Panoptic.exe`.
fn windows_zip(body: &str) -> Vec<u8> {
    build_zip(&[Z::Dir("Panoptic/"), Z::File("Panoptic/Panoptic.exe", body.as_bytes(), 0o644)])
}

/// Check `zip` against a manifest signed with `platform` (`None`: no platform field).
fn check_zip_for(zip: &[u8], platform: Option<&str>) -> Result<Vec<zipcheck::Entry>, String> {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("r.zip");
    fs::write(&path, zip).unwrap();
    let mut m = manifest_for("1.2.3", zip);
    if let Some(p) = platform {
        m["platform"] = json!(p);
    }
    let s = sign_manifest(&master(), &m);
    zipcheck::verify_package(&trust(), &path, &m, &s)
}

#[test]
fn windows_zip_passes_the_windows_rules() {
    let entries = check_zip_for(&windows_zip("MZ"), Some("windows")).unwrap();
    assert!(entries.iter().any(|e| e.path == "Panoptic/Panoptic.exe" && e.kind == zipcheck::Kind::File));
}

#[test]
fn windows_zip_fails_the_mac_rules() {
    for platform in [Some("mac"), None] {
        let err = check_zip_for(&windows_zip("MZ"), platform).unwrap_err();
        assert!(err.contains("outside Panoptic.app"), "{platform:?}: {err}");
    }
}

#[test]
fn mac_zip_still_passes_mac_and_fails_windows() {
    assert!(check_zip_for(&app_zip("hello"), Some("mac")).is_ok());
    let err = check_zip_for(&app_zip("hello"), Some("windows")).unwrap_err();
    assert!(err.contains("outside Panoptic/"), "{err}");
}

#[test]
fn windows_zip_without_the_exe_or_with_extras_is_refused() {
    let no_exe = build_zip(&[Z::Dir("Panoptic/"), Z::File("Panoptic/readme.txt", b"x", 0o644)]);
    assert!(check_zip_for(&no_exe, Some("windows")).unwrap_err().contains("no Panoptic/Panoptic.exe"));
    let exe_dir = build_zip(&[Z::Dir("Panoptic/"), Z::Dir("Panoptic/Panoptic.exe/")]);
    assert!(check_zip_for(&exe_dir, Some("windows")).unwrap_err().contains("no Panoptic/Panoptic.exe"));
    let macosx = build_zip(&[Z::Dir("Panoptic/"), Z::File("Panoptic/Panoptic.exe", b"MZ", 0o644), Z::File("__MACOSX/._Panoptic.exe", b"x", 0o644)]);
    assert!(check_zip_for(&macosx, Some("windows")).unwrap_err().contains("outside Panoptic/"));
    let two_tops = build_zip(&[Z::Dir("Panoptic/"), Z::File("Panoptic/Panoptic.exe", b"MZ", 0o644), Z::File("Other/x", b"x", 0o644)]);
    assert!(check_zip_for(&two_tops, Some("windows")).is_err());
    let link = build_zip(&[Z::Dir("Panoptic/"), Z::File("Panoptic/Panoptic.exe", b"MZ", 0o644), Z::Link("Panoptic/e", "Panoptic.exe")]);
    assert!(check_zip_for(&link, Some("windows")).unwrap_err().contains("symlink"));
}

#[test]
fn unknown_platform_has_no_entry_rules() {
    let err = check_zip_for(&app_zip("hello"), Some("amiga")).unwrap_err();
    assert!(err.contains("no entry rules"), "{err}");
}

#[test]
fn mac_updater_refuses_a_windows_release() {
    let zip = windows_zip("MZ");
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("r.zip");
    fs::write(&path, &zip).unwrap();
    let mut m = manifest_for("1.2.3", &zip);
    m["platform"] = json!("windows");
    let s = sign_manifest(&master(), &m);
    let err = zipcheck::verify_package_as(&trust(), &path, &m, &s, zipcheck::Layout::Mac).unwrap_err();
    assert!(err.contains("for Windows, not Mac"), "{err}");
    assert!(zipcheck::verify_package_as(&trust(), &path, &m, &s, zipcheck::Layout::Windows).is_ok());
}

#[test]
fn unzipped_windows_tree_matches_its_zip() {
    let zip = windows_zip("MZ body");
    let entries = check_zip_for(&zip, Some("windows")).unwrap();
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("r.zip");
    fs::write(&path, &zip).unwrap();
    let dest = tmp.path().join("out");
    zipcheck::extract(&path, &entries, &dest).unwrap();
    zipcheck::tree_matches_in(&entries, &dest.join("Panoptic"), zipcheck::Layout::Windows).unwrap();
    fs::write(dest.join("Panoptic/extra.dll"), b"x").unwrap();
    assert!(zipcheck::tree_matches_in(&entries, &dest.join("Panoptic"), zipcheck::Layout::Windows).unwrap_err().contains("extra"));
}
