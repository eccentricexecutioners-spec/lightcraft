//! Test helpers: zips, signed releases, and a tiny HTTP server on 127.0.0.1.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;

use crate::trust::Trust;
use crate::trust::testing::{public, sign_manifest, signing_key};
use crate::{Config, StateDir};

/// One entry of a test zip.
pub enum Z<'a> {
    Dir(&'a str),
    File(&'a str, &'a [u8], u32),
    Link(&'a str, &'a str),
}

pub fn build_zip(entries: &[Z]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let base = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for e in entries {
        match e {
            Z::Dir(n) => {
                w.add_directory(*n, base.unix_permissions(0o755)).unwrap();
            }
            Z::File(n, data, mode) => {
                w.start_file(*n, base.unix_permissions(*mode)).unwrap();
                w.write_all(data).unwrap();
            }
            Z::Link(n, target) => {
                w.add_symlink(*n, *target, base).unwrap();
            }
        }
    }
    w.finish().unwrap().into_inner()
}

/// A plausible app: an executable, a plist and an inner symlink. `body` is the executable's text.
pub fn app_zip(body: &str) -> Vec<u8> {
    build_zip(&[
        Z::Dir("Panoptic.app/"),
        Z::Dir("Panoptic.app/Contents/"),
        Z::File("Panoptic.app/Contents/Info.plist", b"<plist/>", 0o644),
        Z::Dir("Panoptic.app/Contents/MacOS/"),
        Z::File("Panoptic.app/Contents/MacOS/panoptic", body.as_bytes(), 0o755),
        Z::Dir("Panoptic.app/Contents/Frameworks/"),
        Z::Link("Panoptic.app/Contents/Frameworks/panoptic", "../MacOS/panoptic"),
    ])
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn manifest_for(version: &str, zip: &[u8]) -> Value {
    json!({
        "tool_id": "panoptic", "version": version, "channel": "stable", "kind": "desktop-app",
        "file": format!("Panoptic-{version}.zip"), "sha256": sha256_hex(zip), "size": zip.len(),
        "released_at": "2026-10-08T20:00:00Z", "notes": "test release"
    })
}

pub fn master() -> SigningKey {
    signing_key(100)
}

pub fn trust() -> Trust {
    Trust::with_master(public(&master()))
}

/// A signed manifest (and its signature) for `zip`.
pub fn release(version: &str, zip: &[u8]) -> (Value, String) {
    let m = manifest_for(version, zip);
    let s = sign_manifest(&master(), &m);
    (m, s)
}

pub fn config(state: &std::path::Path, base_url: &str, platform: &'static str) -> Config {
    Config {
        base_url: base_url.to_string(),
        state: StateDir::new(state),
        installed_version: "1.0.0".into(),
        platform,
        trust: trust(),
        timeout: Duration::from_secs(5),
    }
}

/// A request the server saw.
#[derive(Clone, Debug)]
pub struct Req {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

pub enum Resp {
    Json(u16, Value),
    Bytes(u16, Vec<u8>),
    /// Send the bytes in `pieces` parts, `delay_ms` apart.
    Slow(Vec<u8>, usize, u64),
    /// Read the request, then never answer.
    Hang,
}

pub struct TestServer {
    pub url: String,
    hits: Arc<Mutex<Vec<Req>>>,
    stop: Arc<AtomicBool>,
}

fn read_request(stream: &mut TcpStream) -> Option<Req> {
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        data.extend_from_slice(&buf[..n]);
        if let Some(p) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
    };
    let head = String::from_utf8_lossy(&data[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_string();
    let path = first.next()?.to_string();
    let headers: Vec<(String, String)> = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
    let len: usize = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
    while data.len() < head_end + len {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
    }
    let body = String::from_utf8_lossy(&data[head_end..]).into_owned();
    Some(Req { method, path, headers, body })
}

impl TestServer {
    /// Serve on a free 127.0.0.1 port. The handler gets each request and the server's base URL.
    pub fn start(handler: impl Fn(&Req, &str) -> Resp + Send + Sync + 'static) -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let hits = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handler = Arc::new(handler);
        let (h2, s2, u2) = (hits.clone(), stop.clone(), url.clone());
        std::thread::spawn(move || {
            while !s2.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let (hits, stop, handler, url) = (h2.clone(), s2.clone(), handler.clone(), u2.clone());
                        std::thread::spawn(move || {
                            stream.set_nonblocking(false).ok();
                            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                            let Some(req) = read_request(&mut stream) else { return };
                            hits.lock().unwrap().push(req.clone());
                            let (status, ctype, body) = match handler(&req, &url) {
                                Resp::Json(s, v) => (s, "application/json", v.to_string().into_bytes()),
                                Resp::Bytes(s, b) => (s, "application/zip", b),
                                Resp::Slow(b, pieces, delay_ms) => {
                                    stream.set_nodelay(true).ok();
                                    let head = format!(
                                        "HTTP/1.1 200 X\r\ncontent-type: application/zip\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                                        b.len()
                                    );
                                    let _ = stream.write_all(head.as_bytes());
                                    for part in b.chunks(b.len().div_ceil(pieces)) {
                                        let _ = stream.write_all(part);
                                        let _ = stream.flush();
                                        std::thread::sleep(Duration::from_millis(delay_ms));
                                    }
                                    return;
                                }
                                Resp::Hang => {
                                    let t = Instant::now();
                                    while !stop.load(Ordering::Relaxed) && t.elapsed() < Duration::from_secs(8) {
                                        std::thread::sleep(Duration::from_millis(20));
                                    }
                                    return;
                                }
                            };
                            let head = format!(
                                "HTTP/1.1 {status} X\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(head.as_bytes());
                            let _ = stream.write_all(&body);
                        });
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        TestServer { url, hits, stop }
    }

    pub fn hits(&self) -> Vec<Req> {
        self.hits.lock().unwrap().clone()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// A server that offers `version` (a zip of `body`) on `/api/v1/update-check` and serves it on `/dl/zip`.
pub fn update_server(version: &str, zip: Vec<u8>) -> TestServer {
    let (manifest, signature) = release(version, &zip);
    let version = version.to_string();
    TestServer::start(move |req, base| match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/api/v1/update-check") => Resp::Json(
            200,
            json!({"status": "update", "release": {
                "version": version, "channel": "stable", "manifest": manifest,
                "signature": signature, "download_url": format!("{base}/dl/zip")}}),
        ),
        ("GET", "/dl/zip") => Resp::Bytes(200, zip.clone()),
        _ => Resp::Json(404, json!({"error": "not_found"})),
    })
}

pub fn link_key(state: &std::path::Path) {
    StateDir::new(state).save_link(&crate::Link::new("cbk_testkeytestkeytestkey", "http://127.0.0.1")).unwrap();
}

/// Lay a fake installed app under `dir` and return its path.
pub fn fake_installed(dir: &std::path::Path, body: &str) -> PathBuf {
    let bundle = dir.join("Applications").join("Panoptic.app");
    let exe = bundle.join("Contents").join("MacOS");
    std::fs::create_dir_all(&exe).unwrap();
    std::fs::write(exe.join("panoptic"), body).unwrap();
    bundle
}
