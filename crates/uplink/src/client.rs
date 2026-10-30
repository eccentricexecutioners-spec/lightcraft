//! The two Cargo Bay calls (claim a link code, check for an update) and the signed download.
//! One attempt each, no retries. TLS is rustls with the ring provider and the OS root store.

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use ureq::Agent;
use ureq::tls::{Certificate, RootCerts, TlsConfig, TlsProvider};

use crate::{CHECK_PATH, CLAIM_PATH, TIMEOUT, TOOL_ID};

/// Why a link did not happen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkError {
    BadCode,
    NotGranted,
    RateLimited,
    Offline,
    TlsFailed,
    ServerError(String),
}

/// A release the server offers.
#[derive(Clone, Debug, PartialEq)]
pub struct Offer {
    pub version: String,
    pub manifest: Value,
    pub signature: String,
    pub download_url: String,
    pub notes: String,
}

/// The answer to an update check.
#[derive(Clone, Debug, PartialEq)]
pub enum CheckResult {
    UpToDate,
    Update(Offer),
    /// The key was refused (401, bad key, or another tool's key): the caller retires it.
    LinkRemoved,
    NoAccess,
    Offline,
    TlsFailed,
    ServerError(String),
}

/// A network failure, before any HTTP answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Offline,
    Tls,
}

/// `mac`, `windows` or `linux`: the platform this copy is running on, as Cargo Bay names it.
pub fn platform() -> &'static str {
    platform_for(std::env::consts::OS)
}

/// Cargo Bay's name for a Rust OS name (`std::env::consts::OS`): `macos` → `mac`, `windows` →
/// `windows`, anything else → `linux`.
pub fn platform_for(os: &str) -> &'static str {
    match os {
        "macos" => "mac",
        "windows" => "windows",
        _ => "linux",
    }
}

/// https, or http only for 127.0.0.1 / localhost; the trailing `/` is dropped.
pub fn check_base_url(url: &str) -> Result<String, String> {
    let trimmed = url.trim().trim_end_matches('/');
    if trimmed.starts_with("https://") {
        return Ok(trimmed.to_string());
    }
    if let Some(rest) = trimmed.strip_prefix("http://") {
        let host = rest.split(['/', ':']).next().unwrap_or("");
        if host == "127.0.0.1" || host == "localhost" {
            return Ok(trimmed.to_string());
        }
    }
    Err(format!("not an https address: {url}"))
}

/// The code as the server wants it: 8 characters from the link-code alphabet, upper case,
/// spaces and dashes dropped; `None` when it cannot be a code.
pub fn normalize_code(code: &str) -> Option<String> {
    const ALPHABET: &str = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    if code.chars().count() > 32 {
        return None;
    }
    let clean: String = code.to_uppercase().chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    (clean.chars().count() == 8 && clean.chars().all(|c| ALPHABET.contains(c))).then_some(clean)
}

/// Strict enough for the server's rule: `MAJOR.MINOR.PATCH` or `…-beta.N`, no leading zeros.
pub fn valid_version(v: &str) -> bool {
    fn num(s: &str) -> bool {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'))
    }
    let (core, beta) = match v.split_once("-beta.") {
        Some((c, b)) => (c, Some(b)),
        None => (v, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| num(p)) && beta.is_none_or(num)
}

/// True when `a` is a newer Cargo Bay version than `b` (a beta sorts below its release).
/// Either one malformed: false.
pub fn newer(a: &str, b: &str) -> bool {
    fn key(v: &str) -> Option<([u64; 3], u64)> {
        if !valid_version(v) {
            return None;
        }
        let (core, beta) = match v.split_once("-beta.") {
            Some((c, n)) => (c, n.parse().ok()?),
            None => (v, u64::MAX),
        };
        let mut n = core.split('.').map(|p| p.parse::<u64>());
        Some(([n.next()?.ok()?, n.next()?.ok()?, n.next()?.ok()?], beta))
    }
    matches!((key(a), key(b)), (Some(x), Some(y)) if x > y)
}

/// A Cargo Bay client.
pub struct Client {
    base: String,
    api: Agent,
    download: Agent,
}

fn tls_config(base: &str) -> Option<TlsConfig> {
    if !base.starts_with("https://") {
        return None;
    }
    let loaded = rustls_native_certs::load_native_certs();
    for e in &loaded.errors {
        log::warn!("uplink: a system certificate could not be read: {e}");
    }
    let certs: Vec<Certificate<'static>> = loaded.certs.iter().map(|c| Certificate::from_der(c.as_ref()).to_owned()).collect();
    Some(
        TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .root_certs(RootCerts::Specific(Arc::new(certs)))
            .build(),
    )
}

impl Client {
    /// A client with the standard 10 second timeout.
    pub fn new(base_url: &str) -> Result<Client, String> {
        Client::with_timeout(base_url, TIMEOUT)
    }

    pub fn with_timeout(base_url: &str, timeout: Duration) -> Result<Client, String> {
        let base = check_base_url(base_url)?;
        let tls = tls_config(&base);
        let mut api = Agent::config_builder().http_status_as_error(false).max_redirects(0).timeout_global(Some(timeout));
        // The download has no overall limit (an app is big); each wait for the server is
        // limited to the same timeout, and the body gets a generous cap.
        let mut download = Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_connect(Some(timeout))
            .timeout_recv_response(Some(timeout))
            .timeout_recv_body(Some(Duration::from_secs(30 * 60)));
        if let Some(tls) = tls {
            api = api.tls_config(tls.clone());
            download = download.tls_config(tls);
        }
        Ok(Client { base, api: Agent::new_with_config(api.build()), download: Agent::new_with_config(download.build()) })
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    fn classify(e: &ureq::Error) -> Transport {
        match e {
            ureq::Error::Rustls(_) | ureq::Error::Pem(_) => Transport::Tls,
            ureq::Error::Io(io) if io.get_ref().is_some_and(|inner| inner.downcast_ref::<rustls::Error>().is_some()) => Transport::Tls,
            _ => Transport::Offline,
        }
    }

    /// POST JSON; any HTTP status comes back with the parsed JSON object (`Null` if it was not one).
    fn post(&self, path: &str, bearer: Option<&str>, body: &Value) -> Result<(u16, Value), Transport> {
        let url = format!("{}{path}", self.base);
        let mut req = self.api.post(&url).header("Accept", "application/json").content_type("application/json");
        if let Some(key) = bearer {
            req = req.header("Authorization", &format!("Bearer {key}"));
        }
        let resp = req.send(body.to_string().as_str()).map_err(|e| Client::classify(&e))?;
        let status = resp.status().as_u16();
        let text = resp.into_body().read_to_string().map_err(|e| Client::classify(&e))?;
        let value = serde_json::from_str::<Value>(&text).ok().filter(Value::is_object).unwrap_or(Value::Null);
        Ok((status, value))
    }

    /// Trade a link code for an install key. A code that cannot be one is refused without a request.
    pub fn claim(&self, code: &str) -> Result<String, LinkError> {
        let clean = normalize_code(code).ok_or(LinkError::BadCode)?;
        let dashed = format!("{}-{}", &clean[..4], &clean[4..]);
        let body = json!({"link_code": dashed, "tool_id": TOOL_ID, "platform": platform()});
        let (status, reply) = self.post(CLAIM_PATH, None, &body).map_err(|t| match t {
            Transport::Offline => LinkError::Offline,
            Transport::Tls => LinkError::TlsFailed,
        })?;
        let error = reply.get("error").and_then(Value::as_str).unwrap_or("");
        if status == 200
            && let Some(key) = reply.get("install_key").and_then(Value::as_str).filter(|k| !k.is_empty())
        {
            return Ok(key.to_string());
        }
        Err(match (status, error) {
            (404, _) | (_, "bad_code") => LinkError::BadCode,
            (403, _) | (_, "not_granted") => LinkError::NotGranted,
            (429, _) | (_, "rate_limited") => LinkError::RateLimited,
            _ => LinkError::ServerError(if error.is_empty() { format!("http {status}") } else { error.to_string() }),
        })
    }

    /// Ask for an update. A `keyring` in the answer goes to `on_keyring` first.
    pub fn check(&self, key: &str, installed_version: &str, platform: &str, keyring_serial: u64, on_keyring: &dyn Fn(&Value)) -> CheckResult {
        if !valid_version(installed_version) {
            return CheckResult::ServerError("installed version is not readable".into());
        }
        let body = json!({
            "tool_id": TOOL_ID,
            "installed_version": installed_version,
            "channel": "stable",
            "platform": platform,
            "keyring_serial": keyring_serial,
        });
        let (status, reply) = match self.post(CHECK_PATH, Some(key), &body) {
            Ok(r) => r,
            Err(Transport::Offline) => return CheckResult::Offline,
            Err(Transport::Tls) => return CheckResult::TlsFailed,
        };
        if let Some(ring) = reply.get("keyring") {
            on_keyring(ring);
        }
        let error = reply.get("error").and_then(Value::as_str).unwrap_or("");
        if status == 401 || error == "bad_key" || error == "key_tool_mismatch" {
            return CheckResult::LinkRemoved;
        }
        if status == 200 {
            match reply.get("status").and_then(Value::as_str) {
                Some("up_to_date" | "unknown_tool") => return CheckResult::UpToDate,
                Some("not_granted") => return CheckResult::NoAccess,
                Some("update") => {
                    return match offer(&reply) {
                        Some(o) => CheckResult::Update(o),
                        None => CheckResult::ServerError("update answer is incomplete".into()),
                    };
                }
                _ => {}
            }
        }
        CheckResult::ServerError(if error.is_empty() { format!("http {status}") } else { error.to_string() })
    }

    /// GET a signed download URL (no auth header) and hand at most `max_bytes + 1` bytes to
    /// `sink`; returns how many were read.
    pub fn download(&self, url: &str, max_bytes: u64, sink: &mut dyn FnMut(&[u8]) -> std::io::Result<()>) -> Result<u64, DownloadError> {
        check_base_url(url).map_err(|_| DownloadError::Transport(Transport::Offline))?;
        let resp = self.download.get(url).call().map_err(|e| DownloadError::Transport(Client::classify(&e)))?;
        if resp.status().as_u16() >= 400 {
            return Err(DownloadError::Transport(Transport::Offline));
        }
        let mut reader = resp.into_body().into_reader().take(max_bytes.saturating_add(1));
        let mut buf = vec![0u8; 64 * 1024];
        let mut got = 0u64;
        loop {
            let n = reader.read(&mut buf).map_err(|e| {
                let transport = e.get_ref().is_some_and(|i| i.downcast_ref::<rustls::Error>().is_some());
                DownloadError::Transport(if transport { Transport::Tls } else { Transport::Offline })
            })?;
            if n == 0 {
                break;
            }
            got += n as u64;
            sink(&buf[..n]).map_err(DownloadError::Write)?;
        }
        Ok(got)
    }
}

/// Why a download did not finish.
#[derive(Debug)]
pub enum DownloadError {
    Transport(Transport),
    Write(std::io::Error),
}

fn offer(reply: &Value) -> Option<Offer> {
    let release = reply.get("release")?;
    let text = |k: &str| release.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
    let manifest = release.get("manifest").filter(|m| m.is_object())?.clone();
    let notes = manifest.get("notes").and_then(Value::as_str).unwrap_or("").to_string();
    Some(Offer { version: text("version")?, signature: text("signature")?, download_url: text("download_url")?, manifest, notes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_urls() {
        assert_eq!(check_base_url("https://x.example/").unwrap(), "https://x.example");
        assert!(check_base_url("http://127.0.0.1:8080").is_ok());
        assert!(check_base_url("http://localhost:1/").is_ok());
        assert!(check_base_url("http://example.com").is_err());
        assert!(check_base_url("http://127.0.0.1.example.com").is_err());
        assert!(check_base_url("ftp://127.0.0.1").is_err());
    }

    #[test]
    fn codes_and_versions() {
        assert_eq!(normalize_code(" abcd-efgh ").as_deref(), Some("ABCDEFGH"));
        assert_eq!(normalize_code("ABCD EFG2").as_deref(), Some("ABCDEFG2"));
        for bad in ["", "ABCD-EFG", "ABCD-EFGHJ", "ABCD-EFG0", "ABCD-EFGO", "ABCD-EFG1", "ABCD-EFGI", "ABCD-EFGL"] {
            assert_eq!(normalize_code(bad), None, "{bad}");
        }
        assert!(valid_version("1.2.3") && valid_version("0.0.0") && valid_version("1.2.3-beta.4"));
        assert!(!valid_version("01.2.3") && !valid_version("1.2") && !valid_version("1.2.3-beta") && !valid_version("v1.2.3"));
    }

    #[test]
    fn default_timeout_is_ten_seconds() {
        assert_eq!(TIMEOUT, Duration::from_secs(10));
    }
}
