//! The key list: release keys the master key vouches for (cargo-bay `core/keyring.mjs`,
//! Python `keyring.py`). Only the master key can sign a list; a list is kept only when it is
//! valid and its serial is higher than the one held. Nothing here fails a check.

use std::fs;

use serde_json::{Value, json};

use crate::canon;
use crate::state::{StateDir, write_atomic};
use crate::trust::{parse_spki_pem, verify};

const MAX_DOCUMENT: usize = 65_536;

/// A valid key list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keyring {
    pub serial: u64,
    pub keys: Vec<[u8; 32]>,
}

fn digits(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| b.is_ascii_digit())
}

fn issued_at_ok(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() == 20
        && digits(&s[0..4], 4)
        && digits(&s[5..7], 2)
        && digits(&s[8..10], 2)
        && digits(&s[11..13], 2)
        && digits(&s[14..16], 2)
        && digits(&s[17..19], 2)
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'Z'
}

fn key_id_ok(s: &str) -> bool {
    s.len() == 16
        && s.starts_with("rk-")
        && digits(&s[3..11], 8)
        && &s[11..12] == "-"
        && s[12..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The shape rules of contract section 5.
fn parse_shape(doc: &Value) -> Result<Keyring, String> {
    let obj = doc.as_object().ok_or("not an object")?;
    if obj.len() != 4 {
        return Err("wrong fields".into());
    }
    if obj.get("type").and_then(Value::as_str) != Some("cargo-bay-keyring") {
        return Err("wrong type".into());
    }
    let serial = obj.get("serial").and_then(Value::as_u64).filter(|s| (1..=2_147_483_647).contains(s)).ok_or("bad serial")?;
    if !obj.get("issued_at").and_then(Value::as_str).is_some_and(issued_at_ok) {
        return Err("bad issued_at".into());
    }
    let list = obj.get("release_keys").and_then(Value::as_array).ok_or("bad release_keys")?;
    if list.len() > 32 {
        return Err("too many keys".into());
    }
    let mut ids = Vec::new();
    let mut keys = Vec::new();
    for entry in list {
        let e = entry.as_object().filter(|e| e.len() == 2).ok_or("bad key entry")?;
        let id = e.get("key_id").and_then(Value::as_str).filter(|s| key_id_ok(s)).ok_or("bad key_id")?;
        if ids.contains(&id) {
            return Err("duplicate key_id".into());
        }
        ids.push(id);
        let pem = e.get("public_key").and_then(Value::as_str).ok_or("bad public_key")?;
        keys.push(parse_spki_pem(pem)?);
    }
    Ok(Keyring { serial, keys })
}

/// Check a `{document, signature}` pair against the master keys: length, shape, canonical
/// form, then the signature over the document text.
pub fn check_document(masters: &[[u8; 32]], document: &str, signature: &str) -> Result<Keyring, String> {
    if document.chars().count() > MAX_DOCUMENT {
        return Err("too long".into());
    }
    let parsed: Value = serde_json::from_str(document).map_err(|_| "not JSON".to_string())?;
    let ring = parse_shape(&parsed)?;
    if canon::canonical(&parsed)? != document {
        return Err("not in canonical form".into());
    }
    if !masters.iter().any(|m| verify(m, document.as_bytes(), signature)) {
        return Err("does not verify with the built-in key".into());
    }
    Ok(ring)
}

/// The stored list, re-verified now; `None` if there is none or it does not verify.
pub fn load(state: &StateDir, masters: &[[u8; 32]]) -> Option<Keyring> {
    let text = fs::read_to_string(state.keyring_file()).ok()?;
    let stored: Value = serde_json::from_str(&text).ok()?;
    let document = stored.get("document")?.as_str()?;
    let signature = stored.get("signature")?.as_str()?;
    check_document(masters, document, signature).ok()
}

/// The held serial, 0 when none.
pub fn held_serial(state: &StateDir, masters: &[[u8; 32]]) -> u64 {
    load(state, masters).map_or(0, |k| k.serial)
}

/// Keep the reply's key list when it is valid and newer than the held one. Never errors.
pub fn consider(state: &StateDir, masters: &[[u8; 32]], reply: &Value) {
    let (Some(document), Some(signature)) = (reply.get("document").and_then(Value::as_str), reply.get("signature").and_then(Value::as_str)) else {
        log::warn!("uplink: key list ignored (not an object)");
        return;
    };
    let signature = signature.trim();
    let ring = match check_document(masters, document, signature) {
        Ok(r) => r,
        Err(why) => {
            log::warn!("uplink: key list ignored ({why})");
            return;
        }
    };
    let held = held_serial(state, masters);
    if ring.serial <= held {
        log::warn!("uplink: key list {} ignored (holding {held})", ring.serial);
        return;
    }
    let body = json!({"document": document, "signature": signature});
    let saved = serde_json::to_vec(&body).map_err(std::io::Error::other).and_then(|b| write_atomic(state.path(), &state.keyring_file(), &b, false));
    if let Err(e) = saved {
        log::warn!("uplink: key list not kept ({e})");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::testing::*;

    fn fixture() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/cargo-bay-keyring-vectors.json")).unwrap()
    }

    fn master(fx: &Value) -> [u8; 32] {
        parse_spki_pem(fx["master_public_key"].as_str().unwrap()).unwrap()
    }

    fn list(fx: &Value, name: &str) -> Value {
        fx["lists"][name].clone()
    }

    #[test]
    fn fixture_lists_validate_as_expected() {
        let fx = fixture();
        let masters = [master(&fx)];
        for (name, expect) in fx["expect_valid"].as_object().unwrap() {
            let l = list(&fx, name);
            let got = check_document(&masters, l["document"].as_str().unwrap(), l["signature"].as_str().unwrap());
            assert_eq!(got.is_ok(), expect.as_bool().unwrap(), "{name}: {got:?}");
        }
    }

    #[test]
    fn lower_serial_key_list_is_ignored() {
        let fx = fixture();
        let masters = [master(&fx)];
        let tmp = tempfile::TempDir::new().unwrap();
        let state = StateDir::new(tmp.path());
        assert_eq!(held_serial(&state, &masters), 0);
        consider(&state, &masters, &list(&fx, "two_keys_2"));
        assert_eq!(held_serial(&state, &masters), 2);
        assert_eq!(load(&state, &masters).unwrap().keys.len(), 2);
        // Serial 1 and a repeat of serial 2 do not replace it; serial 3 does.
        consider(&state, &masters, &list(&fx, "good_1"));
        consider(&state, &masters, &list(&fx, "drop_a_2"));
        assert_eq!(held_serial(&state, &masters), 2);
        assert_eq!(load(&state, &masters).unwrap().keys.len(), 2);
        consider(&state, &masters, &list(&fx, "empty_3"));
        assert_eq!(held_serial(&state, &masters), 3);
        assert!(load(&state, &masters).unwrap().keys.is_empty());
    }

    #[test]
    fn non_canonical_or_release_signed_key_list_is_refused() {
        let fx = fixture();
        let masters = [master(&fx)];
        let tmp = tempfile::TempDir::new().unwrap();
        let state = StateDir::new(tmp.path());
        for name in ["non_canonical_4", "by_release_key_5", "tampered_1"] {
            consider(&state, &masters, &list(&fx, name));
            assert_eq!(held_serial(&state, &masters), 0, "{name}");
            assert!(!state.keyring_file().exists(), "{name}");
        }
        // Not even an object.
        consider(&state, &masters, &json!("x"));
        consider(&state, &masters, &json!(null));
        assert!(!state.keyring_file().exists());
        // A stored file that no longer verifies counts as none (and is left alone).
        consider(&state, &masters, &list(&fx, "good_1"));
        assert_eq!(held_serial(&state, &masters), 1);
        assert_eq!(held_serial(&state, &[public(&signing_key(9))]), 0);
        assert!(state.keyring_file().exists());
    }
}
