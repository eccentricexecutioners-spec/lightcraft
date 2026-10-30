//! Who we believe: the built-in master key, plus release keys from a stored, master-signed
//! key list. Ed25519 only; keys come as SPKI PEM.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;

use crate::canon;
use crate::keyring;
use crate::state::StateDir;

/// The release master public key, as stamped in all four add-ins' `uplink_*/trust.py:9`
/// (mod-fusion-favorites, mod-client-to-fusion, mod-toolpath, mod-hbc-fusion-push).
pub const MASTER_PUBLIC_KEY_PEM: &str =
    "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAIPO1dQPHYCi4knPIFdwjMQlI40vTXIAbPTi25rCMjRY=\n-----END PUBLIC KEY-----\n";

const DER_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// The 32 raw bytes of an Ed25519 key in an SPKI PEM (first and last line checked, strict
/// base64, 44 DER bytes with the Ed25519 prefix).
pub fn parse_spki_pem(pem: &str) -> Result<[u8; 32], String> {
    let lines: Vec<&str> = pem.trim().lines().map(str::trim).collect();
    if lines.len() < 3 || lines[0] != "-----BEGIN PUBLIC KEY-----" || lines[lines.len() - 1] != "-----END PUBLIC KEY-----" {
        return Err("not a PEM public key".into());
    }
    let body: String = lines[1..lines.len() - 1].concat();
    let der = STANDARD.decode(body).map_err(|_| "public key is not base64".to_string())?;
    if der.len() != 44 || der[..12] != DER_PREFIX {
        return Err("not an Ed25519 public key".into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&der[12..]);
    Ok(key)
}

/// True when `sig_b64` (strict standard base64, exactly 64 bytes) signs `msg` under `key`.
pub fn verify(key: &[u8; 32], msg: &[u8], sig_b64: &str) -> bool {
    let Ok(raw) = STANDARD.decode(sig_b64.trim()) else {
        return false;
    };
    let Ok(raw) = <[u8; 64]>::try_from(raw.as_slice()) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(key) else {
        return false;
    };
    vk.verify(msg, &Signature::from_bytes(&raw)).is_ok()
}

/// The keys this copy trusts.
#[derive(Clone, Debug)]
pub struct Trust {
    pub master: [u8; 32],
    /// More master keys (only the `uplink-test-key` build has any).
    pub extra_masters: Vec<[u8; 32]>,
    pub release: Vec<[u8; 32]>,
}

impl Trust {
    /// The built-in master (plus the test key under the feature) and the stored key list.
    pub fn builtin(state: &StateDir) -> Trust {
        let master = parse_spki_pem(MASTER_PUBLIC_KEY_PEM).unwrap_or([0u8; 32]);
        #[cfg(feature = "uplink-test-key")]
        let extra_masters = crate::test_key::trusted_keys();
        #[cfg(not(feature = "uplink-test-key"))]
        let extra_masters = Vec::new();
        let mut trust = Trust { master, extra_masters, release: Vec::new() };
        trust.release = keyring::load(state, &trust.masters()).map(|k| k.keys).unwrap_or_default();
        trust
    }

    /// Only this master key, no release keys (tests).
    pub fn with_master(master: [u8; 32]) -> Trust {
        Trust { master, extra_masters: Vec::new(), release: Vec::new() }
    }

    /// Every master key.
    pub fn masters(&self) -> Vec<[u8; 32]> {
        let mut all = vec![self.master];
        all.extend(&self.extra_masters);
        all
    }

    /// True when a master key, then a release key, verifies `sig` over the canonical manifest.
    pub fn verify_manifest(&self, manifest: &Value, sig: &str) -> bool {
        if !manifest.is_object() {
            return false;
        }
        let Ok(text) = canon::canonical(manifest) else {
            return false;
        };
        self.masters().iter().chain(self.release.iter()).any(|k| verify(k, text.as_bytes(), sig))
    }
}

#[cfg(test)]
pub(crate) mod testing {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::test_key::TEST_SEED;
    use ed25519_dalek::{Signer, SigningKey};

    pub fn signing_key(seed_byte: u8) -> SigningKey {
        let mut seed = TEST_SEED;
        seed[31] = seed_byte;
        SigningKey::from_bytes(&seed)
    }

    pub fn public(sk: &SigningKey) -> [u8; 32] {
        sk.verifying_key().to_bytes()
    }

    pub fn pem(key: &[u8; 32]) -> String {
        let mut der = DER_PREFIX.to_vec();
        der.extend(key);
        format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", STANDARD.encode(der))
    }

    pub fn sign(sk: &SigningKey, msg: &[u8]) -> String {
        STANDARD.encode(sk.sign(msg).to_bytes())
    }

    pub fn sign_manifest(sk: &SigningKey, manifest: &Value) -> String {
        sign(sk, canon::canonical(manifest).unwrap().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use serde_json::json;

    fn manifest() -> Value {
        json!({"tool_id":"panoptic","version":"1.2.3","channel":"stable","kind":"desktop-app",
          "file":"Panoptic-1.2.3.zip","sha256":"a".repeat(64),"size":10,
          "released_at":"2026-10-08T20:00:00Z","notes":"n","extra":"kept"})
    }

    #[test]
    fn builtin_master_parses() {
        let key = parse_spki_pem(MASTER_PUBLIC_KEY_PEM).unwrap();
        assert_ne!(key, [0u8; 32]);
        assert!(parse_spki_pem("nope").is_err());
        assert!(parse_spki_pem(&MASTER_PUBLIC_KEY_PEM.replace("AyEA", "AyEB")).is_err());
        assert_eq!(parse_spki_pem(&pem(&key)).unwrap(), key);
    }

    #[test]
    fn manifest_signed_by_master_verifies() {
        let sk = signing_key(1);
        let m = manifest();
        let sig = sign_manifest(&sk, &m);
        let trust = Trust::with_master(public(&sk));
        assert!(trust.verify_manifest(&m, &sig));
        // Any change, even in a field a typed struct would drop, breaks it.
        let mut changed = m.clone();
        changed["extra"] = json!("other");
        assert!(!trust.verify_manifest(&changed, &sig));
        assert!(!trust.verify_manifest(&m, ""));
        assert!(!trust.verify_manifest(&m, &sig[..sig.len() - 4]));
    }

    #[test]
    fn manifest_signed_by_listed_release_key_verifies() {
        let master = signing_key(1);
        let release = signing_key(2);
        let m = manifest();
        let sig = sign_manifest(&release, &m);
        let mut trust = Trust::with_master(public(&master));
        assert!(!trust.verify_manifest(&m, &sig));
        trust.release.push(public(&release));
        assert!(trust.verify_manifest(&m, &sig));
    }

    #[test]
    fn manifest_signed_by_unknown_key_is_refused() {
        let master = signing_key(1);
        let listed = signing_key(2);
        let unknown = signing_key(3);
        let m = manifest();
        let mut trust = Trust::with_master(public(&master));
        trust.release.push(public(&listed));
        assert!(!trust.verify_manifest(&m, &sign_manifest(&unknown, &m)));
    }
}
