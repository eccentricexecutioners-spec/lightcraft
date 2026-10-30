//! A TEST master key. It is compiled only for tests and under the `uplink-test-key` feature, so
//! a release binary neither trusts it nor contains [`MARKER`].

use ed25519_dalek::SigningKey;

/// Seed of the test master key. Test data only.
pub const TEST_SEED: [u8; 32] = *b"panoptic-c1-uplink-test-seed-000";

/// A string a build that trusts the test key contains (a release build must not).
pub const MARKER: &str = "uplink-test-key-marker";

/// The test master public key, derived from [`TEST_SEED`].
pub fn public_key() -> [u8; 32] {
    SigningKey::from_bytes(&TEST_SEED).verifying_key().to_bytes()
}

/// The test key as a trusted key; warns once that this build trusts it.
pub fn trusted_keys() -> Vec<[u8; 32]> {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| log::warn!("{MARKER}: this build trusts the test key"));
    vec![public_key()]
}
