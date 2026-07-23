//! Shared test helpers for `mls-ds/server` integration tests.
//!
//! Each integration test file (`tests/*.rs`) is its own crate, so common
//! helpers must be exposed via `mod common;` + this `tests/common/mod.rs`
//! convention. Naming the file `mod.rs` (rather than `tests/common.rs`)
//! tells Cargo not to treat it as its own integration test target.
//!
//! Helpers are marked `#[allow(dead_code)]` because not every consuming
//! test file uses every helper — Rust would otherwise emit per-target
//! warnings for the unused ones.

use catbird_server::db::{init_db, DbConfig};
use sqlx::PgPool;
use std::time::Duration;

pub mod chat_protocol;

#[allow(dead_code)]
pub async fn setup_test_db() -> PgPool {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/catbird_test".to_string());

    let config = DbConfig {
        database_url,
        max_connections: 4,
        min_connections: 1,
        acquire_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(600),
    };

    init_db(config)
        .await
        .expect("Failed to initialize test database")
}

#[allow(dead_code)]
pub async fn cleanup(pool: &PgPool, convo_id: &str) {
    let _ = sqlx::query("DELETE FROM members WHERE convo_id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM conversations WHERE id = $1")
        .bind(convo_id)
        .execute(pool)
        .await;
}

/// Build real, validatable MLS KeyPackage bytes for `identity` (a bare DID).
///
/// `db::store_key_package` deserializes and validates uploaded key packages
/// with OpenMLS (XWing ciphersuite via the libcrux provider) and enforces
/// that the BasicCredential identity equals the bare owner DID — dummy byte
/// fixtures are rejected. This generates the real thing.
#[allow(dead_code)]
pub fn generate_key_package_bytes(identity: &str) -> Vec<u8> {
    use openmls::prelude::{tls_codec::Serialize as TlsSerialize, *};
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::OpenMlsProvider;

    let provider = openmls_libcrux_crypto::Provider::new().expect("libcrux provider");
    let ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

    let credential = BasicCredential::new(identity.as_bytes().to_vec());
    let signature_keys =
        SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("signature keypair");
    signature_keys
        .store(provider.storage())
        .expect("store signature keys");

    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signature_keys.to_public_vec().into(),
    };

    let bundle = KeyPackage::builder()
        .build(ciphersuite, &provider, &signature_keys, credential_with_key)
        .expect("build key package");

    bundle
        .key_package()
        .tls_serialize_detached()
        .expect("serialize key package")
}
