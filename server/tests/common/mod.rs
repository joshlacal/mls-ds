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

use sqlx::PgPool;

pub mod chat_protocol;
pub mod fresh_db;
pub mod http_acceptance;
/// Mint a private, freshly migrated database for one test case.
///
/// This used to read `TEST_DATABASE_URL` — falling back to a hardcoded
/// `postgres://localhost/catbird_test` when unset — and hand it straight to
/// `db::init_db`, which runs `sqlx::migrate!("./migrations")`. That applied the
/// whole ~56-migration legacy set to whatever database the ambient environment
/// named. Fourteen targets call this helper, so with the program's standard
/// environment exported, any one of them silently took the shared clean-chat
/// database's `_sqlx_migrations` ledger from the reviewed 13 to 69 and disabled
/// `validate_exact_reviewed_ledger` for every clean-chat suite — while passing.
///
/// Each caller now owns a private database that is reaped when the returned
/// [`fresh_db::DisposableDatabase`] drops, so the guard must stay bound for the
/// whole test:
///
/// ```ignore
/// let (pool, _database) = common::setup_test_db().await;
/// ```
///
/// There is no fallback: [`fresh_db::maintenance_url_from_env`] validates
/// `TEST_DATABASE_URL` against the single reviewed literal and panics
/// otherwise. A test can no longer quietly adopt a database it did not create.
#[allow(dead_code)]
pub async fn setup_test_db() -> (PgPool, fresh_db::DisposableDatabase) {
    fresh_db::fresh_legacy_pool(fresh_db::SHARED_LEGACY_DB_PREFIX, 4, 1).await
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
