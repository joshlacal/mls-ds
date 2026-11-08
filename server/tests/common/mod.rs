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
#[cfg(feature = "test-support")]
pub mod http_acceptance;
mod proof_i13;

pub use proof_i13::{proof_i13_signer, proof_i13_signer_for};

fn proof_i13_wire_bytes(value: &serde_json::Value, field: &str) -> Vec<u8> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let encoded = value
        .as_str()
        .or_else(|| value.get("$bytes").and_then(serde_json::Value::as_str))
        .unwrap_or_else(|| panic!("{field} must be AT Protocol bytes"));
    STANDARD
        .decode(encoded)
        .unwrap_or_else(|error| panic!("{field} must be base64: {error}"))
}

fn assert_proof_i13_receipt(
    entry: &serde_json::Value,
    expected_archive_commitment: [u8; 32],
    expected_sender_did: &str,
    expected_sender_device_id: &str,
    signer: catbird_server::federation::receipt::I13ReceiptSigner,
) {
    use labyrinth_protocol::receipt::{
        verify_sequencer_receipt, SequencerReceiptPayload, SignedSequencerReceipt,
    };

    let receipt = entry
        .get("sequencerReceipt")
        .and_then(serde_json::Value::as_object)
        .expect("entry must carry a sequencerReceipt");
    assert_eq!(
        receipt
            .get("sequencerDid")
            .and_then(serde_json::Value::as_str),
        Some(signer.sequencer_did())
    );
    assert_eq!(receipt.get("conversationId"), entry.get("conversationId"));
    assert_eq!(receipt.get("entryId"), entry.get("entryId"));
    assert_eq!(receipt.get("seq"), entry.get("seq"));
    assert_eq!(
        receipt.get("senderDid").and_then(serde_json::Value::as_str),
        Some(expected_sender_did)
    );
    assert_eq!(
        receipt
            .get("senderDeviceId")
            .and_then(serde_json::Value::as_str),
        Some(expected_sender_device_id)
    );

    let archive_commitment: [u8; 32] =
        proof_i13_wire_bytes(&receipt["archiveCommitment"], "archiveCommitment")
            .try_into()
            .expect("archiveCommitment must be 32 bytes");
    assert_eq!(archive_commitment, expected_archive_commitment);
    let issued_at_ms = chrono::DateTime::parse_from_rfc3339(
        entry["receivedAt"].as_str().expect("entry receivedAt"),
    )
    .expect("entry receivedAt must be RFC3339")
    .timestamp_millis();
    assert_eq!(
        receipt
            .get("issuedAtMs")
            .and_then(serde_json::Value::as_i64),
        Some(issued_at_ms)
    );

    let signed = SignedSequencerReceipt {
        payload: SequencerReceiptPayload {
            sequencer_did: receipt["sequencerDid"]
                .as_str()
                .expect("sequencerDid")
                .to_owned(),
            conversation_id: receipt["conversationId"]
                .as_str()
                .expect("conversationId")
                .to_owned(),
            group_id: proof_i13_wire_bytes(&receipt["groupId"], "groupId"),
            epoch: receipt["epoch"].as_u64().expect("epoch"),
            sender_device_did_url: format!("{expected_sender_did}#{expected_sender_device_id}"),
            entry_id: receipt["entryId"].as_str().expect("entryId").to_owned(),
            archive_commitment,
            seq: receipt["seq"].as_u64().expect("seq"),
            issued_at_ms,
        },
        key_id: receipt["kid"].as_str().expect("kid").to_owned(),
        signature: proof_i13_wire_bytes(&receipt["signature"], "signature")
            .try_into()
            .expect("signature must be 64 bytes"),
    };
    verify_sequencer_receipt(&signer.verifying_key(), signer.sequencer_did(), &signed)
        .expect("sequencerReceipt must verify with the deterministic I13 key");
}

#[cfg(feature = "test-support")]
fn assert_proof_i13_control_receipt_with_signer(
    entry: &serde_json::Value,
    signer: catbird_server::federation::receipt::I13ReceiptSigner,
) {
    let mut actor_entry = entry.clone();
    actor_entry
        .as_object_mut()
        .expect("control entry object")
        .remove("sequencerReceipt");
    let mutation =
        catbird_server::chat_protocol::transcript::decode_control_entry_mutation_unverified(
            &serde_json::to_vec(&actor_entry).expect("serialize control entry"),
        )
        .expect("control entry must retain a canonical signed mutation");
    assert_proof_i13_receipt(
        entry,
        *mutation.request_digest(),
        mutation.actor_did().as_str(),
        mutation.actor_device_id().as_str(),
        signer,
    );
}

#[cfg(not(feature = "test-support"))]
fn assert_proof_i13_control_receipt_with_signer(
    entry: &serde_json::Value,
    signer: catbird_server::federation::receipt::I13ReceiptSigner,
) {
    let body = &entry["signedRequest"]["body"];
    let archive_commitment: [u8; 32] = proof_i13_wire_bytes(
        &entry["sequencerReceipt"]["archiveCommitment"],
        "archiveCommitment",
    )
    .try_into()
    .expect("archiveCommitment must be 32 bytes");
    assert_proof_i13_receipt(
        entry,
        archive_commitment,
        body["actorDid"].as_str().expect("actorDid"),
        body["actorDeviceId"].as_str().expect("actorDeviceId"),
        signer,
    );
}

#[allow(dead_code)]
pub fn assert_proof_i13_control_receipt(entry: &serde_json::Value) {
    assert_proof_i13_control_receipt_with_signer(entry, proof_i13_signer());
}

#[allow(dead_code)]
pub fn assert_proof_i13_control_receipt_for(entry: &serde_json::Value, sequencer_did: &str) {
    assert_proof_i13_control_receipt_with_signer(entry, proof_i13_signer_for(sequencer_did));
}

/// Mint a private, freshly migrated database for one test case.
///
/// This used to read `TEST_DATABASE_URL` — falling back to a hardcoded
/// `postgres://localhost/catbird_test` when unset — and hand it straight to
/// `db::init_db`, which runs `sqlx::migrate!("./migrations")`. That applied the
/// whole ~56-migration legacy set to whatever database the ambient environment
/// named. Ten targets call this helper, so with the program's standard
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
