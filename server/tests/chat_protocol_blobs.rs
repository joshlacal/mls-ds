//! Live-PostgreSQL tests for clean-chat ciphertext-blob custody (Task 2, Slice 5).
//!
//! Exercises `chat_protocol::repository::blobs`: the migration-3 row writers and
//! the closed prepare/upload/bind/delete/expiry transaction semantics, plus the
//! ciphertext-blind boundary. Every committed-state assertion is a SELECT; each
//! test runs inside one transaction with same-transaction read-back and is then
//! ROLLED BACK, so the never-truncated shared database stays independent between
//! runs. Deferred coherence triggers (`assert_blob_ticket_lifecycle`,
//! `assert_blob_binding_lifecycle`, `assert_blob_usage`, `assert_blob_device_
//! active_cap`) are forced to fire mid-transaction with `SET CONSTRAINTS ALL
//! IMMEDIATE` before the rollback, so a coherent write is proven coherent without
//! committing a per-run leak.
//!
//! Like the sibling repository harnesses this `include!`s the production module
//! directly (it is self-contained: only `chrono`/`sqlx`/`uuid`). The live cases
//! run under the standard whole-suite gate: they hard-fail (panic in
//! `setup_chat_protocol_db`) without `TEST_DATABASE_URL` rather than skipping.
//! Run with:
//!   CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed \
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_blobs -- --test-threads=1

#![allow(dead_code)]

mod common;

mod chat_protocol {
    pub mod dpop {
        pub struct VerifiedReadAdmission;
    }
    pub mod read_authority {
        pub enum OrdinaryReadEndpoint {}
        pub enum ReadAuthorityError { Storage }
        pub struct Attempt;
        pub struct LockedDevice;
        pub struct Admission;
        impl Admission { pub fn into_attempt(self) -> Attempt { Attempt } }
        pub fn into_single_read_admission(
            _admission: super::dpop::VerifiedReadAdmission,
            _endpoint: OrdinaryReadEndpoint,
        ) -> Result<Admission, ()> { Err(()) }
        pub async fn lock_read_device_authority_once(
            _transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
            _attempt: Attempt,
        ) -> Result<LockedDevice, ReadAuthorityError> { Err(ReadAuthorityError::Storage) }
        impl LockedDevice {
            pub fn user_did(&self) -> &str { "" }
            pub fn device_id(&self) -> uuid::Uuid { uuid::Uuid::nil() }
            pub fn auth_generation(&self) -> i64 { 0 }
        }
    }
}

mod repository {
    pub(crate) mod blobs {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/blobs.rs"
        ));
    }
    // The application-send + stale-tombstone writer (Slice 4a) lives in
    // `delivery.rs`; the stale-send five-property proofs compose it. It is
    // self-contained (chrono/sha2/sqlx/uuid), so it is `include!`d standalone
    // exactly like the sibling repository harnesses.
    pub(crate) mod delivery {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/delivery.rs"
        ));
    }

    // The included blob module's ignored drift fixtures import the canonical
    // transition writer through `super::super::transition`. Keep this harness
    // self-contained: those ignored fixtures are not executed here, while the
    // production library continues to resolve the real transition module.
    pub(crate) mod transition {
        use chrono::{DateTime, Utc};
        use uuid::Uuid;

        #[derive(Debug)]
        pub(crate) struct HarnessTransitionError;

        pub(crate) enum IntervalCloseKind {
            Remove,
        }

        pub(crate) struct ApplicationIntervalClose {
            pub(crate) membership_interval_id: Uuid,
            pub(crate) terminal_seq: i64,
            pub(crate) closing_state_version: i64,
            pub(crate) closing_transition_id: Uuid,
            pub(crate) closing_outer_entry_fingerprint: Vec<u8>,
            pub(crate) closing_kind: IntervalCloseKind,
            pub(crate) closing_leaf_period_id: Uuid,
            pub(crate) removed_at: DateTime<Utc>,
        }

        pub(crate) struct LeafClose {
            pub(crate) leaf_period_id: Uuid,
            pub(crate) removed_state_version: i64,
            pub(crate) removed_transition_id: Uuid,
            pub(crate) removed_seq: i64,
            pub(crate) removed_at: DateTime<Utc>,
        }

        pub(crate) struct NewDeviceRevocation {
            pub(crate) revocation_id: Uuid,
            pub(crate) actor_did: String,
            pub(crate) actor_device_id: Uuid,
            pub(crate) actor_key_id: String,
            pub(crate) actor_auth_generation: i64,
            pub(crate) target_did: String,
            pub(crate) target_device_id: Uuid,
            pub(crate) target_auth_generation: i64,
            pub(crate) accepted_request_bytes: Vec<u8>,
            pub(crate) signing_transcript_bytes: Vec<u8>,
            pub(crate) request_digest: Vec<u8>,
            pub(crate) signature: Vec<u8>,
            pub(crate) signed_at: DateTime<Utc>,
            pub(crate) accepted_at: DateTime<Utc>,
        }

        pub(crate) struct RegistrationRevoke {
            pub(crate) target_did: String,
            pub(crate) target_device_id: Uuid,
            pub(crate) expected_auth_generation: i64,
            pub(crate) revocation_id: Uuid,
            pub(crate) revoked_at: DateTime<Utc>,
        }

        pub(crate) async fn close_application_interval<T>(
            _transaction: &mut T,
            _close: &ApplicationIntervalClose,
        ) -> Result<(), HarnessTransitionError> {
            Ok(())
        }

        pub(crate) async fn close_leaf_period<T>(
            _transaction: &mut T,
            _close: &LeafClose,
        ) -> Result<(), HarnessTransitionError> {
            Ok(())
        }

        pub(crate) async fn insert_device_revocation<T>(
            _transaction: &mut T,
            _revocation: &NewDeviceRevocation,
        ) -> Result<(), HarnessTransitionError> {
            Ok(())
        }

        pub(crate) async fn cas_registration_revoke<T>(
            _transaction: &mut T,
            _revoke: &RegistrationRevoke,
        ) -> Result<(), HarnessTransitionError> {
            Ok(())
        }
    }
}

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use repository::blobs::{
    apply_usage_delta, cas_bind_blob, cas_delete_blob, complete_upload, delete_blob,
    expire_due_blobs, insert_prepared_blob, prepare_blob, validate_blob_dimensions, BlobMediaType,
    BlobPurpose, BlobRepositoryError, NewPreparedBlob, PrepareBlobRequest,
    MAX_AUDIO_CIPHERTEXT_BYTES, MAX_CIPHERTEXT_BYTES,
};

// ===========================================================================
// Part 1 — pure `validate_blob_dimensions` matrix (no database).
//
// The ciphertext-blind server's visible outer validation: media-per-purpose, the
// fixed AEAD-tag relation, the plaintext floor, and the per-media ceilings.
// ===========================================================================

#[test]
fn attachment_accepts_every_closed_image_and_audio_mime() {
    // The exact closed application MIME set: five encrypted images (incl. GIF on
    // the ordinary path) and four audio types.
    for media in [
        BlobMediaType::ImageHeic,
        BlobMediaType::ImageJpeg,
        BlobMediaType::ImagePng,
        BlobMediaType::ImageWebp,
        BlobMediaType::ImageGif,
        BlobMediaType::AudioAac,
        BlobMediaType::AudioMp4,
        BlobMediaType::AudioOgg,
        BlobMediaType::AudioOpus,
    ] {
        assert!(
            validate_blob_dimensions(BlobPurpose::Attachment, media, 100, 116).is_ok(),
            "attachment must accept {}",
            media.as_str()
        );
    }
}

#[test]
fn gif_is_an_ordinary_attachment_image_not_a_metadata_avatar() {
    // GIF follows the ordinary encrypted-image path for an attachment...
    assert!(
        validate_blob_dimensions(BlobPurpose::Attachment, BlobMediaType::ImageGif, 10, 26).is_ok()
    );
    // ...but the metadata-avatar contract is NOT widened to admit it.
    assert!(matches!(
        validate_blob_dimensions(BlobPurpose::Metadata, BlobMediaType::ImageGif, 10, 26),
        Err(BlobRepositoryError::MediaTypeNotAllowedForPurpose)
    ));
}

#[test]
fn metadata_avatar_admits_only_the_four_still_images() {
    for media in [
        BlobMediaType::ImageHeic,
        BlobMediaType::ImageJpeg,
        BlobMediaType::ImagePng,
        BlobMediaType::ImageWebp,
    ] {
        assert!(
            validate_blob_dimensions(BlobPurpose::Metadata, media, 100, 116).is_ok(),
            "metadata avatar must accept {}",
            media.as_str()
        );
    }
    // GIF and every audio MIME reject for a metadata avatar without widening it.
    for media in [
        BlobMediaType::ImageGif,
        BlobMediaType::AudioAac,
        BlobMediaType::AudioMp4,
        BlobMediaType::AudioOgg,
        BlobMediaType::AudioOpus,
    ] {
        assert!(
            matches!(
                validate_blob_dimensions(BlobPurpose::Metadata, media, 100, 116),
                Err(BlobRepositoryError::MediaTypeNotAllowedForPurpose)
            ),
            "metadata avatar must reject {}",
            media.as_str()
        );
    }
}

#[test]
fn ciphertext_must_be_exactly_plaintext_plus_sixteen() {
    // Exact relation accepted.
    assert!(
        validate_blob_dimensions(BlobPurpose::Attachment, BlobMediaType::ImagePng, 1, 17).is_ok()
    );
    // Off-by-one on either side rejects.
    for (plaintext, ciphertext) in [(100_i64, 115_i64), (100, 117), (100, 100), (100, 132)] {
        assert!(
            matches!(
                validate_blob_dimensions(
                    BlobPurpose::Attachment,
                    BlobMediaType::ImagePng,
                    plaintext,
                    ciphertext
                ),
                Err(BlobRepositoryError::CiphertextSizeRelation)
            ),
            "must reject plaintext={plaintext} ciphertext={ciphertext}"
        );
    }
}

#[test]
fn image_and_audio_ceilings_are_enforced_at_the_exact_boundary() {
    // Maximum valid encrypted image: ciphertext exactly 10 MiB.
    let image_max_ct = MAX_CIPHERTEXT_BYTES;
    assert!(validate_blob_dimensions(
        BlobPurpose::Attachment,
        BlobMediaType::ImagePng,
        image_max_ct - 16,
        image_max_ct
    )
    .is_ok());
    // One byte over the image ceiling rejects.
    assert!(matches!(
        validate_blob_dimensions(
            BlobPurpose::Attachment,
            BlobMediaType::ImagePng,
            image_max_ct - 15,
            image_max_ct + 1
        ),
        Err(BlobRepositoryError::CiphertextTooLarge)
    ));
    // Maximum valid encrypted audio: ciphertext exactly 8 MiB.
    let audio_max_ct = MAX_AUDIO_CIPHERTEXT_BYTES;
    assert!(validate_blob_dimensions(
        BlobPurpose::Attachment,
        BlobMediaType::AudioOpus,
        audio_max_ct - 16,
        audio_max_ct
    )
    .is_ok());
    // One byte over the audio ceiling rejects even though it is under the image
    // ceiling.
    assert!(matches!(
        validate_blob_dimensions(
            BlobPurpose::Attachment,
            BlobMediaType::AudioOpus,
            audio_max_ct - 15,
            audio_max_ct + 1
        ),
        Err(BlobRepositoryError::CiphertextTooLarge)
    ));
}

#[test]
fn plaintext_floor_is_one_byte() {
    assert!(matches!(
        validate_blob_dimensions(BlobPurpose::Attachment, BlobMediaType::ImagePng, 0, 16),
        Err(BlobRepositoryError::PlaintextSizeInvalid)
    ));
    assert!(
        validate_blob_dimensions(BlobPurpose::Attachment, BlobMediaType::ImagePng, 1, 17).is_ok()
    );
}

// ===========================================================================
// Part 2 — live-PostgreSQL writer + closed-transaction tests.
// ===========================================================================

fn random_plc_did() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bytes = Uuid::new_v4().as_bytes().to_vec();
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    let suffix: String = bytes
        .iter()
        .take(24)
        .map(|byte| ALPHABET[(*byte % 32) as usize] as char)
        .collect();
    format!("did:plc:{suffix}")
}

fn random_ref() -> Vec<u8> {
    let mut bytes = Uuid::new_v4().as_bytes().to_vec();
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    bytes
}

fn deterministic_object_key(blob_id: Uuid, ciphertext_sha256: &[u8]) -> String {
    let hash: [u8; 32] = ciphertext_sha256
        .try_into()
        .expect("ciphertext hash is exactly 32 bytes");
    repository::blobs::derive_blob_cid(blob_id, &hash)
}

async fn clock_now(tx: &mut Transaction<'_, Postgres>) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await
        .expect("sample trusted database clock")
}

/// Seed a principal + active device + device key INSIDE the caller's transaction,
/// returning `(device_id, key_id)`. Rolls back with the test.
async fn seed_owner_tx(tx: &mut Transaction<'_, Postgres>, user_did: &str) -> (Uuid, String) {
    let now = clock_now(tx).await;
    sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2)")
        .bind(user_did)
        .bind(now)
        .execute(&mut **tx)
        .await
        .expect("insert principal");
    let device_id = Uuid::new_v4();
    let public_key = random_ref();
    let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&public_key)
        .fetch_one(&mut **tx)
        .await
        .expect("derive key id");
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'device','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    )
    .bind(user_did)
    .bind(device_id)
    .bind(&key_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .expect("insert device");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
         VALUES($1,$2,$3,$4,1,$5)",
    )
    .bind(user_did)
    .bind(device_id)
    .bind(&key_id)
    .bind(&public_key)
    .bind(now)
    .execute(&mut **tx)
    .await
    .expect("insert device key");
    (device_id, key_id)
}

async fn set_constraints_immediate(tx: &mut Transaction<'_, Postgres>) {
    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut **tx)
        .await
        .expect("fire deferred coherence triggers mid-transaction");
}

/// Read the exact `(status, used, reserved, live_unbound, blob_count)` and assert
/// the maintained counters reconcile with the authoritative blob history.
async fn assert_usage_reconciles(tx: &mut Transaction<'_, Postgres>, owner_did: &str) {
    sqlx::query("SELECT chat.reconcile_blob_usage($1)")
        .bind(owner_did)
        .execute(&mut **tx)
        .await
        .expect("maintained blob-usage counters must reconcile with chat.blobs");
}

async fn blob_status(tx: &mut Transaction<'_, Postgres>, blob_id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM chat.blobs WHERE blob_id = $1")
        .bind(blob_id)
        .fetch_one(&mut **tx)
        .await
        .expect("read blob status")
}

fn prepare_request(
    owner_did: &str,
    owner_device_id: Uuid,
    owner_key_id: &str,
    purpose: BlobPurpose,
    media_type: BlobMediaType,
    plaintext_size: i64,
    prepared_at: DateTime<Utc>,
) -> PrepareBlobRequest {
    let ciphertext_size = plaintext_size + 16;
    PrepareBlobRequest {
        blob_id: Uuid::new_v4(),
        owner_did: owner_did.to_owned(),
        owner_device_id,
        owner_key_id: owner_key_id.to_owned(),
        owner_auth_generation: 1,
        purpose,
        media_type,
        plaintext_size,
        ciphertext_size,
        ciphertext_sha256: Sha256::digest(random_ref()).to_vec(),
        ticket_hash: Sha256::digest(random_ref()).to_vec(),
        prepared_at,
    }
}

#[tokio::test]
async fn prepare_upload_delete_lifecycle_keeps_usage_reconciled() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let mut tx = pool.begin().await.expect("begin");
    let owner = random_plc_did();
    let (device_id, key_id) = seed_owner_tx(&mut tx, &owner).await;
    let now = clock_now(&mut tx).await;

    let request = prepare_request(
        &owner,
        device_id,
        &key_id,
        BlobPurpose::Attachment,
        BlobMediaType::ImagePng,
        1_000,
        now,
    );
    let blob_id = request.blob_id;
    let ciphertext_size = request.ciphertext_size;
    let ticket_hash = request.ticket_hash.clone();
    prepare_blob(&mut tx, &request).await.expect("prepare");

    // A prepared blob reserves quota (reserved += ct, live_unbound += 1, count += 1)
    // and owns exactly one un-consumed ticket.
    assert_eq!(blob_status(&mut tx, blob_id).await, "prepared");
    let (used, reserved, unbound, count): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT used_ciphertext_bytes, reserved_ciphertext_bytes, live_unbound_count, blob_count \
         FROM chat.blob_usage WHERE user_did = $1",
    )
    .bind(&owner)
    .fetch_one(&mut *tx)
    .await
    .expect("usage row");
    assert_eq!((used, reserved, unbound, count), (0, ciphertext_size, 1, 1));

    // Complete the upload: reserved -> used, still one live-unbound blob.
    complete_upload(
        &mut tx,
        blob_id,
        &owner,
        device_id,
        ciphertext_size,
        &ticket_hash,
        now + Duration::seconds(30),
        &deterministic_object_key(blob_id, &request.ciphertext_sha256),
    )
    .await
    .expect("complete upload");
    assert_eq!(blob_status(&mut tx, blob_id).await, "completedUnbound");
    let (used, reserved, unbound, count): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT used_ciphertext_bytes, reserved_ciphertext_bytes, live_unbound_count, blob_count \
         FROM chat.blob_usage WHERE user_did = $1",
    )
    .bind(&owner)
    .fetch_one(&mut *tx)
    .await
    .expect("usage row");
    assert_eq!((used, reserved, unbound, count), (ciphertext_size, 0, 1, 1));

    // Delete by the signing owner: used -> 0, live_unbound -> 0, count -> 0.
    delete_blob(
        &mut tx,
        blob_id,
        &owner,
        device_id,
        ciphertext_size,
        now + Duration::seconds(60),
    )
    .await
    .expect("delete");
    assert_eq!(blob_status(&mut tx, blob_id).await, "deleted");

    assert_usage_reconciles(&mut tx, &owner).await;
    set_constraints_immediate(&mut tx).await;
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn upload_ticket_is_single_use_and_expires_after_five_minutes() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let mut tx = pool.begin().await.expect("begin");
    let owner = random_plc_did();
    let (device_id, key_id) = seed_owner_tx(&mut tx, &owner).await;
    let now = clock_now(&mut tx).await;
    let request = prepare_request(
        &owner,
        device_id,
        &key_id,
        BlobPurpose::Attachment,
        BlobMediaType::ImageJpeg,
        1_000,
        now,
    );
    let blob_id = request.blob_id;
    let ciphertext_size = request.ciphertext_size;
    let ticket_hash = request.ticket_hash.clone();
    prepare_blob(&mut tx, &request).await.expect("prepare");

    // First consume within the 5-minute window succeeds.
    complete_upload(
        &mut tx,
        blob_id,
        &owner,
        device_id,
        ciphertext_size,
        &ticket_hash,
        now + Duration::seconds(60),
        &deterministic_object_key(blob_id, &request.ciphertext_sha256),
    )
    .await
    .expect("first upload");

    // A second consume of the same ticket matches no un-consumed row (single-use).
    let second = repository::blobs::cas_consume_upload_ticket(
        &mut tx,
        &ticket_hash,
        now + Duration::seconds(90),
    )
    .await;
    assert!(matches!(
        second,
        Err(BlobRepositoryError::CompareAndSetConflict)
    ));

    // A consume at exactly the 5-minute expiry is out of `[created_at, expires_at)`
    // and rejected by `blob_upload_tickets_consumption_check`.
    let mut tx2 = pool.begin().await.expect("begin 2");
    let owner2 = random_plc_did();
    let (device2, key2) = seed_owner_tx(&mut tx2, &owner2).await;
    let now2 = clock_now(&mut tx2).await;
    let request2 = prepare_request(
        &owner2,
        device2,
        &key2,
        BlobPurpose::Attachment,
        BlobMediaType::ImageJpeg,
        1_000,
        now2,
    );
    let ticket2 = request2.ticket_hash.clone();
    prepare_blob(&mut tx2, &request2).await.expect("prepare 2");
    let expired_consume = repository::blobs::cas_consume_upload_ticket(
        &mut tx2,
        &ticket2,
        now2 + Duration::minutes(5),
    )
    .await;
    assert!(
        matches!(expired_consume, Err(BlobRepositoryError::Database(_))),
        "consuming at/after the 5-minute expiry must be rejected by the DB check"
    );
    tx2.rollback().await.expect("rollback 2");
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn unbound_blobs_expire_after_one_hour_and_release_quota() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let mut tx = pool.begin().await.expect("begin");
    let owner = random_plc_did();
    let (device_id, key_id) = seed_owner_tx(&mut tx, &owner).await;
    let now = clock_now(&mut tx).await;

    // A prepared blob whose 5-minute upload window already lapsed (never uploaded).
    let prepared_old = prepare_request(
        &owner,
        device_id,
        &key_id,
        BlobPurpose::Attachment,
        BlobMediaType::ImagePng,
        500,
        now - Duration::minutes(10),
    );
    let prepared_id = prepared_old.blob_id;
    prepare_blob(&mut tx, &prepared_old)
        .await
        .expect("prepare old");

    // A completed blob whose 1-hour unbound window already lapsed.
    let completed = prepare_request(
        &owner,
        device_id,
        &key_id,
        BlobPurpose::Attachment,
        BlobMediaType::ImagePng,
        700,
        now - Duration::minutes(130),
    );
    let completed_id = completed.blob_id;
    let completed_ct = completed.ciphertext_size;
    let completed_ticket = completed.ticket_hash.clone();
    prepare_blob(&mut tx, &completed)
        .await
        .expect("prepare completed");
    complete_upload(
        &mut tx,
        completed_id,
        &owner,
        device_id,
        completed_ct,
        &completed_ticket,
        now - Duration::minutes(129),
        &deterministic_object_key(completed_id, &completed.ciphertext_sha256),
    )
    .await
    .expect("complete");

    let expired = expire_due_blobs(&mut tx, now, 32).await.expect("sweep");
    let expired_ids: Vec<Uuid> = expired.iter().map(|blob| blob.blob_id).collect();
    assert!(expired_ids.contains(&prepared_id));
    assert!(expired_ids.contains(&completed_id));
    assert_eq!(blob_status(&mut tx, prepared_id).await, "expired");
    assert_eq!(blob_status(&mut tx, completed_id).await, "expired");

    // Expiry releases quota: both counted blobs are gone from the live set.
    assert_usage_reconciles(&mut tx, &owner).await;
    set_constraints_immediate(&mut tx).await;
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn usage_delta_rejects_over_cap_bytes_and_over_cap_live_unbound() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;

    // 500 MiB total-bytes ceiling: seed reserved just under the cap, then push over.
    let mut tx = pool.begin().await.expect("begin bytes");
    let owner = random_plc_did();
    seed_owner_tx(&mut tx, &owner).await;
    apply_usage_delta(&mut tx, &owner, 0, 524_288_000 - 100, 1, 1)
        .await
        .expect("seed near byte cap");
    let over_bytes = apply_usage_delta(&mut tx, &owner, 0, 101, 0, 0).await;
    assert!(matches!(
        over_bytes,
        Err(BlobRepositoryError::QuotaExceeded)
    ));
    tx.rollback().await.expect("rollback bytes");

    // 100 live-unbound ceiling: seed count at 100, then one more.
    let mut tx = pool.begin().await.expect("begin count");
    let owner = random_plc_did();
    seed_owner_tx(&mut tx, &owner).await;
    apply_usage_delta(&mut tx, &owner, 0, 0, 100, 100)
        .await
        .expect("seed at unbound cap");
    let over_count = apply_usage_delta(&mut tx, &owner, 0, 0, 1, 1).await;
    assert!(matches!(
        over_count,
        Err(BlobRepositoryError::QuotaExceeded)
    ));
    tx.rollback().await.expect("rollback count");
}

#[tokio::test]
async fn two_senders_race_to_bind_one_blob_and_exactly_one_wins() {
    // The bind race resolves at the blob status CAS: `completedUnbound -> bound`
    // matches exactly one row, so the second concurrent binder conflicts.
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let mut tx = pool.begin().await.expect("begin");
    let owner = random_plc_did();
    let (device_id, key_id) = seed_owner_tx(&mut tx, &owner).await;
    let now = clock_now(&mut tx).await;
    let request = prepare_request(
        &owner,
        device_id,
        &key_id,
        BlobPurpose::Attachment,
        BlobMediaType::ImageWebp,
        2_000,
        now,
    );
    let blob_id = request.blob_id;
    let ct = request.ciphertext_size;
    let ticket = request.ticket_hash.clone();
    prepare_blob(&mut tx, &request).await.expect("prepare");
    complete_upload(
        &mut tx,
        blob_id,
        &owner,
        device_id,
        ct,
        &ticket,
        now + Duration::seconds(10),
        &deterministic_object_key(blob_id, &request.ciphertext_sha256),
    )
    .await
    .expect("complete");

    // First binder wins the CAS.
    cas_bind_blob(
        &mut tx,
        blob_id,
        &owner,
        device_id,
        now + Duration::seconds(20),
    )
    .await
    .expect("first binder wins");
    assert_eq!(blob_status(&mut tx, blob_id).await, "bound");
    // Second binder finds no completedUnbound row → conflict.
    let loser = cas_bind_blob(
        &mut tx,
        blob_id,
        &owner,
        device_id,
        now + Duration::seconds(21),
    )
    .await;
    assert!(matches!(
        loser,
        Err(BlobRepositoryError::CompareAndSetConflict)
    ));
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn only_the_signing_owner_device_may_delete_a_completed_unbound_blob() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let mut tx = pool.begin().await.expect("begin");
    let owner = random_plc_did();
    let (device_id, key_id) = seed_owner_tx(&mut tx, &owner).await;
    // A sibling device of the SAME owner DID.
    let (sibling_device, _sibling_key) = {
        let now = clock_now(&mut tx).await;
        let sibling_device = Uuid::new_v4();
        let public_key = random_ref();
        let sibling_key: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
            .bind(&public_key)
            .fetch_one(&mut *tx)
            .await
            .expect("derive sibling key id");
        sqlx::query(
            "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
             VALUES($1,$2,'sibling','active',$3,1,chat.protocol_capabilities(),$4,$4)",
        )
        .bind(&owner)
        .bind(sibling_device)
        .bind(&sibling_key)
        .bind(now)
        .execute(&mut *tx)
        .await
        .expect("insert sibling device");
        sqlx::query(
            "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
             VALUES($1,$2,$3,$4,1,$5)",
        )
        .bind(&owner)
        .bind(sibling_device)
        .bind(&sibling_key)
        .bind(&public_key)
        .bind(now)
        .execute(&mut *tx)
        .await
        .expect("insert sibling key");
        (sibling_device, sibling_key)
    };
    let now = clock_now(&mut tx).await;
    let request = prepare_request(
        &owner,
        device_id,
        &key_id,
        BlobPurpose::Attachment,
        BlobMediaType::ImagePng,
        1_000,
        now,
    );
    let blob_id = request.blob_id;
    let ct = request.ciphertext_size;
    let ticket = request.ticket_hash.clone();
    prepare_blob(&mut tx, &request).await.expect("prepare");
    complete_upload(
        &mut tx,
        blob_id,
        &owner,
        device_id,
        ct,
        &ticket,
        now + Duration::seconds(10),
        &deterministic_object_key(blob_id, &request.ciphertext_sha256),
    )
    .await
    .expect("complete");

    // The sibling device does NOT match the exact owning device → CAS conflict.
    let sibling_delete = cas_delete_blob(
        &mut tx,
        blob_id,
        &owner,
        sibling_device,
        now + Duration::seconds(20),
    )
    .await;
    assert!(matches!(
        sibling_delete,
        Err(BlobRepositoryError::CompareAndSetConflict)
    ));
    assert_eq!(blob_status(&mut tx, blob_id).await, "completedUnbound");

    // The exact signing owner device deletes it.
    cas_delete_blob(
        &mut tx,
        blob_id,
        &owner,
        device_id,
        now + Duration::seconds(21),
    )
    .await
    .expect("owner deletes");
    assert_eq!(blob_status(&mut tx, blob_id).await, "deleted");
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn database_check_backstops_media_per_purpose_and_size_relation() {
    // The dumb writer is trusted, but the sealed DDL is the ultimate authority:
    // a raw prepared insert that violates media-per-purpose or the AEAD relation
    // is rejected by the CHECK even if a caller bypassed `validate_blob_dimensions`.
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let mut tx = pool.begin().await.expect("begin");
    let owner = random_plc_did();
    let (device_id, key_id) = seed_owner_tx(&mut tx, &owner).await;
    let now = clock_now(&mut tx).await;

    // metadata purpose + GIF media violates blobs_media_type_check.
    let bad_media = NewPreparedBlob {
        blob_id: Uuid::new_v4(),
        owner_did: owner.clone(),
        owner_device_id: device_id,
        owner_key_id: key_id.clone(),
        owner_auth_generation: 1,
        purpose: BlobPurpose::Metadata,
        media_type: BlobMediaType::ImageGif,
        plaintext_size: 100,
        ciphertext_size: 116,
        ciphertext_sha256: Sha256::digest(random_ref()).to_vec(),
        prepared_at: now,
    };
    assert!(matches!(
        insert_prepared_blob(&mut tx, &bad_media).await,
        Err(BlobRepositoryError::Database(_))
    ));
    tx.rollback().await.expect("rollback media");

    // ciphertext != plaintext + 16 violates blobs_sizes_check.
    let mut tx = pool.begin().await.expect("begin size");
    let owner = random_plc_did();
    let (device_id, key_id) = seed_owner_tx(&mut tx, &owner).await;
    let now = clock_now(&mut tx).await;
    let bad_size = NewPreparedBlob {
        blob_id: Uuid::new_v4(),
        owner_did: owner.clone(),
        owner_device_id: device_id,
        owner_key_id: key_id,
        owner_auth_generation: 1,
        purpose: BlobPurpose::Attachment,
        media_type: BlobMediaType::ImagePng,
        plaintext_size: 100,
        ciphertext_size: 120,
        ciphertext_sha256: Sha256::digest(random_ref()).to_vec(),
        prepared_at: now,
    };
    assert!(matches!(
        insert_prepared_blob(&mut tx, &bad_size).await,
        Err(BlobRepositoryError::Database(_))
    ));
    tx.rollback().await.expect("rollback size");
}

// ===========================================================================
// Part 3 — stale send: the sole durable terminal tombstone (Slice 5, item 4).
//
// A stale send (the sender's live lease/interval was superseded before its
// message committed) branches BEFORE seq allocation and writes ONLY its terminal
// `chat.message_sends` row — no entry, no seq, no blob binding, no event. The
// send can never later succeed, and an exact replay returns the stored stale
// outcome while changed bytes conflict. The writer under test is the Slice-4a
// `resolve_application_send`.
// ===========================================================================

use repository::delivery::{
    resolve_application_send, AppendEntry, ApplicationSend, ApplicationSendDisposition,
    ApplicationSendOutcome, DeliveryRepositoryError,
};

async fn seed_bare_conversation(tx: &mut Transaction<'_, Postgres>) -> Uuid {
    let conversation_id = Uuid::new_v4();
    let now = clock_now(tx).await;
    sqlx::query(
        "INSERT INTO chat.conversations(conversation_id,kind,lifecycle,current_generation,current_state_version,next_entry_seq,created_at) \
         VALUES($1,'group','active',0,0,1,$2)",
    )
    .bind(conversation_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .expect("insert bare conversation");
    conversation_id
}

/// Build a coherent `ApplicationSend` for `conversation_id`/`message_id`. The
/// `request_digest` is the SHA-256 of the signing transcript so the
/// `message_sends_signature_check` relation holds.
fn application_send(
    conversation_id: Uuid,
    message_id: Uuid,
    actor_did: &str,
    actor_device_id: Uuid,
    actor_key_id: &str,
    transcript_seed: u8,
    received_at: DateTime<Utc>,
) -> ApplicationSend {
    let signing_transcript_bytes = vec![transcript_seed; 48];
    let request_digest = Sha256::digest(&signing_transcript_bytes).to_vec();
    ApplicationSend {
        entry: AppendEntry {
            conversation_id,
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
            accepted_payload_bytes: vec![1_u8; 8],
            accepted_payload_sha256: Sha256::digest([1_u8; 8]).to_vec(),
            signed_request_bytes: vec![2_u8; 16],
            request_digest,
            signature: vec![3_u8; 64],
            server_fields_bytes: vec![0_u8],
            outer_entry_fingerprint: vec![4_u8; 32],
            actor_did: actor_did.to_owned(),
            actor_device_id,
            actor_key_id: actor_key_id.to_owned(),
            actor_auth_generation: 1,
            generation: None,
            state_version: None,
            transition_id: None,
            message_id: Some(message_id),
            received_at,
        },
        signing_transcript_bytes,
        outcome_bytes: vec![9_u8; 8],
    }
}

async fn count_where(tx: &mut Transaction<'_, Postgres>, sql: &str, conversation_id: Uuid) -> i64 {
    sqlx::query_scalar(sql)
        .bind(conversation_id)
        .fetch_one(&mut **tx)
        .await
        .expect("count")
}

#[tokio::test]
async fn stale_send_writes_only_a_tombstone_with_no_entry_seq_blob_or_event() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let mut tx = pool.begin().await.expect("begin");
    let owner = random_plc_did();
    let (device_id, key_id) = seed_owner_tx(&mut tx, &owner).await;
    let conversation_id = seed_bare_conversation(&mut tx).await;
    let message_id = Uuid::new_v4();
    let now = clock_now(&mut tx).await;
    let send = application_send(
        conversation_id,
        message_id,
        &owner,
        device_id,
        &key_id,
        0x11,
        now,
    );

    // Baseline the (non-conversation-scoped) event + outbox tables so a stale-branch
    // event/outbox-emit regression is caught by a nonzero delta. The suite runs
    // --test-threads=1, so no concurrent committer moves these counts across the
    // single resolve call.
    async fn events_plus_outbox(tx: &mut Transaction<'_, Postgres>) -> i64 {
        let events: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.events")
            .fetch_one(&mut **tx)
            .await
            .expect("count events");
        let outbox: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.outbox")
            .fetch_one(&mut **tx)
            .await
            .expect("count outbox");
        events + outbox
    }
    let event_outbox_before = events_plus_outbox(&mut tx).await;

    let outcome = resolve_application_send(&mut tx, &send, ApplicationSendDisposition::Stale)
        .await
        .expect("stale resolves");
    assert_eq!(outcome, ApplicationSendOutcome::Stale);

    // Exactly one durable tombstone: status 'stale', NO accepted seq.
    let (status, accepted_entry_seq): (String, Option<i64>) = sqlx::query_as(
        "SELECT status, accepted_entry_seq FROM chat.message_sends WHERE conversation_id=$1 AND message_id=$2",
    )
    .bind(conversation_id)
    .bind(message_id)
    .fetch_one(&mut *tx)
    .await
    .expect("tombstone row");
    assert_eq!(status, "stale");
    assert_eq!(accepted_entry_seq, None);

    // ZERO entry / seq / blob-binding / event residue for this conversation.
    let entries = count_where(
        &mut tx,
        "SELECT count(*) FROM chat.entries WHERE conversation_id=$1",
        conversation_id,
    )
    .await;
    assert_eq!(entries, 0, "a stale send appends no entry");
    let next_seq: i64 = sqlx::query_scalar(
        "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&mut *tx)
    .await
    .expect("head seq");
    assert_eq!(next_seq, 1, "a stale send allocates no seq");
    let bindings = count_where(
        &mut tx,
        "SELECT count(*) FROM chat.blob_bindings WHERE conversation_id=$1",
        conversation_id,
    )
    .await;
    assert_eq!(bindings, 0, "a stale send binds no blob");
    // ZERO event / outbox residue: the stale writer emits neither. `chat.events`
    // is keyed by `protocol_instance_id` (not `conversation_id`), so this is a
    // global baseline-delta assertion rather than a conversation-scoped count.
    let event_outbox_after = events_plus_outbox(&mut tx).await;
    assert_eq!(
        event_outbox_after, event_outbox_before,
        "a stale send emits no event or outbox work"
    );
    //
    // The deferred `assert_message_send_mapping` accepts a stale row precisely
    // BECAUSE it carries zero entries (its `ELSIF entry_count <> 0` arm), so the
    // tombstone is commit-coherent by construction; we do not fire SET CONSTRAINTS
    // here because a bare conversation intentionally lacks the full generation /
    // state graph a real send would have.
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn stale_send_exact_replay_returns_stale_and_never_later_succeeds() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let mut tx = pool.begin().await.expect("begin");
    let owner = random_plc_did();
    let (device_id, key_id) = seed_owner_tx(&mut tx, &owner).await;
    let conversation_id = seed_bare_conversation(&mut tx).await;
    let message_id = Uuid::new_v4();
    let now = clock_now(&mut tx).await;
    let send = application_send(
        conversation_id,
        message_id,
        &owner,
        device_id,
        &key_id,
        0x22,
        now,
    );

    // First resolution stales.
    assert_eq!(
        resolve_application_send(&mut tx, &send, ApplicationSendDisposition::Stale)
            .await
            .expect("first stale"),
        ApplicationSendOutcome::Stale
    );
    // Exact replay returns the stored stale outcome, ignoring the caller's later
    // disposition — the message can never later succeed.
    assert_eq!(
        resolve_application_send(&mut tx, &send, ApplicationSendDisposition::Accept)
            .await
            .expect("replay ignores disposition"),
        ApplicationSendOutcome::Stale
    );
    // Still no entry appended (the Accept disposition did NOT create one).
    let entries = count_where(
        &mut tx,
        "SELECT count(*) FROM chat.entries WHERE conversation_id=$1",
        conversation_id,
    )
    .await;
    assert_eq!(entries, 0);
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn stale_send_changed_bytes_under_same_message_id_conflicts() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let mut tx = pool.begin().await.expect("begin");
    let owner = random_plc_did();
    let (device_id, key_id) = seed_owner_tx(&mut tx, &owner).await;
    let conversation_id = seed_bare_conversation(&mut tx).await;
    let message_id = Uuid::new_v4();
    let now = clock_now(&mut tx).await;
    let send = application_send(
        conversation_id,
        message_id,
        &owner,
        device_id,
        &key_id,
        0x33,
        now,
    );
    resolve_application_send(&mut tx, &send, ApplicationSendDisposition::Stale)
        .await
        .expect("first stale");

    // A different message reusing the id (different transcript => different
    // request_digest) is a conflict, not a replay.
    let changed = application_send(
        conversation_id,
        message_id,
        &owner,
        device_id,
        &key_id,
        0x44,
        now,
    );
    let result =
        resolve_application_send(&mut tx, &changed, ApplicationSendDisposition::Stale).await;
    assert!(matches!(
        result,
        Err(DeliveryRepositoryError::MessageSendConflict)
    ));
    tx.rollback().await.expect("rollback");
}

// ===========================================================================
// Part 4 — ciphertext-blind boundary (Slice 5, item 2), mls-ds portion.
//
// The delivery service stores every descriptor / AAD as opaque BYTEA and never
// decrypts or parses the encrypted inner application fields. The shared-Rust
// client authority (catbird-mls) owns the reaction / atprotoRecord / externalLink
// / blurhash grammars and their parity fixtures; those are CROSS-REPO evidence
// for the completion gate and are deliberately NOT duplicated here. This test
// proves opaque carriage: descriptor bytes that HAPPEN to contain an `at://`
// URI and reaction-shaped bytes round-trip byte-for-byte with no interpretation.
// ===========================================================================

#[tokio::test]
async fn descriptor_and_aad_bytes_are_stored_opaquely_without_inner_parsing() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let mut tx = pool.begin().await.expect("begin");
    let owner = random_plc_did();
    let (device_id, key_id) = seed_owner_tx(&mut tx, &owner).await;
    let conversation_id = seed_bare_conversation(&mut tx).await;
    let now = clock_now(&mut tx).await;

    // Prepare + complete a real bound-eligible blob so the binding's immediate
    // identity/window FKs are satisfiable.
    let request = prepare_request(
        &owner,
        device_id,
        &key_id,
        BlobPurpose::Attachment,
        BlobMediaType::ImagePng,
        1_000,
        now,
    );
    let blob_id = request.blob_id;
    let ct = request.ciphertext_size;
    let pt = request.plaintext_size;
    let ct_sha = request.ciphertext_sha256.clone();
    let ticket = request.ticket_hash.clone();
    prepare_blob(&mut tx, &request).await.expect("prepare");
    complete_upload(
        &mut tx,
        blob_id,
        &owner,
        device_id,
        ct,
        &ticket,
        now + Duration::seconds(10),
        &deterministic_object_key(blob_id, &request.ciphertext_sha256),
    )
    .await
    .expect("complete");
    cas_bind_blob(
        &mut tx,
        blob_id,
        &owner,
        device_id,
        now + Duration::seconds(20),
    )
    .await
    .expect("bind blob status");

    // Descriptor bytes that embed an at:// URI and reaction-shaped bytes; the
    // server must never parse them — it stores the exact bytes.
    let descriptor_bytes =
        b"at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.bsky.feed.post/xyz \xF0\x9F\x91\x8D".to_vec();
    let aad_bytes = b"externalLink=https://example.com/\\ \x00control".to_vec();
    let binding = repository::blobs::NewBlobBinding {
        blob_id,
        binding_kind: repository::blobs::BindingKind::Application,
        conversation_id,
        entry_seq: Some(1),
        message_id: Some(Uuid::new_v4()),
        metadata_origin_transition_id: None,
        metadata_version: None,
        owner_did: owner.clone(),
        owner_device_id: device_id,
        descriptor_bytes: descriptor_bytes.clone(),
        descriptor_sha256: Sha256::digest(&descriptor_bytes).to_vec(),
        aad_bytes: aad_bytes.clone(),
        aad_sha256: Sha256::digest(&aad_bytes).to_vec(),
        ciphertext_sha256: ct_sha,
        plaintext_size: pt,
        ciphertext_size: ct,
        purpose: BlobPurpose::Attachment,
        bound_at: now + Duration::seconds(20),
        uploaded_at: now + Duration::seconds(10),
        unbound_expires_at: now + Duration::seconds(10) + Duration::hours(1),
    };
    repository::blobs::insert_blob_binding(&mut tx, &binding)
        .await
        .expect("insert opaque binding");

    // Round-trip: the stored bytes equal the input bytes exactly (no normalization,
    // no percent-decoding, no grammar validation).
    let (stored_descriptor, stored_aad): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT descriptor_bytes, aad_bytes FROM chat.blob_bindings WHERE blob_id=$1",
    )
    .bind(blob_id)
    .fetch_one(&mut *tx)
    .await
    .expect("read binding bytes");
    assert_eq!(stored_descriptor, descriptor_bytes);
    assert_eq!(stored_aad, aad_bytes);

    tx.rollback().await.expect("rollback");
}

// ===========================================================================
// Part 5 — application binding + attachment reads against device intervals
// (Slice 5, item 3 and the binding portion of item 1).
//
// A coherent creation graph (conversation + genesis leaf + open interval) plus an
// accepted application entry at seq 2 is seeded in-transaction; a prepared blob is
// completed and bound to that entry via `bind_application_blob`. The whole graph
// is proven commit-coherent with `SET CONSTRAINTS ALL IMMEDIATE`. The attachment
// read then qualifies ONLY through the caller's exact device interval spanning the
// binding seq — a same-DID sibling (no interval), a pre-join device, a gapped
// device, a strictly-before-terminal device, and a re-Add-without-backfill device
// all read `None`; only the exact recipient device with a spanning interval reads
// the opaque view.
// ===========================================================================

use repository::blobs::{
    bind_application_blob, insert_blob_binding, read_application_attachment, BindingKind,
    NewBlobBinding,
};

struct CreationGraph {
    conversation_id: Uuid,
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
    actor_public_key: Vec<u8>,
    leaf_period_id: Uuid,
    creation_transition_id: Uuid,
    group_id: Vec<u8>,
    group_context_hash: Vec<u8>,
    confirmation_tag: Vec<u8>,
    creation_fingerprint: Vec<u8>,
    accepted_at: DateTime<Utc>,
}

/// Seed a coherent genesis conversation (creator active/admin/sole-leaf, one open
/// application interval at start_seq 1, next_entry_seq=2) INSIDE the caller's
/// transaction. Mirrors the proven `seed_fixture` graph; rolls back with the test.
async fn seed_creation_graph_tx(
    tx: &mut Transaction<'_, Postgres>,
    actor_did: &str,
) -> CreationGraph {
    let now = clock_now(tx).await;
    sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2)")
        .bind(actor_did)
        .bind(now)
        .execute(&mut **tx)
        .await
        .expect("principal");
    let actor_device_id = Uuid::new_v4();
    let actor_public_key = random_ref();
    let actor_key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&actor_public_key)
        .fetch_one(&mut **tx)
        .await
        .expect("key id");
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'creator','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    )
    .bind(actor_did).bind(actor_device_id).bind(&actor_key_id).bind(now)
    .execute(&mut **tx).await.expect("device");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
         VALUES($1,$2,$3,$4,1,$5)",
    )
    .bind(actor_did).bind(actor_device_id).bind(&actor_key_id).bind(&actor_public_key).bind(now)
    .execute(&mut **tx).await.expect("device key");

    let conversation_id = Uuid::new_v4();
    let creation_transition_id = Uuid::new_v4();
    let creation_entry_id = Uuid::new_v4();
    let participant_period_id = Uuid::new_v4();
    let leaf_period_id = Uuid::new_v4();
    let metadata_snapshot_id = Uuid::new_v4();
    let group_id = vec![1_u8; 32];
    let group_context_hash = vec![2_u8; 32];
    let confirmation_tag = vec![3_u8; 32];
    let group_info = vec![4_u8; 8];
    let snapshot = vec![5_u8; 8];
    let tree_summary = vec![6_u8; 8];
    let signed_request = vec![7_u8; 8];
    let unsigned_projection = vec![8_u8; 8];
    let signing_transcript = vec![9_u8; 8];
    let request_digest = Sha256::digest(&signing_transcript).to_vec();
    let signature = vec![10_u8; 64];
    let accepted_payload = vec![11_u8; 8];
    let creation_fingerprint = vec![12_u8; 32];
    let metadata_ciphertext = vec![13_u8; 16];
    let basic_credential = format!("{actor_did}#{actor_device_id}").into_bytes();

    sqlx::query(
        "INSERT INTO chat.conversations(conversation_id,kind,lifecycle,current_generation,current_state_version,next_entry_seq,created_at) VALUES($1,'group','active',0,0,2,$2)",
    ).bind(conversation_id).bind(now).execute(&mut **tx).await.expect("conversation");
    sqlx::query(
        "INSERT INTO chat.generations(conversation_id,generation,group_id,lifecycle,genesis_group_info_bytes,genesis_group_info_sha256,current_state_version,activated_seq,activated_at) VALUES($1,0,$2,'active',$3,$4,0,1,$5)",
    ).bind(conversation_id).bind(&group_id).bind(&group_info).bind(Sha256::digest(&group_info).to_vec()).bind(now).execute(&mut **tx).await.expect("generation");
    sqlx::query(
        r#"INSERT INTO chat.transitions(transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,next_generation,next_state_version,metadata_snapshot_id,entry_seq,accepted_at) VALUES($1,$2,'creation',$3,$4,$5,1,'admin','active',$6,$7,$8,$9,$10,0,0,$11,1,$12)"#,
    ).bind(creation_transition_id).bind(conversation_id).bind(actor_did).bind(actor_device_id).bind(&actor_key_id).bind(&signed_request).bind(&unsigned_projection).bind(&signing_transcript).bind(&request_digest).bind(&signature).bind(metadata_snapshot_id).bind(now).execute(&mut **tx).await.expect("transition");
    sqlx::query(
        r#"INSERT INTO chat.generation_states(conversation_id,generation,state_version,group_id,epoch,group_context_hash,confirmation_tag,lifecycle,state_kind,producing_transition_id,public_snapshot_bytes,snapshot_sha256,tree_summary_bytes,tree_summary_sha256,leaf_count,created_at) VALUES($1,0,0,$2,0,$3,$4,'active','creation',$5,$6,$7,$8,$9,1,$10)"#,
    ).bind(conversation_id).bind(&group_id).bind(&group_context_hash).bind(&confirmation_tag).bind(creation_transition_id).bind(&snapshot).bind(Sha256::digest(&snapshot).to_vec()).bind(&tree_summary).bind(Sha256::digest(&tree_summary).to_vec()).bind(now).execute(&mut **tx).await.expect("state");
    sqlx::query(
        r#"INSERT INTO chat.participants(participant_period_id,conversation_id,user_did,status,role,role_transition_id,role_changed_at,created_by_did,created_by_device_id,current_membership,created_at) VALUES($1,$2,$3,'active','admin',$4,$5,$3,$6,true,$5)"#,
    ).bind(participant_period_id).bind(conversation_id).bind(actor_did).bind(creation_transition_id).bind(now).bind(actor_device_id).execute(&mut **tx).await.expect("participant");
    sqlx::query(
        r#"INSERT INTO chat.member_devices(leaf_period_id,participant_period_id,conversation_id,generation,user_did,device_id,leaf_index,basic_credential,leaf_signature_key,leaf_key_id,leaf_auth_generation,origin,joined_state_version,joined_transition_id,joined_seq,active,created_at) VALUES($1,$2,$3,0,$4,$5,0,$6,$7,$8,1,'genesis',0,$9,1,true,$10)"#,
    ).bind(leaf_period_id).bind(participant_period_id).bind(conversation_id).bind(actor_did).bind(actor_device_id).bind(&basic_credential).bind(&actor_public_key).bind(&actor_key_id).bind(creation_transition_id).bind(now).execute(&mut **tx).await.expect("leaf");
    sqlx::query(
        r#"INSERT INTO chat.metadata_snapshots(metadata_snapshot_id,conversation_id,generation,state_version,group_id,epoch,group_context_hash,confirmation_tag,producing_transition_id,origin_transition_id,metadata_version,nonce,ciphertext,ciphertext_sha256,ciphertext_size,author_did,author_device_id,author_key_id,author_public_key,author_auth_generation,author_origin_seq,author_role,author_device_status,created_at) VALUES($1,$2,0,0,$3,0,$4,$5,$6,$6,1,$7,$8,$9,16,$10,$11,$12,$13,1,1,'admin','active',$14)"#,
    ).bind(metadata_snapshot_id).bind(conversation_id).bind(&group_id).bind(&group_context_hash).bind(&confirmation_tag).bind(creation_transition_id).bind(vec![14_u8; 12]).bind(&metadata_ciphertext).bind(Sha256::digest(&metadata_ciphertext).to_vec()).bind(actor_did).bind(actor_device_id).bind(&actor_key_id).bind(&actor_public_key).bind(now).execute(&mut **tx).await.expect("metadata");
    sqlx::query(
        r#"INSERT INTO chat.entries(conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,accepted_payload_sha256,signed_request_bytes,request_digest,signature,server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,actor_key_id,actor_auth_generation,generation,state_version,transition_id,received_at) VALUES($1,1,$2,'blue.catbird.chat.defs#creationEntry',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,0,0,$13,$14)"#,
    ).bind(conversation_id).bind(creation_entry_id).bind(&accepted_payload).bind(Sha256::digest(&accepted_payload).to_vec()).bind(&signed_request).bind(&request_digest).bind(&signature).bind(vec![0_u8]).bind(&creation_fingerprint).bind(actor_did).bind(actor_device_id).bind(&actor_key_id).bind(creation_transition_id).bind(now).execute(&mut **tx).await.expect("creation entry");
    sqlx::query(
        r#"INSERT INTO chat.application_intervals(membership_interval_id,conversation_id,generation,recipient_did,recipient_device_id,start_seq,opening_kind,opening_transition_id,opening_outer_entry_fingerprint,opening_state_version,opening_group_id,opening_epoch,opening_group_context_hash,opening_confirmation_tag,opening_leaf_period_id,created_at) VALUES($1,$2,0,$3,$4,1,'creation',$1,$5,0,$6,0,$7,$8,$9,$10)"#,
    ).bind(creation_transition_id).bind(conversation_id).bind(actor_did).bind(actor_device_id).bind(&creation_fingerprint).bind(&group_id).bind(&group_context_hash).bind(&confirmation_tag).bind(leaf_period_id).bind(now).execute(&mut **tx).await.expect("interval");

    CreationGraph {
        conversation_id,
        actor_did: actor_did.to_owned(),
        actor_device_id,
        actor_key_id,
        actor_public_key,
        leaf_period_id,
        creation_transition_id,
        group_id,
        group_context_hash,
        confirmation_tag,
        creation_fingerprint,
        accepted_at: now,
    }
}

/// Build the accepted application `ApplicationSend` for the creator at seq 2.
fn coherent_app_send(
    graph: &CreationGraph,
    salt: u8,
    received_at: DateTime<Utc>,
) -> ApplicationSend {
    let signing_transcript_bytes = vec![salt ^ 0x5a; 16];
    let request_digest = Sha256::digest(&signing_transcript_bytes).to_vec();
    ApplicationSend {
        entry: AppendEntry {
            conversation_id: graph.conversation_id,
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
            accepted_payload_bytes: vec![salt; 8],
            accepted_payload_sha256: Sha256::digest([salt; 8]).to_vec(),
            signed_request_bytes: vec![salt ^ 0x33; 8],
            request_digest,
            signature: vec![salt; 64],
            server_fields_bytes: vec![salt; 1],
            outer_entry_fingerprint: vec![salt; 32],
            actor_did: graph.actor_did.clone(),
            actor_device_id: graph.actor_device_id,
            actor_key_id: graph.actor_key_id.clone(),
            actor_auth_generation: 1,
            generation: Some(0),
            state_version: Some(0),
            transition_id: None,
            message_id: Some(Uuid::new_v4()),
            received_at,
        },
        signing_transcript_bytes,
        outcome_bytes: vec![salt ^ 0x0f; 8],
    }
}

#[tokio::test]
async fn application_binding_is_readable_by_the_exact_device_and_denied_to_a_sibling() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let mut tx = pool.begin().await.expect("begin");
    let owner = random_plc_did();
    let graph = seed_creation_graph_tx(&mut tx, &owner).await;
    let now = graph.accepted_at;

    // Append the accepted application entry at seq 2.
    let send = coherent_app_send(&graph, 0x21, now);
    let message_id = send.entry.message_id.unwrap();
    let outcome = resolve_application_send(&mut tx, &send, ApplicationSendDisposition::Accept)
        .await
        .expect("accept send");
    assert_eq!(outcome, ApplicationSendOutcome::Accepted { seq: 2 });

    // Prepare + complete + bind a blob to that application entry.
    let request = prepare_request(
        &owner,
        graph.actor_device_id,
        &graph.actor_key_id,
        BlobPurpose::Attachment,
        BlobMediaType::ImagePng,
        1_000,
        now,
    );
    let blob_id = request.blob_id;
    let ct = request.ciphertext_size;
    let pt = request.plaintext_size;
    let ct_sha = request.ciphertext_sha256.clone();
    let ticket = request.ticket_hash.clone();
    prepare_blob(&mut tx, &request).await.expect("prepare");
    let uploaded_at = now + Duration::seconds(10);
    complete_upload(
        &mut tx,
        blob_id,
        &owner,
        graph.actor_device_id,
        ct,
        &ticket,
        uploaded_at,
        &deterministic_object_key(blob_id, &request.ciphertext_sha256),
    )
    .await
    .expect("complete");
    let descriptor_bytes = vec![0xAB_u8; 40];
    let aad_bytes = vec![0xCD_u8; 24];
    let binding = NewBlobBinding {
        blob_id,
        binding_kind: BindingKind::Application,
        conversation_id: graph.conversation_id,
        entry_seq: Some(2),
        message_id: Some(message_id),
        metadata_origin_transition_id: None,
        metadata_version: None,
        owner_did: owner.clone(),
        owner_device_id: graph.actor_device_id,
        descriptor_bytes: descriptor_bytes.clone(),
        descriptor_sha256: Sha256::digest(&descriptor_bytes).to_vec(),
        aad_bytes: aad_bytes.clone(),
        aad_sha256: Sha256::digest(&aad_bytes).to_vec(),
        ciphertext_sha256: ct_sha,
        plaintext_size: pt,
        ciphertext_size: ct,
        purpose: BlobPurpose::Attachment,
        bound_at: now + Duration::seconds(20),
        uploaded_at,
        unbound_expires_at: uploaded_at + Duration::hours(1),
    };
    bind_application_blob(&mut tx, &binding)
        .await
        .expect("bind application blob");

    // The exact recipient device with an open interval spanning seq 2 sees the blob.
    let view = read_application_attachment(&mut tx, blob_id, &owner, graph.actor_device_id)
        .await
        .expect("read")
        .expect("exact device sees the attachment");
    assert_eq!(view.blob_id, blob_id);
    assert_eq!(view.entry_seq, 2);
    assert_eq!(
        view.object_store_key_for_test(),
        deterministic_object_key(blob_id, &request.ciphertext_sha256)
    );
    assert_eq!(view.descriptor_bytes, descriptor_bytes);
    assert_eq!(view.aad_bytes, aad_bytes);

    // A same-DID SIBLING device (no interval) is denied — DID match is never enough.
    let sibling_device = Uuid::new_v4();
    let sibling_pk = random_ref();
    let sibling_key: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&sibling_pk)
        .fetch_one(&mut *tx)
        .await
        .expect("sibling key id");
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'sibling','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    ).bind(&owner).bind(sibling_device).bind(&sibling_key).bind(now).execute(&mut *tx).await.expect("sibling device");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,$3,$4,1,$5)",
    ).bind(&owner).bind(sibling_device).bind(&sibling_key).bind(&sibling_pk).bind(now).execute(&mut *tx).await.expect("sibling key");
    let sibling_view = read_application_attachment(&mut tx, blob_id, &owner, sibling_device)
        .await
        .expect("sibling read runs");
    assert!(
        sibling_view.is_none(),
        "a same-DID sibling with no interval is denied"
    );

    // Prove the WHOLE graph (accepted send mapping + blob binding lifecycle + interval
    // schedules) is commit-coherent.
    set_constraints_immediate(&mut tx).await;
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn attachment_read_predicate_matches_the_exact_device_interval_span() {
    // Isolates the interval-spanning read predicate (the same predicate the delivery
    // read path proves): a binding at seq 5 is visible to a reader ONLY when its
    // interval spans seq 5 inclusively. Extra reader intervals point their opening
    // leaf at the genesis leaf to satisfy the immediate FK; the deferred identity
    // FKs are intentionally NOT fired (this is a read-predicate isolation test, and
    // the binding's full write coherence is proven by the sibling positive above).
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let mut tx = pool.begin().await.expect("begin");
    let owner = random_plc_did();
    let graph = seed_creation_graph_tx(&mut tx, &owner).await;
    let now = graph.accepted_at;
    let binding_seq: i64 = 5;

    // A bound blob + an application binding at seq 5 (deferred entry FKs left unfired).
    let request = prepare_request(
        &owner,
        graph.actor_device_id,
        &graph.actor_key_id,
        BlobPurpose::Attachment,
        BlobMediaType::ImagePng,
        800,
        now,
    );
    let blob_id = request.blob_id;
    let ct = request.ciphertext_size;
    let pt = request.plaintext_size;
    let ct_sha = request.ciphertext_sha256.clone();
    let ticket = request.ticket_hash.clone();
    prepare_blob(&mut tx, &request).await.expect("prepare");
    let uploaded_at = now + Duration::seconds(10);
    complete_upload(
        &mut tx,
        blob_id,
        &owner,
        graph.actor_device_id,
        ct,
        &ticket,
        uploaded_at,
        &deterministic_object_key(blob_id, &request.ciphertext_sha256),
    )
    .await
    .expect("complete");
    cas_bind_blob(
        &mut tx,
        blob_id,
        &owner,
        graph.actor_device_id,
        now + Duration::seconds(20),
    )
    .await
    .expect("bind status");
    let descriptor = vec![0x01_u8; 8];
    let aad = vec![0x02_u8; 8];
    insert_blob_binding(
        &mut tx,
        &NewBlobBinding {
            blob_id,
            binding_kind: BindingKind::Application,
            conversation_id: graph.conversation_id,
            entry_seq: Some(binding_seq),
            message_id: Some(Uuid::new_v4()),
            metadata_origin_transition_id: None,
            metadata_version: None,
            owner_did: owner.clone(),
            owner_device_id: graph.actor_device_id,
            descriptor_bytes: descriptor.clone(),
            descriptor_sha256: Sha256::digest(&descriptor).to_vec(),
            aad_bytes: aad.clone(),
            aad_sha256: Sha256::digest(&aad).to_vec(),
            ciphertext_sha256: ct_sha,
            plaintext_size: pt,
            ciphertext_size: ct,
            purpose: BlobPurpose::Attachment,
            bound_at: now + Duration::seconds(20),
            uploaded_at,
            unbound_expires_at: uploaded_at + Duration::hours(1),
        },
    )
    .await
    .expect("insert binding");

    // Helper: create a fresh predicate-only reader device.
    async fn seed_reader_device(tx: &mut Transaction<'_, Postgres>, graph: &CreationGraph) -> Uuid {
        let now = graph.accepted_at;
        let reader = Uuid::new_v4();
        let pk = random_ref();
        let key: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
            .bind(&pk)
            .fetch_one(&mut **tx)
            .await
            .expect("reader key id");
        sqlx::query("INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'reader','active',$3,1,chat.protocol_capabilities(),$4,$4)").bind(&graph.actor_did).bind(reader).bind(&key).bind(now).execute(&mut **tx).await.expect("reader device");
        sqlx::query("INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,$3,$4,1,$5)").bind(&graph.actor_did).bind(reader).bind(&key).bind(&pk).bind(now).execute(&mut **tx).await.expect("reader key");
        reader
    }

    // Helper: insert one predicate-only interval for an EXISTING reader device.
    async fn add_reader_interval(
        tx: &mut Transaction<'_, Postgres>,
        graph: &CreationGraph,
        reader: Uuid,
        start_seq: i64,
        terminal_seq: Option<i64>,
    ) {
        let now = graph.accepted_at;
        // membership_interval_id must equal opening_transition_id (id_check); use a
        // fresh v4 for both. The opening/closing transition provenance FKs are
        // DEFERRED and intentionally left unfired in this read-predicate isolation.
        let interval_id = Uuid::new_v4();
        let closing_id = Uuid::new_v4();
        if let Some(terminal) = terminal_seq {
            // Finite interval: full close columns (deferred close FKs left unfired).
            sqlx::query(
                r#"INSERT INTO chat.application_intervals(membership_interval_id,conversation_id,generation,recipient_did,recipient_device_id,start_seq,opening_kind,opening_transition_id,opening_outer_entry_fingerprint,opening_state_version,opening_group_id,opening_epoch,opening_group_context_hash,opening_confirmation_tag,opening_leaf_period_id,terminal_seq,closing_state_version,closing_transition_id,closing_outer_entry_fingerprint,closing_kind,closing_leaf_period_id,removed_at,created_at) VALUES($1,$2,0,$3,$4,$5,'creation',$1,$6,0,$7,0,$8,$9,$10,$11,1,$12,$13,'remove',$10,$14,$14)"#,
            ).bind(interval_id).bind(graph.conversation_id).bind(&graph.actor_did).bind(reader).bind(start_seq).bind(&graph.creation_fingerprint).bind(&graph.group_id).bind(&graph.group_context_hash).bind(&graph.confirmation_tag).bind(graph.leaf_period_id).bind(terminal).bind(closing_id).bind(vec![0x77_u8; 32]).bind(now).execute(&mut **tx).await.expect("finite interval");
        } else {
            sqlx::query(
                r#"INSERT INTO chat.application_intervals(membership_interval_id,conversation_id,generation,recipient_did,recipient_device_id,start_seq,opening_kind,opening_transition_id,opening_outer_entry_fingerprint,opening_state_version,opening_group_id,opening_epoch,opening_group_context_hash,opening_confirmation_tag,opening_leaf_period_id,created_at) VALUES($1,$2,0,$3,$4,$5,'creation',$1,$6,0,$7,0,$8,$9,$10,$11)"#,
            ).bind(interval_id).bind(graph.conversation_id).bind(&graph.actor_did).bind(reader).bind(start_seq).bind(&graph.creation_fingerprint).bind(&graph.group_id).bind(&graph.group_context_hash).bind(&graph.confirmation_tag).bind(graph.leaf_period_id).bind(now).execute(&mut **tx).await.expect("open interval");
        }
    }

    // Helper: fresh device + one interval (the common single-interval case).
    async fn seed_reader_interval(
        tx: &mut Transaction<'_, Postgres>,
        graph: &CreationGraph,
        start_seq: i64,
        terminal_seq: Option<i64>,
    ) -> Uuid {
        let reader = seed_reader_device(tx, graph).await;
        add_reader_interval(tx, graph, reader, start_seq, terminal_seq).await;
        reader
    }

    // Open interval spanning seq 5 => visible.
    let spanning = seed_reader_interval(&mut tx, &graph, 1, None).await;
    assert!(
        read_application_attachment(&mut tx, blob_id, &owner, spanning)
            .await
            .expect("read")
            .is_some()
    );

    // Pre-join: interval opens AFTER seq 5 (start_seq 6) => denied.
    let pre_join = seed_reader_interval(&mut tx, &graph, 6, None).await;
    assert!(
        read_application_attachment(&mut tx, blob_id, &owner, pre_join)
            .await
            .expect("read")
            .is_none()
    );

    // Gap: a finite interval ENTIRELY before seq 5 ([1,4]) => denied.
    let gapped = seed_reader_interval(&mut tx, &graph, 1, Some(4)).await;
    assert!(
        read_application_attachment(&mut tx, blob_id, &owner, gapped)
            .await
            .expect("read")
            .is_none()
    );

    // Removed-device terminal boundary is INCLUSIVE: terminal_seq == 5 => still visible.
    let boundary = seed_reader_interval(&mut tx, &graph, 1, Some(5)).await;
    assert!(
        read_application_attachment(&mut tx, blob_id, &owner, boundary)
            .await
            .expect("read")
            .is_some()
    );

    // Strictly-before terminal boundary: terminal_seq == 4 => denied.
    let before = seed_reader_interval(&mut tx, &graph, 1, Some(4)).await;
    assert!(
        read_application_attachment(&mut tx, blob_id, &owner, before)
            .await
            .expect("read")
            .is_none()
    );

    // Re-Add WITHOUT backfill: ONE device removed at seq 4 and re-added at seq 6
    // holds two intervals [1,4] and [6,open]. Seq 5 falls in the gap between them,
    // so the re-added device does NOT inherit the seq-5 attachment (no history
    // backfill) — denied.
    let re_added = seed_reader_device(&mut tx, &graph).await;
    add_reader_interval(&mut tx, &graph, re_added, 1, Some(4)).await;
    add_reader_interval(&mut tx, &graph, re_added, 6, None).await;
    assert!(
        read_application_attachment(&mut tx, blob_id, &owner, re_added)
            .await
            .expect("read")
            .is_none(),
        "a re-Added device does not inherit an attachment from the gap before it rejoined"
    );

    tx.rollback().await.expect("rollback");
}
