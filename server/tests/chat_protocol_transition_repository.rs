//! Live-PostgreSQL repository tests for the clean-chat transition state-family
//! row writers (`chat_protocol::repository::transition`).
//!
//! These prove the per-family appliers persist every migration-1 column
//! faithfully, that each compare-and-set advances/terminalizes exactly the row
//! in the expected pre-state and conflicts on drift, that metadata nonce reuse
//! maps to its typed variant, and that the DDL's own partial-unique / status
//! constraints back-stop the appliers.
//!
//! Isolation boundary: these test a *dumb, exact SQL layer*. Each row writer is
//! exercised inside one transaction with same-transaction read-back and then
//! ROLLED BACK. This deliberately verifies every IMMEDIATE constraint (primary
//! keys, partial-unique indexes, immediate foreign keys, CHECKs), column
//! fidelity, and CAS `rows_affected` semantics — while the migration's DEFERRED
//! cross-table coherence triggers (`assert_participant_provenance`,
//! `assert_reset_request_mapping`, `assert_recovery_fulfillment_mapping`,
//! `assert_entry_transition_mapping`, and the deferred provenance FKs into
//! `chat.entries`/`chat.transitions`) fire only at COMMIT and enforce a fully
//! coherent transition+entry+state graph. Building that graph is the composing
//! executor's job (task E2b) and is verified there, not by these unit writers.
//!
//! The production repository module is gated `#[cfg(not(test))]` (see
//! `src/chat_protocol/repository/mod.rs`), so — mirroring the sibling repository
//! harnesses — this test `include!`s it directly. The module is self-contained
//! (only `chrono`/`sqlx`/`uuid`), so no other production module is included.
//!
//! Run against the dedicated clean-chat database:
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_transition_repository -- --test-threads=1

#![allow(dead_code)]

mod common;

mod repository {
    pub(crate) mod transition {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/transition.rs"
        ));
    }
}

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use repository::transition::{
    cas_key_package_status, cas_participant_pending_to_active, close_leaf_period,
    insert_generation_state_row, insert_leaf_period, insert_leaf_recovery_request,
    insert_leave_request, insert_metadata_snapshot, insert_participant_period, insert_reservation,
    insert_reset_request, insert_transition_row, terminalize_leaf_recovery_request,
    terminalize_leave_request, terminalize_participant_period, terminalize_reservation,
    terminalize_reset_request, GenerationStateKind, GenerationStateLifecycle, LeafClose,
    LeafOrigin, LeafRecoveryKind, LeafRecoverySource, LeafRecoveryTermination,
    LeaveRequestTermination, MetadataAvatarBinding, NewGenerationState, NewLeafPeriod,
    NewLeafRecoveryRequest, NewLeaveRequest, NewMetadataSnapshot, NewParticipantPeriod,
    NewReservation, NewResetRequest, NewTransition, PackageStatus, PackageSuccessor,
    ParticipantAcceptance, ParticipantAcceptanceCas, ParticipantInvitation, ParticipantRole,
    ParticipantStatus, ParticipantTerminalization, ReservationTermination, ResetReason,
    ResetRequestTermination, TransitionActorRole, TransitionCoordinates, TransitionKind,
    TransitionRepositoryError,
};

// ---------------------------------------------------------------------------
// Fixture: a committed, coherent conversation the appliers can extend.
// Adapted from `tests/chat_protocol_delivery.rs::create_conversation_fixture`,
// widened to expose the internal ids the state-family child rows reference.
// ---------------------------------------------------------------------------

struct Fixture {
    conversation_id: Uuid,
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
    actor_public_key: Vec<u8>,
    participant_period_id: Uuid,
    leaf_period_id: Uuid,
    creation_transition_id: Uuid,
    creation_entry_id: Uuid,
    group_id: Vec<u8>,
    group_context_hash: Vec<u8>,
    confirmation_tag: Vec<u8>,
    accepted_at: DateTime<Utc>,
}

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
    let mut v = Uuid::new_v4().as_bytes().to_vec();
    v.extend_from_slice(Uuid::new_v4().as_bytes());
    v
}

async fn clock_now(pool: &PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .expect("sample trusted database clock")
}

/// Seed a principal + device + device key and return `(device_id, key_id,
/// public_key)`. Each identity is fresh so the not-truncated test DB stays
/// independent between runs.
async fn seed_device(pool: &PgPool, user_did: &str, name: &str) -> (Uuid, String, Vec<u8>) {
    let device_id = Uuid::new_v4();
    let public_key = random_ref();
    let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&public_key)
        .fetch_one(pool)
        .await
        .expect("derive key id");
    let now = clock_now(pool).await;
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,$3,'active',$4,1,chat.protocol_capabilities(),$5,$5)",
    )
    .bind(user_did)
    .bind(device_id)
    .bind(name)
    // The device's own key id is a canonical base64url-sha256 (43 chars) and is
    // unique per device, so it is a valid, collision-free dpop_jkt fixture value.
    .bind(&key_id)
    .bind(now)
    .execute(pool)
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
    .execute(pool)
    .await
    .expect("insert device key");
    (device_id, key_id, public_key)
}

async fn seed_principal(pool: &PgPool, user_did: &str) {
    let now = clock_now(pool).await;
    sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2)")
        .bind(user_did)
        .bind(now)
        .execute(pool)
        .await
        .expect("insert principal");
}

/// Seed one available KeyPackage owned by `(owner_did, owner_device_id,
/// owner_key_id)`, returning its unique 32-byte ref and its `not_after`.
async fn seed_key_package(
    pool: &PgPool,
    owner_did: &str,
    owner_device_id: Uuid,
    owner_key_id: &str,
) -> (Vec<u8>, DateTime<Utc>) {
    let key_package_ref = random_ref();
    let wrapper = random_ref();
    let init_key = random_ref();
    let now = clock_now(pool).await;
    let not_before = now - Duration::seconds(60);
    let not_after = now + Duration::seconds(3600);
    sqlx::query(
        r#"
        INSERT INTO chat.key_packages(
            key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,owner_device_id,
            owner_key_id,owner_auth_generation,not_before,not_after,status,created_at
        ) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,'available',$10)
        "#,
    )
    .bind(&key_package_ref)
    .bind(&wrapper)
    .bind(Sha256::digest(&wrapper).to_vec())
    .bind(&init_key)
    .bind(owner_did)
    .bind(owner_device_id)
    .bind(owner_key_id)
    .bind(not_before)
    .bind(not_after)
    .bind(now)
    .execute(pool)
    .await
    .expect("insert key package");
    (key_package_ref, not_after)
}

async fn seed_fixture(pool: &PgPool) -> Fixture {
    let actor_did = random_plc_did();
    seed_principal(pool, &actor_did).await;
    let (actor_device_id, actor_key_id, actor_public_key) =
        seed_device(pool, &actor_did, "creator").await;

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
    let accepted_at = clock_now(pool).await;

    let mut tx = pool.begin().await.expect("begin creation fixture");
    sqlx::query(
        "INSERT INTO chat.conversations(conversation_id,kind,lifecycle,current_generation,current_state_version,next_entry_seq,created_at) VALUES($1,'group','active',0,0,2,$2)",
    )
    .bind(conversation_id)
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert conversation");
    sqlx::query(
        "INSERT INTO chat.generations(conversation_id,generation,group_id,lifecycle,genesis_group_info_bytes,genesis_group_info_sha256,current_state_version,activated_seq,activated_at) VALUES($1,0,$2,'active',$3,$4,0,1,$5)",
    )
    .bind(conversation_id)
    .bind(&group_id)
    .bind(&group_info)
    .bind(Sha256::digest(&group_info).to_vec())
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert generation");
    sqlx::query(
        r#"
        INSERT INTO chat.transitions(
            transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,
            actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,
            unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,
            next_generation,next_state_version,metadata_snapshot_id,entry_seq,accepted_at
        ) VALUES($1,$2,'creation',$3,$4,$5,1,'admin','active',$6,$7,$8,$9,$10,0,0,$11,1,$12)
        "#,
    )
    .bind(creation_transition_id)
    .bind(conversation_id)
    .bind(&actor_did)
    .bind(actor_device_id)
    .bind(&actor_key_id)
    .bind(&signed_request)
    .bind(&unsigned_projection)
    .bind(&signing_transcript)
    .bind(&request_digest)
    .bind(&signature)
    .bind(metadata_snapshot_id)
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert creation transition");
    sqlx::query(
        r#"
        INSERT INTO chat.generation_states(
            conversation_id,generation,state_version,group_id,epoch,group_context_hash,
            confirmation_tag,lifecycle,state_kind,producing_transition_id,
            public_snapshot_bytes,snapshot_sha256,tree_summary_bytes,tree_summary_sha256,
            leaf_count,created_at
        ) VALUES($1,0,0,$2,0,$3,$4,'active','creation',$5,$6,$7,$8,$9,1,$10)
        "#,
    )
    .bind(conversation_id)
    .bind(&group_id)
    .bind(&group_context_hash)
    .bind(&confirmation_tag)
    .bind(creation_transition_id)
    .bind(&snapshot)
    .bind(Sha256::digest(&snapshot).to_vec())
    .bind(&tree_summary)
    .bind(Sha256::digest(&tree_summary).to_vec())
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert creation state");
    sqlx::query(
        r#"
        INSERT INTO chat.participants(
            participant_period_id,conversation_id,user_did,status,role,role_transition_id,
            role_changed_at,created_by_did,created_by_device_id,current_membership,created_at
        ) VALUES($1,$2,$3,'active','admin',$4,$5,$3,$6,true,$5)
        "#,
    )
    .bind(participant_period_id)
    .bind(conversation_id)
    .bind(&actor_did)
    .bind(creation_transition_id)
    .bind(accepted_at)
    .bind(actor_device_id)
    .execute(&mut *tx)
    .await
    .expect("insert creator participant");
    sqlx::query(
        r#"
        INSERT INTO chat.member_devices(
            leaf_period_id,participant_period_id,conversation_id,generation,user_did,
            device_id,leaf_index,basic_credential,leaf_signature_key,leaf_key_id,
            leaf_auth_generation,origin,joined_state_version,joined_transition_id,
            joined_seq,active,created_at
        ) VALUES($1,$2,$3,0,$4,$5,0,$6,$7,$8,1,'genesis',0,$9,1,true,$10)
        "#,
    )
    .bind(leaf_period_id)
    .bind(participant_period_id)
    .bind(conversation_id)
    .bind(&actor_did)
    .bind(actor_device_id)
    .bind(&basic_credential)
    .bind(&actor_public_key)
    .bind(&actor_key_id)
    .bind(creation_transition_id)
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert genesis leaf");
    sqlx::query(
        r#"
        INSERT INTO chat.metadata_snapshots(
            metadata_snapshot_id,conversation_id,generation,state_version,group_id,epoch,
            group_context_hash,confirmation_tag,producing_transition_id,origin_transition_id,
            metadata_version,nonce,ciphertext,ciphertext_sha256,ciphertext_size,author_did,
            author_device_id,author_key_id,author_public_key,author_auth_generation,
            author_origin_seq,author_role,author_device_status,created_at
        ) VALUES($1,$2,0,0,$3,0,$4,$5,$6,$6,1,$7,$8,$9,16,$10,$11,$12,$13,1,1,'admin','active',$14)
        "#,
    )
    .bind(metadata_snapshot_id)
    .bind(conversation_id)
    .bind(&group_id)
    .bind(&group_context_hash)
    .bind(&confirmation_tag)
    .bind(creation_transition_id)
    .bind(vec![14_u8; 12])
    .bind(&metadata_ciphertext)
    .bind(Sha256::digest(&metadata_ciphertext).to_vec())
    .bind(&actor_did)
    .bind(actor_device_id)
    .bind(&actor_key_id)
    .bind(&actor_public_key)
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert creation metadata");
    sqlx::query(
        r#"
        INSERT INTO chat.entries(
            conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
            accepted_payload_sha256,signed_request_bytes,request_digest,signature,
            server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,
            actor_key_id,actor_auth_generation,generation,state_version,transition_id,received_at
        ) VALUES($1,1,$2,'blue.catbird.chat.defs#creationEntry',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,0,0,$13,$14)
        "#,
    )
    .bind(conversation_id)
    .bind(creation_entry_id)
    .bind(&accepted_payload)
    .bind(Sha256::digest(&accepted_payload).to_vec())
    .bind(&signed_request)
    .bind(&request_digest)
    .bind(&signature)
    .bind(vec![0_u8])
    .bind(&creation_fingerprint)
    .bind(&actor_did)
    .bind(actor_device_id)
    .bind(&actor_key_id)
    .bind(creation_transition_id)
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert creation entry");
    sqlx::query(
        r#"
        INSERT INTO chat.application_intervals(
            membership_interval_id,conversation_id,generation,recipient_did,
            recipient_device_id,start_seq,opening_kind,opening_transition_id,
            opening_outer_entry_fingerprint,opening_state_version,opening_group_id,
            opening_epoch,opening_group_context_hash,opening_confirmation_tag,
            opening_leaf_period_id,created_at
        ) VALUES($1,$2,0,$3,$4,1,'creation',$1,$5,0,$6,0,$7,$8,$9,$10)
        "#,
    )
    .bind(creation_transition_id)
    .bind(conversation_id)
    .bind(&actor_did)
    .bind(actor_device_id)
    .bind(&creation_fingerprint)
    .bind(&group_id)
    .bind(&group_context_hash)
    .bind(&confirmation_tag)
    .bind(leaf_period_id)
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert creation application interval");
    tx.commit().await.expect("commit creation fixture");

    Fixture {
        conversation_id,
        actor_did,
        actor_device_id,
        actor_key_id,
        actor_public_key,
        participant_period_id,
        leaf_period_id,
        creation_transition_id,
        creation_entry_id,
        group_id,
        group_context_hash,
        confirmation_tag,
        accepted_at,
    }
}

fn conflict(result: Result<(), TransitionRepositoryError>) {
    match result {
        Err(TransitionRepositoryError::CompareAndSetConflict) => {}
        other => panic!("expected CompareAndSetConflict, got {other:?}"),
    }
}

// ===========================================================================
// Family 1 — participants.
// ===========================================================================

#[tokio::test]
async fn participant_insert_accept_terminalize_are_faithful_and_cas_guarded() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;

    let invited_did = random_plc_did();
    seed_principal(&pool, &invited_did).await;

    let period_id = Uuid::new_v4();
    let now = clock_now(&pool).await;
    let period = NewParticipantPeriod {
        participant_period_id: period_id,
        conversation_id: fixture.conversation_id,
        user_did: invited_did.clone(),
        status: ParticipantStatus::Pending,
        role: ParticipantRole::Member,
        role_transition_id: fixture.creation_transition_id,
        role_changed_at: fixture.accepted_at,
        created_by_did: fixture.actor_did.clone(),
        created_by_device_id: fixture.actor_device_id,
        invitation: Some(ParticipantInvitation {
            invitation_transition_id: fixture.creation_transition_id,
            invitation_entry_id: fixture.creation_entry_id,
            invited_at: now,
        }),
        acceptance: None,
        created_at: fixture.accepted_at,
    };

    let mut tx = pool.begin().await.unwrap();
    insert_participant_period(&mut tx, &period)
        .await
        .expect("insert pending participant");

    // Insert persisted every column (read-your-writes within the transaction).
    let row: (String, String, String, Uuid, String, Uuid, Uuid, Option<Uuid>, bool) =
        sqlx::query_as(
            "SELECT user_did,status,role,role_transition_id,created_by_did,invitation_transition_id,invitation_entry_id,acceptance_transition_id,current_membership \
             FROM chat.participants WHERE participant_period_id=$1",
        )
        .bind(period_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(row.0, invited_did);
    assert_eq!(row.1, "pending");
    assert_eq!(row.2, "member");
    assert_eq!(row.3, fixture.creation_transition_id);
    assert_eq!(row.4, fixture.actor_did);
    assert_eq!(row.5, fixture.creation_transition_id);
    assert_eq!(row.6, fixture.creation_entry_id);
    assert_eq!(row.7, None);
    assert!(row.8);

    // CAS pending -> active with acceptance provenance.
    let accept_cas = ParticipantAcceptanceCas {
        participant_period_id: period_id,
        conversation_id: fixture.conversation_id,
        user_did: invited_did.clone(),
        acceptance: ParticipantAcceptance {
            acceptance_transition_id: fixture.creation_transition_id,
            acceptance_entry_id: fixture.creation_entry_id,
            accepted_at: now,
        },
    };
    cas_participant_pending_to_active(&mut tx, &accept_cas)
        .await
        .expect("promote pending to active");
    let (status, acc_tid): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT status,acceptance_transition_id FROM chat.participants WHERE participant_period_id=$1",
    )
    .bind(period_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(status, "active");
    assert_eq!(acc_tid, Some(fixture.creation_transition_id));

    // Repeat acceptance CAS drifts (row is no longer pending) -> conflict.
    conflict(cas_participant_pending_to_active(&mut tx, &accept_cas).await);

    // Terminalize the current period.
    let termination = ParticipantTerminalization {
        participant_period_id: period_id,
        removing_transition_id: fixture.creation_transition_id,
        removing_seq: 1,
        removed_at: now,
    };
    terminalize_participant_period(&mut tx, &termination)
        .await
        .expect("terminalize current period");
    let (current, rem_seq): (bool, Option<i64>) = sqlx::query_as(
        "SELECT current_membership,removing_seq FROM chat.participants WHERE participant_period_id=$1",
    )
    .bind(period_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert!(!current);
    assert_eq!(rem_seq, Some(1));

    // Second terminalize misses (no longer current) -> conflict.
    conflict(terminalize_participant_period(&mut tx, &termination).await);
    tx.rollback().await.unwrap();

    // DB constraint cross-check: two CURRENT periods for the same
    // (conversation, user) violate participants_one_current_uq (immediate).
    let mut tx = pool.begin().await.unwrap();
    insert_participant_period(&mut tx, &period)
        .await
        .expect("first current period");
    let dup = NewParticipantPeriod {
        participant_period_id: Uuid::new_v4(),
        ..period.clone()
    };
    assert!(
        matches!(
            insert_participant_period(&mut tx, &dup).await,
            Err(TransitionRepositoryError::Database(_))
        ),
        "second current period must violate the one-current partial unique index"
    );
    tx.rollback().await.unwrap();
}

// ===========================================================================
// Family 2 — member_devices.
// ===========================================================================

#[tokio::test]
async fn leaf_insert_and_close_are_faithful_and_cas_guarded() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;

    // A second genesis-origin device for the same actor/participant.
    let (device_id, key_id, public_key) = seed_device(&pool, &fixture.actor_did, "second").await;
    let credential = format!("{}#{}", fixture.actor_did, device_id).into_bytes();
    let leaf_period_id = Uuid::new_v4();
    let now = clock_now(&pool).await;

    let leaf = NewLeafPeriod {
        leaf_period_id,
        participant_period_id: fixture.participant_period_id,
        conversation_id: fixture.conversation_id,
        generation: 0,
        user_did: fixture.actor_did.clone(),
        device_id,
        leaf_index: 1,
        basic_credential: credential.clone(),
        leaf_signature_key: public_key.clone(),
        leaf_key_id: key_id.clone(),
        leaf_auth_generation: 1,
        origin: LeafOrigin::Genesis,
        joined_state_version: 0,
        joined_transition_id: fixture.creation_transition_id,
        joined_seq: 1,
        created_at: fixture.accepted_at,
    };

    let mut tx = pool.begin().await.unwrap();
    insert_leaf_period(&mut tx, &leaf)
        .await
        .expect("insert genesis leaf");

    let row: (i64, Vec<u8>, String, String, bool, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT leaf_index,basic_credential,leaf_key_id,origin,active,join_key_package_ref \
         FROM chat.member_devices WHERE leaf_period_id=$1",
    )
    .bind(leaf_period_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(row.0, 1);
    assert_eq!(row.1, credential);
    assert_eq!(row.2, key_id);
    assert_eq!(row.3, "genesis");
    assert!(row.4);
    assert_eq!(row.5, None);

    // Close the leaf period. removed_seq + removed_transition_id carry a deferred
    // provenance FK to chat.entries; only the CAS/column shape is verified here.
    let close = LeafClose {
        leaf_period_id,
        removed_state_version: 1,
        removed_transition_id: fixture.creation_transition_id,
        removed_seq: 1,
        removed_at: now,
    };
    close_leaf_period(&mut tx, &close)
        .await
        .expect("close leaf period");
    let (active, removed_seq): (bool, Option<i64>) = sqlx::query_as(
        "SELECT active,removed_seq FROM chat.member_devices WHERE leaf_period_id=$1",
    )
    .bind(leaf_period_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert!(!active);
    assert_eq!(removed_seq, Some(1));

    // Second close misses (no longer active) -> conflict.
    conflict(close_leaf_period(&mut tx, &close).await);
    tx.rollback().await.unwrap();

    // DB constraint cross-check: two ACTIVE leaves for the same
    // (conversation, user, device) violate member_devices_current_device_uq.
    let mut tx = pool.begin().await.unwrap();
    insert_leaf_period(&mut tx, &leaf)
        .await
        .expect("first active leaf");
    let dup = NewLeafPeriod {
        leaf_period_id: Uuid::new_v4(),
        leaf_index: 2,
        ..leaf.clone()
    };
    assert!(
        matches!(
            insert_leaf_period(&mut tx, &dup).await,
            Err(TransitionRepositoryError::Database(_))
        ),
        "second active leaf for the same device must violate the current-device unique index"
    );
    tx.rollback().await.unwrap();
}

// ===========================================================================
// Family 3 — metadata_snapshots.
// ===========================================================================

#[tokio::test]
async fn metadata_snapshot_inserts_faithfully_and_nonce_reuse_is_typed() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;

    // Nonce reuse maps to the typed variant: duplicate the (committed) creation
    // snapshot's (conversation, generation=0, epoch=0, nonce=[14;12]) with a
    // fresh id. The non-deferred metadata_snapshots_nonce_uq fires at INSERT.
    let reuse_ciphertext = vec![0x77_u8; 16];
    let reuse = NewMetadataSnapshot {
        metadata_snapshot_id: Uuid::new_v4(),
        conversation_id: fixture.conversation_id,
        generation: 0,
        state_version: 0,
        group_id: fixture.group_id.clone(),
        epoch: 0,
        group_context_hash: fixture.group_context_hash.clone(),
        confirmation_tag: fixture.confirmation_tag.clone(),
        producing_transition_id: Uuid::new_v4(),
        origin_transition_id: fixture.creation_transition_id,
        metadata_version: 2,
        nonce: vec![14_u8; 12],
        ciphertext: reuse_ciphertext.clone(),
        ciphertext_sha256: Sha256::digest(&reuse_ciphertext).to_vec(),
        ciphertext_size: 16,
        avatar: None,
        author_did: fixture.actor_did.clone(),
        author_device_id: fixture.actor_device_id,
        author_key_id: fixture.actor_key_id.clone(),
        author_public_key: fixture.actor_public_key.clone(),
        author_auth_generation: 1,
        author_origin_seq: 1,
        author_role: "admin".to_owned(),
        author_device_status: "active".to_owned(),
        created_at: fixture.accepted_at,
    };
    let mut tx = pool.begin().await.unwrap();
    match insert_metadata_snapshot(&mut tx, &reuse).await {
        Err(TransitionRepositoryError::MetadataNonceReuse) => {}
        other => panic!("expected MetadataNonceReuse, got {other:?}"),
    }
    tx.rollback().await.unwrap();

    // Happy path: a distinct-coordinate snapshot (with an avatar binding) writes
    // every column faithfully. The producing/origin transition + generation-state
    // FKs are DEFERRED, so same-transaction read-back + rollback verifies the
    // insert shape without the (E2b-owned) coherent commit graph.
    let snapshot_id = Uuid::new_v4();
    let ciphertext = vec![0x42_u8; 24];
    let avatar_sha = Sha256::digest(vec![0x43_u8; 8]).to_vec();
    let avatar_blob_id = Uuid::new_v4();
    let snapshot = NewMetadataSnapshot {
        metadata_snapshot_id: snapshot_id,
        conversation_id: fixture.conversation_id,
        generation: 0,
        state_version: 1,
        group_id: fixture.group_id.clone(),
        epoch: 1,
        group_context_hash: vec![0x61_u8; 32],
        confirmation_tag: vec![0x62_u8; 32],
        producing_transition_id: Uuid::new_v4(),
        origin_transition_id: fixture.creation_transition_id,
        metadata_version: 2,
        nonce: vec![0x30_u8; 12],
        ciphertext: ciphertext.clone(),
        ciphertext_sha256: Sha256::digest(&ciphertext).to_vec(),
        ciphertext_size: 24,
        avatar: Some(MetadataAvatarBinding {
            avatar_blob_id,
            avatar_ciphertext_sha256: avatar_sha.clone(),
            avatar_ciphertext_size: 64,
            avatar_binding_origin_transition_id: fixture.creation_transition_id,
            avatar_binding_metadata_version: 2,
            avatar_binding_owner_did: fixture.actor_did.clone(),
            avatar_binding_owner_device_id: fixture.actor_device_id,
        }),
        author_did: fixture.actor_did.clone(),
        author_device_id: fixture.actor_device_id,
        author_key_id: fixture.actor_key_id.clone(),
        author_public_key: fixture.actor_public_key.clone(),
        author_auth_generation: 1,
        author_origin_seq: 1,
        author_role: "admin".to_owned(),
        author_device_status: "active".to_owned(),
        created_at: fixture.accepted_at,
    };
    let mut tx = pool.begin().await.unwrap();
    insert_metadata_snapshot(&mut tx, &snapshot)
        .await
        .expect("insert metadata snapshot with avatar");
    let (mv, size, nonce, back, blob, purpose): (
        i64,
        i64,
        Vec<u8>,
        Vec<u8>,
        Option<Uuid>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT metadata_version,ciphertext_size,nonce,ciphertext_sha256,avatar_blob_id,avatar_purpose FROM chat.metadata_snapshots WHERE metadata_snapshot_id=$1",
    )
    .bind(snapshot_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(mv, 2);
    assert_eq!(size, 24);
    assert_eq!(nonce, vec![0x30_u8; 12]);
    assert_eq!(back, Sha256::digest(&ciphertext).to_vec());
    assert_eq!(blob, Some(avatar_blob_id));
    assert_eq!(purpose.as_deref(), Some("metadata"));
    tx.rollback().await.unwrap();
}

// ===========================================================================
// Family 7 — coordinate spine (generation_states + transitions).
// ===========================================================================

#[tokio::test]
async fn transition_and_generation_state_spine_rows_persist_faithfully() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;

    let transition_id = Uuid::new_v4();
    let transcript = vec![0x51_u8; 16];
    let now = clock_now(&pool).await;
    let transition = NewTransition {
        transition_id,
        conversation_id: fixture.conversation_id,
        kind: TransitionKind::Commit,
        actor_did: fixture.actor_did.clone(),
        actor_device_id: fixture.actor_device_id,
        actor_key_id: fixture.actor_key_id.clone(),
        actor_auth_generation: 1,
        actor_role: TransitionActorRole::Admin,
        actor_device_status: "active".to_owned(),
        signed_request_bytes: vec![0x52_u8; 16],
        unsigned_projection_bytes: vec![0x53_u8; 16],
        signing_transcript_bytes: transcript.clone(),
        request_digest: Sha256::digest(&transcript).to_vec(),
        signature: vec![0x54_u8; 64],
        coordinates: TransitionCoordinates {
            prior: Some((0, 0)),
            next: Some((0, 1)),
            retired: None,
            successor: None,
        },
        reset_request_id: None,
        close_transition_id: None,
        metadata_snapshot_id: None,
        entry_seq: 2,
        accepted_at: now,
    };
    let generation_state = NewGenerationState {
        conversation_id: fixture.conversation_id,
        generation: 0,
        state_version: 1,
        group_id: fixture.group_id.clone(),
        epoch: 1,
        group_context_hash: vec![0x55_u8; 32],
        confirmation_tag: vec![0x56_u8; 32],
        lifecycle: GenerationStateLifecycle::Active,
        state_kind: GenerationStateKind::Commit,
        producing_transition_id: transition_id,
        public_snapshot_bytes: vec![0x57_u8; 32],
        snapshot_sha256: Sha256::digest(vec![0x57_u8; 32]).to_vec(),
        tree_summary_bytes: vec![0x58_u8; 32],
        tree_summary_sha256: Sha256::digest(vec![0x58_u8; 32]).to_vec(),
        leaf_count: 1,
        created_at: now,
    };

    let mut tx = pool.begin().await.unwrap();
    insert_transition_row(&mut tx, &transition)
        .await
        .expect("insert transition");
    insert_generation_state_row(&mut tx, &generation_state)
        .await
        .expect("insert generation state");

    let (kind, next_gen, next_sv, entry_seq): (String, Option<i64>, Option<i64>, i64) =
        sqlx::query_as(
            "SELECT kind,next_generation,next_state_version,entry_seq FROM chat.transitions WHERE transition_id=$1",
        )
        .bind(transition_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(kind, "commit");
    assert_eq!(next_gen, Some(0));
    assert_eq!(next_sv, Some(1));
    assert_eq!(entry_seq, 2);

    let (state_kind, gch_back): (String, Vec<u8>) = sqlx::query_as(
        "SELECT state_kind,group_context_hash FROM chat.generation_states WHERE conversation_id=$1 AND generation=0 AND state_version=1",
    )
    .bind(fixture.conversation_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(state_kind, "commit");
    assert_eq!(gch_back, vec![0x55_u8; 32]);

    // DB constraint cross-check: a duplicate transition_id violates the
    // transitions primary key (immediate).
    assert!(
        matches!(
            insert_transition_row(&mut tx, &transition).await,
            Err(TransitionRepositoryError::Database(_))
        ),
        "duplicate transition_id must violate the transitions primary key"
    );
    tx.rollback().await.unwrap();
}

// ===========================================================================
// Family 4a — reset_requests.
// ===========================================================================

#[tokio::test]
async fn reset_request_insert_and_terminalize_are_cas_guarded() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;

    let reset_request_id = Uuid::new_v4();
    let received_at = clock_now(&pool).await;
    let expires_at = received_at + Duration::hours(24);
    let transcript = vec![0xa1_u8; 16];
    let request = NewResetRequest {
        reset_request_id,
        conversation_id: fixture.conversation_id,
        requester_did: fixture.actor_did.clone(),
        requester_device_id: fixture.actor_device_id,
        requester_key_id: fixture.actor_key_id.clone(),
        requester_auth_generation: 1,
        prior_generation: 0,
        prior_state_version: 0,
        prior_group_id: fixture.group_id.clone(),
        prior_epoch: 0,
        prior_group_context_hash: fixture.group_context_hash.clone(),
        prior_confirmation_tag: fixture.confirmation_tag.clone(),
        reason: ResetReason::EpochDivergence,
        signed_request_bytes: vec![0xa2_u8; 16],
        signing_transcript_bytes: transcript.clone(),
        request_digest: Sha256::digest(&transcript).to_vec(),
        signature: vec![0xa3_u8; 64],
        received_at,
        expires_at,
    };
    let mut tx = pool.begin().await.unwrap();
    insert_reset_request(&mut tx, &request)
        .await
        .expect("insert reset request");
    // Full-column read-back of the signed-request/provenance block.
    #[allow(clippy::type_complexity)]
    let row: (
        String,
        String,
        String,
        String,
        i64,
        i64,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) = sqlx::query_as(
        "SELECT status,reason,requester_did,requester_key_id,requester_auth_generation,\
                prior_generation,prior_state_version,signed_request_bytes,\
                signing_transcript_bytes,request_digest,signature \
           FROM chat.reset_requests WHERE reset_request_id=$1",
    )
    .bind(reset_request_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(row.0, "pending");
    assert_eq!(row.1, "epochDivergence");
    assert_eq!(row.2, fixture.actor_did);
    assert_eq!(row.3, fixture.actor_key_id);
    assert_eq!(row.4, 1);
    assert_eq!(row.5, 0);
    assert_eq!(row.6, 0);
    assert_eq!(row.7, request.signed_request_bytes);
    assert_eq!(row.8, request.signing_transcript_bytes);
    assert_eq!(row.9, request.request_digest);
    assert_eq!(row.10, request.signature);

    // Terminalize pending -> consumed with the terminal transition.
    let termination = ResetRequestTermination::Consumed {
        terminal_transition_id: fixture.creation_transition_id,
        terminal_at: received_at,
    };
    terminalize_reset_request(&mut tx, reset_request_id, &termination)
        .await
        .expect("terminalize reset request");
    let (status, tid): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT status,terminal_transition_id FROM chat.reset_requests WHERE reset_request_id=$1",
    )
    .bind(reset_request_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(status, "consumed");
    assert_eq!(tid, Some(fixture.creation_transition_id));

    // Second terminalize misses (no longer pending) -> conflict.
    conflict(terminalize_reset_request(&mut tx, reset_request_id, &termination).await);
    tx.rollback().await.unwrap();

    // DB constraint cross-check: two pending reset requests for the same
    // conversation violate reset_requests_one_pending_uq (immediate).
    let mut tx = pool.begin().await.unwrap();
    insert_reset_request(&mut tx, &request)
        .await
        .expect("first pending reset");
    let dup = NewResetRequest {
        reset_request_id: Uuid::new_v4(),
        ..request.clone()
    };
    assert!(
        matches!(
            insert_reset_request(&mut tx, &dup).await,
            Err(TransitionRepositoryError::Database(_))
        ),
        "second pending reset must violate reset_requests_one_pending_uq"
    );
    tx.rollback().await.unwrap();
}

// ===========================================================================
// Family 4b — leave_requests.
// ===========================================================================

#[tokio::test]
async fn leave_request_insert_and_terminalize_are_cas_guarded() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;

    let leave_request_id = Uuid::new_v4();
    let received_at = clock_now(&pool).await;
    let expires_at = received_at + Duration::hours(24);
    let transcript = vec![0xb1_u8; 16];
    let request = NewLeaveRequest {
        leave_request_id,
        conversation_id: fixture.conversation_id,
        requester_did: fixture.actor_did.clone(),
        requester_device_id: fixture.actor_device_id,
        requester_key_id: fixture.actor_key_id.clone(),
        requester_auth_generation: 1,
        prior_generation: 0,
        prior_state_version: 0,
        prior_group_id: fixture.group_id.clone(),
        prior_epoch: 0,
        prior_group_context_hash: fixture.group_context_hash.clone(),
        prior_confirmation_tag: fixture.confirmation_tag.clone(),
        signed_request_bytes: vec![0xb2_u8; 16],
        signing_transcript_bytes: transcript.clone(),
        request_digest: Sha256::digest(&transcript).to_vec(),
        signature: vec![0xb3_u8; 64],
        received_at,
        expires_at,
    };
    let mut tx = pool.begin().await.unwrap();
    insert_leave_request(&mut tx, &request)
        .await
        .expect("insert leave request");
    // Full-column read-back of the signed-request/provenance block.
    #[allow(clippy::type_complexity)]
    let row: (
        String,
        String,
        String,
        i64,
        i64,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) = sqlx::query_as(
        "SELECT status,requester_did,requester_key_id,requester_auth_generation,\
                prior_generation,prior_state_version,signed_request_bytes,\
                signing_transcript_bytes,request_digest,signature \
           FROM chat.leave_requests WHERE leave_request_id=$1",
    )
    .bind(leave_request_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(row.0, "pending");
    assert_eq!(row.1, fixture.actor_did);
    assert_eq!(row.2, fixture.actor_key_id);
    assert_eq!(row.3, 1);
    assert_eq!(row.4, 0);
    assert_eq!(row.5, 0);
    assert_eq!(row.6, request.signed_request_bytes);
    assert_eq!(row.7, request.signing_transcript_bytes);
    assert_eq!(row.8, request.request_digest);
    assert_eq!(row.9, request.signature);

    // Cancelled binds a terminal request digest + timestamp (no transition).
    let terminal_digest = Sha256::digest(vec![0xb4_u8; 8]).to_vec();
    let termination = LeaveRequestTermination::Cancelled {
        terminal_request_digest: terminal_digest.clone(),
        terminal_at: received_at,
    };
    terminalize_leave_request(&mut tx, leave_request_id, &termination)
        .await
        .expect("cancel leave request");
    let (status, digest, tid): (String, Option<Vec<u8>>, Option<Uuid>) = sqlx::query_as(
        "SELECT status,terminal_request_digest,terminal_transition_id FROM chat.leave_requests WHERE leave_request_id=$1",
    )
    .bind(leave_request_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(status, "cancelled");
    assert_eq!(digest, Some(terminal_digest));
    assert_eq!(tid, None);

    // Second terminalize misses -> conflict.
    conflict(terminalize_leave_request(&mut tx, leave_request_id, &termination).await);
    tx.rollback().await.unwrap();

    // DB constraint cross-check: two pending leave requests for the same
    // (conversation, requester) violate leave_requests_one_pending_uq (immediate).
    let mut tx = pool.begin().await.unwrap();
    insert_leave_request(&mut tx, &request)
        .await
        .expect("first pending leave");
    let dup = NewLeaveRequest {
        leave_request_id: Uuid::new_v4(),
        ..request.clone()
    };
    assert!(
        matches!(
            insert_leave_request(&mut tx, &dup).await,
            Err(TransitionRepositoryError::Database(_))
        ),
        "second pending leave must violate leave_requests_one_pending_uq"
    );
    tx.rollback().await.unwrap();
}

// ===========================================================================
// Family 6 — key_packages status CAS.
// ===========================================================================

#[tokio::test]
async fn key_package_status_cas_is_guarded_and_faithful() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let (key_package_ref, _not_after) = seed_key_package(
        &pool,
        &fixture.actor_did,
        fixture.actor_device_id,
        &fixture.actor_key_id,
    )
    .await;

    let now = clock_now(&pool).await;
    let mut tx = pool.begin().await.unwrap();

    // available -> reserved.
    cas_key_package_status(
        &mut tx,
        &key_package_ref,
        PackageStatus::Available,
        &PackageSuccessor::Reserve,
    )
    .await
    .expect("reserve available package");
    let status: String =
        sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE key_package_ref=$1")
            .bind(&key_package_ref)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(status, "reserved");

    // Reserving again with the wrong expected `from` (available) misses -> conflict.
    conflict(
        cas_key_package_status(
            &mut tx,
            &key_package_ref,
            PackageStatus::Available,
            &PackageSuccessor::Reserve,
        )
        .await,
    );

    // reserved -> consumed with terminal transition + timestamp.
    cas_key_package_status(
        &mut tx,
        &key_package_ref,
        PackageStatus::Reserved,
        &PackageSuccessor::Consume {
            terminal_transition_id: fixture.creation_transition_id,
            terminal_at: now,
        },
    )
    .await
    .expect("consume reserved package");
    let (status, tid): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT status,terminal_transition_id FROM chat.key_packages WHERE key_package_ref=$1",
    )
    .bind(&key_package_ref)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(status, "consumed");
    assert_eq!(tid, Some(fixture.creation_transition_id));
    tx.rollback().await.unwrap();
}

// ===========================================================================
// Family 4c + 5 — leaf_recovery_requests + key_package_reservations.
//
// These reference each other via DEFERRABLE INITIALLY DEFERRED FKs and a
// deferred `enforce_welcome_mapping` constraint trigger that, at COMMIT,
// cross-checks the open request against its reservation, the reserved KeyPackage,
// the requester's live participant/device authority, and the bound generation
// state. Same-transaction read-back + rollback verifies each writer's INSERT
// shape and immediate constraints; the commit-time coherence (and the
// terminalizers' full fulfillment graph: a welcome delivery + keyPackage-origin
// leaf + leafRecovery transition) is the composing executor's responsibility.
// ===========================================================================

#[tokio::test]
async fn recovery_request_and_reservation_insert_shapes_are_faithful() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let (key_package_ref, _not_after) = seed_key_package(
        &pool,
        &fixture.actor_did,
        fixture.actor_device_id,
        &fixture.actor_key_id,
    )
    .await;

    let recovery_request_id = Uuid::new_v4();
    let now = clock_now(&pool).await;
    let expires_at = now + Duration::minutes(5);
    let transcript = vec![0xc1_u8; 16];

    let recovery = NewLeafRecoveryRequest {
        recovery_request_id,
        conversation_id: fixture.conversation_id,
        generation: 0,
        requester_did: fixture.actor_did.clone(),
        requester_device_id: fixture.actor_device_id,
        requester_key_id: fixture.actor_key_id.clone(),
        requester_auth_generation: 1,
        recovery_kind: LeafRecoveryKind::Add,
        source: LeafRecoverySource::RequestLeafRecovery,
        bound_state_version: 0,
        bound_group_id: fixture.group_id.clone(),
        bound_epoch: 0,
        bound_group_context_hash: fixture.group_context_hash.clone(),
        bound_confirmation_tag: fixture.confirmation_tag.clone(),
        reservation_request_id: recovery_request_id,
        signed_request_bytes: vec![0xc2_u8; 16],
        signing_transcript_bytes: transcript.clone(),
        request_digest: Sha256::digest(&transcript).to_vec(),
        signature: vec![0xc3_u8; 64],
        requested_at: now,
        expires_at,
    };
    let reservation = NewReservation {
        recovery_request_id,
        key_package_ref: key_package_ref.clone(),
        conversation_id: fixture.conversation_id,
        generation: 0,
        requester_did: fixture.actor_did.clone(),
        requester_device_id: fixture.actor_device_id,
        requester_key_id: fixture.actor_key_id.clone(),
        requester_auth_generation: 1,
        recipient_did: fixture.actor_did.clone(),
        recipient_device_id: fixture.actor_device_id,
        bound_state_version: 0,
        bound_group_id: fixture.group_id.clone(),
        bound_epoch: 0,
        bound_group_context_hash: fixture.group_context_hash.clone(),
        bound_confirmation_tag: fixture.confirmation_tag.clone(),
        expires_at,
        created_at: now,
    };

    let mut tx = pool.begin().await.unwrap();
    insert_leaf_recovery_request(&mut tx, &recovery)
        .await
        .expect("insert leaf recovery request");
    insert_reservation(&mut tx, &reservation)
        .await
        .expect("insert reservation");

    let (rk, rstatus, res_req): (String, String, Uuid) = sqlx::query_as(
        "SELECT recovery_kind,status,reservation_request_id FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(recovery_request_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(rk, "add");
    assert_eq!(rstatus, "open");
    assert_eq!(res_req, recovery_request_id);

    let (res_status, res_ref, purpose): (String, Vec<u8>, String) = sqlx::query_as(
        "SELECT status,key_package_ref,purpose FROM chat.key_package_reservations WHERE recovery_request_id=$1",
    )
    .bind(recovery_request_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(res_status, "active");
    assert_eq!(res_ref, key_package_ref);
    assert_eq!(purpose, "leafRecovery");

    // Live-row terminalizer happy-paths (the immediate BEFORE-UPDATE lifecycle +
    // immutable-identity triggers allow active->consumed and open->fulfilled; the
    // heavy fulfillment-mapping trigger is commit-deferred and does not fire on
    // rollback). terminal_at is inside (created/requested_at, expires_at).
    let terminal_at = now + Duration::minutes(1);
    terminalize_reservation(
        &mut tx,
        recovery_request_id,
        &ReservationTermination::Consumed {
            consumed_transition_id: fixture.creation_transition_id,
            terminal_at,
        },
    )
    .await
    .expect("consume reservation");
    let (rs, consumed_tid): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT status,consumed_transition_id FROM chat.key_package_reservations WHERE recovery_request_id=$1",
    )
    .bind(recovery_request_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(rs, "consumed");
    assert_eq!(consumed_tid, Some(fixture.creation_transition_id));

    terminalize_leaf_recovery_request(
        &mut tx,
        recovery_request_id,
        &LeafRecoveryTermination::Fulfilled {
            fulfilling_transition_id: fixture.creation_transition_id,
            terminal_at,
        },
    )
    .await
    .expect("fulfill recovery request");
    let (qs, fulfilling_tid): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT status,fulfilling_transition_id FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(recovery_request_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(qs, "fulfilled");
    assert_eq!(fulfilling_tid, Some(fixture.creation_transition_id));

    // Repeat terminalize misses (no longer active/open) -> conflict.
    conflict(
        terminalize_reservation(
            &mut tx,
            recovery_request_id,
            &ReservationTermination::Expired { terminal_at },
        )
        .await,
    );
    conflict(
        terminalize_leaf_recovery_request(
            &mut tx,
            recovery_request_id,
            &LeafRecoveryTermination::Expired { terminal_at },
        )
        .await,
    );
    tx.rollback().await.unwrap();

    // DB constraint cross-check A: two open recovery requests for the same
    // (conversation, generation, requester device) violate
    // leaf_recovery_requests_one_open_uq (immediate).
    let mut tx = pool.begin().await.unwrap();
    insert_leaf_recovery_request(&mut tx, &recovery)
        .await
        .expect("first open recovery request");
    let dup_id = Uuid::new_v4();
    let dup_recovery = NewLeafRecoveryRequest {
        recovery_request_id: dup_id,
        reservation_request_id: dup_id,
        ..recovery.clone()
    };
    assert!(
        matches!(
            insert_leaf_recovery_request(&mut tx, &dup_recovery).await,
            Err(TransitionRepositoryError::Database(_))
        ),
        "second open recovery request must violate leaf_recovery_requests_one_open_uq"
    );
    tx.rollback().await.unwrap();

    // DB constraint cross-check B: two active reservations for the same
    // KeyPackage ref violate key_package_reservations_active_package_uq (immediate).
    let mut tx = pool.begin().await.unwrap();
    insert_reservation(&mut tx, &reservation)
        .await
        .expect("first active reservation");
    let dup_reservation = NewReservation {
        recovery_request_id: Uuid::new_v4(),
        ..reservation.clone()
    };
    assert!(
        matches!(
            insert_reservation(&mut tx, &dup_reservation).await,
            Err(TransitionRepositoryError::Database(_))
        ),
        "second active reservation for the same KeyPackage must violate key_package_reservations_active_package_uq"
    );
    tx.rollback().await.unwrap();
}

/// The reservation + leaf-recovery terminalizers CAS on the active/open
/// pre-state: an id that matches no such row changes nothing and is a typed
/// conflict.
#[tokio::test]
async fn recovery_terminalizers_conflict_on_missing_row() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let missing = Uuid::new_v4();
    let now = clock_now(&pool).await;

    let mut tx = pool.begin().await.unwrap();
    conflict(
        terminalize_reservation(
            &mut tx,
            missing,
            &ReservationTermination::Expired { terminal_at: now },
        )
        .await,
    );
    conflict(
        terminalize_leaf_recovery_request(
            &mut tx,
            missing,
            &LeafRecoveryTermination::Expired { terminal_at: now },
        )
        .await,
    );
    tx.rollback().await.unwrap();
}
