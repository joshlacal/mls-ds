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
//! The repository `delivery` module consumes sealed `WelcomeCasBinding` authority
//! from `state_machine`, so this harness mirrors the production-shaped nested
//! `chat_protocol` module graph used by the executor integration tests. That graph
//! gives the directly included repository sources their real protocol context.
//!
//! Run against the dedicated clean-chat database:
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_transition_repository -- --test-threads=1

#![allow(dead_code)]

mod common;

// `delivery` now consumes the sealed `WelcomeCasBinding` from the state machine.
// Mirror the executor harness's real nested module graph instead of compiling a
// second, context-free copy of the repository source.
#[allow(dead_code)]
#[path = "../src/chat_protocol/cursor.rs"]
mod cursor;
#[allow(dead_code)]
#[path = "../src/chat_protocol/dpop.rs"]
mod dpop;
#[allow(dead_code)]
#[path = "../src/chat_protocol/model.rs"]
mod model;
#[allow(dead_code)]
#[path = "../src/chat_protocol/relationship_policy.rs"]
mod relationship_policy_source;
#[allow(dead_code)]
mod snapshot {
    pub use catbird_server::chat_protocol::snapshot::*;
}
#[allow(dead_code)]
#[path = "../src/chat_protocol/repository/mod.rs"]
mod repository;
#[allow(dead_code)]
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[allow(dead_code)]
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

mod chat_protocol {
    pub mod validation {
        pub use crate::validation::*;
    }
    pub mod transcript {
        pub use crate::transcript::*;
    }
    pub mod snapshot {
        pub use catbird_server::chat_protocol::snapshot::*;
    }
    pub mod wire {
        pub use catbird_server::chat_protocol::wire::*;
    }
    pub mod public_state {
        #![allow(dead_code)]
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/public_state.rs"
        ));
    }
    pub mod dpop {
        pub use crate::dpop::*;
    }
    pub mod relationship_policy {
        pub use crate::relationship_policy_source::*;
    }
    pub mod repository {
        pub mod execution_context {
            pub(crate) struct ExecutionContextHydrationProof;
            pub(crate) struct RevocationBatchHydrationProof;
        }
        pub mod auth {
            pub use crate::repository::auth::*;
        }
        pub mod prelude {
            pub use crate::repository::prelude::*;
        }
        pub mod recovery {
            pub use crate::repository::recovery::*;
        }
        pub mod relationship {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/relationship.rs"
            ));
        }
        pub mod core {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/core.rs"
            ));
        }
        pub mod transition {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/transition.rs"
            ));
        }
        pub mod delivery {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/delivery.rs"
            ));
        }
    }
    pub mod state_machine {
        #![allow(dead_code)]
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/state_machine.rs"
        ));
    }
}

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use repository::transition::{
    cas_key_package_status, cas_participant_active_role, cas_participant_pending_to_active,
    cas_registration_revoke, close_leaf_period, insert_device_revocation,
    insert_generation_state_row, insert_leaf_period, insert_leaf_recovery_request,
    insert_leave_request, insert_metadata_snapshot, insert_participant_period, insert_reservation,
    insert_reset_request, insert_transition_row, terminalize_leaf_recovery_request,
    terminalize_leave_request, terminalize_participant_period, terminalize_reservation,
    terminalize_reset_request, GenerationStateKind, GenerationStateLifecycle, LeafClose,
    LeafOrigin, LeafRecoveryKind, LeafRecoverySource, LeafRecoveryTermination,
    LeaveRequestTermination, MetadataAvatarBinding, NewDeviceRevocation, NewGenerationState,
    NewLeafPeriod, NewLeafRecoveryRequest, NewLeaveRequest, NewMetadataSnapshot,
    NewParticipantPeriod, NewReservation, NewResetRequest, NewTransition, PackageStatus,
    PackageSuccessor, ParticipantAcceptance, ParticipantAcceptanceCas, ParticipantInvitation,
    ParticipantRole, ParticipantRoleCas, ParticipantStatus, ParticipantTerminalization,
    RegistrationRevoke, ReservationTermination, ResetReason, ResetRequestTermination,
    TransitionActorRole, TransitionCoordinates, TransitionKind, TransitionRepositoryError,
};

use repository::delivery::{
    close_application_interval, insert_application_interval, insert_recovery_work_item,
    insert_schedule_terminal_proof, insert_welcome_bundle, insert_welcome_delivery,
    terminalize_recovery_work_item, terminalize_welcome_delivery_for_supersession,
    ApplicationIntervalClose, DeliveryRepositoryError, IntervalCloseKind, IntervalOpeningKind,
    NewApplicationInterval, NewRecoveryWorkItem, NewScheduleTerminalProof, NewWelcomeBundle,
    NewWelcomeDelivery, RecoveryWorkSourceKind, RecoveryWorkTermination, WelcomeDisposition,
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
/// owner_key_id)` **inside the caller's transaction**, returning its unique
/// 32-byte ref and its `not_after`.
///
/// This is deliberately transaction-scoped (executor = `&mut Transaction`, same
/// SQL as the row it seeds): every caller in this file rolls its transaction
/// back, so the seeded `chat.key_packages` row must roll back with it. The prior
/// pool-scoped variant ran on autocommit and therefore committed one
/// `chat.key_packages` row on **every** run against the never-truncated
/// clean-chat database — a permanent per-run leak. Sampling the clock on the
/// same transaction keeps the seed self-contained (no `&PgPool` argument).
async fn seed_key_package_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    owner_did: &str,
    owner_device_id: Uuid,
    owner_key_id: &str,
) -> (Vec<u8>, DateTime<Utc>) {
    let key_package_ref = random_ref();
    let wrapper = random_ref();
    let init_key = random_ref();
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await
        .expect("sample trusted database clock");
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
    .execute(&mut **tx)
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

/// Migration-2 (delivery) analogue of `conflict`: a CAS that changed no row must
/// surface `DeliveryRepositoryError::CompareAndSetConflict`, never a silent
/// success or an opaque database error.
fn delivery_conflict(result: Result<(), DeliveryRepositoryError>) {
    match result {
        Err(DeliveryRepositoryError::CompareAndSetConflict) => {}
        other => panic!("expected DeliveryRepositoryError::CompareAndSetConflict, got {other:?}"),
    }
}

async fn existing_chat_protocol_db() -> PgPool {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must name the existing clean-chat test database");
    common::chat_protocol::validate_chat_protocol_database_url(Some(&database_url))
        .expect("unsafe TEST_DATABASE_URL for transition repository test");
    PgPool::connect(&database_url)
        .await
        .expect("connect to existing clean-chat test database")
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

/// Focused H2-pre repository proof. This test intentionally uses the
/// already-provisioned schema connector so the task's no-migration safety gate
/// is independent from the canonical migration-aware repository suite above.
#[tokio::test]
async fn participant_active_role_cas_is_exact_and_preserves_every_other_column() {
    let pool = existing_chat_protocol_db().await;
    let fixture = seed_fixture(&pool).await;
    let invited_did = random_plc_did();
    let pending_did = random_plc_did();
    seed_principal(&pool, &invited_did).await;
    seed_principal(&pool, &pending_did).await;

    let now = clock_now(&pool).await;
    let active_period_id = Uuid::new_v4();
    let active = NewParticipantPeriod {
        participant_period_id: active_period_id,
        conversation_id: fixture.conversation_id,
        user_did: invited_did.clone(),
        status: ParticipantStatus::Active,
        role: ParticipantRole::Member,
        role_transition_id: fixture.creation_transition_id,
        role_changed_at: fixture.accepted_at,
        created_by_did: fixture.actor_did.clone(),
        created_by_device_id: fixture.actor_device_id,
        invitation: Some(ParticipantInvitation {
            invitation_transition_id: fixture.creation_transition_id,
            invitation_entry_id: fixture.creation_entry_id,
            invited_at: fixture.accepted_at,
        }),
        acceptance: Some(ParticipantAcceptance {
            acceptance_transition_id: fixture.creation_transition_id,
            acceptance_entry_id: fixture.creation_entry_id,
            accepted_at: fixture.accepted_at,
        }),
        created_at: fixture.accepted_at,
    };
    let pending = NewParticipantPeriod {
        participant_period_id: Uuid::new_v4(),
        user_did: pending_did.clone(),
        status: ParticipantStatus::Pending,
        acceptance: None,
        ..active.clone()
    };
    let role_transition_id = Uuid::new_v4();
    let changed_at = now + Duration::milliseconds(1);
    let role_cas = ParticipantRoleCas {
        conversation_id: fixture.conversation_id,
        user_did: invited_did.clone(),
        expected_role: ParticipantRole::Member,
        successor_role: ParticipantRole::Admin,
        role_transition_id,
        role_changed_at: changed_at,
    };

    let mut tx = pool.begin().await.unwrap();
    insert_participant_period(&mut tx, &active)
        .await
        .expect("insert active participant");
    insert_participant_period(&mut tx, &pending)
        .await
        .expect("insert pending status probe");

    let mut wrong_status = role_cas.clone();
    wrong_status.user_did = pending_did;
    conflict(cas_participant_active_role(&mut tx, &wrong_status).await);

    let immutable_before: serde_json::Value = sqlx::query_scalar(
        "SELECT to_jsonb(p) - ARRAY['role','role_transition_id','role_changed_at'] \
         FROM chat.participants p WHERE participant_period_id=$1",
    )
    .bind(active_period_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    cas_participant_active_role(&mut tx, &role_cas)
        .await
        .expect("member -> admin role CAS");
    let (role, producer, persisted_changed_at): (String, Uuid, DateTime<Utc>) = sqlx::query_as(
        "SELECT role,role_transition_id,role_changed_at \
             FROM chat.participants WHERE participant_period_id=$1",
    )
    .bind(active_period_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(role, "admin");
    assert_eq!(producer, role_transition_id);
    assert_eq!(persisted_changed_at, changed_at);
    let immutable_after: serde_json::Value = sqlx::query_scalar(
        "SELECT to_jsonb(p) - ARRAY['role','role_transition_id','role_changed_at'] \
         FROM chat.participants p WHERE participant_period_id=$1",
    )
    .bind(active_period_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(
        immutable_after, immutable_before,
        "role CAS changed a non-role participant column"
    );

    conflict(cas_participant_active_role(&mut tx, &role_cas).await);
    let mut wrong_principal = role_cas.clone();
    wrong_principal.user_did = random_plc_did();
    conflict(cas_participant_active_role(&mut tx, &wrong_principal).await);

    terminalize_participant_period(
        &mut tx,
        &ParticipantTerminalization {
            participant_period_id: active_period_id,
            removing_transition_id: fixture.creation_transition_id,
            removing_seq: 1,
            removed_at: changed_at + Duration::milliseconds(1),
        },
    )
    .await
    .expect("terminalize active participant");
    let reverse = ParticipantRoleCas {
        expected_role: ParticipantRole::Admin,
        successor_role: ParticipantRole::Member,
        ..role_cas
    };
    conflict(cas_participant_active_role(&mut tx, &reverse).await);
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

    let now = clock_now(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    // Seed the KeyPackage inside the (rolled-back) transaction so no committed
    // row leaks; the CAS reads it via read-your-writes in the same tx.
    let (key_package_ref, _not_after) = seed_key_package_tx(
        &mut tx,
        &fixture.actor_did,
        fixture.actor_device_id,
        &fixture.actor_key_id,
    )
    .await;

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
    // The reservation FKs the reserved KeyPackage. Each transaction that inserts
    // one seeds its own tx-scoped KeyPackage (rolled back with the tx) and binds
    // the reservation to that row's ref, so no committed KeyPackage row leaks.
    let make_reservation = |key_package_ref: Vec<u8>| NewReservation {
        recovery_request_id,
        key_package_ref,
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
    let (key_package_ref, _not_after) = seed_key_package_tx(
        &mut tx,
        &fixture.actor_did,
        fixture.actor_device_id,
        &fixture.actor_key_id,
    )
    .await;
    let reservation = make_reservation(key_package_ref.clone());
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
    let (key_package_ref, _not_after) = seed_key_package_tx(
        &mut tx,
        &fixture.actor_did,
        fixture.actor_device_id,
        &fixture.actor_key_id,
    )
    .await;
    let reservation = make_reservation(key_package_ref);
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

// ===========================================================================
// Migration-2 Family A — chat.application_intervals.
//
// These extend the transition-repository harness to the delivery migration's
// per-device exact-visibility interval writers. As with the migration-1
// families, each writer is exercised inside one transaction with same-transaction
// read-back and then ROLLED BACK: this verifies every IMMEDIATE constraint
// (opening/leaf-opening unique indexes, the `membership_interval_id`
// identity/primary key, the opening-context length CHECKs, the all-or-none
// `application_intervals_close_shape_check`, `terminal_seq > start_seq`, and the
// BEFORE-UPDATE immutable-identity + lifecycle-monotonic triggers) while the
// DEFERRED cross-table coherence triggers and provenance FKs (the composer's job)
// fire only at COMMIT.
// ===========================================================================

#[tokio::test]
async fn application_interval_insert_and_close_are_faithful_and_cas_guarded() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let now = clock_now(&pool).await;

    // A fresh opening transition id doubles as the interval identity
    // (application_intervals_id_check: membership_interval_id = opening_transition_id).
    let interval_id = Uuid::new_v4();
    let fingerprint = vec![0x21_u8; 32];
    let opening_group_id = vec![0x22_u8; 32];
    let opening_gch = vec![0x23_u8; 32];
    let opening_ct = vec![0x24_u8; 32];
    let interval = NewApplicationInterval {
        membership_interval_id: interval_id,
        conversation_id: fixture.conversation_id,
        generation: 0,
        recipient_did: fixture.actor_did.clone(),
        recipient_device_id: fixture.actor_device_id,
        start_seq: 2,
        opening_kind: IntervalOpeningKind::Add,
        opening_transition_id: interval_id,
        opening_outer_entry_fingerprint: fingerprint.clone(),
        opening_state_version: 1,
        opening_group_id: opening_group_id.clone(),
        opening_epoch: 1,
        opening_group_context_hash: opening_gch.clone(),
        opening_confirmation_tag: opening_ct.clone(),
        opening_leaf_period_id: fixture.leaf_period_id,
        created_at: now,
    };

    let mut tx = pool.begin().await.unwrap();
    insert_application_interval(&mut tx, &interval)
        .await
        .expect("insert open application interval");

    // Full-column read-back of the open row (BYTEA byte-equality; all closing
    // columns NULL).
    #[allow(clippy::type_complexity)]
    let row: (
        String,
        i64,
        String,
        Vec<u8>,
        Vec<u8>,
        i64,
        Option<i64>,
        Option<String>,
        Option<Vec<u8>>,
        Option<DateTime<Utc>>,
    ) = sqlx::query_as(
        "SELECT opening_kind,start_seq,recipient_did,opening_outer_entry_fingerprint,\
                opening_group_id,opening_epoch,terminal_seq,closing_kind,\
                closing_outer_entry_fingerprint,removed_at \
           FROM chat.application_intervals WHERE membership_interval_id=$1",
    )
    .bind(interval_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(row.0, "add");
    assert_eq!(row.1, 2);
    assert_eq!(row.2, fixture.actor_did);
    assert_eq!(row.3, fingerprint);
    assert_eq!(row.4, opening_group_id);
    assert_eq!(row.5, 1);
    assert_eq!(row.6, None);
    assert_eq!(row.7, None);
    assert_eq!(row.8, None);
    assert_eq!(row.9, None);

    // CAS close: open -> finite, writing all seven closing columns at once.
    // terminal_seq > start_seq (strict gap). Closing entry/transition provenance
    // FKs are DEFERRED, so only the CAS/column shape is verified here.
    let closing_fingerprint = vec![0x25_u8; 32];
    let close = ApplicationIntervalClose {
        membership_interval_id: interval_id,
        terminal_seq: 5,
        closing_state_version: 2,
        closing_transition_id: fixture.creation_transition_id,
        closing_outer_entry_fingerprint: closing_fingerprint.clone(),
        closing_kind: IntervalCloseKind::Remove,
        closing_leaf_period_id: fixture.leaf_period_id,
        removed_at: now,
    };
    close_application_interval(&mut tx, &close)
        .await
        .expect("close open application interval");
    let (terminal_seq, closing_kind, closing_sv, closing_fp, removed_at): (
        Option<i64>,
        Option<String>,
        Option<i64>,
        Option<Vec<u8>>,
        Option<DateTime<Utc>>,
    ) = sqlx::query_as(
        "SELECT terminal_seq,closing_kind,closing_state_version,closing_outer_entry_fingerprint,removed_at \
           FROM chat.application_intervals WHERE membership_interval_id=$1",
    )
    .bind(interval_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(terminal_seq, Some(5));
    assert_eq!(closing_kind.as_deref(), Some("remove"));
    assert_eq!(closing_sv, Some(2));
    assert_eq!(closing_fp, Some(closing_fingerprint));
    assert!(removed_at.is_some());

    // Second close misses (interval no longer open) -> conflict; a closed interval
    // is immutable/terminal.
    delivery_conflict(close_application_interval(&mut tx, &close).await);

    // CAS-drift: closing an interval id that matches no open row -> conflict.
    let drift = ApplicationIntervalClose {
        membership_interval_id: Uuid::new_v4(),
        ..close.clone()
    };
    delivery_conflict(close_application_interval(&mut tx, &drift).await);
    tx.rollback().await.unwrap();

    // DB constraint cross-check A: a duplicate opening (same membership_interval_id
    // / opening_transition_id) is rejected by the identity primary key (the single
    // opening guard; opening_uq / leaf_opening_uq subsume it since the id equals
    // the opening transition).
    let mut tx = pool.begin().await.unwrap();
    insert_application_interval(&mut tx, &interval)
        .await
        .expect("first open interval");
    assert!(
        matches!(
            insert_application_interval(&mut tx, &interval).await,
            Err(DeliveryRepositoryError::Database(_))
        ),
        "a duplicate opening must violate the interval identity primary key"
    );
    tx.rollback().await.unwrap();

    // DB constraint cross-check B: the all-or-none close shape CHECK rejects a
    // partial close (terminal_seq set while the other closing columns stay NULL).
    // The writer cannot emit a partial close, so this drives the DDL directly.
    let mut tx = pool.begin().await.unwrap();
    insert_application_interval(&mut tx, &interval)
        .await
        .expect("open interval for partial-close probe");
    let partial = sqlx::query(
        "UPDATE chat.application_intervals SET terminal_seq=5 WHERE membership_interval_id=$1",
    )
    .bind(interval_id)
    .execute(&mut *tx)
    .await;
    assert!(
        partial.is_err(),
        "a partial close (terminal_seq without the rest) must violate application_intervals_close_shape_check"
    );
    tx.rollback().await.unwrap();

    // DB constraint cross-check C: terminal_seq must be strictly greater than
    // start_seq. A close with terminal_seq == start_seq is rejected by the DDL and
    // surfaces (via the writer) as a database error, never a CAS success.
    let mut tx = pool.begin().await.unwrap();
    insert_application_interval(&mut tx, &interval)
        .await
        .expect("open interval for strict-gap probe");
    let not_strict = ApplicationIntervalClose {
        terminal_seq: 2, // == start_seq
        ..close.clone()
    };
    assert!(
        matches!(
            close_application_interval(&mut tx, &not_strict).await,
            Err(DeliveryRepositoryError::Database(_))
        ),
        "terminal_seq == start_seq must violate application_intervals_close_shape_check"
    );
    tx.rollback().await.unwrap();

    // DB constraint cross-check D: the five-field opening binding is immutable —
    // an UPDATE of an opening column after insert is rejected by the
    // application_intervals_identity_immutable trigger (opening columns are not in
    // its mutable set).
    let mut tx = pool.begin().await.unwrap();
    insert_application_interval(&mut tx, &interval)
        .await
        .expect("open interval for immutability probe");
    let mutate_opening = sqlx::query(
        "UPDATE chat.application_intervals SET opening_kind='reset' WHERE membership_interval_id=$1",
    )
    .bind(interval_id)
    .execute(&mut *tx)
    .await;
    assert!(
        mutate_opening.is_err(),
        "mutating an opening column must be rejected by the immutable-identity trigger"
    );
    tx.rollback().await.unwrap();
}

// ===========================================================================
// Migration-2 Family B — chat.application_schedule_terminal_proofs.
// ===========================================================================

#[tokio::test]
async fn schedule_terminal_proof_insert_is_faithful_and_pk_guarded() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let now = clock_now(&pool).await;

    // terminal_seq references the committed creation entry at seq 1 (IMMEDIATE
    // entry_fk); transition_id references the creation transition (IMMEDIATE
    // transition_fk). The 4-column provenance FK is DEFERRED.
    let fingerprint = vec![0x31_u8; 32];
    let proof = NewScheduleTerminalProof {
        conversation_id: fixture.conversation_id,
        recipient_did: fixture.actor_did.clone(),
        recipient_device_id: fixture.actor_device_id,
        terminal_seq: 1,
        transition_id: fixture.creation_transition_id,
        outer_entry_fingerprint: fingerprint.clone(),
        received_at: now,
    };

    let mut tx = pool.begin().await.unwrap();
    insert_schedule_terminal_proof(&mut tx, &proof)
        .await
        .expect("insert schedule terminal proof");
    let (terminal_seq, transition_id, fp): (i64, Uuid, Vec<u8>) = sqlx::query_as(
        "SELECT terminal_seq,transition_id,outer_entry_fingerprint \
           FROM chat.application_schedule_terminal_proofs \
          WHERE conversation_id=$1 AND recipient_did=$2 AND recipient_device_id=$3",
    )
    .bind(fixture.conversation_id)
    .bind(&fixture.actor_did)
    .bind(fixture.actor_device_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(terminal_seq, 1);
    assert_eq!(transition_id, fixture.creation_transition_id);
    assert_eq!(fp, fingerprint);

    // DB constraint cross-check: a second proof for the same
    // (conversation, recipient device) violates the primary key.
    assert!(
        matches!(
            insert_schedule_terminal_proof(&mut tx, &proof).await,
            Err(DeliveryRepositoryError::Database(_))
        ),
        "a second proof for the same recipient device must violate the primary key"
    );
    tx.rollback().await.unwrap();
}

// ===========================================================================
// Migration-2 Family C — chat.welcome_bundles.
// ===========================================================================

#[tokio::test]
async fn welcome_bundle_insert_is_faithful_and_transition_unique() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let now = clock_now(&pool).await;

    let welcome_id = Uuid::new_v4();
    let wrapper = vec![0x41_u8; 64];
    let bundle = NewWelcomeBundle {
        welcome_id,
        conversation_id: fixture.conversation_id,
        transition_id: fixture.creation_transition_id,
        entry_seq: 1,
        generation: 0,
        state_version: 0,
        group_id: fixture.group_id.clone(),
        epoch: 0,
        group_context_hash: fixture.group_context_hash.clone(),
        confirmation_tag: fixture.confirmation_tag.clone(),
        wrapper_bytes: wrapper.clone(),
        wrapper_sha256: Sha256::digest(&wrapper).to_vec(),
        created_at: now,
    };

    let mut tx = pool.begin().await.unwrap();
    insert_welcome_bundle(&mut tx, &bundle)
        .await
        .expect("insert welcome bundle");
    let (transition_id, entry_seq, wrapper_back, sha_back): (Uuid, i64, Vec<u8>, Vec<u8>) =
        sqlx::query_as(
            "SELECT transition_id,entry_seq,wrapper_bytes,wrapper_sha256 \
               FROM chat.welcome_bundles WHERE welcome_id=$1",
        )
        .bind(welcome_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(transition_id, fixture.creation_transition_id);
    assert_eq!(entry_seq, 1);
    assert_eq!(wrapper_back, wrapper);
    assert_eq!(sha_back, Sha256::digest(&wrapper).to_vec());

    // DB constraint cross-check: one bundle per Add commit — a second bundle
    // (fresh welcome_id) reusing the same transition_id violates the UNIQUE.
    let dup = NewWelcomeBundle {
        welcome_id: Uuid::new_v4(),
        ..bundle.clone()
    };
    assert!(
        matches!(
            insert_welcome_bundle(&mut tx, &dup).await,
            Err(DeliveryRepositoryError::Database(_))
        ),
        "a second bundle for the same transition_id must violate the UNIQUE"
    );
    tx.rollback().await.unwrap();
}

// ===========================================================================
// Migration-2 Family D + E — chat.welcome_deliveries + chat.welcome_dispositions.
//
// A Welcome delivery's IMMEDIATE FKs require a committed KeyPackage owned by the
// recipient plus a same-transaction leaf-recovery request, reservation, and
// bundle. The terminalizer is the Welcome terminal race: it CAS-flips the pending
// delivery to its terminal status AND inserts the one immutable disposition row in
// one call. The DEFERRED disposition/recovery coherence triggers (the composer's
// job) fire only at COMMIT and are not exercised by these rollback-scoped writers.
// ===========================================================================

/// Seed the committed KeyPackage and same-transaction leaf-recovery request,
/// reservation, and Welcome bundle a delivery's IMMEDIATE FKs require, then return
/// the ids the delivery/disposition writers need. `expires_at` on the delivery
/// must equal the consumed package's `not_after` (composite package-identity FK).
async fn seed_welcome_delivery_prereqs(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    fixture: &Fixture,
    now: DateTime<Utc>,
) -> (Uuid, Uuid, Vec<u8>, DateTime<Utc>) {
    let (key_package_ref, not_after) = seed_key_package_tx(
        tx,
        &fixture.actor_did,
        fixture.actor_device_id,
        &fixture.actor_key_id,
    )
    .await;

    let recovery_request_id = Uuid::new_v4();
    let reservation_expiry = now + Duration::minutes(5);
    let recovery_transcript = vec![0x51_u8; 16];
    let recovery = NewLeafRecoveryRequest {
        recovery_request_id,
        conversation_id: fixture.conversation_id,
        generation: 0,
        requester_did: fixture.actor_did.clone(),
        requester_device_id: fixture.actor_device_id,
        requester_key_id: fixture.actor_key_id.clone(),
        requester_auth_generation: 1,
        recovery_kind: LeafRecoveryKind::Add,
        source: LeafRecoverySource::AcceptConversation,
        bound_state_version: 0,
        bound_group_id: fixture.group_id.clone(),
        bound_epoch: 0,
        bound_group_context_hash: fixture.group_context_hash.clone(),
        bound_confirmation_tag: fixture.confirmation_tag.clone(),
        reservation_request_id: recovery_request_id,
        signed_request_bytes: vec![0x52_u8; 16],
        signing_transcript_bytes: recovery_transcript.clone(),
        request_digest: Sha256::digest(&recovery_transcript).to_vec(),
        signature: vec![0x53_u8; 64],
        requested_at: now,
        expires_at: reservation_expiry,
    };
    insert_leaf_recovery_request(tx, &recovery)
        .await
        .expect("seed leaf recovery request");

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
        expires_at: reservation_expiry,
        created_at: now,
    };
    insert_reservation(tx, &reservation)
        .await
        .expect("seed key package reservation");

    let welcome_id = Uuid::new_v4();
    let wrapper = vec![0x54_u8; 48];
    let bundle = NewWelcomeBundle {
        welcome_id,
        conversation_id: fixture.conversation_id,
        transition_id: fixture.creation_transition_id,
        entry_seq: 1,
        generation: 0,
        state_version: 0,
        group_id: fixture.group_id.clone(),
        epoch: 0,
        group_context_hash: fixture.group_context_hash.clone(),
        confirmation_tag: fixture.confirmation_tag.clone(),
        wrapper_bytes: wrapper.clone(),
        wrapper_sha256: Sha256::digest(&wrapper).to_vec(),
        created_at: now,
    };
    insert_welcome_bundle(tx, &bundle)
        .await
        .expect("seed welcome bundle");

    (welcome_id, recovery_request_id, key_package_ref, not_after)
}

#[tokio::test]
async fn welcome_delivery_insert_and_primary_key_constraint_are_faithful() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let now = clock_now(&pool).await;

    let mut tx = pool.begin().await.unwrap();
    let (welcome_id, recovery_request_id, key_package_ref, not_after) =
        seed_welcome_delivery_prereqs(&mut tx, &fixture, now).await;

    let delivery = NewWelcomeDelivery {
        welcome_id,
        recipient_did: fixture.actor_did.clone(),
        recipient_device_id: fixture.actor_device_id,
        recovery_request_id,
        key_package_ref: key_package_ref.clone(),
        expires_at: not_after,
    };
    insert_welcome_delivery(&mut tx, &delivery)
        .await
        .expect("insert pending welcome delivery");

    // Full-column read-back of the pending delivery (BYTEA byte-equality).
    let (status, ref_back, req_back, terminal_at): (String, Vec<u8>, Uuid, Option<DateTime<Utc>>) =
        sqlx::query_as(
            "SELECT status,key_package_ref,recovery_request_id,terminal_at \
               FROM chat.welcome_deliveries WHERE welcome_id=$1",
        )
        .bind(welcome_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(status, "pending");
    assert_eq!(ref_back, key_package_ref);
    assert_eq!(req_back, recovery_request_id);
    assert_eq!(terminal_at, None);

    tx.rollback().await.unwrap();

    // DB constraint cross-check: one delivery per welcome_id — a second delivery
    // for the same welcome_id violates the primary key (Welcome delivery
    // uniqueness).
    let mut tx = pool.begin().await.unwrap();
    let (welcome_id, recovery_request_id, key_package_ref, not_after) =
        seed_welcome_delivery_prereqs(&mut tx, &fixture, now).await;
    let delivery = NewWelcomeDelivery {
        welcome_id,
        recipient_did: fixture.actor_did.clone(),
        recipient_device_id: fixture.actor_device_id,
        recovery_request_id,
        key_package_ref,
        expires_at: not_after,
    };
    insert_welcome_delivery(&mut tx, &delivery)
        .await
        .expect("first delivery");
    assert!(
        matches!(
            insert_welcome_delivery(&mut tx, &delivery).await,
            Err(DeliveryRepositoryError::Database(_))
        ),
        "a second delivery for the same welcome_id must violate the primary key"
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn welcome_supersession_disposition_persists_exact_exclusive_source_id() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let now = clock_now(&pool).await;

    let mut transition_tx = pool.begin().await.unwrap();
    let (welcome_id, recovery_request_id, key_package_ref, not_after) =
        seed_welcome_delivery_prereqs(&mut transition_tx, &fixture, now).await;
    insert_welcome_delivery(
        &mut transition_tx,
        &NewWelcomeDelivery {
            welcome_id,
            recipient_did: fixture.actor_did.clone(),
            recipient_device_id: fixture.actor_device_id,
            recovery_request_id,
            key_package_ref,
            expires_at: not_after,
        },
    )
    .await
    .expect("insert transition-superseded welcome");
    terminalize_welcome_delivery_for_supersession(
        &mut transition_tx,
        welcome_id,
        &WelcomeDisposition::SupersededByTransition {
            terminal_transition_id: fixture.creation_transition_id,
        },
        now + Duration::minutes(1),
        1,
    )
    .await
    .expect("persist transition supersession source");
    let transition_source: (Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        "SELECT terminal_transition_id,terminal_revocation_id \
           FROM chat.welcome_dispositions WHERE welcome_id=$1",
    )
    .bind(welcome_id)
    .fetch_one(&mut *transition_tx)
    .await
    .expect("read transition supersession source");
    assert_eq!(
        transition_source,
        (Some(fixture.creation_transition_id), None)
    );
    transition_tx.rollback().await.unwrap();

    let mut revocation_tx = pool.begin().await.unwrap();
    let (welcome_id, recovery_request_id, key_package_ref, not_after) =
        seed_welcome_delivery_prereqs(&mut revocation_tx, &fixture, now).await;
    insert_welcome_delivery(
        &mut revocation_tx,
        &NewWelcomeDelivery {
            welcome_id,
            recipient_did: fixture.actor_did.clone(),
            recipient_device_id: fixture.actor_device_id,
            recovery_request_id,
            key_package_ref,
            expires_at: not_after,
        },
    )
    .await
    .expect("insert revocation-superseded welcome");
    let terminal_revocation_id = Uuid::new_v4();
    terminalize_welcome_delivery_for_supersession(
        &mut revocation_tx,
        welcome_id,
        &WelcomeDisposition::SupersededByRevocation {
            terminal_revocation_id,
        },
        now + Duration::minutes(1),
        2,
    )
    .await
    .expect("persist revocation supersession source");
    let revocation_source: (Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        "SELECT terminal_transition_id,terminal_revocation_id \
           FROM chat.welcome_dispositions WHERE welcome_id=$1",
    )
    .bind(welcome_id)
    .fetch_one(&mut *revocation_tx)
    .await
    .expect("read revocation supersession source");
    assert_eq!(revocation_source, (None, Some(terminal_revocation_id)));
    revocation_tx.rollback().await.unwrap();
}

// ===========================================================================
// Migration-2 Family F — chat.recovery_work_items.
// ===========================================================================

#[tokio::test]
async fn recovery_work_item_insert_and_terminalize_are_cas_guarded() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let now = clock_now(&pool).await;

    // The source disposition FK and the (generation, state_version) coordinate FK
    // are DEFERRED, so a pending work item inserts against a fresh source id and
    // the fixture's genesis coordinate without a committed disposition graph.
    let recovery_work_id = Uuid::new_v4();
    let source_id = Uuid::new_v4();
    let item = NewRecoveryWorkItem {
        recovery_work_id,
        conversation_id: fixture.conversation_id,
        recipient_did: fixture.actor_did.clone(),
        recipient_device_id: fixture.actor_device_id,
        source_kind: RecoveryWorkSourceKind::WelcomeExpired,
        source_id,
        generation: 0,
        state_version: 0,
        created_at: now,
    };

    let mut tx = pool.begin().await.unwrap();
    insert_recovery_work_item(&mut tx, &item)
        .await
        .expect("insert pending recovery work item");
    let (source_kind, status, source_back, generation): (String, String, Uuid, i64) =
        sqlx::query_as(
            "SELECT source_kind,status,source_id,generation \
               FROM chat.recovery_work_items WHERE recovery_work_id=$1",
        )
        .bind(recovery_work_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(source_kind, "welcomeExpired");
    assert_eq!(status, "pending");
    assert_eq!(source_back, source_id);
    assert_eq!(generation, 0);

    // Terminalize completed-by-transition (revocation stays NULL). The terminal
    // transition FK is DEFERRED; only the CAS/shape is verified here. terminal_at
    // >= created_at.
    let terminal_at = now + Duration::minutes(1);
    terminalize_recovery_work_item(
        &mut tx,
        recovery_work_id,
        &RecoveryWorkTermination::CompletedByTransition {
            terminal_transition_id: fixture.creation_transition_id,
            terminal_at,
        },
    )
    .await
    .expect("complete recovery work item");
    let (term_status, term_tid, term_rev): (String, Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        "SELECT status,terminal_transition_id,terminal_revocation_id \
           FROM chat.recovery_work_items WHERE recovery_work_id=$1",
    )
    .bind(recovery_work_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(term_status, "completed");
    assert_eq!(term_tid, Some(fixture.creation_transition_id));
    assert_eq!(term_rev, None);

    // Second terminalize misses (no longer pending) -> conflict.
    delivery_conflict(
        terminalize_recovery_work_item(
            &mut tx,
            recovery_work_id,
            &RecoveryWorkTermination::SupersededByRevocation {
                terminal_revocation_id: Uuid::new_v4(),
                terminal_at,
            },
        )
        .await,
    );

    // CAS-drift: terminalizing an id that matches no pending row -> conflict.
    delivery_conflict(
        terminalize_recovery_work_item(
            &mut tx,
            Uuid::new_v4(),
            &RecoveryWorkTermination::SupersededByTransition {
                terminal_transition_id: fixture.creation_transition_id,
                terminal_at,
            },
        )
        .await,
    );
    tx.rollback().await.unwrap();

    // DB constraint cross-check A: the terminal-shape CHECK rejects a wrong
    // status/terminal combination (status='completed' with no terminal columns).
    // The writer cannot emit this shape, so it is driven directly against the DDL.
    let mut tx = pool.begin().await.unwrap();
    let bad_shape = sqlx::query(
        "INSERT INTO chat.recovery_work_items(\
            recovery_work_id,conversation_id,recipient_did,recipient_device_id,\
            source_kind,source_id,generation,state_version,status,created_at) \
         VALUES($1,$2,$3,$4,'welcomeExpired',$5,0,0,'completed',$6)",
    )
    .bind(Uuid::new_v4())
    .bind(fixture.conversation_id)
    .bind(&fixture.actor_did)
    .bind(fixture.actor_device_id)
    .bind(Uuid::new_v4())
    .bind(now)
    .execute(&mut *tx)
    .await;
    assert!(
        bad_shape.is_err(),
        "status='completed' with NULL terminal columns must violate recovery_work_items_terminal_shape_check"
    );
    tx.rollback().await.unwrap();

    // DB constraint cross-check B: one work item per source disposition — a second
    // pending item reusing the same source_id violates recovery_work_items_source_uq.
    let mut tx = pool.begin().await.unwrap();
    insert_recovery_work_item(&mut tx, &item)
        .await
        .expect("first recovery work item");
    let dup = NewRecoveryWorkItem {
        recovery_work_id: Uuid::new_v4(),
        ..item.clone()
    };
    assert!(
        matches!(
            insert_recovery_work_item(&mut tx, &dup).await,
            Err(DeliveryRepositoryError::Database(_))
        ),
        "a second work item for the same source_id must violate recovery_work_items_source_uq"
    );
    tx.rollback().await.unwrap();
}

/// The signed material + identities a device revocation binds. Seeded fresh
/// (in-tx) so the never-truncated clean-chat DB stays independent between runs.
struct RevocationPrereqs {
    revocation_id: Uuid,
    did: String,
    device_id: Uuid,
    key_id: String,
    auth_generation: i64,
    accepted_at: DateTime<Utc>,
    accepted_request_bytes: Vec<u8>,
    signing_transcript_bytes: Vec<u8>,
    request_digest: Vec<u8>,
    signature: Vec<u8>,
}

/// Seed a principal + one active device + its single device key **inside the
/// caller's transaction** (self-revoke: actor == target), and optionally the
/// `revokeDevice` idempotency receipt the `enforce_device_revocation_mapping`
/// COMMIT trigger requires. Everything rolls back with the caller's tx.
async fn seed_revocation_prereqs_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    with_receipt: bool,
) -> RevocationPrereqs {
    let did = random_plc_did();
    let device_id = Uuid::new_v4();
    let public_key = random_ref();
    let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&public_key)
        .fetch_one(&mut **tx)
        .await
        .expect("derive key id");
    let accepted_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await
        .expect("sample clock");
    let created_at = accepted_at - Duration::hours(1);

    sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2)")
        .bind(&did)
        .bind(created_at)
        .execute(&mut **tx)
        .await
        .expect("seed principal");
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'target','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    )
    .bind(&did)
    .bind(device_id)
    .bind(&key_id)
    .bind(created_at)
    .execute(&mut **tx)
    .await
    .expect("seed device");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
         VALUES($1,$2,$3,$4,1,$5)",
    )
    .bind(&did)
    .bind(device_id)
    .bind(&key_id)
    .bind(&public_key)
    .bind(created_at)
    .execute(&mut **tx)
    .await
    .expect("seed device key");

    let revocation_id = Uuid::new_v4();
    let signing_transcript_bytes = random_ref();
    let request_digest = Sha256::digest(&signing_transcript_bytes).to_vec();
    let accepted_request_bytes = random_ref();
    let signature = vec![0x5a_u8; 64];

    if with_receipt {
        let response_bytes = b"revokeDevice-ok".to_vec();
        let response_sha256 = Sha256::digest(&response_bytes).to_vec();
        sqlx::query(
            r#"
            INSERT INTO chat.idempotency_records(
                principal_did, endpoint_nsid, operation_id, request_digest,
                accepted_request_bytes, signing_transcript_bytes, signature,
                completed_status, response_bytes, response_sha256, event_position,
                historical_jkt, current_jkt, completed_at
            ) VALUES($1,'blue.catbird.chat.revokeDevice',$2,$3,$4,$5,$6,200,$7,$8,NULL,$9,NULL,$10)
            "#,
        )
        .bind(&did)
        .bind(revocation_id)
        .bind(&request_digest)
        .bind(&accepted_request_bytes)
        .bind(&signing_transcript_bytes)
        .bind(&signature)
        .bind(&response_bytes)
        .bind(&response_sha256)
        // revokeDevice requires historical_jkt NOT NULL / current_jkt NULL; the
        // device key id is a valid base64url-sha256 thumbprint.
        .bind(&key_id)
        .bind(accepted_at)
        .execute(&mut **tx)
        .await
        .expect("seed revokeDevice receipt");
    }

    RevocationPrereqs {
        revocation_id,
        did,
        device_id,
        key_id,
        auth_generation: 1,
        accepted_at,
        accepted_request_bytes,
        signing_transcript_bytes,
        request_digest,
        signature,
    }
}

fn new_device_revocation(p: &RevocationPrereqs) -> NewDeviceRevocation {
    NewDeviceRevocation {
        revocation_id: p.revocation_id,
        // Self-revoke: actor device == target device (a first-class spec op).
        actor_did: p.did.clone(),
        actor_device_id: p.device_id,
        actor_key_id: p.key_id.clone(),
        actor_auth_generation: p.auth_generation,
        target_did: p.did.clone(),
        target_device_id: p.device_id,
        target_auth_generation: p.auth_generation,
        accepted_request_bytes: p.accepted_request_bytes.clone(),
        signing_transcript_bytes: p.signing_transcript_bytes.clone(),
        request_digest: p.request_digest.clone(),
        signature: p.signature.clone(),
        signed_at: p.accepted_at,
        accepted_at: p.accepted_at,
    }
}

fn registration_revoke(p: &RevocationPrereqs) -> RegistrationRevoke {
    RegistrationRevoke {
        target_did: p.did.clone(),
        target_device_id: p.device_id,
        expected_auth_generation: p.auth_generation,
        revocation_id: p.revocation_id,
        revoked_at: p.accepted_at,
    }
}

#[tokio::test]
async fn device_revocation_insert_and_registration_revoke_commit_past_the_mapping_trigger() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;

    // Fire the DEFERRED `enforce_device_revocation_mapping` trigger via
    // `SET CONSTRAINTS ALL IMMEDIATE` inside a rolled-back tx — the full footprint
    // is present, so the check passes; nothing commits, so nothing leaks.
    let mut tx = pool.begin().await.unwrap();
    let p = seed_revocation_prereqs_tx(&mut tx, true).await;
    insert_device_revocation(&mut tx, &new_device_revocation(&p))
        .await
        .expect("insert revocation row");
    cas_registration_revoke(&mut tx, &registration_revoke(&p))
        .await
        .expect("revoke registration");

    // Committed state as the trigger sees it: registration revoked, key revoked.
    let (status, revoked_at, rev_id): (String, Option<DateTime<Utc>>, Option<Uuid>) = sqlx::query_as(
        "SELECT status, revoked_at, revocation_id FROM chat.devices WHERE user_did=$1 AND device_id=$2",
    )
    .bind(&p.did)
    .bind(p.device_id)
    .fetch_one(&mut *tx)
    .await
    .expect("target device row");
    assert_eq!(status, "revoked");
    assert_eq!(revoked_at, Some(p.accepted_at));
    assert_eq!(rev_id, Some(p.revocation_id));
    let (key_revoked_at, key_rev_id): (Option<DateTime<Utc>>, Option<Uuid>) = sqlx::query_as(
        "SELECT revoked_at, revocation_id FROM chat.device_keys WHERE user_did=$1 AND device_id=$2",
    )
    .bind(&p.did)
    .bind(p.device_id)
    .fetch_one(&mut *tx)
    .await
    .expect("target device key row");
    assert_eq!(key_revoked_at, Some(p.accepted_at));
    assert_eq!(key_rev_id, Some(p.revocation_id));

    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *tx)
        .await
        .expect("full target footprint satisfies enforce_device_revocation_mapping");
    tx.rollback().await.unwrap();

    // Negative: an identical revocation WITHOUT the `revokeDevice` receipt fails
    // the mapping trigger (provenance is missing) at the deferred check.
    let mut tx = pool.begin().await.unwrap();
    let p = seed_revocation_prereqs_tx(&mut tx, false).await;
    insert_device_revocation(&mut tx, &new_device_revocation(&p))
        .await
        .expect("insert revocation row");
    cas_registration_revoke(&mut tx, &registration_revoke(&p))
        .await
        .expect("revoke registration");
    let deferred = sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *tx)
        .await;
    assert!(
        deferred.is_err(),
        "a revocation missing its revokeDevice receipt must fail enforce_device_revocation_mapping"
    );
    tx.rollback().await.unwrap();

    // Negative: the registration revoke CAS conflicts if the device is not active
    // at the expected auth generation (wrong generation matches no row).
    let mut tx = pool.begin().await.unwrap();
    let p = seed_revocation_prereqs_tx(&mut tx, true).await;
    let mut wrong = registration_revoke(&p);
    wrong.expected_auth_generation = 999;
    conflict(cas_registration_revoke(&mut tx, &wrong).await);
    tx.rollback().await.unwrap();
}
