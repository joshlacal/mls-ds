//! Live-PostgreSQL end-to-end verification of the E2b-2/E2b-3 transition
//! executor `apply_conversation_persistence_plan_unscoped_for_test` and the spine/seq-seam writers
//! it composes.
//!
//! Two kinds of coverage:
//!  * The NEW dumb-SQL writers (conversation-head insert/CAS/close, generation
//!    insert/state-version-CAS/supersede, `append_entry_at`) — column fidelity +
//!    CAS advance/conflict, inside one transaction with read-back + ROLLBACK.
//!  * The executor driven end-to-end: a REAL creation plan built through the
//!    production `plan_creation` path (with the E2b-3 `#[cfg(test)]`
//!    metadata-bearing evidence + head-CAS synthesis), applied and COMMITTED,
//!    then the full committed graph SELECT-verified past every DEFERRED trigger;
//!    plus re-apply -> conflict with zero residue, and mid-transaction failure
//!    injection -> whole-graph rollback.
//!
//! Run:
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_executor -- --test-threads=1

#![allow(dead_code)]

mod common;

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
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[allow(dead_code)]
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

mod chat_protocol {
    pub mod validation {
        pub use crate::validation::*;
    }
    pub mod model {
        pub(crate) use crate::model::*;
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
    #[allow(dead_code)]
    pub mod dpop {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/dpop.rs"
        ));
    }
    pub mod relationship_policy {
        pub use crate::relationship_policy_source::*;
    }
    pub mod repository {
        // The raw executor harness never mints production capsules, but the
        // included state-machine module retains their sealed proof types in
        // signatures. Minimal opaque stubs keep that production boundary
        // unforgeable while allowing the legacy test seam to compile.
        pub mod execution_context {
            pub(crate) struct ExecutionContextHydrationProof;
            pub(crate) struct RevocationBatchHydrationProof;
        }
        #[allow(dead_code)]
        pub mod auth {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/auth.rs"
            ));
        }
        #[allow(dead_code)]
        pub mod prelude {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/prelude.rs"
            ));
        }
        pub mod recovery {
            /// The raw executor harness never mints a production Recovery
            /// witness. This opaque test-topology stand-in exists only because
            /// the generic executor accepts `Option<&RecoveryPersistenceWitness>`;
            /// every raw test passes `None`.
            pub(crate) struct RecoveryPersistenceWitness {
                _private: (),
            }

            /// Opaque authority required by exact Recovery SQL writers. Raw
            /// executor tests never construct one because they exercise the
            /// explicit status-CAS compatibility path.
            #[derive(Debug)]
            pub(crate) struct RecoverySqlAuthoritySeal {
                _private: (),
            }

            impl RecoveryPersistenceWitness {
                pub(crate) async fn apply_open(
                    &self,
                    _transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
                ) -> Result<(), super::super::state_machine::ExecutorError> {
                    unreachable!("raw executor tests cannot mint a Recovery witness")
                }

                pub(crate) async fn apply_terminal(
                    &self,
                    _transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
                ) -> Result<(), super::super::state_machine::ExecutorError> {
                    unreachable!("raw executor tests cannot mint a Recovery witness")
                }
            }
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

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::Barrier;
use uuid::Uuid;

use chat_protocol::public_state::ActivePublicState;
use chat_protocol::repository::delivery::WelcomeRejectionReason;
use chat_protocol::repository::delivery::{
    append_entry_at, AppendEntry, DeliveryRepositoryError, EntryEntitlementKind,
    EventEntitlementKind, EventKind, EventRecipient, NewEvent, NewRecoveryWorkItem, OutboxWorkKind,
    RecoveryWorkSourceKind,
};
use chat_protocol::repository::transition::ResetReason;
use chat_protocol::repository::transition::{
    cas_conversation_head, cas_generation_state_version, lock_active_leaf_period_bindings,
    supersede_generation, ActiveLeafPeriodBinding, ConversationHeadCas, ConversationHeadClose,
    GenerationStateVersionCas, GenerationSupersede, TransitionActorRole, TransitionRepositoryError,
};
use chat_protocol::snapshot::{PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle};
use chat_protocol::state_machine::{
    apply_conversation_persistence_plan_unscoped_for_test,
    apply_device_revocation_batch_unscoped_for_test, device_revocation_plan_for_test,
    persistence_plan_for_test, plan_accept_conversation, plan_close, plan_commit, plan_creation,
    plan_device_revocation, plan_leaf_recovery_cancellation, plan_leaf_recovery_fulfillment,
    plan_leaf_recovery_request, plan_leave_cancellation, plan_leave_fulfillment,
    plan_leave_request, plan_policy, plan_reset_activation, plan_reset_request,
    plan_welcome_expiry_for_test, plan_welcome_response_for_test, plan_zero_leaf_leave,
    AcceptConversation, CloseConversation, CommitCommand, ControlEntryContent,
    ConversationHeadCasBinding, ConversationKind, ConversationState, CreationCommand,
    CreationDecision, DeviceIdentity, DeviceRevocationBatchPersistencePlan,
    DeviceRevocationEvidence, EventFanout, ExecutionActor, ExecutionAuthority, ExecutionContext,
    ExecutorError, HydrationAuthority, LeafPersistenceColumns, LeafRecoveryCancellation,
    LeafRecoveryFulfillment, LeafRecoveryKind, LeafRecoveryRequestCommand, LeaveCancellation,
    LeaveFulfillment, LeaveRequestCommand, LockedRegistrationProjection, MetadataAuthorColumns,
    MetadataSnapshotBinding, PolicyPlanMutation, PrincipalId, RecoveryOpenContext,
    RequestEntryKind, RequestEvidence, ResetActivation, ResetRequestCommand, ResetRequestRow,
    RevocationPackageCasBinding, RevocationTargetCasBinding, ServerTimestamp, SpineArtifacts,
    TransitionEvidence, WelcomeDispositionInput, WelcomeExpiryContext, WelcomeRejectionWork,
    WelcomeResponseContext, WelcomeStatus, ZeroLeafLeave,
};
use chat_protocol::transcript::{
    decode_and_verify_control_entry, decode_canonical_signed_mutation,
    rebind_persisted_control_entry, VerifiedMutationProjection,
};
use chat_protocol::validation::ed25519_key_id;
use chat_protocol::wire::{validate_public_commit, MAX_PUBLIC_MESSAGE_WIRE_BYTES};

// ---------------------------------------------------------------------------
// Harness + corpus fixtures (adapted from tests/chat_protocol_state_machine.rs).
// ---------------------------------------------------------------------------

#[path = "common/executor_seed.rs"]
mod executor_seed;
use executor_seed::*;
/// A FRESH invitee each run. Only the creator (alice) must match the corpus
/// genesis leaf; the pending invitee is an arbitrary principal, so a random DID
/// keeps the direct-pair unique index (and bob's global event chain) collision-
/// free across runs of this never-truncated, delete-forbidding database.
fn fresh_bob() -> (DeviceIdentity, String) {
    let did = random_plc_did();
    let device = DeviceIdentity::new(
        PrincipalId::new(did.as_bytes().to_vec()).unwrap(),
        *Uuid::new_v4().as_bytes(),
    )
    .unwrap();
    (device, did)
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

async fn build_creation(pool: &PgPool, kind: ConversationKind) -> CreationApply {
    // Default invitee: a FRESH principal each run with a fresh unique device key so
    // his `chat.device_keys` row (unique on `key_id`) is always present this run.
    let (bob_id, bob_did) = fresh_bob();
    build_creation_with_invitee(pool, kind, bob_id, bob_did, random_ref32().to_vec()).await
}

/// Connect to the already-provisioned clean-chat database without creating,
/// dropping, or migrating any database. Task 4 H2-pre runs only against this
/// explicitly gated accumulated-row fixture.
async fn existing_executor_pool() -> PgPool {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must name the existing clean-chat test database");
    common::chat_protocol::validate_chat_protocol_database_url(Some(&database_url))
        .expect("unsafe TEST_DATABASE_URL for policy ChangeRole executor test");
    PgPool::connect(&database_url)
        .await
        .expect("connect to existing clean-chat test database")
}

/// Pre-clean any leftover ACTIVE direct conversation for the fixed corpus pair
/// so the `conversations_active_direct_pair_uq` does not collide across runs.
async fn preclean_direct_pair(pool: &PgPool, did_a: &str, did_b: &str) {
    let (low, high) = if did_a <= did_b {
        (did_a, did_b)
    } else {
        (did_b, did_a)
    };
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT conversation_id FROM chat.conversations WHERE direct_did_low=$1 AND direct_did_high=$2",
    )
    .bind(low)
    .bind(high)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    for id in ids {
        cleanup(pool, id).await;
    }
}

fn rand_byte() -> u8 {
    use std::cell::Cell;
    thread_local!(static SEED: Cell<u64> = Cell::new(0x9E37_79B9_7F4A_7C15));
    SEED.with(|s| {
        let mut x = s.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.set(x);
        ((x >> 24) as u8) | 0x40
    })
}

async fn assert_welcome_shape_update_rejects(
    pool: &PgPool,
    welcome_id: Uuid,
    mutation: &str,
    label: &str,
) {
    let mut tx = pool.begin().await.expect("begin Welcome shape probe");
    sqlx::query(
        "ALTER TABLE chat.welcome_dispositions \
         DISABLE TRIGGER welcome_dispositions_immutable",
    )
    .execute(&mut *tx)
    .await
    .expect("disable only Welcome disposition immutability");
    let statement = format!("UPDATE chat.welcome_dispositions SET {mutation} WHERE welcome_id=$1");
    let error = sqlx::query(&statement)
        .bind(welcome_id)
        .execute(&mut *tx)
        .await
        .expect_err(label);
    let database = error
        .as_database_error()
        .expect("database constraint error");
    assert_eq!(
        database.code().as_deref(),
        Some("23514"),
        "{label}: {error}"
    );
    assert!(
        database
            .constraint()
            .is_some_and(|name| name == "welcome_dispositions_terminal_source_shape_check"),
        "{label}: unexpected constraint: {error}"
    );
    tx.rollback().await.expect("rollback Welcome shape probe");
}

async fn assert_welcome_source_commit_rejects(
    pool: &PgPool,
    welcome_id: Uuid,
    mutation: &str,
    source_id: Option<Uuid>,
    label: &str,
) {
    let mut tx = pool.begin().await.expect("begin Welcome source probe");
    sqlx::query(
        "ALTER TABLE chat.welcome_dispositions \
         DISABLE TRIGGER welcome_dispositions_immutable",
    )
    .execute(&mut *tx)
    .await
    .expect("disable only Welcome disposition immutability");
    let statement = format!("UPDATE chat.welcome_dispositions SET {mutation} WHERE welcome_id=$1");
    let mut query = sqlx::query(&statement).bind(welcome_id);
    if let Some(source_id) = source_id {
        query = query.bind(source_id);
    }
    query
        .execute(&mut *tx)
        .await
        .unwrap_or_else(|error| panic!("{label}: mutation must reach COMMIT: {error}"));
    // Do not re-enable here: PostgreSQL rejects ALTER TABLE while this table
    // has pending deferred-trigger events. The expected COMMIT failure rolls
    // back this transactional DDL together with the malformed mutation.
    let error = match tx.commit().await {
        Err(error) => error,
        Ok(()) => {
            // The suite normally runs inside FreshDbGuard's per-test database,
            // but restore the named trigger explicitly before failing so even
            // an accidentally shared database cannot retain test-only DDL.
            sqlx::query(
                "ALTER TABLE chat.welcome_dispositions \
                 ENABLE TRIGGER welcome_dispositions_immutable",
            )
            .execute(pool)
            .await
            .expect("restore immutable trigger after unexpected COMMIT success");
            panic!("{label}: malformed Welcome source unexpectedly committed");
        }
    };
    let database = error
        .as_database_error()
        .expect("database constraint error");
    assert_eq!(
        database.code().as_deref(),
        Some("23514"),
        "{label}: {error}"
    );
    assert!(
        database
            .message()
            .contains("terminal Welcome disposition mismatch"),
        "{label}: deferred Welcome CAS did not reject: {error}"
    );
}

async fn commit_isolated_device_revocation(pool: &PgPool) -> (Uuid, DateTime<Utc>) {
    let target_did = random_plc_did();
    let target_device = Uuid::new_v4();
    let mut signing_public_key = [0_u8; 32];
    signing_public_key[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    signing_public_key[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    let target_key_id = seed_actor(pool, &target_did, target_device, &signing_public_key).await;
    let accepted_at = DateTime::from_timestamp_millis(clock_now(pool).await.timestamp_millis())
        .expect("whole-millisecond isolated revocation instant");
    let revocation_id = Uuid::new_v4();
    let accepted_request = vec![0x91_u8; 8];
    let signing_transcript = vec![0x92_u8; 8];
    let request_digest = Sha256::digest(&signing_transcript).to_vec();
    let signature = vec![0x93_u8; 64];
    let response = vec![0x94_u8; 8];
    let mut tx = pool.begin().await.expect("begin isolated revocation");
    sqlx::query(
        r#"
        INSERT INTO chat.idempotency_records(
            principal_did,endpoint_nsid,operation_id,request_digest,
            accepted_request_bytes,signing_transcript_bytes,signature,
            completed_status,response_bytes,response_sha256,historical_jkt,completed_at
        ) VALUES($1,'blue.catbird.chat.revokeDevice',$2,$3,$4,$5,$6,200,$7,$8,$9,$10)
        "#,
    )
    .bind(&target_did)
    .bind(revocation_id)
    .bind(&request_digest)
    .bind(&accepted_request)
    .bind(&signing_transcript)
    .bind(&signature)
    .bind(&response)
    .bind(Sha256::digest(&response).to_vec())
    .bind(&target_key_id)
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert isolated revocation receipt");
    sqlx::query(
        r#"
        INSERT INTO chat.device_revocations(
            revocation_id,actor_did,actor_device_id,actor_key_id,
            actor_auth_generation,target_did,target_device_id,
            target_auth_generation,accepted_request_bytes,
            signing_transcript_bytes,request_digest,signature,signed_at,accepted_at
        ) VALUES($1,$2,$3,$4,1,$2,$3,1,$5,$6,$7,$8,$9,$9)
        "#,
    )
    .bind(revocation_id)
    .bind(&target_did)
    .bind(target_device)
    .bind(&target_key_id)
    .bind(&accepted_request)
    .bind(&signing_transcript)
    .bind(&request_digest)
    .bind(&signature)
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert isolated device revocation");
    sqlx::query(
        "UPDATE chat.devices \
            SET status='revoked',revoked_at=$3,revocation_id=$4,updated_at=$3 \
          WHERE user_did=$1 AND device_id=$2",
    )
    .bind(&target_did)
    .bind(target_device)
    .bind(accepted_at)
    .bind(revocation_id)
    .execute(&mut *tx)
    .await
    .expect("revoke isolated device");
    sqlx::query(
        "UPDATE chat.device_keys SET revoked_at=$3,revocation_id=$4 \
          WHERE user_did=$1 AND device_id=$2",
    )
    .bind(&target_did)
    .bind(target_device)
    .bind(accepted_at)
    .bind(revocation_id)
    .execute(&mut *tx)
    .await
    .expect("revoke isolated device key");
    tx.commit()
        .await
        .expect("commit complete isolated revocation footprint");
    (revocation_id, accepted_at)
}

// ===========================================================================
// New-writer verification (tx + read-back + ROLLBACK).
// ===========================================================================

async fn seed_group_head_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    at: DateTime<Utc>,
) -> Uuid {
    let conversation_id = Uuid::new_v4();
    let group_id = vec![1_u8; 32];
    let group_info = vec![4_u8; 8];
    let transition_id = Uuid::new_v4();
    let snapshot = vec![5_u8; 8];
    let tree = vec![6_u8; 8];
    sqlx::query(
        "INSERT INTO chat.conversations(conversation_id,kind,lifecycle,current_generation,current_state_version,next_entry_seq,created_at) \
         VALUES($1,'group','active',0,0,2,$2)",
    )
    .bind(conversation_id)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("seed head");
    sqlx::query(
        "INSERT INTO chat.generations(conversation_id,generation,group_id,lifecycle,genesis_group_info_bytes,genesis_group_info_sha256,current_state_version,activated_seq,activated_at) \
         VALUES($1,0,$2,'active',$3,$4,0,1,$5)",
    )
    .bind(conversation_id)
    .bind(&group_id)
    .bind(&group_info)
    .bind(Sha256::digest(&group_info).to_vec())
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("seed generation");
    sqlx::query(
        r#"INSERT INTO chat.generation_states(
            conversation_id,generation,state_version,group_id,epoch,group_context_hash,
            confirmation_tag,lifecycle,state_kind,producing_transition_id,public_snapshot_bytes,
            snapshot_sha256,tree_summary_bytes,tree_summary_sha256,leaf_count,created_at
        ) VALUES($1,0,0,$2,0,$3,$4,'active','creation',$5,$6,$7,$8,$9,1,$10)"#,
    )
    .bind(conversation_id)
    .bind(&group_id)
    .bind(vec![2_u8; 32])
    .bind(vec![3_u8; 32])
    .bind(transition_id)
    .bind(&snapshot)
    .bind(Sha256::digest(&snapshot).to_vec())
    .bind(&tree)
    .bind(Sha256::digest(&tree).to_vec())
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("seed generation state");
    conversation_id
}

#[tokio::test]
async fn conversation_head_cas_advances_and_conflicts_on_drift() {
    let (pool, _db) = setup().await;
    let mut tx = pool.begin().await.expect("begin");
    let at = clock_now(&pool).await;
    let conversation_id = seed_group_head_tx(&mut tx, at).await;
    cas_conversation_head(
        &mut tx,
        &ConversationHeadCas {
            conversation_id,
            expected_generation: 0,
            expected_state_version: 0,
            expected_next_entry_seq: 2,
            successor_generation: 0,
            successor_state_version: 1,
            successor_next_entry_seq: 3,
            close: None,
        },
    )
    .await
    .expect("advance head");
    let (sv, next_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&mut *tx)
    .await
    .expect("read advanced head");
    assert_eq!((sv, next_seq), (1, 3));
    let conflict = cas_conversation_head(
        &mut tx,
        &ConversationHeadCas {
            conversation_id,
            expected_generation: 0,
            expected_state_version: 0,
            expected_next_entry_seq: 2,
            successor_generation: 0,
            successor_state_version: 1,
            successor_next_entry_seq: 3,
            close: None,
        },
    )
    .await;
    assert!(matches!(
        conflict,
        Err(TransitionRepositoryError::CompareAndSetConflict)
    ));
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn conversation_head_close_and_generation_supersede() {
    let (pool, _db) = setup().await;
    let mut tx = pool.begin().await.expect("begin");
    let at = clock_now(&pool).await;
    let conversation_id = seed_group_head_tx(&mut tx, at).await;
    let close_transition_id = Uuid::new_v4();
    cas_conversation_head(
        &mut tx,
        &ConversationHeadCas {
            conversation_id,
            expected_generation: 0,
            expected_state_version: 0,
            expected_next_entry_seq: 2,
            successor_generation: 0,
            successor_state_version: 1,
            successor_next_entry_seq: 3,
            close: Some(ConversationHeadClose {
                close_transition_id,
                close_generation: 0,
                close_state_version: 1,
                close_seq: 2,
                closed_at: at,
            }),
        },
    )
    .await
    .expect("close head");
    supersede_generation(
        &mut tx,
        &GenerationSupersede {
            conversation_id,
            generation: 0,
            expected_state_version: 0,
            successor_state_version: 1,
            superseded_seq: 2,
            superseded_at: at,
        },
    )
    .await
    .expect("supersede generation");
    let (lifecycle, ct): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT lifecycle,close_transition_id FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&mut *tx)
    .await
    .expect("read closed head");
    assert_eq!(lifecycle, "superseded");
    assert_eq!(ct, Some(close_transition_id));
    let gen_life: String = sqlx::query_scalar(
        "SELECT lifecycle FROM chat.generations WHERE conversation_id=$1 AND generation=0",
    )
    .bind(conversation_id)
    .fetch_one(&mut *tx)
    .await
    .expect("read gen");
    assert_eq!(gen_life, "superseded");
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn generation_state_version_cas_is_guarded() {
    let (pool, _db) = setup().await;
    let mut tx = pool.begin().await.expect("begin");
    let at = clock_now(&pool).await;
    let conversation_id = seed_group_head_tx(&mut tx, at).await;
    cas_generation_state_version(
        &mut tx,
        &GenerationStateVersionCas {
            conversation_id,
            generation: 0,
            expected_state_version: 0,
            successor_state_version: 1,
        },
    )
    .await
    .expect("advance pointer");
    let conflict = cas_generation_state_version(
        &mut tx,
        &GenerationStateVersionCas {
            conversation_id,
            generation: 0,
            expected_state_version: 0,
            successor_state_version: 1,
        },
    )
    .await;
    assert!(matches!(
        conflict,
        Err(TransitionRepositoryError::CompareAndSetConflict)
    ));
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn append_entry_at_inserts_at_exact_seq_without_touching_head() {
    let (pool, _db) = setup().await;
    let mut tx = pool.begin().await.expect("begin");
    let at = clock_now(&pool).await;
    let conversation_id = seed_group_head_tx(&mut tx, at).await;
    let user_did = format!("did:plc:{}", "a".repeat(24));
    sqlx::query(
        "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(&user_did)
    .bind(at)
    .execute(&mut *tx)
    .await
    .expect("principal");
    let device_id = Uuid::new_v4();
    let pubkey = vec![0x99_u8; 32];
    let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&pubkey)
        .fetch_one(&mut *tx)
        .await
        .expect("key id");
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'a','active',$3,1,chat.protocol_capabilities(),$4,$4) ON CONFLICT DO NOTHING",
    )
    .bind(&user_did)
    .bind(device_id)
    .bind(&key_id)
    .bind(at)
    .execute(&mut *tx)
    .await
    .expect("device");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
         VALUES($1,$2,$3,$4,1,$5)",
    )
    .bind(&user_did)
    .bind(device_id)
    .bind(&key_id)
    .bind(&pubkey)
    .bind(at)
    .execute(&mut *tx)
    .await
    .expect("device key");

    let payload = vec![21_u8; 8];
    let transcript = vec![22_u8; 8];
    let returned = append_entry_at(
        &mut tx,
        &AppendEntry {
            conversation_id,
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#creationEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![23_u8; 64],
            server_fields_bytes: vec![24_u8; 4],
            outer_entry_fingerprint: vec![25_u8; 32],
            actor_did: user_did.clone(),
            actor_device_id: device_id,
            actor_key_id: key_id.clone(),
            actor_auth_generation: 1,
            generation: Some(0),
            state_version: Some(0),
            transition_id: Some(Uuid::new_v4()),
            message_id: None,
            received_at: at,
        },
        1,
    )
    .await
    .expect("append entry at seq 1");
    assert_eq!(returned, 1);
    let head_seq: i64 = sqlx::query_scalar(
        "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&mut *tx)
    .await
    .expect("read head seq");
    assert_eq!(head_seq, 2);
    let _ = DeliveryRepositoryError::SequenceOverflow;
    tx.rollback().await.expect("rollback");
}

// ===========================================================================
// Executor end-to-end: creation -> COMMIT -> SELECT-verify.
// ===========================================================================

async fn count(pool: &PgPool, sql: &str, conversation_id: Uuid) -> i64 {
    sqlx::query_scalar(sql)
        .bind(conversation_id)
        .fetch_one(pool)
        .await
        .expect("count")
}

#[tokio::test]
async fn group_creation_commits_full_graph_past_all_deferred_triggers() {
    let (pool, _db) = setup().await;
    let fixture = build_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;

    let mut tx = pool.begin().await.expect("begin");
    let applied =
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &fixture.plan, &fixture.ctx)
            .await
            .expect("creation applies");
    tx.commit()
        .await
        .expect("COMMIT past all deferred triggers");

    assert_eq!(applied.allocated_seq, 1);
    assert_eq!(applied.event_positions.len(), 1);

    let (kind, lifecycle, gen, sv, next_seq): (String, String, i64, i64, i64) = sqlx::query_as(
        "SELECT kind,lifecycle,current_generation,current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!(
        (kind.as_str(), lifecycle.as_str(), gen, sv, next_seq),
        ("group", "active", 0, 0, 2)
    );

    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.generations WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        1
    );
    let (state_kind, leaf_count): (String, i64) = sqlx::query_as(
        "SELECT state_kind,leaf_count FROM chat.generation_states WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("gen state");
    assert_eq!((state_kind.as_str(), leaf_count), ("creation", 1));

    let (tkind, entry_seq): (String, i64) =
        sqlx::query_as("SELECT kind,entry_seq FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .expect("transition");
    assert_eq!((tkind.as_str(), entry_seq), ("creation", 1));
    let (eseq, ekind): (i64, String) =
        sqlx::query_as("SELECT seq,entry_kind FROM chat.entries WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .expect("entry");
    assert_eq!(
        (eseq, ekind.as_str()),
        (1, "blue.catbird.chat.defs#creationEntry")
    );

    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.metadata_snapshots WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        1
    );

    let (active_admin, pending_member): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE status='active' AND role='admin'), count(*) FILTER (WHERE status='pending' AND role='member') \
         FROM chat.participants WHERE conversation_id=$1 AND current_membership",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("participants");
    assert_eq!((active_admin, pending_member), (1, 1));

    let leaf_origin: String =
        sqlx::query_scalar("SELECT origin FROM chat.member_devices WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .expect("leaf");
    assert_eq!(leaf_origin, "genesis");

    let (start_seq, opening_kind, terminal): (i64, String, Option<i64>) = sqlx::query_as(
        "SELECT start_seq,opening_kind,terminal_seq FROM chat.application_intervals WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("interval");
    assert_eq!(
        (start_seq, opening_kind.as_str(), terminal),
        (1, "creation", None)
    );

    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.entry_recipients WHERE conversation_id=$1 AND seq=1",
            conversation_id
        )
        .await,
        2
    );
    let position = applied.event_positions[0];
    let evt_kind: String =
        sqlx::query_scalar("SELECT event_kind FROM chat.events WHERE event_position=$1")
            .bind(position)
            .fetch_one(&pool)
            .await
            .expect("event");
    assert_eq!(evt_kind, "conversationChanged");
    let evt_recips: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.event_recipients WHERE event_position=$1")
            .bind(position)
            .fetch_one(&pool)
            .await
            .expect("event recips");
    assert_eq!(evt_recips, 2);
    let outbox: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.outbox WHERE event_position=$1")
            .bind(position)
            .fetch_one(&pool)
            .await
            .expect("outbox");
    assert_eq!(outbox, 1);

    // Re-apply the SAME plan -> the head INSERT collides on the conversation PK
    // (true-absence CAS), the whole transaction rolls back, zero new residue.
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut tx2 = pool.begin().await.expect("begin re-apply");
    let reapply = apply_conversation_persistence_plan_unscoped_for_test(
        &mut tx2,
        &fixture.plan,
        &fixture.ctx,
    )
    .await;
    assert!(
        matches!(reapply, Err(ExecutorError::Transition(_))),
        "re-apply must conflict on the head PK"
    );
    tx2.rollback().await.expect("rollback re-apply");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "re-apply left zero residue");
}

#[tokio::test]
async fn group_policy_add_participant_commits_state_version_plus_one() {
    let (pool, _db) = setup().await;
    let fixture = build_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;

    // 1. Commit the creation the policy edge builds on.
    let mut tx = pool.begin().await.expect("begin creation");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &fixture.plan, &fixture.ctx)
        .await
        .expect("creation applies");
    tx.commit().await.expect("creation COMMIT");

    // 2. A fresh third principal to add; seed it (participant + audience FKs).
    let (bob2_id, bob2_did) = fresh_bob();
    let bob2_device = Uuid::from_bytes(*bob2_id.device_id());
    let _ = seed_actor(&pool, &bob2_did, bob2_device, &[0x63_u8; 32]).await;

    // 3. Build the REAL policy plan through the production planner.
    let received_at = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 2_000,
    )
    .unwrap();
    let entry_id = Uuid::new_v4();
    let transition_id = Uuid::new_v4();
    let policy_evidence = TransitionEvidence::for_test_policy_add(
        2,
        *transition_id.as_bytes(),
        [0x12_u8; 32],
        received_at,
        fixture.coordinate,
        vec![bob2_id.principal().clone()],
    )
    .unwrap();
    let planned = plan_policy(
        &fixture.state,
        fixture.alice_id.clone(),
        policy_evidence,
        [0x99_u8; 32],
    )
    .expect("valid policy plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        2,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    // 4. Policy ctx: same actor (alice), policyEntry at seq 2, no metadata, one
    //    new pending participant, audience = the three current devices.
    let applied_at = clock_now(&pool).await;
    let payload = vec![0x51_u8; 12];
    let transcript = vec![0x52_u8; 12];
    let recipients_devices = [
        (fixture.alice_id.clone(), fixture.alice_did.clone()),
        (fixture.bob_id.clone(), fixture.bob_did.clone()),
        (bob2_id.clone(), bob2_did.clone()),
    ];
    let mut sorted = recipients_devices.to_vec();
    sorted
        .sort_by(|l, r| (l.1.as_bytes(), l.0.device_id()).cmp(&(r.1.as_bytes(), r.0.device_id())));
    let entry_recipients = sorted
        .iter()
        .map(|(d, _)| (d.clone(), EntryEntitlementKind::Control))
        .collect();
    let mut event_recips = Vec::new();
    for (device, did) in &sorted {
        let predecessor: Option<i64> = sqlx::query_scalar(
            "SELECT max(event_position) FROM chat.event_recipients WHERE user_did=$1 AND device_id=$2",
        )
        .bind(did)
        .bind(Uuid::from_bytes(*device.device_id()))
        .fetch_one(&pool)
        .await
        .expect("predecessor");
        event_recips.push((
            device.clone(),
            EventEntitlementKind::Participant,
            predecessor,
        ));
    }
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#policyEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x53_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0x54_u8; 64],
            server_fields_bytes: vec![0x55_u8; 8],
            outer_entry_fingerprint: vec![0x12_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0x61_u8; 16],
            public_snapshot_sha256: Sha256::digest([0x61_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0x62_u8; 16],
            tree_summary_sha256: Sha256::digest([0x62_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![Uuid::new_v4()],
        leaf_period_ids: vec![],
        entry_recipients,
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x71_u8; 8],
            recipients: event_recips,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: Vec::new(),
        closing_participant_periods: Vec::new(),
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };

    // 5. Apply + COMMIT the policy edge.
    let mut tx2 = pool.begin().await.expect("begin policy");
    let applied = apply_conversation_persistence_plan_unscoped_for_test(&mut tx2, &plan, &ctx)
        .await
        .expect("policy applies");
    tx2.commit()
        .await
        .expect("policy COMMIT past deferred triggers");
    assert_eq!(applied.allocated_seq, 2);

    // 6. Verify: stateVersion+1 at the same crypto coordinate, seq 2 contiguity.
    let (sv, next_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((sv, next_seq), (1, 3));
    let gen_sv: i64 = sqlx::query_scalar(
        "SELECT current_state_version FROM chat.generations WHERE conversation_id=$1 AND generation=0",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("gen pointer");
    assert_eq!(gen_sv, 1);
    let (skind, slife): (String, String) = sqlx::query_as(
        "SELECT state_kind,lifecycle FROM chat.generation_states WHERE conversation_id=$1 AND state_version=1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("policy state");
    assert_eq!((skind.as_str(), slife.as_str()), ("policy", "active"));
    let (tkind, eseq): (String, i64) = sqlx::query_as(
        "SELECT kind,entry_seq FROM chat.transitions WHERE conversation_id=$1 AND kind='policy'",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("policy transition");
    assert_eq!((tkind.as_str(), eseq), ("policy", 2));
    let added: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND status='pending' AND role='member' AND current_membership",
    )
    .bind(conversation_id)
    .bind(&bob2_did)
    .fetch_one(&pool)
    .await
    .expect("added participant");
    assert_eq!(added, 1);
    // No metadata snapshot for a policy edge.
    let policy_snap: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.metadata_snapshots m JOIN chat.transitions t ON t.transition_id=m.producing_transition_id WHERE t.conversation_id=$1 AND t.kind='policy'",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("policy snapshot count");
    assert_eq!(policy_snap, 0);

    // Reviewer's existing-edge re-apply variant: re-applying the committed POLICY
    // plan hits the head CAS (the head already advanced to stateVersion 1) →
    // typed conflict, whole transaction rolls back with zero residue.
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut tx3 = pool.begin().await.expect("begin re-apply policy");
    let reapply =
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx3, &plan, &ctx).await;
    assert!(
        matches!(reapply, Err(ExecutorError::Transition(_))),
        "policy re-apply must conflict on the head CAS, got {reapply:?}"
    );
    tx3.rollback().await.expect("rollback re-apply policy");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "policy re-apply left zero residue");
}

#[tokio::test]
async fn signed_policy_change_role_commits_exact_active_participant_update() {
    let pool = existing_executor_pool().await;
    let accepted = commit_accepted_group(&pool).await;
    let fixture = &accepted.fixture;
    let prior = &accepted.state;
    let conversation_id = fixture.conversation_id;

    let non_attesting_control = signed_policy_control(
        fixture,
        &fixture.state,
        2,
        vec![SignedPolicyChange::ChangeRole {
            user_did: fixture.alice_did.clone(),
            role: "member",
        }],
    );
    let mut duplicate_wrapper: Value =
        serde_json::from_slice(&non_attesting_control.entry.signed_request_bytes).unwrap();
    let duplicate_arm = duplicate_wrapper["body"]["participantChanges"][0].clone();
    duplicate_wrapper["body"]["participantChanges"]
        .as_array_mut()
        .unwrap()
        .push(duplicate_arm);
    duplicate_wrapper["signature"] = json!(STANDARD.encode([0_u8; 64]));
    assert!(
        decode_canonical_signed_mutation(&serde_json::to_vec(&duplicate_wrapper).unwrap()).is_err(),
        "duplicate signed ChangeRole arms passed canonical decoding"
    );
    let non_attesting_old = non_attesting_control.transition;
    let policy = build_signed_policy_apply(
        &pool,
        fixture,
        prior,
        3,
        vec![SignedPolicyChange::ChangeRole {
            user_did: fixture.bob_did.clone(),
            role: "admin",
        }],
        vec![
            (fixture.alice_id.clone(), fixture.alice_did.clone()),
            (fixture.bob_id.clone(), fixture.bob_did.clone()),
        ],
    )
    .await;
    let transition_id = policy.transition_id;
    let applied_at = policy.ctx.applied_at;
    let plan = &policy.plan;
    let ctx = &policy.ctx;

    // All malformed effect shapes are rejected before the head CAS. These
    // probes reuse the same coherent accepted history and leave no policy row.
    for (mutation, expected) in [
        (PolicyPlanMutation::Principal, "inconsistent"),
        (PolicyPlanMutation::Status, "inconsistent"),
        (PolicyPlanMutation::RoleProducer, "inconsistent"),
        (
            PolicyPlanMutation::OldRoleProducer(non_attesting_old),
            "inconsistent",
        ),
        (PolicyPlanMutation::DuplicateDelta, "inconsistent"),
        (PolicyPlanMutation::Remove, "inconsistent"),
    ] {
        assert_policy_prewrite_rejection(
            &pool,
            &plan.clone().with_policy_mutation_for_test(mutation),
            ctx,
            conversation_id,
            expected,
        )
        .await;
    }
    for drift in ["old-role", "current-membership"] {
        assert_policy_role_cas_conflict_rolls_back(
            &pool,
            plan,
            ctx,
            conversation_id,
            &fixture.bob_did,
            drift,
        )
        .await;
    }

    let metadata_before: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT to_jsonb(m) FROM chat.metadata_snapshots m \
         WHERE conversation_id=$1 ORDER BY metadata_snapshot_id",
    )
    .bind(conversation_id)
    .fetch_all(&pool)
    .await
    .expect("complete retained metadata before policy");
    let participant_non_role_before: serde_json::Value = sqlx::query_scalar(
        "SELECT to_jsonb(p) - ARRAY['role','role_transition_id','role_changed_at'] \
         FROM chat.participants p \
         WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&fixture.bob_did)
    .fetch_one(&pool)
    .await
    .expect("participant before policy");

    let mut transaction = pool.begin().await.expect("begin signed ChangeRole");
    let applied =
        apply_conversation_persistence_plan_unscoped_for_test(&mut transaction, plan, ctx)
            .await
            .expect("signed ChangeRole policy applies");
    transaction
        .commit()
        .await
        .expect("signed ChangeRole COMMIT past deferred checks");
    assert_eq!(applied.allocated_seq, 3);

    let (role, role_transition_id, role_changed_at): (String, Uuid, DateTime<Utc>) =
        sqlx::query_as(
            "SELECT role,role_transition_id,role_changed_at FROM chat.participants \
             WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
        )
        .bind(conversation_id)
        .bind(&fixture.bob_did)
        .fetch_one(&pool)
        .await
        .expect("fresh transaction observes changed role");
    assert_eq!(role, "admin");
    assert_eq!(role_transition_id, transition_id);
    assert_eq!(role_changed_at, applied_at);
    let metadata_after: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT to_jsonb(m) FROM chat.metadata_snapshots m \
         WHERE conversation_id=$1 ORDER BY metadata_snapshot_id",
    )
    .bind(conversation_id)
    .fetch_all(&pool)
    .await
    .expect("complete retained metadata after policy");
    assert_eq!(
        metadata_after, metadata_before,
        "policy head rewrote prior metadata snapshot/author/origin bytes"
    );
    let participant_non_role_after: serde_json::Value = sqlx::query_scalar(
        "SELECT to_jsonb(p) - ARRAY['role','role_transition_id','role_changed_at'] \
         FROM chat.participants p \
         WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&fixture.bob_did)
    .fetch_one(&pool)
    .await
    .expect("participant after policy");
    assert_eq!(
        participant_non_role_after, participant_non_role_before,
        "executor role update changed a non-role participant column"
    );

    // A genuinely signed mixed Add+ChangeRole body is classified in full before
    // writes. First force the role CAS to fail and prove the Add cannot leak;
    // then apply the same plan successfully.
    let (third_id, third_did) = loop {
        let candidate = fresh_bob();
        if candidate.1.as_bytes() < fixture.bob_did.as_bytes() {
            break candidate;
        }
    };
    assert!(
        third_did.as_bytes() < fixture.bob_did.as_bytes(),
        "mixed Add must sort before the failing role CAS"
    );
    let third_device = Uuid::from_bytes(*third_id.device_id());
    let _ = seed_actor(&pool, &third_did, third_device, &[0xA7_u8; 32]).await;
    let mixed_changes = vec![
        SignedPolicyChange::ChangeRole {
            user_did: fixture.bob_did.clone(),
            role: "member",
        },
        SignedPolicyChange::Add(third_did.clone()),
    ];
    let mixed = build_signed_policy_apply(
        &pool,
        fixture,
        &policy.state,
        4,
        mixed_changes,
        vec![
            (fixture.alice_id.clone(), fixture.alice_did.clone()),
            (fixture.bob_id.clone(), fixture.bob_did.clone()),
            (third_id, third_did.clone()),
        ],
    )
    .await;
    let mixed_transition_id = mixed.transition_id;
    for participant_period_ids in [vec![], vec![Uuid::new_v4(), Uuid::new_v4()]] {
        let mut malformed_ctx = mixed.ctx.clone();
        malformed_ctx.participant_period_ids = participant_period_ids;
        assert_policy_prewrite_rejection(
            &pool,
            &mixed.plan,
            &malformed_ctx,
            conversation_id,
            "inconsistent",
        )
        .await;
    }

    let mut mixed_conflict = pool.begin().await.expect("begin mixed CAS conflict");
    sqlx::query(
        "UPDATE chat.participants \
            SET role='member',role_transition_id=$3,role_changed_at=clock_timestamp() \
          WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&fixture.bob_did)
    .bind(Uuid::new_v4())
    .execute(&mut *mixed_conflict)
    .await
    .expect("drift mixed role CAS target");
    let mixed_result = apply_conversation_persistence_plan_unscoped_for_test(
        &mut mixed_conflict,
        &mixed.plan,
        &mixed.ctx,
    )
    .await;
    assert!(matches!(
        mixed_result,
        Err(ExecutorError::Transition(
            TransitionRepositoryError::CompareAndSetConflict
        ))
    ));
    let staged_add: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.participants WHERE conversation_id=$1 AND user_did=$2",
    )
    .bind(conversation_id)
    .bind(&third_did)
    .fetch_one(&mut *mixed_conflict)
    .await
    .expect("read staged Add before rollback");
    assert_eq!(
        staged_add, 1,
        "deterministically earlier Add did not execute before role CAS"
    );
    mixed_conflict
        .rollback()
        .await
        .expect("rollback mixed CAS conflict");
    let leaked_add: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.participants WHERE conversation_id=$1 AND user_did=$2",
    )
    .bind(conversation_id)
    .bind(&third_did)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(leaked_add, 0, "mixed CAS failure leaked its Add");

    let mut mixed_tx = pool.begin().await.expect("begin mixed policy");
    apply_conversation_persistence_plan_unscoped_for_test(&mut mixed_tx, &mixed.plan, &mixed.ctx)
        .await
        .expect("mixed Add+ChangeRole applies");
    mixed_tx
        .commit()
        .await
        .expect("mixed Add+ChangeRole COMMIT");
    let mixed_roles: Vec<(String, String, String, Uuid)> = sqlx::query_as(
        "SELECT user_did,status,role,role_transition_id FROM chat.participants \
         WHERE conversation_id=$1 AND user_did IN ($2,$3) AND current_membership \
         ORDER BY user_did",
    )
    .bind(conversation_id)
    .bind(&fixture.bob_did)
    .bind(&third_did)
    .fetch_all(&pool)
    .await
    .expect("mixed participant rows");
    assert_eq!(mixed_roles.len(), 2);
    for (did, status, role, producer) in mixed_roles {
        assert_eq!(producer, mixed_transition_id);
        if did == fixture.bob_did {
            assert_eq!((status.as_str(), role.as_str()), ("active", "member"));
        } else {
            assert_eq!((status.as_str(), role.as_str()), ("pending", "member"));
        }
    }
}

#[tokio::test]
async fn direct_creation_commits_with_direct_pair_shape() {
    let (pool, _db) = setup().await;
    let fixture = build_creation(&pool, ConversationKind::Direct).await;
    let conversation_id = fixture.conversation_id;
    let mut tx = pool.begin().await.expect("begin");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &fixture.plan, &fixture.ctx)
        .await
        .expect("direct creation applies");
    tx.commit().await.expect("COMMIT");

    let (kind, low, high): (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT kind,direct_did_low,direct_did_high FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!(kind, "direct");
    assert!(low.is_some() && high.is_some());
    assert!(low.as_deref() < high.as_deref());
    let admins: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.participants WHERE conversation_id=$1 AND current_membership AND role='admin'",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("admins");
    assert_eq!(admins, 2);
}

#[tokio::test]
async fn creation_failure_injection_rolls_back_whole_graph() {
    let (pool, _db) = setup().await;
    let fixture = build_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    let mut tx = pool.begin().await.expect("begin");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &fixture.plan, &fixture.ctx)
        .await
        .expect("apply");
    // Force a mid-transaction failure: a duplicate entry at (conversation_id, 1).
    let dup = sqlx::query(
        r#"INSERT INTO chat.entries(conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
            accepted_payload_sha256,signed_request_bytes,request_digest,signature,server_fields_bytes,
            outer_entry_fingerprint,actor_did,actor_device_id,actor_key_id,actor_auth_generation,
            generation,state_version,transition_id,received_at)
           VALUES($1,1,$2,'blue.catbird.chat.defs#creationEntry',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,0,0,$13,$14)"#,
    )
    .bind(conversation_id)
    .bind(Uuid::new_v4())
    .bind(vec![1_u8; 4])
    .bind(Sha256::digest([1_u8; 4]).to_vec())
    .bind(vec![2_u8; 4])
    .bind(Sha256::digest([2_u8; 4]).to_vec())
    .bind(vec![3_u8; 64])
    .bind(vec![4_u8; 8])
    .bind(vec![5_u8; 32])
    .bind(&fixture.alice_did)
    .bind(fixture.alice_device)
    .bind(Uuid::new_v4())
    .bind(clock_now(&pool).await)
    .execute(&mut *tx)
    .await;
    assert!(
        dup.is_err(),
        "duplicate seq must violate the primary key mid-tx"
    );
    tx.rollback().await.expect("rollback");
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.conversations WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.transitions WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.participants WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        0
    );
}

async fn commit_creation(pool: &PgPool, kind: ConversationKind) -> CreationApply {
    let fixture = build_creation(pool, kind).await;
    let mut tx = pool.begin().await.expect("begin creation");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &fixture.plan, &fixture.ctx)
        .await
        .expect("creation applies");
    tx.commit().await.expect("creation COMMIT");
    fixture
}

struct AcceptedGroupFixture {
    fixture: CreationApply,
    state: ConversationState,
}

struct PolicyApplyFixture {
    plan: chat_protocol::state_machine::ConversationPersistencePlan,
    state: ConversationState,
    ctx: ExecutionContext,
    transition_id: Uuid,
}

async fn build_signed_policy_apply(
    pool: &PgPool,
    fixture: &CreationApply,
    prior: &ConversationState,
    seq: u64,
    changes: Vec<SignedPolicyChange>,
    mut audience: Vec<(DeviceIdentity, String)>,
) -> PolicyApplyFixture {
    let add_count = changes
        .iter()
        .filter(|change| matches!(change, SignedPolicyChange::Add(_)))
        .count();
    let signed = signed_policy_control(fixture, prior, seq, changes);
    assert_eq!(
        signed
            .transition
            .signed_authority()
            .map(|authority| authority.kind()),
        Some(chat_protocol::transcript::SignedMutationKind::PolicyTransition)
    );
    let transition_id = signed.transition_id;
    let planned = plan_policy(
        prior,
        fixture.alice_id.clone(),
        signed.transition,
        Sha256::digest(transition_id.as_bytes()).into(),
    )
    .expect("genuine signed policy plan");
    let state = planned.resulting_state().clone();
    let head = ConversationHeadCasBinding::for_test_edge(
        *fixture.conversation_id.as_bytes(),
        *signed.entry.entry_id.as_bytes(),
        *prior.coordinate(),
        seq,
        signed.received_at,
    );
    let plan = persistence_plan_for_test(planned, head);

    audience.sort_by(|left, right| {
        (left.1.as_bytes(), left.0.device_id()).cmp(&(right.1.as_bytes(), right.0.device_id()))
    });
    let entry_recipients = audience
        .iter()
        .map(|(device, _)| (device.clone(), EntryEntitlementKind::Control))
        .collect();
    let mut event_recipients = Vec::new();
    for (device, did) in &audience {
        event_recipients.push((
            device.clone(),
            EventEntitlementKind::Participant,
            device_event_predecessor(pool, did, Uuid::from_bytes(*device.device_id())).await,
        ));
    }
    let marker = u8::try_from(seq).unwrap();
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at: clock_now(pool).await,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(signed.entry),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![marker; 16],
            public_snapshot_sha256: Sha256::digest([marker; 16]).to_vec(),
            tree_summary_bytes: vec![marker | 0x80; 16],
            tree_summary_sha256: Sha256::digest([marker | 0x80; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: (0..add_count).map(|_| Uuid::new_v4()).collect(),
        leaf_period_ids: vec![],
        entry_recipients,
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![marker; 8],
            recipients: event_recipients,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    PolicyApplyFixture {
        plan,
        state,
        ctx,
        transition_id,
    }
}

/// Commit the creation and acceptance edges needed for an active/member role
/// target. The policy edge built on top of this fixture is independently signed
/// and admitted through the production control-entry authority below.
async fn commit_accepted_group(pool: &PgPool) -> AcceptedGroupFixture {
    let fixture = commit_creation(pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    let bob_device = Uuid::from_bytes(*fixture.bob_id.device_id());
    let bob_period: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants \
         WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&fixture.bob_did)
    .fetch_one(pool)
    .await
    .expect("Bob pending participant period");
    let key_package_ref = random_ref32();
    let package_not_after = seed_key_package(
        pool,
        &fixture.bob_did,
        bob_device,
        &fixture.bob_key_id,
        &key_package_ref,
    )
    .await;
    let package_not_after_ts =
        ServerTimestamp::from_unix_millis_for_test(package_not_after.timestamp_millis()).unwrap();
    let received_at = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 3_000,
    )
    .unwrap();
    let entry_id = Uuid::new_v4();
    let transition_id = Uuid::new_v4();
    let recovery_request_id = *Uuid::new_v4().as_bytes();
    let evidence = TransitionEvidence::for_test_acceptance(
        2,
        *transition_id.as_bytes(),
        [0x16_u8; 32],
        received_at,
        fixture.coordinate,
        recovery_request_id,
        fixture.bob_id.clone(),
        fixture.creation_transition_id,
        fixture.alice_id.clone(),
        key_package_ref,
        Sha256::digest([0x62_u8; 32]).into(),
        1,
        package_not_after_ts,
    )
    .unwrap();
    let planned = plan_accept_conversation(
        &fixture.state,
        AcceptConversation {
            actor: fixture.bob_id.clone(),
            transition: evidence,
            recovery_request_id,
            key_package_ref,
            package_not_after: package_not_after_ts,
        },
    )
    .expect("coherent acceptance plan");
    let state = planned.resulting_state().clone();
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        2,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);
    let ctx = acceptance_ctx(
        pool,
        &fixture,
        &fixture.bob_id,
        &fixture.bob_did,
        &fixture.bob_key_id,
        entry_id,
        bob_period,
        package_not_after,
    )
    .await;
    let mut transaction = pool.begin().await.expect("begin acceptance");
    apply_conversation_persistence_plan_unscoped_for_test(&mut transaction, &plan, &ctx)
        .await
        .expect("acceptance applies");
    transaction
        .commit()
        .await
        .expect("acceptance COMMIT past deferred checks");
    AcceptedGroupFixture { fixture, state }
}

async fn assert_policy_prewrite_rejection(
    pool: &PgPool,
    plan: &chat_protocol::state_machine::ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    expected: &'static str,
) {
    let mut transaction = pool.begin().await.expect("begin policy rejection");
    let head_before: (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations \
         WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&mut *transaction)
    .await
    .expect("read head before pre-write rejection");
    let policy_rows_before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.transitions \
         WHERE conversation_id=$1 AND kind='policy'",
    )
    .bind(conversation_id)
    .fetch_one(&mut *transaction)
    .await
    .expect("count policy rows before rejection");
    let result =
        apply_conversation_persistence_plan_unscoped_for_test(&mut transaction, plan, ctx).await;
    match (expected, result) {
        ("inconsistent", Err(ExecutorError::InconsistentPlan(_))) => {}
        (_, other) => panic!("unexpected policy rejection for {expected}: {other:?}"),
    }
    let head_after: (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations \
         WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&mut *transaction)
    .await
    .expect("read head after pre-write rejection");
    assert_eq!(head_after, head_before, "pre-write rejection changed head");
    let policy_rows_after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.transitions \
         WHERE conversation_id=$1 AND kind='policy'",
    )
    .bind(conversation_id)
    .fetch_one(&mut *transaction)
    .await
    .expect("count policy rows after rejection");
    assert_eq!(
        policy_rows_after, policy_rows_before,
        "pre-write rejection inserted a policy row"
    );
    transaction
        .rollback()
        .await
        .expect("rollback policy rejection");
}

async fn assert_policy_role_cas_conflict_rolls_back(
    pool: &PgPool,
    plan: &chat_protocol::state_machine::ConversationPersistencePlan,
    ctx: &ExecutionContext,
    conversation_id: Uuid,
    target_did: &str,
    drift: &'static str,
) {
    let mut transaction = pool.begin().await.expect("begin role CAS drift");
    match drift {
        "old-role" => {
            sqlx::query(
                "UPDATE chat.participants p \
                    SET role='admin', \
                        role_transition_id=t.transition_id, \
                        role_changed_at=t.accepted_at \
                   FROM chat.transitions t \
                  WHERE p.conversation_id=$1 AND p.user_did=$2 \
                    AND p.current_membership AND t.conversation_id=p.conversation_id \
                    AND t.kind='acceptConversation'",
            )
            .bind(conversation_id)
            .bind(target_did)
            .execute(&mut *transaction)
            .await
            .expect("drift stored old role");
        }
        "current-membership" => {
            sqlx::query(
                "UPDATE chat.participants p \
                    SET current_membership=FALSE, \
                        removing_transition_id=t.transition_id, \
                        removing_seq=t.entry_seq, \
                        removed_at=t.accepted_at \
                   FROM chat.transitions t \
                  WHERE p.conversation_id=$1 AND p.user_did=$2 \
                    AND p.current_membership AND t.conversation_id=p.conversation_id \
                    AND t.kind='acceptConversation'",
            )
            .bind(conversation_id)
            .bind(target_did)
            .execute(&mut *transaction)
            .await
            .expect("drift stored current-membership");
        }
        _ => unreachable!("unknown role CAS drift"),
    }
    let result =
        apply_conversation_persistence_plan_unscoped_for_test(&mut transaction, plan, ctx).await;
    assert!(
        matches!(
            result,
            Err(ExecutorError::Transition(
                TransitionRepositoryError::CompareAndSetConflict
            ))
        ),
        "{drift} must surface the typed participant role CAS conflict, got {result:?}"
    );
    transaction
        .rollback()
        .await
        .expect("rollback role CAS drift");

    let (state_version, next_entry_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations \
         WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(pool)
    .await
    .expect("fresh head after role CAS rollback");
    assert_eq!((state_version, next_entry_seq), (1, 3));
    let (role, current): (String, bool) = sqlx::query_as(
        "SELECT role,current_membership FROM chat.participants \
         WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(target_did)
    .fetch_one(pool)
    .await
    .expect("fresh participant after role CAS rollback");
    assert_eq!((role.as_str(), current), ("member", true));
    let policy_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.transitions \
         WHERE conversation_id=$1 AND kind='policy'",
    )
    .bind(conversation_id)
    .fetch_one(pool)
    .await
    .expect("policy rows after role CAS rollback");
    assert_eq!(policy_rows, 0);
}

#[tokio::test]
async fn direct_close_commits_terminal_graph_and_reapply_conflicts() {
    let (pool, _db) = setup().await;
    let fixture = commit_creation(&pool, ConversationKind::Direct).await;
    let conversation_id = fixture.conversation_id;

    // The creator's committed genesis leaf period (the interval's closing leaf).
    let leaf_period_id: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("genesis leaf period");

    // Build the REAL close plan. Close entry is seq 2 (> the creation seq 1).
    let received_at = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 3_000,
    )
    .unwrap();
    let entry_id = Uuid::new_v4();
    let transition_id = Uuid::new_v4();
    let close_evidence =
        TransitionEvidence::for_test_at(2, *transition_id.as_bytes(), [0x13_u8; 32], received_at)
            .unwrap();
    let planned = plan_close(
        &fixture.state,
        CloseConversation {
            actor: fixture.alice_id.clone(),
            transition: close_evidence,
        },
    )
    .expect("valid close plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        2,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let applied_at = clock_now(&pool).await;
    let alice_pred =
        device_event_predecessor(&pool, &fixture.alice_did, fixture.alice_device).await;
    let ctx = close_ctx(&fixture, entry_id, applied_at, leaf_period_id, alice_pred);

    let mut tx = pool.begin().await.expect("begin close");
    let applied = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("close applies");
    tx.commit()
        .await
        .expect("close COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 2);

    // Head superseded with the close coordinate.
    let (lifecycle, ct, cseq): (String, Option<Uuid>, Option<i64>) = sqlx::query_as(
        "SELECT lifecycle,close_transition_id,close_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!(lifecycle, "superseded");
    assert_eq!(ct, Some(transition_id));
    assert_eq!(cseq, Some(2));
    // Generation superseded; superseded closeConversation state at sv 1.
    let gen_life: String = sqlx::query_scalar(
        "SELECT lifecycle FROM chat.generations WHERE conversation_id=$1 AND generation=0",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("gen");
    assert_eq!(gen_life, "superseded");
    let (skind, slife): (String, String) = sqlx::query_as(
        "SELECT state_kind,lifecycle FROM chat.generation_states WHERE conversation_id=$1 AND state_version=1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("close state");
    assert_eq!(
        (skind.as_str(), slife.as_str()),
        ("closeConversation", "superseded")
    );
    // Interval closed with a Terminal proof at the close seq.
    let (tseq, ckind): (Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT terminal_seq,closing_kind FROM chat.application_intervals WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("interval");
    assert_eq!((tseq, ckind.as_deref()), (Some(2), Some("terminal")));
    // One schedule terminal proof; a retained scheduleTerminal audience row.
    assert_eq!(count(&pool, "SELECT count(*) FROM chat.application_schedule_terminal_proofs WHERE conversation_id=$1", conversation_id).await, 1);
    let sched_recips: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.entry_recipients WHERE conversation_id=$1 AND seq=2 AND entitlement_kind='scheduleTerminal'",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("sched recipients");
    assert_eq!(sched_recips, 1);
    // The single conversation-close tombstone event.
    let evt_kind: String =
        sqlx::query_scalar("SELECT event_kind FROM chat.events WHERE event_position=$1")
            .bind(applied.event_positions[0])
            .fetch_one(&pool)
            .await
            .expect("event");
    assert_eq!(evt_kind, "conversationClosed");

    // Re-apply the same close plan -> head CAS conflict (the head is already
    // superseded), whole transaction rolls back with zero residue.
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut tx2 = pool.begin().await.expect("begin re-close");
    let reapply =
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(reapply, Err(ExecutorError::Transition(_))),
        "re-close must conflict, got {reapply:?}"
    );
    tx2.rollback().await.expect("rollback");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "re-close left zero residue");
}

fn close_ctx(
    fixture: &CreationApply,
    entry_id: Uuid,
    applied_at: DateTime<Utc>,
    leaf_period_id: Uuid,
    alice_pred: Option<i64>,
) -> ExecutionContext {
    let payload = vec![0x31_u8; 12];
    let transcript = vec![0x32_u8; 12];
    ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: chat_protocol::repository::transition::TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#conversationCloseEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x33_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0x34_u8; 64],
            server_fields_bytes: vec![0x35_u8; 8],
            outer_entry_fingerprint: vec![0x13_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0x41_u8; 16],
            public_snapshot_sha256: Sha256::digest([0x41_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0x42_u8; 16],
            tree_summary_sha256: Sha256::digest([0x42_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![(
            fixture.alice_id.clone(),
            chat_protocol::repository::delivery::EntryEntitlementKind::ScheduleTerminal,
        )],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationClosed,
            payload_bytes: vec![0x51_u8; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![(fixture.alice_id.clone(), leaf_period_id)],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    }
}

/// Arm 3 #3 close-gap fix (review finding): a close is REACHABLE while a
/// leaf-recovery request is open — here a direct 1:1 whose active party opened a
/// `replace` request for her leaf, then closes (a group-of-1 admin closing after
/// her own request is the same shape). `plan_close` calls
/// `resolve_prior_bound_work` unconditionally, so the close plan carries the
/// request (Open->Superseded) + reservation (Active->Released) + package
/// (Reserved->Available). Before the fix `apply_close` `reject_if_present`
/// HARD-ERRORED this legal close; now it composes the shared supersession and the
/// close SUCCEEDS (request superseded / reservation released / package available).
#[tokio::test]
async fn close_supersedes_pending_leaf_recovery_request() {
    let (pool, _db) = setup().await;
    let fixture = commit_creation(&pool, ConversationKind::Direct).await;
    let conversation_id = fixture.conversation_id;

    // Alice (the active party) opens a `replace` leaf-recovery request for her leaf.
    let committed = commit_replace_recovery_request(&pool, &fixture, 0x71).await;
    let request_id = committed.request_id;
    let key_package_ref = committed.key_package_ref;

    let leaf_period_id: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2",
    )
    .bind(conversation_id)
    .bind(&fixture.alice_did)
    .fetch_one(&pool)
    .await
    .expect("alice leaf period");

    // Alice closes the group WHILE the recovery request is pending (close entry seq 2).
    let close_received = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 5_000,
    )
    .unwrap();
    let entry_id = Uuid::new_v4();
    let close_transition = Uuid::new_v4();
    // The close entry fingerprint MUST equal `close_ctx`'s entry outer fingerprint
    // ([0x13; 32]) — the interval-close provenance FK binds them.
    let close_evidence = TransitionEvidence::for_test_at(
        2,
        *close_transition.as_bytes(),
        [0x13_u8; 32],
        close_received,
    )
    .unwrap();
    let planned = plan_close(
        &committed.state,
        CloseConversation {
            actor: fixture.alice_id.clone(),
            transition: close_evidence,
        },
    )
    .expect("valid close plan with a pending recovery request");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        2,
        close_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);
    let applied_at = clock_now(&pool).await;
    let alice_pred =
        device_event_predecessor(&pool, &fixture.alice_did, fixture.alice_device).await;
    let ctx = close_ctx(&fixture, entry_id, applied_at, leaf_period_id, alice_pred);

    let mut tx = pool.begin().await.expect("begin close");
    let applied = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("close with a pending recovery request applies");
    tx.commit()
        .await
        .expect("close COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 2);

    // The conversation is closed DESPITE the pending request.
    let lifecycle: String =
        sqlx::query_scalar("SELECT lifecycle FROM chat.conversations WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .expect("head");
    assert_eq!(lifecycle, "superseded");
    // The prior-bound recovery work is superseded/released/reactivated.
    let req_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(request_id)
    .fetch_one(&pool)
    .await
    .expect("request");
    assert_eq!(req_status, "superseded");
    let res_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.key_package_reservations WHERE recovery_request_id=$1",
    )
    .bind(request_id)
    .fetch_one(&pool)
    .await
    .expect("reservation");
    assert_eq!(res_status, "released");
    let pkg_status: String =
        sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE key_package_ref=$1")
            .bind(key_package_ref.to_vec())
            .fetch_one(&pool)
            .await
            .expect("package");
    assert_eq!(pkg_status, "available");

    // Replay -> head CAS conflict (head already superseded), zero residue.
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan_unscoped_for_test(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Transition(_))),
        "close replay must conflict on the head CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "close replay left zero residue");
}

#[tokio::test]
async fn reset_request_commits_without_changing_the_coordinate() {
    let (pool, _db) = setup().await;
    let fixture = commit_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;

    // A reset request by the active admin (alice). Non-mutating: seq advances, the
    // (generation,state_version) coordinate must be untouched.
    let request_id = Uuid::new_v4();
    let received_at = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 3_000,
    )
    .unwrap();
    let evidence = RequestEvidence::for_test(
        RequestEntryKind::ResetRequest,
        2,
        *request_id.as_bytes(),
        fixture.alice_id.clone(),
        *conversation_id.as_bytes(),
        received_at,
        0x61,
    )
    .unwrap();
    let planned = plan_reset_request(
        &fixture.state,
        ResetRequestCommand {
            actor: fixture.alice_id.clone(),
            reset_request_id: *request_id.as_bytes(),
            received_at,
            evidence,
        },
    )
    .expect("valid reset request plan");
    let entry_id = Uuid::new_v4();
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        2,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    // The reset-request entry and the reset_requests row MUST carry identical
    // signed bytes / digest / signature / received_at (the entry↔request mapping
    // trigger); source both from the same values.
    let applied_at = clock_now(&pool).await;
    let transcript = vec![0x62_u8; 16];
    let request_digest = Sha256::digest(&transcript).to_vec();
    let signature = vec![0x63_u8; 64];
    let alice_pred =
        device_event_predecessor(&pool, &fixture.alice_did, fixture.alice_device).await;
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: chat_protocol::repository::transition::TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#resetRequestEntry".to_owned(),
            accepted_payload_bytes: vec![0x64_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x64_u8; 8]).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x65_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: request_digest.clone(),
            signature: signature.clone(),
            server_fields_bytes: vec![0x66_u8; 8],
            outer_entry_fingerprint: vec![0x14_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![(
            fixture.alice_id.clone(),
            chat_protocol::repository::delivery::EntryEntitlementKind::Control,
        )],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ResetRequested,
            payload_bytes: vec![0x67_u8; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: Some(ResetRequestRow {
            reset_request_id: request_id,
            reason: ResetReason::PoisonedState,
            signed_request_bytes: transcript.clone(),
            signing_transcript_bytes: transcript.clone(),
            request_digest,
            signature,
            expires_at: applied_at + Duration::hours(24),
        }),
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };

    let mut tx = pool.begin().await.expect("begin reset");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("reset request applies");
    tx.commit().await.expect("reset request COMMIT");

    // Coordinate UNTOUCHED (still 0,0 active); only the seq advanced.
    let (gen, sv, next_seq, lifecycle): (i64, i64, i64, String) = sqlx::query_as(
        "SELECT current_generation,current_state_version,next_entry_seq,lifecycle FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((gen, sv, next_seq, lifecycle.as_str()), (0, 0, 3, "active"));
    // A pending reset request row + a resetRequestEntry, no new transition.
    let (status,): (String,) =
        sqlx::query_as("SELECT status FROM chat.reset_requests WHERE reset_request_id=$1")
            .bind(request_id)
            .fetch_one(&pool)
            .await
            .expect("reset request row");
    assert_eq!(status, "pending");
    let entry_kind: String = sqlx::query_scalar(
        "SELECT entry_kind FROM chat.entries WHERE conversation_id=$1 AND seq=2",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("entry");
    assert_eq!(entry_kind, "blue.catbird.chat.defs#resetRequestEntry");
    // No transition row was produced by the reset request (it is non-mutating).
    let transitions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .expect("transitions");
    assert_eq!(transitions, 1, "only the creation transition exists");
}

/// Build + commit a reset request by the active admin (alice) and return the
/// resulting in-memory state (with the pending request) + the request id.
async fn commit_reset_request(
    pool: &PgPool,
    fixture: &CreationApply,
    request_seq: u64,
    received_at: ServerTimestamp,
) -> (chat_protocol::state_machine::ConversationState, Uuid) {
    let conversation_id = fixture.conversation_id;
    let request_id = Uuid::new_v4();
    let evidence = RequestEvidence::for_test(
        RequestEntryKind::ResetRequest,
        request_seq,
        *request_id.as_bytes(),
        fixture.alice_id.clone(),
        *conversation_id.as_bytes(),
        received_at,
        0x61,
    )
    .unwrap();
    let planned = plan_reset_request(
        &fixture.state,
        ResetRequestCommand {
            actor: fixture.alice_id.clone(),
            reset_request_id: *request_id.as_bytes(),
            received_at,
            evidence,
        },
    )
    .expect("valid reset request plan");
    let state = planned.resulting_state().clone();
    let entry_id = Uuid::new_v4();
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        request_seq,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);
    let applied_at = clock_now(pool).await;
    let transcript = vec![0x62_u8; 16];
    let request_digest = Sha256::digest(&transcript).to_vec();
    let signature = vec![0x63_u8; 64];
    let pred = device_event_predecessor(pool, &fixture.alice_did, fixture.alice_device).await;
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: chat_protocol::repository::transition::TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#resetRequestEntry".to_owned(),
            accepted_payload_bytes: vec![0x64_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x64_u8; 8]).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x65_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: request_digest.clone(),
            signature: signature.clone(),
            server_fields_bytes: vec![0x66_u8; 8],
            outer_entry_fingerprint: vec![0x14_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![(
            fixture.alice_id.clone(),
            chat_protocol::repository::delivery::EntryEntitlementKind::Control,
        )],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ResetRequested,
            payload_bytes: vec![0x67_u8; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: Some(ResetRequestRow {
            reset_request_id: request_id,
            reason: ResetReason::PoisonedState,
            signed_request_bytes: transcript.clone(),
            signing_transcript_bytes: transcript,
            request_digest,
            signature,
            expires_at: applied_at + Duration::hours(24),
        }),
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    let mut tx = pool.begin().await.expect("begin reset request");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("reset request applies");
    tx.commit().await.expect("reset request COMMIT");
    (state, request_id)
}

#[tokio::test]
async fn reset_activation_commits_two_generation_graph_and_conflicts_on_replay() {
    let (pool, _db) = setup().await;
    let fixture = commit_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    let manifest = corpus_manifest();

    // Reset request (seq 2) by the active admin, committed; returns the state that
    // carries the pending request (the activation's prior).
    let req_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 3_000,
    )
    .unwrap();
    let (reset_state, request_id) = commit_reset_request(&pool, &fixture, 2, req_received).await;

    // Committed old-generation identifiers the activation reuses/closes.
    let old_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND generation=0",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("old leaf period");
    let participant_rows: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT user_did,participant_period_id FROM chat.participants WHERE conversation_id=$1 AND current_membership",
    )
    .bind(conversation_id)
    .fetch_all(&pool)
    .await
    .expect("participant periods");

    // Successor coordinate: generation+1, sv0, epoch0, FRESH group/hash/tag.
    let successor_coordinate = chat_protocol::snapshot::PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        fixture.coordinate.generation() + 1,
        0,
        [0x71; 32],
        0,
        [0x72; 32],
        [0x73; 32],
        chat_protocol::snapshot::PublicGroupSnapshotLifecycle::Active,
    );
    let successor_public_state =
        ActivePublicState::for_test(&verified_genesis(&manifest), successor_coordinate);
    let retired_coordinate = chat_protocol::snapshot::PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        fixture.coordinate.generation(),
        fixture.coordinate.state_version() + 1,
        *fixture.coordinate.group_id(),
        fixture.coordinate.epoch(),
        *fixture.coordinate.group_context_hash(),
        *fixture.coordinate.confirmation_tag(),
        chat_protocol::snapshot::PublicGroupSnapshotLifecycle::Superseded,
    );

    let act_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 4_000,
    )
    .unwrap();
    let transition_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    let alice_sig_key: Vec<u8> =
        hex::decode(&manifest.identity.alice.signature_public_key_hex).unwrap();
    let nonce = [0x78_u8; 12];
    let ciphertext = vec![0x79_u8; 48];
    let metadata = MetadataSnapshotBinding::for_test_creation(
        *conversation_id.as_bytes(),
        1,
        0,
        [0x72; 32],
        *transition_id.as_bytes(),
        3,
        fixture.alice_id.clone(),
        Sha256::digest(&alice_sig_key).into(),
        alice_sig_key.clone().try_into().unwrap(),
        1,
        2,
        nonce,
        ciphertext,
    );
    let evidence = TransitionEvidence::for_test_reset_activation_with_metadata(
        3,
        *transition_id.as_bytes(),
        [0x15_u8; 32],
        act_received,
        ConversationKind::Group,
        *request_id.as_bytes(),
        fixture.coordinate,
        retired_coordinate,
        successor_coordinate,
        fixture.alice_id.clone(),
        metadata,
    )
    .unwrap();
    let planned = plan_reset_activation(
        &reset_state,
        ResetActivation {
            actor: fixture.alice_id.clone(),
            reset_request_id: *request_id.as_bytes(),
            transition: evidence,
            successor_public_state,
        },
    )
    .expect("valid reset activation plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        3,
        act_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    // Participant periods in hydration (sorted-DID) order.
    let mut sorted_participants = participant_rows.clone();
    sorted_participants.sort_by(|l, r| l.0.as_bytes().cmp(r.0.as_bytes()));
    let participant_period_ids: Vec<Uuid> = sorted_participants.iter().map(|(_, id)| *id).collect();

    let applied_at = clock_now(&pool).await;
    let payload = vec![0x81_u8; 12];
    let transcript = vec![0x82_u8; 12];
    let pred = device_event_predecessor(&pool, &fixture.alice_did, fixture.alice_device).await;
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: chat_protocol::repository::transition::TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#resetActivationEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x83_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0x84_u8; 64],
            server_fields_bytes: vec![0x85_u8; 8],
            outer_entry_fingerprint: vec![0x15_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0x91_u8; 16],
            public_snapshot_sha256: Sha256::digest([0x91_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0x92_u8; 16],
            tree_summary_sha256: Sha256::digest([0x92_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![0x93_u8; 16],
            genesis_group_info_sha256: Sha256::digest([0x93_u8; 16]).to_vec(),
        },
        opened_leaves: vec![LeafPersistenceColumns {
            device: fixture.alice_id.clone(),
            leaf_key_id: fixture.alice_key_id.clone(),
            leaf_auth_generation: 1,
        }],
        metadata_author: Some(MetadataAuthorColumns {
            author_role: "admin".to_owned(),
            author_device_status: "active".to_owned(),
            author_public_key: alice_sig_key,
            author_key_id: fixture.alice_key_id.clone(),
            metadata_snapshot_id: Uuid::new_v4(),
        }),
        participant_period_ids,
        leaf_period_ids: vec![Uuid::new_v4()],
        // The activator's OLD interval closes with kind=reset at this seq, so her
        // audience row is intervalClose (the DB binds intervalClose to a
        // remove/replace/reset-closed interval at that terminal seq).
        entry_recipients: vec![(
            fixture.alice_id.clone(),
            chat_protocol::repository::delivery::EntryEntitlementKind::IntervalClose,
        )],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x94_u8; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![(fixture.alice_id.clone(), old_leaf_period)],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };

    let mut tx = pool.begin().await.expect("begin activation");
    let applied = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("reset activation applies");
    tx.commit()
        .await
        .expect("reset activation COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 3);

    // Head moved to the successor pointer.
    let (gen, sv, next_seq, lifecycle): (i64, i64, i64, String) = sqlx::query_as(
        "SELECT current_generation,current_state_version,next_entry_seq,lifecycle FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((gen, sv, next_seq, lifecycle.as_str()), (1, 0, 4, "active"));
    // Old generation superseded; new generation active.
    let (g0_life, g1_life): (String, String) = sqlx::query_as(
        "SELECT (SELECT lifecycle FROM chat.generations WHERE conversation_id=$1 AND generation=0), \
                (SELECT lifecycle FROM chat.generations WHERE conversation_id=$1 AND generation=1)",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("generations");
    assert_eq!(
        (g0_life.as_str(), g1_life.as_str()),
        ("superseded", "active")
    );
    // Retired resetRetirement state (superseded) + resetSuccessor state (active).
    let (retired_kind, retired_life): (String, String) = sqlx::query_as(
        "SELECT state_kind,lifecycle FROM chat.generation_states WHERE conversation_id=$1 AND generation=0 AND state_version=1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("retired state");
    assert_eq!(
        (retired_kind.as_str(), retired_life.as_str()),
        ("resetRetirement", "superseded")
    );
    let (succ_kind, succ_life, succ_epoch): (String, String, i64) = sqlx::query_as(
        "SELECT state_kind,lifecycle,epoch FROM chat.generation_states WHERE conversation_id=$1 AND generation=1 AND state_version=0",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("successor state");
    assert_eq!(
        (succ_kind.as_str(), succ_life.as_str(), succ_epoch),
        ("resetSuccessor", "active", 0)
    );
    // Old interval closed at reset seq (kind reset); activator's new interval open at reset seq.
    let closed_at_reset: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.application_intervals WHERE conversation_id=$1 AND terminal_seq=3 AND closing_kind='reset'",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("closed interval");
    assert_eq!(closed_at_reset, 1);
    let opened_at_reset: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.application_intervals WHERE conversation_id=$1 AND start_seq=3 AND opening_kind='reset' AND terminal_seq IS NULL",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("opened interval");
    assert_eq!(opened_at_reset, 1);
    // New genesis leaf at generation 1; the reset request consumed.
    let g1_leaf: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.member_devices WHERE conversation_id=$1 AND generation=1 AND active",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("g1 leaf");
    assert_eq!(g1_leaf, 1);
    let req_status: String =
        sqlx::query_scalar("SELECT status FROM chat.reset_requests WHERE reset_request_id=$1")
            .bind(request_id)
            .fetch_one(&pool)
            .await
            .expect("reset request status");
    assert_eq!(req_status, "consumed");

    // Replay the activation on the OLD coordinate -> head CAS conflict (head is
    // now at generation 1), whole transaction rolls back with zero residue.
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan_unscoped_for_test(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Transition(_))),
        "second activation must conflict on the head CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "activation replay left zero residue");
}

/// Arm 3 #3 (reset shared-path supersession): a reset activation that retires a
/// generation carrying a PENDING WELCOME supersedes it through the same shared
/// `write_prior_bound_supersessions` + `write_welcome_supersessions` + reconcile
/// path the commit/fulfillment/leave arms use (own counts 0). Builds on
/// `run_fulfillment_scenario` (bob added at gen0/sv2 with a pending welcome bound to
/// gen0/sv2), opens an alice reset request, then activates: gen0 retires, a fresh
/// gen1 forms with alice's genesis leaf, both old intervals Reset-close, and bob's
/// pending welcome terminalizes `superseded`. (The open-recovery-request supersession
/// branch is COVERED-BY-EQUIVALENCE by the shared writer, already exercised by
/// `generic_commit_supersedes_prior_open_recovery_request`.)
#[tokio::test]
async fn reset_activation_supersedes_prior_pending_welcome() {
    let (pool, _db) = setup().await;
    let manifest = corpus_manifest();
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let alice_id = scenario.fixture.alice_id.clone();
    let alice_did = scenario.fixture.alice_did.clone();
    let alice_device = scenario.fixture.alice_device;
    let alice_key_id = scenario.fixture.alice_key_id.clone();
    let alice_sig_key = scenario.alice_sig_key.clone();
    let bob_id = scenario.bob_id.clone();
    let bob_did = scenario.bob_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());
    let protocol_instance_id = scenario.fixture.protocol_instance_id;
    let scenario_welcome_id = scenario.welcome_id;

    // The gen0 leaf periods the reset closes (alice + bob).
    let alice_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2 AND active",
    )
    .bind(conversation_id)
    .bind(&alice_did)
    .fetch_one(&pool)
    .await
    .expect("alice leaf period");
    let bob_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2 AND active",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob leaf period");

    // 1. Alice opens a reset request (seq 4) against the fulfillment coordinate.
    let req_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 5_000,
    )
    .unwrap();
    let reset_request_id = Uuid::new_v4();
    let req_evidence = RequestEvidence::for_test(
        RequestEntryKind::ResetRequest,
        4,
        *reset_request_id.as_bytes(),
        alice_id.clone(),
        *conversation_id.as_bytes(),
        req_received,
        0x91,
    )
    .unwrap();
    let req_planned = plan_reset_request(
        &scenario.fulfillment_state,
        ResetRequestCommand {
            actor: alice_id.clone(),
            reset_request_id: *reset_request_id.as_bytes(),
            received_at: req_received,
            evidence: req_evidence,
        },
    )
    .expect("valid reset request plan");
    let reset_state = req_planned.resulting_state().clone();
    let req_entry = Uuid::new_v4();
    let req_head = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *req_entry.as_bytes(),
        scenario.coordinate,
        4,
        req_received,
    );
    let req_plan = persistence_plan_for_test(req_planned, req_head);
    let req_applied_at = clock_now(&pool).await;
    let req_transcript = vec![0x92_u8; 16];
    let req_digest = Sha256::digest(&req_transcript).to_vec();
    let req_signature = vec![0x93_u8; 64];
    let alice_pred_req = device_event_predecessor(&pool, &alice_did, alice_device).await;
    let req_ctx = ExecutionContext {
        protocol_instance_id,
        applied_at: req_applied_at,
        actor: ExecutionActor {
            user_did: alice_did.clone(),
            device_id: alice_device,
            key_id: alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: req_entry,
            entry_kind: "blue.catbird.chat.defs#resetRequestEntry".to_owned(),
            accepted_payload_bytes: vec![0x94_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x94_u8; 8]).to_vec(),
            signed_request_bytes: req_transcript.clone(),
            unsigned_projection_bytes: vec![0x95_u8; 8],
            signing_transcript_bytes: req_transcript.clone(),
            request_digest: req_digest.clone(),
            signature: req_signature.clone(),
            server_fields_bytes: vec![0x96_u8; 8],
            outer_entry_fingerprint: vec![0x1A_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![(alice_id.clone(), EntryEntitlementKind::Control)],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ResetRequested,
            payload_bytes: vec![0x97_u8; 8],
            recipients: vec![(
                alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred_req,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: Some(ResetRequestRow {
            reset_request_id,
            reason: ResetReason::PoisonedState,
            signed_request_bytes: req_transcript.clone(),
            signing_transcript_bytes: req_transcript,
            request_digest: req_digest,
            signature: req_signature,
            expires_at: req_applied_at + Duration::hours(24),
        }),
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    {
        let mut tx = pool.begin().await.expect("begin reset request");
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &req_plan, &req_ctx)
            .await
            .expect("reset request applies");
        tx.commit()
            .await
            .expect("reset request COMMIT past all deferred triggers");
    }

    // 2. Alice activates the reset (seq 5): gen0 retires, gen1 forms with alice's
    //    genesis leaf, and bob's pending welcome supersedes.
    let successor_coordinate = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        scenario.coordinate.generation() + 1,
        0,
        [0xA1_u8; 32],
        0,
        [0xA2_u8; 32],
        [0xA3_u8; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    let successor_public_state =
        ActivePublicState::for_test(&verified_genesis(&manifest), successor_coordinate);
    let retired_coordinate = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        scenario.coordinate.generation(),
        scenario.coordinate.state_version() + 1,
        *scenario.coordinate.group_id(),
        scenario.coordinate.epoch(),
        *scenario.coordinate.group_context_hash(),
        *scenario.coordinate.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Superseded,
    );
    let act_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 6_000,
    )
    .unwrap();
    let act_transition = Uuid::new_v4();
    let act_entry = Uuid::new_v4();
    let metadata = MetadataSnapshotBinding::for_test_creation(
        *conversation_id.as_bytes(),
        1,
        0,
        [0xA2_u8; 32],
        *act_transition.as_bytes(),
        3,
        alice_id.clone(),
        Sha256::digest(&alice_sig_key).into(),
        alice_sig_key.clone().try_into().unwrap(),
        1,
        2,
        [0xA8_u8; 12],
        vec![0xA9_u8; 48],
    );
    let act_evidence = TransitionEvidence::for_test_reset_activation_with_metadata(
        5,
        *act_transition.as_bytes(),
        [0x1B_u8; 32],
        act_received,
        ConversationKind::Group,
        *reset_request_id.as_bytes(),
        scenario.coordinate,
        retired_coordinate,
        successor_coordinate,
        alice_id.clone(),
        metadata,
    )
    .unwrap();
    let planned = plan_reset_activation(
        &reset_state,
        ResetActivation {
            actor: alice_id.clone(),
            reset_request_id: *reset_request_id.as_bytes(),
            transition: act_evidence,
            successor_public_state,
        },
    )
    .expect("valid reset activation plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *act_entry.as_bytes(),
        scenario.coordinate,
        5,
        act_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    // Participant periods in hydration (sorted-DID) order — alice AND bob remain
    // participants in the reset state (bob without a gen1 leaf until he re-joins).
    let mut participant_rows: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT user_did,participant_period_id FROM chat.participants WHERE conversation_id=$1 AND current_membership",
    )
    .bind(conversation_id)
    .fetch_all(&pool)
    .await
    .expect("participant periods");
    participant_rows.sort_by(|l, r| l.0.as_bytes().cmp(r.0.as_bytes()));
    let participant_period_ids: Vec<Uuid> = participant_rows.iter().map(|(_, id)| *id).collect();

    let applied_at = clock_now(&pool).await;
    let payload = vec![0xAA_u8; 12];
    let transcript = vec![0xAB_u8; 12];
    let alice_pred = device_event_predecessor(&pool, &alice_did, alice_device).await;
    let bob_pred = device_event_predecessor(&pool, &bob_did, bob_device).await;
    let ctx = ExecutionContext {
        protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: alice_did.clone(),
            device_id: alice_device,
            key_id: alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: act_entry,
            entry_kind: "blue.catbird.chat.defs#resetActivationEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0xAC_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0xAD_u8; 64],
            server_fields_bytes: vec![0xAE_u8; 8],
            outer_entry_fingerprint: vec![0x1B_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xB1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xB1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xB2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xB2_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![0xB3_u8; 16],
            genesis_group_info_sha256: Sha256::digest([0xB3_u8; 16]).to_vec(),
        },
        opened_leaves: vec![LeafPersistenceColumns {
            device: alice_id.clone(),
            leaf_key_id: alice_key_id.clone(),
            leaf_auth_generation: 1,
        }],
        metadata_author: Some(MetadataAuthorColumns {
            author_role: "admin".to_owned(),
            author_device_status: "active".to_owned(),
            author_public_key: alice_sig_key.clone(),
            author_key_id: alice_key_id.clone(),
            metadata_snapshot_id: Uuid::new_v4(),
        }),
        participant_period_ids,
        leaf_period_ids: vec![Uuid::new_v4()],
        // Both gen0 devices' intervals Reset-close at this seq, so both route via
        // intervalClose; bob's single event this transition is the welcome disposition.
        entry_recipients: vec![
            (alice_id.clone(), EntryEntitlementKind::IntervalClose),
            (bob_id.clone(), EntryEntitlementKind::IntervalClose),
        ],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0xB4_u8; 8],
            recipients: vec![(
                alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![
            (alice_id.clone(), alice_leaf_period),
            (bob_id.clone(), bob_leaf_period),
        ],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![WelcomeDispositionInput {
            welcome_id: scenario_welcome_id,
            event: EventFanout {
                event_id: Uuid::new_v4(),
                event_kind: EventKind::WelcomeDisposition,
                payload_bytes: vec![0xB5_u8; 8],
                recipients: vec![(bob_id.clone(), EventEntitlementKind::Welcome, bob_pred)],
                outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
            },
        }],
    };

    let mut tx = pool.begin().await.expect("begin reset activation");
    let applied = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("reset activation applies");
    tx.commit()
        .await
        .expect("reset activation COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 5);

    // Head at the gen1 successor pointer; bob's pending welcome superseded.
    let (gen, sv, next_seq): (i64, i64, i64) = sqlx::query_as(
        "SELECT current_generation,current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((gen, sv, next_seq), (1, 0, 6));
    let (welcome_status, terminal_transition_id, terminal_revocation_id): (
        String,
        Option<Uuid>,
        Option<Uuid>,
    ) = sqlx::query_as(
        "SELECT delivery.status,disposition.terminal_transition_id,\
                disposition.terminal_revocation_id \
           FROM chat.welcome_deliveries delivery \
           JOIN chat.welcome_dispositions disposition USING (welcome_id) \
          WHERE delivery.welcome_id=$1",
    )
    .bind(scenario_welcome_id)
    .fetch_one(&pool)
    .await
    .expect("welcome transition supersession");
    assert_eq!(
        (
            welcome_status.as_str(),
            terminal_transition_id,
            terminal_revocation_id
        ),
        ("superseded", Some(act_transition), None)
    );

    // Test-only mutations disable only the immutable-row trigger. The shape
    // CHECK remains immediate, and the initially-deferred source FK + exact
    // Welcome CAS remain live through COMMIT.
    assert_welcome_shape_update_rejects(
        &pool,
        scenario_welcome_id,
        "terminal_transition_id=NULL",
        "superseded Welcome with zero terminal sources",
    )
    .await;
    assert_welcome_shape_update_rejects(
        &pool,
        scenario_welcome_id,
        "terminal_revocation_id=gen_random_uuid()",
        "superseded Welcome with both terminal sources",
    )
    .await;
    assert_welcome_shape_update_rejects(
        &pool,
        scenario_welcome_id,
        "winner_kind='expired'",
        "non-superseded Welcome with a terminal source",
    )
    .await;

    let (producer_transition_id, creation_transition_id): (Uuid, Uuid) = sqlx::query_as(
        r#"
        SELECT bundle.transition_id,
               (
                   SELECT transition_id
                     FROM chat.transitions
                    WHERE conversation_id=bundle.conversation_id
                      AND kind='creation'
               )
          FROM chat.welcome_bundles bundle
         WHERE bundle.welcome_id=$1
        "#,
    )
    .bind(scenario_welcome_id)
    .fetch_one(&pool)
    .await
    .expect("load durable malformed-source candidates");
    assert_welcome_source_commit_rejects(
        &pool,
        scenario_welcome_id,
        "terminal_transition_id=$2,terminal_revocation_id=NULL",
        Some(creation_transition_id),
        "transition source with the wrong prior/full coordinate",
    )
    .await;
    assert_welcome_source_commit_rejects(
        &pool,
        scenario_welcome_id,
        "terminal_transition_id=$2,terminal_revocation_id=NULL",
        Some(producer_transition_id),
        "transition source that is not later than the Welcome entry",
    )
    .await;
    assert_welcome_source_commit_rejects(
        &pool,
        scenario_welcome_id,
        "terminal_at=terminal_at+interval '1 millisecond'",
        None,
        "transition source with the wrong terminal instant",
    )
    .await;

    // gen1 active with alice's genesis leaf; the reset request consumed.
    let g1_leaf: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.member_devices WHERE conversation_id=$1 AND generation=1 AND active",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("g1 leaf");
    assert_eq!(g1_leaf, 1);
    let req_status: String =
        sqlx::query_scalar("SELECT status FROM chat.reset_requests WHERE reset_request_id=$1")
            .bind(reset_request_id)
            .fetch_one(&pool)
            .await
            .expect("reset request status");
    assert_eq!(req_status, "consumed");
    // Both gen0 intervals Reset-closed at the activation seq.
    let closed_at_reset: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.application_intervals WHERE conversation_id=$1 AND terminal_seq=5 AND closing_kind='reset'",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("closed intervals");
    assert_eq!(closed_at_reset, 2);

    // Replay -> head CAS conflict (head at gen1), zero residue.
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan_unscoped_for_test(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Transition(_))),
        "reset activation replay must conflict on the head CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "reset activation replay left zero residue");
}

/// Arm 3 (reset shared-path supersession, the OPEN-RECOVERY-REQUEST branch): a
/// reset activation that retires a generation carrying an OPEN leaf-recovery
/// request (+ its reservation + reserved package) supersedes/releases/reactivates
/// all three through the same shared `write_prior_bound_supersessions` +
/// reconcile path — AND exercises `apply_reset_activation`'s own package/reservation
/// shape-check loops + `verify_recovery_package_bijection` over a superseded
/// `Reserved->Available` edge, which the pending-welcome variant does not reach.
/// Builds on `run_fulfillment_scenario`: alice opens an entry-less `replace`
/// recovery request (coordinate UNCHANGED, reserving her package) THEN a reset
/// request, then activates — gen0 retires, gen1 forms, the recovery request goes
/// `superseded`, its reservation `released`, its package back to `available`.
#[tokio::test]
async fn reset_activation_supersedes_prior_open_recovery_request() {
    let (pool, _db) = setup().await;
    let manifest = corpus_manifest();
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let alice_id = scenario.fixture.alice_id.clone();
    let alice_did = scenario.fixture.alice_did.clone();
    let alice_device = scenario.fixture.alice_device;
    let alice_key_id = scenario.fixture.alice_key_id.clone();
    let alice_sig_key = scenario.alice_sig_key.clone();
    let bob_id = scenario.bob_id.clone();
    let bob_did = scenario.bob_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());
    let protocol_instance_id = scenario.fixture.protocol_instance_id;
    let scenario_welcome_id = scenario.welcome_id;

    // The gen0 leaf periods the reset closes (alice + bob).
    let alice_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2 AND active",
    )
    .bind(conversation_id)
    .bind(&alice_did)
    .fetch_one(&pool)
    .await
    .expect("alice leaf period");
    let bob_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2 AND active",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob leaf period");

    // 0. Alice opens an entry-less `replace` leaf-recovery request bound to the
    //    fulfillment coordinate (reserving her package; coordinate + seq UNCHANGED).
    let rec_ref = random_ref32();
    let rec_pkg_not_after =
        seed_key_package(&pool, &alice_did, alice_device, &alice_key_id, &rec_ref).await;
    let rec_pkg_not_after_ts =
        ServerTimestamp::from_unix_millis_for_test(rec_pkg_not_after.timestamp_millis()).unwrap();
    let rec_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 4_000,
    )
    .unwrap();
    let recovery_request_id = Uuid::new_v4();
    let rec_evidence = RequestEvidence::for_test(
        RequestEntryKind::LeafRecoveryRequest,
        4,
        *recovery_request_id.as_bytes(),
        alice_id.clone(),
        *conversation_id.as_bytes(),
        rec_received,
        0xC1,
    )
    .unwrap();
    let rec_planned = plan_leaf_recovery_request(
        &scenario.fulfillment_state,
        LeafRecoveryRequestCommand {
            actor: alice_id.clone(),
            recovery_request_id: *recovery_request_id.as_bytes(),
            kind: LeafRecoveryKind::Replace,
            key_package_ref: rec_ref,
            received_at: rec_received,
            package_not_after: rec_pkg_not_after_ts,
            evidence: rec_evidence,
        },
    )
    .expect("valid leaf recovery request plan");
    let rr_state = rec_planned.resulting_state().clone();
    let rec_head = ConversationHeadCasBinding::for_test_internal(
        *conversation_id.as_bytes(),
        scenario.coordinate,
        4,
        rec_received,
    );
    let rec_plan = persistence_plan_for_test(rec_planned, rec_head);
    let rec_applied_at = clock_now(&pool).await;
    let rec_transcript = vec![0xC2_u8; 16];
    let alice_pred_rec = device_event_predecessor(&pool, &alice_did, alice_device).await;
    let rec_ctx = ExecutionContext {
        protocol_instance_id,
        applied_at: rec_applied_at,
        actor: ExecutionActor {
            user_did: alice_did.clone(),
            device_id: alice_device,
            key_id: alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
            accepted_payload_bytes: vec![0xC3_u8; 8],
            accepted_payload_sha256: Sha256::digest([0xC3_u8; 8]).to_vec(),
            signed_request_bytes: rec_transcript.clone(),
            unsigned_projection_bytes: vec![0xC4_u8; 8],
            signing_transcript_bytes: rec_transcript.clone(),
            request_digest: Sha256::digest(&rec_transcript).to_vec(),
            signature: vec![0xC5_u8; 64],
            server_fields_bytes: vec![0xC6_u8; 8],
            outer_entry_fingerprint: vec![0x17_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0xC7_u8; 8],
            recipients: vec![(
                alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred_rec,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: Some(RecoveryOpenContext {
            participant_period_id: None,
            package_not_after: rec_pkg_not_after,
            replaced_leaf_period_id: Some(alice_leaf_period),
        }),
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    {
        let mut tx = pool.begin().await.expect("begin leaf recovery request");
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &rec_plan, &rec_ctx)
            .await
            .expect("leaf recovery request applies");
        tx.commit().await.expect("leaf recovery request COMMIT");
    }
    // The request is OPEN, its package RESERVED before the reset.
    let pre: (String, String) = sqlx::query_as(
        "SELECT (SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1), \
                (SELECT status FROM chat.key_packages WHERE key_package_ref=$2)",
    )
    .bind(recovery_request_id)
    .bind(rec_ref.to_vec())
    .fetch_one(&pool)
    .await
    .expect("pre state");
    assert_eq!((pre.0.as_str(), pre.1.as_str()), ("open", "reserved"));

    // 1. Alice opens a reset request (seq 4) against the recovery-request state.
    let req_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 5_000,
    )
    .unwrap();
    let reset_request_id = Uuid::new_v4();
    let req_evidence = RequestEvidence::for_test(
        RequestEntryKind::ResetRequest,
        4,
        *reset_request_id.as_bytes(),
        alice_id.clone(),
        *conversation_id.as_bytes(),
        req_received,
        0x91,
    )
    .unwrap();
    let req_planned = plan_reset_request(
        &rr_state,
        ResetRequestCommand {
            actor: alice_id.clone(),
            reset_request_id: *reset_request_id.as_bytes(),
            received_at: req_received,
            evidence: req_evidence,
        },
    )
    .expect("valid reset request plan");
    let reset_state = req_planned.resulting_state().clone();
    let req_entry = Uuid::new_v4();
    let req_head = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *req_entry.as_bytes(),
        scenario.coordinate,
        4,
        req_received,
    );
    let req_plan = persistence_plan_for_test(req_planned, req_head);
    let req_applied_at = clock_now(&pool).await;
    let req_transcript = vec![0x92_u8; 16];
    let req_digest = Sha256::digest(&req_transcript).to_vec();
    let req_signature = vec![0x93_u8; 64];
    let alice_pred_req = device_event_predecessor(&pool, &alice_did, alice_device).await;
    let req_ctx = ExecutionContext {
        protocol_instance_id,
        applied_at: req_applied_at,
        actor: ExecutionActor {
            user_did: alice_did.clone(),
            device_id: alice_device,
            key_id: alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: req_entry,
            entry_kind: "blue.catbird.chat.defs#resetRequestEntry".to_owned(),
            accepted_payload_bytes: vec![0x94_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x94_u8; 8]).to_vec(),
            signed_request_bytes: req_transcript.clone(),
            unsigned_projection_bytes: vec![0x95_u8; 8],
            signing_transcript_bytes: req_transcript.clone(),
            request_digest: req_digest.clone(),
            signature: req_signature.clone(),
            server_fields_bytes: vec![0x96_u8; 8],
            outer_entry_fingerprint: vec![0x1A_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![(alice_id.clone(), EntryEntitlementKind::Control)],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ResetRequested,
            payload_bytes: vec![0x97_u8; 8],
            recipients: vec![(
                alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred_req,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: Some(ResetRequestRow {
            reset_request_id,
            reason: ResetReason::PoisonedState,
            signed_request_bytes: req_transcript.clone(),
            signing_transcript_bytes: req_transcript,
            request_digest: req_digest,
            signature: req_signature,
            expires_at: req_applied_at + Duration::hours(24),
        }),
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    {
        let mut tx = pool.begin().await.expect("begin reset request");
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &req_plan, &req_ctx)
            .await
            .expect("reset request applies");
        tx.commit()
            .await
            .expect("reset request COMMIT past all deferred triggers");
    }

    // 2. Alice activates the reset (seq 5): gen0 retires, gen1 forms with alice's
    //    genesis leaf, bob's pending welcome supersedes AND the open recovery
    //    request is superseded / reservation released / package reactivated.
    let successor_coordinate = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        scenario.coordinate.generation() + 1,
        0,
        [0xA1_u8; 32],
        0,
        [0xA2_u8; 32],
        [0xA3_u8; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    let successor_public_state =
        ActivePublicState::for_test(&verified_genesis(&manifest), successor_coordinate);
    let retired_coordinate = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        scenario.coordinate.generation(),
        scenario.coordinate.state_version() + 1,
        *scenario.coordinate.group_id(),
        scenario.coordinate.epoch(),
        *scenario.coordinate.group_context_hash(),
        *scenario.coordinate.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Superseded,
    );
    let act_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 6_000,
    )
    .unwrap();
    let act_transition = Uuid::new_v4();
    let act_entry = Uuid::new_v4();
    let metadata = MetadataSnapshotBinding::for_test_creation(
        *conversation_id.as_bytes(),
        1,
        0,
        [0xA2_u8; 32],
        *act_transition.as_bytes(),
        3,
        alice_id.clone(),
        Sha256::digest(&alice_sig_key).into(),
        alice_sig_key.clone().try_into().unwrap(),
        1,
        2,
        [0xA8_u8; 12],
        vec![0xA9_u8; 48],
    );
    let act_evidence = TransitionEvidence::for_test_reset_activation_with_metadata(
        5,
        *act_transition.as_bytes(),
        [0x1B_u8; 32],
        act_received,
        ConversationKind::Group,
        *reset_request_id.as_bytes(),
        scenario.coordinate,
        retired_coordinate,
        successor_coordinate,
        alice_id.clone(),
        metadata,
    )
    .unwrap();
    let planned = plan_reset_activation(
        &reset_state,
        ResetActivation {
            actor: alice_id.clone(),
            reset_request_id: *reset_request_id.as_bytes(),
            transition: act_evidence,
            successor_public_state,
        },
    )
    .expect("valid reset activation plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *act_entry.as_bytes(),
        scenario.coordinate,
        5,
        act_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let mut participant_rows: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT user_did,participant_period_id FROM chat.participants WHERE conversation_id=$1 AND current_membership",
    )
    .bind(conversation_id)
    .fetch_all(&pool)
    .await
    .expect("participant periods");
    participant_rows.sort_by(|l, r| l.0.as_bytes().cmp(r.0.as_bytes()));
    let participant_period_ids: Vec<Uuid> = participant_rows.iter().map(|(_, id)| *id).collect();

    let applied_at = clock_now(&pool).await;
    let payload = vec![0xAA_u8; 12];
    let transcript = vec![0xAB_u8; 12];
    let alice_pred = device_event_predecessor(&pool, &alice_did, alice_device).await;
    let bob_pred = device_event_predecessor(&pool, &bob_did, bob_device).await;
    let ctx = ExecutionContext {
        protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: alice_did.clone(),
            device_id: alice_device,
            key_id: alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: act_entry,
            entry_kind: "blue.catbird.chat.defs#resetActivationEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0xAC_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0xAD_u8; 64],
            server_fields_bytes: vec![0xAE_u8; 8],
            outer_entry_fingerprint: vec![0x1B_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xB1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xB1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xB2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xB2_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![0xB3_u8; 16],
            genesis_group_info_sha256: Sha256::digest([0xB3_u8; 16]).to_vec(),
        },
        opened_leaves: vec![LeafPersistenceColumns {
            device: alice_id.clone(),
            leaf_key_id: alice_key_id.clone(),
            leaf_auth_generation: 1,
        }],
        metadata_author: Some(MetadataAuthorColumns {
            author_role: "admin".to_owned(),
            author_device_status: "active".to_owned(),
            author_public_key: alice_sig_key.clone(),
            author_key_id: alice_key_id.clone(),
            metadata_snapshot_id: Uuid::new_v4(),
        }),
        participant_period_ids,
        leaf_period_ids: vec![Uuid::new_v4()],
        entry_recipients: vec![
            (alice_id.clone(), EntryEntitlementKind::IntervalClose),
            (bob_id.clone(), EntryEntitlementKind::IntervalClose),
        ],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0xB4_u8; 8],
            recipients: vec![(
                alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![
            (alice_id.clone(), alice_leaf_period),
            (bob_id.clone(), bob_leaf_period),
        ],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![WelcomeDispositionInput {
            welcome_id: scenario_welcome_id,
            event: EventFanout {
                event_id: Uuid::new_v4(),
                event_kind: EventKind::WelcomeDisposition,
                payload_bytes: vec![0xB5_u8; 8],
                recipients: vec![(bob_id.clone(), EventEntitlementKind::Welcome, bob_pred)],
                outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
            },
        }],
    };

    let mut tx = pool.begin().await.expect("begin reset activation");
    let applied = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("reset activation applies");
    tx.commit()
        .await
        .expect("reset activation COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 5);

    // The reset consumed + welcome superseded (as in the pending-welcome variant).
    let welcome_status: String =
        sqlx::query_scalar("SELECT status FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(scenario_welcome_id)
            .fetch_one(&pool)
            .await
            .expect("welcome");
    assert_eq!(welcome_status, "superseded");
    let req_status: String =
        sqlx::query_scalar("SELECT status FROM chat.reset_requests WHERE reset_request_id=$1")
            .bind(reset_request_id)
            .fetch_one(&pool)
            .await
            .expect("reset request status");
    assert_eq!(req_status, "consumed");

    // NEW coverage: the open recovery request is superseded, its reservation
    // released, and its reserved package reactivated to available.
    let (rec_status, res_status, pkg_status): (String, String, String) = sqlx::query_as(
        "SELECT (SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1), \
                (SELECT status FROM chat.key_package_reservations WHERE recovery_request_id=$1), \
                (SELECT status FROM chat.key_packages WHERE key_package_ref=$2)",
    )
    .bind(recovery_request_id)
    .bind(rec_ref.to_vec())
    .fetch_one(&pool)
    .await
    .expect("superseded recovery state");
    assert_eq!(
        (
            rec_status.as_str(),
            res_status.as_str(),
            pkg_status.as_str()
        ),
        ("superseded", "released", "available")
    );
}

#[tokio::test]
async fn creation_plan_without_invitation_quota_binding_is_rejected() {
    let (pool, _db) = setup().await;
    let fixture = build_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    // A Creation plan MUST carry the invitation-quota CAS binding (production
    // `into_persistence_plan` rejects it as InvalidHydrationAuthority otherwise).
    // The executor rejects the stripped plan as InconsistentPlan BEFORE any write.
    let stripped = fixture.plan.with_invitation_quota_cleared_for_test();
    let mut tx = pool.begin().await.expect("begin");
    let result =
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &stripped, &fixture.ctx)
            .await;
    assert!(
        matches!(result, Err(ExecutorError::InconsistentPlan(_))),
        "missing invitation-quota binding must be an InconsistentPlan, got {result:?}"
    );
    tx.rollback().await.expect("rollback");
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.conversations WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        0,
        "a rejected plan writes nothing"
    );
}

#[tokio::test]
async fn creation_mid_executor_metadata_conflict_rolls_back_whole_graph() {
    let (pool, _db) = setup().await;

    // A real creation that COMMITS — its metadata snapshot id is a global primary
    // key we then force a collision against.
    let first = build_creation(&pool, ConversationKind::Group).await;
    let mut tx0 = pool.begin().await.expect("begin first");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx0, &first.plan, &first.ctx)
        .await
        .expect("first creation applies");
    tx0.commit().await.expect("first COMMIT");
    let existing_snapshot_id: Uuid = sqlx::query_scalar(
        "SELECT metadata_snapshot_id FROM chat.metadata_snapshots WHERE conversation_id=$1",
    )
    .bind(first.conversation_id)
    .fetch_one(&pool)
    .await
    .expect("first snapshot id");

    // Second creation whose metadata snapshot id collides with the committed one.
    // The executor's OWN metadata insert (step 5, AFTER the head insert at step 1)
    // fails on the metadata_snapshots primary key mid-executor; the whole graph
    // must roll back.
    let mut second = build_creation(&pool, ConversationKind::Group).await;
    let conversation_id = second.conversation_id;
    second
        .ctx
        .metadata_author
        .as_mut()
        .expect("creation carries a metadata author")
        .metadata_snapshot_id = existing_snapshot_id;

    let mut tx = pool.begin().await.expect("begin second");
    let result =
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &second.plan, &second.ctx)
            .await;
    assert!(
        matches!(result, Err(ExecutorError::Transition(_))),
        "mid-executor metadata PK collision must surface as a Transition error, got {result:?}"
    );
    tx.rollback().await.expect("rollback second");

    // The head insert (step 1) executed inside the same transaction BEFORE the
    // failing metadata insert (step 5): confirm it — and every other row — rolled
    // back, proving executor atomicity across the whole graph.
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.conversations WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.generations WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.participants WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.entries WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        0
    );
}

fn random_ref32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes
}

#[tokio::test]
async fn acceptance_commits_recovery_open_and_promotes_participant() {
    let (pool, _db) = setup().await;
    let fixture = commit_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    let bob_device = Uuid::from_bytes(*fixture.bob_id.device_id());

    // bob's pending participant period (the acceptance CAS target).
    let bob_period: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&fixture.bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob participant period");
    let bob_key_id = fixture.bob_key_id.clone();

    // The key package bob's acceptance reserves.
    let key_package_ref = random_ref32();
    let package_not_after = seed_key_package(
        &pool,
        &fixture.bob_did,
        bob_device,
        &bob_key_id,
        &key_package_ref,
    )
    .await;

    let received_at = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 3_000,
    )
    .unwrap();
    let pkg_not_after_ts = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 3_600_000,
    )
    .unwrap();
    let entry_id = Uuid::new_v4();
    let transition_id = Uuid::new_v4();
    let recovery_request_id = *Uuid::new_v4().as_bytes();
    let evidence = TransitionEvidence::for_test_acceptance(
        2,
        *transition_id.as_bytes(),
        [0x16_u8; 32],
        received_at,
        fixture.coordinate,
        recovery_request_id,
        fixture.bob_id.clone(),
        fixture.creation_transition_id,
        fixture.alice_id.clone(),
        key_package_ref,
        Sha256::digest([0x62_u8; 32]).into(),
        1,
        pkg_not_after_ts,
    )
    .unwrap();
    let planned = plan_accept_conversation(
        &fixture.state,
        AcceptConversation {
            actor: fixture.bob_id.clone(),
            transition: evidence,
            recovery_request_id,
            key_package_ref,
            package_not_after: pkg_not_after_ts,
        },
    )
    .expect("valid acceptance plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        2,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let applied_at = clock_now(&pool).await;
    let payload = vec![0xA1_u8; 12];
    let transcript = vec![0xA2_u8; 12];
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.bob_did.clone(),
            device_id: bob_device,
            key_id: bob_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Member,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#participantAcceptanceEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0xA3_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0xA4_u8; 64],
            server_fields_bytes: vec![0xA5_u8; 8],
            outer_entry_fingerprint: vec![0x16_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xB1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xB1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xB2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xB2_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: entry_audience(
            &fixture.alice_id,
            &fixture.alice_did,
            &fixture.bob_id,
            &fixture.bob_did,
        ),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0xB4_u8; 8],
            recipients: event_audience(
                &pool,
                &fixture.alice_id,
                &fixture.alice_did,
                &fixture.bob_id,
                &fixture.bob_did,
            )
            .await,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: Some(RecoveryOpenContext {
            participant_period_id: Some(bob_period),
            package_not_after,
            replaced_leaf_period_id: None,
        }),
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };

    let mut tx = pool.begin().await.expect("begin acceptance");
    let applied = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("acceptance applies");
    tx.commit()
        .await
        .expect("acceptance COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 2);

    // stateVersion+1 at the same crypto coordinate; seq 2->3.
    let (sv, next_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((sv, next_seq), (1, 3));
    let (skind, slife): (String, String) = sqlx::query_as(
        "SELECT state_kind,lifecycle FROM chat.generation_states WHERE conversation_id=$1 AND state_version=1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("accept state");
    assert_eq!(
        (skind.as_str(), slife.as_str()),
        ("acceptConversation", "active")
    );
    // bob promoted to active with acceptance provenance.
    let (status, has_accept): (String, bool) = sqlx::query_as(
        "SELECT status, acceptance_transition_id IS NOT NULL FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&fixture.bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob participant");
    assert_eq!((status.as_str(), has_accept), ("active", true));
    // The atomic recovery open: request open, reservation active, package reserved.
    let (req_status, req_source, req_kind): (String, String, String) = sqlx::query_as(
        "SELECT status,source,recovery_kind FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(Uuid::from_bytes(recovery_request_id))
    .fetch_one(&pool)
    .await
    .expect("recovery request");
    assert_eq!(
        (req_status.as_str(), req_source.as_str(), req_kind.as_str()),
        ("open", "acceptConversation", "add")
    );
    let res_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.key_package_reservations WHERE recovery_request_id=$1",
    )
    .bind(Uuid::from_bytes(recovery_request_id))
    .fetch_one(&pool)
    .await
    .expect("reservation");
    assert_eq!(res_status, "active");
    let pkg_status: String =
        sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE key_package_ref=$1")
            .bind(key_package_ref.to_vec())
            .fetch_one(&pool)
            .await
            .expect("package");
    assert_eq!(pkg_status, "reserved");
    // The acceptance transition (prior 0,0 -> next 0,1).
    let (tkind, eseq): (String, i64) = sqlx::query_as(
        "SELECT kind,entry_seq FROM chat.transitions WHERE conversation_id=$1 AND kind='acceptConversation'",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("acceptance transition");
    assert_eq!((tkind.as_str(), eseq), ("acceptConversation", 2));

    // Review MINOR-3: re-apply the committed acceptance plan -> the head CAS
    // conflicts (the head already advanced to stateVersion 1), the whole
    // transaction rolls back with zero residue.
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut tx2 = pool.begin().await.expect("begin re-apply acceptance");
    let reapply =
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(reapply, Err(ExecutorError::Transition(_))),
        "acceptance re-apply must conflict on the head CAS, got {reapply:?}"
    );
    tx2.rollback().await.expect("rollback re-apply acceptance");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "acceptance re-apply left zero residue");
}

/// Concern-2 completeness for the arm that OWNS recovery work: bob's acceptance,
/// executed from a coordinate where the active member alice has an OPEN
/// leaf-recovery request, both opens bob's OWN recovery (None->Open request +
/// None->Active reservation + Available->Reserved package) AND supersedes alice's
/// (Open->Superseded / Active->Released / Reserved->Available). The own vs
/// superseded partition (own counts {1,1,1}) is the load-bearing new logic; before
/// the fix `apply_acceptance` required EXACTLY one delta per family and rejected the
/// welcome family, so a co-open recovery request hard-errored.
#[tokio::test]
async fn acceptance_supersedes_prior_open_recovery_request() {
    let (pool, _db) = setup().await;
    let fixture = commit_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    let bob_device = Uuid::from_bytes(*fixture.bob_id.device_id());

    // Alice (active) opens an entry-less recovery request bound to the creation
    // coordinate (reserving her package), then bob accepts and supersedes it.
    let (rr_state, alice_rid, alice_ref) = seed_alice_open_recovery(&pool, &fixture).await;

    let bob_period: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&fixture.bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob participant period");
    let bob_key_id = fixture.bob_key_id.clone();
    let key_package_ref = random_ref32();
    let package_not_after = seed_key_package(
        &pool,
        &fixture.bob_did,
        bob_device,
        &bob_key_id,
        &key_package_ref,
    )
    .await;
    // Acceptance at eval+3000 — AFTER alice's request (eval+2000), so the
    // supersession's transition_follows_origin holds.
    let received_at = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 3_000,
    )
    .unwrap();
    let pkg_not_after_ts = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 3_600_000,
    )
    .unwrap();
    let entry_id = Uuid::new_v4();
    let transition_id = Uuid::new_v4();
    let recovery_request_id = *Uuid::new_v4().as_bytes();
    let evidence = TransitionEvidence::for_test_acceptance(
        2,
        *transition_id.as_bytes(),
        [0x16_u8; 32],
        received_at,
        fixture.coordinate,
        recovery_request_id,
        fixture.bob_id.clone(),
        fixture.creation_transition_id,
        fixture.alice_id.clone(),
        key_package_ref,
        Sha256::digest([0x62_u8; 32]).into(),
        1,
        pkg_not_after_ts,
    )
    .unwrap();
    let planned = plan_accept_conversation(
        &rr_state,
        AcceptConversation {
            actor: fixture.bob_id.clone(),
            transition: evidence,
            recovery_request_id,
            key_package_ref,
            package_not_after: pkg_not_after_ts,
        },
    )
    .expect("valid acceptance plan over a co-open recovery request");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        2,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);
    let applied_at = clock_now(&pool).await;
    let payload = vec![0xA1_u8; 12];
    let transcript = vec![0xA2_u8; 12];
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.bob_did.clone(),
            device_id: bob_device,
            key_id: bob_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Member,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#participantAcceptanceEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0xA3_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0xA4_u8; 64],
            server_fields_bytes: vec![0xA5_u8; 8],
            outer_entry_fingerprint: vec![0x16_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xB1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xB1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xB2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xB2_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: entry_audience(
            &fixture.alice_id,
            &fixture.alice_did,
            &fixture.bob_id,
            &fixture.bob_did,
        ),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0xB4_u8; 8],
            recipients: event_audience(
                &pool,
                &fixture.alice_id,
                &fixture.alice_did,
                &fixture.bob_id,
                &fixture.bob_did,
            )
            .await,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: Some(RecoveryOpenContext {
            participant_period_id: Some(bob_period),
            package_not_after,
            replaced_leaf_period_id: None,
        }),
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };

    let mut tx = pool.begin().await.expect("begin acceptance");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("acceptance that supersedes a co-open recovery request applies");
    tx.commit()
        .await
        .expect("acceptance COMMIT past all deferred triggers");

    // bob promoted + bob's OWN recovery opened (own edges), alice's superseded.
    let bob_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&fixture.bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob participant");
    assert_eq!(bob_status, "active");
    let bob_req_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(Uuid::from_bytes(recovery_request_id))
    .fetch_one(&pool)
    .await
    .expect("bob recovery request");
    assert_eq!(bob_req_status, "open", "bob's own recovery is opened");
    // Alice's prior recovery is superseded / released / reactivated.
    let (alice_status, alice_res, alice_pkg): (String, String, String) = sqlx::query_as(
        "SELECT (SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1), \
                (SELECT status FROM chat.key_package_reservations WHERE recovery_request_id=$1), \
                (SELECT status FROM chat.key_packages WHERE key_package_ref=$2)",
    )
    .bind(alice_rid)
    .bind(alice_ref.to_vec())
    .fetch_one(&pool)
    .await
    .expect("alice superseded recovery state");
    assert_eq!(
        (
            alice_status.as_str(),
            alice_res.as_str(),
            alice_pkg.as_str()
        ),
        ("superseded", "released", "available")
    );
}

/// Review follow-up: acceptance's kind (`acceptConversation`) is DB-legal as the
/// terminal authority for a reset-request `stale` edge (reset staling has no kind
/// restriction), so a bob acceptance executed while the active member alice has a
/// co-pending reset request STALES it — exactly like apply_policy. Before the fix
/// `apply_acceptance` rejected reset_request_changes (mis-bundled into the deferred
/// leave-kind Concern 1/3), hard-erroring this reachable, fail-closed case.
#[tokio::test]
async fn acceptance_stales_prior_pending_reset_request() {
    let (pool, _db) = setup().await;
    let fixture = commit_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    let bob_device = Uuid::from_bytes(*fixture.bob_id.device_id());

    // Alice (active) files a reset request (control entry, seq 2, eval+2000); bob's
    // acceptance (seq 3, eval+3000, coordinate still sv 0) stales it.
    let reset_received = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 2_000,
    )
    .unwrap();
    let (reset_state, reset_request_id) =
        commit_reset_request(&pool, &fixture, 2, reset_received).await;

    let bob_period: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&fixture.bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob participant period");
    let bob_key_id = fixture.bob_key_id.clone();
    let key_package_ref = random_ref32();
    let package_not_after = seed_key_package(
        &pool,
        &fixture.bob_did,
        bob_device,
        &bob_key_id,
        &key_package_ref,
    )
    .await;
    let received_at = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 3_000,
    )
    .unwrap();
    let pkg_not_after_ts = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 3_600_000,
    )
    .unwrap();
    let entry_id = Uuid::new_v4();
    let transition_id = Uuid::new_v4();
    let recovery_request_id = *Uuid::new_v4().as_bytes();
    let evidence = TransitionEvidence::for_test_acceptance(
        3,
        *transition_id.as_bytes(),
        [0x16_u8; 32],
        received_at,
        fixture.coordinate,
        recovery_request_id,
        fixture.bob_id.clone(),
        fixture.creation_transition_id,
        fixture.alice_id.clone(),
        key_package_ref,
        Sha256::digest([0x62_u8; 32]).into(),
        1,
        pkg_not_after_ts,
    )
    .unwrap();
    let planned = plan_accept_conversation(
        &reset_state,
        AcceptConversation {
            actor: fixture.bob_id.clone(),
            transition: evidence,
            recovery_request_id,
            key_package_ref,
            package_not_after: pkg_not_after_ts,
        },
    )
    .expect("valid acceptance plan over a co-pending reset request");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        3,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);
    let applied_at = clock_now(&pool).await;
    let payload = vec![0xA1_u8; 12];
    let transcript = vec![0xA2_u8; 12];
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.bob_did.clone(),
            device_id: bob_device,
            key_id: bob_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Member,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#participantAcceptanceEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0xA3_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0xA4_u8; 64],
            server_fields_bytes: vec![0xA5_u8; 8],
            outer_entry_fingerprint: vec![0x16_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xB1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xB1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xB2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xB2_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: entry_audience(
            &fixture.alice_id,
            &fixture.alice_did,
            &fixture.bob_id,
            &fixture.bob_did,
        ),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0xB4_u8; 8],
            recipients: event_audience(
                &pool,
                &fixture.alice_id,
                &fixture.alice_did,
                &fixture.bob_id,
                &fixture.bob_did,
            )
            .await,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: Some(RecoveryOpenContext {
            participant_period_id: Some(bob_period),
            package_not_after,
            replaced_leaf_period_id: None,
        }),
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };

    let mut tx = pool.begin().await.expect("begin acceptance");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("acceptance that stales a co-pending reset request applies");
    tx.commit()
        .await
        .expect("acceptance COMMIT past all deferred triggers");

    // bob promoted, alice's reset request staled bound to the acceptance transition.
    let bob_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&fixture.bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob participant");
    assert_eq!(bob_status, "active");
    let (reset_status, reset_tid): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT status,terminal_transition_id FROM chat.reset_requests WHERE reset_request_id=$1",
    )
    .bind(reset_request_id)
    .fetch_one(&pool)
    .await
    .expect("reset terminal");
    assert_eq!(reset_status, "stale");
    assert_eq!(reset_tid, Some(transition_id));
}

#[tokio::test]
async fn leaf_recovery_replace_request_commits_without_advancing_coordinate() {
    let (pool, _db) = setup().await;
    let fixture = commit_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;

    // alice's committed genesis leaf period (the leaf a `replace` recovers).
    let alice_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2",
    )
    .bind(conversation_id)
    .bind(&fixture.alice_did)
    .fetch_one(&pool)
    .await
    .expect("alice leaf period");

    // A fresh available key package owned by alice to reserve.
    let key_package_ref = random_ref32();
    let package_not_after = seed_key_package(
        &pool,
        &fixture.alice_did,
        fixture.alice_device,
        &fixture.alice_key_id,
        &key_package_ref,
    )
    .await;

    let received_at = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 3_000,
    )
    .unwrap();
    let pkg_not_after_ts = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 3_600_000,
    )
    .unwrap();
    let recovery_request_id = Uuid::new_v4();
    let evidence = RequestEvidence::for_test(
        RequestEntryKind::LeafRecoveryRequest,
        2,
        *recovery_request_id.as_bytes(),
        fixture.alice_id.clone(),
        *conversation_id.as_bytes(),
        received_at,
        0x71,
    )
    .unwrap();
    let planned = plan_leaf_recovery_request(
        &fixture.state,
        LeafRecoveryRequestCommand {
            actor: fixture.alice_id.clone(),
            recovery_request_id: *recovery_request_id.as_bytes(),
            kind: LeafRecoveryKind::Replace,
            key_package_ref,
            received_at,
            package_not_after: pkg_not_after_ts,
            evidence,
        },
    )
    .expect("valid leaf recovery request plan");
    let head_cas = ConversationHeadCasBinding::for_test_internal(
        *conversation_id.as_bytes(),
        fixture.coordinate,
        2,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let applied_at = clock_now(&pool).await;
    let transcript = vec![0x72_u8; 16];
    let alice_pred =
        device_event_predecessor(&pool, &fixture.alice_did, fixture.alice_device).await;
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        // Internal op: the executor appends no control entry, but write_recovery_open
        // sources the leaf_recovery_requests signed material from ctx.entry.
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
            accepted_payload_bytes: vec![0x73_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x73_u8; 8]).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x74_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0x75_u8; 64],
            server_fields_bytes: vec![0x76_u8; 8],
            outer_entry_fingerprint: vec![0x17_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x77_u8; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: Some(RecoveryOpenContext {
            participant_period_id: None,
            package_not_after,
            replaced_leaf_period_id: Some(alice_leaf_period),
        }),
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };

    let mut tx = pool.begin().await.expect("begin leaf recovery request");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("leaf recovery request applies");
    tx.commit()
        .await
        .expect("leaf recovery request COMMIT past all deferred triggers");

    // Coordinate + seq counter UNCHANGED (still 0,0,active,next_seq 2).
    let (gen, sv, next_seq, lifecycle): (i64, i64, i64, String) = sqlx::query_as(
        "SELECT current_generation,current_state_version,next_entry_seq,lifecycle FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((gen, sv, next_seq, lifecycle.as_str()), (0, 0, 2, "active"));
    // No new transition (internal op authored none).
    let transitions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .expect("transitions");
    assert_eq!(transitions, 1, "only the creation transition exists");
    // Open replace recovery request + active reservation + reserved package.
    let (req_status, req_source, req_kind, replaced): (String, String, String, Option<Uuid>) = sqlx::query_as(
        "SELECT status,source,recovery_kind,replaced_leaf_period_id FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(recovery_request_id)
    .fetch_one(&pool)
    .await
    .expect("recovery request");
    assert_eq!(
        (req_status.as_str(), req_source.as_str(), req_kind.as_str()),
        ("open", "requestLeafRecovery", "replace")
    );
    assert_eq!(replaced, Some(alice_leaf_period));
    let res_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.key_package_reservations WHERE recovery_request_id=$1",
    )
    .bind(recovery_request_id)
    .fetch_one(&pool)
    .await
    .expect("reservation");
    assert_eq!(res_status, "active");
    let pkg_status: String =
        sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE key_package_ref=$1")
            .bind(key_package_ref.to_vec())
            .fetch_one(&pool)
            .await
            .expect("package");
    assert_eq!(pkg_status, "reserved");
}

struct CommittedRecoveryRequest {
    state: ConversationState,
    request_id: Uuid,
    key_package_ref: [u8; 32],
    package_not_after: DateTime<Utc>,
}

/// Build + commit a `replace` leaf-recovery request by the active creator (alice)
/// and return the resulting state (carrying the open request) + its identifiers.
struct BuiltReplaceRequest {
    plan: chat_protocol::state_machine::ConversationPersistencePlan,
    ctx: ExecutionContext,
    committed: CommittedRecoveryRequest,
}

async fn commit_replace_recovery_request(
    pool: &PgPool,
    fixture: &CreationApply,
    request_byte: u8,
) -> CommittedRecoveryRequest {
    let built = build_replace_recovery_request(pool, fixture, request_byte).await;
    let mut tx = pool.begin().await.expect("begin recovery request");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &built.plan, &built.ctx)
        .await
        .expect("recovery request applies");
    tx.commit().await.expect("recovery request COMMIT");
    built.committed
}

async fn build_replace_recovery_request(
    pool: &PgPool,
    fixture: &CreationApply,
    request_byte: u8,
) -> BuiltReplaceRequest {
    let conversation_id = fixture.conversation_id;
    let alice_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2",
    )
    .bind(conversation_id)
    .bind(&fixture.alice_did)
    .fetch_one(pool)
    .await
    .expect("alice leaf period");
    let key_package_ref = random_ref32();
    let package_not_after = seed_key_package(
        pool,
        &fixture.alice_did,
        fixture.alice_device,
        &fixture.alice_key_id,
        &key_package_ref,
    )
    .await;
    let received_at = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 3_000,
    )
    .unwrap();
    let pkg_not_after_ts = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 3_600_000,
    )
    .unwrap();
    let request_id = Uuid::new_v4();
    let evidence = RequestEvidence::for_test(
        RequestEntryKind::LeafRecoveryRequest,
        2,
        *request_id.as_bytes(),
        fixture.alice_id.clone(),
        *conversation_id.as_bytes(),
        received_at,
        request_byte,
    )
    .unwrap();
    let planned = plan_leaf_recovery_request(
        &fixture.state,
        LeafRecoveryRequestCommand {
            actor: fixture.alice_id.clone(),
            recovery_request_id: *request_id.as_bytes(),
            kind: LeafRecoveryKind::Replace,
            key_package_ref,
            received_at,
            package_not_after: pkg_not_after_ts,
            evidence,
        },
    )
    .expect("valid leaf recovery request plan");
    let state = planned.resulting_state().clone();
    let head_cas = ConversationHeadCasBinding::for_test_internal(
        *conversation_id.as_bytes(),
        fixture.coordinate,
        2,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);
    let applied_at = clock_now(pool).await;
    let transcript = vec![request_byte; 16];
    let alice_pred = device_event_predecessor(pool, &fixture.alice_did, fixture.alice_device).await;
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
            accepted_payload_bytes: vec![request_byte; 8],
            accepted_payload_sha256: Sha256::digest([request_byte; 8]).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![request_byte; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![request_byte; 64],
            server_fields_bytes: vec![request_byte; 8],
            outer_entry_fingerprint: vec![request_byte; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![request_byte; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: Some(RecoveryOpenContext {
            participant_period_id: None,
            package_not_after,
            replaced_leaf_period_id: Some(alice_leaf_period),
        }),
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    BuiltReplaceRequest {
        plan,
        ctx,
        committed: CommittedRecoveryRequest {
            state,
            request_id,
            key_package_ref,
            package_not_after,
        },
    }
}

#[tokio::test]
async fn recovery_package_cas_desync_is_rejected() {
    let (pool, _db) = setup().await;
    let fixture = commit_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    // A valid replace-request plan, then STRIP its recovery_package_cas so it
    // desyncs from package_transitions. Production requires the two bijective
    // (package_cas_bijection_valid); the executor's load-bearing
    // verify_recovery_package_consistency must reject BEFORE any write — removing
    // that assert fails this test.
    let built = build_replace_recovery_request(&pool, &fixture, 0x93).await;
    let stripped = built.plan.with_recovery_package_cas_cleared_for_test();
    let mut tx = pool.begin().await.expect("begin");
    let result =
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &stripped, &built.ctx).await;
    assert!(
        matches!(result, Err(ExecutorError::InconsistentPlan(_))),
        "a desynced recovery_package_cas must be an InconsistentPlan, got {result:?}"
    );
    tx.rollback().await.expect("rollback");
    let reservations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.key_package_reservations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("reservations");
    assert_eq!(reservations, 0, "a rejected plan writes nothing");
}

#[tokio::test]
async fn leaf_recovery_cancellation_releases_reservation_and_reactivates_package() {
    let (pool, _db) = setup().await;
    let fixture = commit_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    let req = commit_replace_recovery_request(&pool, &fixture, 0x71).await;
    let baseline_statuses: (String, String, String) = sqlx::query_as(
        r#"SELECT request.status,reservation.status,package.status
           FROM chat.leaf_recovery_requests request
           JOIN chat.key_package_reservations reservation
             ON reservation.recovery_request_id=request.recovery_request_id
           JOIN chat.key_packages package
             ON package.key_package_ref=reservation.key_package_ref
           WHERE request.recovery_request_id=$1"#,
    )
    .bind(req.request_id)
    .fetch_one(&pool)
    .await
    .expect("baseline Recovery terminal triple");
    assert_eq!(
        baseline_statuses,
        (
            "open".to_owned(),
            "active".to_owned(),
            "reserved".to_owned()
        )
    );
    let baseline_counts: (i64, i64, i64) = sqlx::query_as(
        r#"SELECT
             (SELECT count(*) FROM chat.entries WHERE conversation_id=$1),
             (SELECT count(*) FROM chat.events),
             (SELECT count(*) FROM chat.outbox)"#,
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("baseline append/event/outbox counts");

    // Cancel the open request: received AFTER the request, a DISTINCT digest.
    let cancel_received = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 4_000,
    )
    .unwrap();
    let cancel_evidence = RequestEvidence::for_test(
        RequestEntryKind::LeafRecoveryCancellation,
        2,
        *req.request_id.as_bytes(),
        fixture.alice_id.clone(),
        *conversation_id.as_bytes(),
        cancel_received,
        0x81,
    )
    .unwrap();
    let planned = plan_leaf_recovery_cancellation(
        &req.state,
        LeafRecoveryCancellation {
            actor: fixture.alice_id.clone(),
            recovery_request_id: *req.request_id.as_bytes(),
            received_at: cancel_received,
            evidence: cancel_evidence,
        },
    )
    .expect("valid cancellation plan");
    let head_cas = ConversationHeadCasBinding::for_test_internal(
        *conversation_id.as_bytes(),
        fixture.coordinate,
        2,
        cancel_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let applied_at = clock_now(&pool).await;
    let cancel_transcript = vec![0x82_u8; 16];
    let alice_pred =
        device_event_predecessor(&pool, &fixture.alice_did, fixture.alice_device).await;
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
            accepted_payload_bytes: vec![0x83_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x83_u8; 8]).to_vec(),
            signed_request_bytes: cancel_transcript.clone(),
            unsigned_projection_bytes: vec![0x84_u8; 8],
            signing_transcript_bytes: cancel_transcript.clone(),
            request_digest: Sha256::digest(&cancel_transcript).to_vec(),
            signature: vec![0x85_u8; 64],
            server_fields_bytes: vec![0x86_u8; 8],
            outer_entry_fingerprint: vec![0x18_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x87_u8; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };

    // Preparing and then abandoning the plan is write-free. This is the
    // raw-executor topology's cancellation-between-prepare-and-apply proof.
    let abandoned_statuses: (String, String, String) = sqlx::query_as(
        r#"SELECT request.status,reservation.status,package.status
           FROM chat.leaf_recovery_requests request
           JOIN chat.key_package_reservations reservation
             ON reservation.recovery_request_id=request.recovery_request_id
           JOIN chat.key_packages package
             ON package.key_package_ref=reservation.key_package_ref
           WHERE request.recovery_request_id=$1"#,
    )
    .bind(req.request_id)
    .fetch_one(&pool)
    .await
    .expect("abandoned-plan Recovery terminal triple");
    let abandoned_counts: (i64, i64, i64) = sqlx::query_as(
        r#"SELECT
             (SELECT count(*) FROM chat.entries WHERE conversation_id=$1),
             (SELECT count(*) FROM chat.events),
             (SELECT count(*) FROM chat.outbox)"#,
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("abandoned-plan append/event/outbox counts");
    assert_eq!(abandoned_statuses, baseline_statuses);
    assert_eq!(abandoned_counts, baseline_counts);

    // Force a late event uniqueness failure after the raw executor has already
    // terminalized request + reservation + package. Rolling back the caller-owned
    // transaction must remove every earlier business write and all event/outbox
    // residue.
    let existing_event_id: Uuid =
        sqlx::query_scalar("SELECT event_id FROM chat.events ORDER BY event_position LIMIT 1")
            .fetch_one(&pool)
            .await
            .expect("existing event id for late-write conflict");
    let mut rollback_ctx = ctx.clone();
    rollback_ctx.events[0].event_id = existing_event_id;
    let mut rollback_tx = pool
        .begin()
        .await
        .expect("begin partial-write rollback probe");
    let late_failure = apply_conversation_persistence_plan_unscoped_for_test(
        &mut rollback_tx,
        &plan,
        &rollback_ctx,
    )
    .await;
    assert!(
        matches!(late_failure, Err(ExecutorError::Delivery(_))),
        "duplicate event id must fail after the Recovery terminal writes, got {late_failure:?}"
    );
    rollback_tx
        .rollback()
        .await
        .expect("rollback partial Recovery execution");
    let rolled_back_statuses: (String, String, String) = sqlx::query_as(
        r#"SELECT request.status,reservation.status,package.status
           FROM chat.leaf_recovery_requests request
           JOIN chat.key_package_reservations reservation
             ON reservation.recovery_request_id=request.recovery_request_id
           JOIN chat.key_packages package
             ON package.key_package_ref=reservation.key_package_ref
           WHERE request.recovery_request_id=$1"#,
    )
    .bind(req.request_id)
    .fetch_one(&pool)
    .await
    .expect("rolled-back Recovery terminal triple");
    let rolled_back_counts: (i64, i64, i64) = sqlx::query_as(
        r#"SELECT
             (SELECT count(*) FROM chat.entries WHERE conversation_id=$1),
             (SELECT count(*) FROM chat.events),
             (SELECT count(*) FROM chat.outbox)"#,
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("rolled-back append/event/outbox counts");
    assert_eq!(rolled_back_statuses, baseline_statuses);
    assert_eq!(rolled_back_counts, baseline_counts);

    let mut tx = pool.begin().await.expect("begin cancellation");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("cancellation applies");
    tx.commit()
        .await
        .expect("cancellation COMMIT past all deferred triggers");

    // Coordinate + seq counter still byte-untouched.
    let (gen, sv, next_seq): (i64, i64, i64) = sqlx::query_as(
        "SELECT current_generation,current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((gen, sv, next_seq), (0, 0, 2));
    // Request cancelled, reservation released, package back to available.
    let req_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(req.request_id)
    .fetch_one(&pool)
    .await
    .expect("recovery request");
    assert_eq!(req_status, "cancelled");
    let res_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.key_package_reservations WHERE recovery_request_id=$1",
    )
    .bind(req.request_id)
    .fetch_one(&pool)
    .await
    .expect("reservation");
    assert_eq!(res_status, "released");
    let (pkg_status, terminal_at): (String, Option<DateTime<Utc>>) =
        sqlx::query_as("SELECT status,terminal_at FROM chat.key_packages WHERE key_package_ref=$1")
            .bind(req.key_package_ref.to_vec())
            .fetch_one(&pool)
            .await
            .expect("package");
    assert_eq!((pkg_status.as_str(), terminal_at), ("available", None));
    let committed_counts: (i64, i64, i64) = sqlx::query_as(
        r#"SELECT
             (SELECT count(*) FROM chat.entries WHERE conversation_id=$1),
             (SELECT count(*) FROM chat.events),
             (SELECT count(*) FROM chat.outbox)"#,
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("committed append/event/outbox counts");

    // Replay the cancellation -> the request is no longer 'open', the terminalize
    // CAS conflicts, whole transaction rolls back with zero residue.
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan_unscoped_for_test(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Transition(_))),
        "cancellation replay must conflict on the terminalize CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    // The package stayed available (no double re-activation).
    let pkg_after: String =
        sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE key_package_ref=$1")
            .bind(req.key_package_ref.to_vec())
            .fetch_one(&pool)
            .await
            .expect("package after replay");
    assert_eq!(pkg_after, "available");
    let replay_statuses: (String, String, String) = sqlx::query_as(
        r#"SELECT request.status,reservation.status,package.status
           FROM chat.leaf_recovery_requests request
           JOIN chat.key_package_reservations reservation
             ON reservation.recovery_request_id=request.recovery_request_id
           JOIN chat.key_packages package
             ON package.key_package_ref=reservation.key_package_ref
           WHERE request.recovery_request_id=$1"#,
    )
    .bind(req.request_id)
    .fetch_one(&pool)
    .await
    .expect("replayed Recovery terminal triple");
    let replay_counts: (i64, i64, i64) = sqlx::query_as(
        r#"SELECT
             (SELECT count(*) FROM chat.entries WHERE conversation_id=$1),
             (SELECT count(*) FROM chat.events),
             (SELECT count(*) FROM chat.outbox)"#,
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("replayed append/event/outbox counts");
    assert_eq!(
        replay_statuses,
        (
            "cancelled".to_owned(),
            "released".to_owned(),
            "available".to_owned()
        )
    );
    assert_eq!(replay_counts, committed_counts);
    let _ = req.package_not_after;
}

#[tokio::test]
async fn leaf_recovery_fulfillment_commits_add_leaf_and_welcome() {
    let (pool, _db) = setup().await;
    let _ = run_fulfillment_scenario(&pool).await;
}

/// Arm 4 (welcome expiry): a pending Welcome whose `expires_at` has passed is
/// terminalized `expired` (server-authored disposition + `welcomeDisposition`
/// event) and a `welcomeExpired` recovery-work item is materialized — atomically,
/// past every deferred trigger (`assert_welcome_disposition_cas` +
/// `assert_recovery_work_integrity`). The op is ENTRY-LESS: the coordinate and seq
/// counter are byte-untouched (head CAS verify). Builds on `run_fulfillment_scenario`,
/// which leaves bob a pending Welcome at the fulfillment coordinate (gen 0, sv 2).
#[tokio::test]
async fn welcome_expiry_terminalizes_delivery_and_materializes_recovery_work() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let welcome_id = scenario.welcome_id;

    // The pending Welcome's expiry instant (== the reserved package `not_after`).
    // The delivery terminal_at, the disposition + its event's created_at, and the
    // recovery-work item's created_at must ALL equal this (the DB cross-checks), so
    // the executor's applied_at for an expiry is exactly the welcome's expires_at.
    let expires_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT expires_at FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .expect("pending welcome expires_at");

    let planned = plan_welcome_expiry_for_test(&scenario.fulfillment_state, *welcome_id.as_bytes())
        .expect("valid welcome expiry plan");
    let locked_at = ServerTimestamp::from_unix_millis_for_test(expires_at.timestamp_millis())
        .expect("locked_at");
    // Entry-less head: prior = the fulfillment coordinate, counter UNCHANGED at 4.
    let head_cas = ConversationHeadCasBinding::for_test_internal(
        *conversation_id.as_bytes(),
        scenario.coordinate,
        4,
        locked_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    // applied_at == the welcome's expires_at (the disposition event created_at must
    // equal the delivery terminal_at per `assert_welcome_disposition_cas`).
    let applied_at = expires_at;
    let bob_device = Uuid::from_bytes(*scenario.bob_id.device_id());
    let bob_pred = device_event_predecessor(&pool, &scenario.bob_did, bob_device).await;
    let recovery_work_id = Uuid::new_v4();
    let disposition_event_id = Uuid::new_v4();
    let fixture = &scenario.fixture;
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        // Server-observed expiry: the actor fields are not written (no transition).
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::Entryless {
            operation_id: welcome_id,
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![],
        events: vec![],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        // The recovery-work id + the welcomeDisposition event (recipient = bob, the
        // welcome recipient, entitlement `welcome`, a `stream` outbox row).
        welcome_expiry: Some(WelcomeExpiryContext {
            recovery_work_id,
            event: EventFanout {
                event_id: disposition_event_id,
                event_kind: EventKind::WelcomeDisposition,
                payload_bytes: vec![0xF8_u8; 8],
                recipients: vec![(
                    scenario.bob_id.clone(),
                    EventEntitlementKind::Welcome,
                    bob_pred,
                )],
                outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
            },
        }),
        welcome_response: None,
        welcome_dispositions: vec![],
    };

    let mut tx = pool.begin().await.expect("begin welcome expiry");
    let applied = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("welcome expiry applies");
    tx.commit()
        .await
        .expect("welcome expiry COMMIT past all deferred triggers");
    // No seq allocated (internal op): the counter is echoed unchanged.
    assert_eq!(applied.allocated_seq, 4);

    // Coordinate + seq counter byte-untouched (still gen 0, sv 2, next_seq 4).
    let (gen, sv, next_seq): (i64, i64, i64) = sqlx::query_as(
        "SELECT current_generation,current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((gen, sv, next_seq), (0, 2, 4));

    // The delivery is `expired`, terminal_at == expires_at.
    let (del_status, del_terminal): (String, Option<DateTime<Utc>>) = sqlx::query_as(
        "SELECT status,terminal_at FROM chat.welcome_deliveries WHERE welcome_id=$1",
    )
    .bind(welcome_id)
    .fetch_one(&pool)
    .await
    .expect("delivery");
    assert_eq!(
        (del_status.as_str(), del_terminal),
        ("expired", Some(expires_at))
    );

    // Exactly one disposition row, winner `expired`, bound to the welcomeDisposition event.
    let (winner, disp_terminal): (String, DateTime<Utc>) = sqlx::query_as(
        "SELECT winner_kind,terminal_at FROM chat.welcome_dispositions WHERE welcome_id=$1",
    )
    .bind(welcome_id)
    .fetch_one(&pool)
    .await
    .expect("disposition");
    assert_eq!((winner.as_str(), disp_terminal), ("expired", expires_at));
    let disp_event_kind: String = sqlx::query_scalar(
        "SELECT event.event_kind FROM chat.welcome_dispositions disposition \
         JOIN chat.events event ON event.event_position = disposition.event_position \
         WHERE disposition.welcome_id=$1",
    )
    .bind(welcome_id)
    .fetch_one(&pool)
    .await
    .expect("disposition event");
    assert_eq!(disp_event_kind, "welcomeDisposition");

    // The `welcomeExpired` recovery-work item: pending, at the welcome BUNDLE's
    // coordinate (gen 0, sv 2), created_at == the disposition terminal_at, for bob.
    let (rw_kind, rw_status, rw_gen, rw_sv, rw_created, rw_recipient): (
        String,
        String,
        i64,
        i64,
        DateTime<Utc>,
        String,
    ) = sqlx::query_as(
        "SELECT source_kind,status,generation,state_version,created_at,recipient_did \
         FROM chat.recovery_work_items WHERE source_id=$1",
    )
    .bind(welcome_id)
    .fetch_one(&pool)
    .await
    .expect("recovery work item");
    assert_eq!(
        (rw_kind.as_str(), rw_status.as_str(), rw_gen, rw_sv),
        ("welcomeExpired", "pending", 0, 2)
    );
    assert_eq!(rw_created, expires_at);
    assert_eq!(rw_recipient, scenario.bob_did);
    let rw_id: Uuid = sqlx::query_scalar(
        "SELECT recovery_work_id FROM chat.recovery_work_items WHERE source_id=$1",
    )
    .bind(welcome_id)
    .fetch_one(&pool)
    .await
    .expect("recovery work id");
    assert_eq!(rw_id, recovery_work_id);

    // Replay -> conflict (the disposition event id + the pending-only delivery CAS
    // are both already consumed), whole transaction rolls back, zero residue.
    let before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.recovery_work_items WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan_unscoped_for_test(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Delivery(_))),
        "welcome expiry replay must conflict, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.recovery_work_items WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(before, after, "welcome expiry replay left zero residue");
}

/// Build (but do not apply) a client-authored welcome response (acknowledge /
/// reject) against the fulfillment scenario's pending Welcome for bob. Returns the
/// plan + ctx + the delivery's `expires_at` (for verification). `applied_at` (the
/// request instant, used for every timestamp) is set just before `expires_at` so
/// the DB `terminal_at < expires_at` shape holds.
async fn build_welcome_response(
    pool: &PgPool,
    scenario: &FulfillmentScenario,
    kind: RequestEntryKind,
    successor: WelcomeStatus,
    rejection: Option<WelcomeRejectionWork>,
    byte: u8,
) -> (
    chat_protocol::state_machine::ConversationPersistencePlan,
    ExecutionContext,
    DateTime<Utc>,
) {
    let conversation_id = scenario.conversation_id;
    let bob_id = scenario.bob_id.clone();
    let bob_did = scenario.bob_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());
    let welcome_id = scenario.welcome_id;
    let fixture = &scenario.fixture;

    let expires_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT expires_at FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(pool)
            .await
            .expect("pending welcome expires_at");
    let transition_seq: i64 =
        sqlx::query_scalar("SELECT entry_seq FROM chat.welcome_bundles WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(pool)
            .await
            .expect("welcome bundle entry_seq");
    // The request instant: 1s before the welcome's expiry (the plan requires
    // `received_at < expires_at`, and the DB requires the terminal_at `< expires_at`).
    let received_ms = expires_at.timestamp_millis() - 1_000;
    let received_at = ServerTimestamp::from_unix_millis_for_test(received_ms).unwrap();
    let applied_at = DateTime::from_timestamp_millis(received_ms).unwrap();

    let evidence = RequestEvidence::for_test_welcome_response(
        kind,
        *welcome_id.as_bytes(),
        bob_id.clone(),
        *conversation_id.as_bytes(),
        scenario.coordinate,
        transition_seq as u64,
        received_at,
        byte,
    )
    .unwrap();
    let planned = plan_welcome_response_for_test(&scenario.fulfillment_state, evidence, successor)
        .expect("valid welcome response plan");
    let head_cas = ConversationHeadCasBinding::for_test_internal(
        *conversation_id.as_bytes(),
        scenario.coordinate,
        4,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let bob_pred = device_event_predecessor(pool, &bob_did, bob_device).await;
    // The client's signed authorization the disposition row binds (from ctx.entry).
    let transcript = vec![byte; 24];
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: bob_did.clone(),
            device_id: bob_device,
            key_id: fixture.bob_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Member,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
            accepted_payload_bytes: vec![byte.wrapping_add(1); 8],
            accepted_payload_sha256: Sha256::digest([byte.wrapping_add(1); 8]).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![byte.wrapping_add(2); 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![byte.wrapping_add(3); 64],
            server_fields_bytes: vec![byte.wrapping_add(4); 8],
            outer_entry_fingerprint: vec![byte.wrapping_add(5); 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![],
        events: vec![],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: Some(WelcomeResponseContext {
            event: EventFanout {
                event_id: Uuid::new_v4(),
                event_kind: EventKind::WelcomeDisposition,
                payload_bytes: vec![byte.wrapping_add(6); 8],
                recipients: vec![(bob_id.clone(), EventEntitlementKind::Welcome, bob_pred)],
                outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
            },
            rejection,
        }),
        welcome_dispositions: vec![],
    };
    (plan, ctx, expires_at)
}

#[tokio::test]
async fn welcome_acknowledgement_terminalizes_delivery_without_recovery_work() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let welcome_id = scenario.welcome_id;
    let (plan, ctx, _expires) = build_welcome_response(
        &pool,
        &scenario,
        RequestEntryKind::WelcomeAcknowledgement,
        WelcomeStatus::Acknowledged,
        None,
        0x51,
    )
    .await;

    let mut tx = pool.begin().await.expect("begin ack");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("welcome acknowledgement applies");
    tx.commit().await.expect("welcome acknowledgement COMMIT");

    // Coordinate + seq untouched.
    let (sv, next_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((sv, next_seq), (2, 4));
    // Delivery acknowledged; disposition winner acknowledged with the signed bytes,
    // NO rejection reason.
    let del_status: String =
        sqlx::query_scalar("SELECT status FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .expect("delivery");
    assert_eq!(del_status, "acknowledged");
    let (winner, has_sig, reason): (String, bool, Option<String>) = sqlx::query_as(
        "SELECT winner_kind, signed_request_bytes IS NOT NULL, rejection_reason FROM chat.welcome_dispositions WHERE welcome_id=$1",
    )
    .bind(welcome_id)
    .fetch_one(&pool)
    .await
    .expect("disposition");
    assert_eq!(winner, "acknowledged");
    assert!(
        has_sig,
        "acknowledgement disposition binds the signed request"
    );
    assert_eq!(reason, None);
    // NO recovery work for an acknowledgement.
    let rw_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.recovery_work_items WHERE source_id=$1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .expect("recovery work");
    assert_eq!(rw_count, 0);

    // Replay -> delivery-CAS conflict, zero residue.
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan_unscoped_for_test(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Delivery(_))),
        "acknowledgement replay must conflict on the delivery CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
}

#[tokio::test]
async fn welcome_rejection_terminalizes_delivery_and_creates_recovery_work() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let welcome_id = scenario.welcome_id;
    let bob_did = scenario.bob_did.clone();
    let recovery_work_id = Uuid::new_v4();
    let (plan, ctx, _expires) = build_welcome_response(
        &pool,
        &scenario,
        RequestEntryKind::WelcomeRejection,
        WelcomeStatus::Rejected,
        Some(WelcomeRejectionWork {
            recovery_work_id,
            reason: WelcomeRejectionReason::NoMatchingKeyPackage,
        }),
        0x61,
    )
    .await;

    let mut tx = pool.begin().await.expect("begin reject");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("welcome rejection applies");
    tx.commit().await.expect("welcome rejection COMMIT");

    // Delivery rejected; disposition winner rejected with signed bytes + the reason.
    let del_status: String =
        sqlx::query_scalar("SELECT status FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .expect("delivery");
    assert_eq!(del_status, "rejected");
    let (winner, has_sig, reason): (String, bool, Option<String>) = sqlx::query_as(
        "SELECT winner_kind, signed_request_bytes IS NOT NULL, rejection_reason FROM chat.welcome_dispositions WHERE welcome_id=$1",
    )
    .bind(welcome_id)
    .fetch_one(&pool)
    .await
    .expect("disposition");
    assert_eq!(winner, "rejected");
    assert!(has_sig);
    assert_eq!(reason.as_deref(), Some("noMatchingKeyPackage"));
    // A welcomeRejected recovery work item for bob, pending.
    let (rw_kind, rw_status, rw_recipient, rw_id): (String, String, String, Uuid) = sqlx::query_as(
        "SELECT source_kind,status,recipient_did,recovery_work_id FROM chat.recovery_work_items WHERE source_id=$1",
    )
    .bind(welcome_id)
    .fetch_one(&pool)
    .await
    .expect("recovery work");
    assert_eq!(
        (rw_kind.as_str(), rw_status.as_str(), rw_recipient.as_str()),
        ("welcomeRejected", "pending", bob_did.as_str())
    );
    assert_eq!(rw_id, recovery_work_id);
    let _ = conversation_id;

    // Replay -> delivery-CAS conflict, no duplicate recovery work.
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan_unscoped_for_test(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Delivery(_))),
        "rejection replay must conflict on the delivery CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let rw_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.recovery_work_items WHERE source_id=$1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rw_count, 1, "replay wrote no duplicate recovery work");
}

/// The welcome-disposition arms validate the `welcome_cas` binding LOAD-BEARING
/// against the `welcome_changes` delta. A corrupted binding (mismatched welcome id)
/// must be a hard `InconsistentPlan`, never a silently-unread witness — removing the
/// 6-field validation fails this test. (`persistence_plan_for_test` always
/// synthesizes a MATCHING binding, so corruption is the only way to drive it red.)
#[tokio::test]
async fn welcome_response_corrupted_cas_binding_is_rejected() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let welcome_id = scenario.welcome_id;
    let (plan, ctx, _expires) = build_welcome_response(
        &pool,
        &scenario,
        RequestEntryKind::WelcomeAcknowledgement,
        WelcomeStatus::Acknowledged,
        None,
        0x71,
    )
    .await;
    let bad = plan.with_welcome_cas_corrupted_for_test();
    let mut tx = pool.begin().await.expect("begin");
    let result = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &bad, &ctx).await;
    assert!(
        matches!(result, Err(ExecutorError::InconsistentPlan(_))),
        "a corrupted welcome_cas binding must be an InconsistentPlan, got {result:?}"
    );
    tx.rollback().await.expect("rollback");
    // Zero residue: the pending delivery is untouched.
    let status: String =
        sqlx::query_scalar("SELECT status FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .expect("delivery");
    assert_eq!(status, "pending");
}

/// Silent-drop guard (fulfillment arm): a plan carrying an EXTRA recovery-request
/// delta that is neither the arm's own `Open->Fulfilled` edge nor a valid
/// `Open->Superseded` supersession must be REJECTED, never silently dropped.
/// `write_prior_bound_supersessions` skips it; `reconcile_coordinate_change_families`
/// catches the `own + superseded != total` mismatch. Removing that reconciliation
/// makes this fulfillment COMMIT with the extra delta lost.
#[tokio::test]
async fn fulfillment_untracked_recovery_request_delta_is_rejected() {
    let (pool, _db) = setup().await;
    let built = build_fulfillment(&pool).await;
    let conversation_id = built.conversation_id;
    let recovery_request_id = built.recovery_request_id;
    let bad = built.plan.with_extra_untracked_recovery_request_for_test();
    let mut tx = pool.begin().await.expect("begin");
    let result =
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &bad, &built.ctx).await;
    assert!(
        matches!(result, Err(ExecutorError::InconsistentPlan(_))),
        "an untracked recovery-request delta must be an InconsistentPlan, got {result:?}"
    );
    tx.rollback().await.expect("rollback");

    // Zero residue: the accepted-state coordinate (sv 1) is untouched, the request
    // is still open, and no fulfillment transition landed.
    let sv: i64 = sqlx::query_scalar(
        "SELECT current_state_version FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!(sv, 1);
    let req_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(recovery_request_id)
    .fetch_one(&pool)
    .await
    .expect("request");
    assert_eq!(
        req_status, "open",
        "a rejected fulfillment leaves the request open"
    );
    let transitions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .expect("transitions");
    assert_eq!(
        transitions, 2,
        "only creation + acceptance transitions exist"
    );
}

/// The uncommitted generic (epoch-only) commit plan + ctx on top of a COMMITTED
/// fulfillment scenario — extracted so the reconciliation negative test can apply
/// a MUTATED plan (a corrupted welcome supersession) without committing it first.
struct BuiltGenericCommit {
    plan: chat_protocol::state_machine::ConversationPersistencePlan,
    ctx: ExecutionContext,
    conversation_id: Uuid,
    commit_transition: Uuid,
}

async fn build_generic_commit(pool: &PgPool, scenario: &FulfillmentScenario) -> BuiltGenericCommit {
    let pool = pool.clone();
    let manifest = corpus_manifest();
    let fixture = &scenario.fixture;
    let conversation_id = scenario.conversation_id;
    let prior = &scenario.fulfillment_state; // sv 2, epoch 1, alice + bob.

    // This isolated executor scenario uses an arbitrary conversation coordinate,
    // so it cannot consume the fixed-identity corpus Commit. Drive only the
    // already-verified public-state effect through the synthetic seam here; the
    // substrate corpus gate separately processes the real proposal-free Commit
    // and exact predecessor through production `process_commit`.
    let commit_bytes = corpus_file("commit-generic-public.mls");
    validate_public_commit(&commit_bytes, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
        .expect("frozen generic Commit parses as a valid public commit");
    let successor_coord = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        manifest.chain.generation,
        prior.coordinate().state_version() + 1,
        *prior.coordinate().group_id(),
        prior.coordinate().epoch() + 1,
        [0xAB_u8; 32],
        [0xCD_u8; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    let commit = chat_protocol::public_state::VerifiedCommitPublicState::for_test_generic(
        prior.public_state(),
        successor_coord,
        0,
    )
    .expect("synthetic zero-proposal commit");
    assert_eq!(successor_coord.epoch(), 2);
    assert_eq!(successor_coord.state_version(), 3);

    let commit_transition = Uuid::new_v4();
    let commit_entry = Uuid::new_v4();
    let commit_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 5_000,
    )
    .unwrap();
    let alice_key_id_bytes: [u8; 32] = Sha256::digest(&scenario.alice_sig_key).into();
    // Re-encryption: SAME author/origin/version/size as the prior snapshot; a fresh
    // nonce + 48-byte ciphertext; coordinate epoch = 2 (validate_state).
    let reencryption = MetadataSnapshotBinding::for_test_creation(
        *conversation_id.as_bytes(),
        0,
        successor_coord.epoch(),
        *successor_coord.group_context_hash(),
        fixture.creation_transition_id,
        1,
        fixture.alice_id.clone(),
        alice_key_id_bytes,
        scenario.alice_sig_key.clone().try_into().unwrap(),
        1,
        1,
        [0xE1_u8; 12],
        vec![0xE2_u8; 48],
    );
    let commit_evidence = TransitionEvidence::for_test_commit_with_metadata(
        4,
        *commit_transition.as_bytes(),
        [0x1A_u8; 32],
        commit_received,
        *prior.coordinate(),
        successor_coord,
        reencryption,
    )
    .unwrap();
    let planned = plan_commit(
        prior,
        CommitCommand {
            actor: fixture.alice_id.clone(),
            transition: commit_evidence,
            commit,
        },
    )
    .expect("valid generic commit plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *commit_entry.as_bytes(),
        *prior.coordinate(),
        4,
        commit_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let applied_at = clock_now(&pool).await;
    let payload = vec![0xE3_u8; 12];
    let transcript = vec![0xE4_u8; 12];
    let alice_pred =
        device_event_predecessor(&pool, &fixture.alice_did, fixture.alice_device).await;
    let bob_device = Uuid::from_bytes(*scenario.bob_id.device_id());
    let bob_pred = device_event_predecessor(&pool, &scenario.bob_did, bob_device).await;
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: commit_entry,
            entry_kind: "blue.catbird.chat.defs#commitEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0xE5_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0xE6_u8; 64],
            server_fields_bytes: vec![0xE7_u8; 8],
            outer_entry_fingerprint: vec![0x1A_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xF1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xF1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xF2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xF2_u8; 16]).to_vec(),
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: Some(MetadataAuthorColumns {
            author_role: "admin".to_owned(),
            author_device_status: "active".to_owned(),
            author_public_key: scenario.alice_sig_key.clone(),
            author_key_id: fixture.alice_key_id.clone(),
            metadata_snapshot_id: Uuid::new_v4(),
        }),
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: entry_audience(
            &fixture.alice_id,
            &fixture.alice_did,
            &scenario.bob_id,
            &scenario.bob_did,
        ),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0xF4_u8; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        // The epoch change supersedes the fulfillment's pending Welcome; provide its
        // welcomeDisposition event (recipient = bob, the welcome recipient).
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![WelcomeDispositionInput {
            welcome_id: scenario.welcome_id,
            event: EventFanout {
                event_id: Uuid::new_v4(),
                event_kind: EventKind::WelcomeDisposition,
                payload_bytes: vec![0xF5_u8; 8],
                recipients: vec![(
                    scenario.bob_id.clone(),
                    EventEntitlementKind::Welcome,
                    bob_pred,
                )],
                outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
            },
        }],
    };

    BuiltGenericCommit {
        plan,
        ctx,
        conversation_id,
        commit_transition,
    }
}

const ALICE_SIGNING_SEED: [u8; 32] = [
    0x38, 0x8f, 0x37, 0x73, 0x57, 0x9e, 0x8a, 0x2b, 0x5d, 0x57, 0x2d, 0x3b, 0x19, 0x85, 0x55, 0xa6,
    0x93, 0x6f, 0xb7, 0xf0, 0x13, 0xb8, 0x58, 0xe2, 0x69, 0xf6, 0x4f, 0x6e, 0x8c, 0x6b, 0x12, 0x8d,
];

fn signed_coordinate_json(coordinate: &PublicGroupSnapshotCoordinate) -> Value {
    json!({
        "conversationId": Uuid::from_bytes(*coordinate.conversation_id()),
        "generation": coordinate.generation(),
        "stateVersion": coordinate.state_version(),
        "groupId": STANDARD.encode(coordinate.group_id()),
        "epoch": coordinate.epoch(),
        "groupContextHash": STANDARD.encode(coordinate.group_context_hash()),
        "confirmationTag": STANDARD.encode(coordinate.confirmation_tag()),
        "lifecycle": "active",
    })
}

struct SignedPolicyControl {
    transition: TransitionEvidence,
    entry: ControlEntryContent,
    transition_id: Uuid,
    received_at: ServerTimestamp,
}

enum SignedPolicyChange {
    Add(String),
    ChangeRole {
        user_did: String,
        role: &'static str,
    },
}

impl SignedPolicyChange {
    fn user_did(&self) -> &str {
        match self {
            Self::Add(user_did) | Self::ChangeRole { user_did, .. } => user_did,
        }
    }
}

fn signed_policy_control(
    fixture: &CreationApply,
    prior: &ConversationState,
    seq: u64,
    mut changes: Vec<SignedPolicyChange>,
) -> SignedPolicyControl {
    let transition_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    changes.sort_by(|left, right| left.user_did().as_bytes().cmp(right.user_did().as_bytes()));
    let participant_changes: Vec<_> = changes
        .into_iter()
        .map(|change| match change {
            SignedPolicyChange::Add(user_did) => json!({
                "$type": "blue.catbird.chat.defs#addParticipant",
                "userDid": user_did,
                "status": "pending",
                "role": "member",
                "invitationProvenance": {
                    "invitedByDid": fixture.alice_did,
                    "invitedByDeviceId": fixture.alice_device,
                    "invitationTransitionId": transition_id,
                },
            }),
            SignedPolicyChange::ChangeRole { user_did, role } => json!({
                "$type": "blue.catbird.chat.defs#changeParticipantRole",
                "userDid": user_did,
                "role": role,
            }),
        })
        .collect();
    let next = PublicGroupSnapshotCoordinate::new(
        *prior.coordinate().conversation_id(),
        prior.coordinate().generation(),
        prior.coordinate().state_version() + 1,
        *prior.coordinate().group_id(),
        prior.coordinate().epoch(),
        *prior.coordinate().group_context_hash(),
        *prior.coordinate().confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    );
    let evaluation_millis = corpus_manifest().evaluation_unix_seconds as i64 * 1_000;
    let received_millis = evaluation_millis + i64::try_from(seq).unwrap() * 1_000 + 1_000;
    let signed_at = DateTime::<Utc>::from_timestamp_millis(received_millis - 500)
        .unwrap()
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let received_at_text = DateTime::<Utc>::from_timestamp_millis(received_millis)
        .unwrap()
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let signer = SigningKey::from_bytes(&ALICE_SIGNING_SEED);
    assert_eq!(
        signer.verifying_key().as_bytes(),
        prior.metadata().unwrap().signature_public_key()
    );
    let body = json!({
        "$type": "blue.catbird.chat.defs#policyTransitionBody",
        "signatureDomain": "CATBIRD-CHAT-POLICY\u{0}",
        "transitionId": transition_id,
        "actorDid": fixture.alice_did,
        "actorDeviceId": fixture.alice_device,
        "keyId": fixture.alice_key_id,
        "authGeneration": 1,
        "prior": signed_coordinate_json(prior.coordinate()),
        "next": signed_coordinate_json(&next),
        "participantChanges": participant_changes,
        "idempotencyKey": Uuid::new_v4(),
        "signedAt": signed_at,
    });
    let mut wrapper = json!({
        "body": body,
        "signature": STANDARD.encode([0_u8; 64]),
    });
    let unsigned = serde_json::to_vec(&wrapper).unwrap();
    let canonical = decode_canonical_signed_mutation(&unsigned).unwrap();
    let signature = signer.sign(canonical.transcript_bytes()).to_bytes();
    wrapper["signature"] = json!(STANDARD.encode(signature));
    let signed_wrapper = serde_json::to_vec(&wrapper).unwrap();
    let canonical = decode_canonical_signed_mutation(&signed_wrapper).unwrap();
    let outer_row = json!({
        "$type": "blue.catbird.chat.defs#policyEntry",
        "entryId": entry_id,
        "conversationId": fixture.conversation_id,
        "seq": seq,
        "signedRequest": wrapper,
        "receivedAt": received_at_text,
    });
    let outer_row_bytes = serde_json::to_vec(&outer_row).unwrap();
    let verified_entry =
        decode_and_verify_control_entry(&outer_row_bytes, signer.verifying_key().as_bytes())
            .unwrap();
    let verified_entry = rebind_persisted_control_entry(
        verified_entry,
        &signed_wrapper,
        signer.verifying_key().as_bytes(),
    )
    .unwrap();
    let outer_fingerprint = *verified_entry.outer_control_fingerprint();
    let server_fields = verified_entry.server_fields_dag_cbor().unwrap();
    let authority =
        HydrationAuthority::new(*fixture.conversation_id.as_bytes()).expect("policy authority");
    let transition = authority
        .control_transition(verified_entry)
        .expect("genuine signed policy transition");
    SignedPolicyControl {
        transition,
        entry: ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#policyEntry".to_owned(),
            accepted_payload_bytes: outer_row_bytes.clone(),
            accepted_payload_sha256: Sha256::digest(&outer_row_bytes).to_vec(),
            signed_request_bytes: signed_wrapper,
            unsigned_projection_bytes: canonical.canonical_projection().to_vec(),
            signing_transcript_bytes: canonical.transcript_bytes().to_vec(),
            request_digest: canonical.request_digest().to_vec(),
            signature: signature.to_vec(),
            server_fields_bytes: server_fields,
            outer_entry_fingerprint: outer_fingerprint.to_vec(),
        },
        transition_id,
        received_at: ServerTimestamp::from_canonical_stored(&received_at_text).unwrap(),
    }
}

fn aad_prior_json(coordinate: &PublicGroupSnapshotCoordinate) -> Value {
    json!({
        "conversationId": STANDARD.encode(coordinate.conversation_id()),
        "generation": coordinate.generation(),
        "stateVersion": coordinate.state_version(),
        "groupId": STANDARD.encode(coordinate.group_id()),
        "epoch": coordinate.epoch(),
        "groupContextHash": STANDARD.encode(coordinate.group_context_hash()),
        "confirmationTag": STANDARD.encode(coordinate.confirmation_tag()),
        "lifecycle": "active",
    })
}

/// Build a real Ed25519-signed generic Commit carrying one canonical RemoveLeaf,
/// mint its production `VerifiedControlEntry`/`HydrationAuthority` evidence, then
/// pair that authority with the synthetic public-tree seam used by executor tests.
async fn build_signed_generic_remove_commit(
    pool: &PgPool,
    scenario: &FulfillmentScenario,
) -> (BuiltGenericCommit, Uuid) {
    let mut built = build_generic_commit(pool, scenario).await;
    let fixture = &scenario.fixture;
    let prior = &scenario.fulfillment_state;
    let conversation_id = scenario.conversation_id;
    let bob_leaf = prior.leaf(&scenario.bob_id).expect("bob leaf");
    let alice_leaf = prior.leaf(&fixture.alice_id).expect("alice leaf");
    let successor = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        prior.coordinate().generation(),
        prior.coordinate().state_version() + 1,
        *prior.coordinate().group_id(),
        prior.coordinate().epoch() + 1,
        [0xAB_u8; 32],
        [0xCD_u8; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    let commit_bytes = [0x31_u8; 8];
    let ciphertext = [0xE2_u8; 48];
    let metadata = prior.metadata().expect("prior metadata");
    let transition_id = built.commit_transition;
    let signed_at = "2026-07-22T14:05:09.123Z";
    let received_at = "2026-07-22T14:05:10.123Z";
    let signer = SigningKey::from_bytes(&ALICE_SIGNING_SEED);
    assert_eq!(
        signer.verifying_key().as_bytes(),
        metadata.signature_public_key(),
        "fixture seed must be the exact active Alice signing key"
    );
    assert_eq!(
        ed25519_key_id(signer.verifying_key().as_bytes())
            .expect("Alice key id")
            .as_str(),
        fixture.alice_key_id
    );
    let aad = json!({
        "protocolVersion": "1",
        "conversationId": STANDARD.encode(conversation_id.as_bytes()),
        "generation": prior.coordinate().generation(),
        "transitionId": STANDARD.encode(transition_id.as_bytes()),
        "prior": aad_prior_json(prior.coordinate()),
    });
    let body = json!({
        "$type": "blue.catbird.chat.defs#commitTransitionBody",
        "signatureDomain": "CATBIRD-CHAT-COMMIT\u{0}",
        "transitionId": transition_id,
        "actorDid": fixture.alice_did,
        "actorDeviceId": fixture.alice_device,
        "keyId": fixture.alice_key_id,
        "authGeneration": 1,
        "prior": signed_coordinate_json(prior.coordinate()),
        "next": signed_coordinate_json(&successor),
        "aad": aad,
        "manifest": {
            "participantChanges": [],
            "leafChanges": [{
                "$type": "blue.catbird.chat.defs#removeLeaf",
                "userDid": scenario.bob_did,
                "deviceId": Uuid::from_bytes(*scenario.bob_id.device_id()),
            }],
        },
        "commit": {
            "framing": "mlsMessage",
            "contentType": "publicMessageCommit",
            "bytes": STANDARD.encode(commit_bytes),
            "sha256": STANDARD.encode(Sha256::digest(commit_bytes)),
        },
        "metadataSnapshot": {
            "coordinate": {
                "conversationId": STANDARD.encode(conversation_id.as_bytes()),
                "generation": successor.generation(),
                "groupId": STANDARD.encode(successor.group_id()),
                "epoch": successor.epoch(),
                "groupContextHash": STANDARD.encode(successor.group_context_hash()),
                "confirmationTag": STANDARD.encode(successor.confirmation_tag()),
            },
            "originTransitionId": Uuid::from_bytes(*metadata.origin_transition_id()),
            "metadataVersion": metadata.metadata_version(),
            "nonce": STANDARD.encode([0xE1_u8; 12]),
            "ciphertext": STANDARD.encode(ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(ciphertext)),
            "ciphertextSize": ciphertext.len(),
            "authorProof": {
                "authorDid": fixture.alice_did,
                "authorDeviceId": Uuid::from_bytes(*metadata.author().device_id()),
                "authorKeyId": fixture.alice_key_id,
                "signaturePublicKey": STANDARD.encode(metadata.signature_public_key()),
                "authGenerationAtOrigin": metadata.author_auth_generation_at_origin(),
                "originTransitionId": Uuid::from_bytes(*metadata.author_origin_transition_id()),
                "originSeq": metadata.author_origin_seq(),
                "roleAtOrigin": "admin",
                "deviceStatusAtOrigin": "active",
            },
        },
        "idempotencyKey": conversation_id,
        "signedAt": signed_at,
    });
    let mut wrapper = json!({
        "body": body,
        "signature": STANDARD.encode([0_u8; 64]),
    });
    let unsigned = serde_json::to_vec(&wrapper).expect("unsigned wrapper");
    let canonical =
        decode_canonical_signed_mutation(&unsigned).expect("canonical generic Remove wrapper");
    let signature = signer.sign(canonical.transcript_bytes()).to_bytes();
    wrapper["signature"] = json!(STANDARD.encode(signature));
    let signed_wrapper = serde_json::to_vec(&wrapper).expect("signed wrapper");
    let canonical =
        decode_canonical_signed_mutation(&signed_wrapper).expect("signed canonical wrapper");
    let verified = chat_protocol::transcript::decode_and_verify_signed_mutation(
        &signed_wrapper,
        signer.verifying_key().as_bytes(),
    )
    .expect("real Alice signature verifies");
    let VerifiedMutationProjection::CommitTransition(projection) = verified.projection() else {
        unreachable!()
    };
    let mut exact_aad = b"CATBIRD-CHAT-MLS-AAD-COMMIT\0".to_vec();
    exact_aad.extend_from_slice(&projection.aad().canonical_dag_cbor());
    let aad_sha256: [u8; 32] = Sha256::digest(exact_aad).into();
    let entry_id = built
        .ctx
        .authority
        .control_entry()
        .expect("generic commit carries control-entry authority")
        .entry_id;
    let row = json!({
        "$type": "blue.catbird.chat.defs#commitEntry",
        "entryId": entry_id,
        "conversationId": conversation_id,
        "seq": 4,
        "signedRequest": wrapper,
        "receivedAt": received_at,
    });
    let row_bytes = serde_json::to_vec(&row).expect("commit control row");
    let verified_entry =
        decode_and_verify_control_entry(&row_bytes, signer.verifying_key().as_bytes())
            .expect("production commit control verification");
    let verified_entry = rebind_persisted_control_entry(
        verified_entry,
        &signed_wrapper,
        signer.verifying_key().as_bytes(),
    )
    .expect("bind exact accepted signed wrapper");
    let outer_fingerprint = *verified_entry.outer_control_fingerprint();
    let server_fields = verified_entry
        .server_fields_dag_cbor()
        .expect("empty server fields");
    let authority = HydrationAuthority::new(*conversation_id.as_bytes()).unwrap();
    let transition = authority
        .control_transition(verified_entry)
        .expect("production transition authority");
    let commit = chat_protocol::public_state::VerifiedCommitPublicState::for_test_remove(
        prior.public_state(),
        successor,
        alice_leaf.leaf_index(),
        &[bob_leaf.leaf_index()],
    )
    .expect("coherent generic Remove public state")
    .with_verified_bindings_for_test(Sha256::digest(commit_bytes).into(), aad_sha256)
    .expect("bind exact signed Commit/AAD digests");
    let planned = plan_commit(
        prior,
        CommitCommand {
            actor: fixture.alice_id.clone(),
            transition,
            commit,
        },
    )
    .expect("signed generic Remove plan");
    let received = ServerTimestamp::from_canonical_stored(received_at).unwrap();
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        *prior.coordinate(),
        4,
        received,
    );
    built.plan = persistence_plan_for_test(planned, head_cas);
    built.ctx.authority = ExecutionAuthority::ControlEntry(ControlEntryContent {
        entry_id,
        entry_kind: "blue.catbird.chat.defs#commitEntry".to_owned(),
        accepted_payload_bytes: row_bytes.clone(),
        accepted_payload_sha256: Sha256::digest(&row_bytes).to_vec(),
        signed_request_bytes: signed_wrapper,
        unsigned_projection_bytes: canonical.canonical_projection().to_vec(),
        signing_transcript_bytes: canonical.transcript_bytes().to_vec(),
        request_digest: canonical.request_digest().to_vec(),
        signature: signature.to_vec(),
        server_fields_bytes: server_fields,
        outer_entry_fingerprint: outer_fingerprint.to_vec(),
    });
    built.ctx.spine.leaf_count = 1;
    built.ctx.entry_recipients = vec![
        (fixture.alice_id.clone(), EntryEntitlementKind::Control),
        (scenario.bob_id.clone(), EntryEntitlementKind::IntervalClose),
    ];
    let bob_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices \
         WHERE conversation_id=$1 AND user_did=$2 AND device_id=$3 AND active",
    )
    .bind(conversation_id)
    .bind(&scenario.bob_did)
    .bind(Uuid::from_bytes(*scenario.bob_id.device_id()))
    .fetch_one(pool)
    .await
    .expect("active bob leaf period");
    built.ctx.closing_leaf_periods = vec![(scenario.bob_id.clone(), bob_leaf_period)];
    (built, bob_leaf_period)
}

#[tokio::test]
async fn signed_generic_remove_commit_closes_only_removed_leaf_and_interval() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let (built, bob_leaf_period) = build_signed_generic_remove_commit(&pool, &scenario).await;
    let applied_at = built.ctx.applied_at;
    let outer_fingerprint = built
        .ctx
        .authority
        .control_entry()
        .expect("generic commit carries control-entry authority")
        .outer_entry_fingerprint
        .clone();

    let mut tx = pool.begin().await.expect("begin signed generic Remove");
    let applied =
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &built.plan, &built.ctx)
            .await
            .expect("signed generic Remove applies");
    tx.commit()
        .await
        .expect("signed generic Remove COMMIT past deferred constraints");
    assert_eq!(applied.allocated_seq, 4);

    // Verify from a fresh transaction, not from the writer's transaction view.
    let mut verify = pool.begin().await.expect("fresh verification transaction");
    let (state_version, next_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations \
         WHERE conversation_id=$1",
    )
    .bind(built.conversation_id)
    .fetch_one(&mut *verify)
    .await
    .expect("advanced head");
    assert_eq!((state_version, next_seq), (3, 5));
    let (state_kind, epoch, leaf_count): (String, i64, i64) = sqlx::query_as(
        "SELECT state_kind,epoch,leaf_count FROM chat.generation_states \
         WHERE conversation_id=$1 AND generation=0 AND state_version=3",
    )
    .bind(built.conversation_id)
    .fetch_one(&mut *verify)
    .await
    .expect("successor generation state");
    assert_eq!((state_kind.as_str(), epoch, leaf_count), ("commit", 2, 1));
    let (kind, entry_seq, accepted_at): (String, i64, DateTime<Utc>) = sqlx::query_as(
        "SELECT kind,entry_seq,accepted_at FROM chat.transitions WHERE transition_id=$1",
    )
    .bind(built.commit_transition)
    .fetch_one(&mut *verify)
    .await
    .expect("commit transition");
    assert_eq!(
        (kind.as_str(), entry_seq, accepted_at),
        ("commit", 4, applied_at)
    );
    let metadata_snapshots: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.metadata_snapshots WHERE producing_transition_id=$1",
    )
    .bind(built.commit_transition)
    .fetch_one(&mut *verify)
    .await
    .expect("metadata snapshot");
    assert_eq!(metadata_snapshots, 1);

    let removed: (
        bool,
        Option<i64>,
        Option<Uuid>,
        Option<i64>,
        Option<DateTime<Utc>>,
    ) = sqlx::query_as(
        "SELECT active,removed_state_version,removed_transition_id,removed_seq,removed_at \
             FROM chat.member_devices WHERE leaf_period_id=$1",
    )
    .bind(bob_leaf_period)
    .fetch_one(&mut *verify)
    .await
    .expect("removed leaf period");
    assert_eq!(
        removed,
        (
            false,
            Some(3),
            Some(built.commit_transition),
            Some(4),
            Some(applied_at)
        )
    );
    let interval: (
        Option<i64>,
        Option<i64>,
        Option<Uuid>,
        Option<Vec<u8>>,
        Option<String>,
        Option<Uuid>,
        Option<DateTime<Utc>>,
    ) = sqlx::query_as(
        "SELECT terminal_seq,closing_state_version,closing_transition_id,\
                closing_outer_entry_fingerprint,closing_kind,closing_leaf_period_id,removed_at \
         FROM chat.application_intervals \
         WHERE conversation_id=$1 AND recipient_did=$2 AND recipient_device_id=$3",
    )
    .bind(built.conversation_id)
    .bind(&scenario.bob_did)
    .bind(Uuid::from_bytes(*scenario.bob_id.device_id()))
    .fetch_one(&mut *verify)
    .await
    .expect("removed device interval");
    assert_eq!(
        interval,
        (
            Some(4),
            Some(3),
            Some(built.commit_transition),
            Some(outer_fingerprint),
            Some("remove".to_owned()),
            Some(bob_leaf_period),
            Some(applied_at),
        )
    );

    let bob_participant: (bool, Option<Uuid>, Option<i64>, Option<DateTime<Utc>>) = sqlx::query_as(
        "SELECT current_membership,removing_transition_id,removing_seq,removed_at \
             FROM chat.participants WHERE conversation_id=$1 AND user_did=$2",
    )
    .bind(built.conversation_id)
    .bind(&scenario.bob_did)
    .fetch_one(&mut *verify)
    .await
    .expect("bob participant remains active");
    assert_eq!(bob_participant, (true, None, None, None));
    let alice_active_leaf: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.member_devices \
         WHERE conversation_id=$1 AND user_did=$2 AND active",
    )
    .bind(built.conversation_id)
    .bind(&scenario.fixture.alice_did)
    .fetch_one(&mut *verify)
    .await
    .expect("remaining leaf");
    assert_eq!(alice_active_leaf, 1);
    let alice_open_interval: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.application_intervals \
         WHERE conversation_id=$1 AND recipient_did=$2 AND terminal_seq IS NULL",
    )
    .bind(built.conversation_id)
    .bind(&scenario.fixture.alice_did)
    .fetch_one(&mut *verify)
    .await
    .expect("remaining interval");
    assert_eq!(alice_open_interval, 1);
    let welcome_counts: (i64, i64) = sqlx::query_as(
        "SELECT count(*),count(*) FILTER (WHERE status='superseded') \
         FROM chat.welcome_deliveries delivery \
         JOIN chat.welcome_bundles bundle USING (welcome_id) \
         WHERE bundle.conversation_id=$1",
    )
    .bind(built.conversation_id)
    .fetch_one(&mut *verify)
    .await
    .expect("no generic-commit Welcome");
    assert_eq!(welcome_counts, (1, 1));
    let fulfilled_recovery: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.leaf_recovery_requests \
         WHERE conversation_id=$1 AND status='fulfilled'",
    )
    .bind(built.conversation_id)
    .fetch_one(&mut *verify)
    .await
    .expect("no generic recovery fulfillment");
    assert_eq!(fulfilled_recovery, 1);
    verify
        .rollback()
        .await
        .expect("close verification transaction");
}

#[derive(Clone, Copy, Debug)]
enum GenericRemoveCorruption {
    Add,
    EmptyLeafDelta,
    MissingInterval,
    IntervalWithoutLeaf,
    DuplicateInterval,
    WrongCloseKind,
    WrongCloseFingerprint,
    WrongIntervalCoordinate,
    MissingClosingLeafContext,
    ForeignClosingLeafContext,
    DuplicateClosingLeafContext,
    MismatchedClosingLeafPeriod,
}

#[tokio::test]
async fn signed_generic_remove_commit_rejects_nonbijective_effect_shapes() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let alice_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices \
         WHERE conversation_id=$1 AND user_did=$2 AND device_id=$3 AND active",
    )
    .bind(scenario.conversation_id)
    .bind(&scenario.fixture.alice_did)
    .bind(scenario.fixture.alice_device)
    .fetch_one(&pool)
    .await
    .expect("active Alice leaf period");
    let bob_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices \
         WHERE conversation_id=$1 AND user_did=$2 AND device_id=$3 AND active",
    )
    .bind(scenario.conversation_id)
    .bind(&scenario.bob_did)
    .bind(Uuid::from_bytes(*scenario.bob_id.device_id()))
    .fetch_one(&pool)
    .await
    .expect("active Bob leaf period");
    let cases = [
        GenericRemoveCorruption::Add,
        GenericRemoveCorruption::EmptyLeafDelta,
        GenericRemoveCorruption::MissingInterval,
        GenericRemoveCorruption::IntervalWithoutLeaf,
        GenericRemoveCorruption::DuplicateInterval,
        GenericRemoveCorruption::WrongCloseKind,
        GenericRemoveCorruption::WrongCloseFingerprint,
        GenericRemoveCorruption::WrongIntervalCoordinate,
        GenericRemoveCorruption::MissingClosingLeafContext,
        GenericRemoveCorruption::ForeignClosingLeafContext,
        GenericRemoveCorruption::DuplicateClosingLeafContext,
        GenericRemoveCorruption::MismatchedClosingLeafPeriod,
    ];

    for case in cases {
        let (mut built, bob_leaf_period) =
            build_signed_generic_remove_commit(&pool, &scenario).await;
        match case {
            GenericRemoveCorruption::MissingClosingLeafContext => {
                built.ctx.closing_leaf_periods.clear();
            }
            GenericRemoveCorruption::ForeignClosingLeafContext => {
                built.ctx.closing_leaf_periods =
                    vec![(scenario.fixture.alice_id.clone(), bob_leaf_period)];
            }
            GenericRemoveCorruption::DuplicateClosingLeafContext => {
                built
                    .ctx
                    .closing_leaf_periods
                    .push((scenario.bob_id.clone(), Uuid::new_v4()));
            }
            GenericRemoveCorruption::MismatchedClosingLeafPeriod => {
                built.ctx.closing_leaf_periods = vec![(scenario.bob_id.clone(), alice_leaf_period)];
            }
            _ => {}
        }
        let plan = match case {
            GenericRemoveCorruption::Add => built.plan.with_generic_remove_add_for_test(),
            GenericRemoveCorruption::EmptyLeafDelta => {
                built.plan.with_generic_remove_empty_leaf_delta_for_test()
            }
            GenericRemoveCorruption::MissingInterval => {
                built.plan.with_generic_remove_interval_dropped_for_test()
            }
            GenericRemoveCorruption::IntervalWithoutLeaf => {
                built.plan.with_generic_remove_leaf_dropped_for_test()
            }
            GenericRemoveCorruption::DuplicateInterval => built
                .plan
                .with_generic_remove_interval_duplicated_for_test(),
            GenericRemoveCorruption::WrongCloseKind => built
                .plan
                .with_generic_remove_close_kind_corrupted_for_test(),
            GenericRemoveCorruption::WrongCloseFingerprint => built
                .plan
                .with_generic_remove_close_fingerprint_corrupted_for_test(),
            GenericRemoveCorruption::WrongIntervalCoordinate => built
                .plan
                .with_generic_remove_interval_coordinate_corrupted_for_test(),
            GenericRemoveCorruption::MissingClosingLeafContext
            | GenericRemoveCorruption::ForeignClosingLeafContext
            | GenericRemoveCorruption::DuplicateClosingLeafContext
            | GenericRemoveCorruption::MismatchedClosingLeafPeriod => built.plan,
        };
        let mut tx = pool.begin().await.expect("begin corrupted generic Remove");
        let result =
            apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &built.ctx).await;
        match case {
            GenericRemoveCorruption::MissingClosingLeafContext => assert!(
                matches!(result, Err(ExecutorError::MissingContext(_))),
                "{case:?} must fail MissingContext, got {result:?}"
            ),
            _ => assert!(
                matches!(result, Err(ExecutorError::InconsistentPlan(_))),
                "{case:?} must fail InconsistentPlan, got {result:?}"
            ),
        }
        tx.rollback().await.expect("rollback corrupted plan");
    }

    let swapped_bindings = [
        ActiveLeafPeriodBinding {
            leaf_period_id: alice_leaf_period,
            conversation_id: scenario.conversation_id,
            generation: 0,
            user_did: scenario.bob_did.clone(),
            device_id: Uuid::from_bytes(*scenario.bob_id.device_id()),
        },
        ActiveLeafPeriodBinding {
            leaf_period_id: bob_leaf_period,
            conversation_id: scenario.conversation_id,
            generation: 0,
            user_did: scenario.fixture.alice_did.clone(),
            device_id: scenario.fixture.alice_device,
        },
    ];
    let mut tx = pool
        .begin()
        .await
        .expect("begin swapped leaf-period binding");
    assert!(
        !lock_active_leaf_period_bindings(&mut tx, &swapped_bindings)
            .await
            .expect("lock swapped active leaf-period bindings"),
        "two active periods swapped across devices must not match"
    );
    tx.rollback()
        .await
        .expect("rollback swapped leaf-period binding");

    let (state_version, transitions): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,\
                (SELECT count(*) FROM chat.transitions WHERE conversation_id=$1) \
         FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(scenario.conversation_id)
    .fetch_one(&pool)
    .await
    .expect("all adversarial cases leave zero residue");
    assert_eq!((state_version, transitions), (2, 3));
}

#[tokio::test]
async fn generic_commit_commits_epoch_bump_and_reencrypts_metadata() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let BuiltGenericCommit {
        plan,
        ctx,
        conversation_id,
        commit_transition,
    } = build_generic_commit(&pool, &scenario).await;

    let mut tx = pool.begin().await.expect("begin generic commit");
    let applied = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("generic commit applies");
    tx.commit()
        .await
        .expect("generic commit COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 4);

    // sv 2 -> 3, seq 4 -> 5; commit gen_state at the NEW epoch 2, leaf_count 2.
    let (sv, next_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((sv, next_seq), (3, 5));
    let (skind, sepoch, sleaf): (String, i64, i64) = sqlx::query_as(
        "SELECT state_kind,epoch,leaf_count FROM chat.generation_states WHERE conversation_id=$1 AND state_version=3",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("commit gen state");
    assert_eq!((skind.as_str(), sepoch, sleaf), ("commit", 2, 2));
    // New hash/tag differ from the prior state.
    let (prior_hash, new_hash): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT (SELECT group_context_hash FROM chat.generation_states WHERE conversation_id=$1 AND state_version=2), \
                (SELECT group_context_hash FROM chat.generation_states WHERE conversation_id=$1 AND state_version=3)",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("hashes");
    assert_ne!(
        prior_hash, new_hash,
        "generic commit rotates the group context hash"
    );
    // No membership change: still exactly 2 active leaves, no new participant.
    let leaves: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.member_devices WHERE conversation_id=$1 AND active",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("leaves");
    assert_eq!(leaves, 2);
    // The re-encryption snapshot for the commit transition.
    let snap_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.metadata_snapshots WHERE producing_transition_id=$1",
    )
    .bind(commit_transition)
    .fetch_one(&pool)
    .await
    .expect("snapshot");
    assert_eq!(snap_count, 1);
    let (tkind, eseq): (String, i64) = sqlx::query_as(
        "SELECT kind,entry_seq FROM chat.transitions WHERE conversation_id=$1 AND kind='commit'",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("commit transition");
    assert_eq!((tkind.as_str(), eseq), ("commit", 4));

    // Replay -> head CAS conflict, zero residue.
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan_unscoped_for_test(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Transition(_))),
        "generic commit replay must conflict on the head CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "generic commit replay left zero residue");
}

/// Silent-drop guard (generic commit arm — the welcome MINOR): a generic commit
/// whose ONLY welcome delta is a non-supersession shape (`Pending->Expired`, which
/// `write_welcome_supersessions` skips) must be REJECTED, not committed with the
/// durable Welcome delivery left un-terminalized. `reconcile_coordinate_change_families`
/// catches `own(0) + superseded(0) != total(1)`. Removing the welcome reconciliation
/// makes this generic commit COMMIT while silently dropping the welcome supersession.
#[tokio::test]
async fn generic_commit_untracked_welcome_delta_is_rejected() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let welcome_id = scenario.welcome_id;
    let built = build_generic_commit(&pool, &scenario).await;
    let bad = built.plan.with_welcome_supersession_corrupted_for_test();
    let mut tx = pool.begin().await.expect("begin");
    let result =
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &bad, &built.ctx).await;
    assert!(
        matches!(result, Err(ExecutorError::InconsistentPlan(_))),
        "a corrupted welcome supersession must be an InconsistentPlan, got {result:?}"
    );
    tx.rollback().await.expect("rollback");

    // Zero residue: the epoch commit never landed (head still at sv 2), and the
    // prior pending Welcome delivery is UNTOUCHED (still pending, not superseded).
    let sv: i64 = sqlx::query_scalar(
        "SELECT current_state_version FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!(sv, 2);
    let welcome_status: String =
        sqlx::query_scalar("SELECT status FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .expect("welcome delivery");
    assert_eq!(
        welcome_status, "pending",
        "a rejected commit leaves the prior Welcome delivery pending"
    );
}

/// Build + COMMIT a `leaveRequest` by the active member `bob` (leafed at the
/// fulfillment-scenario sv 2 / epoch 1 coordinate), returning the resulting
/// in-memory state (with the pending consent) + the leave-request id + the seq
/// the entry landed at, so the cancellation test can build on it.
async fn commit_leave_request(
    pool: &PgPool,
    scenario: &FulfillmentScenario,
    request_seq: u64,
    received_at: ServerTimestamp,
) -> (
    ConversationState,
    Uuid,
    u64,
    chat_protocol::state_machine::ConversationPersistencePlan,
    ExecutionContext,
) {
    let fixture = &scenario.fixture;
    let conversation_id = scenario.conversation_id;
    let bob_id = scenario.bob_id.clone();
    let bob_did = scenario.bob_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());
    let request_id = Uuid::new_v4();
    let evidence = RequestEvidence::for_test(
        RequestEntryKind::LeaveRequest,
        request_seq,
        *request_id.as_bytes(),
        bob_id.clone(),
        *conversation_id.as_bytes(),
        received_at,
        0x71,
    )
    .unwrap();
    let registration = LockedRegistrationProjection::for_test(&evidence);
    let planned = plan_leave_request(
        &scenario.fulfillment_state,
        LeaveRequestCommand {
            actor: bob_id.clone(),
            leave_request_id: *request_id.as_bytes(),
            received_at,
            evidence,
            registration,
        },
    )
    .expect("valid leave request plan");
    let state = planned.resulting_state().clone();
    let entry_id = Uuid::new_v4();
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        scenario.coordinate,
        request_seq,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);
    let applied_at = clock_now(pool).await;
    let transcript = vec![0x72_u8; 16];
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: bob_did.clone(),
            device_id: bob_device,
            key_id: fixture.bob_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Member,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#leaveRequestEntry".to_owned(),
            accepted_payload_bytes: vec![0x74_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x74_u8; 8]).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x75_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0x76_u8; 64],
            server_fields_bytes: vec![0x77_u8; 8],
            outer_entry_fingerprint: vec![0x1A_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: entry_audience(&fixture.alice_id, &fixture.alice_did, &bob_id, &bob_did),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::LeaveRequest,
            payload_bytes: vec![0x78_u8; 8],
            recipients: event_audience(
                pool,
                &fixture.alice_id,
                &fixture.alice_did,
                &bob_id,
                &bob_did,
            )
            .await,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    let mut tx = pool.begin().await.expect("begin leave request");
    let applied = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("leave request applies");
    tx.commit().await.expect("leave request COMMIT");
    (state, request_id, applied.allocated_seq, plan, ctx)
}

#[tokio::test]
async fn leave_request_commits_pending_consent_without_advancing_coordinate() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let bob_did = scenario.bob_did.clone();
    let received_at = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 5_000,
    )
    .unwrap();
    let (_state, request_id, seq, plan, ctx) =
        commit_leave_request(&pool, &scenario, 4, received_at).await;
    assert_eq!(seq, 4);

    // Coordinate UNTOUCHED (still gen 0, sv 2, active); only the seq advanced 4->5.
    let (gen, sv, next_seq, lifecycle): (i64, i64, i64, String) = sqlx::query_as(
        "SELECT current_generation,current_state_version,next_entry_seq,lifecycle FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((gen, sv, next_seq, lifecycle.as_str()), (0, 2, 5, "active"));

    // A pending, 24h-consent leave_requests row for bob; expires_at == received_at + 24h.
    let (status, req_did, rcv, exp): (String, String, DateTime<Utc>, DateTime<Utc>) = sqlx::query_as(
        "SELECT status,requester_did,received_at,expires_at FROM chat.leave_requests WHERE leave_request_id=$1",
    )
    .bind(request_id)
    .fetch_one(&pool)
    .await
    .expect("leave request row");
    assert_eq!(status, "pending");
    assert_eq!(req_did, bob_did);
    assert_eq!(exp, rcv + Duration::hours(24));

    // The leaveRequestEntry at seq 4 carries NO transition (non-mutating).
    let (entry_kind, transition): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT entry_kind,transition_id FROM chat.entries WHERE conversation_id=$1 AND seq=4",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("entry");
    assert_eq!(entry_kind, "blue.catbird.chat.defs#leaveRequestEntry");
    assert!(transition.is_none());

    // Replay -> the head CAS conflicts (seq already advanced 4->5), zero residue
    // (symmetric with the cancellation + zero-leaf happy paths).
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan_unscoped_for_test(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Transition(_))),
        "leave request replay must conflict on the head CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let leave_requests: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.leave_requests WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .expect("leave requests");
    assert_eq!(leave_requests, 1, "replay wrote no duplicate leave request");
}

#[tokio::test]
async fn leave_cancellation_terminalizes_pending_request_and_conflicts_on_replay() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let fixture = &scenario.fixture;
    let bob_id = scenario.bob_id.clone();
    let bob_did = scenario.bob_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());

    // 1. Bob opens a pending leave request (seq 4).
    let req_received = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 5_000,
    )
    .unwrap();
    let (pending_state, request_id, _seq, _plan, _ctx) =
        commit_leave_request(&pool, &scenario, 4, req_received).await;

    // 2. Bob cancels it (a later control seq 5, same coordinate).
    let cancel_received = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 6_000,
    )
    .unwrap();
    let cancel_evidence = RequestEvidence::for_test(
        RequestEntryKind::LeaveCancellation,
        5,
        *request_id.as_bytes(),
        bob_id.clone(),
        *conversation_id.as_bytes(),
        cancel_received,
        0x81,
    )
    .unwrap();
    let registration = LockedRegistrationProjection::for_test(&cancel_evidence);
    let planned = plan_leave_cancellation(
        &pending_state,
        LeaveCancellation {
            actor: bob_id.clone(),
            leave_request_id: *request_id.as_bytes(),
            received_at: cancel_received,
            evidence: cancel_evidence,
            registration,
        },
    )
    .expect("valid leave cancellation plan");
    let entry_id = Uuid::new_v4();
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        scenario.coordinate,
        5,
        cancel_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);
    let applied_at = clock_now(&pool).await;
    let transcript = vec![0x82_u8; 16];
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: bob_did.clone(),
            device_id: bob_device,
            key_id: fixture.bob_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Member,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#leaveCancellationEntry".to_owned(),
            accepted_payload_bytes: vec![0x84_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x84_u8; 8]).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x85_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0x86_u8; 64],
            server_fields_bytes: vec![0x87_u8; 8],
            outer_entry_fingerprint: vec![0x1B_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: entry_audience(&fixture.alice_id, &fixture.alice_did, &bob_id, &bob_did),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::LeaveRequest,
            payload_bytes: vec![0x88_u8; 8],
            recipients: event_audience(
                &pool,
                &fixture.alice_id,
                &fixture.alice_did,
                &bob_id,
                &bob_did,
            )
            .await,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    let mut tx = pool.begin().await.expect("begin leave cancellation");
    let applied = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("leave cancellation applies");
    tx.commit().await.expect("leave cancellation COMMIT");
    assert_eq!(applied.allocated_seq, 5);

    // The request is cancelled: terminal digest == the cancellation entry's digest,
    // terminal_at set, no terminal transition (non-mutating).
    let (status, term_digest, term_transition, term_at): (
        String,
        Option<Vec<u8>>,
        Option<Uuid>,
        Option<DateTime<Utc>>,
    ) = sqlx::query_as(
        "SELECT status,terminal_request_digest,terminal_transition_id,terminal_at FROM chat.leave_requests WHERE leave_request_id=$1",
    )
    .bind(request_id)
    .fetch_one(&pool)
    .await
    .expect("cancelled leave request");
    assert_eq!(status, "cancelled");
    assert_eq!(term_digest, Some(Sha256::digest(&transcript).to_vec()));
    assert!(term_transition.is_none());
    assert!(term_at.is_some());

    // The leaveCancellationEntry landed at seq 5, coordinate still sv 2, seq now 6.
    let entry_kind: String = sqlx::query_scalar(
        "SELECT entry_kind FROM chat.entries WHERE conversation_id=$1 AND seq=5",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("entry");
    assert_eq!(entry_kind, "blue.catbird.chat.defs#leaveCancellationEntry");
    let next_seq: i64 = sqlx::query_scalar(
        "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!(next_seq, 6);

    // Replay -> the head CAS conflicts (seq already advanced to 6), zero residue.
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan_unscoped_for_test(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Transition(_))),
        "leave cancellation replay must conflict on the head CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
}

#[tokio::test]
async fn zero_leaf_leave_commits_immediate_self_removal() {
    let (pool, _db) = setup().await;
    let fixture = build_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    let bob_id = fixture.bob_id.clone();
    let bob_did = fixture.bob_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());

    // Commit the creation (alice active/admin + bob pending/member, no leaf).
    {
        let mut tx = pool.begin().await.expect("begin creation");
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &fixture.plan, &fixture.ctx)
            .await
            .expect("creation applies");
        tx.commit().await.expect("creation COMMIT");
    }

    // Bob's existing pending participant period — the DB fact the plan can't carry
    // (the leaver is removed from the successor hydration).
    let bob_period: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob participant period");

    // Bob (pending, leafless) self-removes immediately via a zeroLeafLeave.
    let received_at = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 2_000,
    )
    .unwrap();
    let transition_id = Uuid::new_v4();
    let evidence =
        TransitionEvidence::for_test_at(2, *transition_id.as_bytes(), [0x82_u8; 32], received_at)
            .unwrap();
    let planned = plan_zero_leaf_leave(
        &fixture.state,
        ZeroLeafLeave {
            actor: bob_id.clone(),
            transition: evidence,
        },
    )
    .expect("valid zero-leaf leave plan");
    assert_eq!(planned.resulting_state().coordinate().state_version(), 1);
    let entry_id = Uuid::new_v4();
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        2,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);
    let applied_at = clock_now(&pool).await;
    let transcript = vec![0x92_u8; 16];
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: bob_did.clone(),
            device_id: bob_device,
            key_id: fixture.bob_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Member,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#zeroLeafLeaveEntry".to_owned(),
            accepted_payload_bytes: vec![0x94_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x94_u8; 8]).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x95_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0x96_u8; 64],
            server_fields_bytes: vec![0x97_u8; 8],
            outer_entry_fingerprint: vec![0x1C_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xE1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xE1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xE2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xE2_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: entry_audience(&fixture.alice_id, &fixture.alice_did, &bob_id, &bob_did),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x98_u8; 8],
            recipients: event_audience(
                &pool,
                &fixture.alice_id,
                &fixture.alice_did,
                &bob_id,
                &bob_did,
            )
            .await,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![(bob_id.principal().clone(), bob_period)],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };

    let mut tx = pool.begin().await.expect("begin zero-leaf leave");
    let applied = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("zero-leaf leave applies");
    tx.commit()
        .await
        .expect("zero-leaf leave COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 2);

    // Coordinate advanced sv 0 -> 1 (same generation/epoch), seq 2 -> 3.
    let (gen, sv, next_seq, lifecycle): (i64, i64, i64, String) = sqlx::query_as(
        "SELECT current_generation,current_state_version,next_entry_seq,lifecycle FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((gen, sv, next_seq, lifecycle.as_str()), (0, 1, 3, "active"));

    // A leavePolicy generation state at sv 1.
    let skind: String = sqlx::query_scalar(
        "SELECT state_kind FROM chat.generation_states WHERE conversation_id=$1 AND state_version=1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("gen state");
    assert_eq!(skind, "leavePolicy");

    // Bob's participant period is closed, bound to the leave transition; no metadata.
    let (membership, removing): (bool, Option<Uuid>) = sqlx::query_as(
        "SELECT current_membership,removing_transition_id FROM chat.participants WHERE participant_period_id=$1",
    )
    .bind(bob_period)
    .fetch_one(&pool)
    .await
    .expect("bob period");
    assert!(!membership);
    assert_eq!(removing, Some(transition_id));
    let (tkind, meta): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT kind,metadata_snapshot_id FROM chat.transitions WHERE transition_id=$1",
    )
    .bind(transition_id)
    .fetch_one(&pool)
    .await
    .expect("transition");
    assert_eq!(tkind, "leavePolicy");
    assert!(meta.is_none());

    // The zeroLeafLeaveEntry landed at seq 2.
    let entry_kind: String = sqlx::query_scalar(
        "SELECT entry_kind FROM chat.entries WHERE conversation_id=$1 AND seq=2",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("entry");
    assert_eq!(entry_kind, "blue.catbird.chat.defs#zeroLeafLeaveEntry");

    // Replay -> head CAS conflict (sv already 1), zero residue.
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan_unscoped_for_test(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Transition(_))),
        "zero-leaf leave replay must conflict on the head CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "zero-leaf leave replay left zero residue");
}

/// Concern-2 completeness for the third arm: a zeroLeafLeave (bob, pending/leafless,
/// self-removing) executed from a coordinate where the active member alice has an
/// OPEN leaf-recovery request supersedes it — request superseded / reservation
/// released / package reactivated — while still removing bob. zeroLeafLeave owns
/// none of the recovery families (own == default), same as policy; its LEAVE-request
/// staling half stays fail-closed (deferred Concerns 1/3), untouched here.
#[tokio::test]
async fn zero_leaf_leave_supersedes_prior_open_recovery_request() {
    let (pool, _db) = setup().await;
    let fixture = build_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    let bob_id = fixture.bob_id.clone();
    let bob_did = fixture.bob_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());
    {
        let mut tx = pool.begin().await.expect("begin creation");
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &fixture.plan, &fixture.ctx)
            .await
            .expect("creation applies");
        tx.commit().await.expect("creation COMMIT");
    }

    // Alice (active) opens an entry-less recovery request (eval+2000), then bob's
    // zeroLeafLeave (eval+3000, strictly after) supersedes it.
    let (rr_state, alice_rid, alice_ref) = seed_alice_open_recovery(&pool, &fixture).await;

    let bob_period: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob participant period");
    let received_at = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 3_000,
    )
    .unwrap();
    let transition_id = Uuid::new_v4();
    let evidence =
        TransitionEvidence::for_test_at(2, *transition_id.as_bytes(), [0x82_u8; 32], received_at)
            .unwrap();
    let planned = plan_zero_leaf_leave(
        &rr_state,
        ZeroLeafLeave {
            actor: bob_id.clone(),
            transition: evidence,
        },
    )
    .expect("valid zero-leaf leave plan over a co-open recovery request");
    let entry_id = Uuid::new_v4();
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        2,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);
    let applied_at = clock_now(&pool).await;
    let transcript = vec![0x92_u8; 16];
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: bob_did.clone(),
            device_id: bob_device,
            key_id: fixture.bob_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Member,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#zeroLeafLeaveEntry".to_owned(),
            accepted_payload_bytes: vec![0x94_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x94_u8; 8]).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x95_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0x96_u8; 64],
            server_fields_bytes: vec![0x97_u8; 8],
            outer_entry_fingerprint: vec![0x1C_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xE1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xE1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xE2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xE2_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: entry_audience(&fixture.alice_id, &fixture.alice_did, &bob_id, &bob_did),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x98_u8; 8],
            recipients: event_audience(
                &pool,
                &fixture.alice_id,
                &fixture.alice_did,
                &bob_id,
                &bob_did,
            )
            .await,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![(bob_id.principal().clone(), bob_period)],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };

    let mut tx = pool.begin().await.expect("begin zero-leaf leave");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("zero-leaf leave over a co-open recovery request applies");
    tx.commit()
        .await
        .expect("zero-leaf leave COMMIT past all deferred triggers");

    // bob removed + alice's recovery superseded / released / reactivated.
    let bob_current: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob membership");
    assert_eq!(bob_current, 0, "bob self-removed");
    let (alice_status, alice_res, alice_pkg): (String, String, String) = sqlx::query_as(
        "SELECT (SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1), \
                (SELECT status FROM chat.key_package_reservations WHERE recovery_request_id=$1), \
                (SELECT status FROM chat.key_packages WHERE key_package_ref=$2)",
    )
    .bind(alice_rid)
    .bind(alice_ref.to_vec())
    .fetch_one(&pool)
    .await
    .expect("alice superseded recovery state");
    assert_eq!(
        (
            alice_status.as_str(),
            alice_res.as_str(),
            alice_pkg.as_str()
        ),
        ("superseded", "released", "available")
    );
}

#[tokio::test]
async fn leave_fulfillment_commits_remove_and_supersedes_pending_welcome() {
    let (pool, _db) = setup().await;
    let manifest = corpus_manifest();
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let bob_id = scenario.bob_id.clone();
    let bob_did = scenario.bob_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());
    let welcome_id = scenario.welcome_id;
    let alice_id = scenario.fixture.alice_id.clone();
    let alice_did = scenario.fixture.alice_did.clone();
    let alice_device = scenario.fixture.alice_device;
    let alice_key_id = scenario.fixture.alice_key_id.clone();
    let creation_transition_id = scenario.fixture.creation_transition_id;
    let protocol_instance_id = scenario.fixture.protocol_instance_id;

    // 1. Bob opens a pending leave request (seq 4).
    let req_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 5_000,
    )
    .unwrap();
    let (pending_state, leave_request_id, _seq, _plan, _ctx) =
        commit_leave_request(&pool, &scenario, 4, req_received).await;

    // Bob's existing leaf + participant periods — the DB facts the successor
    // hydration can't carry (bob is removed from it).
    let bob_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2 AND active",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob leaf period");
    let bob_participant_period: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob participant period");

    // 2. Alice fulfills the retained consent with a Remove commit removing bob.
    let alice_leaf_index = pending_state
        .leaf(&alice_id)
        .expect("alice leaf")
        .leaf_index();
    let bob_leaf_index = pending_state.leaf(&bob_id).expect("bob leaf").leaf_index();
    let successor_coord = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        manifest.chain.generation,
        pending_state.coordinate().state_version() + 1,
        *pending_state.coordinate().group_id(),
        pending_state.coordinate().epoch() + 1,
        [0xD1_u8; 32],
        [0xD2_u8; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    assert_eq!(successor_coord.state_version(), 3);
    assert_eq!(successor_coord.epoch(), 2);
    let commit = chat_protocol::public_state::VerifiedCommitPublicState::for_test_remove(
        pending_state.public_state(),
        successor_coord,
        alice_leaf_index,
        &[bob_leaf_index],
    )
    .expect("synthetic sealed remove evidence");

    let fulfill_transition = Uuid::new_v4();
    let fulfill_entry = Uuid::new_v4();
    let fulfill_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 6_000,
    )
    .unwrap();
    let alice_key_id_bytes: [u8; 32] = Sha256::digest(&scenario.alice_sig_key).into();
    // Re-encryption: SAME author/origin/version/size as the creation snapshot; a
    // fresh nonce + ciphertext; coordinate epoch = 2 (validate_state).
    let reencryption = MetadataSnapshotBinding::for_test_creation(
        *conversation_id.as_bytes(),
        0,
        successor_coord.epoch(),
        *successor_coord.group_context_hash(),
        creation_transition_id,
        1,
        alice_id.clone(),
        alice_key_id_bytes,
        scenario.alice_sig_key.clone().try_into().unwrap(),
        1,
        1,
        [0xF7_u8; 12],
        vec![0xF8_u8; 48],
    );
    let fulfill_evidence = TransitionEvidence::for_test_leave_fulfillment_with_metadata(
        5,
        *fulfill_transition.as_bytes(),
        [0x1D_u8; 32],
        fulfill_received,
        *leave_request_id.as_bytes(),
        *pending_state.coordinate(),
        successor_coord,
        bob_id.clone(),
        reencryption,
    )
    .unwrap();
    let planned = plan_leave_fulfillment(
        &pending_state,
        LeaveFulfillment {
            actor: alice_id.clone(),
            requester: bob_id.principal().clone(),
            leave_request_id: *leave_request_id.as_bytes(),
            transition: fulfill_evidence,
            commit,
        },
    )
    .expect("valid leave fulfillment plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *fulfill_entry.as_bytes(),
        *pending_state.coordinate(),
        5,
        fulfill_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let applied_at = clock_now(&pool).await;
    let payload = vec![0xFA_u8; 12];
    let transcript = vec![0xFB_u8; 12];
    let alice_pred = device_event_predecessor(&pool, &alice_did, alice_device).await;
    let bob_pred = device_event_predecessor(&pool, &bob_did, bob_device).await;
    let ctx = ExecutionContext {
        protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: alice_did.clone(),
            device_id: alice_device,
            key_id: alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: fulfill_entry,
            entry_kind: "blue.catbird.chat.defs#leaveCommitFulfillmentEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0xFC_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0xFD_u8; 64],
            server_fields_bytes: vec![0xFE_u8; 8],
            outer_entry_fingerprint: vec![0x1D_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xC1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xC1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xC2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xC2_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: Some(MetadataAuthorColumns {
            author_role: "admin".to_owned(),
            author_device_status: "active".to_owned(),
            author_public_key: scenario.alice_sig_key.clone(),
            author_key_id: alice_key_id.clone(),
            metadata_snapshot_id: Uuid::new_v4(),
        }),
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        // Alice (remaining) fetches the control entry; bob (removed) fetches the
        // closing control via the `intervalClose` entitlement the interval-close
        // provenance trigger requires at the terminal seq.
        entry_recipients: vec![
            (alice_id.clone(), EntryEntitlementKind::Control),
            (bob_id.clone(), EntryEntitlementKind::IntervalClose),
        ],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::LeaveRequest,
            payload_bytes: vec![0xC4_u8; 8],
            recipients: vec![(
                alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![(bob_id.clone(), bob_leaf_period)],
        closing_participant_periods: vec![(bob_id.principal().clone(), bob_participant_period)],
        reset_request_row: None,
        recovery_open: None,
        // The epoch change supersedes the fulfillment scenario's pending Welcome.
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![WelcomeDispositionInput {
            welcome_id,
            event: EventFanout {
                event_id: Uuid::new_v4(),
                event_kind: EventKind::WelcomeDisposition,
                payload_bytes: vec![0xC5_u8; 8],
                recipients: vec![(bob_id.clone(), EventEntitlementKind::Welcome, bob_pred)],
                outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
            },
        }],
    };

    let mut tx = pool.begin().await.expect("begin leave fulfillment");
    let applied = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("leave fulfillment applies");
    tx.commit()
        .await
        .expect("leave fulfillment COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 5);

    // Head at the committed successor (sv 3, seq 6).
    let (sv, next_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((sv, next_seq), (3, 6));
    // commit gen_state at epoch 2, one leaf (bob removed).
    let (skind, sepoch, sleaf): (String, i64, i64) = sqlx::query_as(
        "SELECT state_kind,epoch,leaf_count FROM chat.generation_states WHERE conversation_id=$1 AND state_version=3",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("commit gen state");
    assert_eq!((skind.as_str(), sepoch, sleaf), ("commit", 2, 1));
    // Bob's leaf is closed, bound to the leave transition.
    let (bob_active, removed_transition): (bool, Option<Uuid>) = sqlx::query_as(
        "SELECT active,removed_transition_id FROM chat.member_devices WHERE leaf_period_id=$1",
    )
    .bind(bob_leaf_period)
    .fetch_one(&pool)
    .await
    .expect("bob leaf");
    assert!(!bob_active);
    assert_eq!(removed_transition, Some(fulfill_transition));
    // Bob's interval is Remove-closed at the fulfillment seq.
    let (interval_end, close_kind): (Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT terminal_seq,closing_kind FROM chat.application_intervals WHERE conversation_id=$1 AND recipient_did=$2",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob interval");
    assert_eq!(interval_end, Some(5));
    assert_eq!(close_kind.as_deref(), Some("remove"));
    // Bob's participant is closed; the leave request is fulfilled.
    let bob_membership: bool = sqlx::query_scalar(
        "SELECT current_membership FROM chat.participants WHERE participant_period_id=$1",
    )
    .bind(bob_participant_period)
    .fetch_one(&pool)
    .await
    .expect("bob participant");
    assert!(!bob_membership);
    let (leave_status, leave_terminal): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT status,terminal_transition_id FROM chat.leave_requests WHERE leave_request_id=$1",
    )
    .bind(leave_request_id)
    .fetch_one(&pool)
    .await
    .expect("leave request");
    assert_eq!(leave_status, "fulfilled");
    assert_eq!(leave_terminal, Some(fulfill_transition));
    // The prior pending Welcome is superseded.
    let welcome_status: String =
        sqlx::query_scalar("SELECT status FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .expect("welcome");
    assert_eq!(welcome_status, "superseded");
    // The re-encryption metadata snapshot for the fulfillment transition.
    let snap_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.metadata_snapshots WHERE producing_transition_id=$1",
    )
    .bind(fulfill_transition)
    .fetch_one(&pool)
    .await
    .expect("snapshot");
    assert_eq!(snap_count, 1);

    // Replay -> head CAS conflict (head already at sv 3), zero residue.
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan_unscoped_for_test(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Transition(_))),
        "leave fulfillment replay must conflict on the head CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "leave fulfillment replay left zero residue");
}

/// The uncommitted `replace` leaf-recovery fulfillment plan + ctx (create +
/// acceptance + add-fulfillment + the bob `replace` request are already COMMITTED).
/// Extracted so a desync negative can apply a MUTATED ctx against the same state.
struct BuiltReplaceFulfillment {
    plan: chat_protocol::state_machine::ConversationPersistencePlan,
    ctx: ExecutionContext,
    conversation_id: Uuid,
    bob_did: String,
    bob_signature_key: Vec<u8>,
    bob_old_leaf_period: Uuid,
    replace_transition: Uuid,
    replace_request_id: Uuid,
    replace_welcome_id: Uuid,
    scenario_welcome_id: Uuid,
    new_ref: [u8; 32],
    new_package_not_after: DateTime<Utc>,
}

async fn build_replace_fulfillment(pool: &PgPool) -> BuiltReplaceFulfillment {
    let pool = pool.clone();
    let manifest = corpus_manifest();
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let bob_id = scenario.bob_id.clone();
    let bob_did = scenario.bob_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());
    let bob_key_id = scenario.fixture.bob_key_id.clone();
    let alice_id = scenario.fixture.alice_id.clone();
    let alice_did = scenario.fixture.alice_did.clone();
    let alice_device = scenario.fixture.alice_device;
    let alice_key_id = scenario.fixture.alice_key_id.clone();
    let creation_transition_id = scenario.fixture.creation_transition_id;
    let protocol_instance_id = scenario.fixture.protocol_instance_id;
    let scenario_welcome_id = scenario.welcome_id;

    // Bob's current (add-fulfillment) leaf period — the OLD leaf a `replace` closes.
    let bob_old_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2 AND active",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob old leaf period");

    // 1. Bob opens a REPLACE recovery request for his own leaf (bound to sv 2),
    //    reserving a FRESH key package. A leaf recovery keeps the device's signing
    //    identity, so the fresh package is owned by bob's EXISTING key. Internal op
    //    — the coordinate + seq counter are byte-untouched.
    let new_ref = random_ref32();
    let new_package_not_after =
        seed_key_package(&pool, &bob_did, bob_device, &bob_key_id, &new_ref).await;
    let req_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 5_000,
    )
    .unwrap();
    let pkg_not_after_ts =
        ServerTimestamp::from_unix_millis_for_test(new_package_not_after.timestamp_millis())
            .unwrap();
    let replace_request_id = Uuid::new_v4();
    let req_evidence = RequestEvidence::for_test(
        RequestEntryKind::LeafRecoveryRequest,
        4,
        *replace_request_id.as_bytes(),
        bob_id.clone(),
        *conversation_id.as_bytes(),
        req_received,
        0x81,
    )
    .unwrap();
    let req_planned = plan_leaf_recovery_request(
        &scenario.fulfillment_state,
        LeafRecoveryRequestCommand {
            actor: bob_id.clone(),
            recovery_request_id: *replace_request_id.as_bytes(),
            kind: LeafRecoveryKind::Replace,
            key_package_ref: new_ref,
            received_at: req_received,
            package_not_after: pkg_not_after_ts,
            evidence: req_evidence,
        },
    )
    .expect("valid bob replace request plan");
    let requested_state = req_planned.resulting_state().clone();
    let req_head = ConversationHeadCasBinding::for_test_internal(
        *conversation_id.as_bytes(),
        scenario.coordinate,
        4,
        req_received,
    );
    let req_plan = persistence_plan_for_test(req_planned, req_head);
    let req_applied_at = clock_now(&pool).await;
    let req_transcript = vec![0x82_u8; 16];
    let bob_pred_req = device_event_predecessor(&pool, &bob_did, bob_device).await;
    let req_ctx = ExecutionContext {
        protocol_instance_id,
        applied_at: req_applied_at,
        actor: ExecutionActor {
            user_did: bob_did.clone(),
            device_id: bob_device,
            key_id: bob_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Member,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
            accepted_payload_bytes: vec![0x83_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x83_u8; 8]).to_vec(),
            signed_request_bytes: req_transcript.clone(),
            unsigned_projection_bytes: vec![0x84_u8; 8],
            signing_transcript_bytes: req_transcript.clone(),
            request_digest: Sha256::digest(&req_transcript).to_vec(),
            signature: vec![0x85_u8; 64],
            server_fields_bytes: vec![0x86_u8; 8],
            outer_entry_fingerprint: vec![0x18_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x87_u8; 8],
            recipients: vec![(
                bob_id.clone(),
                EventEntitlementKind::Participant,
                bob_pred_req,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: Some(RecoveryOpenContext {
            participant_period_id: None,
            package_not_after: new_package_not_after,
            replaced_leaf_period_id: Some(bob_old_leaf_period),
        }),
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    {
        let mut tx = pool.begin().await.expect("begin replace request");
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &req_plan, &req_ctx)
            .await
            .expect("replace request applies");
        tx.commit()
            .await
            .expect("replace request COMMIT past all deferred triggers");
    }

    // 2. Alice fulfills the `replace` with a synthetic rotation commit (bob's old
    //    leaf removed + a fresh bob leaf carrying `new_ref`), sv 2 -> 3, epoch 1 -> 2.
    let alice_leaf_index = requested_state
        .leaf(&alice_id)
        .expect("alice leaf")
        .leaf_index();
    let bob_leaf_index = requested_state
        .leaf(&bob_id)
        .expect("bob leaf")
        .leaf_index();
    let successor_coord = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        manifest.chain.generation,
        requested_state.coordinate().state_version() + 1,
        *requested_state.coordinate().group_id(),
        requested_state.coordinate().epoch() + 1,
        [0xB1_u8; 32],
        [0xB2_u8; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    assert_eq!(successor_coord.state_version(), 3);
    assert_eq!(successor_coord.epoch(), 2);
    let new_encryption_key = vec![0xB6_u8; 32];
    let commit = chat_protocol::public_state::VerifiedCommitPublicState::for_test_replace(
        requested_state.public_state(),
        successor_coord,
        alice_leaf_index,
        bob_leaf_index,
        new_encryption_key,
        new_ref,
    )
    .expect("synthetic sealed replace evidence");
    let welcome_wire = corpus_file("welcome.mls");
    let welcome = chat_protocol::public_state::VerifiedRecoveryWelcome::for_test_bound(
        welcome_wire.clone(),
        new_ref,
    );
    let replace_welcome_id = Uuid::new_v4();
    let replace_transition = Uuid::new_v4();
    let replace_entry = Uuid::new_v4();
    let replace_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 6_000,
    )
    .unwrap();
    let alice_key_id_bytes: [u8; 32] = Sha256::digest(&scenario.alice_sig_key).into();
    let reencryption = MetadataSnapshotBinding::for_test_creation(
        *conversation_id.as_bytes(),
        0,
        successor_coord.epoch(),
        *successor_coord.group_context_hash(),
        creation_transition_id,
        1,
        alice_id.clone(),
        alice_key_id_bytes,
        scenario.alice_sig_key.clone().try_into().unwrap(),
        1,
        1,
        [0xB7_u8; 12],
        vec![0xB8_u8; 48],
    );
    let fulfill_evidence =
        TransitionEvidence::for_test_leaf_recovery_replace_fulfillment_with_metadata(
            4,
            *replace_transition.as_bytes(),
            [0x1E_u8; 32],
            replace_received,
            *replace_request_id.as_bytes(),
            *requested_state.coordinate(),
            successor_coord,
            bob_id.clone(),
            new_ref,
            *replace_welcome_id.as_bytes(),
            welcome_wire.clone(),
            reencryption,
        )
        .unwrap();
    let planned = plan_leaf_recovery_fulfillment(
        &requested_state,
        LeafRecoveryFulfillment {
            actor: alice_id.clone(),
            target: bob_id.clone(),
            recovery_request_id: *replace_request_id.as_bytes(),
            welcome_id: *replace_welcome_id.as_bytes(),
            transition: fulfill_evidence,
            commit,
            welcome,
        },
    )
    .expect("valid replace fulfillment plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *replace_entry.as_bytes(),
        *requested_state.coordinate(),
        4,
        replace_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    // Participant periods in hydration (sorted-DID) order — bob's participant
    // period is UNCHANGED by a rotation (the new leaf reuses it).
    let mut participant_rows: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT user_did,participant_period_id FROM chat.participants WHERE conversation_id=$1 AND current_membership",
    )
    .bind(conversation_id)
    .fetch_all(&pool)
    .await
    .expect("participant periods");
    participant_rows.sort_by(|l, r| l.0.as_bytes().cmp(r.0.as_bytes()));
    let participant_period_ids: Vec<Uuid> = participant_rows.iter().map(|(_, id)| *id).collect();

    let applied_at = clock_now(&pool).await;
    let payload = vec![0xBA_u8; 12];
    let transcript = vec![0xBB_u8; 12];
    let alice_pred = device_event_predecessor(&pool, &alice_did, alice_device).await;
    let bob_pred = device_event_predecessor(&pool, &bob_did, bob_device).await;
    let ctx = ExecutionContext {
        protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: alice_did.clone(),
            device_id: alice_device,
            key_id: alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: replace_entry,
            entry_kind: "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0xBC_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0xBD_u8; 64],
            server_fields_bytes: vec![0xBE_u8; 8],
            outer_entry_fingerprint: vec![0x1E_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xC1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xC1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xC2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xC2_u8; 16]).to_vec(),
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        // The rotated-in leaf's persistence columns: bob's SAME signing identity.
        opened_leaves: vec![LeafPersistenceColumns {
            device: bob_id.clone(),
            leaf_key_id: bob_key_id.clone(),
            leaf_auth_generation: 1,
        }],
        metadata_author: Some(MetadataAuthorColumns {
            author_role: "admin".to_owned(),
            author_device_status: "active".to_owned(),
            author_public_key: scenario.alice_sig_key.clone(),
            author_key_id: alice_key_id.clone(),
            metadata_snapshot_id: Uuid::new_v4(),
        }),
        participant_period_ids,
        // The FRESH leaf period for bob's rotated-in leaf.
        leaf_period_ids: vec![Uuid::new_v4()],
        // Alice (remaining) fetches the control entry; bob's OLD interval close
        // routes to him via the `intervalClose` entitlement the interval-close
        // provenance trigger requires at the fulfillment seq.
        entry_recipients: vec![
            (alice_id.clone(), EntryEntitlementKind::Control),
            (bob_id.clone(), EntryEntitlementKind::IntervalClose),
        ],
        // The remaining member (alice) observes the rotation via WelcomeAvailable;
        // bob's single event this transition is the WelcomeDisposition below (the
        // per-device event predecessor chain forbids a device in two events at once).
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::WelcomeAvailable,
            payload_bytes: vec![0xBF_u8; 8],
            recipients: vec![(
                alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        // The OLD leaf period closed by the rotation.
        closing_leaf_periods: vec![(bob_id.clone(), bob_old_leaf_period)],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        // The epoch change supersedes the scenario's prior pending Welcome for bob.
        welcome_dispositions: vec![WelcomeDispositionInput {
            welcome_id: scenario_welcome_id,
            event: EventFanout {
                event_id: Uuid::new_v4(),
                event_kind: EventKind::WelcomeDisposition,
                payload_bytes: vec![0xC5_u8; 8],
                recipients: vec![(bob_id.clone(), EventEntitlementKind::Welcome, bob_pred)],
                outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
            },
        }],
    };

    let bob_signature_key = hex::decode(&manifest.identity.bob.signature_public_key_hex).unwrap();
    BuiltReplaceFulfillment {
        plan,
        ctx,
        conversation_id,
        bob_did,
        bob_signature_key,
        bob_old_leaf_period,
        replace_transition,
        replace_request_id,
        replace_welcome_id,
        scenario_welcome_id,
        new_ref,
        new_package_not_after,
    }
}

/// Arm 3 #1 (`replace` fulfillment): a leaf-recovery `replace` ROTATES the
/// target's leaf in place. Because the state diff is keyed by DEVICE (not leaf
/// index), the rotation surfaces as ONE (Some,Some) leaf change for bob (new
/// key-package origin + HPKE key, SAME signing identity) — the executor closes
/// bob's OLD leaf period + Replace-closes his OLD interval at the fulfillment
/// seq, AND opens a fresh leaf period + Add interval, all past the deferred
/// `assert_application_interval_provenance` (which requires the `replace` close
/// to route an `intervalClose` entitlement to bob and be authored by a
/// `leafRecovery` transition). Builds on `run_fulfillment_scenario` (bob added at
/// sv 2 / epoch 1), opens a bob-authored `replace` request reserving a FRESH key
/// package, then fulfills sv 2 -> 3 / epoch 1 -> 2.
#[tokio::test]
async fn leaf_recovery_replace_fulfillment_rotates_leaf_and_closes_prior_interval() {
    let (pool, _db) = setup().await;
    let BuiltReplaceFulfillment {
        plan,
        ctx,
        conversation_id,
        bob_did,
        bob_signature_key,
        bob_old_leaf_period,
        replace_transition,
        replace_request_id,
        replace_welcome_id,
        scenario_welcome_id,
        new_ref,
        new_package_not_after,
    } = Box::pin(build_replace_fulfillment(&pool)).await;

    let mut tx = pool.begin().await.expect("begin replace fulfillment");
    let applied = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("replace fulfillment applies");
    tx.commit()
        .await
        .expect("replace fulfillment COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 4);

    // Head at the committed successor (sv 3, seq 5); commit gen_state epoch 2, 2 leaves.
    let (sv, next_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((sv, next_seq), (3, 5));
    let (skind, sepoch, sleaf): (String, i64, i64) = sqlx::query_as(
        "SELECT state_kind,epoch,leaf_count FROM chat.generation_states WHERE conversation_id=$1 AND state_version=3",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("commit gen state");
    assert_eq!((skind.as_str(), sepoch, sleaf), ("commit", 2, 2));

    // Bob's OLD leaf period is closed, bound to the fulfillment transition.
    let (old_active, old_removed): (bool, Option<Uuid>) = sqlx::query_as(
        "SELECT active,removed_transition_id FROM chat.member_devices WHERE leaf_period_id=$1",
    )
    .bind(bob_old_leaf_period)
    .fetch_one(&pool)
    .await
    .expect("bob old leaf");
    assert!(!old_active);
    assert_eq!(old_removed, Some(replace_transition));
    // Bob's NEW active leaf carries the fresh key package + the SAME signing key.
    let (new_active, new_origin, new_join_ref, new_sig): (bool, String, Option<Vec<u8>>, Vec<u8>) =
        sqlx::query_as(
            "SELECT active,origin,join_key_package_ref,leaf_signature_key FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2 AND active",
        )
        .bind(conversation_id)
        .bind(&bob_did)
        .fetch_one(&pool)
        .await
        .expect("bob new leaf");
    assert!(new_active);
    assert_eq!(
        (new_origin.as_str(), new_join_ref),
        ("keyPackage", Some(new_ref.to_vec()))
    );
    assert_eq!(new_sig, bob_signature_key);
    // Bob's OLD interval is Replace-closed at the fulfillment seq; his NEW interval
    // is Add-opened at the same seq.
    let (old_start, old_end, old_kind): (i64, Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT start_seq,terminal_seq,closing_kind FROM chat.application_intervals WHERE conversation_id=$1 AND recipient_did=$2 AND terminal_seq IS NOT NULL",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob closed interval");
    assert_eq!(old_start, 3);
    assert_eq!(old_end, Some(4));
    assert_eq!(old_kind.as_deref(), Some("replace"));
    let (new_start, new_open): (i64, String) = sqlx::query_as(
        "SELECT start_seq,opening_kind FROM chat.application_intervals WHERE conversation_id=$1 AND recipient_did=$2 AND terminal_seq IS NULL",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob open interval");
    assert_eq!((new_start, new_open.as_str()), (4, "add"));

    // Request fulfilled, reservation consumed, fresh package consumed.
    let req_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(replace_request_id)
    .fetch_one(&pool)
    .await
    .expect("request");
    assert_eq!(req_status, "fulfilled");
    let res_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.key_package_reservations WHERE recovery_request_id=$1",
    )
    .bind(replace_request_id)
    .fetch_one(&pool)
    .await
    .expect("reservation");
    assert_eq!(res_status, "consumed");
    let pkg_status: String =
        sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE key_package_ref=$1")
            .bind(new_ref.to_vec())
            .fetch_one(&pool)
            .await
            .expect("package");
    assert_eq!(pkg_status, "consumed");
    // A fresh pending Welcome for bob; the scenario's prior Welcome is superseded.
    let (new_del_status, new_expires): (String, DateTime<Utc>) =
        sqlx::query_as("SELECT status,expires_at FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(replace_welcome_id)
            .fetch_one(&pool)
            .await
            .expect("new delivery");
    assert_eq!(new_del_status, "pending");
    assert_eq!(new_expires, new_package_not_after);
    let prior_welcome_status: String =
        sqlx::query_scalar("SELECT status FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(scenario_welcome_id)
            .fetch_one(&pool)
            .await
            .expect("prior welcome");
    assert_eq!(prior_welcome_status, "superseded");
    // The re-encryption metadata snapshot for the fulfillment transition.
    let snap_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.metadata_snapshots WHERE producing_transition_id=$1",
    )
    .bind(replace_transition)
    .fetch_one(&pool)
    .await
    .expect("snapshot");
    assert_eq!(snap_count, 1);

    // Replay -> head CAS conflict (head already at sv 3), zero residue.
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan_unscoped_for_test(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Transition(_))),
        "replace fulfillment replay must conflict on the head CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        before, after,
        "replace fulfillment replay left zero residue"
    );
}

/// Desync negative for the `replace` composition: with the OLD leaf period absent
/// from `ctx.closing_leaf_periods`, the executor must HARD-ERROR (`MissingContext`)
/// rather than silently opening bob's new leaf while leaving the old one active —
/// the exact half-rotation silent-bug this arm guards against. The whole
/// transaction rolls back (zero residue).
#[tokio::test]
async fn leaf_recovery_replace_fulfillment_without_old_leaf_period_is_rejected() {
    let (pool, _db) = setup().await;
    let built = Box::pin(build_replace_fulfillment(&pool)).await;
    let conversation_id = built.conversation_id;
    let plan = built.plan;
    let mut ctx = built.ctx;
    // Drop the OLD leaf period the rotation must close.
    ctx.closing_leaf_periods.clear();

    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut tx = pool
        .begin()
        .await
        .expect("begin rejected replace fulfillment");
    let result = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx).await;
    assert!(
        matches!(result, Err(ExecutorError::MissingContext(_))),
        "replace fulfillment without the old leaf period must hard-error, got {result:?}"
    );
    tx.rollback().await.expect("rollback rejected replace");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        before, after,
        "rejected replace fulfillment left zero residue"
    );
}

/// Commit a leave fulfillment that Removes bob (a self-contained mirror of
/// `leave_fulfillment_commits_remove_…`): alice fulfills bob's pending leave with a
/// synthetic Remove commit, sv 2 -> 3 / epoch 1 -> 2. Leaves alice the single member
/// with bob's interval Remove-closed (the close prior for arm 3 #4). Returns the
/// post-leave state.
async fn commit_bob_leave_fulfillment(
    pool: &PgPool,
    scenario: &FulfillmentScenario,
    pending_state: &ConversationState,
    leave_request_id: Uuid,
) -> ConversationState {
    let (plan, ctx, post_leave) =
        build_bob_leave_fulfillment(pool, scenario, pending_state, leave_request_id).await;
    let mut tx = pool.begin().await.expect("begin leave fulfillment");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("leave fulfillment applies");
    tx.commit()
        .await
        .expect("leave fulfillment COMMIT past all deferred triggers");
    post_leave
}

/// Build (but do NOT commit) alice's leaveCommit fulfilling bob's retained leave
/// consent, returning the plan + ctx + the post-leave state. Split from
/// `commit_bob_leave_fulfillment` so the ADR-019 desync negative can apply a
/// CORRUPTED variant of the same plan.
async fn build_bob_leave_fulfillment(
    pool: &PgPool,
    scenario: &FulfillmentScenario,
    pending_state: &ConversationState,
    leave_request_id: Uuid,
) -> (
    chat_protocol::state_machine::ConversationPersistencePlan,
    ExecutionContext,
    ConversationState,
) {
    let manifest = corpus_manifest();
    let conversation_id = scenario.conversation_id;
    let bob_id = scenario.bob_id.clone();
    let bob_did = scenario.bob_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());
    let alice_id = scenario.fixture.alice_id.clone();
    let alice_did = scenario.fixture.alice_did.clone();
    let alice_device = scenario.fixture.alice_device;
    let alice_key_id = scenario.fixture.alice_key_id.clone();
    let creation_transition_id = scenario.fixture.creation_transition_id;
    let protocol_instance_id = scenario.fixture.protocol_instance_id;

    let bob_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2 AND active",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(pool)
    .await
    .expect("bob leaf period");
    let bob_participant_period: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(pool)
    .await
    .expect("bob participant period");

    let alice_leaf_index = pending_state
        .leaf(&alice_id)
        .expect("alice leaf")
        .leaf_index();
    let bob_leaf_index = pending_state.leaf(&bob_id).expect("bob leaf").leaf_index();
    let successor_coord = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        manifest.chain.generation,
        pending_state.coordinate().state_version() + 1,
        *pending_state.coordinate().group_id(),
        pending_state.coordinate().epoch() + 1,
        [0xD1_u8; 32],
        [0xD2_u8; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    let commit = chat_protocol::public_state::VerifiedCommitPublicState::for_test_remove(
        pending_state.public_state(),
        successor_coord,
        alice_leaf_index,
        &[bob_leaf_index],
    )
    .expect("synthetic sealed remove evidence");
    let fulfill_transition = Uuid::new_v4();
    let fulfill_entry = Uuid::new_v4();
    let fulfill_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 6_000,
    )
    .unwrap();
    let alice_key_id_bytes: [u8; 32] = Sha256::digest(&scenario.alice_sig_key).into();
    let reencryption = MetadataSnapshotBinding::for_test_creation(
        *conversation_id.as_bytes(),
        0,
        successor_coord.epoch(),
        *successor_coord.group_context_hash(),
        creation_transition_id,
        1,
        alice_id.clone(),
        alice_key_id_bytes,
        scenario.alice_sig_key.clone().try_into().unwrap(),
        1,
        1,
        [0xF7_u8; 12],
        vec![0xF8_u8; 48],
    );
    let fulfill_evidence = TransitionEvidence::for_test_leave_fulfillment_with_metadata(
        5,
        *fulfill_transition.as_bytes(),
        [0x1D_u8; 32],
        fulfill_received,
        *leave_request_id.as_bytes(),
        *pending_state.coordinate(),
        successor_coord,
        bob_id.clone(),
        reencryption,
    )
    .unwrap();
    let planned = plan_leave_fulfillment(
        pending_state,
        LeaveFulfillment {
            actor: alice_id.clone(),
            requester: bob_id.principal().clone(),
            leave_request_id: *leave_request_id.as_bytes(),
            transition: fulfill_evidence,
            commit,
        },
    )
    .expect("valid leave fulfillment plan");
    let post_leave = planned.resulting_state().clone();
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *fulfill_entry.as_bytes(),
        *pending_state.coordinate(),
        5,
        fulfill_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let applied_at = clock_now(pool).await;
    let payload = vec![0xFA_u8; 12];
    let transcript = vec![0xFB_u8; 12];
    let alice_pred = device_event_predecessor(pool, &alice_did, alice_device).await;
    let bob_pred = device_event_predecessor(pool, &bob_did, bob_device).await;
    let ctx = ExecutionContext {
        protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: alice_did.clone(),
            device_id: alice_device,
            key_id: alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: fulfill_entry,
            entry_kind: "blue.catbird.chat.defs#leaveCommitFulfillmentEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0xFC_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0xFD_u8; 64],
            server_fields_bytes: vec![0xFE_u8; 8],
            outer_entry_fingerprint: vec![0x1D_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xC1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xC1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xC2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xC2_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: Some(MetadataAuthorColumns {
            author_role: "admin".to_owned(),
            author_device_status: "active".to_owned(),
            author_public_key: scenario.alice_sig_key.clone(),
            author_key_id: alice_key_id.clone(),
            metadata_snapshot_id: Uuid::new_v4(),
        }),
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![
            (alice_id.clone(), EntryEntitlementKind::Control),
            (bob_id.clone(), EntryEntitlementKind::IntervalClose),
        ],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::LeaveRequest,
            payload_bytes: vec![0xC4_u8; 8],
            recipients: vec![(
                alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![(bob_id.clone(), bob_leaf_period)],
        closing_participant_periods: vec![(bob_id.principal().clone(), bob_participant_period)],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![WelcomeDispositionInput {
            welcome_id: scenario.welcome_id,
            event: EventFanout {
                event_id: Uuid::new_v4(),
                event_kind: EventKind::WelcomeDisposition,
                payload_bytes: vec![0xC5_u8; 8],
                recipients: vec![(bob_id.clone(), EventEntitlementKind::Welcome, bob_pred)],
                outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
            },
        }],
    };
    (plan, ctx, post_leave)
}

/// ADR-019 Erratum 01 desync (leave-fulfillment, ruling point 3): a leaveCommit
/// plan that ALSO carries a `Pending->Stale` delta for the SAME request it fulfills
/// is a hard `InconsistentPlan` — the fulfilled request is `fulfilled`, never
/// `stale`. The count-only reconciliation cannot catch it (own + staled still equals
/// total), so the explicit same-request guard is load-bearing. Zero residue.
#[tokio::test]
async fn leave_fulfillment_staling_its_own_request_is_rejected() {
    let (pool, _db) = setup().await;
    let manifest = corpus_manifest();
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let req_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 5_000,
    )
    .unwrap();
    let (pending_state, leave_request_id, _seq, _plan, _ctx) =
        commit_leave_request(&pool, &scenario, 4, req_received).await;
    let (plan, ctx, _post) =
        build_bob_leave_fulfillment(&pool, &scenario, &pending_state, leave_request_id).await;
    let bad = plan.with_leave_fulfillment_own_staled_for_test();

    let mut tx = pool
        .begin()
        .await
        .expect("begin corrupted leave fulfillment");
    let result = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &bad, &ctx).await;
    assert!(
        matches!(result, Err(ExecutorError::InconsistentPlan(_))),
        "staling the fulfilled request must be InconsistentPlan, got {result:?}"
    );
    tx.rollback().await.expect("rollback");
    // Zero residue: coordinate unchanged (sv 2), the leave request still pending.
    let (sv, leave_status): (i64, String) = sqlx::query_as(
        "SELECT (SELECT current_state_version FROM chat.conversations WHERE conversation_id=$1), \
                (SELECT status FROM chat.leave_requests WHERE leave_request_id=$2)",
    )
    .bind(conversation_id)
    .bind(leave_request_id)
    .fetch_one(&pool)
    .await
    .expect("residue");
    assert_eq!((sv, leave_status.as_str()), (2, "pending"));
    cleanup(&pool, conversation_id).await;
}

/// Arm 3 #4 (proof-only close branch, E2b-5 MINOR-2): a close AFTER a member's
/// interval was already Remove-closed inserts that member's `scheduleTerminal`
/// proof WITHOUT a second interval close — the already-closed interval is BYTE-
/// UNTOUCHED. `plan_close` emits a proof for every historical device (open OR
/// closed); the executor closes only the still-open interval (alice, Terminal) and
/// inserts a schedule proof per `terminal_proof_change` (alice + the removed bob).
/// Both proofs route via a `scheduleTerminal` entitlement at the close seq
/// (`assert_application_terminal_proof`); bob's is valid because his latest interval
/// is `remove`-closed at an EARLIER seq.
#[tokio::test]
async fn close_after_leave_emits_proof_only_for_removed_device() {
    let (pool, _db) = setup().await;
    let manifest = corpus_manifest();
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let alice_id = scenario.fixture.alice_id.clone();
    let alice_did = scenario.fixture.alice_did.clone();
    let alice_device = scenario.fixture.alice_device;
    let alice_key_id = scenario.fixture.alice_key_id.clone();
    let bob_id = scenario.bob_id.clone();
    let bob_did = scenario.bob_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());
    let protocol_instance_id = scenario.fixture.protocol_instance_id;

    // 1. Bob leaves (seq 4 request, seq 5 fulfillment) — his interval Remove-closes.
    let req_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 5_000,
    )
    .unwrap();
    let (pending_state, leave_request_id, _seq, _plan, _ctx) =
        commit_leave_request(&pool, &scenario, 4, req_received).await;
    let post_leave =
        commit_bob_leave_fulfillment(&pool, &scenario, &pending_state, leave_request_id).await;

    // Snapshot bob's Remove-closed interval BEFORE the close (to prove it's untouched).
    let (bob_terminal_seq, bob_close_kind, bob_close_transition): (i64, String, Uuid) =
        sqlx::query_as(
            "SELECT terminal_seq,closing_kind,closing_transition_id FROM chat.application_intervals WHERE conversation_id=$1 AND recipient_did=$2",
        )
        .bind(conversation_id)
        .bind(&bob_did)
        .fetch_one(&pool)
        .await
        .expect("bob interval pre-close");
    assert_eq!(bob_close_kind, "remove");
    assert_eq!(bob_terminal_seq, 5);

    // Alice's still-active gen0 leaf period (the only leaf the close closes).
    let alice_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2 AND active",
    )
    .bind(conversation_id)
    .bind(&alice_did)
    .fetch_one(&pool)
    .await
    .expect("alice leaf period");

    // 2. Alice closes the group (seq 6).
    let close_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 7_000,
    )
    .unwrap();
    let close_transition = Uuid::new_v4();
    let close_entry = Uuid::new_v4();
    let close_evidence = TransitionEvidence::for_test_at(
        6,
        *close_transition.as_bytes(),
        [0x1F_u8; 32],
        close_received,
    )
    .unwrap();
    let planned = plan_close(
        &post_leave,
        CloseConversation {
            actor: alice_id.clone(),
            transition: close_evidence,
        },
    )
    .expect("valid close plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *close_entry.as_bytes(),
        *post_leave.coordinate(),
        6,
        close_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let applied_at = clock_now(&pool).await;
    let payload = vec![0xE1_u8; 12];
    let transcript = vec![0xE2_u8; 12];
    let alice_pred = device_event_predecessor(&pool, &alice_did, alice_device).await;
    let ctx = ExecutionContext {
        protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: alice_did.clone(),
            device_id: alice_device,
            key_id: alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: close_entry,
            entry_kind: "blue.catbird.chat.defs#conversationCloseEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0xE3_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0xE4_u8; 64],
            server_fields_bytes: vec![0xE5_u8; 8],
            outer_entry_fingerprint: vec![0x1F_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xE6_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xE6_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xE7_u8; 16],
            tree_summary_sha256: Sha256::digest([0xE7_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        // Every historical device's proof needs a scheduleTerminal entitlement at
        // the close seq — alice (terminal-closed) AND bob (already remove-closed).
        entry_recipients: vec![
            (alice_id.clone(), EntryEntitlementKind::ScheduleTerminal),
            (bob_id.clone(), EntryEntitlementKind::ScheduleTerminal),
        ],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationClosed,
            payload_bytes: vec![0xE8_u8; 8],
            recipients: vec![(
                alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![(alice_id.clone(), alice_leaf_period)],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };

    let mut tx = pool.begin().await.expect("begin close");
    let applied = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("close applies");
    tx.commit()
        .await
        .expect("close COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 6);

    // Conversation superseded (closed).
    let lifecycle: String =
        sqlx::query_scalar("SELECT lifecycle FROM chat.conversations WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .expect("head");
    assert_eq!(lifecycle, "superseded");
    // Alice's interval Terminal-closed at the close seq.
    let (alice_end, alice_kind): (Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT terminal_seq,closing_kind FROM chat.application_intervals WHERE conversation_id=$1 AND recipient_did=$2",
    )
    .bind(conversation_id)
    .bind(&alice_did)
    .fetch_one(&pool)
    .await
    .expect("alice interval");
    assert_eq!(
        (alice_end, alice_kind.as_deref()),
        (Some(6), Some("terminal"))
    );
    // BOTH devices got a schedule terminal proof at the close seq.
    let proofs: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.application_schedule_terminal_proofs WHERE conversation_id=$1 AND terminal_seq=6",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("proofs");
    assert_eq!(proofs, 2);
    let bob_proof: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.application_schedule_terminal_proofs WHERE conversation_id=$1 AND recipient_did=$2 AND terminal_seq=6",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob proof");
    assert_eq!(bob_proof, 1);
    // Bob's Remove-closed interval is BYTE-UNTOUCHED (terminal_seq / kind / transition
    // still the LEAVE's, not the close's).
    let (bob_terminal_seq_after, bob_close_kind_after, bob_close_transition_after): (i64, String, Uuid) =
        sqlx::query_as(
            "SELECT terminal_seq,closing_kind,closing_transition_id FROM chat.application_intervals WHERE conversation_id=$1 AND recipient_did=$2",
        )
        .bind(conversation_id)
        .bind(&bob_did)
        .fetch_one(&pool)
        .await
        .expect("bob interval post-close");
    assert_eq!(bob_terminal_seq_after, bob_terminal_seq);
    assert_eq!(bob_close_kind_after, bob_close_kind);
    assert_eq!(bob_close_transition_after, bob_close_transition);
    assert_ne!(bob_close_transition_after, close_transition);
    // bob_device referenced to keep the binding meaningful across the assert set.
    let _ = bob_device;

    // Replay -> head CAS conflict (head superseded), zero residue.
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan_unscoped_for_test(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Transition(_))),
        "close replay must conflict on the head CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "close replay left zero residue");
}

#[tokio::test]
async fn generic_commit_supersedes_prior_open_recovery_request() {
    let (pool, _db) = setup().await;
    let manifest = corpus_manifest();
    let scenario = run_fulfillment_scenario(&pool).await;
    let fixture = &scenario.fixture;
    let conversation_id = scenario.conversation_id;
    let prior = &scenario.fulfillment_state; // sv 2, epoch 1.

    // 1. Open a REPLACE leaf-recovery request by alice, bound to the fulfillment
    //    coordinate (sv 2). Seed alice's key package.
    let alice_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2 AND active",
    )
    .bind(conversation_id)
    .bind(&fixture.alice_did)
    .fetch_one(&pool)
    .await
    .expect("alice leaf period");
    let req_ref = random_ref32();
    let req_pkg_not_after = seed_key_package(
        &pool,
        &fixture.alice_did,
        fixture.alice_device,
        &fixture.alice_key_id,
        &req_ref,
    )
    .await;
    let req_pkg_not_after_ts =
        ServerTimestamp::from_unix_millis_for_test(req_pkg_not_after.timestamp_millis()).unwrap();
    let req_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 5_000,
    )
    .unwrap();
    let request_id = Uuid::new_v4();
    let req_evidence = RequestEvidence::for_test(
        RequestEntryKind::LeafRecoveryRequest,
        4,
        *request_id.as_bytes(),
        fixture.alice_id.clone(),
        *conversation_id.as_bytes(),
        req_received,
        0xC1,
    )
    .unwrap();
    let req_planned = plan_leaf_recovery_request(
        prior,
        LeafRecoveryRequestCommand {
            actor: fixture.alice_id.clone(),
            recovery_request_id: *request_id.as_bytes(),
            kind: LeafRecoveryKind::Replace,
            key_package_ref: req_ref,
            received_at: req_received,
            package_not_after: req_pkg_not_after_ts,
            evidence: req_evidence,
        },
    )
    .expect("valid leaf recovery request plan");
    let request_state = req_planned.resulting_state().clone();
    let req_head = ConversationHeadCasBinding::for_test_internal(
        *conversation_id.as_bytes(),
        *prior.coordinate(),
        4,
        req_received,
    );
    let req_plan = persistence_plan_for_test(req_planned, req_head);
    let req_applied_at = clock_now(&pool).await;
    let req_transcript = vec![0xC1_u8; 16];
    let req_pred = device_event_predecessor(&pool, &fixture.alice_did, fixture.alice_device).await;
    let req_ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at: req_applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
            accepted_payload_bytes: vec![0xC1_u8; 8],
            accepted_payload_sha256: Sha256::digest([0xC1_u8; 8]).to_vec(),
            signed_request_bytes: req_transcript.clone(),
            unsigned_projection_bytes: vec![0xC1_u8; 8],
            signing_transcript_bytes: req_transcript.clone(),
            request_digest: Sha256::digest(&req_transcript).to_vec(),
            signature: vec![0xC1_u8; 64],
            server_fields_bytes: vec![0xC1_u8; 8],
            outer_entry_fingerprint: vec![0xC1_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0xC1_u8; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                req_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: Some(RecoveryOpenContext {
            participant_period_id: None,
            package_not_after: req_pkg_not_after,
            replaced_leaf_period_id: Some(alice_leaf_period),
        }),
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    {
        let mut tx = pool.begin().await.expect("begin request");
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &req_plan, &req_ctx)
            .await
            .expect("recovery request applies");
        tx.commit().await.expect("recovery request COMMIT");
    }
    // The request is OPEN, its package RESERVED before the commit.
    let pre: (String, String) = sqlx::query_as(
        "SELECT (SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1), \
                (SELECT status FROM chat.key_packages WHERE key_package_ref=$2)",
    )
    .bind(request_id)
    .bind(req_ref.to_vec())
    .fetch_one(&pool)
    .await
    .expect("pre state");
    assert_eq!((pre.0.as_str(), pre.1.as_str()), ("open", "reserved"));

    // 2. Generic commit on the request state (sv 2 -> 3) — supersedes the open
    //    request + its reservation + package, AND the fulfillment's pending welcome.
    validate_public_commit(
        &corpus_file("commit-generic-public.mls"),
        MAX_PUBLIC_MESSAGE_WIRE_BYTES,
    )
    .expect("generic commit parses");
    let successor_coord = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        manifest.chain.generation,
        request_state.coordinate().state_version() + 1,
        *request_state.coordinate().group_id(),
        request_state.coordinate().epoch() + 1,
        [0xB1_u8; 32],
        [0xB2_u8; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    let commit = chat_protocol::public_state::VerifiedCommitPublicState::for_test_generic(
        request_state.public_state(),
        successor_coord,
        0,
    )
    .expect("synthetic zero-proposal commit");
    let commit_transition = Uuid::new_v4();
    let commit_entry = Uuid::new_v4();
    let commit_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 6_000,
    )
    .unwrap();
    let alice_key_id_bytes: [u8; 32] = Sha256::digest(&scenario.alice_sig_key).into();
    let reencryption = MetadataSnapshotBinding::for_test_creation(
        *conversation_id.as_bytes(),
        0,
        successor_coord.epoch(),
        *successor_coord.group_context_hash(),
        fixture.creation_transition_id,
        1,
        fixture.alice_id.clone(),
        alice_key_id_bytes,
        scenario.alice_sig_key.clone().try_into().unwrap(),
        1,
        1,
        [0xB3_u8; 12],
        vec![0xB4_u8; 48],
    );
    let commit_evidence = TransitionEvidence::for_test_commit_with_metadata(
        4,
        *commit_transition.as_bytes(),
        [0x1B_u8; 32],
        commit_received,
        *request_state.coordinate(),
        successor_coord,
        reencryption,
    )
    .unwrap();
    let planned = plan_commit(
        &request_state,
        CommitCommand {
            actor: fixture.alice_id.clone(),
            transition: commit_evidence,
            commit,
        },
    )
    .expect("valid generic commit plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *commit_entry.as_bytes(),
        *request_state.coordinate(),
        4,
        commit_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let applied_at = clock_now(&pool).await;
    let alice_pred =
        device_event_predecessor(&pool, &fixture.alice_did, fixture.alice_device).await;
    let bob_device = Uuid::from_bytes(*scenario.bob_id.device_id());
    let bob_pred = device_event_predecessor(&pool, &scenario.bob_did, bob_device).await;
    let commit_transcript = vec![0xB5_u8; 12];
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: commit_entry,
            entry_kind: "blue.catbird.chat.defs#commitEntry".to_owned(),
            accepted_payload_bytes: vec![0xB6_u8; 12],
            accepted_payload_sha256: Sha256::digest([0xB6_u8; 12]).to_vec(),
            signed_request_bytes: commit_transcript.clone(),
            unsigned_projection_bytes: vec![0xB7_u8; 8],
            signing_transcript_bytes: commit_transcript.clone(),
            request_digest: Sha256::digest(&commit_transcript).to_vec(),
            signature: vec![0xB8_u8; 64],
            server_fields_bytes: vec![0xB9_u8; 8],
            outer_entry_fingerprint: vec![0x1B_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xBA_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xBA_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xBB_u8; 16],
            tree_summary_sha256: Sha256::digest([0xBB_u8; 16]).to_vec(),
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: Some(MetadataAuthorColumns {
            author_role: "admin".to_owned(),
            author_device_status: "active".to_owned(),
            author_public_key: scenario.alice_sig_key.clone(),
            author_key_id: fixture.alice_key_id.clone(),
            metadata_snapshot_id: Uuid::new_v4(),
        }),
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: entry_audience(
            &fixture.alice_id,
            &fixture.alice_did,
            &scenario.bob_id,
            &scenario.bob_did,
        ),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0xBC_u8; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![WelcomeDispositionInput {
            welcome_id: scenario.welcome_id,
            event: EventFanout {
                event_id: Uuid::new_v4(),
                event_kind: EventKind::WelcomeDisposition,
                payload_bytes: vec![0xBD_u8; 8],
                recipients: vec![(
                    scenario.bob_id.clone(),
                    EventEntitlementKind::Welcome,
                    bob_pred,
                )],
                outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
            },
        }],
    };

    let mut tx = pool.begin().await.expect("begin generic commit");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("generic commit with supersession applies");
    tx.commit()
        .await
        .expect("generic commit COMMIT past all deferred triggers");

    // The superseded request + released reservation + re-available package.
    let (req_status, res_status, pkg_status): (String, String, String) = sqlx::query_as(
        "SELECT (SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1), \
                (SELECT status FROM chat.key_package_reservations WHERE recovery_request_id=$1), \
                (SELECT status FROM chat.key_packages WHERE key_package_ref=$2)",
    )
    .bind(request_id)
    .bind(req_ref.to_vec())
    .fetch_one(&pool)
    .await
    .expect("superseded state");
    assert_eq!(
        (
            req_status.as_str(),
            res_status.as_str(),
            pkg_status.as_str()
        ),
        ("superseded", "released", "available")
    );
    // The superseding transition is recorded on the request.
    let terminal_tid: Option<Uuid> = sqlx::query_scalar(
        "SELECT terminal_transition_id FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(request_id)
    .fetch_one(&pool)
    .await
    .expect("terminal transition");
    assert_eq!(terminal_tid, Some(commit_transition));
}

/// Seed a PENDING reset request (alice) + a PENDING leave request (bob) bound to
/// the fulfillment coordinate (sv 2, non-mutating), then build (but do NOT apply)
/// the UNCOMMITTED generic commit (sv 2 -> 3) whose planner stales BOTH. Returns
/// the commit plan + ctx + the two request ids + the commit transition id, so the
/// positive test can apply it and the reconciliation negatives can apply a
/// CORRUPTED copy. `pool` is cloned in so the caller keeps its own handle.
async fn seed_reset_leave_then_build_commit(
    pool: PgPool,
    scenario: &FulfillmentScenario,
) -> (
    chat_protocol::state_machine::ConversationPersistencePlan,
    ExecutionContext,
    Uuid,
    Uuid,
    Uuid,
) {
    let manifest = corpus_manifest();
    let fixture = &scenario.fixture;
    let conversation_id = scenario.conversation_id;
    let alice_id = fixture.alice_id.clone();
    let alice_did = fixture.alice_did.clone();
    let alice_device = fixture.alice_device;
    let alice_key_id = fixture.alice_key_id.clone();
    let bob_id = scenario.bob_id.clone();
    let bob_did = scenario.bob_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());
    let protocol_instance_id = fixture.protocol_instance_id;

    // 1. Alice opens a reset request (seq 4) bound to the fulfillment coordinate
    //    (sv 2) — non-mutating, coordinate unchanged.
    let reset_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 5_000,
    )
    .unwrap();
    let reset_request_id = Uuid::new_v4();
    let reset_evidence = RequestEvidence::for_test(
        RequestEntryKind::ResetRequest,
        4,
        *reset_request_id.as_bytes(),
        alice_id.clone(),
        *conversation_id.as_bytes(),
        reset_received,
        0x91,
    )
    .unwrap();
    let reset_planned = plan_reset_request(
        &scenario.fulfillment_state,
        ResetRequestCommand {
            actor: alice_id.clone(),
            reset_request_id: *reset_request_id.as_bytes(),
            received_at: reset_received,
            evidence: reset_evidence,
        },
    )
    .expect("valid reset request plan");
    let reset_state = reset_planned.resulting_state().clone();
    let reset_entry = Uuid::new_v4();
    let reset_head = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *reset_entry.as_bytes(),
        scenario.coordinate,
        4,
        reset_received,
    );
    let reset_plan = persistence_plan_for_test(reset_planned, reset_head);
    let reset_applied_at = clock_now(&pool).await;
    let reset_transcript = vec![0x92_u8; 16];
    let reset_digest = Sha256::digest(&reset_transcript).to_vec();
    let reset_signature = vec![0x93_u8; 64];
    let alice_pred_reset = device_event_predecessor(&pool, &alice_did, alice_device).await;
    let reset_ctx = ExecutionContext {
        protocol_instance_id,
        applied_at: reset_applied_at,
        actor: ExecutionActor {
            user_did: alice_did.clone(),
            device_id: alice_device,
            key_id: alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: reset_entry,
            entry_kind: "blue.catbird.chat.defs#resetRequestEntry".to_owned(),
            accepted_payload_bytes: vec![0x94_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x94_u8; 8]).to_vec(),
            signed_request_bytes: reset_transcript.clone(),
            unsigned_projection_bytes: vec![0x95_u8; 8],
            signing_transcript_bytes: reset_transcript.clone(),
            request_digest: reset_digest.clone(),
            signature: reset_signature.clone(),
            server_fields_bytes: vec![0x96_u8; 8],
            outer_entry_fingerprint: vec![0x1A_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![(alice_id.clone(), EntryEntitlementKind::Control)],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ResetRequested,
            payload_bytes: vec![0x97_u8; 8],
            recipients: vec![(
                alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred_reset,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: Some(ResetRequestRow {
            reset_request_id,
            reason: ResetReason::PoisonedState,
            signed_request_bytes: reset_transcript.clone(),
            signing_transcript_bytes: reset_transcript.clone(),
            request_digest: reset_digest.clone(),
            signature: reset_signature.clone(),
            expires_at: reset_applied_at + Duration::hours(24),
        }),
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    {
        let mut tx = pool.begin().await.expect("begin reset request");
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &reset_plan, &reset_ctx)
            .await
            .expect("reset request applies");
        tx.commit().await.expect("reset request COMMIT");
    }

    // 2. Bob opens a leave request (seq 5) against the reset state — still bound to
    //    sv 2, coordinate unchanged, BOTH requests now pending.
    let leave_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 6_000,
    )
    .unwrap();
    let leave_request_id = Uuid::new_v4();
    let leave_evidence = RequestEvidence::for_test(
        RequestEntryKind::LeaveRequest,
        5,
        *leave_request_id.as_bytes(),
        bob_id.clone(),
        *conversation_id.as_bytes(),
        leave_received,
        0x71,
    )
    .unwrap();
    let leave_registration = LockedRegistrationProjection::for_test(&leave_evidence);
    let leave_planned = plan_leave_request(
        &reset_state,
        LeaveRequestCommand {
            actor: bob_id.clone(),
            leave_request_id: *leave_request_id.as_bytes(),
            received_at: leave_received,
            evidence: leave_evidence,
            registration: leave_registration,
        },
    )
    .expect("valid leave request plan");
    let leave_state = leave_planned.resulting_state().clone();
    let leave_entry = Uuid::new_v4();
    let leave_head = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *leave_entry.as_bytes(),
        scenario.coordinate,
        5,
        leave_received,
    );
    let leave_plan = persistence_plan_for_test(leave_planned, leave_head);
    let leave_applied_at = clock_now(&pool).await;
    let leave_transcript = vec![0x72_u8; 16];
    let leave_ctx = ExecutionContext {
        protocol_instance_id,
        applied_at: leave_applied_at,
        actor: ExecutionActor {
            user_did: bob_did.clone(),
            device_id: bob_device,
            key_id: fixture.bob_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Member,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: leave_entry,
            entry_kind: "blue.catbird.chat.defs#leaveRequestEntry".to_owned(),
            accepted_payload_bytes: vec![0x74_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x74_u8; 8]).to_vec(),
            signed_request_bytes: leave_transcript.clone(),
            unsigned_projection_bytes: vec![0x75_u8; 8],
            signing_transcript_bytes: leave_transcript.clone(),
            request_digest: Sha256::digest(&leave_transcript).to_vec(),
            signature: vec![0x76_u8; 64],
            server_fields_bytes: vec![0x77_u8; 8],
            outer_entry_fingerprint: vec![0x1A_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: entry_audience(&alice_id, &alice_did, &bob_id, &bob_did),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::LeaveRequest,
            payload_bytes: vec![0x78_u8; 8],
            recipients: event_audience(&pool, &alice_id, &alice_did, &bob_id, &bob_did).await,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    {
        let mut tx = pool.begin().await.expect("begin leave request");
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &leave_plan, &leave_ctx)
            .await
            .expect("leave request applies");
        tx.commit().await.expect("leave request COMMIT");
    }
    // Both requests are pending before the commit.
    let (pre_reset, pre_leave): (String, String) = sqlx::query_as(
        "SELECT (SELECT status FROM chat.reset_requests WHERE reset_request_id=$1), \
                (SELECT status FROM chat.leave_requests WHERE leave_request_id=$2)",
    )
    .bind(reset_request_id)
    .bind(leave_request_id)
    .fetch_one(&pool)
    .await
    .expect("pre state");
    assert_eq!(
        (pre_reset.as_str(), pre_leave.as_str()),
        ("pending", "pending")
    );

    // 3. Generic commit on the leave state (sv 2 -> 3, epoch 1 -> 2, seq 6). It
    //    stales BOTH pending requests and supersedes the fulfillment's pending
    //    welcome.
    validate_public_commit(
        &corpus_file("commit-generic-public.mls"),
        MAX_PUBLIC_MESSAGE_WIRE_BYTES,
    )
    .expect("generic commit parses");
    let successor_coord = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        manifest.chain.generation,
        leave_state.coordinate().state_version() + 1,
        *leave_state.coordinate().group_id(),
        leave_state.coordinate().epoch() + 1,
        [0xB1_u8; 32],
        [0xB2_u8; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    let commit = chat_protocol::public_state::VerifiedCommitPublicState::for_test_generic(
        leave_state.public_state(),
        successor_coord,
        0,
    )
    .expect("synthetic zero-proposal commit");
    let commit_transition = Uuid::new_v4();
    let commit_entry = Uuid::new_v4();
    let commit_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 7_000,
    )
    .unwrap();
    let alice_key_id_bytes: [u8; 32] = Sha256::digest(&scenario.alice_sig_key).into();
    let reencryption = MetadataSnapshotBinding::for_test_creation(
        *conversation_id.as_bytes(),
        0,
        successor_coord.epoch(),
        *successor_coord.group_context_hash(),
        fixture.creation_transition_id,
        1,
        alice_id.clone(),
        alice_key_id_bytes,
        scenario.alice_sig_key.clone().try_into().unwrap(),
        1,
        1,
        [0xB3_u8; 12],
        vec![0xB4_u8; 48],
    );
    let commit_evidence = TransitionEvidence::for_test_commit_with_metadata(
        6,
        *commit_transition.as_bytes(),
        [0x1B_u8; 32],
        commit_received,
        *leave_state.coordinate(),
        successor_coord,
        reencryption,
    )
    .unwrap();
    let planned = plan_commit(
        &leave_state,
        CommitCommand {
            actor: alice_id.clone(),
            transition: commit_evidence,
            commit,
        },
    )
    .expect("valid generic commit plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *commit_entry.as_bytes(),
        *leave_state.coordinate(),
        6,
        commit_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);
    let applied_at = clock_now(&pool).await;
    let alice_pred = device_event_predecessor(&pool, &alice_did, alice_device).await;
    let bob_pred = device_event_predecessor(&pool, &bob_did, bob_device).await;
    let commit_transcript = vec![0xB5_u8; 12];
    let commit_request_digest = Sha256::digest(&commit_transcript).to_vec();
    let ctx = ExecutionContext {
        protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: alice_did.clone(),
            device_id: alice_device,
            key_id: alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: commit_entry,
            entry_kind: "blue.catbird.chat.defs#commitEntry".to_owned(),
            accepted_payload_bytes: vec![0xB6_u8; 12],
            accepted_payload_sha256: Sha256::digest([0xB6_u8; 12]).to_vec(),
            signed_request_bytes: commit_transcript.clone(),
            unsigned_projection_bytes: vec![0xB7_u8; 8],
            signing_transcript_bytes: commit_transcript.clone(),
            request_digest: commit_request_digest.clone(),
            signature: vec![0xB8_u8; 64],
            server_fields_bytes: vec![0xB9_u8; 8],
            outer_entry_fingerprint: vec![0x1B_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xBA_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xBA_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xBB_u8; 16],
            tree_summary_sha256: Sha256::digest([0xBB_u8; 16]).to_vec(),
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: Some(MetadataAuthorColumns {
            author_role: "admin".to_owned(),
            author_device_status: "active".to_owned(),
            author_public_key: scenario.alice_sig_key.clone(),
            author_key_id: alice_key_id.clone(),
            metadata_snapshot_id: Uuid::new_v4(),
        }),
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: entry_audience(&alice_id, &alice_did, &bob_id, &bob_did),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0xBC_u8; 8],
            recipients: vec![(
                alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![WelcomeDispositionInput {
            welcome_id: scenario.welcome_id,
            event: EventFanout {
                event_id: Uuid::new_v4(),
                event_kind: EventKind::WelcomeDisposition,
                payload_bytes: vec![0xBD_u8; 8],
                recipients: vec![(bob_id.clone(), EventEntitlementKind::Welcome, bob_pred)],
                outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
            },
        }],
    };

    let _ = commit_request_digest;
    (
        plan,
        ctx,
        reset_request_id,
        leave_request_id,
        commit_transition,
    )
}

/// A coordinate-advancing generic commit executed from a coordinate carrying a
/// PENDING reset request (alice) AND a PENDING leave request (bob) durably STALES
/// both — the executor consumes the planner's `(Pending -> Stale)` reset/leave
/// deltas via `write_prior_bound_staling` instead of hard-erroring. Both terminal
/// edges are bound to the commit transition; the leave `stale` edge additionally
/// binds the commit's request digest (the DB `assert_leave_request_mapping` stale
/// arm requires digest + terminal transition of a NON-leaveCommit/leavePolicy kind,
/// which the `commit` kind satisfies).
#[tokio::test]
async fn generic_commit_stales_prior_pending_reset_and_leave_requests() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let (plan, ctx, reset_request_id, leave_request_id, commit_transition) =
        seed_reset_leave_then_build_commit(pool.clone(), &scenario).await;
    let commit_request_digest = ctx
        .authority
        .control_entry()
        .expect("commit carries control-entry authority")
        .request_digest
        .clone();

    let mut tx = pool.begin().await.expect("begin generic commit");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("generic commit that stales reset + leave requests applies");
    tx.commit()
        .await
        .expect("generic commit COMMIT past all deferred triggers");

    // Both requests are STALE, each bound to the commit transition; the leave
    // request additionally carries the commit's request digest as its terminal.
    let (reset_status, reset_tid): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT status,terminal_transition_id FROM chat.reset_requests WHERE reset_request_id=$1",
    )
    .bind(reset_request_id)
    .fetch_one(&pool)
    .await
    .expect("reset terminal");
    assert_eq!(reset_status, "stale");
    assert_eq!(reset_tid, Some(commit_transition));
    let (leave_status, leave_tid, leave_digest): (String, Option<Uuid>, Option<Vec<u8>>) =
        sqlx::query_as(
            "SELECT status,terminal_transition_id,terminal_request_digest \
               FROM chat.leave_requests WHERE leave_request_id=$1",
        )
        .bind(leave_request_id)
        .fetch_one(&pool)
        .await
        .expect("leave terminal");
    assert_eq!(leave_status, "stale");
    assert_eq!(leave_tid, Some(commit_transition));
    assert_eq!(leave_digest, Some(commit_request_digest));
}

/// The reset-family half of the silent-drop guard is load-bearing: a plan whose
/// reset staling is corrupted to a non-`Pending->Stale` shape (which
/// `write_prior_bound_staling` skips) is a hard `InconsistentPlan`, with ZERO
/// residue — the commit never lands and the reset request stays pending.
#[tokio::test]
async fn generic_commit_corrupted_reset_staling_is_rejected() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let (plan, ctx, reset_request_id, _leave, _tid) =
        seed_reset_leave_then_build_commit(pool.clone(), &scenario).await;
    let bad = plan.with_reset_staling_corrupted_for_test();
    let mut tx = pool.begin().await.expect("begin");
    let result = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &bad, &ctx).await;
    assert!(
        matches!(result, Err(ExecutorError::InconsistentPlan(_))),
        "a corrupted reset staling must be InconsistentPlan, got {result:?}"
    );
    tx.rollback().await.expect("rollback");
    let (sv, reset_status): (i64, String) = sqlx::query_as(
        "SELECT (SELECT current_state_version FROM chat.conversations WHERE conversation_id=$1), \
                (SELECT status FROM chat.reset_requests WHERE reset_request_id=$2)",
    )
    .bind(scenario.conversation_id)
    .bind(reset_request_id)
    .fetch_one(&pool)
    .await
    .expect("residue");
    assert_eq!((sv, reset_status.as_str()), (2, "pending"));
}

/// The leave-family half of the same guard: a corrupted leave staling
/// (`Pending->Stale` -> `Pending->Expired`) is likewise a hard `InconsistentPlan`
/// with zero residue.
#[tokio::test]
async fn generic_commit_corrupted_leave_staling_is_rejected() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let (plan, ctx, _reset, leave_request_id, _tid) =
        seed_reset_leave_then_build_commit(pool.clone(), &scenario).await;
    let bad = plan.with_leave_staling_corrupted_for_test();
    let mut tx = pool.begin().await.expect("begin");
    let result = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &bad, &ctx).await;
    assert!(
        matches!(result, Err(ExecutorError::InconsistentPlan(_))),
        "a corrupted leave staling must be InconsistentPlan, got {result:?}"
    );
    tx.rollback().await.expect("rollback");
    let (sv, leave_status): (i64, String) = sqlx::query_as(
        "SELECT (SELECT current_state_version FROM chat.conversations WHERE conversation_id=$1), \
                (SELECT status FROM chat.leave_requests WHERE leave_request_id=$2)",
    )
    .bind(scenario.conversation_id)
    .bind(leave_request_id)
    .fetch_one(&pool)
    .await
    .expect("residue");
    assert_eq!((sv, leave_status.as_str()), (2, "pending"));
}

// ===========================================================================
// ADR-019 Erratum 01 — leave-kind transitions stale OTHER members' pending
// leaves. A genuine >=3-member group: alice (admin, leaf), bob (member, leaf,
// via the recovery fulfillment scenario), carol (member, LEAFLESS, added by a
// policy edge). Bob holds a pending leave; carol self-removes via a
// zeroLeafLeave (leavePolicy), which must now SUCCEED while staling bob's leave.
// ===========================================================================

struct ThreeMemberLeaveSetup {
    scenario: FulfillmentScenario,
    carol_id: DeviceIdentity,
    carol_did: String,
    carol_period: Uuid,
    leave_state: ConversationState,
    bob_leave_request_id: Uuid,
}

/// Sorted (entry Control, event Participant+predecessor) audiences for an explicit
/// device set — the >=3-member analogue of `entry_audience`/`event_audience`.
async fn member_audiences(
    pool: &PgPool,
    members: &[(DeviceIdentity, String)],
) -> (
    Vec<(DeviceIdentity, EntryEntitlementKind)>,
    Vec<(DeviceIdentity, EventEntitlementKind, Option<i64>)>,
) {
    let mut sorted = members.to_vec();
    sorted
        .sort_by(|l, r| (l.1.as_bytes(), l.0.device_id()).cmp(&(r.1.as_bytes(), r.0.device_id())));
    let entry = sorted
        .iter()
        .map(|(d, _)| (d.clone(), EntryEntitlementKind::Control))
        .collect();
    let mut events = Vec::with_capacity(sorted.len());
    for (device, did) in &sorted {
        let pred = device_event_predecessor(pool, did, Uuid::from_bytes(*device.device_id())).await;
        events.push((device.clone(), EventEntitlementKind::Participant, pred));
    }
    (entry, events)
}

/// Build+commit: recovery scenario (alice+bob leaves) -> policy-add carol
/// (leafless, superseding the scenario's pending welcome) -> bob opens a pending
/// leave request bound to the post-add coordinate. Returns the pre-zeroLeafLeave
/// state + carol's identity/period + bob's leave-request id.
async fn seed_three_member_bob_pending_leave(
    pool: &PgPool,
    scenario: FulfillmentScenario,
) -> ThreeMemberLeaveSetup {
    let manifest = corpus_manifest();
    let conversation_id = scenario.conversation_id;
    let alice_id = scenario.fixture.alice_id.clone();
    let alice_did = scenario.fixture.alice_did.clone();
    let alice_device = scenario.fixture.alice_device;
    let alice_key_id = scenario.fixture.alice_key_id.clone();
    let bob_id = scenario.bob_id.clone();
    let bob_did = scenario.bob_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());
    let protocol_instance_id = scenario.fixture.protocol_instance_id;

    // A fresh leafless invitee carol; seed her device_keys FK.
    let (carol_id, carol_did) = fresh_bob();
    let carol_device = Uuid::from_bytes(*carol_id.device_id());
    let _ = seed_actor(pool, &carol_did, carol_device, &[0x6C_u8; 32]).await;
    let members = [
        (alice_id.clone(), alice_did.clone()),
        (bob_id.clone(), bob_did.clone()),
        (carol_id.clone(), carol_did.clone()),
    ];

    // 1. Policy edge (seq 4, sv 2 -> 3) adds carol pending/leafless AND supersedes
    //    the scenario's pending Welcome (bound to sv 2).
    let s0 = scenario.fulfillment_state.clone();
    let policy_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 20_000,
    )
    .unwrap();
    let policy_transition = Uuid::new_v4();
    let policy_entry = Uuid::new_v4();
    let policy_evidence = TransitionEvidence::for_test_policy_add(
        4,
        *policy_transition.as_bytes(),
        [0x12_u8; 32],
        policy_received,
        *s0.coordinate(),
        vec![carol_id.principal().clone()],
    )
    .unwrap();
    let policy_planned = plan_policy(&s0, alice_id.clone(), policy_evidence, [0x99_u8; 32])
        .expect("valid policy plan adding carol");
    let policy_state = policy_planned.resulting_state().clone();
    let policy_head = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *policy_entry.as_bytes(),
        *s0.coordinate(),
        4,
        policy_received,
    );
    let policy_plan = persistence_plan_for_test(policy_planned, policy_head);
    let (policy_entry_recips, _) = member_audiences(pool, &members).await;
    // Bob receives ONLY the welcome-disposition event this tx; alice + carol receive
    // the ConversationChanged (canonically ordered). Each device gets exactly one
    // event so the per-device event-recipient chain trigger holds.
    let bob_pred = device_event_predecessor(pool, &bob_did, bob_device).await;
    let (_, policy_event_recips) = member_audiences(
        pool,
        &[
            (alice_id.clone(), alice_did.clone()),
            (carol_id.clone(), carol_did.clone()),
        ],
    )
    .await;
    let policy_applied_at = clock_now(pool).await;
    let policy_transcript = vec![0x52_u8; 12];
    let policy_ctx = ExecutionContext {
        protocol_instance_id,
        applied_at: policy_applied_at,
        actor: ExecutionActor {
            user_did: alice_did.clone(),
            device_id: alice_device,
            key_id: alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: policy_entry,
            entry_kind: "blue.catbird.chat.defs#policyEntry".to_owned(),
            accepted_payload_bytes: vec![0x51_u8; 12],
            accepted_payload_sha256: Sha256::digest([0x51_u8; 12]).to_vec(),
            signed_request_bytes: policy_transcript.clone(),
            unsigned_projection_bytes: vec![0x53_u8; 8],
            signing_transcript_bytes: policy_transcript.clone(),
            request_digest: Sha256::digest(&policy_transcript).to_vec(),
            signature: vec![0x54_u8; 64],
            server_fields_bytes: vec![0x55_u8; 8],
            outer_entry_fingerprint: vec![0x12_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0x61_u8; 16],
            public_snapshot_sha256: Sha256::digest([0x61_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0x62_u8; 16],
            tree_summary_sha256: Sha256::digest([0x62_u8; 16]).to_vec(),
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![Uuid::new_v4()],
        leaf_period_ids: vec![],
        entry_recipients: policy_entry_recips,
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x71_u8; 8],
            recipients: policy_event_recips,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: Vec::new(),
        closing_participant_periods: Vec::new(),
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![WelcomeDispositionInput {
            welcome_id: scenario.welcome_id,
            event: EventFanout {
                event_id: Uuid::new_v4(),
                event_kind: EventKind::WelcomeDisposition,
                payload_bytes: vec![0xBD_u8; 8],
                recipients: vec![(bob_id.clone(), EventEntitlementKind::Welcome, bob_pred)],
                outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
            },
        }],
    };
    {
        let mut tx = pool.begin().await.expect("begin policy add carol");
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &policy_plan, &policy_ctx)
            .await
            .expect("policy add carol applies");
        tx.commit().await.expect("policy add carol COMMIT");
    }
    let carol_period: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&carol_did)
    .fetch_one(pool)
    .await
    .expect("carol participant period");

    // 2. Bob opens a pending leave request (seq 5) bound to the post-add coordinate
    //    (sv 3, coordinate unchanged).
    let leave_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 21_000,
    )
    .unwrap();
    let bob_leave_request_id = Uuid::new_v4();
    let leave_evidence = RequestEvidence::for_test(
        RequestEntryKind::LeaveRequest,
        5,
        *bob_leave_request_id.as_bytes(),
        bob_id.clone(),
        *conversation_id.as_bytes(),
        leave_received,
        0x71,
    )
    .unwrap();
    let leave_registration = LockedRegistrationProjection::for_test(&leave_evidence);
    let leave_planned = plan_leave_request(
        &policy_state,
        LeaveRequestCommand {
            actor: bob_id.clone(),
            leave_request_id: *bob_leave_request_id.as_bytes(),
            received_at: leave_received,
            evidence: leave_evidence,
            registration: leave_registration,
        },
    )
    .expect("valid bob leave request plan");
    let leave_state = leave_planned.resulting_state().clone();
    let leave_entry = Uuid::new_v4();
    let leave_head = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *leave_entry.as_bytes(),
        *policy_state.coordinate(),
        5,
        leave_received,
    );
    let leave_plan = persistence_plan_for_test(leave_planned, leave_head);
    let (leave_entry_recips, leave_event_recips) = member_audiences(pool, &members).await;
    let leave_applied_at = clock_now(pool).await;
    let leave_transcript = vec![0x72_u8; 16];
    let leave_ctx = ExecutionContext {
        protocol_instance_id,
        applied_at: leave_applied_at,
        actor: ExecutionActor {
            user_did: bob_did.clone(),
            device_id: bob_device,
            key_id: scenario.fixture.bob_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Member,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: leave_entry,
            entry_kind: "blue.catbird.chat.defs#leaveRequestEntry".to_owned(),
            accepted_payload_bytes: vec![0x74_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x74_u8; 8]).to_vec(),
            signed_request_bytes: leave_transcript.clone(),
            unsigned_projection_bytes: vec![0x75_u8; 8],
            signing_transcript_bytes: leave_transcript.clone(),
            request_digest: Sha256::digest(&leave_transcript).to_vec(),
            signature: vec![0x76_u8; 64],
            server_fields_bytes: vec![0x77_u8; 8],
            outer_entry_fingerprint: vec![0x1A_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: leave_entry_recips,
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::LeaveRequest,
            payload_bytes: vec![0x78_u8; 8],
            recipients: leave_event_recips,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    {
        let mut tx = pool.begin().await.expect("begin bob leave request");
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &leave_plan, &leave_ctx)
            .await
            .expect("bob leave request applies");
        tx.commit().await.expect("bob leave request COMMIT");
    }

    ThreeMemberLeaveSetup {
        scenario,
        carol_id,
        carol_did,
        carol_period,
        leave_state,
        bob_leave_request_id,
    }
}

/// Build (do NOT commit) carol's zeroLeafLeave (seq 6, sv 3 -> 4) over the state
/// where bob holds a pending leave request. The plan stales bob's leave. Returns
/// the plan + ctx + the leavePolicy transition id.
async fn build_carol_zero_leaf_leave(
    pool: &PgPool,
    setup: &ThreeMemberLeaveSetup,
) -> (
    chat_protocol::state_machine::ConversationPersistencePlan,
    ExecutionContext,
    Uuid,
) {
    let manifest = corpus_manifest();
    let scenario = &setup.scenario;
    let conversation_id = scenario.conversation_id;
    let alice_id = scenario.fixture.alice_id.clone();
    let alice_did = scenario.fixture.alice_did.clone();
    let bob_id = scenario.bob_id.clone();
    let bob_did = scenario.bob_did.clone();
    let carol_id = setup.carol_id.clone();
    let carol_did = setup.carol_did.clone();
    let carol_device = Uuid::from_bytes(*carol_id.device_id());
    let members = [
        (alice_id.clone(), alice_did.clone()),
        (bob_id.clone(), bob_did.clone()),
        (carol_id.clone(), carol_did.clone()),
    ];

    let received_at = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 22_000,
    )
    .unwrap();
    let transition_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    let evidence =
        TransitionEvidence::for_test_at(6, *transition_id.as_bytes(), [0x82_u8; 32], received_at)
            .unwrap();
    let planned = plan_zero_leaf_leave(
        &setup.leave_state,
        ZeroLeafLeave {
            actor: carol_id.clone(),
            transition: evidence,
        },
    )
    .expect("valid carol zero-leaf leave plan staling bob's pending leave");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        *setup.leave_state.coordinate(),
        6,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);
    let (entry_recips, event_recips) = member_audiences(pool, &members).await;
    let applied_at = clock_now(pool).await;
    let transcript = vec![0x92_u8; 16];
    let ctx = ExecutionContext {
        protocol_instance_id: scenario.fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: carol_did.clone(),
            device_id: carol_device,
            key_id: seed_actor_key_id(pool, &carol_did, carol_device).await,
            auth_generation: 1,
            role: TransitionActorRole::Member,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#zeroLeafLeaveEntry".to_owned(),
            accepted_payload_bytes: vec![0x94_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x94_u8; 8]).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x95_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0x96_u8; 64],
            server_fields_bytes: vec![0x97_u8; 8],
            outer_entry_fingerprint: vec![0x1C_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xE1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xE1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xE2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xE2_u8; 16]).to_vec(),
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: entry_recips,
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x98_u8; 8],
            recipients: event_recips,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![(carol_id.principal().clone(), setup.carol_period)],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    (plan, ctx, transition_id)
}

/// Re-derive carol's `device_keys.key_id` the same way `seed_actor` did (the
/// ed25519 thumbprint of her seeded signing key), so her zeroLeafLeave ctx actor
/// carries the exact key id her device row holds.
async fn seed_actor_key_id(pool: &PgPool, did: &str, device: Uuid) -> String {
    sqlx::query_scalar("SELECT key_id FROM chat.device_keys WHERE user_did=$1 AND device_id=$2")
        .bind(did)
        .bind(device)
        .fetch_one(pool)
        .await
        .expect("carol device key id")
}

/// ADR-019 Erratum 01 (Concern 1) POSITIVE: a zeroLeafLeave (leavePolicy) by a
/// leafless member SUCCEEDS while a DIFFERENT member holds a pending leave request,
/// durably staling that request bound to the leavePolicy transition. This was
/// fail-closed before the erratum (the DDL forbade a leaveCommit/leavePolicy stale
/// authority).
#[tokio::test]
async fn zero_leaf_leave_stales_other_members_pending_leave_request() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let setup_data = seed_three_member_bob_pending_leave(&pool, scenario).await;
    let conversation_id = setup_data.scenario.conversation_id;
    let carol_did = setup_data.carol_did.clone();
    let bob_leave_request_id = setup_data.bob_leave_request_id;
    let (plan, ctx, zll_transition) = build_carol_zero_leaf_leave(&pool, &setup_data).await;
    let zll_request_digest = ctx
        .authority
        .control_entry()
        .expect("zero-leaf leave carries control-entry authority")
        .request_digest
        .clone();

    let mut tx = pool.begin().await.expect("begin carol zero-leaf leave");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("carol zero-leaf leave staling bob's pending leave applies");
    tx.commit()
        .await
        .expect("carol zero-leaf leave COMMIT past all deferred triggers");

    // Coordinate advanced sv 3 -> 4 (leavePolicy, same generation/epoch).
    let (sv, next_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((sv, next_seq), (4, 7));
    // Carol self-removed.
    let carol_current: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&carol_did)
    .fetch_one(&pool)
    .await
    .expect("carol membership");
    assert_eq!(carol_current, 0, "carol self-removed");
    // Bob's pending leave is STALE, bound to the leavePolicy transition + its digest.
    let (leave_status, leave_tid, leave_digest): (String, Option<Uuid>, Option<Vec<u8>>) =
        sqlx::query_as(
            "SELECT status,terminal_transition_id,terminal_request_digest \
               FROM chat.leave_requests WHERE leave_request_id=$1",
        )
        .bind(bob_leave_request_id)
        .fetch_one(&pool)
        .await
        .expect("bob leave terminal");
    assert_eq!(leave_status, "stale");
    assert_eq!(leave_tid, Some(zll_transition));
    assert_eq!(leave_digest, Some(zll_request_digest));
    // The terminal transition is a leavePolicy — the previously-forbidden kind.
    let tkind: String =
        sqlx::query_scalar("SELECT kind FROM chat.transitions WHERE transition_id=$1")
            .bind(zll_transition)
            .fetch_one(&pool)
            .await
            .expect("zll transition kind");
    assert_eq!(tkind, "leavePolicy");
    cleanup(&pool, conversation_id).await;
}

/// ADR-019 Erratum 01 desync (zero-leaf-leave shape guard): a zeroLeafLeave plan
/// whose leave delta is `Pending->Fulfilled` (a zeroLeafLeave owns NO leave request
/// of its own) is a hard `InconsistentPlan` with zero residue.
#[tokio::test]
async fn zero_leaf_leave_carrying_a_fulfilled_leave_delta_is_rejected() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let setup_data = seed_three_member_bob_pending_leave(&pool, scenario).await;
    let conversation_id = setup_data.scenario.conversation_id;
    let bob_leave_request_id = setup_data.bob_leave_request_id;
    let (plan, ctx, _zll) = build_carol_zero_leaf_leave(&pool, &setup_data).await;
    let bad = plan.with_leave_staling_flipped_to_fulfilled_for_test();

    let mut tx = pool.begin().await.expect("begin corrupted zero-leaf leave");
    let result = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &bad, &ctx).await;
    assert!(
        matches!(result, Err(ExecutorError::InconsistentPlan(_))),
        "a Fulfilled leave delta in a zeroLeafLeave must be InconsistentPlan, got {result:?}"
    );
    tx.rollback().await.expect("rollback");
    // Zero residue: coordinate still sv 3, bob's leave still pending.
    let (sv, leave_status): (i64, String) = sqlx::query_as(
        "SELECT (SELECT current_state_version FROM chat.conversations WHERE conversation_id=$1), \
                (SELECT status FROM chat.leave_requests WHERE leave_request_id=$2)",
    )
    .bind(conversation_id)
    .bind(bob_leave_request_id)
    .fetch_one(&pool)
    .await
    .expect("residue");
    assert_eq!((sv, leave_status.as_str()), (3, "pending"));
    cleanup(&pool, conversation_id).await;
}

/// Remove one conversation's committed graph so the shared, never-truncated
/// clean-chat DB stays clean across runs. Runs inside ONE transaction: the
/// `chat.entries` <-> `chat.transitions` provenance FKs are circular and
/// DEFERRABLE INITIALLY DEFERRED, so both must be deleted before the (single)
/// commit-time check fires. Global `chat.events`/`chat.outbox` rows are not
/// conversation-scoped and are left in place (the event-recipient chain is
/// re-derived per run, so their accumulation is harmless).
async fn cleanup(pool: &PgPool, conversation_id: Uuid) {
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return,
    };
    for stmt in [
        "DELETE FROM chat.application_intervals WHERE conversation_id=$1",
        "DELETE FROM chat.member_devices WHERE conversation_id=$1",
        "DELETE FROM chat.participants WHERE conversation_id=$1",
        "DELETE FROM chat.metadata_snapshots WHERE conversation_id=$1",
        "DELETE FROM chat.entry_recipients WHERE conversation_id=$1",
        "DELETE FROM chat.entries WHERE conversation_id=$1",
        "DELETE FROM chat.transitions WHERE conversation_id=$1",
        "DELETE FROM chat.generation_states WHERE conversation_id=$1",
        "DELETE FROM chat.generations WHERE conversation_id=$1",
        "DELETE FROM chat.conversations WHERE conversation_id=$1",
    ] {
        if sqlx::query(stmt)
            .bind(conversation_id)
            .execute(&mut *tx)
            .await
            .is_err()
        {
            let _ = tx.rollback().await;
            return;
        }
    }
    let _ = tx.commit().await;
}

// ---------------------------------------------------------------------------
// Device revocation (arm 5) — the entry-less per-conversation arm driven by the
// batch entry point, committed past the DEFERRED enforce_device_revocation_mapping.
// ---------------------------------------------------------------------------

/// Everything the revocation batch test needs: the assembled batch plan + the
/// entry-less conversation context + the ids a SELECT-verify uses. Alice is a
/// self-revoke target (actor == target) whose `replace` leaf-recovery request
/// opened one request + reservation + reserved package (Request-origin, so the
/// revocation's `expected_target_auth_generation` binds `origin.auth_generation`).
struct RevocationSetup {
    batch_plan: DeviceRevocationBatchPersistencePlan,
    conv_ctx: ExecutionContext,
    target_did: String,
    target_device: Uuid,
    target_key_id: String,
    conversation_id: Uuid,
    revocation_id: Uuid,
    recovery_request_id: Uuid,
    key_package_ref: [u8; 32],
    accepted_dt: DateTime<Utc>,
    signing_transcript: Vec<u8>,
    signed_request: Vec<u8>,
    request_digest: Vec<u8>,
    signature: Vec<u8>,
}

/// Create a group, have alice open a `replace` leaf-recovery request (opening her
/// request + reservation + reserved package, coordinate UNCHANGED), then assemble
/// a self-revoke batch of alice against the post-request state. `accepted_at` is
/// DB-clock-based (the corpus eval instant, 2023, predates the real `created_at`
/// of the seeded devices, which would fail the trigger's
/// `actor.created_at <= accepted_at` check).
async fn setup_revoked_target(pool: &PgPool) -> RevocationSetup {
    let fixture = commit_creation(pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    let alice_id = fixture.alice_id.clone();
    let alice_did = fixture.alice_did.clone();
    let alice_device = fixture.alice_device;
    let alice_key_id = fixture.alice_key_id.clone();
    let alice_sig_key =
        hex::decode(&corpus_manifest().identity.alice.signature_public_key_hex).unwrap();

    // Alice's genesis leaf period (the leaf a `replace` request recovers).
    let alice_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2",
    )
    .bind(conversation_id)
    .bind(&alice_did)
    .fetch_one(pool)
    .await
    .expect("alice leaf period");

    // Alice opens a `replace` leaf-recovery request (entry-less; coordinate + seq
    // counter UNCHANGED, still gen0/sv0/next_seq 2).
    let key_package_ref = random_ref32();
    let package_not_after = seed_key_package(
        pool,
        &alice_did,
        alice_device,
        &alice_key_id,
        &key_package_ref,
    )
    .await;
    // DB-clock-based so the request's expires_at (received_at + 5 min) stays AFTER
    // the revocation's accepted_at (also DB-clock, sampled ~ms later). With an
    // eval-based (2023) received_at, plan_device_revocation would terminalize the
    // request as EXPIRED (accepted_at >= expires_at), not revocation-superseded.
    let req_received =
        ServerTimestamp::from_unix_millis_for_test(clock_now(pool).await.timestamp_millis())
            .unwrap();
    let pkg_not_after_ts =
        ServerTimestamp::from_unix_millis_for_test(package_not_after.timestamp_millis()).unwrap();
    let recovery_request_id = Uuid::new_v4();
    let req_evidence = RequestEvidence::for_test(
        RequestEntryKind::LeafRecoveryRequest,
        2,
        *recovery_request_id.as_bytes(),
        alice_id.clone(),
        *conversation_id.as_bytes(),
        req_received,
        0x71,
    )
    .unwrap();
    let req_planned = plan_leaf_recovery_request(
        &fixture.state,
        LeafRecoveryRequestCommand {
            actor: alice_id.clone(),
            recovery_request_id: *recovery_request_id.as_bytes(),
            kind: LeafRecoveryKind::Replace,
            key_package_ref,
            received_at: req_received,
            package_not_after: pkg_not_after_ts,
            evidence: req_evidence,
        },
    )
    .expect("valid leaf recovery request plan");
    let post_request_state = req_planned.resulting_state().clone();
    let req_head = ConversationHeadCasBinding::for_test_internal(
        *conversation_id.as_bytes(),
        fixture.coordinate,
        2,
        req_received,
    );
    let req_plan = persistence_plan_for_test(req_planned, req_head);
    let req_applied_at = clock_now(pool).await;
    let req_transcript = vec![0x72_u8; 16];
    let alice_pred = device_event_predecessor(pool, &alice_did, alice_device).await;
    let req_ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at: req_applied_at,
        actor: ExecutionActor {
            user_did: alice_did.clone(),
            device_id: alice_device,
            key_id: alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
            accepted_payload_bytes: vec![0x73_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x73_u8; 8]).to_vec(),
            signed_request_bytes: req_transcript.clone(),
            unsigned_projection_bytes: vec![0x74_u8; 8],
            signing_transcript_bytes: req_transcript.clone(),
            request_digest: Sha256::digest(&req_transcript).to_vec(),
            signature: vec![0x75_u8; 64],
            server_fields_bytes: vec![0x76_u8; 8],
            outer_entry_fingerprint: vec![0x17_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x77_u8; 8],
            recipients: vec![(
                alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: Some(RecoveryOpenContext {
            participant_period_id: None,
            package_not_after,
            replaced_leaf_period_id: Some(alice_leaf_period),
        }),
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    {
        let mut tx = pool.begin().await.expect("begin leaf recovery request");
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &req_plan, &req_ctx)
            .await
            .expect("leaf recovery request applies");
        tx.commit().await.expect("leaf recovery request COMMIT");
    }

    // Self-revoke alice against the post-request state. `accepted_at` is
    // millisecond-aligned DB-clock (after the seeded devices' created_at).
    let now = clock_now(pool).await;
    let accepted_dt = DateTime::from_timestamp_millis(now.timestamp_millis()).unwrap();
    let accepted_st =
        ServerTimestamp::from_unix_millis_for_test(accepted_dt.timestamp_millis()).unwrap();
    // The device key id is base64url(sha256(pubkey)); its raw 32 bytes ARE the
    // revocation actor_key_id (which the batch re-encodes back to `alice_key_id`).
    let actor_key_id: [u8; 32] = Sha256::digest(&alice_sig_key).into();
    let revocation_id = Uuid::new_v4();
    let signing_transcript = vec![0x7b_u8; 24];
    let request_digest: [u8; 32] = Sha256::digest(&signing_transcript).into();
    let signature = [0x5a_u8; 64];
    let signed_request = vec![0x7c_u8; 24];
    let evidence = DeviceRevocationEvidence::for_test(
        *revocation_id.as_bytes(),
        alice_id.clone(),
        alice_id.clone(),
        actor_key_id,
        1,
        1,
        accepted_st,
        accepted_st,
        request_digest,
        signature,
        signed_request.clone(),
        signing_transcript.clone(),
    );
    let revocation_planned = plan_device_revocation(&post_request_state, evidence.clone())
        .expect("valid revocation plan");
    let head_cas = ConversationHeadCasBinding::for_test_internal(
        *conversation_id.as_bytes(),
        *post_request_state.coordinate(),
        2,
        accepted_st,
    );
    let conv_plan = device_revocation_plan_for_test(revocation_planned, head_cas, evidence.clone());
    let target_cas = RevocationTargetCasBinding::for_test(alice_id.clone(), 1, accepted_st);
    let batch_plan = DeviceRevocationBatchPersistencePlan::for_test(
        evidence,
        target_cas,
        vec![],
        vec![conv_plan],
    );

    let conv_ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at: accepted_dt,
        actor: ExecutionActor {
            user_did: alice_did.clone(),
            device_id: alice_device,
            key_id: alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::Entryless {
            operation_id: revocation_id,
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![],
        events: vec![],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };

    RevocationSetup {
        batch_plan,
        conv_ctx,
        target_did: alice_did,
        target_device: alice_device,
        target_key_id: alice_key_id,
        conversation_id,
        revocation_id,
        recovery_request_id,
        key_package_ref,
        accepted_dt,
        signing_transcript,
        signed_request,
        request_digest: request_digest.to_vec(),
        signature: signature.to_vec(),
    }
}

/// Seed the `revokeDevice` idempotency receipt the DEFERRED mapping trigger
/// requires (production's request handler writes this through the sealed
/// operation-completion path).
async fn seed_revoke_receipt(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, s: &RevocationSetup) {
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
    .bind(&s.target_did)
    .bind(s.revocation_id)
    .bind(&s.request_digest)
    .bind(&s.signed_request)
    .bind(&s.signing_transcript)
    .bind(&s.signature)
    .bind(&response_bytes)
    .bind(&response_sha256)
    .bind(&s.target_key_id)
    .bind(s.accepted_dt)
    .execute(&mut **tx)
    .await
    .expect("seed revokeDevice receipt");
}

#[tokio::test]
async fn device_revocation_batch_commits_and_supersedes_target_work() {
    let (pool, _db) = setup().await;
    let s = setup_revoked_target(&pool).await;

    let mut tx = pool.begin().await.expect("begin revocation");
    seed_revoke_receipt(&mut tx, &s).await;
    let applied = apply_device_revocation_batch_unscoped_for_test(
        &mut tx,
        &s.batch_plan,
        std::slice::from_ref(&s.conv_ctx),
    )
    .await
    .expect("device revocation batch applies");
    tx.commit()
        .await
        .expect("device revocation COMMIT past enforce_device_revocation_mapping");
    assert_eq!(applied.len(), 1);
    // Entry-less: the seq counter is echoed unchanged (still 2).
    assert_eq!(applied[0].allocated_seq, 2);

    // The target registration is revoked, bound to the revocation.
    let (dev_status, dev_rev): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT status, revocation_id FROM chat.devices WHERE user_did=$1 AND device_id=$2",
    )
    .bind(&s.target_did)
    .bind(s.target_device)
    .fetch_one(&pool)
    .await
    .expect("target device");
    assert_eq!(
        (dev_status.as_str(), dev_rev),
        ("revoked", Some(s.revocation_id))
    );
    let key_rev: Option<Uuid> = sqlx::query_scalar(
        "SELECT revocation_id FROM chat.device_keys WHERE user_did=$1 AND device_id=$2",
    )
    .bind(&s.target_did)
    .bind(s.target_device)
    .fetch_one(&pool)
    .await
    .expect("target device key");
    assert_eq!(key_rev, Some(s.revocation_id));

    // The target's own work is superseded/released/revoked, all revocation-bound.
    let (req_status, req_rev): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT status, terminal_revocation_id FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(s.recovery_request_id)
    .fetch_one(&pool)
    .await
    .expect("recovery request");
    assert_eq!(
        (req_status.as_str(), req_rev),
        ("superseded", Some(s.revocation_id))
    );
    let (res_status, res_rev): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT status, terminal_revocation_id FROM chat.key_package_reservations WHERE recovery_request_id=$1",
    )
    .bind(s.recovery_request_id)
    .fetch_one(&pool)
    .await
    .expect("reservation");
    assert_eq!(
        (res_status.as_str(), res_rev),
        ("released", Some(s.revocation_id))
    );
    let (pkg_status, pkg_rev, pkg_terminal): (String, Option<Uuid>, Option<DateTime<Utc>>) =
        sqlx::query_as(
            "SELECT status, terminal_revocation_id, terminal_at FROM chat.key_packages WHERE key_package_ref=$1",
        )
        .bind(s.key_package_ref.to_vec())
        .fetch_one(&pool)
        .await
        .expect("package");
    assert_eq!(
        (pkg_status.as_str(), pkg_rev, pkg_terminal),
        ("revoked", Some(s.revocation_id), Some(s.accepted_dt))
    );

    // Coordinate + seq counter byte-untouched (entry-less op).
    let (gen, sv, next_seq): (i64, i64, i64) = sqlx::query_as(
        "SELECT current_generation,current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(s.conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((gen, sv, next_seq), (0, 0, 2));

    // Full target-footprint completeness (what the COMMIT trigger enforced).
    let live_packages: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.key_packages WHERE owner_did=$1 AND owner_device_id=$2 AND status IN ('available','reserved')",
    )
    .bind(&s.target_did)
    .bind(s.target_device)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(live_packages, 0, "no live target packages remain");
    let open_requests: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.leaf_recovery_requests WHERE requester_did=$1 AND requester_device_id=$2 AND status='open'",
    )
    .bind(&s.target_did)
    .bind(s.target_device)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(open_requests, 0, "no open target requests remain");
    let active_reservations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.key_package_reservations WHERE recipient_did=$1 AND recipient_device_id=$2 AND status='active'",
    )
    .bind(&s.target_did)
    .bind(s.target_device)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        active_reservations, 0,
        "no active target reservations remain"
    );
}

async fn commit_bob_welcome_revocation(
    pool: &PgPool,
    scenario: &FulfillmentScenario,
    accepted_at: DateTime<Utc>,
) -> Uuid {
    let bob_device = Uuid::from_bytes(*scenario.bob_id.device_id());
    let bob_key_id: String = sqlx::query_scalar(
        "SELECT key_id FROM chat.device_keys \
         WHERE user_did=$1 AND device_id=$2 AND revoked_at IS NULL",
    )
    .bind(&scenario.bob_did)
    .bind(bob_device)
    .fetch_one(pool)
    .await
    .expect("bob active signing key");
    let bob_signing_key =
        hex::decode(&corpus_manifest().identity.bob.signature_public_key_hex).unwrap();
    let accepted_st =
        ServerTimestamp::from_unix_millis_for_test(accepted_at.timestamp_millis()).unwrap();
    let revocation_id = Uuid::new_v4();
    let signing_transcript = vec![0x8A_u8; 24];
    let request_digest: [u8; 32] = Sha256::digest(&signing_transcript).into();
    let signed_request = vec![0x8B_u8; 24];
    let signature = [0x8C_u8; 64];
    let actor_key_id: [u8; 32] = Sha256::digest(&bob_signing_key).into();
    let evidence = DeviceRevocationEvidence::for_test(
        *revocation_id.as_bytes(),
        scenario.bob_id.clone(),
        scenario.bob_id.clone(),
        actor_key_id,
        1,
        1,
        accepted_st,
        accepted_st,
        request_digest,
        signature,
        signed_request.clone(),
        signing_transcript.clone(),
    );
    let planned = plan_device_revocation(&scenario.fulfillment_state, evidence.clone())
        .expect("pending Welcome target has a valid revocation plan");
    let head_cas = ConversationHeadCasBinding::for_test_internal(
        *scenario.conversation_id.as_bytes(),
        scenario.coordinate,
        4,
        accepted_st,
    );
    let conversation_plan = device_revocation_plan_for_test(planned, head_cas, evidence.clone());
    let batch_plan = DeviceRevocationBatchPersistencePlan::for_test(
        evidence,
        RevocationTargetCasBinding::for_test(scenario.bob_id.clone(), 1, accepted_st),
        vec![],
        vec![conversation_plan],
    );
    let bob_predecessor = device_event_predecessor(pool, &scenario.bob_did, bob_device).await;
    let ctx = ExecutionContext {
        protocol_instance_id: scenario.fixture.protocol_instance_id,
        applied_at: accepted_at,
        actor: ExecutionActor {
            user_did: scenario.bob_did.clone(),
            device_id: bob_device,
            key_id: bob_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Member,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::Entryless {
            operation_id: revocation_id,
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![],
        events: vec![],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![WelcomeDispositionInput {
            welcome_id: scenario.welcome_id,
            event: EventFanout {
                event_id: Uuid::new_v4(),
                event_kind: EventKind::WelcomeDisposition,
                payload_bytes: vec![0x90_u8; 8],
                recipients: vec![(
                    scenario.bob_id.clone(),
                    EventEntitlementKind::Welcome,
                    bob_predecessor,
                )],
                outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
            },
        }],
    };

    let response_bytes = b"revokeDevice-welcome-ok".to_vec();
    let mut tx = pool.begin().await.expect("begin Welcome revocation");
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
    .bind(&scenario.bob_did)
    .bind(revocation_id)
    .bind(request_digest.to_vec())
    .bind(&signed_request)
    .bind(&signing_transcript)
    .bind(signature.to_vec())
    .bind(&response_bytes)
    .bind(Sha256::digest(&response_bytes).to_vec())
    .bind(&bob_key_id)
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("seed Welcome revocation receipt");
    apply_device_revocation_batch_unscoped_for_test(
        &mut tx,
        &batch_plan,
        std::slice::from_ref(&ctx),
    )
    .await
    .expect("apply Welcome revocation batch");
    tx.commit()
        .await
        .expect("commit Welcome revocation provenance");
    revocation_id
}

#[tokio::test]
async fn device_revocation_supersedes_pending_welcome_with_exact_revocation_source() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    // A fully mapped revocation of a foreign device at the SAME instant gives
    // the deferred Welcome CAS a durable wrong-target candidate. It satisfies
    // the direct FK and the revocation's own mapping, so only recipient binding
    // distinguishes it from the real source.
    let (foreign_revocation_id, accepted_at) = commit_isolated_device_revocation(&pool).await;
    let revocation_id = commit_bob_welcome_revocation(&pool, &scenario, accepted_at).await;

    let (status, terminal_transition_id, terminal_revocation_id): (
        String,
        Option<Uuid>,
        Option<Uuid>,
    ) = sqlx::query_as(
        "SELECT delivery.status,disposition.terminal_transition_id,\
                disposition.terminal_revocation_id \
           FROM chat.welcome_deliveries delivery \
           JOIN chat.welcome_dispositions disposition USING (welcome_id) \
          WHERE delivery.welcome_id=$1",
    )
    .bind(scenario.welcome_id)
    .fetch_one(&pool)
    .await
    .expect("read Welcome revocation source");
    assert_eq!(
        (
            status.as_str(),
            terminal_transition_id,
            terminal_revocation_id
        ),
        ("superseded", None, Some(revocation_id))
    );

    assert_welcome_source_commit_rejects(
        &pool,
        scenario.welcome_id,
        "terminal_transition_id=NULL,terminal_revocation_id=$2",
        Some(foreign_revocation_id),
        "revocation source targeting the wrong recipient device",
    )
    .await;
    assert_welcome_source_commit_rejects(
        &pool,
        scenario.welcome_id,
        "terminal_at=terminal_at+interval '1 millisecond'",
        None,
        "revocation source with the wrong terminal instant",
    )
    .await;
}

/// The device-revocation batch's AVAILABLE-package path (step 3): a target device
/// with an available (`conversation_id IS NULL`) key package alongside its reserved
/// one has BOTH revoked in one transaction — the reserved by the per-conversation
/// arm, the available by `apply_device_revocation_batch_unscoped_for_test`'s
/// `cas_key_package_status(Available, Revoke)` loop over the plan's
/// `revoked_packages`. The available package MUST be seeded BEFORE the batch and
/// carried in `revoked_packages` (not post-hoc), or the DEFERRED
/// `assert_device_revocation_mapping` footprint trigger — which requires ZERO
/// remaining available/reserved target packages — rejects the commit.
#[tokio::test]
async fn device_revocation_batch_revokes_available_target_package() {
    let (pool, _db) = setup().await;
    let s = setup_revoked_target(&pool).await;

    // Seed a second, AVAILABLE (conversation_id NULL) package for the same target
    // device — committed before the batch. Its `created_at` is set BEFORE the
    // revocation's `accepted_at` so the revoked-shape check (`terminal_at >=
    // created_at`) holds (the batch stamps `terminal_at = accepted_at`); a naive
    // post-setup `seed_key_package` samples the clock AFTER accepted_at and fails
    // that check. Without a matching revoked_packages binding it would also leave a
    // live target package and trip the footprint trigger.
    let available_ref = random_ref32();
    let avail_created = s.accepted_dt - Duration::hours(1);
    let avail_not_before = avail_created - Duration::hours(1);
    let avail_not_after =
        DateTime::from_timestamp_millis((avail_created + Duration::hours(24)).timestamp_millis())
            .unwrap();
    let avail_wrapper = vec![0xC1_u8; 32];
    let avail_init_key = {
        let mut key = vec![0u8; 32];
        key[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        key[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        key
    };
    sqlx::query(
        "INSERT INTO chat.key_packages(key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,status,created_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,'available',$10)",
    )
    .bind(available_ref.to_vec())
    .bind(&avail_wrapper)
    .bind(Sha256::digest(&avail_wrapper).to_vec())
    .bind(&avail_init_key)
    .bind(&s.target_did)
    .bind(s.target_device)
    .bind(&s.target_key_id)
    .bind(avail_not_before)
    .bind(avail_not_after)
    .bind(avail_created)
    .execute(&pool)
    .await
    .expect("seed available target package");
    let accepted_st =
        ServerTimestamp::from_unix_millis_for_test(s.accepted_dt.timestamp_millis()).unwrap();
    let revocation_id = s.revocation_id;

    let mut tx = pool.begin().await.expect("begin revocation");
    // Seed the idempotency receipt (needs the whole `&s`) BEFORE consuming
    // `s.batch_plan` via into_parts below.
    seed_revoke_receipt(&mut tx, &s).await;
    // Rebuild the batch plan carrying the available-package revoke binding (the base
    // setup passes an empty revoked_packages list). Reuse the same authority /
    // target CAS / conversation plan.
    let (authority, target_cas, empty_packages, _digest, conversations) = s.batch_plan.into_parts();
    assert!(
        empty_packages.is_empty(),
        "base setup carries no available-package bindings"
    );
    let available_binding = RevocationPackageCasBinding::for_test_available(
        authority.target().clone(),
        available_ref,
        *revocation_id.as_bytes(),
        accepted_st,
    );
    let batch_plan = DeviceRevocationBatchPersistencePlan::for_test(
        authority,
        target_cas,
        vec![available_binding],
        conversations,
    );
    apply_device_revocation_batch_unscoped_for_test(
        &mut tx,
        &batch_plan,
        std::slice::from_ref(&s.conv_ctx),
    )
    .await
    .expect("device revocation batch with available package applies");
    tx.commit()
        .await
        .expect("device revocation COMMIT past the footprint trigger");

    // The available package is now revoked, bound to the revocation at accepted_at.
    let (avail_status, avail_rev, avail_terminal): (String, Option<Uuid>, Option<DateTime<Utc>>) =
        sqlx::query_as(
            "SELECT status, terminal_revocation_id, terminal_at FROM chat.key_packages WHERE key_package_ref=$1",
        )
        .bind(available_ref.to_vec())
        .fetch_one(&pool)
        .await
        .expect("available package");
    assert_eq!(
        (avail_status.as_str(), avail_rev, avail_terminal),
        ("revoked", Some(revocation_id), Some(s.accepted_dt))
    );
    // The reserved package (per-conversation arm) is revoked too.
    let reserved_status: String =
        sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE key_package_ref=$1")
            .bind(s.key_package_ref.to_vec())
            .fetch_one(&pool)
            .await
            .expect("reserved package");
    assert_eq!(reserved_status, "revoked");
    // Footprint: zero live target packages remain (what the commit trigger enforced).
    let live_packages: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.key_packages WHERE owner_did=$1 AND owner_device_id=$2 AND status IN ('available','reserved')",
    )
    .bind(&s.target_did)
    .bind(s.target_device)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(live_packages, 0, "no live target packages remain");
}

const PRE_V4_CHAT_MIGRATIONS: [&str; 3] = [
    "20260722000001_chat_protocol_core.sql",
    "20260722000002_chat_protocol_delivery.sql",
    "20260722000003_chat_protocol_blobs.sql",
];
const WELCOME_PROVENANCE_PREFLIGHT_MIGRATION: &str =
    "20260725000001_prepare_welcome_provenance_backfill.sql";
const WELCOME_PROVENANCE_QUARANTINE_MIGRATION: &str =
    "20260725000002_refine_welcome_provenance_quarantine.sql";
const WELCOME_PROVENANCE_MIGRATION: &str = "20260726000001_welcome_supersession_provenance.sql";
const WELCOME_PROVENANCE_POSTFLIGHT_MIGRATION: &str =
    "20260726000002_restore_welcome_provenance_deferred_triggers.sql";
const WELCOME_PROVENANCE_FINALIZER_MIGRATION: &str =
    "20260726000003_finalize_welcome_provenance_triggers.sql";

struct PreV4WelcomeHistory {
    welcome_id: Uuid,
    source_id: Uuid,
    recipient_did: String,
    recipient_device_id: Uuid,
    terminal_at: DateTime<Utc>,
}

fn migration_text(filename: &str) -> String {
    std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("migrations")
            .join(filename),
    )
    .unwrap_or_else(|error| panic!("read {filename}: {error}"))
}

async fn fresh_upgrade_db() -> (PgPool, FreshDbGuard) {
    let maintenance_url = maintenance_url_from_env();
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&maintenance_url)
        .await
        .expect("connect to loopback maintenance database");
    let db_name = format!("chat_upgrade_{}", Uuid::new_v4().simple());
    assert!(
        db_name.starts_with("chat_upgrade_")
            && db_name.strip_prefix("chat_upgrade_").is_some_and(
                |suffix| suffix.len() == 32 && suffix.bytes().all(|b| b.is_ascii_hexdigit())
            ),
        "scratch database name must be a validated UUID-derived identifier"
    );
    sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
        .execute(&admin)
        .await
        .expect("create isolated upgrade database");
    admin.close().await;

    let mut db_url = url::Url::parse(&maintenance_url).expect("maintenance URL");
    db_url.set_path(&format!("/{db_name}"));
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(db_url.as_str())
        .await
        .expect("connect to isolated upgrade database");
    (
        pool,
        FreshDbGuard {
            maintenance_url,
            db_name,
        },
    )
}

async fn fresh_pre_v4_upgrade_db() -> (PgPool, FreshDbGuard) {
    let (pool, guard) = fresh_upgrade_db().await;
    for filename in PRE_V4_CHAT_MIGRATIONS {
        let sql = migration_text(filename);
        let mut tx = pool.begin().await.expect("begin ordered pre-v4 migration");
        sqlx::Executor::execute(&mut *tx, sql.as_str())
            .await
            .unwrap_or_else(|error| panic!("apply {filename}: {error}"));
        tx.commit()
            .await
            .unwrap_or_else(|error| panic!("commit {filename}: {error}"));
    }
    (pool, guard)
}

async fn add_temporary_writer_columns(pool: &PgPool) {
    sqlx::query(
        "ALTER TABLE chat.welcome_dispositions \
         ADD COLUMN terminal_transition_id UUID, \
         ADD COLUMN terminal_revocation_id UUID",
    )
    .execute(pool)
    .await
    .expect("add nullable writer-compatibility columns");
}

async fn restore_exact_pre_v4_table_boundary(pool: &PgPool) {
    sqlx::query(
        "ALTER TABLE chat.welcome_dispositions \
         DROP COLUMN terminal_transition_id, \
         DROP COLUMN terminal_revocation_id",
    )
    .execute(pool)
    .await
    .expect("drop writer-compatibility columns before v4");
    assert_eq!(
        welcome_source_column_count(pool).await,
        0,
        "pre-v4 boundary must have neither provenance column"
    );
}

async fn welcome_source_column_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.columns \
          WHERE table_schema='chat' AND table_name='welcome_dispositions' \
            AND column_name IN ('terminal_transition_id','terminal_revocation_id')",
    )
    .fetch_one(pool)
    .await
    .expect("count Welcome source columns")
}

async fn prepare_transition_supersession_history() -> (PgPool, FreshDbGuard, PreV4WelcomeHistory) {
    let (pool, guard) = fresh_pre_v4_upgrade_db().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    add_temporary_writer_columns(&pool).await;
    let built = build_generic_commit(&pool, &scenario).await;
    let source_id = built.commit_transition;
    let mut tx = pool
        .begin()
        .await
        .expect("begin historical transition supersession");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &built.plan, &built.ctx)
        .await
        .expect("apply historical transition supersession");
    tx.commit()
        .await
        .expect("commit old-CAS-coherent transition supersession");
    let terminal_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT terminal_at FROM chat.welcome_dispositions WHERE welcome_id=$1")
            .bind(scenario.welcome_id)
            .fetch_one(&pool)
            .await
            .expect("read transition supersession instant");
    restore_exact_pre_v4_table_boundary(&pool).await;
    (
        pool,
        guard,
        PreV4WelcomeHistory {
            welcome_id: scenario.welcome_id,
            source_id,
            recipient_did: scenario.bob_did,
            recipient_device_id: Uuid::from_bytes(*scenario.bob_id.device_id()),
            terminal_at,
        },
    )
}

async fn prepare_revocation_supersession_history() -> (PgPool, FreshDbGuard, PreV4WelcomeHistory) {
    let (pool, guard) = fresh_pre_v4_upgrade_db().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    add_temporary_writer_columns(&pool).await;
    let (_foreign_revocation_id, accepted_at) = commit_isolated_device_revocation(&pool).await;
    let source_id = commit_bob_welcome_revocation(&pool, &scenario, accepted_at).await;
    restore_exact_pre_v4_table_boundary(&pool).await;
    (
        pool,
        guard,
        PreV4WelcomeHistory {
            welcome_id: scenario.welcome_id,
            source_id,
            recipient_did: scenario.bob_did,
            recipient_device_id: Uuid::from_bytes(*scenario.bob_id.device_id()),
            terminal_at: accepted_at,
        },
    )
}

async fn apply_manual_migration(pool: &PgPool, filename: &str) {
    let sql = migration_text(filename);
    let mut tx = pool.begin().await.expect("begin manual migration");
    sqlx::Executor::execute(&mut *tx, sql.as_str())
        .await
        .unwrap_or_else(|error| panic!("apply {filename}: {error}"));
    tx.commit()
        .await
        .unwrap_or_else(|error| panic!("commit {filename}: {error}"));
}

/// Exercise the exact pre-v4 Welcome terminalization order: fanout first, then
/// delivery CAS + the historical nine-column disposition INSERT, and only then
/// the required recovery-work row. This intentionally does not call the current
/// writer because its two v4 provenance columns do not exist at this boundary.
#[derive(Clone, Copy)]
enum PreV4WelcomeTerminalKind {
    Expired,
    Rejected,
}

struct PreV4WelcomeTerminalization {
    terminal_at: DateTime<Utc>,
    event_position: i64,
    recovery_work_id: Uuid,
}

async fn commit_pre_v4_welcome_terminalization(
    pool: &PgPool,
    scenario: &FulfillmentScenario,
    kind: PreV4WelcomeTerminalKind,
) -> Result<PreV4WelcomeTerminalization, DeliveryRepositoryError> {
    let welcome_id = scenario.welcome_id;
    let recipient_device_id = Uuid::from_bytes(*scenario.bob_id.device_id());
    let expires_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT expires_at FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(pool)
            .await?;
    let terminal_at = match kind {
        PreV4WelcomeTerminalKind::Expired => expires_at,
        PreV4WelcomeTerminalKind::Rejected => expires_at - Duration::seconds(1),
    };
    let (winner_kind, source_kind) = match kind {
        PreV4WelcomeTerminalKind::Expired => ("expired", RecoveryWorkSourceKind::WelcomeExpired),
        PreV4WelcomeTerminalKind::Rejected => ("rejected", RecoveryWorkSourceKind::WelcomeRejected),
    };
    let predecessor = device_event_predecessor(pool, &scenario.bob_did, recipient_device_id).await;
    let event_id = Uuid::new_v4();
    let outbox_id = Uuid::new_v4();
    let recovery_work_id = Uuid::new_v4();
    let mut tx = pool.begin().await?;

    let event_position = chat_protocol::repository::delivery::append_event(
        &mut tx,
        &NewEvent {
            event_id,
            event_kind: EventKind::WelcomeDisposition,
            payload_bytes: vec![0xE1; 8],
            created_at: terminal_at,
            protocol_instance_id: scenario.fixture.protocol_instance_id,
        },
    )
    .await?;
    chat_protocol::repository::delivery::insert_event_recipients(
        &mut tx,
        event_position,
        &[EventRecipient {
            user_did: scenario.bob_did.clone(),
            device_id: recipient_device_id,
            entitlement_kind: EventEntitlementKind::Welcome,
            audience_predecessor_position: predecessor,
        }],
    )
    .await?;
    chat_protocol::repository::delivery::enqueue_outbox(
        &mut tx,
        outbox_id,
        event_position,
        OutboxWorkKind::Stream,
        terminal_at,
    )
    .await?;

    let updated = sqlx::query(
        "UPDATE chat.welcome_deliveries \
            SET status=$2, terminal_at=$3 \
          WHERE welcome_id=$1 AND status='pending'",
    )
    .bind(welcome_id)
    .bind(winner_kind)
    .bind(terminal_at)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(DeliveryRepositoryError::CompareAndSetConflict);
    }

    // Historical v1-v3 writer shape. Under migration A this INSERT fires the
    // recovery assertion before the next statement can materialize its work.
    let transcript = vec![0xE2; 24];
    let digest = Sha256::digest(&transcript).to_vec();
    let (signed_request, signing_transcript, request_digest, signature, rejection_reason): (
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<&str>,
    ) = match kind {
        PreV4WelcomeTerminalKind::Expired => (None, None, None, None, None),
        PreV4WelcomeTerminalKind::Rejected => (
            Some(transcript.clone()),
            Some(transcript),
            Some(digest),
            Some(vec![0xE3; 64]),
            Some("noMatchingKeyPackage"),
        ),
    };
    sqlx::query(
        "INSERT INTO chat.welcome_dispositions( \
            welcome_id,winner_kind,signed_request_bytes,signing_transcript_bytes, \
            request_digest,signature,rejection_reason,terminal_at,event_position \
         ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(welcome_id)
    .bind(winner_kind)
    .bind(signed_request)
    .bind(signing_transcript)
    .bind(request_digest)
    .bind(signature)
    .bind(rejection_reason)
    .bind(terminal_at)
    .bind(event_position)
    .execute(&mut *tx)
    .await?;

    chat_protocol::repository::delivery::insert_recovery_work_item(
        &mut tx,
        &NewRecoveryWorkItem {
            recovery_work_id,
            conversation_id: scenario.conversation_id,
            recipient_did: scenario.bob_did.clone(),
            recipient_device_id,
            source_kind,
            source_id: welcome_id,
            generation: i64::try_from(scenario.coordinate.generation())
                .expect("test generation fits BIGINT"),
            state_version: i64::try_from(scenario.coordinate.state_version())
                .expect("test state version fits BIGINT"),
            created_at: terminal_at,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(PreV4WelcomeTerminalization {
        terminal_at,
        event_position,
        recovery_work_id,
    })
}

#[tokio::test]
async fn old_schema_welcome_expiry_commits_during_preflight_quarantine() {
    let (pool, _guard) = fresh_pre_v4_upgrade_db().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    apply_manual_migration(&pool, WELCOME_PROVENANCE_PREFLIGHT_MIGRATION).await;
    apply_manual_migration(&pool, WELCOME_PROVENANCE_QUARANTINE_MIGRATION).await;

    let terminalization =
        commit_pre_v4_welcome_terminalization(&pool, &scenario, PreV4WelcomeTerminalKind::Expired)
            .await
            .expect("old writer must cross the pre-v4 quarantine without changing statement order");
    assert_pre_v4_welcome_terminalization(
        &pool,
        &scenario,
        &terminalization,
        "expired",
        "welcomeExpired",
    )
    .await;
}

#[tokio::test]
async fn old_schema_welcome_rejection_commits_during_preflight_quarantine() {
    let (pool, _guard) = fresh_pre_v4_upgrade_db().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    apply_manual_migration(&pool, WELCOME_PROVENANCE_PREFLIGHT_MIGRATION).await;
    apply_manual_migration(&pool, WELCOME_PROVENANCE_QUARANTINE_MIGRATION).await;

    let terminalization =
        commit_pre_v4_welcome_terminalization(&pool, &scenario, PreV4WelcomeTerminalKind::Rejected)
            .await
            .expect("old rejection writer must cross the pre-v4 quarantine");
    assert_pre_v4_welcome_terminalization(
        &pool,
        &scenario,
        &terminalization,
        "rejected",
        "welcomeRejected",
    )
    .await;
}

async fn assert_pre_v4_welcome_terminalization(
    pool: &PgPool,
    scenario: &FulfillmentScenario,
    terminalization: &PreV4WelcomeTerminalization,
    winner_kind: &str,
    source_kind: &str,
) {
    let row: (
        String,
        DateTime<Utc>,
        i64,
        String,
        String,
        Uuid,
        DateTime<Utc>,
    ) = sqlx::query_as(
        "SELECT disposition.winner_kind,disposition.terminal_at, \
                disposition.event_position,event.event_kind,work.source_kind, \
                work.recovery_work_id,work.created_at \
           FROM chat.welcome_dispositions disposition \
           JOIN chat.events event \
             ON event.event_position=disposition.event_position \
           JOIN chat.event_recipients recipient \
             ON recipient.event_position=event.event_position \
            AND recipient.user_did=$2 AND recipient.device_id=$3 \
            AND recipient.entitlement_kind='welcome' \
           JOIN chat.outbox outbox \
             ON outbox.event_position=event.event_position \
            AND outbox.work_kind='stream' \
           JOIN chat.recovery_work_items work \
             ON work.source_id=disposition.welcome_id \
          WHERE disposition.welcome_id=$1",
    )
    .bind(scenario.welcome_id)
    .bind(&scenario.bob_did)
    .bind(Uuid::from_bytes(*scenario.bob_id.device_id()))
    .fetch_one(pool)
    .await
    .expect("read committed old-writer disposition graph");
    assert_eq!(row.0, winner_kind);
    assert_eq!(row.1, terminalization.terminal_at);
    assert_eq!(row.2, terminalization.event_position);
    assert_eq!(row.3, "welcomeDisposition");
    assert_eq!(row.4, source_kind);
    assert_eq!(row.5, terminalization.recovery_work_id);
    assert_eq!(row.6, terminalization.terminal_at);
}

async fn welcome_disposition_triggers_are_initially_deferred(pool: &PgPool) -> bool {
    let states: Vec<bool> = sqlx::query_scalar(
        "SELECT tginitdeferred FROM pg_trigger \
          WHERE tgrelid='chat.welcome_dispositions'::regclass \
            AND tgname IN ( \
                'welcome_dispositions_delivery_cas_deferred', \
                'welcome_dispositions_recovery_work_deferred' \
            ) \
          ORDER BY tgname",
    )
    .fetch_all(pool)
    .await
    .expect("read Welcome trigger deferral states");
    assert_eq!(
        states.len(),
        2,
        "both Welcome constraint triggers must exist"
    );
    assert_eq!(
        states[0], states[1],
        "Welcome constraint triggers must share one timing mode"
    );
    states[0]
}

async fn assert_welcome_disposition_trigger_catalog(
    pool: &PgPool,
    expected_update_event: bool,
    expected_initially_deferred: bool,
    label: &str,
) {
    let states: Vec<(String, bool, bool, bool, bool, bool, String)> = sqlx::query_as(
        "SELECT tgname,tgdeferrable,tginitdeferred, \
                (tgtype & 4)=4,(tgtype & 8)=8,(tgtype & 16)=16,tgenabled::text \
           FROM pg_trigger \
          WHERE tgrelid='chat.welcome_dispositions'::regclass \
            AND tgname IN ( \
                'welcome_dispositions_delivery_cas_deferred', \
                'welcome_dispositions_recovery_work_deferred' \
            ) \
          ORDER BY tgname",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_else(|error| panic!("{label}: read Welcome trigger catalog: {error}"));
    assert_eq!(states.len(), 2, "{label}: exact trigger count");
    for (name, deferrable, initially_deferred, insert, delete, update, enabled) in states {
        assert!(deferrable, "{label}: {name} must be DEFERRABLE");
        assert_eq!(
            initially_deferred, expected_initially_deferred,
            "{label}: {name} initial timing"
        );
        assert!(insert, "{label}: {name} must cover INSERT");
        assert!(delete, "{label}: {name} must cover DELETE");
        assert_eq!(
            update, expected_update_event,
            "{label}: {name} UPDATE event"
        );
        assert_eq!(enabled, "O", "{label}: {name} enabled state");
    }
}

async fn apply_welcome_provenance_bridge(pool: &PgPool) {
    apply_manual_migration(pool, WELCOME_PROVENANCE_PREFLIGHT_MIGRATION).await;
    assert_welcome_disposition_trigger_catalog(pool, true, false, "preflight A").await;
    apply_manual_migration(pool, WELCOME_PROVENANCE_QUARANTINE_MIGRATION).await;
    assert_welcome_disposition_trigger_catalog(pool, false, true, "quarantine A2").await;
    apply_manual_migration(pool, WELCOME_PROVENANCE_MIGRATION).await;
    apply_manual_migration(pool, WELCOME_PROVENANCE_POSTFLIGHT_MIGRATION).await;
    apply_manual_migration(pool, WELCOME_PROVENANCE_FINALIZER_MIGRATION).await;
    assert_welcome_disposition_trigger_catalog(pool, true, true, "finalizer D").await;
}

async fn assert_failed_frozen_upgrade_is_atomic(pool: &PgPool, label: &str) {
    apply_manual_migration(pool, WELCOME_PROVENANCE_PREFLIGHT_MIGRATION).await;
    apply_manual_migration(pool, WELCOME_PROVENANCE_QUARANTINE_MIGRATION).await;
    assert_welcome_disposition_trigger_catalog(pool, false, true, label).await;
    let sql = migration_text(WELCOME_PROVENANCE_MIGRATION);
    let mut tx = pool
        .begin()
        .await
        .expect("begin expected-failure v4 migration");
    let error = sqlx::Executor::execute(&mut *tx, sql.as_str())
        .await
        .expect_err(label);
    let database = error.as_database_error().expect("database migration error");
    assert_eq!(
        database.code().as_deref(),
        Some("23514"),
        "{label}: {error}"
    );
    tx.rollback()
        .await
        .expect("rollback failed frozen v4 migration");
    assert_eq!(
        welcome_source_column_count(pool).await,
        0,
        "{label}: failed v4 persisted provenance columns"
    );
    let trigger_state: String = sqlx::query_scalar(
        "SELECT tgenabled::text FROM pg_trigger \
          WHERE tgrelid='chat.welcome_dispositions'::regclass \
            AND tgname='welcome_dispositions_immutable' AND NOT tgisinternal",
    )
    .fetch_one(pool)
    .await
    .unwrap_or_else(|error| panic!("{label}: immutable trigger missing: {error}"));
    assert_eq!(
        trigger_state, "O",
        "{label}: immutable trigger must remain enabled"
    );
    assert_welcome_disposition_trigger_catalog(pool, false, true, label).await;
}

struct RuntimeMigrationSource {
    path: std::path::PathBuf,
}

impl RuntimeMigrationSource {
    fn containing(label: &str, filenames: &[&str]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "catbird_sqlx_migrations_{label}_{}",
            Uuid::new_v4().simple()
        ));
        std::fs::create_dir(&path).expect("create isolated runtime migration source");
        for filename in filenames {
            std::fs::copy(
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("migrations")
                    .join(filename),
                path.join(filename),
            )
            .unwrap_or_else(|error| panic!("copy runtime migration {filename}: {error}"));
        }
        Self { path }
    }
}

impl Drop for RuntimeMigrationSource {
    fn drop(&mut self) {
        let safe_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("catbird_sqlx_migrations_"));
        if safe_name {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[tokio::test]
async fn installed_v4_sqlx_migrator_applies_older_preflight_and_newer_postflight() {
    let (pool, _guard) = fresh_upgrade_db().await;
    let initially_installed = RuntimeMigrationSource::containing(
        "installed_v4",
        &[
            PRE_V4_CHAT_MIGRATIONS[0],
            PRE_V4_CHAT_MIGRATIONS[1],
            PRE_V4_CHAT_MIGRATIONS[2],
            WELCOME_PROVENANCE_MIGRATION,
            WELCOME_PROVENANCE_POSTFLIGHT_MIGRATION,
        ],
    );
    let initial_migrator = sqlx::migrate::Migrator::new(initially_installed.path.as_path())
        .await
        .expect("resolve installed-v4 migration source");
    initial_migrator
        .run(&pool)
        .await
        .expect("create actual SQLx-ledger installed-v4 database");

    let frozen_checksum_before: Vec<u8> = sqlx::query_scalar(
        "SELECT checksum FROM public._sqlx_migrations WHERE version=20260726000001",
    )
    .fetch_one(&pool)
    .await
    .expect("read installed frozen-v4 checksum");
    assert_eq!(
        hex::encode(&frozen_checksum_before),
        "78c31ff78db5b8889fb00cb7024186a0f048975fc7a059c667e326162e3f338396d9760143367c9206802d21269484f4",
        "installed v4 must be the frozen reviewed artifact"
    );

    let bridged_source = RuntimeMigrationSource::containing(
        "bridged",
        &[
            PRE_V4_CHAT_MIGRATIONS[0],
            PRE_V4_CHAT_MIGRATIONS[1],
            PRE_V4_CHAT_MIGRATIONS[2],
            WELCOME_PROVENANCE_PREFLIGHT_MIGRATION,
            WELCOME_PROVENANCE_QUARANTINE_MIGRATION,
            WELCOME_PROVENANCE_MIGRATION,
            WELCOME_PROVENANCE_POSTFLIGHT_MIGRATION,
            WELCOME_PROVENANCE_FINALIZER_MIGRATION,
        ],
    );
    let bridged_migrator = sqlx::migrate::Migrator::new(bridged_source.path.as_path())
        .await
        .expect("resolve eight-file bridged migration source");
    bridged_migrator
        .run(&pool)
        .await
        .expect("actual SQLx migrator must install the missing lower preflight and postflight");

    let applied_versions: Vec<i64> = sqlx::query_scalar(
        "SELECT version FROM public._sqlx_migrations \
          WHERE version=ANY($1::bigint[]) ORDER BY version",
    )
    .bind([
        20260722000001_i64,
        20260722000002,
        20260722000003,
        20260725000001,
        20260725000002,
        20260726000001,
        20260726000002,
        20260726000003,
    ])
    .fetch_all(&pool)
    .await
    .expect("read bridged SQLx ledger");
    assert_eq!(
        applied_versions,
        [
            20260722000001,
            20260722000002,
            20260722000003,
            20260725000001,
            20260725000002,
            20260726000001,
            20260726000002,
            20260726000003,
        ],
        "SQLx must apply the missing lower preflight even after v4 is installed"
    );
    let frozen_checksum_after: Vec<u8> = sqlx::query_scalar(
        "SELECT checksum FROM public._sqlx_migrations WHERE version=20260726000001",
    )
    .fetch_one(&pool)
    .await
    .expect("re-read frozen-v4 checksum");
    assert_eq!(
        frozen_checksum_after, frozen_checksum_before,
        "bridge application must not replace or rewrite the frozen-v4 ledger row"
    );
    assert_welcome_disposition_trigger_catalog(&pool, true, true, "bridged SQLx ledger").await;
}

async fn corrupt_history_to_zero_candidates(pool: &PgPool, welcome_id: Uuid) {
    let mut tx = pool.begin().await.expect("begin zero-candidate corruption");
    for trigger in [
        "welcome_dispositions_immutable",
        "welcome_dispositions_delivery_cas_deferred",
        "welcome_dispositions_recovery_work_deferred",
    ] {
        sqlx::query(&format!(
            "ALTER TABLE chat.welcome_dispositions DISABLE TRIGGER {trigger}"
        ))
        .execute(&mut *tx)
        .await
        .unwrap_or_else(|error| panic!("disable scratch trigger {trigger}: {error}"));
    }
    sqlx::query(
        "UPDATE chat.welcome_dispositions \
            SET terminal_at=terminal_at+interval '1 millisecond' \
          WHERE welcome_id=$1",
    )
    .bind(welcome_id)
    .execute(&mut *tx)
    .await
    .expect("move historical terminal instant off every source");
    for trigger in [
        "welcome_dispositions_recovery_work_deferred",
        "welcome_dispositions_delivery_cas_deferred",
        "welcome_dispositions_immutable",
    ] {
        sqlx::query(&format!(
            "ALTER TABLE chat.welcome_dispositions ENABLE TRIGGER {trigger}"
        ))
        .execute(&mut *tx)
        .await
        .unwrap_or_else(|error| panic!("restore scratch trigger {trigger}: {error}"));
    }
    tx.commit()
        .await
        .expect("commit tightly scoped zero-candidate history");
}

async fn clone_transition_candidate(pool: &PgPool, source_id: Uuid) {
    let clone_id = Uuid::new_v4();
    let clone_entry_id = Uuid::new_v4();
    let clone_entry_seq: i64 = sqlx::query_scalar(
        "SELECT max(seq)+1 FROM chat.entries \
          WHERE conversation_id=(SELECT conversation_id FROM chat.transitions WHERE transition_id=$1)",
    )
    .bind(source_id)
    .fetch_one(pool)
    .await
    .expect("allocate scratch duplicate-transition entry seq");
    let mut tx = pool
        .begin()
        .await
        .expect("begin duplicate transition candidate");
    for trigger in [
        "transitions_entry_mapping_deferred",
        "transitions_state_outputs_deferred",
        "transitions_metadata_mapping_deferred",
    ] {
        sqlx::query(&format!(
            "ALTER TABLE chat.transitions DISABLE TRIGGER {trigger}"
        ))
        .execute(&mut *tx)
        .await
        .unwrap_or_else(|error| panic!("disable scratch trigger {trigger}: {error}"));
    }
    for trigger in [
        "entries_transition_mapping_deferred",
        "entries_control_request_mapping_deferred",
        "entries_message_mapping_deferred",
        "entries_contiguity_deferred",
    ] {
        sqlx::query(&format!(
            "ALTER TABLE chat.entries DISABLE TRIGGER {trigger}"
        ))
        .execute(&mut *tx)
        .await
        .unwrap_or_else(|error| panic!("disable scratch trigger {trigger}: {error}"));
    }
    sqlx::query(
        r#"
        INSERT INTO chat.entries
        SELECT (
            jsonb_populate_record(
                NULL::chat.entries,
                to_jsonb(source_row)
                    || jsonb_build_object(
                        'seq', $3,
                        'entry_id', $4::text,
                        'transition_id', $2::text
                    )
            )
        ).*
          FROM chat.entries source_row
         WHERE source_row.transition_id=$1
        "#,
    )
    .bind(source_id)
    .bind(clone_id)
    .bind(clone_entry_seq)
    .bind(clone_entry_id)
    .execute(&mut *tx)
    .await
    .expect("insert matching entry for second transition candidate");
    sqlx::query(
        r#"
        INSERT INTO chat.transitions
        SELECT (
            jsonb_populate_record(
                NULL::chat.transitions,
                to_jsonb(source_row)
                    || jsonb_build_object(
                        'transition_id', $2::text,
                        'metadata_snapshot_id', NULL,
                        'entry_seq', $3
                    )
            )
        ).*
          FROM chat.transitions source_row
         WHERE source_row.transition_id=$1
        "#,
    )
    .bind(source_id)
    .bind(clone_id)
    .bind(clone_entry_seq)
    .execute(&mut *tx)
    .await
    .expect("insert second transition candidate");
    tx.commit()
        .await
        .expect("commit tightly scoped duplicate transition candidate");
    // Re-enable in a separate transaction: PostgreSQL correctly rejects ALTER
    // TABLE while the inserting transaction still has pending deferred events.
    // This scratch-only gap has no intervening writes and never weakens a
    // production schema.
    let mut restore = pool
        .begin()
        .await
        .expect("begin transition trigger restore");
    for trigger in [
        "entries_contiguity_deferred",
        "entries_message_mapping_deferred",
        "entries_control_request_mapping_deferred",
        "entries_transition_mapping_deferred",
    ] {
        sqlx::query(&format!(
            "ALTER TABLE chat.entries ENABLE TRIGGER {trigger}"
        ))
        .execute(&mut *restore)
        .await
        .unwrap_or_else(|error| panic!("restore scratch trigger {trigger}: {error}"));
    }
    for trigger in [
        "transitions_metadata_mapping_deferred",
        "transitions_state_outputs_deferred",
        "transitions_entry_mapping_deferred",
    ] {
        sqlx::query(&format!(
            "ALTER TABLE chat.transitions ENABLE TRIGGER {trigger}"
        ))
        .execute(&mut *restore)
        .await
        .unwrap_or_else(|error| panic!("restore scratch trigger {trigger}: {error}"));
    }
    restore
        .commit()
        .await
        .expect("commit transition trigger restoration");
}

async fn clone_revocation_candidate(pool: &PgPool, source_id: Uuid) {
    let clone_id = Uuid::new_v4();
    let mut tx = pool
        .begin()
        .await
        .expect("begin duplicate revocation candidate");
    sqlx::query(
        "ALTER TABLE chat.device_revocations \
         DROP CONSTRAINT device_revocations_one_per_target_uq",
    )
    .execute(&mut *tx)
    .await
    .expect("remove scratch-only one-per-target uniqueness");
    sqlx::query(
        "ALTER TABLE chat.device_revocations \
         DISABLE TRIGGER device_revocations_mapping_deferred",
    )
    .execute(&mut *tx)
    .await
    .expect("disable scratch revocation mapping");
    sqlx::query(
        r#"
        INSERT INTO chat.device_revocations
        SELECT (
            jsonb_populate_record(
                NULL::chat.device_revocations,
                to_jsonb(source_row)
                    || jsonb_build_object('revocation_id', $2::text)
            )
        ).*
          FROM chat.device_revocations source_row
         WHERE source_row.revocation_id=$1
        "#,
    )
    .bind(source_id)
    .bind(clone_id)
    .execute(&mut *tx)
    .await
    .expect("insert second revocation candidate");
    sqlx::query(
        "ALTER TABLE chat.device_revocations \
         ENABLE TRIGGER device_revocations_mapping_deferred",
    )
    .execute(&mut *tx)
    .await
    .expect("restore scratch revocation mapping");
    tx.commit()
        .await
        .expect("commit tightly scoped duplicate revocation candidate");
}

async fn insert_simultaneous_revocation_candidate(pool: &PgPool, history: &PreV4WelcomeHistory) {
    let actor_key_id: String = sqlx::query_scalar(
        "SELECT key_id FROM chat.device_keys WHERE user_did=$1 AND device_id=$2",
    )
    .bind(&history.recipient_did)
    .bind(history.recipient_device_id)
    .fetch_one(pool)
    .await
    .expect("load Welcome recipient key");
    let transcript = vec![0xA1_u8; 8];
    let digest = Sha256::digest(&transcript).to_vec();
    let mut tx = pool.begin().await.expect("begin simultaneous candidate");
    sqlx::query(
        "ALTER TABLE chat.device_revocations \
         DISABLE TRIGGER device_revocations_mapping_deferred",
    )
    .execute(&mut *tx)
    .await
    .expect("disable scratch revocation mapping");
    sqlx::query(
        r#"
        INSERT INTO chat.device_revocations(
            revocation_id,actor_did,actor_device_id,actor_key_id,
            actor_auth_generation,target_did,target_device_id,
            target_auth_generation,accepted_request_bytes,
            signing_transcript_bytes,request_digest,signature,signed_at,accepted_at
        ) VALUES($1,$2,$3,$4,1,$2,$3,1,$5,$6,$7,$8,$9,$9)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(&history.recipient_did)
    .bind(history.recipient_device_id)
    .bind(actor_key_id)
    .bind(vec![0xA2_u8; 8])
    .bind(&transcript)
    .bind(&digest)
    .bind(vec![0xA3_u8; 64])
    .bind(history.terminal_at)
    .execute(&mut *tx)
    .await
    .expect("insert exact-recipient simultaneous revocation candidate");
    sqlx::query(
        "ALTER TABLE chat.device_revocations \
         ENABLE TRIGGER device_revocations_mapping_deferred",
    )
    .execute(&mut *tx)
    .await
    .expect("restore scratch revocation mapping");
    tx.commit()
        .await
        .expect("commit tightly scoped simultaneous candidate");
}

#[tokio::test]
async fn populated_pre_v4_upgrade_backfills_unique_transition_source() {
    let (pool, _guard, history) = prepare_transition_supersession_history().await;
    apply_welcome_provenance_bridge(&pool).await;
    let sources: (Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        "SELECT terminal_transition_id,terminal_revocation_id \
           FROM chat.welcome_dispositions WHERE welcome_id=$1",
    )
    .bind(history.welcome_id)
    .fetch_one(&pool)
    .await
    .expect("read transition backfill");
    assert_eq!(sources, (Some(history.source_id), None));
}

#[tokio::test]
async fn populated_pre_v4_upgrade_backfills_unique_revocation_source() {
    let (pool, _guard, history) = prepare_revocation_supersession_history().await;
    apply_welcome_provenance_bridge(&pool).await;
    let sources: (Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        "SELECT terminal_transition_id,terminal_revocation_id \
           FROM chat.welcome_dispositions WHERE welcome_id=$1",
    )
    .bind(history.welcome_id)
    .fetch_one(&pool)
    .await
    .expect("read revocation backfill");
    assert_eq!(sources, (None, Some(history.source_id)));
}

#[tokio::test]
async fn populated_pre_v4_upgrade_zero_candidates_aborts_atomically() {
    let (pool, _guard, history) = prepare_transition_supersession_history().await;
    corrupt_history_to_zero_candidates(&pool, history.welcome_id).await;
    assert_failed_frozen_upgrade_is_atomic(&pool, "zero combined candidates").await;
}

#[tokio::test]
async fn populated_pre_v4_upgrade_multiple_transition_candidates_aborts_atomically() {
    let (pool, _guard, history) = prepare_transition_supersession_history().await;
    clone_transition_candidate(&pool, history.source_id).await;
    assert_failed_frozen_upgrade_is_atomic(&pool, "multiple transition candidates").await;
}

#[tokio::test]
async fn populated_pre_v4_upgrade_multiple_revocation_candidates_aborts_atomically() {
    let (pool, _guard, history) = prepare_revocation_supersession_history().await;
    clone_revocation_candidate(&pool, history.source_id).await;
    assert_failed_frozen_upgrade_is_atomic(&pool, "multiple revocation candidates").await;
}

#[tokio::test]
async fn populated_pre_v4_upgrade_simultaneous_source_kinds_abort_atomically() {
    let (pool, _guard, history) = prepare_transition_supersession_history().await;
    insert_simultaneous_revocation_candidate(&pool, &history).await;
    assert_failed_frozen_upgrade_is_atomic(
        &pool,
        "simultaneous transition and revocation candidates",
    )
    .await;
}

#[tokio::test]
async fn device_revocation_without_receipt_fails_the_commit_trigger() {
    let (pool, _db) = setup().await;
    let s = setup_revoked_target(&pool).await;

    // Apply the whole batch but DO NOT seed the revokeDevice receipt: the writers
    // all succeed (the mapping trigger is DEFERRED), but COMMIT RAISEs because the
    // target-footprint provenance (the receipt) is missing.
    let mut tx = pool.begin().await.expect("begin revocation");
    apply_device_revocation_batch_unscoped_for_test(
        &mut tx,
        &s.batch_plan,
        std::slice::from_ref(&s.conv_ctx),
    )
    .await
    .expect("batch applies (the mapping trigger is deferred to COMMIT)");
    let committed = tx.commit().await;
    assert!(
        committed.is_err(),
        "a revocation missing its revokeDevice receipt must fail enforce_device_revocation_mapping at COMMIT"
    );
}

// ===========================================================================
// E3 — real-Postgres concurrency races over the executor edges.
//
// Each case commits a coherent prior state, then applies competing edges from
// ONE prior coordinate CONCURRENTLY: two `apply_conversation_persistence_plan_unscoped_for_test`
// futures interleave under `tokio::join!` (a Barrier lines them up at the head
// write), and the Postgres conversation-head row lock is the serialization
// authority. Exactly one edge commits; every loser hits a typed executor error
// (the head CAS / head-PK conflict) and rolls back with ZERO business residue —
// equivalent to one legal lock-ordered serialization, never an impossible
// interleaving.
// ===========================================================================

/// Build (but do not apply) a real policy `addParticipant` edge on top of a
/// committed creation `fixture`, returning its plan + execution context. Mirrors
/// `group_policy_add_participant_commits_state_version_plus_one`.
async fn build_policy_edge(
    pool: &PgPool,
    fixture: &CreationApply,
    state: &chat_protocol::state_machine::ConversationState,
    seq: u64,
) -> (
    chat_protocol::state_machine::ConversationPersistencePlan,
    ExecutionContext,
) {
    let conversation_id = fixture.conversation_id;
    let (bob2_id, bob2_did) = fresh_bob();
    let bob2_device = Uuid::from_bytes(*bob2_id.device_id());
    let _ = seed_actor(pool, &bob2_did, bob2_device, &[0x63_u8; 32]).await;

    // A receivedAt strictly after any prior edge at a lower seq (so an edge that
    // follows a committed reset request at seq 2 is monotonically later).
    let received_at = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + (seq as i64) * 1_000 + 2_000,
    )
    .unwrap();
    let entry_id = Uuid::new_v4();
    let transition_id = Uuid::new_v4();
    let policy_evidence = TransitionEvidence::for_test_policy_add(
        seq,
        *transition_id.as_bytes(),
        [0x12_u8; 32],
        received_at,
        fixture.coordinate,
        vec![bob2_id.principal().clone()],
    )
    .unwrap();
    let planned = plan_policy(
        state,
        fixture.alice_id.clone(),
        policy_evidence,
        [0x99_u8; 32],
    )
    .expect("valid policy plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        seq,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let applied_at = clock_now(pool).await;
    let payload = vec![0x51_u8; 12];
    let transcript = vec![0x52_u8; 12];
    let recipients_devices = [
        (fixture.alice_id.clone(), fixture.alice_did.clone()),
        (fixture.bob_id.clone(), fixture.bob_did.clone()),
        (bob2_id.clone(), bob2_did.clone()),
    ];
    let mut sorted = recipients_devices.to_vec();
    sorted
        .sort_by(|l, r| (l.1.as_bytes(), l.0.device_id()).cmp(&(r.1.as_bytes(), r.0.device_id())));
    let entry_recipients = sorted
        .iter()
        .map(|(d, _)| (d.clone(), EntryEntitlementKind::Control))
        .collect();
    let mut event_recips = Vec::new();
    for (device, did) in &sorted {
        let predecessor: Option<i64> = sqlx::query_scalar(
            "SELECT max(event_position) FROM chat.event_recipients WHERE user_did=$1 AND device_id=$2",
        )
        .bind(did)
        .bind(Uuid::from_bytes(*device.device_id()))
        .fetch_one(pool)
        .await
        .expect("predecessor");
        event_recips.push((
            device.clone(),
            EventEntitlementKind::Participant,
            predecessor,
        ));
    }
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#policyEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x53_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0x54_u8; 64],
            server_fields_bytes: vec![0x55_u8; 8],
            outer_entry_fingerprint: vec![0x12_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0x61_u8; 16],
            public_snapshot_sha256: Sha256::digest([0x61_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0x62_u8; 16],
            tree_summary_sha256: Sha256::digest([0x62_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![Uuid::new_v4()],
        leaf_period_ids: vec![],
        entry_recipients,
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x71_u8; 8],
            recipients: event_recips,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: Vec::new(),
        closing_participant_periods: Vec::new(),
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    (plan, ctx)
}

/// Build (but do not apply) a real `closeConversation` edge on top of a committed
/// creation `fixture`. Mirrors `direct_close_commits_terminal_graph_and_reapply_conflicts`.
async fn build_close_edge(
    pool: &PgPool,
    fixture: &CreationApply,
) -> (
    chat_protocol::state_machine::ConversationPersistencePlan,
    ExecutionContext,
) {
    let conversation_id = fixture.conversation_id;
    let leaf_period_id: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(pool)
    .await
    .expect("genesis leaf period");
    let received_at = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 3_000,
    )
    .unwrap();
    let entry_id = Uuid::new_v4();
    let transition_id = Uuid::new_v4();
    let close_evidence =
        TransitionEvidence::for_test_at(2, *transition_id.as_bytes(), [0x13_u8; 32], received_at)
            .unwrap();
    let planned = plan_close(
        &fixture.state,
        CloseConversation {
            actor: fixture.alice_id.clone(),
            transition: close_evidence,
        },
    )
    .expect("valid close plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        2,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);
    let applied_at = clock_now(pool).await;
    let alice_pred = device_event_predecessor(pool, &fixture.alice_did, fixture.alice_device).await;
    let ctx = close_ctx(fixture, entry_id, applied_at, leaf_period_id, alice_pred);
    (plan, ctx)
}

/// Two operations from ONE prior coordinate: the SAME committed-creation
/// conversation is advanced by the SAME policy edge from two transactions at once.
/// Exactly one commits (`stateVersion` 0 -> 1); the loser's head CAS matches no row
/// and is a typed `ExecutorError::Transition`, rolling back with zero residue — the
/// state advances exactly once and exactly one policy transition exists.
#[tokio::test]
async fn concurrent_edge_apply_from_one_coordinate_yields_one_commit() {
    let (pool, _db) = setup().await;
    let fixture = build_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    let mut tx = pool.begin().await.expect("begin creation");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &fixture.plan, &fixture.ctx)
        .await
        .expect("creation applies");
    tx.commit().await.expect("creation COMMIT");

    let (plan, ctx) = build_policy_edge(&pool, &fixture, &fixture.state, 2).await;

    let barrier = Barrier::new(2);
    let racer_a = async {
        let mut tx = pool.begin().await.expect("begin A");
        barrier.wait().await;
        let result =
            apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx).await;
        let ok = result.is_ok();
        if ok {
            tx.commit().await.expect("A commit");
        } else {
            tx.rollback().await.expect("A rollback");
            assert!(
                matches!(result, Err(ExecutorError::Transition(_))),
                "loser is a typed transition conflict, got {result:?}"
            );
        }
        ok
    };
    let racer_b = async {
        let mut tx = pool.begin().await.expect("begin B");
        barrier.wait().await;
        let result =
            apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx).await;
        let ok = result.is_ok();
        if ok {
            tx.commit().await.expect("B commit");
        } else {
            tx.rollback().await.expect("B rollback");
            assert!(
                matches!(result, Err(ExecutorError::Transition(_))),
                "loser is a typed transition conflict, got {result:?}"
            );
        }
        ok
    };
    let (a, b) = tokio::join!(racer_a, racer_b);
    assert!(
        a ^ b,
        "exactly one policy edge commits from the shared coordinate"
    );

    let (sv, next_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((sv, next_seq), (1, 3), "state advanced exactly once");
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.transitions WHERE conversation_id=$1 AND kind='policy'",
            conversation_id
        )
        .await,
        1,
        "exactly one policy transition — the loser left zero residue"
    );
}

/// Seed an entry-less `replace` leaf-recovery request by the creator alice against
/// a committed creation `fixture` (coordinate + seq UNCHANGED, reserving her key
/// package), returning the resulting in-memory state + the request id + package ref
/// so a following coordinate-advancing edge can supersede it. Mirrors
/// `setup_revoked_target`'s request-seed block.
async fn seed_alice_open_recovery(
    pool: &PgPool,
    fixture: &CreationApply,
) -> (
    chat_protocol::state_machine::ConversationState,
    Uuid,
    [u8; 32],
) {
    let conversation_id = fixture.conversation_id;
    let alice_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2 AND active",
    )
    .bind(conversation_id)
    .bind(&fixture.alice_did)
    .fetch_one(pool)
    .await
    .expect("alice leaf period");
    let rec_ref = random_ref32();
    let pkg_not_after = seed_key_package(
        pool,
        &fixture.alice_did,
        fixture.alice_device,
        &fixture.alice_key_id,
        &rec_ref,
    )
    .await;
    let pkg_not_after_ts =
        ServerTimestamp::from_unix_millis_for_test(pkg_not_after.timestamp_millis()).unwrap();
    // Eval-based so the request precedes the eval-based coordinate-advancing edge
    // that supersedes it (the Superseded arm of validate_recovery_work requires
    // `transition.received_at >= request.received_at`); a clock-based (real-now)
    // request would sort AFTER the eval-based (2023) edge and fail that check.
    let rec_received = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 2_000,
    )
    .unwrap();
    let recovery_request_id = Uuid::new_v4();
    let rec_evidence = RequestEvidence::for_test(
        RequestEntryKind::LeafRecoveryRequest,
        2,
        *recovery_request_id.as_bytes(),
        fixture.alice_id.clone(),
        *conversation_id.as_bytes(),
        rec_received,
        0x71,
    )
    .unwrap();
    let rec_planned = plan_leaf_recovery_request(
        &fixture.state,
        LeafRecoveryRequestCommand {
            actor: fixture.alice_id.clone(),
            recovery_request_id: *recovery_request_id.as_bytes(),
            kind: LeafRecoveryKind::Replace,
            key_package_ref: rec_ref,
            received_at: rec_received,
            package_not_after: pkg_not_after_ts,
            evidence: rec_evidence,
        },
    )
    .expect("valid leaf recovery request plan");
    let rr_state = rec_planned.resulting_state().clone();
    let rec_head = ConversationHeadCasBinding::for_test_internal(
        *conversation_id.as_bytes(),
        fixture.coordinate,
        2,
        rec_received,
    );
    let rec_plan = persistence_plan_for_test(rec_planned, rec_head);
    let rec_applied_at = clock_now(pool).await;
    let rec_transcript = vec![0x72_u8; 16];
    let alice_pred = device_event_predecessor(pool, &fixture.alice_did, fixture.alice_device).await;
    let rec_ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at: rec_applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
            accepted_payload_bytes: vec![0x73_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x73_u8; 8]).to_vec(),
            signed_request_bytes: rec_transcript.clone(),
            unsigned_projection_bytes: vec![0x74_u8; 8],
            signing_transcript_bytes: rec_transcript.clone(),
            request_digest: Sha256::digest(&rec_transcript).to_vec(),
            signature: vec![0x75_u8; 64],
            server_fields_bytes: vec![0x76_u8; 8],
            outer_entry_fingerprint: vec![0x17_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x77_u8; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: Some(RecoveryOpenContext {
            participant_period_id: None,
            package_not_after: pkg_not_after,
            replaced_leaf_period_id: Some(alice_leaf_period),
        }),
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    let mut tx = pool.begin().await.expect("begin recovery request");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &rec_plan, &rec_ctx)
        .await
        .expect("leaf recovery request applies");
    tx.commit().await.expect("leaf recovery request COMMIT");
    (rr_state, recovery_request_id, rec_ref)
}

/// Concern-2 completeness: a policy `addParticipant` executed from a coordinate
/// carrying a DIFFERENT member's OPEN leaf-recovery request no longer hard-errors —
/// it supersedes the request / releases its reservation / reactivates its package
/// through the same shared writers the commit/close arms use, while adding the new
/// participant. Before the fix, `apply_policy`'s `reject_if_present` on the recovery
/// families made this a hard `UnsupportedEffect`.
#[tokio::test]
async fn policy_add_supersedes_prior_open_recovery_request() {
    let (pool, _db) = setup().await;
    let fixture = build_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    let mut tx = pool.begin().await.expect("begin creation");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &fixture.plan, &fixture.ctx)
        .await
        .expect("creation applies");
    tx.commit().await.expect("creation COMMIT");

    let (rr_state, recovery_request_id, rec_ref) = seed_alice_open_recovery(&pool, &fixture).await;
    let (plan, ctx) = build_policy_edge(&pool, &fixture, &rr_state, 2).await;

    let mut tx = pool.begin().await.expect("begin policy");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("policy add over a co-open recovery request applies");
    tx.commit()
        .await
        .expect("policy COMMIT past all deferred triggers");

    // The other member's recovery work is superseded / released / reactivated.
    let (rec_status, res_status, pkg_status): (String, String, String) = sqlx::query_as(
        "SELECT (SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1), \
                (SELECT status FROM chat.key_package_reservations WHERE recovery_request_id=$1), \
                (SELECT status FROM chat.key_packages WHERE key_package_ref=$2)",
    )
    .bind(recovery_request_id)
    .bind(rec_ref.to_vec())
    .fetch_one(&pool)
    .await
    .expect("superseded recovery state");
    assert_eq!(
        (
            rec_status.as_str(),
            res_status.as_str(),
            pkg_status.as_str()
        ),
        ("superseded", "released", "available")
    );
    // The policy still advanced the coordinate + added the participant.
    let (sv, participants): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT current_state_version FROM chat.conversations WHERE conversation_id=$1), \
                (SELECT count(*) FROM chat.participants WHERE conversation_id=$1 AND current_membership)",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head + participants");
    assert_eq!(sv, 1, "policy advanced the coordinate");
    assert_eq!(participants, 3, "policy added the third participant");
}

/// The recovery-family silent-drop guard is load-bearing for `apply_policy` too: a
/// policy plan carrying an extra recovery-request delta that is NOT a supersession
/// (an injected `Open->Expired`) is a hard `InconsistentPlan` with zero residue.
#[tokio::test]
async fn policy_untracked_recovery_delta_is_rejected() {
    let (pool, _db) = setup().await;
    let fixture = build_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    let mut tx = pool.begin().await.expect("begin creation");
    apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &fixture.plan, &fixture.ctx)
        .await
        .expect("creation applies");
    tx.commit().await.expect("creation COMMIT");

    let (rr_state, _rid, _ref) = seed_alice_open_recovery(&pool, &fixture).await;
    let (plan, ctx) = build_policy_edge(&pool, &fixture, &rr_state, 2).await;
    let bad = plan.with_extra_untracked_recovery_request_for_test();
    let mut tx = pool.begin().await.expect("begin policy");
    let result = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &bad, &ctx).await;
    assert!(
        matches!(result, Err(ExecutorError::InconsistentPlan(_))),
        "an untracked policy recovery delta must be InconsistentPlan, got {result:?}"
    );
    tx.rollback().await.expect("rollback");
    let sv: i64 = sqlx::query_scalar(
        "SELECT current_state_version FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!(sv, 0, "a rejected policy left zero residue");
}

/// Close serializes against a competing head mutation from ONE prior coordinate:
/// two transactions apply the same `closeConversation` edge to a DIRECT
/// conversation at once. Exactly one commits (head -> `superseded` with the close
/// coordinate); the loser's head CAS matches no unsuperseded row and is a typed
/// `ExecutorError::Transition`, rolling back with zero residue — exactly one close
/// transition, and no second head mutation is admitted after the head is closed.
#[tokio::test]
async fn concurrent_close_apply_yields_one_supersede_zero_residue() {
    let (pool, _db) = setup().await;
    let fixture = commit_creation(&pool, ConversationKind::Direct).await;
    let conversation_id = fixture.conversation_id;

    let (close_plan, close_ctx) = build_close_edge(&pool, &fixture).await;

    let barrier = Barrier::new(2);
    let racer_a = async {
        let mut tx = pool.begin().await.expect("begin A");
        barrier.wait().await;
        let result =
            apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &close_plan, &close_ctx)
                .await;
        let ok = result.is_ok();
        if ok {
            tx.commit().await.expect("A commit");
        } else {
            tx.rollback().await.expect("A rollback");
            assert!(
                matches!(result, Err(ExecutorError::Transition(_))),
                "loser is a typed transition conflict, got {result:?}"
            );
        }
        ok
    };
    let racer_b = async {
        let mut tx = pool.begin().await.expect("begin B");
        barrier.wait().await;
        let result =
            apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &close_plan, &close_ctx)
                .await;
        let ok = result.is_ok();
        if ok {
            tx.commit().await.expect("B commit");
        } else {
            tx.rollback().await.expect("B rollback");
            assert!(
                matches!(result, Err(ExecutorError::Transition(_))),
                "loser is a typed transition conflict, got {result:?}"
            );
        }
        ok
    };
    let (a, b) = tokio::join!(racer_a, racer_b);
    assert!(a ^ b, "exactly one close commits");

    let lifecycle: String =
        sqlx::query_scalar("SELECT lifecycle FROM chat.conversations WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .expect("lifecycle");
    assert_eq!(
        lifecycle, "superseded",
        "the close winner supersedes the head"
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM chat.transitions WHERE conversation_id=$1 AND kind='closeConversation'", conversation_id).await,
        1,
        "exactly one close transition — the loser left zero residue",
    );
}

/// Two concurrent applies of the SAME creation plan: exactly one commits the head
/// insert; the other collides on the conversation-head primary key and rolls back
/// with zero residue. Exactly one conversation, one creation transition, and one
/// creation entry exist afterwards.
#[tokio::test]
async fn concurrent_duplicate_creation_yields_one_commit() {
    let (pool, _db) = setup().await;
    let fixture = build_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;

    let barrier = Barrier::new(2);
    let racer_a = async {
        let mut tx = pool.begin().await.expect("begin A");
        barrier.wait().await;
        let result = apply_conversation_persistence_plan_unscoped_for_test(
            &mut tx,
            &fixture.plan,
            &fixture.ctx,
        )
        .await;
        let ok = result.is_ok();
        if ok {
            tx.commit().await.expect("A commit");
        } else {
            tx.rollback().await.expect("A rollback");
        }
        ok
    };
    let racer_b = async {
        let mut tx = pool.begin().await.expect("begin B");
        barrier.wait().await;
        let result = apply_conversation_persistence_plan_unscoped_for_test(
            &mut tx,
            &fixture.plan,
            &fixture.ctx,
        )
        .await;
        let ok = result.is_ok();
        if ok {
            tx.commit().await.expect("B commit");
        } else {
            tx.rollback().await.expect("B rollback");
        }
        ok
    };
    let (a, b) = tokio::join!(racer_a, racer_b);
    assert!(a ^ b, "exactly one creation commits");

    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.conversations WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        1,
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.transitions WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        1,
        "one creation transition — the loser left zero residue",
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.entries WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        1,
        "one creation entry — the loser left zero residue",
    );
}

/// Build (but do not apply) a real reset ACTIVATION edge on top of a committed
/// creation `fixture`: commits the non-mutating reset request at seq 2, then
/// constructs the activation plan/ctx that retires generation 0 and forms
/// generation 1 at seq 3. Mirrors
/// `reset_activation_commits_two_generation_graph_and_conflicts_on_replay`.
async fn build_reset_activation_edge(
    pool: &PgPool,
    fixture: &CreationApply,
) -> (
    chat_protocol::state_machine::ConversationPersistencePlan,
    ExecutionContext,
    Uuid,
) {
    let conversation_id = fixture.conversation_id;
    let manifest = corpus_manifest();
    let req_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 3_000,
    )
    .unwrap();
    let (reset_state, request_id) = commit_reset_request(pool, fixture, 2, req_received).await;

    let old_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND generation=0",
    )
    .bind(conversation_id)
    .fetch_one(pool)
    .await
    .expect("old leaf period");
    let participant_rows: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT user_did,participant_period_id FROM chat.participants WHERE conversation_id=$1 AND current_membership",
    )
    .bind(conversation_id)
    .fetch_all(pool)
    .await
    .expect("participant periods");

    let successor_coordinate = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        fixture.coordinate.generation() + 1,
        0,
        [0x71; 32],
        0,
        [0x72; 32],
        [0x73; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    let successor_public_state =
        ActivePublicState::for_test(&verified_genesis(&manifest), successor_coordinate);
    let retired_coordinate = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        fixture.coordinate.generation(),
        fixture.coordinate.state_version() + 1,
        *fixture.coordinate.group_id(),
        fixture.coordinate.epoch(),
        *fixture.coordinate.group_context_hash(),
        *fixture.coordinate.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Superseded,
    );

    let act_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 4_000,
    )
    .unwrap();
    let transition_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    let alice_sig_key: Vec<u8> =
        hex::decode(&manifest.identity.alice.signature_public_key_hex).unwrap();
    let nonce = [0x78_u8; 12];
    let ciphertext = vec![0x79_u8; 48];
    let metadata = MetadataSnapshotBinding::for_test_creation(
        *conversation_id.as_bytes(),
        1,
        0,
        [0x72; 32],
        *transition_id.as_bytes(),
        3,
        fixture.alice_id.clone(),
        Sha256::digest(&alice_sig_key).into(),
        alice_sig_key.clone().try_into().unwrap(),
        1,
        2,
        nonce,
        ciphertext,
    );
    let evidence = TransitionEvidence::for_test_reset_activation_with_metadata(
        3,
        *transition_id.as_bytes(),
        [0x15_u8; 32],
        act_received,
        ConversationKind::Group,
        *request_id.as_bytes(),
        fixture.coordinate,
        retired_coordinate,
        successor_coordinate,
        fixture.alice_id.clone(),
        metadata,
    )
    .unwrap();
    let planned = plan_reset_activation(
        &reset_state,
        ResetActivation {
            actor: fixture.alice_id.clone(),
            reset_request_id: *request_id.as_bytes(),
            transition: evidence,
            successor_public_state,
        },
    )
    .expect("valid reset activation plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        3,
        act_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let mut sorted_participants = participant_rows.clone();
    sorted_participants.sort_by(|l, r| l.0.as_bytes().cmp(r.0.as_bytes()));
    let participant_period_ids: Vec<Uuid> = sorted_participants.iter().map(|(_, id)| *id).collect();

    let applied_at = clock_now(pool).await;
    let payload = vec![0x81_u8; 12];
    let transcript = vec![0x82_u8; 12];
    let pred = device_event_predecessor(pool, &fixture.alice_did, fixture.alice_device).await;
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#resetActivationEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x83_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0x84_u8; 64],
            server_fields_bytes: vec![0x85_u8; 8],
            outer_entry_fingerprint: vec![0x15_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0x91_u8; 16],
            public_snapshot_sha256: Sha256::digest([0x91_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0x92_u8; 16],
            tree_summary_sha256: Sha256::digest([0x92_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![0x93_u8; 16],
            genesis_group_info_sha256: Sha256::digest([0x93_u8; 16]).to_vec(),
        },
        opened_leaves: vec![LeafPersistenceColumns {
            device: fixture.alice_id.clone(),
            leaf_key_id: fixture.alice_key_id.clone(),
            leaf_auth_generation: 1,
        }],
        metadata_author: Some(MetadataAuthorColumns {
            author_role: "admin".to_owned(),
            author_device_status: "active".to_owned(),
            author_public_key: alice_sig_key,
            author_key_id: fixture.alice_key_id.clone(),
            metadata_snapshot_id: Uuid::new_v4(),
        }),
        participant_period_ids,
        leaf_period_ids: vec![Uuid::new_v4()],
        entry_recipients: vec![(
            fixture.alice_id.clone(),
            EntryEntitlementKind::IntervalClose,
        )],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x94_u8; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![(fixture.alice_id.clone(), old_leaf_period)],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    (plan, ctx, request_id)
}

/// Two reset ACTIVATIONS race from ONE prior coordinate: two transactions apply
/// the same activation edge (retire generation 0, form generation 1) at once.
/// Exactly one commits (head -> generation 1, the reset request `consumed`); the
/// loser's head CAS matches no row at the old coordinate and is a typed
/// `ExecutorError::Transition`, rolling back with zero residue — exactly one
/// activation transition and exactly one active generation-1 leaf.
#[tokio::test]
async fn concurrent_reset_activation_yields_one_commit_zero_residue() {
    let (pool, _db) = setup().await;
    let fixture = commit_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    let (plan, ctx, request_id) = build_reset_activation_edge(&pool, &fixture).await;

    let barrier = Barrier::new(2);
    let racer_a = async {
        let mut tx = pool.begin().await.expect("begin A");
        barrier.wait().await;
        let result =
            apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx).await;
        let ok = result.is_ok();
        if ok {
            tx.commit().await.expect("A commit");
        } else {
            tx.rollback().await.expect("A rollback");
            assert!(
                matches!(result, Err(ExecutorError::Transition(_))),
                "loser is a typed transition conflict, got {result:?}"
            );
        }
        ok
    };
    let racer_b = async {
        let mut tx = pool.begin().await.expect("begin B");
        barrier.wait().await;
        let result =
            apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx).await;
        let ok = result.is_ok();
        if ok {
            tx.commit().await.expect("B commit");
        } else {
            tx.rollback().await.expect("B rollback");
            assert!(
                matches!(result, Err(ExecutorError::Transition(_))),
                "loser is a typed transition conflict, got {result:?}"
            );
        }
        ok
    };
    let (a, b) = tokio::join!(racer_a, racer_b);
    assert!(a ^ b, "exactly one reset activation commits");

    let (gen, sv, lifecycle): (i64, i64, String) = sqlx::query_as(
        "SELECT current_generation,current_state_version,lifecycle FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!(
        (gen, sv, lifecycle.as_str()),
        (1, 0, "active"),
        "the successor generation is live exactly once"
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM chat.transitions WHERE conversation_id=$1 AND kind='resetActivation'", conversation_id).await,
        1,
        "exactly one activation transition — the loser left zero residue",
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM chat.member_devices WHERE conversation_id=$1 AND generation=1 AND active", conversation_id).await,
        1,
        "exactly one active generation-1 leaf",
    );
    let req_status: String =
        sqlx::query_scalar("SELECT status FROM chat.reset_requests WHERE reset_request_id=$1")
            .bind(request_id)
            .fetch_one(&pool)
            .await
            .expect("reset request status");
    assert_eq!(
        req_status, "consumed",
        "the winning activation consumed the request"
    );
}

/// Duplicate DIRECT creation returns the typed `existingDirectConversationResult`,
/// not a second conversation. `concurrent_duplicate_creation_yields_one_commit`
/// covers the raw head-PK collision for a group; this covers the planner's
/// dedicated direct-pair short-circuit: given an existing active direct
/// conversation for a pair, a fresh creation command for that SAME unordered pair
/// resolves to `CreationDecision::ExistingDirect` carrying the EXISTING
/// conversation's id + coordinate, with no new plan produced.
#[tokio::test]
async fn duplicate_direct_creation_returns_typed_existing_direct_result() {
    let (pool, _db) = setup().await;
    let fixture = build_creation(&pool, ConversationKind::Direct).await;
    let manifest = corpus_manifest();

    // A fresh creation command for the SAME (alice, bob) direct pair.
    let new_conversation = Uuid::new_v4();
    let template = verified_genesis(&manifest);
    let coordinate =
        coordinate_with_conversation(&genesis_coordinate(&manifest), *new_conversation.as_bytes());
    let public_state = ActivePublicState::for_test(&template, coordinate);
    let transition_id = Uuid::new_v4();
    let received_at = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 5_000,
    )
    .unwrap();
    let alice_sig_key: Vec<u8> =
        hex::decode(&manifest.identity.alice.signature_public_key_hex).unwrap();
    let alice_key_id_bytes: [u8; 32] = Sha256::digest(&alice_sig_key).into();
    let metadata = MetadataSnapshotBinding::for_test_creation(
        *new_conversation.as_bytes(),
        0,
        0,
        *coordinate.group_context_hash(),
        *transition_id.as_bytes(),
        1,
        fixture.alice_id.clone(),
        alice_key_id_bytes,
        alice_sig_key.clone().try_into().unwrap(),
        1,
        1,
        [0x77_u8; 12],
        vec![0x88_u8; 48],
    );
    let evidence = TransitionEvidence::for_test_creation_with_metadata(
        1,
        *transition_id.as_bytes(),
        [0x11_u8; 32],
        received_at,
        ConversationKind::Direct,
        coordinate,
        fixture.alice_id.clone(),
        metadata,
    )
    .unwrap();
    let command = CreationCommand {
        kind: ConversationKind::Direct,
        creator: fixture.alice_id.clone(),
        invitees: vec![fixture.bob_id.principal().clone()],
        transition: evidence,
        public_state,
    };

    // The existing direct state short-circuits: typed ExistingDirect, no new plan.
    let decision = plan_creation(Some(&fixture.state), command).expect("planner decides");
    match decision {
        CreationDecision::ExistingDirect {
            conversation_id, ..
        } => {
            assert_eq!(
                conversation_id,
                *fixture.conversation_id.as_bytes(),
                "existingDirectConversationResult points at the existing direct conversation",
            );
        }
        CreationDecision::Create(_) => {
            panic!("a duplicate direct pair must short-circuit to ExistingDirect, not Create")
        }
    }
}
