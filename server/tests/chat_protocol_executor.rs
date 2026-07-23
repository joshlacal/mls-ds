//! Live-PostgreSQL verification for the transition-executor spine writers added
//! in task E2b-2 (`repository::transition` conversation-head + generation
//! writers, and `repository::delivery::append_entry_at`).
//!
//! The executor itself (`state_machine::apply_conversation_persistence_plan`)
//! is gated `#[cfg(not(test))]` — like every `super::repository::*` consumer in
//! `state_machine.rs` — so it is not reachable through this `cfg(test)`
//! integration crate without also exposing the whole locked-guard plan-build
//! path; that end-to-end commit test is the E2b-2 remainder (see the report).
//! What IS verified here, green against the dedicated clean-chat database, is
//! every NEW dumb-SQL writer the executor composes: column fidelity on insert,
//! and compare-and-set advance/conflict semantics — each inside one transaction
//! with same-transaction read-back and ROLLBACK (the E2a/E2b-1 unit boundary;
//! the DEFERRED cross-table triggers fire only at COMMIT and are the composing
//! executor's responsibility).
//!
//! Run:
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_executor -- --test-threads=1

#![allow(dead_code)]

mod common;

mod repository {
    pub(crate) mod transition {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/transition.rs"
        ));
    }

    pub(crate) mod delivery {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/delivery.rs"
        ));
    }
}

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use repository::delivery::{append_entry_at, AppendEntry, DeliveryRepositoryError};
use repository::transition::{
    cas_conversation_head, cas_generation_state_version, insert_conversation_head,
    insert_generation, supersede_generation, ConversationHeadCas, ConversationHeadClose,
    ConversationHeadKind, GenerationStateVersionCas, GenerationSupersede, NewConversationHead,
    NewGeneration, TransitionRepositoryError,
};

async fn setup() -> PgPool {
    common::chat_protocol::setup_chat_protocol_db(4).await
}

async fn clock_now(pool: &PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .expect("sample trusted database clock")
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

/// Seed one principal + active device + device-key row **inside `tx`** so the
/// entry's immediate actor foreign keys resolve. Transaction-scoped so it rolls
/// back with the test (never leaks into the never-truncated shared database).
async fn seed_principal_device_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    at: DateTime<Utc>,
) -> (String, Uuid, String) {
    let user_did = random_plc_did();
    sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2)")
        .bind(&user_did)
        .bind(at)
        .execute(&mut **tx)
        .await
        .expect("insert principal");
    let device_id = Uuid::new_v4();
    let public_key = Uuid::new_v4()
        .as_bytes()
        .iter()
        .chain(Uuid::new_v4().as_bytes())
        .copied()
        .collect::<Vec<u8>>();
    let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&public_key)
        .fetch_one(&mut **tx)
        .await
        .expect("derive key id");
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'creator','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    )
    .bind(&user_did)
    .bind(device_id)
    .bind(&key_id)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("insert device");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
         VALUES($1,$2,$3,$4,1,$5)",
    )
    .bind(&user_did)
    .bind(device_id)
    .bind(&key_id)
    .bind(&public_key)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("insert device key");
    (user_did, device_id, key_id)
}

/// Insert one group head + gen-0 generation + gen-0 creation `generation_state`
/// inside `tx` so the deferred head/gen → state FKs are satisfiable and the
/// generation writers have a coherent row to advance. Returns the conversation id.
async fn seed_group_head_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    at: DateTime<Utc>,
) -> (Uuid, Vec<u8>) {
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
    (conversation_id, group_id)
}

#[tokio::test]
async fn conversation_head_insert_is_faithful_and_group_shaped() {
    let pool = setup().await;
    let mut tx = pool.begin().await.expect("begin");
    let at = clock_now(&pool).await;
    let conversation_id = Uuid::new_v4();
    insert_conversation_head(
        &mut tx,
        &NewConversationHead {
            conversation_id,
            kind: ConversationHeadKind::Group,
            current_generation: 0,
            current_state_version: 0,
            next_entry_seq: 2,
            created_at: at,
        },
    )
    .await
    .expect("insert group head");

    let (kind, lifecycle, gen, sv, next_seq, low, high): (
        String,
        String,
        i64,
        i64,
        i64,
        Option<String>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT kind,lifecycle,current_generation,current_state_version,next_entry_seq,direct_did_low,direct_did_high \
         FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&mut *tx)
    .await
    .expect("read head");
    assert_eq!(kind, "group");
    assert_eq!(lifecycle, "active");
    assert_eq!((gen, sv, next_seq), (0, 0, 2));
    assert_eq!((low, high), (None, None));
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn conversation_head_cas_advances_and_conflicts_on_drift() {
    let pool = setup().await;
    let mut tx = pool.begin().await.expect("begin");
    let at = clock_now(&pool).await;
    let (conversation_id, _group_id) = seed_group_head_tx(&mut tx, at).await;

    // A same-generation stateVersion+1 policy edge advances the head counter.
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

    let (sv, next_seq, lifecycle): (i64, i64, String) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq,lifecycle FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&mut *tx)
    .await
    .expect("read advanced head");
    assert_eq!((sv, next_seq, lifecycle.as_str()), (1, 3, "active"));

    // Re-applying the SAME expected prior now drifts (head already moved) — the
    // CAS matches zero rows and is a typed conflict, not a silent no-op.
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
async fn conversation_head_close_cas_supersedes_with_close_block() {
    let pool = setup().await;
    let mut tx = pool.begin().await.expect("begin");
    let at = clock_now(&pool).await;
    let (conversation_id, _group_id) = seed_group_head_tx(&mut tx, at).await;
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

    let (lifecycle, ct, closed): (String, Option<Uuid>, Option<DateTime<Utc>>) = sqlx::query_as(
        "SELECT lifecycle,close_transition_id,closed_at FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&mut *tx)
    .await
    .expect("read closed head");
    assert_eq!(lifecycle, "superseded");
    assert_eq!(ct, Some(close_transition_id));
    assert!(closed.is_some());
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn generation_insert_and_state_version_cas_are_faithful_and_guarded() {
    let pool = setup().await;
    let mut tx = pool.begin().await.expect("begin");
    let at = clock_now(&pool).await;
    let conversation_id = Uuid::new_v4();
    let group_id = vec![7_u8; 32];
    let group_info = vec![8_u8; 8];
    // Head first (generations FK -> conversations is immediate).
    insert_conversation_head(
        &mut tx,
        &NewConversationHead {
            conversation_id,
            kind: ConversationHeadKind::Group,
            current_generation: 0,
            current_state_version: 0,
            next_entry_seq: 2,
            created_at: at,
        },
    )
    .await
    .expect("head");
    insert_generation(
        &mut tx,
        &NewGeneration {
            conversation_id,
            generation: 0,
            group_id: group_id.clone(),
            genesis_group_info_bytes: group_info.clone(),
            genesis_group_info_sha256: Sha256::digest(&group_info).to_vec(),
            current_state_version: 0,
            activated_seq: 1,
            activated_at: at,
        },
    )
    .await
    .expect("insert generation");

    let (lifecycle, current_sv, activated_seq, stored_group): (String, i64, i64, Vec<u8>) =
        sqlx::query_as(
            "SELECT lifecycle,current_state_version,activated_seq,group_id FROM chat.generations WHERE conversation_id=$1 AND generation=0",
        )
        .bind(conversation_id)
        .fetch_one(&mut *tx)
        .await
        .expect("read generation");
    assert_eq!(
        (lifecycle.as_str(), current_sv, activated_seq),
        ("active", 0, 1)
    );
    assert_eq!(stored_group, group_id);

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
    .expect("advance generation pointer");
    let advanced: i64 = sqlx::query_scalar(
        "SELECT current_state_version FROM chat.generations WHERE conversation_id=$1 AND generation=0",
    )
    .bind(conversation_id)
    .fetch_one(&mut *tx)
    .await
    .expect("read advanced pointer");
    assert_eq!(advanced, 1);

    // Repeat with the stale expected pointer -> typed conflict.
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

    // Supersede from the current (advanced) pointer.
    supersede_generation(
        &mut tx,
        &GenerationSupersede {
            conversation_id,
            generation: 0,
            expected_state_version: 1,
            successor_state_version: 1,
            superseded_seq: 2,
            superseded_at: at,
        },
    )
    .await
    .expect("supersede generation");
    let (lifecycle, superseded_seq): (String, Option<i64>) = sqlx::query_as(
        "SELECT lifecycle,superseded_seq FROM chat.generations WHERE conversation_id=$1 AND generation=0",
    )
    .bind(conversation_id)
    .fetch_one(&mut *tx)
    .await
    .expect("read superseded generation");
    assert_eq!(lifecycle, "superseded");
    assert_eq!(superseded_seq, Some(2));
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn append_entry_at_inserts_at_exact_seq_without_touching_head() {
    let pool = setup().await;
    let mut tx = pool.begin().await.expect("begin");
    let at = clock_now(&pool).await;
    let (user_did, device_id, key_id) = seed_principal_device_tx(&mut tx, at).await;
    let conversation_id = Uuid::new_v4();
    // Head with next_entry_seq deliberately already advanced past the entry seq
    // (the executor's head write is the counter authority; append_entry_at only
    // materializes the row and must NOT re-advance the head).
    insert_conversation_head(
        &mut tx,
        &NewConversationHead {
            conversation_id,
            kind: ConversationHeadKind::Group,
            current_generation: 0,
            current_state_version: 0,
            next_entry_seq: 2,
            created_at: at,
        },
    )
    .await
    .expect("head");

    let payload = vec![21_u8; 8];
    let transcript = vec![22_u8; 8];
    let returned = append_entry_at(
        &mut tx,
        &AppendEntry {
            conversation_id,
            entry_id: Uuid::new_v4(),
            // A control entry carries the full closed Lexicon kind and a non-null
            // transition_id (its FK is DEFERRABLE INITIALLY DEFERRED, so a fresh
            // UUID is legal under this rollback-scoped read-back).
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

    let (stored_seq, stored_kind): (i64, String) =
        sqlx::query_as("SELECT seq,entry_kind FROM chat.entries WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&mut *tx)
            .await
            .expect("read entry");
    assert_eq!(
        (stored_seq, stored_kind.as_str()),
        (1, "blue.catbird.chat.defs#creationEntry")
    );

    // The head counter is untouched by append_entry_at.
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
