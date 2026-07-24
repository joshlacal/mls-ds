//! Live-PostgreSQL verification of the T4-H2-pre conversation-substrate
//! production hydrators (`chat_protocol::repository::core`).
//!
//! These exercise the REAL, production `#[cfg(not(test))]` guard-hydration path,
//! which no other suite compiles: the lib build gates `repository::core` behind
//! `#[cfg(not(test))]`, and the state-machine/executor harnesses use the
//! `for_test` guard constructors instead. So — like the executor harness — this
//! test `include!`s the whole `chat_protocol` module tree (so `core.rs`'s
//! `super::super::{snapshot,state_machine,validation}` paths resolve) and adds
//! `repository::core` on top.
//!
//! Live cases are `#[ignore]`d and run explicitly against the dedicated,
//! freshly-migrated gate database:
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_conversation_substrate -- --ignored --test-threads=1

#![allow(dead_code)]

mod common;

#[allow(dead_code)]
#[path = "../src/chat_protocol/model.rs"]
mod model;
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
    pub mod repository {
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

use std::time::Duration;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use chat_protocol::repository::core::{
    hydrate_locked_conversation_head, ConversationHeadHydrationError,
};
use chat_protocol::snapshot::PublicGroupSnapshotLifecycle;

// ---------------------------------------------------------------------------
// Harness (seeders adapted verbatim from tests/chat_protocol_concurrency.rs so a
// coherent committed GROUP conversation exists for the head hydrator to lock).
// ---------------------------------------------------------------------------

struct BaseConversation {
    conversation_id: Uuid,
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
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

async fn clock_now(pool: &PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .expect("sample trusted database clock")
}

/// The single canonical trusted request instant threaded to the head lock: a
/// whole-millisecond server timestamp (the guard rejects sub-millisecond values).
async fn clock_now_millis(pool: &PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
        .fetch_one(pool)
        .await
        .expect("sample whole-millisecond database clock")
}

async fn seed_actor(pool: &PgPool) -> (String, Uuid, String) {
    let actor_did = random_plc_did();
    let actor_device_id = Uuid::new_v4();
    let mut actor_public_key = Uuid::new_v4().as_bytes().to_vec();
    actor_public_key.extend_from_slice(Uuid::new_v4().as_bytes());
    let actor_key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&actor_public_key)
        .fetch_one(pool)
        .await
        .expect("derive actor key id");
    let at = clock_now(pool).await;
    sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2)")
        .bind(&actor_did)
        .bind(at)
        .execute(pool)
        .await
        .expect("insert principal");
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'substrate-actor','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    )
    .bind(&actor_did)
    .bind(actor_device_id)
    .bind(format!("{:042}A", 0_u128))
    .bind(at)
    .execute(pool)
    .await
    .expect("insert actor device");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
         VALUES($1,$2,$3,$4,1,$5)",
    )
    .bind(&actor_did)
    .bind(actor_device_id)
    .bind(&actor_key_id)
    .bind(&actor_public_key)
    .bind(at)
    .execute(pool)
    .await
    .expect("insert actor device key");
    (actor_did, actor_device_id, actor_key_id)
}

/// Seed a coherent committed GROUP conversation (genesis creation at seq 1,
/// generation 0 / state_version 0, `next_entry_seq` 2, lifecycle `active`).
async fn seed_base(pool: &PgPool) -> BaseConversation {
    let (actor_did, actor_device_id, actor_key_id) = seed_actor(pool).await;
    let actor_public_key: Vec<u8> =
        sqlx::query_scalar("SELECT signing_public_key FROM chat.device_keys WHERE key_id=$1")
            .bind(&actor_key_id)
            .fetch_one(pool)
            .await
            .expect("read actor public key");
    let conversation_id = commit_coherent_group_creation(
        pool,
        &actor_did,
        actor_device_id,
        &actor_key_id,
        &actor_public_key,
    )
    .await;
    BaseConversation {
        conversation_id,
        actor_did,
        actor_device_id,
        actor_key_id,
    }
}

async fn commit_coherent_group_creation(
    pool: &PgPool,
    principal: &str,
    actor_device_id: Uuid,
    actor_key_id: &str,
    actor_public_key: &[u8],
) -> Uuid {
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
    let basic_credential = format!("{principal}#{actor_device_id}").into_bytes();
    let accepted_at = clock_now(pool).await;

    let mut tx = pool.begin().await.expect("begin creation");
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
        r#"INSERT INTO chat.transitions(
            transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,
            actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,
            unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,
            next_generation,next_state_version,metadata_snapshot_id,entry_seq,accepted_at
        ) VALUES($1,$2,'creation',$3,$4,$5,1,'admin','active',$6,$7,$8,$9,$10,0,0,$11,1,$12)"#,
    )
    .bind(creation_transition_id)
    .bind(conversation_id)
    .bind(principal)
    .bind(actor_device_id)
    .bind(actor_key_id)
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
        r#"INSERT INTO chat.generation_states(
            conversation_id,generation,state_version,group_id,epoch,group_context_hash,
            confirmation_tag,lifecycle,state_kind,producing_transition_id,
            public_snapshot_bytes,snapshot_sha256,tree_summary_bytes,tree_summary_sha256,
            leaf_count,created_at
        ) VALUES($1,0,0,$2,0,$3,$4,'active','creation',$5,$6,$7,$8,$9,1,$10)"#,
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
        r#"INSERT INTO chat.participants(
            participant_period_id,conversation_id,user_did,status,role,role_transition_id,
            role_changed_at,created_by_did,created_by_device_id,current_membership,created_at
        ) VALUES($1,$2,$3,'active','admin',$4,$5,$3,$6,true,$5)"#,
    )
    .bind(participant_period_id)
    .bind(conversation_id)
    .bind(principal)
    .bind(creation_transition_id)
    .bind(accepted_at)
    .bind(actor_device_id)
    .execute(&mut *tx)
    .await
    .expect("insert participant");
    sqlx::query(
        r#"INSERT INTO chat.member_devices(
            leaf_period_id,participant_period_id,conversation_id,generation,user_did,
            device_id,leaf_index,basic_credential,leaf_signature_key,leaf_key_id,
            leaf_auth_generation,origin,joined_state_version,joined_transition_id,
            joined_seq,active,created_at
        ) VALUES($1,$2,$3,0,$4,$5,0,$6,$7,$8,1,'genesis',0,$9,1,true,$10)"#,
    )
    .bind(leaf_period_id)
    .bind(participant_period_id)
    .bind(conversation_id)
    .bind(principal)
    .bind(actor_device_id)
    .bind(&basic_credential)
    .bind(actor_public_key)
    .bind(actor_key_id)
    .bind(creation_transition_id)
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert leaf");
    sqlx::query(
        r#"INSERT INTO chat.metadata_snapshots(
            metadata_snapshot_id,conversation_id,generation,state_version,group_id,epoch,
            group_context_hash,confirmation_tag,producing_transition_id,origin_transition_id,
            metadata_version,nonce,ciphertext,ciphertext_sha256,ciphertext_size,author_did,
            author_device_id,author_key_id,author_public_key,author_auth_generation,
            author_origin_seq,author_role,author_device_status,created_at
        ) VALUES($1,$2,0,0,$3,0,$4,$5,$6,$6,1,$7,$8,$9,16,$10,$11,$12,$13,1,1,'admin','active',$14)"#,
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
    .bind(principal)
    .bind(actor_device_id)
    .bind(actor_key_id)
    .bind(actor_public_key)
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert metadata");
    sqlx::query(
        r#"INSERT INTO chat.entries(
            conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
            accepted_payload_sha256,signed_request_bytes,request_digest,signature,
            server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,
            actor_key_id,actor_auth_generation,generation,state_version,transition_id,received_at
        ) VALUES($1,1,$2,'blue.catbird.chat.defs#creationEntry',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,0,0,$13,$14)"#,
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
    .bind(principal)
    .bind(actor_device_id)
    .bind(actor_key_id)
    .bind(creation_transition_id)
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert creation entry");
    sqlx::query(
        r#"INSERT INTO chat.application_intervals(
            membership_interval_id,conversation_id,generation,recipient_did,
            recipient_device_id,start_seq,opening_kind,opening_transition_id,
            opening_outer_entry_fingerprint,opening_state_version,opening_group_id,
            opening_epoch,opening_group_context_hash,opening_confirmation_tag,
            opening_leaf_period_id,created_at
        ) VALUES($1,$2,0,$3,$4,1,'creation',$1,$5,0,$6,0,$7,$8,$9,$10)"#,
    )
    .bind(creation_transition_id)
    .bind(conversation_id)
    .bind(principal)
    .bind(actor_device_id)
    .bind(&creation_fingerprint)
    .bind(&group_id)
    .bind(&group_context_hash)
    .bind(&confirmation_tag)
    .bind(leaf_period_id)
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert creation interval");
    tx.commit().await.expect("commit creation");
    conversation_id
}

// ===========================================================================
// G2 — existing-conversation head lock primitive.
// ===========================================================================

/// The hydrator assembles `prior_coordinate` EXACTLY from the committed
/// `chat.conversations` head columns + the current `chat.generation_states`
/// crypto columns, with `next_entry_seq` from the head and lifecycle exact-mapped.
#[tokio::test]
#[ignore = "requires the dedicated gate database"]
async fn existing_head_hydrates_the_exact_current_coordinate() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let base = seed_base(&pool).await;
    let locked_at = clock_now_millis(&pool).await;

    let mut tx = pool.begin().await.expect("begin");
    let head = hydrate_locked_conversation_head(&mut tx, base.conversation_id, locked_at)
        .await
        .expect("existing head hydrates");
    tx.commit().await.expect("commit");

    assert_eq!(head.conversation_id(), base.conversation_id);
    assert_eq!(head.next_entry_seq(), 2, "genesis-advanced append counter");
    assert_eq!(
        head.locked_at().timestamp_millis(),
        locked_at.timestamp_millis()
    );
    let coordinate = head
        .prior_coordinate()
        .expect("an existing head carries its current coordinate");
    assert_eq!(
        coordinate.conversation_id(),
        base.conversation_id.as_bytes()
    );
    assert_eq!(coordinate.generation(), 0);
    assert_eq!(coordinate.state_version(), 0);
    assert_eq!(coordinate.epoch(), 0);
    assert_eq!(coordinate.group_id(), &[1_u8; 32]);
    assert_eq!(coordinate.group_context_hash(), &[2_u8; 32]);
    assert_eq!(coordinate.confirmation_tag(), &[3_u8; 32]);
    assert_eq!(coordinate.lifecycle(), PublicGroupSnapshotLifecycle::Active);
}

/// Absence is fail-closed: no `chat.conversations` row yields `ConversationMissing`,
/// never a fabricated head.
#[tokio::test]
#[ignore = "requires the dedicated gate database"]
async fn absent_conversation_head_is_conversation_missing() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let locked_at = clock_now_millis(&pool).await;

    let mut tx = pool.begin().await.expect("begin");
    let result = hydrate_locked_conversation_head(&mut tx, Uuid::new_v4(), locked_at).await;
    tx.rollback().await.expect("rollback");

    assert!(matches!(
        result,
        Err(ConversationHeadHydrationError::ConversationMissing)
    ));
}

/// MUTUAL EXCLUSION: the head hydrator's `FOR UPDATE OF c` on `chat.conversations`
/// is a real serialization point — a second transaction hydrating the SAME head
/// BLOCKS until the first transaction releases the row lock, then completes. There
/// is no lock-free hydration path.
#[tokio::test]
#[ignore = "requires the dedicated gate database"]
async fn concurrent_head_hydration_blocks_on_for_update() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let base = seed_base(&pool).await;
    let conversation_id = base.conversation_id;

    // A deterministically acquires the head lock FIRST (in this task) and holds
    // its transaction open, so B necessarily contends against a held lock.
    let mut tx_a = pool.begin().await.expect("begin A");
    let locked_at_a = clock_now_millis(&pool).await;
    let head_a = hydrate_locked_conversation_head(&mut tx_a, conversation_id, locked_at_a)
        .await
        .expect("A acquires the head lock");
    assert_eq!(head_a.next_entry_seq(), 2);

    // B attempts the same head lock on a distinct connection; its `FOR UPDATE OF c`
    // must block on A's held row lock (an async wait on the DB, so the runtime is
    // free to fire the timeout below) until A commits.
    let pool_b = pool.clone();
    let mut b = tokio::spawn(async move {
        let mut tx_b = pool_b.begin().await.expect("begin B");
        let locked_at_b = clock_now_millis(&pool_b).await;
        let head_b = hydrate_locked_conversation_head(&mut tx_b, conversation_id, locked_at_b)
            .await
            .expect("B acquires the head lock after A releases");
        tx_b.commit().await.expect("B commits");
        head_b.next_entry_seq()
    });

    // While A holds the lock, B cannot finish within the window — it is blocked on
    // `FOR UPDATE OF c`, proving there is no lock-free hydration path.
    match tokio::time::timeout(Duration::from_millis(1000), &mut b).await {
        Err(_elapsed) => { /* still blocked — the property under test */ }
        Ok(_) => panic!("B must block on FOR UPDATE while A holds the conversation head"),
    }

    // Release A; B then unblocks and observes the same committed head.
    tx_a.commit().await.expect("A commits");
    let seq_b = b.await.expect("B task joins");
    assert_eq!(
        seq_b, 2,
        "B observes the same committed head after unblocking"
    );
}
